//! Lease-aware HTTP/WebSocket proxy for the PicoCompute edge gateway.
//!
//! Implements [`pingora_proxy::ProxyHttp`] to intercept proxied requests
//! and validate access leases before forwarding traffic to sandbox TCP
//! backends.

use hashbrown::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use http::HeaderMap;
use parking_lot::Mutex;
use pico_core::{
    AuditEventBuilder, AuditEventDetails, AuditEventKind, AuditEventSink, AuditOutcome,
    AuditProducer, EnforceContext, Hlc, LeaseAction, LeaseAuthority, LeaseId, LeaseManager,
    LeaseScope, LeaseValidationError, SandboxId, TenantId,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};

use crate::routing::{RoutingTable, Upstream};

/// Header name for the PicoCompute lease ID.
pub const HEADER_PICO_LEASE_ID: &str = "x-pico-lease-id";

/// Header name for a signed access-lease blob.
pub const HEADER_PICO_ACCESS_LEASE: &str = "x-pico-access-lease";

/// Header name for the PicoCompute tenant ID.
pub const HEADER_PICO_TENANT_ID: &str = "x-pico-tenant-id";

/// Header name for the PicoCompute sandbox ID.
pub const HEADER_PICO_SANDBOX_ID: &str = "x-pico-sandbox-id";

/// Header name for the target guest port.
pub const HEADER_PICO_GUEST_PORT: &str = "x-pico-guest-port";

/// Lease-aware HTTP/WebSocket proxy for the PicoCompute edge gateway.
///
/// Each proxied request is intercepted, the lease is validated against
/// `LeaseManager`, and audit events are emitted for enforcement decisions.
pub struct EdgeProxy {
    /// Lease manager for validating access leases.
    pub lease_manager: Arc<LeaseManager>,
    /// Routing table for mapping host headers to upstream backends.
    pub routing_table: Arc<RoutingTable>,
    /// Audit event sink.
    pub audit_sink: Arc<dyn AuditEventSink>,
    /// HLC for event timestamps.
    pub hlc: Arc<Hlc>,
    /// Current policy epoch for lease validation.
    pub policy_epoch: u64,
    /// Whether lease validation is required for all requests.
    pub require_lease: bool,
    /// Authority used to verify signed lease blobs.
    pub lease_authority: Option<LeaseAuthority>,
    /// Connection timeout for upstream connections.
    pub connect_timeout: Duration,
    /// Read timeout for upstream connections.
    pub read_timeout: Duration,
    /// Global default requests-per-second limit applied to every endpoint.
    ///
    /// This is a global default. Per-upstream limits (stored on [`Upstream`])
    /// are not yet wired into the proxy pipeline; see the `Upstream` fields
    /// `max_rps` / `max_connections` for planned per-endpoint enforcement.
    pub default_max_rps: Option<u32>,
    /// Global default max concurrent connections.
    ///
    /// This is a global default. Per-upstream limits (stored on [`Upstream`])
    /// are not yet wired into the proxy pipeline.
    pub default_max_connections: Option<usize>,
    /// Rate limiter buckets keyed by host.
    rate_limiter: Mutex<HashMap<String, RateBucket>>,
    /// Active connection counter.
    active_connections: AtomicU64,
}

/// Extracted lease identifiers from an incoming request.
///
/// Returned by [`EdgeProxy::validate_lease_for_request`] so callers can emit
/// audit events with the correct sandbox/tenant/lease context.
pub(crate) struct LeaseContext {
    lease_id: Option<LeaseId>,
    sandbox_id: SandboxId,
    tenant_id: TenantId,
}

/// Token-bucket rate limiter for a single endpoint.
#[derive(Debug)]
struct RateBucket {
    /// Tokens currently available.
    tokens: f64,
    /// Maximum tokens (burst capacity).
    capacity: f64,
    /// Token refill rate per second.
    rate: f64,
    /// Last token refill timestamp (seconds since epoch).
    last_refill: f64,
}

impl RateBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            capacity: burst,
            rate,
            last_refill: now_secs(),
        }
    }

    /// Try to consume one token. Returns `true` if allowed.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = now_secs();
        let elapsed = now - self.last_refill;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}

fn now_secs() -> f64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

impl EdgeProxy {
    /// Create a new EdgeProxy with the given components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_manager: Arc<LeaseManager>,
        routing_table: Arc<RoutingTable>,
        audit_sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
        policy_epoch: u64,
        require_lease: bool,
        default_max_rps: Option<u32>,
        default_max_connections: Option<usize>,
    ) -> Self {
        Self {
            lease_manager,
            routing_table,
            audit_sink,
            hlc,
            policy_epoch,
            require_lease,
            lease_authority: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            default_max_rps,
            default_max_connections,
            rate_limiter: Mutex::new(HashMap::new()),
            active_connections: AtomicU64::new(0),
        }
    }

    /// Installs the lease authority used to verify signed lease blobs.
    pub fn with_lease_authority(mut self, authority: LeaseAuthority) -> Self {
        self.lease_authority = Some(authority);
        self
    }

    /// Extract the signed lease blob from request headers.
    fn extract_access_lease(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(HEADER_PICO_ACCESS_LEASE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// Extract the lease ID from request headers.
    fn extract_lease_id(&self, headers: &HeaderMap) -> Option<LeaseId> {
        headers
            .get(HEADER_PICO_LEASE_ID)
            .and_then(|v| v.to_str().ok())
            .map(LeaseId::from_string)
    }

    /// Extract the tenant ID from request headers.
    fn extract_tenant_id(&self, headers: &HeaderMap) -> Option<TenantId> {
        headers
            .get(HEADER_PICO_TENANT_ID)
            .and_then(|v| v.to_str().ok())
            .map(TenantId::from_string)
    }

    /// Extract the sandbox ID from request headers.
    fn extract_sandbox_id(&self, headers: &HeaderMap) -> Option<SandboxId> {
        headers
            .get(HEADER_PICO_SANDBOX_ID)
            .and_then(|v| v.to_str().ok())
            .map(SandboxId::from_string)
    }

    /// Extract the guest port from request headers.
    fn extract_guest_port(&self, headers: &HeaderMap) -> Option<u16> {
        headers
            .get(HEADER_PICO_GUEST_PORT)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    }

    /// Validate the lease for a proxied request.
    ///
    /// Returns the extracted [`LeaseContext`] if the lease is valid, or `Err`
    /// with a human-readable reason. Callers use the context to emit rich audit
    /// events with sandbox/tenant/lease identifiers.
    pub(crate) fn validate_lease_for_request(
        &self,
        session: &mut Session,
    ) -> Result<LeaseContext, LeaseValidationError> {
        let headers = &session.req_header().headers;

        let lease_id = self.extract_lease_id(headers);
        let sandbox_id = self
            .extract_sandbox_id(headers)
            .unwrap_or_else(|| SandboxId::from_string("unknown"));
        let tenant_id = self
            .extract_tenant_id(headers)
            .unwrap_or_else(|| TenantId::from_string("unknown"));
        let guest_port = self.extract_guest_port(headers);

        let requested_scope = if let Some(port) = guest_port {
            LeaseScope {
                ports: vec![port],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            }
        } else {
            LeaseScope::unbounded()
        };

        if let Some(blob) = self.extract_access_lease(headers) {
            let authority = self
                .lease_authority
                .as_ref()
                .ok_or(LeaseValidationError::InvalidSignature)?;
            let lease = authority.enforce_blob(
                &blob,
                &EnforceContext {
                    sandbox_id: &sandbox_id,
                    tenant_id: &tenant_id,
                    action: LeaseAction::PortForward,
                    scope: &requested_scope,
                    policy_epoch: self.policy_epoch,
                },
            )?;
            return Ok(LeaseContext {
                lease_id: Some(lease.lease_id),
                sandbox_id,
                tenant_id,
            });
        }

        let Some(ref lease_id) = lease_id else {
            if self.require_lease {
                return Err(LeaseValidationError::NotFound {
                    lease_id: "<missing>".to_string(),
                });
            }
            // When lease checks are optional and no lease header is
            // present, the request passes through with an Allow audit
            // (emitted by request_filter). The LeaseContext carries the
            // sandbox/tenant IDs but no lease reference.
            return Ok(LeaseContext {
                lease_id: None,
                sandbox_id,
                tenant_id,
            });
        };

        self.lease_manager.validate_with_scope(
            lease_id,
            &sandbox_id,
            &tenant_id,
            LeaseAction::PortForward,
            &requested_scope,
            self.policy_epoch,
        )?;

        Ok(LeaseContext {
            lease_id: Some(lease_id.clone()),
            sandbox_id,
            tenant_id,
        })
    }

    /// Emit an audit event for a proxied connection.
    pub fn emit_proxy_audit(
        &self,
        outcome: AuditOutcome,
        lease_id: Option<&LeaseId>,
        sandbox_id: Option<&str>,
        tenant_id: Option<&TenantId>,
        host: Option<&str>,
        reason: Option<&str>,
    ) {
        let _ = self.audit_sink.emit(
            AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::NetworkEnforcement)
                .producer(AuditProducer::LeaseManager)
                .action("edge_proxy")
                .outcome(outcome)
                .lease_id(lease_id.map(|l| l.as_str().to_string()).unwrap_or_default())
                .sandbox_id(
                    sandbox_id
                        .map(SandboxId::from_string)
                        .unwrap_or_else(|| SandboxId::from_string("unknown")),
                )
                .tenant_id(
                    tenant_id
                        .cloned()
                        .unwrap_or_else(|| TenantId::from_string("unknown")),
                )
                .details(AuditEventDetails::NetworkEnforcement {
                    action: "edge_proxy".to_string(),
                    destination: host.map(|h| h.to_string()),
                    outcome: outcome.to_string(),
                    reason: reason.map(|s| s.to_string()),
                    lease_id: lease_id.map(|l| l.as_str().to_string()),
                })
                .build(),
        );
    }

    /// Try to consume one token from the rate limiter for the given host.
    fn try_consume_rate_limit(&self, host: Option<&str>, max_rps: u32) -> bool {
        let key = host.unwrap_or("__default__").to_string();
        let mut limiter = self.rate_limiter.lock();
        let bucket = limiter
            .entry(key)
            .or_insert_with(|| RateBucket::new(max_rps as f64, (max_rps * 2) as f64));
        bucket.try_consume()
    }

    /// Resolve the upstream backend for this request.
    pub fn resolve_upstream(&self, session: &Session) -> Arc<Upstream> {
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());
        self.routing_table.resolve(host)
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    /// Per-request context: `true` when a connection-tracking slot was acquired
    /// and must be released in [`logging`](ProxyHttp::logging).
    ///
    /// WebSocket upgrades are handled natively by Pingora's proxy layer —
    /// no additional code is needed. The HTTP upgrade handshake passes through
    /// the same [`request_filter`](ProxyHttp::request_filter) / [`upstream_peer`](ProxyHttp::upstream_peer)
    /// pipeline, and Pingora transparently switches to bidirectional TCP forwarding
    /// for the WebSocket frames.
    ///
    /// Graceful reload is provided by Pingora's [`Server`](pingora_core::server::Server)
    /// lifecycle. When a reload signal is received, the old process stops accepting
    /// new connections while allowing existing connections (including WebSocket streams)
    /// to drain. The new process takes over without dropping active sessions.
    type CTX = bool;

    fn new_ctx(&self) -> Self::CTX {
        false
    }

    /// Determine the upstream peer from the routing table based on the host header.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let upstream = self.resolve_upstream(session);
        let mut peer = Box::new(HttpPeer::new(&upstream.addr, upstream.tls, String::new()));
        peer.options.connection_timeout = Some(self.connect_timeout);
        peer.options.read_timeout = Some(self.read_timeout);
        Ok(peer)
    }

    /// Validate the access lease before proxying.
    ///
    /// Also enforces per-endpoint rate limits and connection limits.
    ///
    /// If lease validation fails (and leases are required), the request is
    /// rejected with a 403 Forbidden response. If leases are optional and no
    /// lease is present, the request passes through.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Extract headers and host before the mutable borrow needed for
        // lease validation.
        let (lease_id, host) = {
            let headers = &session.req_header().headers;
            let lease_id = self.extract_lease_id(headers);
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            (lease_id, host)
        };

        // Enforce rate limit.
        if let Some(max_rps) = self.default_max_rps
            && !self.try_consume_rate_limit(host.as_deref(), max_rps)
        {
            self.emit_proxy_audit(
                AuditOutcome::Denied,
                lease_id.as_ref(),
                None,
                None,
                host.as_deref(),
                Some("rate limit exceeded"),
            );
            let _ = session.respond_error(429).await;
            return Ok(true);
        }

        // Enforce connection limit.
        if let Some(max_conns) = self.default_max_connections {
            let current = self.active_connections.fetch_add(1, Ordering::AcqRel) + 1;
            if current > max_conns as u64 {
                // Reject and roll back the counter atomically.
                self.active_connections.fetch_sub(1, Ordering::AcqRel);
                self.emit_proxy_audit(
                    AuditOutcome::Denied,
                    lease_id.as_ref(),
                    None,
                    None,
                    host.as_deref(),
                    Some("connection limit exceeded"),
                );
                let _ = session.respond_error(503).await;
                return Ok(true);
            }
            *ctx = true;
        }

        match self.validate_lease_for_request(session) {
            Ok(lctx) => {
                self.emit_proxy_audit(
                    AuditOutcome::Allow,
                    lctx.lease_id.as_ref(),
                    Some(lctx.sandbox_id.as_str()),
                    Some(&lctx.tenant_id),
                    host.as_deref(),
                    None,
                );
                Ok(false)
            }
            Err(err) => {
                if self.require_lease {
                    let err_str = err.to_string();
                    self.emit_proxy_audit(
                        AuditOutcome::Denied,
                        lease_id.as_ref(),
                        None,
                        None,
                        host.as_deref(),
                        Some(&err_str),
                    );
                    // Send a 403 response and signal early return.
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
                Ok(false)
            }
        }
    }

    /// Log the request outcome and release connection tracking.
    ///
    /// The connection-slot release is deferred here because Pingora guarantees
    /// [`logging`](ProxyHttp::logging) is called for every request regardless of
    /// outcome (including early returns from [`request_filter`](ProxyHttp::request_filter)).
    /// This avoids double-decrement bugs when a request is denied after acquiring a slot.
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        // Only release a slot if this request successfully acquired one.
        if *ctx {
            self.active_connections.fetch_sub(1, Ordering::AcqRel);
            *ctx = false;
        }

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        tracing::debug!(
            status,
            active_connections = self.active_connections.load(Ordering::Relaxed),
            "request completed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::policy::PolicyAction;
    use pico_core::{InMemoryAuditSink, LeaseScope, PolicyEngine, PrincipalId, RevocationReason};

    fn test_lease_manager() -> Arc<LeaseManager> {
        Arc::new(LeaseManager::new())
    }

    fn test_proxy(require_lease: bool) -> (EdgeProxy, Arc<InMemoryAuditSink>) {
        let sink = Arc::new(InMemoryAuditSink::new());
        let lease_manager = test_lease_manager();
        let routing = Arc::new(RoutingTable::new(Upstream::tcp("127.0.0.1:9000")));

        let proxy = EdgeProxy::new(
            Arc::clone(&lease_manager),
            routing,
            Arc::<InMemoryAuditSink>::clone(&sink),
            Arc::new(Hlc::new()),
            1,
            require_lease,
            None,
            None,
        );
        (proxy, sink)
    }

    fn issue_port_forward_lease(
        lease_manager: &LeaseManager,
        tenant: &TenantId,
        sandbox: &SandboxId,
        port: u16,
    ) -> LeaseId {
        let engine = PolicyEngine::new();
        engine
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let principal = PrincipalId::new("user:test");
        let decision = engine.evaluate(&principal, tenant, PolicyAction::Exec);
        lease_manager
            .issue(
                tenant.clone(),
                principal,
                sandbox.clone(),
                LeaseAction::PortForward,
                LeaseScope {
                    ports: vec![port],
                    paths: vec![],
                    egress_cidrs: vec![],
                    credential_types: vec![],
                },
                &decision,
                3600,
            )
            .lease_id
    }

    #[test]
    fn extract_lease_id_from_headers() {
        let (proxy, _) = test_proxy(true);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_PICO_LEASE_ID),
            "lse_01JXYZ".parse().unwrap(),
        );

        let lease_id = proxy.extract_lease_id(&headers);
        assert!(lease_id.is_some());
        assert!(lease_id.unwrap().as_str().starts_with("lse_"));
    }

    #[test]
    fn extract_tenant_id_from_headers() {
        let (proxy, _) = test_proxy(true);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_PICO_TENANT_ID),
            "tnt_01JXYZ".parse().unwrap(),
        );

        let tenant_id = proxy.extract_tenant_id(&headers);
        assert!(tenant_id.is_some());
        assert!(tenant_id.unwrap().as_str().starts_with("tnt_"));
    }

    #[test]
    fn extract_sandbox_id_from_headers() {
        let (proxy, _) = test_proxy(true);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_PICO_SANDBOX_ID),
            "sbx_01JXYZ".parse().unwrap(),
        );

        let sandbox_id = proxy.extract_sandbox_id(&headers);
        assert!(sandbox_id.is_some());
        assert!(sandbox_id.unwrap().as_str().starts_with("sbx_"));
    }

    #[test]
    fn extract_guest_port_from_headers() {
        let (proxy, _) = test_proxy(true);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_PICO_GUEST_PORT),
            "8080".parse().unwrap(),
        );

        let port = proxy.extract_guest_port(&headers);
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn lease_blob_enforces_without_store() {
        use pico_core::{Admission, DEFAULT_PERMIT_POLICY, QuotaEngine};

        let authority = LeaseAuthority::generate();
        let policy = Arc::new(PolicyEngine::new());
        policy.load_policies(DEFAULT_PERMIT_POLICY).unwrap();
        let admission = Admission::new(policy, Arc::new(QuotaEngine::new()), authority.clone());
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease = admission
            .admit(pico_core::AdmitRequest {
                tenant_id: tenant.clone(),
                principal: PrincipalId::new("user:test"),
                sandbox_id: sandbox.clone(),
                action: LeaseAction::PortForward,
                scope: LeaseScope {
                    ports: vec![8080],
                    paths: vec![],
                    egress_cidrs: vec![],
                    credential_types: vec![],
                },
                ttl_secs: Some(3600),
                quota: None,
            })
            .unwrap();
        let blob = admission.encode(&lease).unwrap();

        let (mut proxy, _) = test_proxy(true);
        proxy = proxy.with_lease_authority(authority);
        let ctx = EnforceContext {
            sandbox_id: &sandbox,
            tenant_id: &tenant,
            action: LeaseAction::PortForward,
            scope: &LeaseScope {
                ports: vec![8080],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            policy_epoch: proxy.policy_epoch,
        };
        assert!(
            proxy
                .lease_authority
                .as_ref()
                .unwrap()
                .enforce_blob(&blob, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn lease_validation_with_valid_lease() {
        let (proxy, _) = test_proxy(true);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = issue_port_forward_lease(&proxy.lease_manager, &tenant, &sandbox, 8080);

        let result = proxy.lease_manager.validate(
            &lease_id,
            &sandbox,
            &tenant,
            LeaseAction::PortForward,
            proxy.policy_epoch,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn lease_validation_with_revoked_lease() {
        let (proxy, _) = test_proxy(true);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = issue_port_forward_lease(&proxy.lease_manager, &tenant, &sandbox, 8080);

        proxy
            .lease_manager
            .revoke(&lease_id, RevocationReason::AdminAction)
            .unwrap();

        let result = proxy.lease_manager.validate(
            &lease_id,
            &sandbox,
            &tenant,
            LeaseAction::PortForward,
            proxy.policy_epoch,
        );
        assert!(matches!(result, Err(LeaseValidationError::Revoked { .. })));
    }

    #[test]
    fn emit_proxy_audit_allow() {
        let (proxy, sink) = test_proxy(true);
        let lease_id = LeaseId::generate();
        let tenant = TenantId::generate();

        proxy.emit_proxy_audit(
            AuditOutcome::Allow,
            Some(&lease_id),
            Some("sbx_test"),
            Some(&tenant),
            Some("sandbox.example.com"),
            None,
        );

        let events = sink.events_by_kind(AuditEventKind::NetworkEnforcement);
        assert!(!events.is_empty());
        assert_eq!(events[0].outcome.as_deref(), Some("allow"));
    }

    #[test]
    fn emit_proxy_audit_denied() {
        let (proxy, sink) = test_proxy(true);
        let lease_id = LeaseId::generate();

        proxy.emit_proxy_audit(
            AuditOutcome::Denied,
            Some(&lease_id),
            Some("sbx_test"),
            None,
            Some("sandbox.example.com"),
            Some("lease expired"),
        );

        let events = sink.events_by_kind(AuditEventKind::NetworkEnforcement);
        assert!(!events.is_empty());
        assert_eq!(events[0].outcome.as_deref(), Some("denied"));
    }

    #[test]
    fn rate_limiter_allows_then_denies() {
        let (proxy, _) = test_proxy(true);
        assert!(proxy.default_max_rps.is_none()); // sanity: default test proxy has no limit

        // Create a proxy with a 2 rps limit (burst 4).
        let limited_proxy = EdgeProxy::new(
            Arc::new(LeaseManager::new()),
            Arc::new(RoutingTable::new(Upstream::tcp("127.0.0.1:9000"))),
            Arc::new(InMemoryAuditSink::new()),
            Arc::new(Hlc::new()),
            1,
            true,
            Some(2),
            None,
        );

        // First 4 requests (burst) are allowed.
        for _ in 0..4 {
            assert!(limited_proxy.try_consume_rate_limit(Some("test.example.com"), 2));
        }
        // Fifth request is denied.
        assert!(!limited_proxy.try_consume_rate_limit(Some("test.example.com"), 2));
    }

    #[test]
    fn active_connection_counter_tracks_acquisitions() {
        let proxy = EdgeProxy::new(
            Arc::new(LeaseManager::new()),
            Arc::new(RoutingTable::new(Upstream::tcp("127.0.0.1:9000"))),
            Arc::new(InMemoryAuditSink::new()),
            Arc::new(Hlc::new()),
            1,
            true,
            None,
            Some(2),
        );

        assert_eq!(proxy.active_connections.load(Ordering::Relaxed), 0);
        proxy.active_connections.fetch_add(1, Ordering::AcqRel);
        assert_eq!(proxy.active_connections.load(Ordering::Relaxed), 1);
        proxy.active_connections.fetch_sub(1, Ordering::AcqRel);
        assert_eq!(proxy.active_connections.load(Ordering::Relaxed), 0);
    }
}
