//! Controlled port-forwarding API and data path.
//!
//! Port forwarding is disabled by default. Exposing a sandbox port requires a
//! valid, unexpired, unrevoked access lease issued by the control plane. The
//! manager validates the lease, binds a platform-managed local TCP listener,
//! and emits audit events for expose, revoke, expiry, and denial.
//!
//! The data path delegates TCP forwarding to [`PortProxyManager`](super::port_proxy::PortProxyManager)
//! and enforces per-endpoint connection limits and revocation-driven
//! connection termination.

use hashbrown::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use pico_core::leases::has_lease_expired;
use pico_core::{
    AuditEventBuilder, AuditEventDetails, AuditEventKind, AuditEventSink, AuditOutcome,
    AuditProducer, EnforceContext, Hlc, LeaseAction, LeaseAuthority, LeaseId, LeaseManager,
    LeaseScope, LeaseValidationError, PortForwardEndpoint, PortForwardEndpointState,
    PortForwardRequest, PortForwardResponse, SandboxError, SandboxId, TenantId, now_iso,
};

use crate::metrics::{
    record_port_forward_denied, record_port_forward_endpoints_active, record_port_forward_expired,
    record_port_forward_expose, record_port_forward_revoke,
};
use crate::port_proxy::{BindOptions, PortProxyManager};

struct EndpointEntry {
    endpoint: PortForwardEndpoint,
    cancel: CancellationToken,
}

/// Manager for controlled port-forward endpoints.
///
/// The manager is `Send + Sync` and intended to live behind an `Arc` shared by
/// the API/RPC surface and the sandbox lifecycle code.
pub struct PortForwardManager {
    port_proxy: Arc<PortProxyManager>,
    lease_manager: Arc<LeaseManager>,
    lease_authority: parking_lot::RwLock<Option<LeaseAuthority>>,
    audit_sink: Arc<dyn AuditEventSink>,
    hlc: Arc<Hlc>,
    endpoints: Mutex<HashMap<String, EndpointEntry>>,
    public_host: String,
}

impl PortForwardManager {
    /// Creates a new port-forward manager.
    #[must_use]
    pub fn new(
        port_proxy: Arc<PortProxyManager>,
        lease_manager: Arc<LeaseManager>,
        audit_sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
        public_host: impl Into<String>,
    ) -> Self {
        Self {
            port_proxy,
            lease_manager,
            lease_authority: parking_lot::RwLock::new(None),
            audit_sink,
            hlc,
            endpoints: Mutex::new(HashMap::new()),
            public_host: public_host.into(),
        }
    }

    /// Installs the lease authority used to verify signed lease blobs.
    pub fn set_lease_authority(&self, authority: LeaseAuthority) {
        *self.lease_authority.write() = Some(authority);
    }

    fn enforce_lease(
        &self,
        req: &PortForwardRequest,
        sandbox: &SandboxId,
        requested_scope: &LeaseScope,
        current_policy_epoch: u64,
    ) -> Result<pico_core::AccessLease, LeaseValidationError> {
        if let Some(blob) = req.lease.as_deref() {
            let authority = self.lease_authority.read();
            let Some(authority) = authority.as_ref() else {
                return Err(LeaseValidationError::InvalidSignature);
            };
            return authority.enforce_blob_revocable(
                blob,
                &EnforceContext {
                    sandbox_id: sandbox,
                    tenant_id: &req.tenant_id,
                    action: LeaseAction::PortForward,
                    scope: requested_scope,
                    policy_epoch: current_policy_epoch,
                },
                |id| self.lease_manager.is_revoked(id),
            );
        }
        self.lease_manager.validate_with_scope(
            &req.lease_id,
            sandbox,
            &req.tenant_id,
            LeaseAction::PortForward,
            requested_scope,
            current_policy_epoch,
        )
    }

    /// Exposes a sandbox guest port through a platform-managed endpoint.
    ///
    /// Validates the supplied access lease, binds a local listener, and emits
    /// an audit event. Returns the created endpoint metadata.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::Unauthorized` if the lease is invalid, expired,
    /// revoked, or out of scope. Returns `SandboxError::PortInUse` or
    /// `SandboxError::Io` if the local listener cannot be bound.
    pub async fn expose(
        &self,
        sandbox_id: &str,
        req: PortForwardRequest,
        current_policy_epoch: u64,
    ) -> pico_core::Result<PortForwardEndpoint> {
        let requested_scope = LeaseScope {
            ports: vec![req.guest_port],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec![],
        };

        let sandbox = SandboxId::from_string(sandbox_id);
        let lease = match self.enforce_lease(&req, &sandbox, &requested_scope, current_policy_epoch)
        {
            Ok(lease) => lease,
            Err(err) => {
                record_port_forward_denied();
                self.emit_network_enforcement(
                    sandbox_id,
                    &req.tenant_id,
                    "expose",
                    AuditOutcome::Denied,
                    Some(&err.to_string()),
                    Some(req.lease_id.as_str().to_string()),
                );
                return Err(lease_error_to_sandbox_error(err));
            }
        };

        let host = if req.localhost_only {
            "localhost".to_string()
        } else {
            self.public_host.clone()
        };
        let requested_host_port = req.requested_host_port.unwrap_or(0);
        let cancel = CancellationToken::new();

        let actual_host_port = match Arc::clone(&self.port_proxy)
            .bind_with_options(
                sandbox_id,
                requested_host_port,
                req.guest_port,
                req.localhost_only,
                BindOptions {
                    cancel: Some(cancel.clone()),
                    max_connections: req.max_connections,
                },
            )
            .await
        {
            Ok(port) => port,
            Err(err) => {
                record_port_forward_denied();
                let kind = err.kind();
                self.emit_network_enforcement(
                    sandbox_id,
                    &req.tenant_id,
                    "expose",
                    AuditOutcome::Failed,
                    Some(&format!("bind failed: {err}")),
                    Some(req.lease_id.as_str().to_string()),
                );
                return Err(if kind == std::io::ErrorKind::AddrInUse {
                    SandboxError::PortInUse(requested_host_port)
                } else {
                    SandboxError::Io(err)
                });
            }
        };

        let endpoint = PortForwardEndpoint {
            endpoint_id: pico_core::new_port_forward_id(),
            sandbox_id: sandbox_id.to_string(),
            tenant_id: req.tenant_id,
            lease_id: req.lease_id.clone(),
            policy_decision_id: lease.policy_decision_id.clone(),
            owner: lease.subject.clone(),
            guest_port: req.guest_port,
            host_port: actual_host_port,
            host,
            localhost_only: req.localhost_only,
            created_at: now_iso(),
            expires_at: lease.expires_at.clone(),
            revoked_at: None,
            state: PortForwardEndpointState::Active,
            max_connections: req.max_connections,
            // TODO: track active connection count from the proxy semaphore.
            active_connections: 0,
        };

        {
            let mut endpoints = self.endpoints.lock().await;
            endpoints.insert(
                endpoint.endpoint_id.clone(),
                EndpointEntry {
                    endpoint: endpoint.clone(),
                    cancel,
                },
            );
        }

        record_port_forward_expose();
        self.emit_network_enforcement(
            sandbox_id,
            &endpoint.tenant_id,
            "expose",
            AuditOutcome::Allow,
            None,
            Some(req.lease_id.as_str().to_string()),
        );

        self.record_active_endpoint_count().await;

        Ok(endpoint)
    }

    /// Returns a created endpoint by ID, if it exists.
    #[must_use]
    pub async fn get(&self, endpoint_id: &str) -> Option<PortForwardEndpoint> {
        let endpoints = self.endpoints.lock().await;
        endpoints.get(endpoint_id).map(|e| e.endpoint.clone())
    }

    /// Revokes a single endpoint.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::BadRequest` if the endpoint is unknown or does
    /// not belong to the given sandbox.
    pub async fn revoke(
        &self,
        sandbox_id: &str,
        endpoint_id: &str,
        reason: &str,
    ) -> pico_core::Result<PortForwardResponse> {
        let entry = {
            let mut endpoints = self.endpoints.lock().await;
            let entry = endpoints.get_mut(endpoint_id).ok_or_else(|| {
                SandboxError::BadRequest(format!("endpoint not found: {endpoint_id}"))
            })?;
            if entry.endpoint.sandbox_id != sandbox_id {
                return Err(SandboxError::BadRequest(format!(
                    "endpoint {endpoint_id} does not belong to sandbox {sandbox_id}"
                )));
            }
            entry.endpoint.state = PortForwardEndpointState::Revoked;
            entry.endpoint.revoked_at = Some(now_iso());
            entry.cancel.cancel();
            entry.endpoint.clone()
        };

        self.port_proxy.unbind(sandbox_id, entry.host_port).await;

        record_port_forward_revoke();
        self.record_active_endpoint_count().await;

        self.emit_network_enforcement(
            sandbox_id,
            &entry.tenant_id,
            "revoke",
            AuditOutcome::Revoked,
            Some(reason),
            Some(entry.lease_id.as_str().to_string()),
        );

        Ok(PortForwardResponse { endpoint: entry })
    }

    /// Lists active and revoked endpoints for a sandbox.
    pub async fn list(&self, sandbox_id: &str) -> Vec<PortForwardEndpoint> {
        self.cleanup_expired().await;
        let endpoints = self.endpoints.lock().await;
        let mut items: Vec<PortForwardEndpoint> = endpoints
            .values()
            .filter(|e| e.endpoint.sandbox_id == sandbox_id)
            .map(|e| e.endpoint.clone())
            .collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        items
    }

    /// Revokes every endpoint for a sandbox. Returns the number revoked.
    ///
    /// Used during sandbox destroy/suspend to ensure no ingress remains.
    pub async fn revoke_all_for_sandbox(&self, sandbox_id: &str) -> usize {
        let ids: Vec<String> = {
            let endpoints = self.endpoints.lock().await;
            endpoints
                .values()
                .filter(|e| {
                    e.endpoint.sandbox_id == sandbox_id
                        && e.endpoint.state == PortForwardEndpointState::Active
                })
                .map(|e| e.endpoint.endpoint_id.clone())
                .collect()
        };

        for id in &ids {
            let _ = self.revoke(sandbox_id, id, "sandbox_destroyed").await;
        }
        ids.len()
    }

    /// Revokes every endpoint associated with a lease. Returns the number revoked.
    pub async fn revoke_by_lease(&self, lease_id: &LeaseId) -> usize {
        let lease_str = lease_id.as_str().to_string();
        let ids: Vec<(String, String)> = {
            let endpoints = self.endpoints.lock().await;
            endpoints
                .values()
                .filter(|e| {
                    e.endpoint.lease_id.as_str() == lease_str
                        && e.endpoint.state == PortForwardEndpointState::Active
                })
                .map(|e| {
                    (
                        e.endpoint.sandbox_id.clone(),
                        e.endpoint.endpoint_id.clone(),
                    )
                })
                .collect()
        };

        for (sandbox_id, endpoint_id) in &ids {
            let _ = self.revoke(sandbox_id, endpoint_id, "lease_revoked").await;
        }
        ids.len()
    }

    /// Removes expired endpoints and releases their listeners.
    ///
    /// Returns the number of endpoints that transitioned to expired.
    pub async fn cleanup_expired(&self) -> usize {
        let now = now_iso();
        let expired_ids: Vec<(String, String)> = {
            let endpoints = self.endpoints.lock().await;
            endpoints
                .values()
                .filter(|e| {
                    e.endpoint.state == PortForwardEndpointState::Active
                        && has_lease_expired(&e.endpoint.expires_at, &now)
                })
                .map(|e| {
                    (
                        e.endpoint.sandbox_id.clone(),
                        e.endpoint.endpoint_id.clone(),
                    )
                })
                .collect()
        };

        for (sandbox_id, endpoint_id) in &expired_ids {
            // Transition directly to Expired to avoid emitting a spurious
            // "revoked" audit event. The cancel + unbind match what revoke
            // does, but the audit event says "expired".
            let (tenant_id, host_port, lease_id) = {
                let mut endpoints = self.endpoints.lock().await;
                let Some(entry) = endpoints.get_mut(endpoint_id) else {
                    continue;
                };
                if entry.endpoint.state != PortForwardEndpointState::Active {
                    continue;
                }
                entry.endpoint.state = PortForwardEndpointState::Expired;
                entry.endpoint.revoked_at = Some(now_iso());
                entry.cancel.cancel();
                (
                    entry.endpoint.tenant_id.clone(),
                    entry.endpoint.host_port,
                    entry.endpoint.lease_id.as_str().to_string(),
                )
            };

            self.port_proxy.unbind(sandbox_id, host_port).await;

            record_port_forward_expired();
            self.emit_network_enforcement(
                sandbox_id,
                &tenant_id,
                "expire",
                AuditOutcome::Expired,
                Some("lease_expired"),
                Some(lease_id),
            );
        }

        self.record_active_endpoint_count().await;

        expired_ids.len()
    }

    /// Record the current active endpoint count as a gauge.
    async fn record_active_endpoint_count(&self) {
        let endpoints = self.endpoints.lock().await;
        let active_count: u64 = endpoints
            .values()
            .filter(|e| e.endpoint.state == PortForwardEndpointState::Active)
            .count() as u64;
        record_port_forward_endpoints_active(active_count);
    }

    fn emit_network_enforcement(
        &self,
        sandbox_id: &str,
        tenant_id: &TenantId,
        action: &str,
        outcome: AuditOutcome,
        reason: Option<&str>,
        lease_id: Option<String>,
    ) {
        let _ = self.audit_sink.emit(
            AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::NetworkEnforcement)
                .sandbox_id(SandboxId::from_string(sandbox_id))
                .tenant_id(tenant_id.clone())
                .producer(AuditProducer::HostAgent)
                .action(action)
                .outcome(outcome)
                .lease_id(lease_id.clone().unwrap_or_default())
                .details(AuditEventDetails::NetworkEnforcement {
                    action: action.to_string(),
                    destination: None,
                    outcome: outcome.to_string(),
                    reason: reason.map(|s| s.to_string()),
                    lease_id,
                })
                .build(),
        );
    }
}

fn lease_error_to_sandbox_error(err: LeaseValidationError) -> SandboxError {
    match err {
        LeaseValidationError::InvalidSignature
        | LeaseValidationError::NotFound { .. }
        | LeaseValidationError::Expired { .. }
        | LeaseValidationError::Revoked { .. }
        | LeaseValidationError::WrongSandbox { .. }
        | LeaseValidationError::WrongTenant { .. }
        | LeaseValidationError::WrongAction { .. }
        | LeaseValidationError::StalePolicyEpoch { .. }
        | LeaseValidationError::ScopeExceeded { .. }
        | LeaseValidationError::Malformed { .. } => SandboxError::Unauthorized,
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;

    use pico_core::{
        AuditEventKind, InMemoryAuditSink, LeaseAction, LeaseManager, LeaseScope, PolicyEngine,
        PrincipalId, SandboxId, TenantId,
    };

    use pico_core::leases::RevocationReason;
    use pico_core::policy::PolicyAction;

    use super::*;

    #[allow(clippy::type_complexity)]
    fn resolve_addr(
        port: u16,
    ) -> Arc<
        dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send>> + Send + Sync,
    > {
        Arc::new(move |_, _| {
            let p = port;
            Box::pin(async move { Some(SocketAddr::from((Ipv4Addr::LOCALHOST, p))) })
        })
    }

    #[allow(clippy::type_complexity)]
    fn wake_fn(
        port: u16,
    ) -> Arc<
        dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send>> + Send + Sync,
    > {
        resolve_addr(port)
    }

    fn test_manager(
        public_host: &str,
    ) -> (
        PortForwardManager,
        Arc<InMemoryAuditSink>,
        Arc<LeaseManager>,
    ) {
        let proxy = Arc::new(PortProxyManager::new(resolve_addr(12345), wake_fn(12345)));
        let sink = Arc::new(InMemoryAuditSink::new());
        let lease_manager = Arc::new(LeaseManager::new());
        let manager = PortForwardManager::new(
            proxy,
            Arc::clone(&lease_manager),
            Arc::<InMemoryAuditSink>::clone(&sink),
            Arc::new(Hlc::new()),
            public_host,
        );
        (manager, sink, lease_manager)
    }

    fn allow_lease(
        lease_manager: &LeaseManager,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        guest_port: u16,
    ) -> LeaseId {
        let engine = PolicyEngine::new();
        engine
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let principal = PrincipalId::new("user:test");
        let decision = engine.evaluate(&principal, tenant_id, PolicyAction::Exec);
        lease_manager
            .issue(
                tenant_id.clone(),
                principal,
                sandbox_id.clone(),
                LeaseAction::PortForward,
                LeaseScope {
                    ports: vec![guest_port],
                    paths: vec![],
                    egress_cidrs: vec![],
                    credential_types: vec![],
                },
                &decision,
                3600,
            )
            .lease_id
    }

    #[tokio::test]
    async fn expose_accepts_signed_lease_blob() {
        use pico_core::{Admission, DEFAULT_PERMIT_POLICY, QuotaEngine};

        let (manager, _sink, _lease_manager) = test_manager("localhost");
        let authority = LeaseAuthority::generate();
        manager.set_lease_authority(authority.clone());
        let policy = Arc::new(PolicyEngine::new());
        policy.load_policies(DEFAULT_PERMIT_POLICY).unwrap();
        let admission = Admission::new(policy, Arc::new(QuotaEngine::new()), authority);
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

        let req = PortForwardRequest {
            tenant_id: tenant,
            lease_id: lease.lease_id.clone(),
            guest_port: 8080,
            requested_host_port: None,
            localhost_only: true,
            max_connections: None,
            lease: Some(blob),
        };
        let endpoint = manager
            .expose(sandbox.as_str(), req, lease.policy_epoch)
            .await
            .unwrap();
        assert_eq!(endpoint.guest_port, 8080);
        assert_eq!(endpoint.lease_id, lease.lease_id);
    }

    #[tokio::test]
    async fn expose_creates_endpoint_with_valid_lease() {
        let (manager, sink, lease_manager) = test_manager("api.example.com");
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = allow_lease(&lease_manager, &tenant, &sandbox, 8080);

        let req = PortForwardRequest {
            tenant_id: tenant.clone(),
            lease_id: lease_id.clone(),
            guest_port: 8080,
            requested_host_port: None,
            localhost_only: false,
            max_connections: None,
            lease: None,
        };

        let endpoint = manager.expose(sandbox.as_str(), req, 1).await.unwrap();

        assert_eq!(endpoint.sandbox_id, sandbox.as_str());
        assert_eq!(endpoint.tenant_id, tenant);
        assert_eq!(endpoint.lease_id, lease_id);
        assert_eq!(endpoint.guest_port, 8080);
        assert_ne!(endpoint.host_port, 0);
        assert_eq!(endpoint.host, "api.example.com");
        assert_eq!(endpoint.state, PortForwardEndpointState::Active);

        let events = sink.events_by_kind(AuditEventKind::NetworkEnforcement);
        assert!(!events.is_empty());
        assert_eq!(events[0].outcome.as_deref(), Some("allow"));
    }

    #[tokio::test]
    async fn expose_rejects_out_of_scope_port() {
        let (manager, _sink, lease_manager) = test_manager("localhost");
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = allow_lease(&lease_manager, &tenant, &sandbox, 8080);

        let req = PortForwardRequest {
            tenant_id: tenant,
            lease_id,
            guest_port: 9999,
            requested_host_port: None,
            localhost_only: true,
            max_connections: None,
            lease: None,
        };

        let err = manager.expose(sandbox.as_str(), req, 1).await.unwrap_err();

        assert!(matches!(err, SandboxError::Unauthorized));
    }

    #[tokio::test]
    async fn expose_rejects_revoked_lease() {
        let (manager, _sink, lease_manager) = test_manager("localhost");
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = allow_lease(&lease_manager, &tenant, &sandbox, 8080);
        lease_manager
            .revoke(&lease_id, RevocationReason::AdminAction)
            .unwrap();

        let req = PortForwardRequest {
            tenant_id: tenant,
            lease_id,
            guest_port: 8080,
            requested_host_port: None,
            localhost_only: true,
            max_connections: None,
            lease: None,
        };

        let err = manager.expose(sandbox.as_str(), req, 1).await.unwrap_err();

        assert!(matches!(err, SandboxError::Unauthorized));
    }

    #[tokio::test]
    async fn revoke_closes_endpoint() {
        let (manager, sink, lease_manager) = test_manager("localhost");
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let lease_id = allow_lease(&lease_manager, &tenant, &sandbox, 8080);

        let req = PortForwardRequest {
            tenant_id: tenant.clone(),
            lease_id: lease_id.clone(),
            guest_port: 8080,
            requested_host_port: None,
            localhost_only: true,
            max_connections: None,
            lease: None,
        };

        let endpoint = manager.expose(sandbox.as_str(), req, 1).await.unwrap();

        let resp = manager
            .revoke(sandbox.as_str(), &endpoint.endpoint_id, "admin_revoke")
            .await
            .unwrap();
        assert_eq!(resp.endpoint.state, PortForwardEndpointState::Revoked);

        let revoked_events: Vec<_> = sink
            .events_by_kind(AuditEventKind::NetworkEnforcement)
            .into_iter()
            .filter(|e| e.action.as_deref() == Some("revoke"))
            .collect();
        assert_eq!(revoked_events.len(), 1);
        assert_eq!(revoked_events[0].outcome.as_deref(), Some("revoked"));
    }

    #[tokio::test]
    async fn list_filters_by_sandbox() {
        let (manager, _sink, lease_manager) = test_manager("localhost");
        let tenant = TenantId::generate();
        let sandbox_a = SandboxId::generate();
        let sandbox_b = SandboxId::generate();
        let lease_a = allow_lease(&lease_manager, &tenant, &sandbox_a, 8080);
        let lease_b = allow_lease(&lease_manager, &tenant, &sandbox_b, 9090);

        manager
            .expose(
                sandbox_a.as_str(),
                PortForwardRequest {
                    tenant_id: tenant.clone(),
                    lease_id: lease_a,
                    guest_port: 8080,
                    requested_host_port: None,
                    localhost_only: true,
                    max_connections: None,
                    lease: None,
                },
                1,
            )
            .await
            .unwrap();

        manager
            .expose(
                sandbox_b.as_str(),
                PortForwardRequest {
                    tenant_id: tenant,
                    lease_id: lease_b,
                    guest_port: 9090,
                    requested_host_port: None,
                    localhost_only: true,
                    max_connections: None,
                    lease: None,
                },
                1,
            )
            .await
            .unwrap();

        let a_list = manager.list(sandbox_a.as_str()).await;
        assert_eq!(a_list.len(), 1);
        assert_eq!(a_list[0].guest_port, 8080);
    }
}
