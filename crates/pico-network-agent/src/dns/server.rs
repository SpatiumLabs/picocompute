//! DNS proxy server: policy-aware UDP/TCP handler.
//!
//! The [`DnsProxy`] listens for DNS queries from sandboxes (redirected via
//! nftables prerouting), evaluates each query against the sending sandbox's
//! active [`DnsPolicy`], and either returns a deterministic NXDOMAIN or
//! resolves upstream and returns filtered answers.

use hashbrown::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use heapless::Vec as HVec;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::cache::DnsCache;
use super::metrics;
use super::metrics::dns_action;
use super::policy::DnsPolicy;
use super::policy::DnsProxyConfig;
use super::resolver::DnsResolver;
use super::resolver::is_platform_internal_domain;

/// Trait for emitting DNS audit events without depending on pico-core.
///
/// Host-agent implements this trait using pico-core's
/// `AuditEventBuilder` and `AuditEventSink`.
pub trait DnsAuditSink: Send + Sync {
    /// Emit an allow decision log entry.
    fn emit_allow(&self, ctx: &DnsAuditContext);
    /// Emit a deny decision log entry.
    fn emit_deny(&self, ctx: &DnsAuditContext, reason: &str);
    /// Emit a resolution failure audit event.
    fn emit_failure(&self, ctx: &DnsAuditContext, reason: &str);
}

/// Context for a DNS audit event.
#[derive(Debug, Clone)]
pub struct DnsAuditContext {
    pub sandbox_id: String,
    pub tenant_id: String,
    pub policy_decision_id: String,
    pub policy_epoch: u64,
    pub qname_class: String,
    pub record_type: String,
}

impl DnsAuditContext {
    #[must_use]
    pub fn new(
        sandbox_id: &str,
        tenant_id: &str,
        policy_decision_id: &str,
        policy_epoch: u64,
        qname_class: &str,
        record_type: &str,
    ) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            tenant_id: tenant_id.into(),
            policy_decision_id: policy_decision_id.into(),
            policy_epoch,
            qname_class: qname_class.into(),
            record_type: record_type.into(),
        }
    }
}

/// No-op audit sink used when audit is disabled.
pub struct NoopDnsAuditSink;

impl DnsAuditSink for NoopDnsAuditSink {
    fn emit_allow(&self, _: &DnsAuditContext) {}
    fn emit_deny(&self, _: &DnsAuditContext, _: &str) {}
    fn emit_failure(&self, _: &DnsAuditContext, _: &str) {}
}

/// A sandbox entry in the policy registry.
#[derive(Debug, Clone)]
struct PolicyEntry {
    sandbox_id: String,
    policy: DnsPolicy,
}

/// Policy-aware DNS proxy service.
pub struct DnsProxy {
    config: DnsProxyConfig,
    resolver: Arc<DnsResolver>,
    audit: Arc<dyn DnsAuditSink>,
    registry: Arc<RwLock<HashMap<Ipv4Addr, PolicyEntry>>>,
    cache: Arc<RwLock<DnsCache>>,
}

impl DnsProxy {
    /// Create a new DNS proxy.
    #[must_use]
    pub fn new(
        config: DnsProxyConfig,
        resolver: DnsResolver,
        audit: Arc<dyn DnsAuditSink>,
    ) -> Self {
        Self {
            config,
            resolver: Arc::new(resolver),
            audit,
            registry: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(DnsCache::default())),
        }
    }

    /// Register a sandbox's DNS policy keyed by its guest IP.
    pub fn register_policy(&self, guest_ip: Ipv4Addr, policy: DnsPolicy) {
        let sandbox_id = policy.sandbox_id.clone();
        let entry = PolicyEntry {
            sandbox_id: sandbox_id.clone(),
            policy,
        };
        self.registry
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(guest_ip, entry);
        let count = self
            .registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        metrics::record_registered_sandboxes(count as u64);
        info!(%guest_ip, sandbox_id = %sandbox_id, "DNS policy registered");
    }

    /// Remove a sandbox's DNS policy by guest IP.
    pub fn unregister_policy(&self, guest_ip: Ipv4Addr) {
        let sandbox_id = self
            .registry
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&guest_ip)
            .map(|entry| entry.sandbox_id);
        if let Some(sid) = sandbox_id {
            self.cache
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove_sandbox(&sid);
            let count = self
                .registry
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            metrics::record_registered_sandboxes(count as u64);
            info!(%guest_ip, sandbox_id = %sid, "DNS policy unregistered");
        }
    }

    /// Return the proxy's listen address.
    #[must_use]
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.config.listen_addr
    }

    /// Spawn UDP and TCP listeners, returning a join handle.
    /// The proxy can continue to be used for policy management after spawning.
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let udp = Self::run_udp(
                this.config.listen_addr,
                Arc::clone(&this.registry),
                Arc::clone(&this.resolver),
                Arc::clone(&this.cache),
                Arc::clone(&this.audit),
            );
            let tcp = Self::run_tcp(
                this.config.listen_addr,
                Arc::clone(&this.registry),
                Arc::clone(&this.resolver),
                Arc::clone(&this.cache),
                Arc::clone(&this.audit),
            );
            tokio::select! {
                r = udp => { if let Err(e) = r { error!(error = %e, "UDP DNS listener failed"); } }
                r = tcp => { if let Err(e) = r { error!(error = %e, "TCP DNS listener failed"); } }
            }
        })
    }

    async fn run_udp(
        addr: SocketAddr,
        registry: Arc<RwLock<HashMap<Ipv4Addr, PolicyEntry>>>,
        resolver: Arc<DnsResolver>,
        cache: Arc<RwLock<DnsCache>>,
        audit: Arc<dyn DnsAuditSink>,
    ) -> Result<(), std::io::Error> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(%addr, "DNS proxy UDP listener started");
        // PERF: 4KB stack allocation avoids malloc in the DNS hot path.
        // Modern stacks default to 8MB; 4KB is well within safe limits.
        let mut buf: HVec<u8, 4096> = HVec::new();
        buf.resize(4096, 0).expect("4096 <= capacity");

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "UDP recv error");
                    continue;
                }
            };

            metrics::record_query();

            let mut request_bytes: HVec<u8, 4096> = HVec::new();
            request_bytes
                .extend_from_slice(&buf[..len])
                .expect("len <= 4096");
            let registry_c = Arc::clone(&registry);
            let resolver_c = Arc::clone(&resolver);
            let cache_c = Arc::clone(&cache);
            let audit_c = Arc::clone(&audit);
            let socket_c = Arc::clone(&socket);

            tokio::spawn(async move {
                let response = handle_query(
                    &request_bytes,
                    src,
                    &registry_c,
                    &resolver_c,
                    &cache_c,
                    &audit_c,
                )
                .await;
                if let Err(e) = socket_c.send_to(&response, src).await {
                    warn!(error = %e, src = %src, "UDP sendto error");
                }
            });
        }
    }

    async fn run_tcp(
        addr: SocketAddr,
        registry: Arc<RwLock<HashMap<Ipv4Addr, PolicyEntry>>>,
        resolver: Arc<DnsResolver>,
        cache: Arc<RwLock<DnsCache>>,
        audit: Arc<dyn DnsAuditSink>,
    ) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        info!(%addr, "DNS proxy TCP listener started");

        loop {
            let (mut stream, src) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "TCP accept error");
                    continue;
                }
            };

            let registry_c = Arc::clone(&registry);
            let resolver_c = Arc::clone(&resolver);
            let cache_c = Arc::clone(&cache);
            let audit_c = Arc::clone(&audit);

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len > 4096 {
                    return;
                }
                let mut msg_buf: HVec<u8, 4096> = HVec::new();
                msg_buf.resize(msg_len, 0).expect("msg_len <= 4096");
                if stream.read_exact(&mut msg_buf).await.is_err() {
                    return;
                }

                metrics::record_query();

                let response =
                    handle_query(&msg_buf, src, &registry_c, &resolver_c, &cache_c, &audit_c).await;

                let resp_len = (response.len() as u16).to_be_bytes();
                let _ = stream.write_all(&resp_len).await;
                let _ = stream.write_all(&response).await;
            });
        }
    }
}

/// Process a single DNS query and return wire-format response bytes.
async fn handle_query(
    request_bytes: &[u8],
    src: SocketAddr,
    registry: &Arc<RwLock<HashMap<Ipv4Addr, PolicyEntry>>>,
    resolver: &Arc<DnsResolver>,
    cache: &Arc<RwLock<DnsCache>>,
    audit: &Arc<dyn DnsAuditSink>,
) -> HVec<u8, 4096> {
    let request = match Message::from_vec(request_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            debug!(error = %e, "failed to parse DNS message");
            return build_formerr_response(request_bytes);
        }
    };

    let req_id = request.metadata.id;

    // Determine sandbox by source IP
    let guest_ip = match src.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            // IPv6 is not supported in v1; dual-stack sandboxes are deferred.
            metrics::record_denied("ipv6_unsupported", dns_action::IPV6_UNSUPPORTED);
            return build_error_response(req_id, ResponseCode::NXDomain);
        }
    };

    let policy = {
        let guard = registry.read().unwrap_or_else(|e| e.into_inner());
        guard.get(&guest_ip).cloned()
    };

    let Some(policy_entry) = policy else {
        debug!(%src, "no DNS policy for source IP");
        metrics::record_denied("no_policy", dns_action::NO_POLICY);
        return build_error_response(req_id, ResponseCode::NXDomain);
    };

    let policy = &policy_entry.policy;
    let questions = &request.queries;

    if questions.is_empty() {
        return build_error_response(req_id, ResponseCode::FormErr);
    }

    let mut response = Message::response(req_id, OpCode::Query);
    response.metadata.recursion_available = true;

    for question in questions {
        let qname = question.name().to_string();
        let qname = qname.trim_end_matches('.').to_lowercase();
        let qtype = question.query_type().to_string();
        let qname_class = classify_domain(&qname);

        // Only A records are supported; deny everything else.
        // This is intentional scoping for v1. Follow-up for AAAA, SRV, TXT
        // support should be gated behind a per-policy configuration option
        // (see acceptance criteria: "DNS decisions include safe domain
        // metadata"; full record-type matrix deferred for now).
        if qtype != "A" {
            debug!(%qname_class, %qtype, %guest_ip, "unsupported record type denied");
            metrics::record_denied("unsupported_qtype", dns_action::UNSUPPORTED_QTYPE);
            metrics::record_query_domain(&qname_class, "denied");
            metrics::record_response_code("nxdomain", &qname_class);
            response.metadata.response_code = ResponseCode::NXDomain;
            continue;
        }

        // Platform-internal domain hard deny
        if is_platform_internal_domain(&qname) {
            debug!(%qname_class, %guest_ip, "platform-internal domain denied");
            metrics::record_denied("platform_internal", dns_action::PLATFORM_INTERNAL);
            metrics::record_query_domain(&qname_class, "denied");
            metrics::record_response_code("nxdomain", &qname_class);
            audit.emit_deny(
                &DnsAuditContext::new(
                    &policy.sandbox_id,
                    &policy.tenant_id,
                    &policy.policy_decision_id,
                    policy.policy_epoch,
                    &qname_class,
                    &qtype,
                ),
                "platform-internal domain",
            );
            response.metadata.response_code = ResponseCode::NXDomain;
            continue;
        }

        let decision = policy.evaluate(&qname, &qtype);
        if !decision.allowed {
            debug!(%qname_class, %guest_ip, reason = %decision.reason, "DNS denied by policy");
            let action_label = if decision.matched_rule.is_some() {
                dns_action::DENY_RULE
            } else {
                dns_action::DEFAULT_DENY
            };
            metrics::record_denied("policy_deny", action_label);
            metrics::record_query_domain(&qname_class, "denied");
            metrics::record_response_code("nxdomain", &qname_class);
            audit.emit_deny(
                &DnsAuditContext::new(
                    &policy.sandbox_id,
                    &policy.tenant_id,
                    &policy.policy_decision_id,
                    policy.policy_epoch,
                    &qname_class,
                    &qtype,
                ),
                &decision.reason,
            );
            response.metadata.response_code = ResponseCode::NXDomain;
            continue;
        }

        // Determine whether the decision came from a specific rule or the default.
        let action_label = if decision.matched_rule.is_some() {
            dns_action::ALLOW_RULE
        } else {
            dns_action::DEFAULT_ALLOW
        };

        // Check cache
        let cached = {
            let cache_guard = cache.read().unwrap_or_else(|e| e.into_inner());
            cache_guard
                .get(&policy.sandbox_id, &qname, &qtype, policy.policy_epoch)
                .cloned()
        };

        if let Some(ref cached) = cached {
            debug!(%qname_class, "cache hit");
            metrics::record_cache_hit();
            metrics::record_allowed(action_label, "cache");
            metrics::record_query_domain(&qname_class, "allowed");
            metrics::record_response_code("noerror", &qname_class);
            add_answer_records(
                &mut response,
                question,
                &cached.addresses,
                cached.ttl.as_secs() as u32,
            );
            response.metadata.response_code = ResponseCode::NoError;
            continue;
        }

        metrics::record_cache_miss();

        let resolve_start = std::time::Instant::now();
        match resolver.resolve_a(&qname).await {
            Ok(answer) => {
                let latency = resolve_start.elapsed();
                let latency_s = latency.as_secs_f64();
                metrics::record_resolution_duration(latency_s, &qname_class);
                metrics::record_allowed(action_label, "resolved");
                metrics::record_query_domain(&qname_class, "allowed");
                metrics::record_response_code("noerror", &qname_class);

                audit.emit_allow(&DnsAuditContext::new(
                    &policy.sandbox_id,
                    &policy.tenant_id,
                    &policy.policy_decision_id,
                    policy.policy_epoch,
                    &qname_class,
                    &qtype,
                ));

                {
                    let mut cache_guard = cache.write().unwrap_or_else(|e| e.into_inner());
                    cache_guard.insert(
                        &policy.sandbox_id,
                        &qname,
                        &qtype,
                        policy.policy_epoch,
                        answer.addresses.clone(),
                        Duration::from_secs(answer.min_ttl_secs as u64),
                    );
                }

                add_answer_records(
                    &mut response,
                    question,
                    &answer.addresses,
                    answer.min_ttl_secs,
                );
                response.metadata.response_code = ResponseCode::NoError;
            }
            Err(e) => {
                warn!(%qname_class, error = %e, "upstream resolution failed");
                metrics::record_failed("upstream_failure");
                metrics::record_query_domain(&qname_class, "failed");
                metrics::record_response_code("servfail", &qname_class);
                response.metadata.response_code = ResponseCode::ServFail;
            }
        }
    }

    build_wire_response(&response)
}

/// Classify a domain into a safe suffix class for audit/metrics.
///
/// Produces strings like ".com.example" (reversed second-level + TLD)
/// for safe aggregation without exposing high-cardinality query names.
fn classify_domain(qname: &str) -> heapless::String<256> {
    use core::fmt::Write;
    use heapless::Vec as HVec;
    let mut parts: HVec<&str, 3> = HVec::new();
    for part in qname.rsplitn(3, '.') {
        let _ = parts.push(part);
    }
    if parts.len() >= 2 {
        let mut result: heapless::String<256> = heapless::String::new();
        write!(&mut result, ".{}.{}", parts[1], parts[0]).ok();
        result
    } else {
        heapless::String::<256>::try_from("unknown").unwrap_or(heapless::String::new())
    }
}

fn add_answer_records(response: &mut Message, question: &Query, addresses: &[IpAddr], ttl: u32) {
    for addr in addresses {
        if let IpAddr::V4(v4) = addr {
            let record = Record::from_rdata(question.name().clone(), ttl, RData::A(A(*v4)));
            response.add_answer(record);
        }
    }
}

fn build_error_response(id: u16, code: ResponseCode) -> HVec<u8, 4096> {
    let response = Message::error_msg(id, OpCode::Query, code);
    build_wire_response(&response)
}

fn build_formerr_response(request_bytes: &[u8]) -> HVec<u8, 4096> {
    if let Ok(request) = Message::from_vec(request_bytes) {
        build_error_response(request.metadata.id, ResponseCode::FormErr)
    } else {
        HVec::new()
    }
}

fn build_wire_response(response: &Message) -> HVec<u8, 4096> {
    match response.to_vec() {
        Ok(bytes) => HVec::from_slice(&bytes).unwrap_or(HVec::new()),
        Err(e) => {
            warn!(error = %e, "failed to serialize DNS response");
            HVec::new()
        }
    }
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver").finish_non_exhaustive()
    }
}
