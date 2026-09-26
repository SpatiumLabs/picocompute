//! DNS proxy attach ownership for sandboxd.
//!
//! sandboxd owns DNS proxy attach receipts in the durable ledger. The DNS
//! proxy process itself may run in sandboxd (default for).

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use pico_core::ResourceReceipt;
use pico_network_agent::dns::resolver::DnsResolver;
use pico_network_agent::dns::{DnsAction, DnsPolicy, DnsProxy, DnsProxyConfig, NoopDnsAuditSink};
use pico_network_agent::dns_attachment::DnsAttachmentConfig;
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};
use pico_network_agent::receipt::ResourceReceipt as NetworkResourceReceipt;
use tonic::async_trait;

/// Performs the kernel-level DNS redirect provisioning for a sandbox.
///
/// sandboxd owns the DNS attach receipts in the durable ledger; the
/// provisioner implements the platform mechanics (nftables on Linux).
/// Tests inject a fake provisioner so ledger ownership can be verified
/// without requiring kernel privileges.
#[async_trait]
pub trait DnsAttachProvisioner: Send + Sync {
    /// Installs the sandbox DNS redirect and returns platform receipts.
    async fn provision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String>;

    /// Removes the sandbox DNS redirect and returns platform receipts.
    async fn deprovision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String>;
}

/// nftables-based provisioner used in production.
struct NftablesProvisioner;

#[async_trait]
impl DnsAttachProvisioner for NftablesProvisioner {
    async fn provision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        provision_dns(config).await
    }

    async fn deprovision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        deprovision_dns(config).await
    }
}

/// Configuration for DNS attach ownership inside sandboxd.
#[derive(Debug, Clone, Default)]
pub struct DnsAttachConfig {
    /// When set, sandboxd starts a DNS policy proxy on this address.
    pub listen_addr: Option<SocketAddr>,
}

/// Per-sandbox DNS attach bookkeeping held only while the sandbox is live.
#[derive(Debug, Clone)]
struct ActiveDnsAttach {
    config: DnsAttachmentConfig,
    guest_ip: std::net::Ipv4Addr,
}

/// Owns the optional DNS proxy and live attach state for GC/destroy.
pub struct DnsAttachManager {
    proxy: Option<Arc<DnsProxy>>,
    active: RwLock<hashbrown::HashMap<String, ActiveDnsAttach>>,
    provisioner: Arc<dyn DnsAttachProvisioner>,
}

impl DnsAttachManager {
    /// Builds a manager. When `listen_addr` is set, starts the DNS proxy.
    #[must_use]
    pub fn new(config: DnsAttachConfig) -> Self {
        let proxy = config.listen_addr.map(init_dns_proxy);
        Self {
            proxy,
            active: RwLock::new(hashbrown::HashMap::default()),
            provisioner: Arc::new(NftablesProvisioner),
        }
    }

    /// Overrides the provisioning backend (used by tests and alternate platforms).
    #[must_use]
    pub fn with_provisioner(mut self, provisioner: Arc<dyn DnsAttachProvisioner>) -> Self {
        self.provisioner = provisioner;
        self
    }

    /// Creates a disabled manager (no proxy, no attach).
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(DnsAttachConfig::default())
    }

    /// Whether DNS attach is available (proxy configured).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.proxy.is_some()
    }

    /// Returns the proxy listen address when configured.
    #[must_use]
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.proxy.as_ref().map(|p| p.listen_addr())
    }

    /// Provisions DNS attach for a sandbox and records ledger receipts.
    ///
    /// No-op when DNS is disabled. On Linux this installs nftables redirects
    /// and registers a default-deny DNS policy with the proxy.
    pub async fn attach(
        &self,
        sandbox_id: &str,
        tenant_id: &str,
        backend_class: BackendClass,
        policy_epoch: u64,
    ) -> Result<Vec<ResourceReceipt>, String> {
        let Some(proxy) = &self.proxy else {
            return Ok(Vec::new());
        };

        let identity = SandboxNetworkIdentity::for_sandbox(sandbox_id, backend_class);
        let dns_config = DnsAttachmentConfig {
            sandbox_id: sandbox_id.into(),
            tenant_id: if tenant_id.is_empty() {
                "unknown".into()
            } else {
                tenant_id.into()
            },
            if_name: identity.if_name.clone(),
            proxy_addr: proxy.listen_addr(),
        };

        let net_receipts = self.provisioner.provision(&dns_config).await?;
        let policy = DnsPolicy {
            tenant_id: dns_config.tenant_id.clone(),
            sandbox_id: sandbox_id.into(),
            policy_decision_id: "dns-default-deny".into(),
            policy_epoch,
            workload_class: None,
            rules: vec![],
            default_action: DnsAction::Deny,
        };
        proxy.register_policy(identity.guest_ip, policy);

        self.active.write().insert(
            sandbox_id.into(),
            ActiveDnsAttach {
                config: dns_config,
                guest_ip: identity.guest_ip,
            },
        );

        let mut receipts = Vec::with_capacity(net_receipts.len().max(1));
        for r in net_receipts {
            receipts.push(ResourceReceipt {
                class: "dns_attachment".into(),
                name: r.resource_name,
                external_id: Some(format!("proxy={}", proxy.listen_addr())),
            });
        }
        if receipts.is_empty() {
            // Non-Linux or dry platforms still record ownership for ledger parity.
            receipts.push(ResourceReceipt {
                class: "dns_attachment".into(),
                name: format!("dns-attachment-{}", proxy.listen_addr()),
                external_id: Some(format!("proxy={}", proxy.listen_addr())),
            });
        }

        tracing::info!(
            sandbox_id = %sandbox_id,
            guest_ip = %identity.guest_ip,
            "DNS attachment provisioned by sandboxd"
        );
        Ok(receipts)
    }

    /// Deprovisions DNS attach and unregisters the proxy policy.
    ///
    /// Returns resource names that were released for ledger marking.
    pub async fn detach(&self, sandbox_id: &str) -> Vec<String> {
        let Some(active) = self.active.write().remove(sandbox_id) else {
            return Vec::new();
        };

        if let Some(proxy) = &self.proxy {
            proxy.unregister_policy(active.guest_ip);
        }

        let names = match self.provisioner.deprovision(&active.config).await {
            Ok(receipts) => {
                let mut names: Vec<String> =
                    receipts.into_iter().map(|r| r.resource_name).collect();
                if names.is_empty() {
                    names.push(format!("dns-attachment-{}", active.config.proxy_addr));
                }
                names
            }
            Err(err) => {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "DNS attachment deprovision failed"
                );
                vec![format!("dns-attachment-{}", active.config.proxy_addr)]
            }
        };

        tracing::info!(sandbox_id = %sandbox_id, "DNS attachment deprovisioned by sandboxd");
        names
    }
}

fn init_dns_proxy(listen_addr: SocketAddr) -> Arc<DnsProxy> {
    tracing::info!(%listen_addr, "initializing sandboxd DNS policy proxy");
    let resolver = match DnsResolver::from_system_config() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to build DNS resolver from system config; using fallback resolver"
            );
            DnsResolver::from_fallback()
        }
    };
    let proxy = Arc::new(DnsProxy::new(
        DnsProxyConfig { listen_addr },
        resolver,
        Arc::new(NoopDnsAuditSink),
    ));
    let _handle = proxy.spawn();
    proxy
}

#[cfg(target_os = "linux")]
async fn provision_dns(
    config: &DnsAttachmentConfig,
) -> Result<Vec<NetworkResourceReceipt>, String> {
    pico_network_agent::NetworkAgent::provision_dns_attachment(config)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
async fn provision_dns(
    _config: &DnsAttachmentConfig,
) -> Result<Vec<NetworkResourceReceipt>, String> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
async fn deprovision_dns(
    config: &DnsAttachmentConfig,
) -> Result<Vec<NetworkResourceReceipt>, String> {
    pico_network_agent::NetworkAgent::deprovision_dns_attachment(config)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
async fn deprovision_dns(
    _config: &DnsAttachmentConfig,
) -> Result<Vec<NetworkResourceReceipt>, String> {
    Ok(Vec::new())
}
