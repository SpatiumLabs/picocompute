//! Per-sandbox network provision ownership for sandboxd.
//!
//! sandboxd is the only caller of the network-agent pipeline. Runtime adapters
//! attach pre-created TAP/veth devices and do not create host network objects.
//! Tests inject a fake provisioner so ledger ownership can be verified without
//! kernel privileges.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pico_core::ResourceReceipt;
use pico_network_agent::error::NetworkAgentError;
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};
use pico_network_agent::receipt::{CleanupReceipt, ProvisionReceipt};
use pico_network_agent::{NetworkAgent, ProvisionExtras};
use tonic::async_trait;

/// Performs kernel-level network provisioning for a sandbox.
///
/// Production uses [`NetworkAgent`]. Tests inject a fake so TAP/veth receipts
/// land in the ledger without `CAP_NET_ADMIN`.
#[async_trait]
pub trait NetworkProvisioner: Send + Sync {
    /// Creates TAP/veth/route (and optional extras) and returns the pipeline receipt.
    async fn provision(
        &self,
        identity: &SandboxNetworkIdentity,
    ) -> Result<ProvisionReceipt, String>;

    /// Removes network objects for `identity`. Idempotent.
    async fn deprovision(
        &self,
        identity: &SandboxNetworkIdentity,
        receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt;
}

struct NetworkAgentProvisioner;

#[async_trait]
impl NetworkProvisioner for NetworkAgentProvisioner {
    async fn provision(
        &self,
        identity: &SandboxNetworkIdentity,
    ) -> Result<ProvisionReceipt, String> {
        let (conn, handle) =
            pico_network_agent::netlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        match NetworkAgent::provision_all(identity, &handle, &ProvisionExtras::default()).await {
            Ok(receipt) => Ok(receipt),
            Err(NetworkAgentError::UnsupportedPlatform) => Ok(synthetic_receipt(identity)),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn deprovision(
        &self,
        identity: &SandboxNetworkIdentity,
        receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt {
        match pico_network_agent::netlink::new_connection() {
            Ok((conn, handle)) => {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                NetworkAgent::deprovision(identity, &handle, receipt).await
            }
            Err(_) => CleanupReceipt::new(identity.sandbox_id.clone()),
        }
    }
}

/// Owns live network provision state and maps pipeline receipts into the ledger.
pub struct NetworkAttachManager {
    enabled: bool,
    active: RwLock<hashbrown::HashMap<String, ActiveNetwork>>,
    provisioner: Arc<dyn NetworkProvisioner>,
}

struct ActiveNetwork {
    identity: SandboxNetworkIdentity,
    receipt: ProvisionReceipt,
}

impl NetworkAttachManager {
    /// Builds an enabled manager that calls [`NetworkAgent`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            active: RwLock::new(hashbrown::HashMap::default()),
            provisioner: Arc::new(NetworkAgentProvisioner),
        }
    }

    /// Overrides the provisioning backend (used by tests).
    #[must_use]
    pub fn with_provisioner(mut self, provisioner: Arc<dyn NetworkProvisioner>) -> Self {
        self.enabled = true;
        self.provisioner = provisioner;
        self
    }

    /// Creates a disabled manager (no TAP/veth creation).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            active: RwLock::new(hashbrown::HashMap::default()),
            provisioner: Arc::new(NetworkAgentProvisioner),
        }
    }

    /// Whether the pipeline will create host network objects.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Provisions TAP/veth/route for a sandbox and returns ledger receipts.
    ///
    /// No-op when disabled. On partial kernel failure the provisioner rolls
    /// back before this method returns an error.
    pub async fn provision(
        &self,
        sandbox_id: &str,
        backend_class: BackendClass,
    ) -> Result<Vec<ResourceReceipt>, String> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let identity = SandboxNetworkIdentity::for_sandbox(sandbox_id, backend_class);
        let net_receipt = self.provisioner.provision(&identity).await?;
        let ledger: Vec<ResourceReceipt> = net_receipt
            .resources
            .iter()
            .filter(|r| r.created)
            .map(pico_network_agent::receipt::ResourceReceipt::to_ledger)
            .collect();

        self.active.write().insert(
            sandbox_id.into(),
            ActiveNetwork {
                identity,
                receipt: net_receipt,
            },
        );

        tracing::info!(sandbox_id = %sandbox_id, receipts = ledger.len(), "network pipeline provisioned by sandboxd");
        Ok(ledger)
    }

    /// Deprovisions network objects and returns released ledger names.
    ///
    /// After a sandboxd restart the in-memory map is empty; identity is
    /// derived so cleanup still runs when this manager is enabled.
    pub async fn deprovision(&self, sandbox_id: &str, backend_class: BackendClass) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let active = self.active.write().remove(sandbox_id);
        let (identity, receipt) = match active {
            Some(active) => (active.identity, Some(active.receipt)),
            None => (
                SandboxNetworkIdentity::for_sandbox(sandbox_id, backend_class),
                None,
            ),
        };

        let cleanup = self
            .provisioner
            .deprovision(&identity, receipt.as_ref())
            .await;
        let mut names: Vec<String> = cleanup
            .resources_removed
            .into_iter()
            .map(|r| r.resource_name)
            .collect();
        names.extend(cleanup.resources_absent);

        tracing::info!(sandbox_id = %sandbox_id, "network pipeline deprovisioned by sandboxd");
        names
    }
}

impl Default for NetworkAttachManager {
    fn default() -> Self {
        Self::disabled()
    }
}

fn synthetic_receipt(identity: &SandboxNetworkIdentity) -> ProvisionReceipt {
    let kind = match identity.backend_class {
        BackendClass::MicroVm => pico_network_agent::receipt::ResourceKind::Tap,
        BackendClass::Container => pico_network_agent::receipt::ResourceKind::Veth,
    };
    let mut receipt = ProvisionReceipt::new(identity.sandbox_id.clone(), identity.backend_class, 1);
    receipt.push(pico_network_agent::receipt::ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: identity.if_name.clone(),
        kind,
        created: true,
        provision_latency: Duration::ZERO,
    });
    receipt.finalize(Duration::ZERO);
    receipt
}
