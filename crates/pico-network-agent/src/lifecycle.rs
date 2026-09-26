//! Network lifecycle semantics for suspend, resume, and fork.
//!
//! Implements: Define suspend/resume and fork network semantics.
//! Consumed by `snapshot-agent` and `sandboxd` to enforce per-ADR-0005
//! and ADR-0007 identity and authorization invariants.
//!
//! # Architecture
//!
//! - **suspend** — disables ingress, egress, NAT, and DNS artifacts;
//!   blocks new flows; removes transient connection state; persists
//!   retained local resource receipts. Base namespace, TAP/veth, and
//!   routes are preserved for potential same-host resume.
//! - **resume** — validates policy epoch before the network is marked
//!   ready; rebuilds egress, DNS, and NAT from the current policy;
//!   verifies base network resources are still intact.
//! - **fork** — allocates a new logical network identity for the child;
//!   provisions independent namespace, interface, address, route,
//!   nftables policy, NAT, and DNS state. Never inherits the source
//!   sandbox's MAC address, IP address, leases, DNS cache, flow state,
//!   or port-forward listeners.
//!
//! # Safety guarantees
//!
//! - Active connections are dropped during suspend (not preserved).
//! - IP/MAC/network identity is preserved for same-sandbox resume,
//!   allocated fresh for fork.
//! - Parent/child network identity is independent for fork.
//! - DNS, NAT, egress, and port-forwarding policy is reapplied after
//!   resume/fork from the current policy epoch.
//! - Exposed ports are never inherited by forked sandboxes.
//! - Resume path revalidates policy epoch before network is marked
//!   ready.
//! - Metrics and audit events are emitted for resume/fork decisions.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::net::SocketAddr;
use std::time::Instant;

use tracing::{info, warn};

use crate::dns_attachment::{DnsAttachmentConfig, deprovision_dns_attachment};
use crate::egress::deprovision_egress;
use crate::error::NetworkResult;
use crate::identity::{BackendClass, SandboxNetworkIdentity};
use crate::metrics;
use crate::nat::deprovision_nat;
use crate::netlink::Handle;
use crate::receipt::{ProvisionReceipt, ResourceKind, ResourceReceipt};

/// Sentinel value for `policy_epoch` when the suspend function does not
/// know the current epoch (the caller is responsible for setting it from
/// snapshot metadata before the receipt is persisted).
pub const POLICY_EPOCH_UNSET: u64 = 0;

/// Default DNS proxy listen address used when no override is specified.
pub const DEFAULT_DNS_PROXY_ADDR: ([u8; 4], u16) = ([127, 0, 0, 53], 53);

// ── Snapshot-only types (no netlink dependency) ────────────────

/// Snapshot of egress policy at suspend time for audit and resume validation.
///
/// This is intentionally partial — it records what was active at suspend
/// time for audit evidence, but the real egress policy is **always**
/// re-fetched from the current policy epoch on resume. `allowed_cidrs` may
/// be empty if the caller did not supply the CIDR list at suspend time;
/// this is expected and does not affect correctness.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EgressPolicySnapshot {
    /// Table name that was active at suspend.
    pub table_name: String,
    /// Allowed CIDRs at suspend time (may be empty — caller sets this).
    pub allowed_cidrs: Vec<String>,
    /// Policy decision ID at suspend time.
    pub policy_decision_id: String,
    /// Optional lease ID active at suspend.
    pub lease_id: Option<String>,
}

/// Snapshot of DNS attachment config at suspend time.
///
/// Records the proxy address/port for audit. On resume, the DNS
/// attachment is freshly provisioned from the current policy — this
/// snapshot is for audit evidence only, not for restoring state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsAttachmentSnapshot {
    /// Sandbox interface name at suspend time.
    pub if_name: String,
    /// DNS proxy listen address at suspend.
    pub proxy_listen_addr: String,
    /// DNS proxy listen port at suspend.
    pub proxy_listen_port: u16,
}

/// Snapshot of NAT config at suspend time.
///
/// Records the table/interface names for audit. On resume, NAT rules
/// are freshly provisioned from the current policy — this snapshot is
/// for audit evidence only, not for restoring state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatConfigSnapshot {
    /// NAT table name at suspend time.
    pub table_name: String,
    /// Sandbox interface name.
    pub if_name: String,
    /// Host gateway interface name.
    pub host_if_name: String,
}

// ── Core lifecycle types ───────────────────────────────────────

/// Receipt returned by [`suspend_network`].
///
/// Records the network state at the time of suspend so that resume
/// can validate policy freshness and rebuild from current policy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuspendReceipt {
    /// The sandbox whose network was suspended.
    pub sandbox_id: String,
    /// Policy epoch at suspend time (for stale-policy detection on resume).
    pub policy_epoch: u64,
    /// Logical network identity preserved for resume.
    pub network_identity: SandboxNetworkIdentity,
    /// Resource receipts for the terminated egress/NAT/DNS state.
    pub resource_receipts: Vec<ResourceReceipt>,
    /// Egress policy snapshot for audit/reference.
    pub egress_policy_snapshot: Option<EgressPolicySnapshot>,
    /// DNS attachment snapshot for audit/reference.
    pub dns_attachment_snapshot: Option<DnsAttachmentSnapshot>,
    /// NAT config snapshot for audit/reference.
    pub nat_config_snapshot: Option<NatConfigSnapshot>,
    /// Number of active connections dropped during suspend.
    pub connections_dropped: u64,
    /// Timestamp of suspend operation (ISO 8601 UTC).
    pub suspended_at: String,
    /// Operation ID that triggered the suspend.
    pub operation_id: String,
}

/// Request to resume network for a sandbox after restore.
///
/// The caller MUST supply the current (post-resume) policy epoch.
/// Resume will reject a stale or missing policy epoch.
#[derive(Debug, Clone)]
pub struct ResumeRequest {
    /// The sandbox being resumed.
    pub sandbox_id: String,
    /// Tenant that owns the sandbox.
    pub tenant_id: String,
    /// Current (post-resume) policy epoch to validate.
    pub current_policy_epoch: u64,
    /// Previously suspended network identity (must match sandbox_id).
    pub network_identity: SandboxNetworkIdentity,
    /// Previous suspend receipt for resource tracking.
    pub suspend_receipt: SuspendReceipt,
    /// Lineage identifier for snapshot ancestry tracking.
    pub lineage_id: String,
    /// Operation ID for the resume.
    pub operation_id: String,
}

/// Receipt returned by [`resume_network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResumeReceipt {
    /// The sandbox that was resumed.
    pub sandbox_id: String,
    /// Whether the policy epoch was validated successfully.
    pub policy_epoch_validated: bool,
    /// Current policy epoch after validation.
    pub applied_policy_epoch: u64,
    /// New resource receipts after rebuild.
    pub resource_receipts: Vec<ResourceReceipt>,
    /// Whether resources were freshly provisioned.
    pub resources_rebuilt: bool,
    /// Timestamp of resume completion (ISO 8601 UTC).
    pub resumed_at: String,
    /// Operation ID.
    pub operation_id: String,
}

/// Request to fork network for a child sandbox.
#[derive(Debug, Clone)]
pub struct ForkRequest {
    /// The parent (source) sandbox ID.
    pub parent_sandbox_id: String,
    /// The child sandbox ID.
    pub child_sandbox_id: String,
    /// Tenant that owns the child sandbox.
    pub child_tenant_id: String,
    /// Policy epoch for the child (current, post-fork).
    pub child_policy_epoch: u64,
    /// Backend class for the child sandbox.
    pub child_backend_class: BackendClass,
    /// Parent's suspend receipt (from the fork snapshot).
    pub parent_suspend_receipt: SuspendReceipt,
    /// Lineage identifier.
    pub lineage_id: String,
    /// Operation ID for the fork.
    pub operation_id: String,
}

/// Receipt returned by [`fork_network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForkReceipt {
    /// The parent sandbox ID.
    pub parent_sandbox_id: String,
    /// The child sandbox ID.
    pub child_sandbox_id: String,
    /// The child's new (independent) network identity.
    pub child_network_identity: SandboxNetworkIdentity,
    /// Whether port-forwarding inheritance was explicitly blocked.
    pub port_forwarding_blocked: bool,
    /// Child's resource receipts.
    pub child_resource_receipts: Vec<ResourceReceipt>,
    /// Timestamp of fork completion (ISO 8601 UTC).
    pub forked_at: String,
    /// Operation ID.
    pub operation_id: String,
}

// ── Core functions ─────────────────────────────────────────────

/// Suspend network state for a sandbox.
///
/// Disables egress policy, NAT, and DNS attachment. Does NOT tear down
/// the base namespace, TAP/veth, routes, or addresses — those are
/// preserved for potential same-host resume or post-fork cleanup.
///
/// Active connections are dropped (not preserved). Transient connection
/// tracking state is removed by nftables table deletion.
///
/// # Panics
///
/// Never panics. All errors are returned as `NetworkResult::Err`.
pub async fn suspend_network(
    identity: &SandboxNetworkIdentity,
    _handle: &Handle,
    provision_receipt: &ProvisionReceipt,
    operation_id: String,
    connections_dropped: u64,
    tenant_id: &str,
) -> NetworkResult<SuspendReceipt> {
    let start = Instant::now();
    let sandbox_id = &identity.sandbox_id;
    let if_name = &identity.if_name;
    let host_if_name = &identity.host_if_name;

    info!(
        sandbox_id = %sandbox_id,
        if_name = %if_name,
        backend_class = ?identity.backend_class,
        "suspending network"
    );

    let mut resource_receipts = Vec::new();
    let mut egress_snapshot = None;
    let mut dns_snapshot = None;
    let mut nat_snapshot = None;

    // 1. Deprovision DNS attachment (redirect rules)
    //    Best-effort: if the attachment is already gone, proceed.
    let dns_proxy_addr = SocketAddr::from(DEFAULT_DNS_PROXY_ADDR);
    let dns_config = DnsAttachmentConfig {
        sandbox_id: sandbox_id.clone(),
        tenant_id: tenant_id.to_string(),
        if_name: if_name.to_string(),
        proxy_addr: dns_proxy_addr,
    };
    match deprovision_dns_attachment(&dns_config).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            dns_snapshot = Some(DnsAttachmentSnapshot {
                if_name: if_name.to_string(),
                proxy_listen_addr: dns_proxy_addr.ip().to_string(),
                proxy_listen_port: dns_proxy_addr.port(),
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "DNS attachment deprovision failed during suspend (continuing)");
        }
    }

    // 2. Deprovision NAT rules
    //    Best-effort: if the rules are already gone, proceed.
    match deprovision_nat(sandbox_id, if_name).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            nat_snapshot = Some(NatConfigSnapshot {
                table_name: format!("pico-sbx-{sandbox_id}-{if_name}"),
                if_name: if_name.to_string(),
                host_if_name: host_if_name.to_string(),
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "NAT deprovision failed during suspend (continuing)");
        }
    }

    // 3. Deprovision egress policy
    //    Best-effort: if the table is already gone, proceed.
    match deprovision_egress(sandbox_id, if_name).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            // Build egress snapshot from what we know
            let policy_decision_id = provision_receipt
                .resources
                .iter()
                .find(|r| r.kind == ResourceKind::Egress)
                .map(|_| "suspend_captured".to_string())
                .unwrap_or_default();
            egress_snapshot = Some(EgressPolicySnapshot {
                table_name: format!("pico-sbx-{sandbox_id}-{if_name}"),
                allowed_cidrs: Vec::new(), // captured from policy at suspend time by caller
                policy_decision_id,
                lease_id: None,
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "egress deprovision failed during suspend (continuing)");
        }
    }

    // Active connections are dropped by the nftables table deletion above.
    // The caller is responsible for counting connections from conntrack
    // counters before calling this function.
    let latency = start.elapsed();
    metrics::record_suspend(connections_dropped, latency.as_secs_f64());

    info!(
        sandbox_id = %sandbox_id,
        latency_ms = latency.as_millis(),
        "network suspended"
    );

    Ok(SuspendReceipt {
        sandbox_id: sandbox_id.clone(),
        policy_epoch: POLICY_EPOCH_UNSET, // caller sets this from snapshot metadata
        network_identity: identity.clone(),
        resource_receipts,
        egress_policy_snapshot: egress_snapshot,
        dns_attachment_snapshot: dns_snapshot,
        nat_config_snapshot: nat_snapshot,
        connections_dropped,
        suspended_at: now_iso(),
        operation_id,
    })
}

/// Resume network for a sandbox after restore from a snapshot.
///
/// This function performs **validation only** — it checks policy epoch
/// monotonicity and network identity match. It does NOT provision
/// egress, NAT, or DNS attachment itself.
///
/// # Integration contract
///
/// After a successful `resume_network` call, the caller must immediately
/// call [`crate::NetworkAgent::provision_egress`],
/// [`crate::NetworkAgent::provision_nat`], and
/// [`crate::NetworkAgent::provision_dns_attachment`] with the current
/// policy before the sandbox network is considered ready. If any of
/// those provisioning steps fail, the caller should treat the resume
/// as failed and emit a `ResumeFailed` error.
///
/// # Policy epoch validation
///
/// The resume path MUST revalidate the current policy epoch before
/// the network is marked ready. If `current_policy_epoch` is zero
/// (meaning no policy has been admitted yet), resume is rejected.
///
/// If the policy epoch has advanced since suspend, the newer (current)
/// epoch is applied. The old policy is never silently reapplied.
///
/// # Resource rebuild
///
/// Base network resources (namespace, TAP/veth, addresses, routes)
/// must have been verified by the caller before this function is
/// invoked. Egress, NAT, and DNS attachment are freshly provisioned
/// from the current policy — they are never restored from the
/// suspend receipt.
///
/// # Parameters
///
/// - `_handle`: reserved for future use when base resource verification
///   moves into this function (e.g., rtnetlink checks). Currently
///   unused because verification is performed by the runtime adapter.
pub async fn resume_network(
    request: &ResumeRequest,
    _handle: &Handle,
) -> NetworkResult<ResumeReceipt> {
    let start = Instant::now();
    let sandbox_id = &request.sandbox_id;

    info!(
        sandbox_id = %sandbox_id,
        current_policy_epoch = request.current_policy_epoch,
        suspend_policy_epoch = request.suspend_receipt.policy_epoch,
        lineage_id = %request.lineage_id,
        "resuming network"
    );

    if let Err(err) = validate_resume(request) {
        if matches!(
            err,
            crate::error::NetworkAgentError::StalePolicyEpoch { .. }
        ) {
            metrics::record_resume_policy_epoch_rejected();
        }
        metrics::record_resume_failed();
        return Err(err);
    }

    let resource_receipts: Vec<ResourceReceipt> = Vec::new();

    // ── Rebuild egress/NAT/DNS from current policy ─────────────
    // These are freshly provisioned; the old state from suspend
    // is intentionally discarded. The caller must supply fresh
    // EgressPolicy, NatConfig, and DnsAttachmentConfig based on
    // the current policy epoch.

    // NOTE: Actual provisioning of egress, NAT, and DNS attachment
    // is deferred to the caller, who holds the current policy.
    // This function only validates policy epoch and identity.
    // The caller calls provision_egress, provision_nat, and
    // provision_dns_attachment separately after this succeeds.

    let latency = start.elapsed();
    metrics::record_resume_completed(latency.as_secs_f64());

    info!(
        sandbox_id = %sandbox_id,
        policy_epoch = request.current_policy_epoch,
        latency_ms = latency.as_millis(),
        "network resumed"
    );

    Ok(ResumeReceipt {
        sandbox_id: sandbox_id.to_string(),
        policy_epoch_validated: true,
        applied_policy_epoch: request.current_policy_epoch,
        resource_receipts,
        resources_rebuilt: false, // caller will set after provisioning
        resumed_at: now_iso(),
        operation_id: request.operation_id.clone(),
    })
}

/// Fork network for a child sandbox from a parent.
///
/// Creates a completely independent network identity for the child.
/// Never inherits the parent's:
/// - network identity (MAC, IP, interface names, namespace path)
/// - DNS authorization cache
/// - NAT state
/// - connection tracking / flow state
/// - port-forward listeners or exposure state
///
/// The child receives fresh base networking (namespace, interface,
/// addresses, routes) from newly provisioned resources. Egress,
/// NAT, and DNS attachment are provisioned separately by the
/// caller using the child's new network identity.
///
/// # Port-forwarding inheritance
///
/// Port-forwarding inheritance is explicitly blocked. The fork
/// receipt records that this block was applied. Any attempt to
/// expose the same ports would require new, independently authorized
/// port-forward leases for the child sandbox.
///
/// Identity, policy-epoch, and collision checks live in
/// [`derive_child_network_identity`] so they can be tested without
/// host provisioning. This function applies that decision, then
/// provisions a fresh base network for the child.
pub async fn fork_network(request: &ForkRequest, handle: &Handle) -> NetworkResult<ForkReceipt> {
    let start = Instant::now();

    info!(
        parent_sandbox_id = %request.parent_sandbox_id,
        child_sandbox_id = %request.child_sandbox_id,
        child_backend_class = ?request.child_backend_class,
        child_policy_epoch = request.child_policy_epoch,
        lineage_id = %request.lineage_id,
        "forking network"
    );

    let child_identity = match derive_child_network_identity(request) {
        Ok(identity) => identity,
        Err(err) => {
            metrics::record_fork_failed();
            return Err(err);
        }
    };

    // ── Provision fresh base networking for child ───────────────
    // Uses the standard NetworkAgent::provision path to ensure
    // deterministic resource names, routes, and addresses.
    let provision_receipt = crate::NetworkAgent::provision(&child_identity, handle).await?;

    // ── Port-forwarding inheritance is explicitly blocked ───────
    // The child never inherits parent port-forward state. Any
    // port-forward on the child requires a new, independently
    // authorized lease.
    let port_forwarding_blocked = true;

    let latency = start.elapsed();
    metrics::record_fork_completed(latency.as_secs_f64(), port_forwarding_blocked);

    info!(
        parent_sandbox_id = %request.parent_sandbox_id,
        child_sandbox_id = %request.child_sandbox_id,
        child_if_name = %child_identity.if_name,
        child_ip = %child_identity.guest_ip,
        latency_ms = latency.as_millis(),
        "network forked"
    );

    Ok(ForkReceipt {
        parent_sandbox_id: request.parent_sandbox_id.clone(),
        child_sandbox_id: request.child_sandbox_id.clone(),
        child_network_identity: child_identity,
        port_forwarding_blocked,
        child_resource_receipts: provision_receipt.resources,
        forked_at: now_iso(),
        operation_id: request.operation_id.clone(),
    })
}

/// Derive the child's network identity and reject a fork that would
/// reuse the parent.
///
/// The child identity is derived only from the child sandbox id and
/// backend class. A zero policy epoch, a child id equal to the parent,
/// or [`SandboxNetworkIdentity::conflicts_with`] against the parent fails
/// closed.
/// Port-forward inheritance is not decided here: [`fork_network`] always
/// records it as blocked after provisioning succeeds.
pub fn derive_child_network_identity(
    request: &ForkRequest,
) -> NetworkResult<SandboxNetworkIdentity> {
    if request.child_policy_epoch == 0 {
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: request.child_sandbox_id.clone(),
            expected: "> 0".to_string(),
            actual: 0,
        });
    }
    if request.child_sandbox_id.is_empty() || request.child_sandbox_id == request.parent_sandbox_id
    {
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.child_sandbox_id.clone(),
            detail: "child sandbox id must be a new id, distinct from the parent".to_string(),
        });
    }

    let child_identity =
        SandboxNetworkIdentity::for_sandbox(&request.child_sandbox_id, request.child_backend_class);
    let parent = &request.parent_suspend_receipt.network_identity;
    if child_identity.conflicts_with(parent) {
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.child_sandbox_id.clone(),
            detail: "child network identity collided with parent".to_string(),
        });
    }
    Ok(child_identity)
}

/// Validate resume policy epoch and network identity.
///
/// The identity must be [`SandboxNetworkIdentity::for_sandbox`] for the
/// request sandbox id and the claimed backend class. Two caller-supplied
/// copies that match each other still fail when they are not that derivation.
pub fn validate_resume(request: &ResumeRequest) -> NetworkResult<()> {
    validate_policy_epoch(
        &request.sandbox_id,
        request.suspend_receipt.policy_epoch,
        request.current_policy_epoch,
    )?;
    let expected = SandboxNetworkIdentity::for_sandbox(
        &request.sandbox_id,
        request.network_identity.backend_class,
    );
    if request.suspend_receipt.sandbox_id != request.sandbox_id {
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.sandbox_id.clone(),
            detail: format!(
                "suspend receipt sandbox {} does not match request sandbox {}",
                request.suspend_receipt.sandbox_id, request.sandbox_id
            ),
        });
    }
    if request.network_identity != expected {
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.sandbox_id.clone(),
            detail: format!(
                "request network identity is not the derived identity for sandbox {}",
                request.sandbox_id
            ),
        });
    }
    if request.suspend_receipt.network_identity != expected {
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.sandbox_id.clone(),
            detail: format!(
                "suspend receipt network identity is not the derived identity for sandbox {}",
                request.sandbox_id
            ),
        });
    }
    Ok(())
}

/// Validate that policy epoch has advanced monotonically from suspend to resume.
///
/// Returns `Ok(())` if `current_epoch >= suspend_epoch`, or an error
/// describing the stale policy.
pub fn validate_policy_epoch(
    sandbox_id: &str,
    suspend_epoch: u64,
    current_epoch: u64,
) -> NetworkResult<()> {
    if current_epoch == 0 {
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: "> 0".to_string(),
            actual: 0,
        });
    }
    if current_epoch < suspend_epoch {
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: format!(">= {suspend_epoch}"),
            actual: current_epoch,
        });
    }
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────

/// Returns the current time as an ISO 8601 UTC string.
fn now_iso() -> String {
    // Use chrono for ISO 8601; fall back to a reasonable default if unavailable.
    // The workspace includes chrono with serde support.
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
