//! Typed network provisioning and cleanup errors.

use thiserror::Error;

pub type NetworkResult<T> = std::result::Result<T, NetworkAgentError>;

#[derive(Debug, Error)]
pub enum NetworkAgentError {
    #[error("TAP device creation failed for {tap_name}: {source}")]
    TapCreate {
        tap_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("TAP device deletion failed for {tap_name}: {source}")]
    TapDelete {
        tap_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("TAP device {tap_name} not found during cleanup")]
    TapNotFound { tap_name: String },

    #[error("veth pair creation failed for {veth_name}: {source}")]
    VethCreate {
        veth_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("veth peer setup failed for {veth_name}: {source}")]
    VethPeerSetup {
        veth_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("network namespace creation failed for {ns_name}: {source}")]
    NamespaceCreate {
        ns_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("network namespace {ns_name} not found during cleanup")]
    NamespaceNotFound { ns_name: String },

    #[error("network namespace deletion failed for {ns_name}: {source}")]
    NamespaceDelete {
        ns_name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("route addition failed for {interface}: {source}")]
    RouteAdd {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("route deletion failed for {interface}: {source}")]
    RouteDelete {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("link set up failed for {interface}: {source}")]
    LinkUp {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("address assignment failed for {interface}/{addr}: {source}")]
    AddressAssign {
        interface: String,
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "partial provisioning state: {completed} of {total} objects created before failure: {reason}"
    )]
    PartialProvisioning {
        completed: usize,
        total: usize,
        reason: String,
    },

    #[error("netlink error: {0}")]
    Netlink(String),

    #[error("sandbox identity missing field: {field}")]
    IdentityMissing { field: &'static str },

    #[error("provisioning not supported on this platform")]
    UnsupportedPlatform,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("nftables operation failed: {operation}: {detail}")]
    Nftables { operation: String, detail: String },

    #[error("egress policy denied for sandbox {sandbox_id}: {reason}")]
    EgressDenied { sandbox_id: String, reason: String },

    #[error("egress policy setup failed for sandbox {sandbox_id}: {detail}")]
    EgressSetupFailed { sandbox_id: String, detail: String },

    #[error("egress policy cleanup failed for sandbox {sandbox_id}: {detail}")]
    EgressCleanupFailed { sandbox_id: String, detail: String },

    #[error("NAT setup failed for sandbox {sandbox_id}: {detail}")]
    NatSetupFailed { sandbox_id: String, detail: String },

    #[error("NAT teardown failed for sandbox {sandbox_id}: {detail}")]
    NatTeardownFailed { sandbox_id: String, detail: String },

    #[error("invalid CIDR notation: {cidr}")]
    InvalidCidr { cidr: String },

    #[error("egress lease not found or invalid: {lease_id}")]
    EgressLeaseInvalid { lease_id: String },

    #[error("no egress lease authorization for sandbox {sandbox_id}")]
    EgressLeaseRequired { sandbox_id: String },

    #[error("DNS attachment setup failed for sandbox {sandbox_id}: {detail}")]
    DnsAttachmentFailed { sandbox_id: String, detail: String },

    // ── Lifecycle (suspend/resume/fork) errors ───────────────
    /// Returned by `resume_network` and `validate_policy_epoch` when
    /// the current policy epoch is zero (unset) or older than the
    /// suspend epoch.
    #[error("stale policy epoch for sandbox {sandbox_id}: expected {expected}, got {actual}")]
    StalePolicyEpoch {
        sandbox_id: String,
        expected: String,
        actual: u64,
    },

    /// Returned by `resume_network` when the network identity in the
    /// resume request does not match the expected sandbox.
    #[error("network identity conflict for sandbox {sandbox_id}: {detail}")]
    IdentityConflict { sandbox_id: String, detail: String },

    /// Produced by higher-level orchestration (`snapshot-agent` /
    /// `sandboxd`) when a fork attempt would inherit port-forwarding
    /// state from the parent sandbox. The `lifecycle` module records
    /// the block in `ForkReceipt`; callers raise the error.
    #[error(
        "port-forwarding inheritance blocked for child sandbox {child_sandbox_id} (parent: {parent_sandbox_id}): {detail}"
    )]
    PortInheritanceBlocked {
        parent_sandbox_id: String,
        child_sandbox_id: String,
        detail: String,
    },

    /// Produced by higher-level orchestration when a resumed sandbox
    /// attempts to re-establish connections that were dropped during
    /// suspend. Connections are always dropped; this error signals
    /// that reconnect is not supported.
    #[error(
        "active connections cannot be re-established for sandbox {sandbox_id} after suspend/resume: {detail}"
    )]
    ReconnectFailed { sandbox_id: String, detail: String },

    /// Produced by higher-level orchestration when the suspend
    /// operation fails at the snapshot or fencing layer, beyond
    /// the best-effort deprovision performed by `suspend_network`.
    #[error("network suspend failed for sandbox {sandbox_id}: {detail}")]
    SuspendFailed { sandbox_id: String, detail: String },

    /// Produced by higher-level orchestration when `resume_network`
    /// succeeds but subsequent egress/NAT/DNS provisioning fails.
    #[error("network resume failed for sandbox {sandbox_id}: {detail}")]
    ResumeFailed { sandbox_id: String, detail: String },

    /// Produced by higher-level orchestration when `fork_network`
    /// succeeds but subsequent policy provisioning fails for the
    /// child sandbox.
    #[error(
        "network fork failed for parent {parent_sandbox_id} -> child {child_sandbox_id}: {detail}"
    )]
    ForkFailed {
        parent_sandbox_id: String,
        child_sandbox_id: String,
        detail: String,
    },

    // ── Reconciliation errors ──────────────────────────────
    /// Returned when reconciliation discovers ambiguous resources
    /// whose ownership cannot be resolved automatically.
    #[error("ambiguous network resource {resource_name}: {detail}")]
    AmbiguousResource {
        resource_name: String,
        detail: String,
    },

    /// Returned when cleanup of a stale resource fails during
    /// reconciliation. The resource is marked for operator review.
    #[error("stale resource cleanup failed for {resource_name}: {detail}")]
    StaleResourceCleanupFailed {
        resource_name: String,
        detail: String,
    },

    /// Returned when the reconciliation pass itself fails due to
    /// an unrecoverable error (e.g. netlink socket exhaustion).
    #[error("reconciliation pass failed: {detail}")]
    ReconciliationPassFailed { detail: String },

    // ── Bandwidth shaping errors ────────────────────────
    /// Returned when bandwidth limit validation fails.
    #[error("invalid bandwidth limit for sandbox {sandbox_id}: {limit_bps} bps -- {reason}")]
    BandwidthLimitInvalid {
        sandbox_id: String,
        limit_bps: u64,
        reason: String,
    },

    /// Returned when bandwidth shaping setup fails.
    #[error("bandwidth shaping setup failed for sandbox {sandbox_id}: {detail}")]
    BandwidthSetupFailed { sandbox_id: String, detail: String },

    /// Returned when a tc command execution fails.
    #[error("bandwidth tc command failed ({operation}): {detail}")]
    BandwidthTcExec { operation: String, detail: String },

    /// Returned when bandwidth shaping cleanup fails.
    #[error("bandwidth shaping cleanup failed for sandbox {sandbox_id}: {detail}")]
    BandwidthCleanupFailed { sandbox_id: String, detail: String },
    /// Returned when eBPF program loading fails.
    #[error("eBPF program load failed: {detail}")]
    EbpfLoadFailed { detail: String },

    /// Returned when eBPF program attachment to an interface fails.
    #[error("eBPF program attach failed for interface {if_name}: {detail}")]
    EbpfAttachFailed { if_name: String, detail: String },

    /// Returned when eBPF program detachment from an interface fails.
    #[error("eBPF program detach failed for interface {if_name}: {detail}")]
    EbpfDetachFailed { if_name: String, detail: String },

    /// Returned when eBPF map operations fail.
    #[error("eBPF map operation failed: {detail}")]
    EbpfMapError { detail: String },

    /// Returned when eBPF networking is not supported on this platform.
    #[error("eBPF networking not available on this platform")]
    EbpfUnavailable,
}
