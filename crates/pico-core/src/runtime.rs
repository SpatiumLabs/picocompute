//! Backend-neutral runtime lifecycle contracts.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{ExecRequest, ExecResponse, SandboxConfig, SandboxError, SandboxState, now_iso};

/// Runtime implementation selected for a sandbox.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    strum::Display,
    strum::EnumString,
    strum::VariantNames,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum RuntimeType {
    /// Firecracker microVM backend.
    #[default]
    Firecracker,
    /// Development backend that connects to an externally managed Firecracker guest.
    RemoteFirecracker,
    /// QEMU compatibility backend.
    Qemu,
    /// gVisor userspace application kernel.
    #[serde(rename = "gvisor")]
    #[strum(serialize = "gvisor")]
    GVisor,
}

impl RuntimeType {
    /// Returns true when this backend is production-eligible.
    #[must_use]
    pub fn is_production_eligible(&self) -> bool {
        matches!(self, Self::Firecracker | Self::Qemu | Self::GVisor)
    }

    /// Returns true when this backend provides a hardware VM boundary.
    #[must_use]
    pub fn is_vm_boundary(&self) -> bool {
        matches!(
            self,
            Self::Firecracker | Self::Qemu | Self::RemoteFirecracker
        )
    }

    /// Returns true when this backend provides a microVM boundary.
    #[must_use]
    pub fn is_microvm_boundary(&self) -> bool {
        matches!(self, Self::Firecracker | Self::RemoteFirecracker)
    }
}

/// A lifecycle operation executed by a runtime backend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BackendOperation {
    /// Prepare deterministic runtime resources.
    Prepare,
    /// Boot the runtime.
    Boot,
    /// Attach the host-to-guest transport.
    AttachTransport,
    /// Wait for the guest agent to complete its readiness handshake.
    WaitReady,
    /// Hand an exec request to the guest.
    Exec,
    /// Suspend the runtime.
    Suspend,
    /// Resume the runtime.
    Resume,
    /// Fork a child runtime.
    Fork,
    /// Destroy the runtime and its owned resources.
    Destroy,
    /// Continue cleanup after an incomplete operation.
    Cleanup,
    /// Read runtime statistics.
    Stats,
    /// Probe backend health.
    Health,
    /// Capture diagnostic evidence.
    Diagnostics,
    /// Restore VM memory and device state from snapshot blobs.
    RestoreSnapshot,
}

impl fmt::Display for BackendOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepare => "prepare",
            Self::Boot => "boot",
            Self::AttachTransport => "attach_transport",
            Self::WaitReady => "wait_ready",
            Self::Exec => "exec",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Fork => "fork",
            Self::Destroy => "destroy",
            Self::Cleanup => "cleanup",
            Self::Stats => "stats",
            Self::Health => "health",
            Self::Diagnostics => "diagnostics",
            Self::RestoreSnapshot => "restore_snapshot",
        })
    }
}

/// Capability declared by a runtime backend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BackendCapability {
    /// The backend can prepare resources and boot a sandbox.
    Boot,
    /// The backend exposes a guest transport after boot.
    GuestTransport,
    /// The backend can verify guest-agent readiness on the attached transport.
    GuestReadiness,
    /// The backend can hand off command execution to the guest.
    Exec,
    /// The backend can suspend a running sandbox.
    Suspend,
    /// The backend can resume a suspended sandbox.
    Resume,
    /// The backend can create a child from a source sandbox.
    Fork,
    /// The backend can report runtime statistics.
    Stats,
    /// The backend can report health.
    Health,
    /// The backend can capture diagnostics.
    Diagnostics,
    /// The backend owns host-side forwarding for at least one guest port.
    BackendManagedPortForwarding,
    /// The backend can restore VM memory and device state from snapshot blobs.
    SnapshotRestore,
    /// The backend supports eBPF-based network policy (XDP/TC) on TAP/veth interfaces.
    EbpFNetworking,
}

/// A deterministic set of backend capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct BackendCapabilities(BTreeSet<BackendCapability>);

impl BackendCapabilities {
    /// Builds a capability set from an iterator.
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = BackendCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    /// Returns true when the capability is declared.
    #[must_use]
    pub fn contains(&self, capability: BackendCapability) -> bool {
        self.0.contains(&capability)
    }

    /// Returns true when every required capability is declared.
    #[must_use]
    pub fn supports_all(&self, required: &Self) -> bool {
        required.0.is_subset(&self.0)
    }

    /// Returns required capabilities that this backend does not declare.
    #[must_use]
    pub fn missing(&self, required: &Self) -> Vec<BackendCapability> {
        required.0.difference(&self.0).copied().collect()
    }

    /// Returns the first missing required capability, if any.
    #[must_use]
    pub fn first_missing(&self, required: &Self) -> Option<BackendCapability> {
        required.0.difference(&self.0).next().copied()
    }

    /// Iterates over capabilities in stable order.
    pub fn iter(&self) -> impl Iterator<Item = BackendCapability> + '_ {
        self.0.iter().copied()
    }
}

impl<const N: usize> From<[BackendCapability; N]> for BackendCapabilities {
    fn from(capabilities: [BackendCapability; N]) -> Self {
        Self::new(capabilities)
    }
}

/// Static identity and capabilities for a backend implementation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendMetadata {
    /// Backend family selected by placement.
    pub runtime: RuntimeType,
    /// Adapter or runtime version used for compatibility evidence.
    pub version: String,
    /// Operations and integration modes implemented by the backend.
    pub capabilities: BackendCapabilities,
}

/// Backend-owned resource created during prepare.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceReceipt {
    /// Stable resource class such as `vm`, `socket`, or `tap`.
    pub class: String,
    /// Deterministic resource name used for retry and reconciliation.
    pub name: String,
    /// Backend-specific external identity when one exists.
    pub external_id: Option<String>,
}

/// Result of preparing backend resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedSandbox {
    /// Resources that may require cleanup if a later step fails.
    pub resources: Vec<ResourceReceipt>,
}

/// Local transport used to communicate with the guest agent.
///
/// Production transports are vsock and Unix only.
///
/// Stored bundles containing any other `kind` value fail to deserialize;
/// that fail-closed behavior is intentional so an unrecognized transport
/// can never be admitted silently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuestTransport {
    /// Unix domain socket transport.
    Unix { path: String },
    /// Virtio-vsock transport.
    ///
    /// Firecracker exposes vsock to the host as a Unix domain socket. When
    /// `uds_path` is set, the host connects to that socket and issues
    /// `CONNECT <port>`.
    Vsock {
        cid: u32,
        port: u32,
        /// Host-side Unix socket mapping used by Firecracker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uds_path: Option<String>,
    },
}

/// Identifies who owns exposure of a guest port on the host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortExposure {
    /// The host agent must bind and proxy the port.
    HostProxy,
    /// The backend already exposes the port on the host.
    BackendManaged,
    /// The backend cannot expose the port.
    Unsupported,
}

/// Result of a backend fork hook.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkResult {
    /// Backend-owned child resources.
    pub resources: Vec<ResourceReceipt>,
}

/// Result of destroy or cleanup.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupReport {
    /// Resource names proven absent.
    pub released: Vec<String>,
    /// Resource names that still require cleanup.
    pub remaining: Vec<String>,
}

/// Backend runtime statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BackendStats {
    /// Resident memory attributed to the runtime.
    pub memory_bytes: Option<u64>,
    /// CPU time attributed to the runtime.
    pub cpu_time_ms: Option<u64>,
    /// Backend-specific values that do not affect lifecycle policy.
    pub details: Value,
}

/// Current readiness of a backend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendHealthStatus {
    /// Backend is ready for admitted operations.
    Ready,
    /// Backend remains usable but needs operator attention.
    Degraded,
    /// Backend cannot accept operations.
    Unavailable,
}

/// Backend health observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendHealth {
    /// Current readiness.
    pub status: BackendHealthStatus,
    /// Observation timestamp.
    pub checked_at: String,
    /// Stable human-readable detail without secrets.
    pub message: Option<String>,
}

impl BackendHealth {
    /// Creates a ready health observation.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            status: BackendHealthStatus::Ready,
            checked_at: now_iso(),
            message: None,
        }
    }
}

/// Diagnostic evidence captured from a backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticBundle {
    /// Capture timestamp.
    pub captured_at: String,
    /// Short backend-neutral summary.
    pub summary: String,
    /// Paths or identifiers for redacted diagnostic artifacts.
    pub artifacts: Vec<String>,
}

/// Machine-readable reason that a sandbox did not become ready.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NonReadyReason {
    /// Image validation or materialization failed.
    Image,
    /// Network identity or attachment setup failed.
    Network,
    /// Host resource validation or allocation failed.
    Resource,
    /// Runtime backend startup failed.
    Backend,
    /// Guest-agent transport, authentication, or protocol validation failed.
    Protocol,
    /// The boot deadline elapsed.
    Timeout,
    /// Rollback or cleanup did not complete.
    Cleanup,
}

impl NonReadyReason {
    /// Returns the canonical lowercase wire representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Network => "network",
            Self::Resource => "resource",
            Self::Backend => "backend",
            Self::Protocol => "protocol",
            Self::Timeout => "timeout",
            Self::Cleanup => "cleanup",
        }
    }

    /// All non-ready reasons in definition order.
    pub const ALL: &[NonReadyReason] = &[
        Self::Image,
        Self::Network,
        Self::Resource,
        Self::Backend,
        Self::Protocol,
        Self::Timeout,
        Self::Cleanup,
    ];
}

impl fmt::Display for NonReadyReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed failures returned by runtime backends.
#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
pub enum BackendError {
    /// A boot phase completed with a typed non-ready outcome.
    #[error("{operation} did not become ready ({reason}): {message}")]
    NotReady {
        /// Operation that failed.
        operation: BackendOperation,
        /// Stable failure classification for control-plane reporting.
        reason: NonReadyReason,
        /// Redacted diagnostic detail.
        message: String,
    },
    /// An operation exceeded its persisted deadline.
    #[error("{operation} timed out: {message}")]
    Timeout {
        operation: BackendOperation,
        message: String,
    },
    /// Prepare or boot may have created resources but did not complete.
    #[error("{operation} left incomplete setup: {message}")]
    IncompleteSetup {
        operation: BackendOperation,
        message: String,
    },
    /// Destroy released some resources but cleanup remains.
    #[error("partial cleanup remains for resources: {remaining:?}")]
    PartialCleanup { remaining: Vec<String> },
    /// The backend observed state older than the caller's command or ledger.
    #[error("stale backend state: {message}")]
    StaleState { message: String },
    /// The backend does not implement a requested capability.
    #[error("backend does not support {capability:?}")]
    Unsupported { capability: BackendCapability },
    /// The operation was called from an invalid backend state.
    #[error("{operation} requires {expected:?}, actual state is {actual}")]
    InvalidState {
        operation: BackendOperation,
        expected: Vec<SandboxState>,
        actual: SandboxState,
    },
    /// The backend failed without a more specific classification.
    #[error("{operation} failed: {message}")]
    Failed {
        operation: BackendOperation,
        message: String,
    },
    /// A backend implementation returned an unclassified internal failure.
    #[error("backend failure: {message}")]
    Backend { message: String },
}

impl BackendError {
    /// Wraps a legacy or implementation-specific failure.
    #[must_use]
    pub fn failed(operation: BackendOperation, error: impl fmt::Display) -> Self {
        Self::Failed {
            operation,
            message: error.to_string(),
        }
    }

    /// Returns the stable non-ready classification for this backend failure.
    #[must_use]
    pub fn non_ready_reason(&self) -> NonReadyReason {
        match self {
            Self::NotReady { reason, .. } => *reason,
            Self::Timeout { .. } => NonReadyReason::Timeout,
            Self::PartialCleanup { .. } => NonReadyReason::Cleanup,
            Self::IncompleteSetup { .. } => NonReadyReason::Resource,
            Self::StaleState { .. }
            | Self::Unsupported { .. }
            | Self::InvalidState { .. }
            | Self::Failed { .. }
            | Self::Backend { .. } => NonReadyReason::Backend,
        }
    }
}

/// Result returned by the runtime backend contract.
pub type BackendResult<T> = std::result::Result<T, BackendError>;

/// Context for a snapshot restore operation passed to the runtime backend.
#[derive(Debug, Clone)]
pub struct BackendRestoreContext {
    /// Identifier of the snapshot being restored.
    pub snapshot_id: String,
    /// Identifier of the sandbox being restored.
    pub sandbox_id: String,
    /// Resolved file paths for the backend's snapshot state.
    pub blob_paths: Vec<PathBuf>,
}

/// Common lifecycle interface implemented by every runtime backend.
///
/// Implementations perform bounded backend mechanics only. They do not select
/// another backend, own desired lifecycle state, or report directly to the
/// control plane. All methods must be idempotent for the same sandbox and
/// operation identity supplied by the caller's orchestration layer.
///
/// The caller is responsible for durable orchestration, state transitions, and
/// retry policy. Backends are responsible for reporting deterministic resource
/// identity, capability-gated behavior, and typed failure modes that let the
/// caller decide whether to retry, reconcile, or surface a terminal error.
#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    /// Returns backend identity and explicitly supported capabilities.
    ///
    /// Callers may inspect this before invoking any mutating operation. The
    /// returned capability set must stay stable for the life of the adapter
    /// instance so conformance checks and host orchestration can rely on it.
    fn metadata(&self) -> BackendMetadata;

    /// Prepares deterministic resources for a `Pending` or `Preparing` sandbox.
    ///
    /// Success means all returned receipts are safe to persist before boot.
    /// Returned resource names should be stable enough to support later
    /// rollback, cleanup, or reconciliation after partial failure.
    async fn prepare(&self, _config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Boot,
        })
    }

    /// Boots a prepared sandbox.
    ///
    /// The backend must reject calls unless prepare completed. Success means
    /// runtime readiness is established, but the caller must still attach and
    /// authenticate the guest transport before reporting `Running`. If boot
    /// allocates additional backend resources and then fails, the backend
    /// should preserve enough identity for a later [`RuntimeBackend::cleanup`].
    async fn boot(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Boot,
        })
    }

    /// Attaches the host-to-guest transport after boot or resume.
    ///
    /// This returns the concrete channel the host should use for guest
    /// interaction, such as vsock or a Unix socket. Implementations
    /// should reject attachment until the guest side is ready to accept work.
    async fn attach_transport(&self) -> BackendResult<GuestTransport> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::GuestTransport,
        })
    }

    /// Waits for the guest agent to complete readiness validation.
    ///
    /// A successful backend start is not sufficient to report the sandbox as
    /// running. Implementations must verify the guest agent on the scoped
    /// transport and return a typed protocol or timeout failure otherwise.
    async fn wait_ready(&self, _transport: &GuestTransport) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::GuestReadiness,
        })
    }

    /// Hands an exec request to an attached, running guest.
    ///
    /// The backend may enforce transport-specific preconditions here, but it
    /// should not invent higher-level task semantics. Command execution
    /// remains a guest concern once transport attachment succeeds.
    async fn exec(&self, _request: ExecRequest) -> BackendResult<ExecResponse> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Exec,
        })
    }

    /// Suspends a `Running` sandbox.
    ///
    /// Repeated suspension of an already `Suspended` sandbox may succeed as an
    /// idempotent no-op. Other states must return
    /// [`BackendError::InvalidState`]. Backends that do not implement suspend
    /// must omit [`BackendCapability::Suspend`] and may rely on the default
    /// unsupported implementation.
    async fn suspend(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Suspend,
        })
    }

    /// Resumes a `Suspended` sandbox.
    ///
    /// Repeated resume of an already `Running` sandbox may succeed as an
    /// idempotent no-op. Other states must return
    /// [`BackendError::InvalidState`]. The hook remains generic so mocks and
    /// capability-gated backends can exercise resume semantics through the same
    /// interface used by the host agent.
    async fn resume(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Resume,
        })
    }

    /// Creates backend resources for a child from a `Running` or `Suspended`
    /// source sandbox.
    ///
    /// Returned receipts describe the child-side resources only. The caller is
    /// still responsible for assigning new identity, policy, and durable
    /// metadata to the child sandbox.
    async fn fork(&self, _target: &SandboxConfig) -> BackendResult<ForkResult> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Fork,
        })
    }

    /// Restores VM memory and device state from snapshot blobs.
    ///
    /// Receives a [`BackendRestoreContext`] that carries snapshot identity,
    /// sandbox identity, and resolved blob paths. The backend loads the
    /// memory image and restores runtime device state so that guest
    /// execution can resume. Only backends that declare
    /// [`BackendCapability::SnapshotRestore`] must implement this.
    ///
    /// Backends document their expected blob ordering:
    ///
    /// - Firecracker: `[memory_dump, vm_state]` (index 0 = guest RAM dump,
    ///   index 1 = microVM state file).
    ///
    /// After successful restore, the backend must support the normal guest
    /// transport attachment path. The caller is responsible for sending
    /// `ResumeNotify` and performing post-restore health checks before
    /// declaring the sandbox ready.
    async fn restore_snapshot(&self, _ctx: &BackendRestoreContext) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::SnapshotRestore,
        })
    }

    /// Destroys the runtime and releases all backend-owned resources.
    ///
    /// A partial release must return [`BackendError::PartialCleanup`] and retain
    /// enough deterministic identity for a later [`RuntimeBackend::cleanup`].
    /// Repeated destroy calls after resources are absent must succeed. Silent
    /// resource leaks are not acceptable because the caller cannot distinguish a
    /// complete destroy from a cleanup retry requirement.
    ///
    /// Every non-mock backend must implement this. The default returns
    /// [`BackendError::Failed`] (not [`BackendError::Unsupported`]) because a
    /// backend that cannot destroy its own resources is fundamentally broken;
    /// silently defaulting here would leak resources.
    async fn destroy(&self) -> BackendResult<CleanupReport> {
        Err(BackendError::Failed {
            operation: BackendOperation::Destroy,
            message: "destroy is not implemented".into(),
        })
    }

    /// Continues rollback or cleanup after an incomplete operation.
    ///
    /// This is the retry path for failed prepare, boot, or destroy work. The
    /// default delegates to [`RuntimeBackend::destroy`], but implementations may
    /// preserve extra context from earlier failures and use it here.
    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.destroy().await
    }

    /// Returns the backend's current observed lifecycle state.
    ///
    /// This is an observation API, not the source of truth for desired state.
    /// Implementations should report what the backend currently sees without
    /// changing runtime state as a side effect.
    async fn state(&self) -> BackendResult<SandboxState> {
        Err(BackendError::Backend {
            message: "state inspection is not implemented".into(),
        })
    }

    /// Returns runtime statistics without changing lifecycle state.
    ///
    /// Use this for backend metrics or counters that help placement,
    /// conformance, or debugging. Unsupported backends should omit
    /// [`BackendCapability::Stats`].
    async fn stats(&self) -> BackendResult<BackendStats> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Stats,
        })
    }

    /// Returns backend health without changing lifecycle state.
    ///
    /// Health is narrower than lifecycle state: a backend may still report
    /// readiness or degraded service even when no sandbox is currently booted.
    async fn health(&self) -> BackendResult<BackendHealth> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Health,
        })
    }

    /// Captures redacted diagnostic evidence without changing lifecycle state.
    ///
    /// Artifacts may include log paths, backend identifiers, or structured
    /// debug summaries. Returned data must be safe to persist or surface in
    /// operator tooling.
    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Diagnostics,
        })
    }

    /// Resolves a guest port for host-managed proxying.
    ///
    /// This is only consulted when [`RuntimeBackend::port_exposure`] returns
    /// [`PortExposure::HostProxy`]. `Ok(None)` means the backend cannot yet
    /// resolve the destination, typically because the guest is not ready.
    async fn port_addr(&self, _guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        Ok(None)
    }

    /// Returns who owns exposure of a guest port.
    ///
    /// Host-proxied ports are bound by the host agent. Backend-managed ports
    /// are already exposed by the runtime itself. Unsupported ports should be
    /// rejected before any host binding is attempted.
    fn port_exposure(&self, _guest_port: u16) -> PortExposure {
        PortExposure::HostProxy
    }

    /// Returns the SSH account exposed by the guest image.
    ///
    /// This lets the host agent install or revoke temporary keys without
    /// knowing backend-specific guest image details.
    fn ssh_username(&self) -> &str {
        "root"
    }

    /// Returns the SSH account home directory.
    ///
    /// The returned directory is used for guest-side key management when the
    /// host agent provisions ephemeral SSH access.
    fn ssh_home_dir(&self) -> &str {
        "/root"
    }
}

/// Execution operations: run commands, suspend, resume, fork.
///
/// Separated from the full [`RuntimeBackend`] contract so that backends
/// can declare execution support independently. Consumers that only need
/// execution semantics can bound on this trait.
#[async_trait]
pub trait BackendExec: Send + Sync {
    /// Hands an exec request to an attached, running guest.
    async fn exec(&self, _request: ExecRequest) -> BackendResult<ExecResponse> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Exec,
        })
    }

    /// Suspends a `Running` sandbox.
    async fn suspend(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Suspend,
        })
    }

    /// Resumes a `Suspended` sandbox.
    async fn resume(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Resume,
        })
    }

    /// Creates backend resources for a child from a source sandbox.
    async fn fork(&self, _target: &SandboxConfig) -> BackendResult<ForkResult> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Fork,
        })
    }
}

/// Delegates [`BackendExec`] to any [`RuntimeBackend`] implementation.
#[async_trait]
impl<T: RuntimeBackend> BackendExec for T {
    async fn exec(&self, request: ExecRequest) -> BackendResult<ExecResponse> {
        RuntimeBackend::exec(self, request).await
    }

    async fn suspend(&self) -> BackendResult<()> {
        RuntimeBackend::suspend(self).await
    }

    async fn resume(&self) -> BackendResult<()> {
        RuntimeBackend::resume(self).await
    }

    async fn fork(&self, target: &SandboxConfig) -> BackendResult<ForkResult> {
        RuntimeBackend::fork(self, target).await
    }
}

/// Observability: statistics, health checks, diagnostics.
///
/// Backends implement this to expose runtime metrics without depending
/// on the full lifecycle or execution contracts.
#[async_trait]
pub trait BackendObservability: Send + Sync {
    /// Returns runtime statistics.
    async fn stats(&self) -> BackendResult<BackendStats> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Stats,
        })
    }

    /// Returns backend health.
    async fn health(&self) -> BackendResult<BackendHealth> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Health,
        })
    }

    /// Captures redacted diagnostic evidence.
    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Diagnostics,
        })
    }
}

/// Delegates [`BackendObservability`] to any [`RuntimeBackend`] implementation.
#[async_trait]
impl<T: RuntimeBackend> BackendObservability for T {
    async fn stats(&self) -> BackendResult<BackendStats> {
        RuntimeBackend::stats(self).await
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        RuntimeBackend::health(self).await
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        RuntimeBackend::diagnostics(self).await
    }
}

/// Networking: guest port resolution and exposure ownership.
#[async_trait]
pub trait BackendNetworking: Send + Sync {
    /// Resolves a guest port for host-managed proxying.
    async fn port_addr(&self, _guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        Ok(None)
    }

    /// Returns who owns exposure of a guest port.
    fn port_exposure(&self, _guest_port: u16) -> PortExposure {
        PortExposure::HostProxy
    }
}

/// Delegates [`BackendNetworking`] to any [`RuntimeBackend`] implementation.
#[async_trait]
impl<T: RuntimeBackend> BackendNetworking for T {
    async fn port_addr(&self, guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        RuntimeBackend::port_addr(self, guest_port).await
    }

    fn port_exposure(&self, guest_port: u16) -> PortExposure {
        RuntimeBackend::port_exposure(self, guest_port)
    }
}

/// SSH metadata: guest username and home directory for key management.
pub trait BackendSsh: Send + Sync {
    /// Returns the SSH account exposed by the guest image.
    fn ssh_username(&self) -> &str {
        "root"
    }

    /// Returns the SSH account home directory.
    fn ssh_home_dir(&self) -> &str {
        "/root"
    }
}

/// Delegates [`BackendSsh`] to any [`RuntimeBackend`] implementation.
impl<T: RuntimeBackend> BackendSsh for T {
    fn ssh_username(&self) -> &str {
        RuntimeBackend::ssh_username(self)
    }

    fn ssh_home_dir(&self) -> &str {
        RuntimeBackend::ssh_home_dir(self)
    }
}

impl From<BackendError> for SandboxError {
    fn from(error: BackendError) -> Self {
        let message = error.to_string();
        match error {
            BackendError::NotReady { .. }
            | BackendError::Timeout { .. }
            | BackendError::IncompleteSetup { .. } => Self::NotReady(message),
            BackendError::PartialCleanup { .. } => Self::Conflict(message),
            BackendError::StaleState { .. } => Self::OperationStale(message),
            BackendError::Unsupported { .. } => Self::Unprocessable(message),
            BackendError::InvalidState { .. } => Self::InvalidStateTransition(message),
            BackendError::Failed { .. } | BackendError::Backend { .. } => Self::Other(message),
        }
    }
}

impl From<SandboxError> for BackendError {
    fn from(error: SandboxError) -> Self {
        Self::Backend {
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_matching_reports_missing_requirements() {
        let offered = BackendCapabilities::from([BackendCapability::Boot, BackendCapability::Exec]);
        let required = BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::Exec,
            BackendCapability::Suspend,
        ]);

        assert!(!offered.supports_all(&required));
        assert_eq!(offered.missing(&required), vec![BackendCapability::Suspend]);
    }

    #[test]
    fn backend_errors_map_to_host_agent_errors() {
        let timeout = BackendError::Timeout {
            operation: BackendOperation::Boot,
            message: "guest readiness deadline elapsed".into(),
        };
        let partial = BackendError::PartialCleanup {
            remaining: vec!["tap-sbx_test".into()],
        };
        let stale = BackendError::StaleState {
            message: "older fencing token".into(),
        };

        assert!(matches!(
            SandboxError::from(timeout),
            SandboxError::NotReady(_)
        ));
        assert!(matches!(
            SandboxError::from(partial),
            SandboxError::Conflict(_)
        ));
        assert!(matches!(
            SandboxError::from(stale),
            SandboxError::OperationStale(_)
        ));
    }

    #[test]
    fn backend_errors_have_stable_non_ready_reasons() {
        let protocol = BackendError::NotReady {
            operation: BackendOperation::WaitReady,
            reason: NonReadyReason::Protocol,
            message: "guest rejected handshake".into(),
        };
        let cleanup = BackendError::PartialCleanup {
            remaining: vec!["tap-sbx_test".into()],
        };

        assert_eq!(protocol.non_ready_reason(), NonReadyReason::Protocol);
        assert_eq!(cleanup.non_ready_reason(), NonReadyReason::Cleanup);
    }
}
