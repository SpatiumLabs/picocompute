use crate::DnsAttachManager;
use crate::NetworkAttachManager;
use crate::ledger::Ledger;
use crate::process::ProcessRegistry;
use crate::resources::HostResourceManager;
use crate::secrets::{SecretsCoordinationError, SecretsCoordinator};
use hashbrown::HashMap;
use pico_core::{FencingToken, NonReadyReason, OperationId, RuntimeType, SandboxId, SandboxState};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell, RwLock};
use tokio_util::sync::CancellationToken;

use super::RuntimeHandle;

/// Result of racing an operation future against a deadline and cancellation.
#[derive(Debug)]
pub(crate) enum Execution<T> {
    /// The operation future produced a value before the deadline.
    Completed(T),
    /// The cancellation token fired before the operation finished.
    Canceled,
    /// The operation deadline elapsed before the operation finished.
    TimedOut,
}

/// Runs a future until its deadline, racing cancellation and timeout first.
///
/// Cancellation and timeout take priority over completion because the future
/// may be stuck on a slow backend call. The caller owns canceling the work the
/// future performs; this only reports which condition fired first.
pub(crate) async fn run_until_deadline<F, T>(
    token: &CancellationToken,
    deadline_unix_ms: i64,
    future: F,
) -> Execution<T>
where
    F: Future<Output = T>,
{
    let timeout = super::duration_until(deadline_unix_ms);
    tokio::select! {
        biased;
        () = token.cancelled() => Execution::Canceled,
        () = tokio::time::sleep(timeout) => Execution::TimedOut,
        result = future => Execution::Completed(result),
    }
}

/// Context attached to every state-changing command sent by `host-agent`.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// Sandbox whose local resources are affected.
    pub sandbox_id: SandboxId,
    /// Stable idempotency identity for this logical operation.
    pub operation_id: OperationId,
    /// Assignment token used to reject stale host commands.
    pub assignment_fencing_token: FencingToken,
    /// Policy version admitted by `host-agent`.
    pub policy_epoch: u64,
    /// Absolute Unix deadline in milliseconds.
    pub deadline_unix_ms: i64,
}

/// A supervised operation persisted by `sandboxd`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Prepare deterministic runtime resources.
    Prepare,
    /// Boot the runtime and attach its guest transport.
    Boot,
    /// Execute a guest command through the runtime adapter.
    Exec,
    /// Suspend a running sandbox and preserve its runtime state.
    Suspend,
    /// Resume a suspended sandbox and rehydrate its runtime state.
    Resume,
    /// Destroy runtime resources and complete cleanup.
    Destroy,
    /// Supervise a host process and its standard streams.
    Process,
    /// Restore sandbox state from a snapshot.
    Restore,
    /// Fork a child sandbox from a snapshot point.
    Fork,
}

/// Terminal or active state of a supervised operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    /// The operation is active.
    Running,
    /// The operation completed successfully.
    Succeeded,
    /// The operation failed.
    Failed,
    /// The caller explicitly canceled the operation.
    Canceled,
    /// The persisted absolute deadline elapsed.
    TimedOut,
    /// Ownership or completion could not be proven automatically.
    RequiresReview,
}

/// Machine-readable reason for a supervised operation outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReason {
    /// The operation has not reached a terminal outcome.
    InProgress,
    /// The requested runtime operation completed.
    Completed,
    /// The runtime adapter returned a typed failure.
    BackendFailure,
    /// `host-agent` requested cancellation.
    CanceledByHost,
    /// The persisted absolute deadline elapsed.
    DeadlineExceeded,
    /// Destroy or cleanup left known resources behind.
    PartialCleanup,
    /// The operation was active when `sandboxd` restarted.
    SupervisorRestarted,
    /// A supervised process exited normally.
    ProcessExited,
    /// A supervised process exited due to a signal or without an exit code.
    ProcessSignaled,
    /// A supervised process could not be spawned or waited on.
    ProcessFailure,
    /// Snapshot restore or fork was rejected by compatibility, integrity,
    /// tenant, lineage, or exclusion validation.
    RestoreRejected,
}

/// Persisted outcome returned to `host-agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationOutcome {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Sandbox affected by the operation.
    pub sandbox_id: SandboxId,
    /// Kind of operation that ran.
    pub kind: OperationKind,
    /// Terminal or active outcome.
    pub status: OutcomeStatus,
    /// Machine-readable outcome reason.
    pub reason: OutcomeReason,
    /// Stable boot failure classification when the sandbox did not become ready.
    pub non_ready_reason: Option<NonReadyReason>,
    /// Redacted detail suitable for host reporting.
    pub message: Option<String>,
    /// Time the outcome was last updated.
    pub completed_at: String,
}

/// Host-local observed sandbox state exposed to `host-agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxStatus {
    /// Sandbox identity.
    pub sandbox_id: SandboxId,
    /// Greatest assignment fencing token accepted locally.
    pub assignment_fencing_token: FencingToken,
    /// Greatest policy epoch observed locally.
    pub policy_epoch: u64,
    /// Runtime backend family.
    pub runtime: RuntimeType,
    /// Runtime adapter version.
    pub backend_version: String,
    /// Host-local observed lifecycle state.
    pub observed_state: SandboxState,
    /// Supervisor observation identity, including the host boot and daemon incarnation.
    pub host_boot_id: String,
    /// Last ledger update time.
    pub updated_at: String,
}

/// Resolved port publication for one guest port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPortTarget {
    /// Host-reachable TCP upstream for the port proxy.
    Tcp(std::net::SocketAddr),
    /// Backend already exposes the port on the host.
    BackendManaged,
    /// Backend cannot expose the port.
    Unsupported,
}

/// One guest port entry included in an observation snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortTargetObservation {
    /// Guest-side port number.
    pub guest_port: u16,
    /// How the port is exposed (or that it cannot be).
    pub target: ResolvedPortTarget,
}

/// Enriched observation combining durable ledger status with live handle data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxObservationSnapshot {
    /// Durable ledger status fields.
    pub status: SandboxStatus,
    /// Monotonic generation for cache and port-route invalidation.
    pub generation: u64,
    /// Guest boot identity when a framed session is established.
    pub guest_boot_id: String,
    /// Port targets currently published for host proxy resolution.
    pub ports: Vec<PortTargetObservation>,
    /// SSH host port from prepare config, when known.
    pub ssh_host_port: Option<u16>,
    /// SSH public key from prepare host resources, when known.
    pub ssh_public_key: Option<String>,
}

/// Watch stream event published to host-agent subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationWatchEvent {
    /// Full observation upsert for one sandbox.
    Upsert(SandboxObservationSnapshot),
    /// Sandbox is gone from the live set (successful destroy).
    Removed(SandboxId),
    /// Initial reconcile marker after the current snapshot burst.
    Reconcile {
        /// Whether startup reconcile finished.
        complete: bool,
        /// Review-required operation count.
        review_findings: u64,
        /// Observation identity of this supervisor process.
        host_boot_id: String,
    },
}

/// Aggregate readiness of the local supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupervisorHealth {
    /// Whether mutating operations can be accepted.
    pub ready: bool,
    /// Whether startup reconcile completed. Set after
    /// `reconcile_interrupted_operations` finishes, independently from
    /// `ready`, so the wire can distinguish future states where work is
    /// accepted before reconcile finishes.
    pub reconcile_complete: bool,
    /// Number of operations that require operator or fenced control-plane review.
    pub review_required: u64,
    /// Number of runtime handles held by this supervisor process.
    pub runtime_handles: usize,
    /// Number of process handles held by this supervisor process.
    pub process_handles: usize,
    /// Number of stdin, stdout, and stderr handles held by supervised processes.
    pub stream_handles: usize,
    /// Number of Linux pidfds held by supervised processes.
    pub pidfd_handles: usize,
}

/// Persisted cleanup state of one resource receipt recorded by prepare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceReceiptStatus {
    /// Resource class such as `workspace`, `cgroup`, or a backend class.
    pub class: String,
    /// Deterministic resource name.
    pub name: String,
    /// Cleanup state: `present` or `released`.
    pub cleanup_state: String,
}

/// Typed guest-session failures returned by the local supervisor boundary.
///
/// Carries the failure class as data so the gRPC layer maps variants to
/// status codes without parsing error message text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestSessionError {
    /// No framed guest session is established for the sandbox.
    #[error("sandbox {sandbox_id} has no guest session")]
    NoSession {
        /// Sandbox that has no guest session.
        sandbox_id: String,
    },
    /// A guest file payload exceeded the server-side byte cap.
    #[error("file {path} exceeds max_bytes {cap}")]
    OutputLimit {
        /// File path that exceeded the cap.
        path: String,
        /// Byte cap that was exceeded.
        cap: u64,
    },
    /// An exec stream was canceled before a terminal event.
    #[error("exec stream canceled")]
    ExecCanceled,
    /// An exec stream timed out before a terminal event.
    #[error("exec stream timed out")]
    ExecTimedOut,
    /// An exec stream cannot replay a prior durable outcome.
    #[error("exec stream cannot replay a prior durable outcome")]
    ReplayNotSupported,
    /// Any other guest RPC failure with redacted detail.
    #[error("guest session error: {detail}")]
    RpcFailed {
        /// Redacted guest RPC failure detail.
        detail: String,
    },
}

/// Failures returned by the local supervisor boundary.
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// State database access failed.
    #[error("sandboxd ledger error: {0}")]
    Ledger(#[from] sqlx::Error),
    /// Local filesystem access failed.
    #[error("sandboxd I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Persisted data could not be decoded safely.
    #[error("invalid sandboxd ledger value: {0}")]
    InvalidLedgerValue(String),
    /// A stale host assignment attempted a mutation.
    #[error("stale fencing token {request}; current token is {current}")]
    StaleFencingToken {
        /// Token supplied by the request.
        request: FencingToken,
        /// Greatest token already observed.
        current: FencingToken,
    },
    /// The same operation is already active.
    #[error("operation {0} is already in progress")]
    OperationInProgress(String),
    /// One operation ID was reused for a different sandbox or operation kind.
    #[error("operation {0} was reused with conflicting identity")]
    OperationIdentityConflict(String),
    /// The request carries a policy epoch older than what the supervisor has already accepted.
    #[error("stale policy epoch {request}; current epoch is {current}")]
    StalePolicyEpoch {
        /// Epoch supplied by the request.
        request: u64,
        /// Greatest epoch already observed.
        current: u64,
    },
    /// No live runtime handle is registered for the sandbox.
    #[error("sandbox {0} has no attached runtime handle")]
    RuntimeNotAttached(String),
    /// The command sandbox did not match the runtime configuration.
    #[error("sandbox command targets {command}, but runtime configuration targets {config}")]
    SandboxMismatch {
        /// Sandbox from the command envelope.
        command: String,
        /// Sandbox from the runtime configuration.
        config: String,
    },
    /// A process request was empty or otherwise invalid.
    #[error("invalid process request: {0}")]
    InvalidProcessRequest(String),
    /// Guest session is missing or the framed guest RPC failed.
    #[error(transparent)]
    GuestSession(#[from] GuestSessionError),
    /// Snapshot restore or fork failed before backend execution.
    #[error("snapshot restore error: {0}")]
    SnapshotRestore(String),
    /// Secrets coordination failed.
    #[error("secrets error: {0}")]
    Secrets(#[from] SecretsCoordinationError),
}

/// Durable local runtime and process supervisor.
#[derive(Clone)]
pub struct SandboxSupervisor {
    pub(super) ledger: Ledger,
    pub(super) runtimes: Arc<RwLock<HashMap<String, Arc<RuntimeHandle>>>>,
    pub(super) active_operations: Arc<Mutex<HashMap<String, CancellationToken>>>,
    pub(super) process_registry: ProcessRegistry,
    pub(super) initialized: Arc<OnceCell<()>>,
    pub(super) reconcile_complete: Arc<AtomicBool>,
    pub(super) host_boot_id: Arc<String>,
    pub(super) review_required: Arc<AtomicU64>,
    /// When true, Boot establishes a fail-closed framed guest session and does
    /// not use JSON-RPC wait_ready.
    pub(super) require_guest_session: bool,
    pub(super) host_resources: HostResourceManager,
    /// Fan-out channel for observation Watch subscribers.
    pub(super) watch_tx: tokio::sync::broadcast::Sender<ObservationWatchEvent>,
    /// Secrets coordinator (broker + optional lease validation + audit).
    pub(super) secrets: Arc<SecretsCoordinator>,
    /// DNS proxy attach ownership and ledger receipts.
    pub(super) dns: Arc<DnsAttachManager>,
    /// TAP/veth/route pipeline ownership and ledger receipts.
    pub(super) network: Arc<NetworkAttachManager>,
    /// Snapshot restore stores (repository, locator, COW engine, key resolver).
    ///
    /// `None` until `with_snapshot_stores` installs them; restore and fork
    /// fail closed while unconfigured.
    pub(super) snapshot_stores:
        Arc<parking_lot::RwLock<Option<super::restore::SnapshotRestoreStores>>>,
}
