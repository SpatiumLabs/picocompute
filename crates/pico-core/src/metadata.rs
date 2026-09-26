//! Sandbox metadata state machine.
//!
//! Implements the 12-state lifecycle model from ADR-0001 with transition
//! enforcement, optimistic concurrency, structured failure information,
//! placement identity, secure timestamps, and reconciliation detection.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::backend_selection::WorkloadClass;
use crate::identity::{FencingToken, OperationId, PrincipalId, SandboxId, ServiceId, TenantId};
use crate::runtime::RuntimeType;

// ---- Lifecycle State ----

/// The 12-state canonical sandbox lifecycle state machine from ADR-0001.
///
/// Five states are transitory (resolve to durable within timeout or escalate
/// to `Failed`). Seven states are durable (stable states the sandbox rests in).
/// `Executing` and `Idle` from v1 are removed; activity detection is now an
/// observed attribute rather than a lifecycle transition.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum SandboxState {
    /// Request received, not yet accepted by the scheduler.
    Pending,
    /// Accepted and assigned to a cell.
    Scheduled,
    /// Cell controller is allocating resources (workspace, IP, cgroup).
    Preparing,
    /// Host agent is starting the VM.
    Booting,
    /// VM is operational and accepting exec requests.
    Running,
    /// VM is being paused; memory is being saved.
    Suspending,
    /// VM is paused; memory and device state are preserved.
    Suspended,
    /// VM is being restored from suspend.
    Resuming,
    /// VM has been cleanly shut down; workspace is preserved.
    Stopped,
    /// Resources are being released.
    Destroying,
    /// Terminal state; all resources released; no further transitions.
    Destroyed,
    /// An unrecoverable error occurred; carries structured `FailureInfo`.
    Failed,
}

impl SandboxState {
    /// Returns the user-facing state name as a static string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Scheduled => "Scheduled",
            Self::Preparing => "Preparing",
            Self::Booting => "Booting",
            Self::Running => "Running",
            Self::Suspending => "Suspending",
            Self::Suspended => "Suspended",
            Self::Resuming => "Resuming",
            Self::Stopped => "Stopped",
            Self::Destroying => "Destroying",
            Self::Destroyed => "Destroyed",
            Self::Failed => "Failed",
        }
    }

    /// True if this is a transitory state that must resolve into durable
    /// within a timeout or escalate to `Failed`.
    pub fn is_transitory(self) -> bool {
        matches!(
            self,
            Self::Preparing | Self::Booting | Self::Suspending | Self::Resuming | Self::Destroying
        )
    }

    /// True if this state is durable (stable).
    pub fn is_durable(self) -> bool {
        !self.is_transitory()
    }

    /// True if this state is terminal (no further transitions possible).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Destroyed)
    }

    /// All valid lifecycle states in definition order.
    pub const ALL: &[SandboxState] = &[
        Self::Pending,
        Self::Scheduled,
        Self::Preparing,
        Self::Booting,
        Self::Running,
        Self::Suspending,
        Self::Suspended,
        Self::Resuming,
        Self::Stopped,
        Self::Destroying,
        Self::Destroyed,
        Self::Failed,
    ];

    /// Transitory states only.
    pub const TRANSITORY: &[SandboxState] = &[
        Self::Preparing,
        Self::Booting,
        Self::Suspending,
        Self::Resuming,
        Self::Destroying,
    ];

    /// Durable states only.
    pub const DURABLE: &[SandboxState] = &[
        Self::Pending,
        Self::Scheduled,
        Self::Running,
        Self::Suspended,
        Self::Stopped,
        Self::Destroyed,
        Self::Failed,
    ];

    /// Human-readable description of what this state means.
    pub fn description(self) -> &'static str {
        match self {
            Self::Pending => "Request received, not yet accepted by the scheduler",
            Self::Scheduled => "Accepted and assigned to a cell",
            Self::Preparing => "Cell controller is allocating resources",
            Self::Booting => "Host agent is starting the VM",
            Self::Running => "VM is operational and accepting requests",
            Self::Suspending => "VM is being paused; memory is being saved",
            Self::Suspended => "VM is paused; memory and device state are preserved",
            Self::Resuming => "VM is being restored from suspend",
            Self::Stopped => "VM has been cleanly shut down; workspace is preserved",
            Self::Destroying => "Resources are being released",
            Self::Destroyed => "Terminal; all resources released",
            Self::Failed => "An unrecoverable error occurred",
        }
    }
}

impl std::fmt::Display for SandboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---- Transition Errors ----

/// Errors returned when a lifecycle transition is rejected.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    /// The requested from -> to transition is not allowed.
    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition {
        from: SandboxState,
        to: SandboxState,
    },

    /// The sandbox is already in the target state (idempotent no-op).
    #[error("already in state {0}")]
    AlreadyInState(SandboxState),

    /// Optimistic concurrency failure: version mismatch.
    #[error("version conflict: expected {expected}, actual {actual}")]
    VersionConflict { expected: u64, actual: u64 },

    /// A transitory state has exceeded its timeout.
    #[error("transitory state timeout: stuck in {state} for {duration_secs}s")]
    TransitoryTimeout {
        state: SandboxState,
        duration_secs: u64,
    },

    /// Replayed operation with a stale operation ID.
    #[error("stale operation: {op_id}")]
    StaleOperation { op_id: String },

    /// Replayed operation with a stale policy epoch.
    #[error("stale policy epoch: {op_epoch} >= {current_epoch}")]
    StalePolicyEpoch { op_epoch: u64, current_epoch: u64 },

    /// Replayed operation with a stale fencing token.
    #[error("stale fencing token: request {request_token} is behind current {current_token}")]
    StaleFencingToken {
        request_token: FencingToken,
        current_token: FencingToken,
    },

    /// The sandbox is in a terminal state that disallows transitions.
    #[error("cannot transition from terminal state {0}")]
    TerminalState(SandboxState),

    /// `commit` was called with a `from` state that does not match the record.
    #[error("unexpected state: expected {expected}, actual {actual}")]
    UnexpectedState {
        expected: SandboxState,
        actual: SandboxState,
    },
}

// ---- Failure Info ----

/// Machine-readable failure codes per ADR-0001.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    /// Guest agent did not respond within boot timeout.
    BootTimeout,
    /// Insufficient CPU, memory, or disk on host.
    ResourceExhausted,
    /// Guest network stack failed to initialize.
    NetworkUnreachable,
    /// VM suspend operation returned an error.
    SuspendFailed,
    /// VM resume operation returned an error.
    ResumeFailed,
    /// Workspace filesystem is corrupted.
    WorkspaceCorrupted,
    /// Root filesystem image could not be fetched.
    ImagePullFailed,
    /// Tenant quota exceeded at scheduling time.
    QuotaExceeded,
    /// Policy engine rejected the request.
    PolicyDenied,
    /// Unexpected internal error; requires investigation.
    InternalError,
}

impl FailureCode {
    /// Whether the failure is retryable.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::BootTimeout
                | Self::ResourceExhausted
                | Self::NetworkUnreachable
                | Self::SuspendFailed
                | Self::ResumeFailed
                | Self::ImagePullFailed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BootTimeout => "boot_timeout",
            Self::ResourceExhausted => "resource_exhausted",
            Self::NetworkUnreachable => "network_unreachable",
            Self::SuspendFailed => "suspend_failed",
            Self::ResumeFailed => "resume_failed",
            Self::WorkspaceCorrupted => "workspace_corrupted",
            Self::ImagePullFailed => "image_pull_failed",
            Self::QuotaExceeded => "quota_exceeded",
            Self::PolicyDenied => "policy_denied",
            Self::InternalError => "internal_error",
        }
    }
}

/// Structured error information carried by the `Failed` state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureInfo {
    /// Machine-readable error category.
    pub code: FailureCode,
    /// Human-readable description.
    pub message: String,
    /// Which component detected the failure.
    pub component: Option<String>,
    /// Whether the operation can be retried.
    pub retryable: bool,
    /// When the failure was detected (ISO 8601).
    pub occurred_at: String,
}

// ---- Placement Info ----

/// Placement identity for a sandbox: where it lives and how to reach it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlacementInfo {
    /// Regional identifier (e.g. "us-east-1").
    pub region: Option<String>,
    /// Cell identifier within the region.
    pub cell: Option<String>,
    /// Host machine identifier within the cell.
    pub host: Option<String>,
    /// Runtime backend (Firecracker, QEMU, etc.).
    pub runtime_backend: Option<RuntimeType>,
    /// Network identity: IP address or hostname on the cell network.
    pub network_identity: Option<String>,
}

// ---- Secure Timestamps ----

/// Secure timestamp model for metadata records.
///
/// Uses four timestamps to provide ordering, freshness, and expiry context.
/// All timestamps are ISO 8601 UTC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureTimestamps {
    /// When the operation was initiated by the caller.
    pub issued_at: String,
    /// When the operation was first observed by the receiving component.
    pub observed_at: Option<String>,
    /// When the state transition was committed to the metadata store.
    pub committed_at: Option<String>,
    /// When the current lease, decision, or metadata entry expires.
    pub expires_at: Option<String>,
}

// ---- Resource Limits ----

/// Resource limits for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Memory in megabytes.
    pub memory_mb: u64,
    /// Virtual CPU count.
    pub vcpus: u32,
    /// Idle timeout in seconds before automatic suspension.
    pub idle_timeout_secs: u64,
    /// Soft memory limit in megabytes (reclaim throttle, no OOM).
    #[serde(default)]
    pub memory_soft_mb: Option<u64>,
    /// Maximum number of processes in the cgroup.
    #[serde(default)]
    pub max_pids: Option<u32>,
    /// I/O limits for the cgroup.
    #[serde(default)]
    pub io_limits: Vec<crate::types::IoLimit>,
    /// CPU bandwidth cap.
    #[serde(default)]
    pub cpu_bandwidth: Option<crate::types::CpuBandwidth>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            vcpus: 2,
            idle_timeout_secs: 300,
            memory_soft_mb: None,
            max_pids: Some(512),
            io_limits: Vec::new(),
            cpu_bandwidth: None,
        }
    }
}

// ---- Sandbox Metadata ----

/// The authoritative metadata record for a sandbox.
///
/// This is the single source of truth stored in the regional metadata store.
/// Every lifecycle transition updates this record atomically with an
/// incremented version for optimistic concurrency control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMetadata {
    // Identity
    /// Unique sandbox identifier (e.g. "sbx_01JXYZ...").
    pub id: SandboxId,
    /// Tenant that owns this sandbox.
    pub tenant_id: TenantId,
    /// Container image or rootfs identifier.
    pub image: String,
    /// Runtime backend.
    pub runtime: Option<RuntimeType>,

    // Backend selection
    /// Workload class used for backend selection.
    pub workload_class: Option<WorkloadClass>,
    /// Backend selection reason code.
    pub backend_selection_reason: Option<String>,
    /// Rejected backend candidates with gate and reason.
    pub backend_selection_rejected: Option<Vec<crate::backend_selection::RejectedCandidate>>,

    // Lifecycle
    /// Current lifecycle state.
    pub state: SandboxState,
    /// Monotonic version counter for optimistic concurrency.
    pub version: u64,
    /// Current operation ID (populated during transitory states).
    pub operation_id: Option<OperationId>,
    /// Idempotency key for the initiating request.
    pub idempotency_key: Option<String>,

    // Identity binding
    /// Identity of the actor (user, service account) that initiated the current transition.
    pub actor_identity: Option<PrincipalId>,
    /// Identity of the service component executing the current transition.
    pub service_identity: Option<ServiceId>,

    // Fencing
    /// Current fencing token for state-changing operations.
    pub fencing_token: Option<FencingToken>,

    // Policy
    /// Policy epoch at the time of the access decision.
    pub policy_epoch: Option<u64>,
    /// Access decision ID from the policy engine.
    pub access_decision_id: Option<String>,

    // Placement
    /// Where this sandbox is placed (region, cell, host, network).
    pub placement: Option<PlacementInfo>,

    // Resource limits
    pub resource_limits: ResourceLimits,

    // Timestamps
    pub timestamps: SecureTimestamps,

    // Failure
    /// Set when state is `Failed`; describes what went wrong.
    pub failure: Option<FailureInfo>,

    // Audit
    /// Causal links to audit event IDs.
    pub audit_event_ids: Vec<String>,

    // Snapshot lineage
    /// Parent sandbox ID if this was forked.
    pub parent_sandbox_id: Option<String>,
    /// Snapshot lineage identifier.
    pub snapshot_lineage: Option<String>,

    // Labels
    /// User-defined key-value labels.
    pub labels: Option<hashbrown::HashMap<String, String>>,

    // Created/updated
    pub created_at: String,
    pub updated_at: String,
}

// ---- Transition Table ----

/// Checks whether transitioning from `from` to `to` is allowed.
///
/// Returns `Ok(())` if the transition is valid, or a `TransitionError`
/// describing why it is not.
pub fn can_transition(from: SandboxState, to: SandboxState) -> Result<(), TransitionError> {
    if from == to {
        return Err(TransitionError::AlreadyInState(from));
    }
    if from.is_terminal() {
        return Err(TransitionError::TerminalState(from));
    }
    let allowed = matches!(
        (from, to),
        (
            SandboxState::Pending,
            SandboxState::Scheduled
        ) | (
            SandboxState::Scheduled,
            SandboxState::Preparing
        ) | (
            SandboxState::Preparing,
            SandboxState::Booting
        ) | (
            SandboxState::Booting,
            SandboxState::Running
        ) | (
            SandboxState::Running,
            SandboxState::Suspending
        ) | (
            SandboxState::Running,
            SandboxState::Stopped
        ) | (
            SandboxState::Suspending,
            SandboxState::Suspended
        ) | (
            SandboxState::Suspended,
            SandboxState::Resuming
        ) | (
            SandboxState::Resuming,
            SandboxState::Running
        ) | (
            SandboxState::Stopped,
            SandboxState::Running
        ) | (
            SandboxState::Destroying,
            SandboxState::Destroyed
        )
    ) || to == SandboxState::Destroying // Force-destroy from any state
        || (to == SandboxState::Failed && !from.is_terminal()); // Any non-terminal state can transition to Failed

    if allowed {
        Ok(())
    } else {
        Err(TransitionError::InvalidTransition { from, to })
    }
}

/// Applies a transition with optimistic concurrency control.
///
/// Verifies the transition is allowed, the version matches, and returns the
/// updated metadata if successful.
pub fn apply_transition(
    metadata: &mut SandboxMetadata,
    to: SandboxState,
    expected_version: u64,
) -> Result<(), TransitionError> {
    if metadata.version != expected_version {
        return Err(TransitionError::VersionConflict {
            expected: expected_version,
            actual: metadata.version,
        });
    }
    can_transition(metadata.state, to)?;
    metadata.state = to;
    metadata.version += 1;
    Ok(())
}

/// Applies a transition with both optimistic concurrency and fencing token
/// validation.
///
/// In addition to version matching, this requires that the request carries a
/// fencing token that is not stale relative to the current fencing token on
/// the metadata record. This prevents replayed operations from stale
/// components.
pub fn apply_transition_with_fencing(
    metadata: &mut SandboxMetadata,
    to: SandboxState,
    expected_version: u64,
    request_token: Option<FencingToken>,
) -> Result<(), TransitionError> {
    if let (Some(req), Some(cur)) = (request_token, metadata.fencing_token)
        && req.is_stale(&cur)
    {
        return Err(TransitionError::StaleFencingToken {
            request_token: req,
            current_token: cur,
        });
    }

    apply_transition(metadata, to, expected_version)?;

    if let Some(req) = request_token {
        metadata.fencing_token = Some(req);
    }

    Ok(())
}

/// Applies a transition and emits an audit event on success.
///
/// Combines `apply_transition` with audit event emission. The event is
/// emitted only after the state change is committed (i.e., the function
/// returns `Ok`). This satisfies the requirement that events are emitted
/// only after durable state commits.
pub fn apply_transition_with_audit(
    metadata: &mut SandboxMetadata,
    to: SandboxState,
    expected_version: u64,
    sink: &dyn crate::event_bus::AuditEventSink,
    hlc: &std::sync::Arc<crate::identity::Hlc>,
) -> Result<(), TransitionError> {
    let from = metadata.state;
    apply_transition(metadata, to, expected_version)?;

    let _ = sink.emit(
        crate::event_bus::AuditEventBuilder::new(
            Arc::clone(hlc),
            crate::identity::AuditEventKind::LifecycleTransition,
        )
        .sandbox_id(metadata.id.clone())
        .tenant_id(metadata.tenant_id.clone())
        .from_state(from.as_str())
        .to_state(to.as_str())
        .details(crate::identity::AuditEventDetails::LifecycleTransition {
            fencing_token: metadata.fencing_token,
        })
        .build(),
    );

    Ok(())
}

/// Applies a transition with fencing token validation and emits an audit
/// event on success.
///
/// Combines `apply_transition_with_fencing` with audit event emission.
pub fn apply_transition_with_fencing_and_audit(
    metadata: &mut SandboxMetadata,
    to: SandboxState,
    expected_version: u64,
    request_token: Option<FencingToken>,
    sink: &dyn crate::event_bus::AuditEventSink,
    hlc: &std::sync::Arc<crate::identity::Hlc>,
) -> Result<(), TransitionError> {
    let from = metadata.state;
    apply_transition_with_fencing(metadata, to, expected_version, request_token)?;

    let _ = sink.emit(
        crate::event_bus::AuditEventBuilder::new(
            Arc::clone(hlc),
            crate::identity::AuditEventKind::LifecycleTransition,
        )
        .sandbox_id(metadata.id.clone())
        .tenant_id(metadata.tenant_id.clone())
        .from_state(from.as_str())
        .to_state(to.as_str())
        .details(crate::identity::AuditEventDetails::LifecycleTransition {
            fencing_token: metadata.fencing_token,
        })
        .fencing_token(metadata.fencing_token.unwrap_or(FencingToken::new(0)))
        .build(),
    );

    Ok(())
}

/// Validates that a request's policy epoch is not stale.
///
/// Returns `Ok(())` if the request epoch is current or unset. Returns a
/// `StalePolicyEpoch` error if the request epoch is behind the current epoch
/// on the metadata record.
pub fn validate_policy_epoch(
    request_epoch: Option<u64>,
    current_epoch: Option<u64>,
) -> Result<(), TransitionError> {
    match (request_epoch, current_epoch) {
        (Some(req), Some(cur)) if req < cur => Err(TransitionError::StalePolicyEpoch {
            op_epoch: req,
            current_epoch: cur,
        }),
        _ => Ok(()),
    }
}

// ---- Reconciliation Detection ----

fn parse_iso8601_utc(s: &str) -> Option<time::OffsetDateTime> {
    time::PrimitiveDateTime::parse(s, &time::format_description::well_known::Iso8601::DEFAULT)
        .ok()
        .map(|dt| dt.assume_utc())
}

/// Diagnostics for the reconciliation loop to detect problematic states.
impl SandboxMetadata {
    /// True if this metadata is stale (behind the latest known version).
    pub fn is_stale(&self, latest_version: u64) -> bool {
        self.version < latest_version
    }

    /// True if this sandbox is stuck in a transitory state beyond the timeout.
    ///
    /// Compares `updated_at` to the current time. If the state is transitory
    /// and `updated_at + timeout_secs < now`, the sandbox is stuck.
    ///
    /// Returns `false` if timestamps cannot be parsed (treated as not stuck
    /// to avoid false-positive escalations on malformed data).
    pub fn is_stuck(&self, timeout_secs: u64, now: &str) -> bool {
        if !self.state.is_transitory() {
            return false;
        }
        let Some(updated) = parse_iso8601_utc(&self.updated_at) else {
            return false;
        };
        let Some(now) = parse_iso8601_utc(now) else {
            return false;
        };
        updated + time::Duration::seconds(timeout_secs as i64) < now
    }

    /// True if this sandbox has suffered a catastrophic failure that
    /// cannot be automatically recovered (e.g., internal error).
    pub fn looks_unrecoverable(&self) -> bool {
        matches!(self.state, SandboxState::Failed)
            && self
                .failure
                .as_ref()
                .is_some_and(|f| f.code == FailureCode::InternalError)
    }

    /// True if the given operation ID has already been processed for this sandbox.
    pub fn is_replayed(&self, op_id: &str) -> bool {
        self.audit_event_ids.iter().any(|id| id == op_id)
    }

    /// Returns the recommended timeout in seconds for each transitory state.
    pub fn transitory_timeout(&self) -> Option<u64> {
        match self.state {
            SandboxState::Booting => Some(300),
            SandboxState::Suspending | SandboxState::Resuming => Some(120),
            SandboxState::Destroying => Some(60),
            SandboxState::Preparing => Some(120),
            _ => None,
        }
    }
}

// ---- Status API Helpers ----

impl SandboxMetadata {
    /// Returns the user-facing lifecycle state.
    ///
    /// This is the same as `self.state` -- the canonical state is always
    /// user-visible. The diagnostic reason provides additional internal detail.
    pub fn user_facing_state(&self) -> SandboxState {
        self.state
    }

    /// Returns an internal diagnostic reason describing why the sandbox is
    /// in its current state, for operators and debugging.
    ///
    /// This augments the user-facing state with component-level detail.
    pub fn diagnostic_reason(&self) -> String {
        match self.state {
            SandboxState::Failed => {
                if let Some(ref failure) = self.failure {
                    format!(
                        "failed: {} (code={}, retryable={}, component={})",
                        failure.message,
                        failure.code.as_str(),
                        failure.retryable,
                        failure.component.as_deref().unwrap_or("unknown")
                    )
                } else {
                    "failed: no failure info".into()
                }
            }
            SandboxState::Pending => {
                format!(
                    "pending: awaiting scheduler acceptance (tenant={})",
                    self.tenant_id
                )
            }
            SandboxState::Scheduled => {
                if let Some(ref placement) = self.placement {
                    format!(
                        "scheduled to cell={} host={}",
                        placement.cell.as_deref().unwrap_or("unknown"),
                        placement.host.as_deref().unwrap_or("unknown")
                    )
                } else {
                    "scheduled: no placement assigned yet".into()
                }
            }
            SandboxState::Preparing => {
                "preparing: allocating resources (workspace, IP, cgroup)".into()
            }
            SandboxState::Booting => "booting: starting VM and waiting for guest agent".into(),
            SandboxState::Running => "running: VM is operational".into(),
            SandboxState::Suspending => "suspending: pausing VM and saving memory state".into(),
            SandboxState::Suspended => {
                "suspended: VM is paused; memory and device state preserved".into()
            }
            SandboxState::Resuming => "resuming: restoring VM from suspend".into(),
            SandboxState::Stopped => "stopped: VM cleanly shut down; workspace preserved".into(),
            SandboxState::Destroying => "destroying: releasing all resources".into(),
            SandboxState::Destroyed => "destroyed: terminal; all resources released".into(),
        }
    }

    /// Returns the recommended action for a reconciliation loop given
    /// the desired state versus the observed metadata.
    pub fn reconcile_action(&self, desired_state: SandboxState) -> Option<ReconcileAction> {
        if self.state == desired_state {
            return None;
        }
        match (desired_state, self.state) {
            (SandboxState::Running, SandboxState::Failed) => Some(ReconcileAction::EvaluateFailure),
            (SandboxState::Running, _) => Some(ReconcileAction::PrepareAndBoot),
            (SandboxState::Stopped, SandboxState::Running) => Some(ReconcileAction::Stop),
            (SandboxState::Suspended, SandboxState::Running) => Some(ReconcileAction::Suspend),
            (SandboxState::Destroying, _) if !matches!(self.state, SandboxState::Destroyed) => {
                Some(ReconcileAction::Destroy)
            }
            (SandboxState::Destroyed, _) => Some(ReconcileAction::ConfirmDestroyed),
            _ => None,
        }
    }
}

/// Actions a reconciliation loop can take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Prepare and boot the sandbox on an available host.
    PrepareAndBoot,
    /// Send stop command to host agent.
    Stop,
    /// Send suspend command to host agent.
    Suspend,
    /// Send destroy command to host agent.
    Destroy,
    /// Confirm cleanup and mark as fully destroyed.
    ConfirmDestroyed,
    /// Evaluate error to decide re-prepare or mark as Failed.
    EvaluateFailure,
}

// ---- Clock-Skew and Stale-Decision Utilities ----

/// Clock-skew tolerance in seconds. If two timestamps differ by more than
/// this, the decision is considered potentially stale.
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 30;

/// Checks whether an access decision is potentially stale due to clock skew.
///
/// A decision is stale if the issued timestamp is sufficiently far from the
/// current time that the policy epoch may have changed.
pub fn is_decision_stale(
    issued_at_epoch_secs: i64,
    current_epoch_secs: i64,
    tolerance_secs: i64,
) -> bool {
    (current_epoch_secs - issued_at_epoch_secs).abs() > tolerance_secs
}

/// Returns the default clock-skew tolerance.
pub fn default_clock_skew_tolerance() -> i64 {
    CLOCK_SKEW_TOLERANCE_SECS
}

// ---- Helper: Create a new metadata record ----

impl SandboxMetadata {
    /// Commits a desired-state transition.
    ///
    /// This is the only mutation path for desired lifecycle state. Callers
    /// supply the expected current state (`from`) so a concurrent or stale
    /// commit fails without applying. When `token` is present, fencing is
    /// checked against the record and stored on success.
    pub fn commit(
        &mut self,
        from: SandboxState,
        to: SandboxState,
        token: Option<FencingToken>,
    ) -> Result<(), TransitionError> {
        if self.state != from {
            return Err(TransitionError::UnexpectedState {
                expected: from,
                actual: self.state,
            });
        }
        apply_transition_with_fencing(self, to, self.version, token)?;
        let now = crate::types::now_iso();
        self.updated_at = now.clone();
        self.timestamps.committed_at = Some(now);
        if to != SandboxState::Failed {
            self.failure = None;
        }
        Ok(())
    }

    /// Commits with operation identity for stale-retry convergence.
    ///
    /// Records `operation_id` on success and pushes it into
    /// `audit_event_ids` so a replayed operation is recognized. Retries
    /// converge without duplicate side effects:
    ///
    /// - Same operation on the same transition after success returns
    ///   `AlreadyInState` with no version move.
    /// - Same operation for a different transition returns `StaleOperation`.
    /// - A fresh operation retrying an already-completed transition returns
    ///   `AlreadyInState` with no version move (state-level idempotence, so
    ///   partition retries with new operation ids still converge). The replay
    ///   path intentionally bypasses fencing-token validation: the transition
    ///   already committed, so revalidating a stale token would turn a safe
    ///   retry into a spurious failure.
    /// - Otherwise the call behaves like [`Self::commit`].
    pub fn commit_with_operation(
        &mut self,
        from: SandboxState,
        to: SandboxState,
        token: Option<FencingToken>,
        operation_id: Option<OperationId>,
        idempotency_key: Option<String>,
    ) -> Result<(), TransitionError> {
        if let Some(ref req_op) = operation_id {
            let req_str = req_op.as_str();
            if self.audit_event_ids.iter().any(|id| id == req_str) {
                if self.state == to && self.operation_id.as_ref() == Some(req_op) {
                    return Err(TransitionError::AlreadyInState(to));
                }
                return Err(TransitionError::StaleOperation {
                    op_id: req_str.to_string(),
                });
            }
            if self.state != from && self.state == to {
                return Err(TransitionError::AlreadyInState(to));
            }
        }
        self.commit(from, to, token)?;
        if let Some(op) = operation_id {
            self.operation_id = Some(op.clone());
            self.audit_event_ids.push(op.as_str().to_string());
        }
        if let Some(key) = idempotency_key {
            self.idempotency_key = Some(key);
        }
        Ok(())
    }

    /// Reconstructs a metadata record after the in-memory desired record was
    /// lost (host-agent restart).
    ///
    /// This is not a transition. The record starts at `observed` so the host
    /// can resume gating without inventing a second state machine.
    pub fn recover_from_observed(
        id: SandboxId,
        tenant_id: TenantId,
        image: String,
        runtime: Option<RuntimeType>,
        observed: SandboxState,
        fencing_token: Option<FencingToken>,
        policy_epoch: Option<u64>,
    ) -> Self {
        let mut metadata = Self::new(
            id,
            tenant_id,
            image,
            runtime,
            ResourceLimits::default(),
            None,
        );
        metadata.state = observed;
        metadata.fencing_token = fencing_token;
        metadata.policy_epoch = policy_epoch;
        metadata
    }

    /// Creates a new `SandboxMetadata` in `Pending` state.
    pub fn new(
        id: SandboxId,
        tenant_id: TenantId,
        image: String,
        runtime: Option<RuntimeType>,
        resource_limits: ResourceLimits,
        labels: Option<hashbrown::HashMap<String, String>>,
    ) -> Self {
        let now = crate::types::now_iso();
        Self {
            id,
            tenant_id,
            image,
            runtime,
            workload_class: None,
            backend_selection_reason: None,
            backend_selection_rejected: None,
            state: SandboxState::Pending,
            version: 1,
            operation_id: None,
            idempotency_key: None,
            actor_identity: None,
            service_identity: None,
            fencing_token: None,
            policy_epoch: None,
            access_decision_id: None,
            placement: None,
            resource_limits,
            timestamps: SecureTimestamps {
                issued_at: now.clone(),
                observed_at: None,
                committed_at: None,
                expires_at: None,
            },
            failure: None,
            audit_event_ids: Vec::new(),
            parent_sandbox_id: None,
            snapshot_lineage: None,
            labels,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // State classification
    // ================================================================

    #[test]
    fn transitory_states_are_correct() {
        let transitory: Vec<_> = SandboxState::ALL
            .iter()
            .copied()
            .filter(|s| s.is_transitory())
            .collect();
        assert_eq!(transitory.len(), 5);
        assert!(transitory.contains(&SandboxState::Preparing));
        assert!(transitory.contains(&SandboxState::Booting));
        assert!(transitory.contains(&SandboxState::Suspending));
        assert!(transitory.contains(&SandboxState::Resuming));
        assert!(transitory.contains(&SandboxState::Destroying));
    }

    #[test]
    fn durable_states_are_correct() {
        let durable: Vec<_> = SandboxState::ALL
            .iter()
            .copied()
            .filter(|s| s.is_durable())
            .collect();
        assert_eq!(durable.len(), 7);
    }

    #[test]
    fn destroyed_is_the_only_terminal_state() {
        for state in SandboxState::ALL {
            if *state == SandboxState::Destroyed {
                assert!(state.is_terminal());
            } else {
                assert!(!state.is_terminal(), "{state} should not be terminal");
            }
        }
    }

    #[test]
    fn state_as_str_matches_expectation() {
        assert_eq!(SandboxState::Pending.as_str(), "Pending");
        assert_eq!(SandboxState::Running.as_str(), "Running");
        assert_eq!(SandboxState::Failed.as_str(), "Failed");
    }

    #[test]
    fn state_display_matches_as_str() {
        for state in SandboxState::ALL {
            assert_eq!(format!("{state}"), state.as_str());
        }
    }

    // ================================================================
    // Allowed transitions (happy path)
    // ================================================================

    #[test]
    fn pending_to_scheduled_is_allowed() {
        assert!(can_transition(SandboxState::Pending, SandboxState::Scheduled).is_ok());
    }

    #[test]
    fn pending_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Pending, SandboxState::Failed).is_ok());
    }

    #[test]
    fn scheduled_to_preparing_is_allowed() {
        assert!(can_transition(SandboxState::Scheduled, SandboxState::Preparing).is_ok());
    }

    #[test]
    fn preparing_to_booting_is_allowed() {
        assert!(can_transition(SandboxState::Preparing, SandboxState::Booting).is_ok());
    }

    #[test]
    fn preparing_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Preparing, SandboxState::Failed).is_ok());
    }

    #[test]
    fn booting_to_running_is_allowed() {
        assert!(can_transition(SandboxState::Booting, SandboxState::Running).is_ok());
    }

    #[test]
    fn booting_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Booting, SandboxState::Failed).is_ok());
    }

    #[test]
    fn running_to_suspending_is_allowed() {
        assert!(can_transition(SandboxState::Running, SandboxState::Suspending).is_ok());
    }

    #[test]
    fn running_to_stopped_is_allowed() {
        assert!(can_transition(SandboxState::Running, SandboxState::Stopped).is_ok());
    }

    #[test]
    fn suspending_to_suspended_is_allowed() {
        assert!(can_transition(SandboxState::Suspending, SandboxState::Suspended).is_ok());
    }

    #[test]
    fn suspending_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Suspending, SandboxState::Failed).is_ok());
    }

    #[test]
    fn suspended_to_resuming_is_allowed() {
        assert!(can_transition(SandboxState::Suspended, SandboxState::Resuming).is_ok());
    }

    #[test]
    fn suspended_to_destroying_is_allowed() {
        assert!(can_transition(SandboxState::Suspended, SandboxState::Destroying).is_ok());
    }

    #[test]
    fn resuming_to_running_is_allowed() {
        assert!(can_transition(SandboxState::Resuming, SandboxState::Running).is_ok());
    }

    #[test]
    fn resuming_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Resuming, SandboxState::Failed).is_ok());
    }

    #[test]
    fn stopped_to_running_is_allowed() {
        assert!(can_transition(SandboxState::Stopped, SandboxState::Running).is_ok());
    }

    #[test]
    fn stopped_to_destroying_is_allowed() {
        assert!(can_transition(SandboxState::Stopped, SandboxState::Destroying).is_ok());
    }

    #[test]
    fn failed_to_destroying_is_allowed() {
        assert!(can_transition(SandboxState::Failed, SandboxState::Destroying).is_ok());
    }

    #[test]
    fn destroying_to_destroyed_is_allowed() {
        assert!(can_transition(SandboxState::Destroying, SandboxState::Destroyed).is_ok());
    }

    #[test]
    fn destroying_to_failed_is_allowed() {
        assert!(can_transition(SandboxState::Destroying, SandboxState::Failed).is_ok());
    }

    #[test]
    fn force_destroy_from_any_state_is_allowed() {
        for state in SandboxState::ALL {
            let result = can_transition(*state, SandboxState::Destroying);
            if state.is_terminal() {
                assert!(
                    matches!(result, Err(TransitionError::TerminalState(_))),
                    "force-destroy from terminal {state} should be rejected with TerminalState"
                );
            } else if *state == SandboxState::Destroying {
                assert!(
                    matches!(result, Err(TransitionError::AlreadyInState(_))),
                    "Destroying -> Destroying should be AlreadyInState"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "force-destroy from {state} should be allowed"
                );
            }
        }
    }

    #[test]
    fn any_non_terminal_can_fail() {
        for state in SandboxState::ALL {
            let result = can_transition(*state, SandboxState::Failed);
            if state.is_terminal() {
                assert!(
                    result.is_err(),
                    "terminal {state} should not transition to Failed"
                );
            } else if *state == SandboxState::Failed {
                // Self-transition to Failed is idempotent, not a valid transition
                assert!(
                    matches!(result, Err(TransitionError::AlreadyInState(_))),
                    "{state} -> Failed should be AlreadyInState"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "{state} should be able to transition to Failed"
                );
            }
        }
    }

    // ================================================================
    // Disallowed transitions (negative tests)
    // ================================================================

    #[test]
    fn same_state_transition_is_idempotent_error() {
        assert_eq!(
            can_transition(SandboxState::Running, SandboxState::Running).unwrap_err(),
            TransitionError::AlreadyInState(SandboxState::Running)
        );
    }

    #[test]
    fn destroyed_is_terminal_no_exit() {
        for state in SandboxState::ALL {
            let result = can_transition(SandboxState::Destroyed, *state);
            if *state == SandboxState::Destroyed {
                assert!(matches!(result, Err(TransitionError::AlreadyInState(_))));
            } else {
                assert!(
                    matches!(result, Err(TransitionError::TerminalState(_))),
                    "transition from Destroyed to {state} should be TerminalState error"
                );
            }
        }
    }

    #[test]
    fn running_cannot_suspend_twice() {
        let result = can_transition(SandboxState::Running, SandboxState::Running);
        assert!(matches!(
            result,
            Err(TransitionError::AlreadyInState(SandboxState::Running))
        ));
    }

    #[test]
    fn pending_cannot_go_directly_to_running() {
        assert!(can_transition(SandboxState::Pending, SandboxState::Running).is_err());
    }

    #[test]
    fn booting_cannot_go_directly_to_suspended() {
        assert!(can_transition(SandboxState::Booting, SandboxState::Suspended).is_err());
    }

    #[test]
    fn suspended_cannot_go_directly_to_running() {
        assert!(can_transition(SandboxState::Suspended, SandboxState::Running).is_err());
    }

    #[test]
    fn failed_cannot_go_back_to_running() {
        assert!(can_transition(SandboxState::Failed, SandboxState::Running).is_err());
    }

    #[test]
    fn destroying_cannot_go_back_to_running() {
        assert!(can_transition(SandboxState::Destroying, SandboxState::Running).is_err());
    }

    // ================================================================
    // Optimistic concurrency
    // ================================================================

    #[test]
    fn apply_transition_increments_version() {
        let mut meta = make_test_metadata();
        let old_version = meta.version;
        assert!(apply_transition(&mut meta, SandboxState::Scheduled, old_version).is_ok());
        assert_eq!(meta.state, SandboxState::Scheduled);
        assert_eq!(meta.version, old_version + 1);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut meta = make_test_metadata();
        let err = apply_transition(&mut meta, SandboxState::Scheduled, 999).unwrap_err();
        assert_eq!(
            err,
            TransitionError::VersionConflict {
                expected: 999,
                actual: 1
            }
        );
        // State and version must be unchanged.
        assert_eq!(meta.state, SandboxState::Pending);
        assert_eq!(meta.version, 1);
    }

    #[test]
    fn apply_transition_respects_transition_rules() {
        let mut meta = make_test_metadata();
        let err = apply_transition(&mut meta, SandboxState::Running, 1).unwrap_err();
        assert_eq!(
            err,
            TransitionError::InvalidTransition {
                from: SandboxState::Pending,
                to: SandboxState::Running,
            }
        );
    }

    #[test]
    fn sequential_transitions_are_allowed() {
        let mut meta = make_test_metadata();
        apply_transition(&mut meta, SandboxState::Scheduled, 1).unwrap();
        assert_eq!(meta.version, 2);
        apply_transition(&mut meta, SandboxState::Preparing, 2).unwrap();
        assert_eq!(meta.version, 3);
        apply_transition(&mut meta, SandboxState::Booting, 3).unwrap();
        assert_eq!(meta.version, 4);
        apply_transition(&mut meta, SandboxState::Running, 4).unwrap();
        assert_eq!(meta.version, 5);
        assert_eq!(meta.state, SandboxState::Running);
    }

    // ================================================================
    // commit(from, to, token) - the live desired-state mutation
    // ================================================================

    #[test]
    fn commit_walks_prepare_to_boot_sequence() {
        let mut meta = make_test_metadata();
        let token = FencingToken::default();
        meta.commit(SandboxState::Pending, SandboxState::Scheduled, Some(token))
            .unwrap();
        meta.commit(
            SandboxState::Scheduled,
            SandboxState::Preparing,
            Some(token),
        )
        .unwrap();
        meta.commit(SandboxState::Preparing, SandboxState::Booting, Some(token))
            .unwrap();
        meta.commit(SandboxState::Booting, SandboxState::Running, Some(token))
            .unwrap();
        assert_eq!(meta.state, SandboxState::Running);
        assert_eq!(meta.version, 5);
        assert_eq!(meta.fencing_token, Some(token));
        assert!(meta.timestamps.committed_at.is_some());
    }

    #[test]
    fn commit_rejects_preparing_to_pending() {
        let mut meta = make_test_metadata();
        meta.commit(SandboxState::Pending, SandboxState::Scheduled, None)
            .unwrap();
        meta.commit(SandboxState::Scheduled, SandboxState::Preparing, None)
            .unwrap();
        let err = meta
            .commit(SandboxState::Preparing, SandboxState::Pending, None)
            .unwrap_err();
        assert_eq!(
            err,
            TransitionError::InvalidTransition {
                from: SandboxState::Preparing,
                to: SandboxState::Pending,
            }
        );
        assert_eq!(meta.state, SandboxState::Preparing);
    }

    #[test]
    fn commit_rejects_unexpected_from_state() {
        let mut meta = make_test_metadata();
        let err = meta
            .commit(SandboxState::Running, SandboxState::Stopped, None)
            .unwrap_err();
        assert_eq!(
            err,
            TransitionError::UnexpectedState {
                expected: SandboxState::Running,
                actual: SandboxState::Pending,
            }
        );
        assert_eq!(meta.state, SandboxState::Pending);
        assert_eq!(meta.version, 1);
    }

    #[test]
    fn commit_rejects_stale_fencing_token() {
        let mut meta = make_test_metadata();
        let current = FencingToken {
            epoch: 1,
            sequence: 2,
        };
        meta.commit(
            SandboxState::Pending,
            SandboxState::Scheduled,
            Some(current),
        )
        .unwrap();
        let stale = FencingToken {
            epoch: 1,
            sequence: 1,
        };
        let err = meta
            .commit(
                SandboxState::Scheduled,
                SandboxState::Preparing,
                Some(stale),
            )
            .unwrap_err();
        assert_eq!(
            err,
            TransitionError::StaleFencingToken {
                request_token: stale,
                current_token: current,
            }
        );
        assert_eq!(meta.state, SandboxState::Scheduled);
    }

    #[test]
    fn recover_from_observed_is_not_a_transition() {
        let meta = SandboxMetadata::recover_from_observed(
            SandboxId::from_string("sbx_recovered"),
            TenantId::from_string("tenant-1"),
            "alpine".into(),
            None,
            SandboxState::Running,
            Some(FencingToken::default()),
            Some(3),
        );
        assert_eq!(meta.state, SandboxState::Running);
        assert_eq!(meta.version, 1);
        assert_eq!(meta.policy_epoch, Some(3));
    }

    // ================================================================
    // Reconciliation detection
    // ================================================================

    #[test]
    fn stale_metadata_is_stale() {
        let meta = make_test_metadata();
        assert!(!meta.is_stale(1));
        assert!(meta.is_stale(2));
        assert!(meta.is_stale(100));
    }

    #[test]
    fn non_transitory_is_not_stuck() {
        let meta = make_test_metadata();
        assert!(!meta.is_stuck(1, "2026-01-01T00:05:00Z"));
    }

    #[test]
    fn transitory_state_is_stuck_after_timeout() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Booting;
        meta.updated_at = "2026-01-01T00:00:00Z".into();
        // 300s after updated_at = 00:05:00. now is 00:10:00, well past the timeout.
        assert!(meta.is_stuck(300, "2026-01-01T00:10:00Z"));
    }

    #[test]
    fn transitory_state_is_not_stuck_before_timeout() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Booting;
        meta.updated_at = "2026-01-01T00:00:00Z".into();
        // 300s after = 00:05:00. now is 00:04:00, still within timeout.
        assert!(!meta.is_stuck(300, "2026-01-01T00:04:00Z"));
    }

    #[test]
    fn looks_unrecoverable_detects_catastrophic_failure() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Failed;
        meta.failure = Some(FailureInfo {
            code: FailureCode::InternalError,
            message: "unexpected crash".into(),
            component: Some("host-agent".into()),
            retryable: false,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        assert!(meta.looks_unrecoverable());
    }

    #[test]
    fn looks_unrecoverable_false_for_retryable_failures() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Failed;
        meta.failure = Some(FailureInfo {
            code: FailureCode::BootTimeout,
            message: "timeout".into(),
            component: None,
            retryable: true,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        assert!(!meta.looks_unrecoverable());
    }

    #[test]
    fn looks_unrecoverable_false_for_non_failed_state() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        meta.failure = Some(FailureInfo {
            code: FailureCode::InternalError,
            message: "unexpected".into(),
            component: None,
            retryable: false,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        assert!(!meta.looks_unrecoverable());
    }

    #[test]
    fn replay_detection_via_audit_event_ids() {
        let mut meta = make_test_metadata();
        meta.audit_event_ids.push("op_01JXYZ".into());
        assert!(meta.is_replayed("op_01JXYZ"));
        assert!(!meta.is_replayed("op_other"));
    }

    #[test]
    fn transitory_timeout_is_correct() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Booting;
        assert_eq!(meta.transitory_timeout(), Some(300));
        meta.state = SandboxState::Suspending;
        assert_eq!(meta.transitory_timeout(), Some(120));
        meta.state = SandboxState::Resuming;
        assert_eq!(meta.transitory_timeout(), Some(120));
        meta.state = SandboxState::Destroying;
        assert_eq!(meta.transitory_timeout(), Some(60));
        meta.state = SandboxState::Preparing;
        assert_eq!(meta.transitory_timeout(), Some(120));
        meta.state = SandboxState::Running;
        assert_eq!(meta.transitory_timeout(), None);
    }

    // ================================================================
    // Status API
    // ================================================================

    #[test]
    fn user_facing_state_is_the_current_state() {
        let meta = make_test_metadata();
        assert_eq!(meta.user_facing_state(), SandboxState::Pending);
    }

    #[test]
    fn diagnostic_reason_for_failed_with_failure_info() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Failed;
        meta.failure = Some(FailureInfo {
            code: FailureCode::BootTimeout,
            message: "guest agent did not respond".into(),
            component: Some("host-agent".into()),
            retryable: true,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        let reason = meta.diagnostic_reason();
        assert!(reason.contains("failed: guest agent did not respond"));
        assert!(reason.contains("code=boot_timeout"));
        assert!(reason.contains("retryable=true"));
        assert!(reason.contains("component=host-agent"));
    }

    #[test]
    fn diagnostic_reason_for_running() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        let reason = meta.diagnostic_reason();
        assert!(reason.contains("running"));
    }

    // ================================================================
    // Reconciliation actions
    // ================================================================

    #[test]
    fn no_action_when_states_match() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        assert_eq!(meta.reconcile_action(SandboxState::Running), None);
    }

    #[test]
    fn reconcile_running_when_state_mismatches() {
        let meta = make_test_metadata();
        assert_eq!(
            meta.reconcile_action(SandboxState::Running),
            Some(ReconcileAction::PrepareAndBoot)
        );
    }

    #[test]
    fn reconcile_stop_when_desired_stopped_but_observed_running() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        assert_eq!(
            meta.reconcile_action(SandboxState::Stopped),
            Some(ReconcileAction::Stop)
        );
    }

    #[test]
    fn reconcile_suspend_when_desired_suspended_but_observed_running() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        assert_eq!(
            meta.reconcile_action(SandboxState::Suspended),
            Some(ReconcileAction::Suspend)
        );
    }

    #[test]
    fn reconcile_destroy_when_desired_destroying() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        assert_eq!(
            meta.reconcile_action(SandboxState::Destroying),
            Some(ReconcileAction::Destroy)
        );
    }

    #[test]
    fn reconcile_confirm_destroyed() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Running;
        assert_eq!(
            meta.reconcile_action(SandboxState::Destroyed),
            Some(ReconcileAction::ConfirmDestroyed)
        );
    }

    #[test]
    fn reconcile_evaluate_failure_when_desired_running_but_failed() {
        let mut meta = make_test_metadata();
        meta.state = SandboxState::Failed;
        meta.failure = Some(FailureInfo {
            code: FailureCode::BootTimeout,
            message: "timeout".into(),
            component: None,
            retryable: true,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        });
        assert_eq!(
            meta.reconcile_action(SandboxState::Running),
            Some(ReconcileAction::EvaluateFailure)
        );
    }

    // ================================================================
    // Failure codes
    // ================================================================

    #[test]
    fn retryable_codes_are_retryable() {
        assert!(FailureCode::BootTimeout.is_retryable());
        assert!(FailureCode::ResourceExhausted.is_retryable());
        assert!(FailureCode::NetworkUnreachable.is_retryable());
        assert!(FailureCode::SuspendFailed.is_retryable());
        assert!(FailureCode::ResumeFailed.is_retryable());
        assert!(FailureCode::ImagePullFailed.is_retryable());
    }

    #[test]
    fn non_retryable_codes_are_not_retryable() {
        assert!(!FailureCode::WorkspaceCorrupted.is_retryable());
        assert!(!FailureCode::QuotaExceeded.is_retryable());
        assert!(!FailureCode::PolicyDenied.is_retryable());
        assert!(!FailureCode::InternalError.is_retryable());
    }

    #[test]
    fn failure_code_as_str_uses_snake_case() {
        assert_eq!(FailureCode::BootTimeout.as_str(), "boot_timeout");
        assert_eq!(
            FailureCode::WorkspaceCorrupted.as_str(),
            "workspace_corrupted"
        );
        assert_eq!(FailureCode::InternalError.as_str(), "internal_error");
    }

    // ================================================================
    // Clock-skew detection
    // ================================================================

    #[test]
    fn clock_skew_within_tolerance_is_not_stale() {
        assert!(!is_decision_stale(1000, 1020, 30));
    }

    #[test]
    fn clock_skew_beyond_tolerance_is_stale() {
        assert!(is_decision_stale(1000, 1040, 30));
    }

    #[test]
    fn negative_clock_skew_is_also_detected() {
        assert!(is_decision_stale(1040, 1000, 30));
    }

    // ================================================================
    // SandboxMetadata constructor
    // ================================================================

    #[test]
    fn new_metadata_starts_in_pending() {
        let meta = make_test_metadata();
        assert_eq!(meta.state, SandboxState::Pending);
        assert_eq!(meta.version, 1);
        assert!(!meta.timestamps.issued_at.is_empty());
        assert_eq!(meta.created_at, meta.timestamps.issued_at);
    }

    #[test]
    fn new_metadata_stores_all_fields() {
        let meta = SandboxMetadata::new(
            SandboxId::from_string("sbx_test"),
            TenantId::from_string("tenant-1"),
            "alpine-6.1".into(),
            Some(RuntimeType::Firecracker),
            ResourceLimits::default(),
            Some([("purpose".into(), "test".into())].into_iter().collect()),
        );
        let id_str = meta.id.as_str();
        assert_eq!(id_str, "sbx_test");
        assert_eq!(meta.tenant_id.as_str(), "tenant-1");
        assert_eq!(meta.image, "alpine-6.1");
        assert_eq!(meta.runtime, Some(RuntimeType::Firecracker));
        assert_eq!(meta.labels.unwrap().get("purpose").unwrap(), "test");
    }

    // ================================================================
    // Serialization round-trips
    // ================================================================

    #[test]
    fn lifecycle_state_serde_roundtrip() {
        for state in SandboxState::ALL {
            let json = serde_json::to_string(state).unwrap();
            let deserialized: SandboxState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, deserialized, "roundtrip failed for {state}");
        }
    }

    #[test]
    fn failure_info_serde_roundtrip() {
        let failure = FailureInfo {
            code: FailureCode::BootTimeout,
            message: "guest agent did not respond".into(),
            component: Some("host-agent".into()),
            retryable: true,
            occurred_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&failure).unwrap();
        let deserialized: FailureInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(failure, deserialized);
    }

    #[test]
    fn metadata_serde_roundtrip() {
        let meta = SandboxMetadata::new(
            SandboxId::from_string("sbx_test"),
            TenantId::from_string("tenant-1"),
            "alpine-6.1".into(),
            Some(RuntimeType::Firecracker),
            ResourceLimits::default(),
            None,
        );
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: SandboxMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.id, deserialized.id);
        assert_eq!(meta.state, deserialized.state);
        assert_eq!(meta.version, deserialized.version);
        assert_eq!(meta.tenant_id, deserialized.tenant_id);
    }

    #[test]
    fn placement_info_serde_roundtrip() {
        let placement = PlacementInfo {
            region: Some("us-east-1".into()),
            cell: Some("cell-01".into()),
            host: Some("host-42".into()),
            runtime_backend: Some(RuntimeType::Firecracker),
            network_identity: Some("10.0.1.42".into()),
        };
        let json = serde_json::to_string(&placement).unwrap();
        let deserialized: PlacementInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(placement, deserialized);
    }

    #[test]
    fn secure_timestamps_serde_roundtrip() {
        let ts = SecureTimestamps {
            issued_at: "2026-01-01T00:00:00Z".into(),
            observed_at: Some("2026-01-01T00:00:01Z".into()),
            committed_at: Some("2026-01-01T00:00:02Z".into()),
            expires_at: Some("2026-01-01T00:05:00Z".into()),
        };
        let json = serde_json::to_string(&ts).unwrap();
        let deserialized: SecureTimestamps = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, deserialized);
    }

    #[test]
    fn transition_error_display_and_debug() {
        let err = TransitionError::InvalidTransition {
            from: SandboxState::Running,
            to: SandboxState::Destroying,
        };
        assert!(err.to_string().contains("Running"));
        assert!(err.to_string().contains("Destroying"));

        let err = TransitionError::VersionConflict {
            expected: 5,
            actual: 3,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));

        let err = TransitionError::AlreadyInState(SandboxState::Destroyed);
        assert!(err.to_string().contains("Destroyed"));

        let err = TransitionError::TransitoryTimeout {
            state: SandboxState::Booting,
            duration_secs: 310,
        };
        assert!(err.to_string().contains("Booting"));
        assert!(err.to_string().contains("310"));

        let err = TransitionError::StaleOperation {
            op_id: "op_old".into(),
        };
        assert!(err.to_string().contains("op_old"));

        let err = TransitionError::StalePolicyEpoch {
            op_epoch: 1,
            current_epoch: 2,
        };
        assert!(err.to_string().contains("1"));
        assert!(err.to_string().contains("2"));

        let err = TransitionError::TerminalState(SandboxState::Destroyed);
        assert!(err.to_string().contains("Destroyed"));

        let err = TransitionError::UnexpectedState {
            expected: SandboxState::Running,
            actual: SandboxState::Preparing,
        };
        assert!(err.to_string().contains("Running"));
        assert!(err.to_string().contains("Preparing"));
    }

    // ================================================================
    // Default resource limits
    // ================================================================

    #[test]
    fn default_resource_limits_are_reasonable() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_mb, 512);
        assert_eq!(limits.vcpus, 2);
        assert_eq!(limits.idle_timeout_secs, 300);
    }

    // ================================================================
    // Helper
    // ================================================================

    fn make_test_metadata() -> SandboxMetadata {
        SandboxMetadata::new(
            SandboxId::from_string("sbx_test"),
            TenantId::from_string("tenant-1"),
            "alpine-6.1".into(),
            None,
            ResourceLimits::default(),
            None,
        )
    }
}
