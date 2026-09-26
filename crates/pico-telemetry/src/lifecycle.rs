//! Shared lifecycle operation and outcome taxonomy.
//!
//! All lifecycle metrics MUST use the constants and helpers defined here
//! to ensure consistent label values across services.

/// Lifecycle operation identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleOperation {
    Create,
    Schedule,
    Prepare,
    Boot,
    Ready,
    Exec,
    Suspend,
    Resume,
    Fork,
    Destroy,
    ImagePrepare,
    NetworkSetup,
    SnapshotRestore,
    Cleanup,
}

impl LifecycleOperation {
    /// Returns the canonical label value for this operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Schedule => "schedule",
            Self::Prepare => "prepare",
            Self::Boot => "boot",
            Self::Ready => "ready",
            Self::Exec => "exec",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Fork => "fork",
            Self::Destroy => "destroy",
            Self::ImagePrepare => "image_prepare",
            Self::NetworkSetup => "network_setup",
            Self::SnapshotRestore => "snapshot_restore",
            Self::Cleanup => "cleanup",
        }
    }
}

/// Lifecycle outcome taxonomy.
///
/// Use these to consistently label success, failure, and rejection
/// reasons across all lifecycle metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleOutcome {
    /// Operation completed successfully.
    Success,
    /// Operation timed out.
    Timeout,
    /// Operation was cancelled by the caller.
    Cancelled,
    /// Policy engine rejected the request.
    PolicyRejected,
    /// Quota exceeded.
    QuotaRejected,
    /// Placement failed (no suitable host or resource).
    PlacementFailed,
    /// Runtime reported an error.
    RuntimeFailed,
    /// Internal or unknown failure.
    InternalError,
}

/// Resource limit events emitted during sandbox execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceEvent {
    /// Cgroup OOM kill occurred.
    OomKilled,
    /// Soft memory limit (memory.high) exceeded.
    MemoryHigh,
    /// CPU throttling occurred.
    CpuThrottled,
    /// PID limit reached.
    PidLimitHit,
}

impl ResourceEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OomKilled => "oom_killed",
            Self::MemoryHigh => "memory_high",
            Self::CpuThrottled => "cpu_throttled",
            Self::PidLimitHit => "pid_limit_hit",
        }
    }
}

impl LifecycleOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::PolicyRejected => "policy_rejected",
            Self::QuotaRejected => "quota_rejected",
            Self::PlacementFailed => "placement_failed",
            Self::RuntimeFailed => "runtime_failed",
            Self::InternalError => "internal_error",
        }
    }
}
