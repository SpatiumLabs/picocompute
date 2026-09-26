//! Shared error types used across the PicoCompute crates.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SandboxError>;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox not found: {0}")]
    SandboxNotFound(String),
    #[error("task not found: {0}")]
    TaskNotFound(String),
    #[error("workspace not found: {0}")]
    WorkspaceNotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("path escapes workspace: {0}")]
    PathEscape(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    /// A requested host port is already bound by another sandbox or process.
    #[error("port in use: {0}")]
    PortInUse(u16),
    #[error("unprocessable: {0}")]
    Unprocessable(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("runtime not ready: {0}")]
    NotReady(String),
    #[error("invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("version conflict: {0}")]
    VersionConflict(String),
    #[error("stale operation: {0}")]
    OperationStale(String),
    #[error("quota exceeded: {resource} limit={limit} current={current}")]
    QuotaExceeded {
        resource: String,
        limit: u64,
        current: u64,
    },
    /// A bounded resource was exhausted without quota semantics.
    ///
    /// Unlike [`SandboxError::QuotaExceeded`], this carries no limit/current
    /// numbers: it reports transport and payload bounds (e.g. sandboxd file
    /// caps) where fabricating quota figures would mislead operators.
    #[error("resource exhausted: {detail}")]
    ResourceExhausted { detail: String },
    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },
    #[error("backend selection rejected for class {class}: {rejected_count} candidates failed")]
    BackendSelectionRejected {
        class: String,
        rejected_count: usize,
        reasons: Vec<String>,
    },
    /// Scheduler placement shed load under pressure or capacity exhaustion.
    ///
    /// Fail-closed admission signal for `InsufficientCapacity` and
    /// `PressureSaturated` outcomes. The API maps this to 422 with a
    /// `Retry-After` hint (preserving the existing unprocessable contract)
    /// instead of silently falling back to another backend or host.
    #[error("placement throttled: {reason} (retry after {retry_after_secs}s)")]
    PlacementThrottled {
        reason: String,
        retry_after_secs: u64,
    },
    /// Cgroup setup failed for a specific controller.
    #[error("cgroup setup failed for controller {controller}: {reason}")]
    CgroupSetupFailed { controller: String, reason: String },
    /// Cgroup cleanup failed after bounded transient retries.
    ///
    /// Destroy and GC already retried EBUSY/ENOTEMPTY-style failures in-process.
    /// Remaining failures need a later GC pass or operator review.
    #[error("cgroup cleanup failed: {reason}")]
    CgroupCleanupFailed { reason: String },
    #[error("{0}")]
    Other(String),
}

impl From<crate::metadata::TransitionError> for SandboxError {
    fn from(err: crate::metadata::TransitionError) -> Self {
        match err {
            crate::metadata::TransitionError::InvalidTransition { from, to } => {
                SandboxError::InvalidStateTransition(format!(
                    "cannot transition from {from} to {to}"
                ))
            }
            crate::metadata::TransitionError::AlreadyInState(state) => {
                SandboxError::Conflict(format!("sandbox is already {state}"))
            }
            crate::metadata::TransitionError::VersionConflict { expected, actual } => {
                SandboxError::VersionConflict(format!("expected version {expected}, got {actual}"))
            }
            crate::metadata::TransitionError::TransitoryTimeout {
                state,
                duration_secs,
            } => SandboxError::InvalidStateTransition(format!(
                "transitory state {state} timed out after {duration_secs}s"
            )),
            crate::metadata::TransitionError::StaleOperation { op_id } => {
                SandboxError::OperationStale(op_id)
            }
            crate::metadata::TransitionError::StalePolicyEpoch {
                op_epoch,
                current_epoch,
            } => SandboxError::Conflict(format!(
                "stale policy epoch {op_epoch} (current: {current_epoch})"
            )),
            crate::metadata::TransitionError::StaleFencingToken {
                request_token,
                current_token,
            } => SandboxError::Conflict(format!(
                "stale fencing token {request_token} (current: {current_token})"
            )),
            crate::metadata::TransitionError::TerminalState(state) => {
                SandboxError::InvalidStateTransition(format!(
                    "cannot transition from terminal state {state}"
                ))
            }
            crate::metadata::TransitionError::UnexpectedState { expected, actual } => {
                SandboxError::InvalidStateTransition(format!(
                    "unexpected state: expected {expected}, actual {actual}"
                ))
            }
        }
    }
}

impl From<crate::cell_scheduler::CellSchedulerError> for SandboxError {
    fn from(err: crate::cell_scheduler::CellSchedulerError) -> Self {
        // Narrow: only capacity/pressure carry Retry-After through CreateError.
        // Empty-registry (NoHostsAvailable) and draining stay Unprocessable
        // here to preserve the pre-unification CreateError contract; the API
        // gate handles empty registries via its own NoCapacity path.
        match err {
            crate::cell_scheduler::CellSchedulerError::InsufficientCapacity { .. }
            | crate::cell_scheduler::CellSchedulerError::PressureSaturated => {
                SandboxError::PlacementThrottled {
                    reason: err.to_string(),
                    retry_after_secs: PLACEMENT_RETRY_AFTER_SECS,
                }
            }
            other => SandboxError::Unprocessable(other.to_string()),
        }
    }
}

impl From<crate::scheduler::SchedulerError> for SandboxError {
    fn from(err: crate::scheduler::SchedulerError) -> Self {
        // Narrow: only capacity/pressure carry Retry-After through CreateError.
        // Empty-region (NoCellsAvailable) and FailureDomainExhausted stay
        // Unprocessable here to preserve the pre-unification contract; the
        // gate maps empty registries via NoCapacity and throttles
        // FailureDomainExhausted explicitly.
        match err {
            crate::scheduler::SchedulerError::InsufficientCapacity { .. }
            | crate::scheduler::SchedulerError::PressureSaturated => {
                SandboxError::PlacementThrottled {
                    reason: err.to_string(),
                    retry_after_secs: PLACEMENT_RETRY_AFTER_SECS,
                }
            }
            other => SandboxError::Unprocessable(other.to_string()),
        }
    }
}

/// Retry hint for throttled placement when the admit path has no gate
/// configured hint of its own. This is the single owner of the 30s value;
/// `pico-api` aliases it for the gate default.
pub const PLACEMENT_RETRY_AFTER_SECS: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_error_display() {
        let err = SandboxError::SandboxNotFound("abc".into());
        assert_eq!(err.to_string(), "sandbox not found: abc");

        let _io_err = SandboxError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file"));
        assert!(err.to_string().contains("sandbox not found"));

        let other = SandboxError::Other("something broke".into());
        assert_eq!(other.to_string(), "something broke");
    }

    #[test]
    fn sandbox_error_debug() {
        let err = SandboxError::Other("test".into());
        assert!(!format!("{err:?}").is_empty());
    }

    #[test]
    fn quota_exceeded_display() {
        let err = SandboxError::QuotaExceeded {
            resource: "vcpus".into(),
            limit: 32,
            current: 32,
        };
        assert!(err.to_string().contains("quota exceeded"));
        assert!(err.to_string().contains("vcpus"));
    }

    #[test]
    fn policy_denied_display() {
        let err = SandboxError::PolicyDenied {
            reason: "untrusted image provenance".into(),
        };
        assert!(err.to_string().contains("policy denied"));
        assert!(err.to_string().contains("untrusted image"));
    }

    #[test]
    fn sandbox_error_from_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: SandboxError = io.into();
        assert!(err.to_string().contains("denied"));
    }

    #[test]
    fn resource_exhausted_preserves_detail_without_quota_numbers() {
        let err = SandboxError::ResourceExhausted {
            detail: "sandboxd: file out.bin exceeds max_bytes 1024".into(),
        };
        assert!(err.to_string().contains("resource exhausted"));
        assert!(err.to_string().contains("out.bin"));
    }

    #[test]
    fn scheduler_capacity_errors_preserve_retry_hint() {
        for regional_err in [
            crate::scheduler::SchedulerError::InsufficientCapacity {
                vcpus: 8,
                memory_mb: 16384,
            },
            crate::scheduler::SchedulerError::PressureSaturated,
        ] {
            let err: SandboxError = regional_err.into();
            match err {
                SandboxError::PlacementThrottled {
                    reason,
                    retry_after_secs,
                } => {
                    assert_eq!(retry_after_secs, PLACEMENT_RETRY_AFTER_SECS);
                    assert!(!reason.is_empty());
                }
                other => panic!("expected PlacementThrottled, got {other:?}"),
            }
        }

        for cell_err in [
            crate::cell_scheduler::CellSchedulerError::InsufficientCapacity {
                vcpus: 8,
                memory_mb: 16384,
                disk_mb: 1024,
            },
            crate::cell_scheduler::CellSchedulerError::PressureSaturated,
        ] {
            let err: SandboxError = cell_err.into();
            match err {
                SandboxError::PlacementThrottled {
                    retry_after_secs, ..
                } => {
                    assert_eq!(retry_after_secs, PLACEMENT_RETRY_AFTER_SECS);
                }
                other => panic!("expected PlacementThrottled, got {other:?}"),
            }
        }
    }

    #[test]
    fn scheduler_hard_rejections_stay_unprocessable() {
        let err: SandboxError = crate::scheduler::SchedulerError::UnsupportedRuntime {
            runtime: "kata".into(),
        }
        .into();
        assert!(matches!(err, SandboxError::Unprocessable(_)));

        let err: SandboxError = crate::cell_scheduler::CellSchedulerError::AllHostsDraining.into();
        assert!(matches!(err, SandboxError::Unprocessable(_)));
    }
}
