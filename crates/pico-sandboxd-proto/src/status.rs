//! Map sandboxd operation outcomes and error classes to tonic status codes.
//!
//! This module is intentionally free of a dependency on `pico-sandboxd` so
//! host-agent and sandboxd can share the same mapping without a crate cycle.
//! Wire `status`/`reason_code` are proto enums in `pico.sandboxd.v1`.

use tonic::{Code, Status};

use crate::v1::{OutcomeReason, OutcomeStatus};

/// gRPC metadata key for the shared host-agent <-> sandboxd token.
pub const METADATA_TOKEN_KEY: &str = "x-pico-sandboxd-token";

/// Stable error class for mapping host/sandboxd failures to gRPC codes.
///
/// Mirrors `SupervisorError` variants without importing that type, and extends
/// them with RPC-layer classes (`Unauthenticated`, `PermissionDenied`,
/// `NotFound`, `Internal`) that have no ledger equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorErrorClass {
    /// Ledger/SQL failure.
    Ledger,
    /// Local I/O failure.
    Io,
    /// Corrupt ledger payload.
    InvalidLedgerValue,
    /// Assignment fencing token is stale.
    StaleFencingToken,
    /// Operation already active.
    OperationInProgress,
    /// Operation id reused with different identity.
    OperationIdentityConflict,
    /// Policy epoch is stale.
    StalePolicyEpoch,
    /// No runtime handle attached.
    RuntimeNotAttached,
    /// Command sandbox id does not match config.
    SandboxMismatch,
    /// Invalid process request.
    InvalidProcessRequest,
    /// Auth token or peer credentials rejected.
    Unauthenticated,
    /// Caller not permitted for this socket/sandbox.
    PermissionDenied,
    /// Sandbox not found in ledger.
    NotFound,
    /// Snapshot restore or fork failed before backend execution.
    SnapshotRestore,
    /// Catch-all internal failure.
    Internal,
}

impl SupervisorErrorClass {
    /// Returns the tonic code used when this class is raised as an RPC error
    /// (as opposed to a successful RPC carrying a failed [`crate::v1::Outcome`]).
    #[must_use]
    pub fn tonic_code(self) -> Code {
        match self {
            Self::Ledger | Self::Io | Self::InvalidLedgerValue | Self::Internal => Code::Internal,
            Self::StaleFencingToken | Self::StalePolicyEpoch | Self::OperationIdentityConflict => {
                Code::FailedPrecondition
            }
            Self::SnapshotRestore => Code::FailedPrecondition,
            Self::OperationInProgress => Code::AlreadyExists,
            Self::RuntimeNotAttached | Self::NotFound => Code::NotFound,
            Self::SandboxMismatch | Self::InvalidProcessRequest => Code::InvalidArgument,
            Self::Unauthenticated => Code::Unauthenticated,
            Self::PermissionDenied => Code::PermissionDenied,
        }
    }

    /// Builds a tonic [`Status`] with a redacted message.
    #[must_use]
    pub fn status(self, message: impl Into<String>) -> Status {
        Status::new(self.tonic_code(), message)
    }
}

/// Map a terminal or active outcome `status` enum to a tonic code when
/// the server chooses to surface the outcome as a gRPC error.
///
/// Successful RPCs normally return `Outcome` in the response body even when
/// `status == Failed`. Use this when a call cannot produce a body (auth, parse)
/// or when a streaming call aborts before `ExecFailed`.
#[must_use]
pub fn outcome_status_to_code(status: OutcomeStatus) -> Code {
    match status {
        OutcomeStatus::Succeeded | OutcomeStatus::Running => Code::Ok,
        OutcomeStatus::Canceled => Code::Cancelled,
        OutcomeStatus::TimedOut => Code::DeadlineExceeded,
        OutcomeStatus::RequiresReview => Code::FailedPrecondition,
        OutcomeStatus::Failed => Code::Internal,
        OutcomeStatus::Unspecified => Code::Unknown,
    }
}

/// Map a wire `reason_code` enum to a tonic code for finer failure classification.
#[must_use]
pub fn outcome_reason_to_code(reason_code: OutcomeReason) -> Code {
    match reason_code {
        OutcomeReason::Completed | OutcomeReason::InProgress | OutcomeReason::ProcessExited => {
            Code::Ok
        }
        OutcomeReason::CanceledByHost => Code::Cancelled,
        OutcomeReason::DeadlineExceeded => Code::DeadlineExceeded,
        OutcomeReason::PartialCleanup
        | OutcomeReason::SupervisorRestarted
        | OutcomeReason::BackendFailure
        | OutcomeReason::RestoreRejected => Code::FailedPrecondition,
        OutcomeReason::ProcessSignaled | OutcomeReason::ProcessFailure => Code::Internal,
        OutcomeReason::Unspecified => Code::Unknown,
    }
}

/// Prefer reason-specific codes when present; fall back to outcome status.
#[must_use]
pub fn outcome_to_code(status: OutcomeStatus, reason_code: OutcomeReason) -> Code {
    let from_reason = outcome_reason_to_code(reason_code);
    if from_reason != Code::Unknown && from_reason != Code::Ok {
        return from_reason;
    }
    if status == OutcomeStatus::Succeeded || status == OutcomeStatus::Running {
        return Code::Ok;
    }
    let from_status = outcome_status_to_code(status);
    if from_status != Code::Unknown {
        return from_status;
    }
    from_reason
}

/// Build a status from outcome wire enums (for stream abort/no-body paths).
#[must_use]
pub fn status_from_outcome_fields(
    status: OutcomeStatus,
    reason_code: OutcomeReason,
    message: Option<&str>,
) -> Status {
    let code = outcome_to_code(status, reason_code);
    let msg = message
        .unwrap_or(match status {
            OutcomeStatus::Succeeded => "succeeded",
            OutcomeStatus::Running => "running",
            OutcomeStatus::Failed => "failed",
            OutcomeStatus::Canceled => "canceled",
            OutcomeStatus::TimedOut => "timed_out",
            OutcomeStatus::RequiresReview => "requires_review",
            OutcomeStatus::Unspecified => "unspecified",
        })
        .to_string();
    Status::new(code, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{OutcomeReason, OutcomeStatus};

    #[test]
    fn stale_fencing_is_failed_precondition() {
        assert_eq!(
            SupervisorErrorClass::StaleFencingToken.tonic_code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn snapshot_restore_is_failed_precondition() {
        assert_eq!(
            SupervisorErrorClass::SnapshotRestore.tonic_code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn operation_in_progress_is_already_exists() {
        assert_eq!(
            SupervisorErrorClass::OperationInProgress.tonic_code(),
            Code::AlreadyExists
        );
    }

    #[test]
    fn timed_out_outcome_maps_to_deadline_exceeded() {
        assert_eq!(
            outcome_to_code(OutcomeStatus::TimedOut, OutcomeReason::DeadlineExceeded),
            Code::DeadlineExceeded
        );
    }

    #[test]
    fn canceled_outcome_maps_to_cancelled() {
        assert_eq!(
            outcome_to_code(OutcomeStatus::Canceled, OutcomeReason::CanceledByHost),
            Code::Cancelled
        );
    }

    #[test]
    fn succeeded_is_ok() {
        assert_eq!(
            outcome_to_code(OutcomeStatus::Succeeded, OutcomeReason::Completed),
            Code::Ok
        );
    }

    #[test]
    fn metadata_token_key_matches_adr() {
        assert_eq!(METADATA_TOKEN_KEY, "x-pico-sandboxd-token");
    }

    #[test]
    fn process_failure_reasons_map_to_internal() {
        assert_eq!(
            outcome_reason_to_code(OutcomeReason::ProcessSignaled),
            Code::Internal
        );
        assert_eq!(
            outcome_reason_to_code(OutcomeReason::ProcessFailure),
            Code::Internal
        );
    }

    #[test]
    fn outcome_reason_all_is_exhaustive_and_mapped() {
        let all = [
            OutcomeReason::InProgress,
            OutcomeReason::Completed,
            OutcomeReason::BackendFailure,
            OutcomeReason::CanceledByHost,
            OutcomeReason::DeadlineExceeded,
            OutcomeReason::PartialCleanup,
            OutcomeReason::SupervisorRestarted,
            OutcomeReason::ProcessExited,
            OutcomeReason::ProcessSignaled,
            OutcomeReason::ProcessFailure,
            OutcomeReason::RestoreRejected,
        ];
        assert_eq!(all.len(), 11);
        for reason in all {
            assert_ne!(
                outcome_reason_to_code(reason),
                Code::Unknown,
                "unmapped reason_code {reason:?}"
            );
        }
    }

    #[test]
    fn unspecified_maps_to_unknown() {
        assert_eq!(
            outcome_status_to_code(OutcomeStatus::Unspecified),
            Code::Unknown
        );
        assert_eq!(
            outcome_reason_to_code(OutcomeReason::Unspecified),
            Code::Unknown
        );
    }
}
