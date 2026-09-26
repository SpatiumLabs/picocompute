//! Stop/stop-purge/destroy caller contract.
//!
//! Single owner for the `stop`/`purge`/`destroy` split used by
//! [`crate::SandboxFacade`]. The transition table in [`crate::metadata`]
//! defines what the state machine allows; this module defines what callers
//! must intend:
//!
//! | Call      | Intended transition              | Misuse rejected                      |
//! |-----------|----------------------------------|----------------------------------------|
//! | `stop`    | `Running` -> `Stopped` (idempotent on `Stopped`) | non-`Running` live states (`409`) |
//! | `purge`   | `Stopped` -> teardown (requires prior `stop`) | `Running`/`Preparing`/`Suspended`/etc (`409`) |
//! | `destroy` | force-teardown from any non-terminal state | terminal state (`409` if retained, otherwise `404`) |
//!
//! `purge` is not an alias for `destroy`. A caller that wants force-teardown
//! calls `destroy`. A caller that wants post-`stop` cleanup calls `purge`
//! after `stop` succeeds. The guard functions below close the wrong-call
//! path at the backend boundary so a `purge`-on-`Running` mistake cannot
//! delete a live workload.

use crate::{Result, SandboxError, SandboxState, TransitionError, can_transition};

/// Rejects `stop` from any state except `Running` (plus idempotent `Stopped`).
///
/// # Errors
///
/// Returns [`SandboxError::InvalidStateTransition`] when `state` is not
/// `Running` or `Stopped`.
pub fn ensure_stop_precondition(state: SandboxState) -> Result<()> {
    // Repeated stop is an operation-level idempotent retry, even though the
    // raw state-machine transition reports AlreadyInState.
    if state == SandboxState::Stopped {
        return Ok(());
    }
    if can_transition(state, SandboxState::Stopped).is_ok() {
        return Ok(());
    }
    Err(SandboxError::InvalidStateTransition(format!(
        "cannot stop sandbox from state {state}"
    )))
}

/// Rejects `destroy` only when the record is already terminal.
///
/// Destroy remains a force path for every non-terminal state, including
/// `Failed` and `Destroying` retries. A terminal record is normally removed
/// by the adapter, so callers normally observe `SandboxNotFound` instead.
pub fn ensure_destroy_precondition(state: SandboxState) -> Result<()> {
    match can_transition(state, SandboxState::Destroying) {
        Ok(()) | Err(TransitionError::AlreadyInState(SandboxState::Destroying)) => Ok(()),
        Err(_) => Err(SandboxError::InvalidStateTransition(format!(
            "cannot destroy sandbox from terminal state {state}"
        ))),
    }
}

/// Rejects `purge` from any state except `Stopped`.
///
/// `purge` is post-`stop` cleanup. Callers that want force-teardown of a
/// live sandbox must call `destroy` instead.
///
/// # Errors
///
/// Returns [`SandboxError::InvalidStateTransition`] when `state` is not
/// `Stopped`.
pub fn ensure_purge_precondition(state: SandboxState) -> Result<()> {
    if state == SandboxState::Stopped && can_transition(state, SandboxState::Destroying).is_ok() {
        Ok(())
    } else {
        Err(SandboxError::InvalidStateTransition(format!(
            "cannot purge sandbox from state {state}; stop first (purge requires Stopped, use destroy for force-teardown)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxState;

    #[test]
    fn stop_accepts_running_and_stopped() {
        assert!(ensure_stop_precondition(SandboxState::Running).is_ok());
        assert!(ensure_stop_precondition(SandboxState::Stopped).is_ok());
    }

    #[test]
    fn stop_rejects_other_live_states() {
        for state in [
            SandboxState::Pending,
            SandboxState::Scheduled,
            SandboxState::Preparing,
            SandboxState::Booting,
            SandboxState::Suspending,
            SandboxState::Suspended,
            SandboxState::Resuming,
            SandboxState::Failed,
            SandboxState::Destroying,
            SandboxState::Destroyed,
        ] {
            assert!(
                ensure_stop_precondition(state).is_err(),
                "stop from {state} must be rejected"
            );
        }
    }

    #[test]
    fn destroy_rejects_terminal_state_but_allows_force_paths() {
        assert!(ensure_destroy_precondition(SandboxState::Running).is_ok());
        assert!(ensure_destroy_precondition(SandboxState::Failed).is_ok());
        assert!(ensure_destroy_precondition(SandboxState::Destroying).is_ok());
        assert!(ensure_destroy_precondition(SandboxState::Destroyed).is_err());
    }

    #[test]
    fn purge_requires_stopped() {
        assert!(ensure_purge_precondition(SandboxState::Stopped).is_ok());
    }

    #[test]
    fn purge_rejects_live_states() {
        for state in [
            SandboxState::Pending,
            SandboxState::Scheduled,
            SandboxState::Preparing,
            SandboxState::Booting,
            SandboxState::Running,
            SandboxState::Suspending,
            SandboxState::Suspended,
            SandboxState::Resuming,
            SandboxState::Failed,
            SandboxState::Destroying,
            SandboxState::Destroyed,
        ] {
            let err = ensure_purge_precondition(state).unwrap_err();
            assert!(
                matches!(err, SandboxError::InvalidStateTransition(_)),
                "purge from {state} must be InvalidStateTransition"
            );
            assert!(
                err.to_string().contains("stop first"),
                "purge error must direct callers to stop first, got: {err}"
            );
        }
    }
}
