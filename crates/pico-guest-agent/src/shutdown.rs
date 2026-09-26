//! Shutdown handler for the guest agent. Supports graceful and forced
//! shutdown with idempotent behavior.
//!
//! The handler sets a flag that the dispatch loop checks at the top of
//! each iteration.  Graceful shutdown allows the loop to break cleanly;
//! forced shutdown calls `process::exit` after sending the acknowledgement.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, write_tagged_response};

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum ShutdownError {
    #[error("already shutting down")]
    AlreadyShuttingDown,

    #[error("context validation failed: {0}")]
    ContextValidation(String),
}

#[derive(Debug, Clone)]
pub(crate) struct ShutdownState {
    pub shutting_down: Arc<AtomicBool>,
}

impl ShutdownState {
    pub(crate) fn new() -> Self {
        Self {
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub(crate) async fn handle_shutdown(
    session: &OperationalSession,
    request: ShutdownRequest,
    writer: &SharedWriter,
    timeout: std::time::Duration,
    shutdown_state: &ShutdownState,
) -> Result<(), ShutdownError> {
    let _ = crate::secrets::teardown_secrets_mount();

    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| ShutdownError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| ShutdownError::ContextValidation(e.to_string()))?;

    if shutdown_state.shutting_down.swap(true, Ordering::AcqRel) {
        return Err(ShutdownError::AlreadyShuttingDown);
    }

    let reason = if request.reason.is_empty() {
        "requested by host".to_string()
    } else {
        request.reason.clone()
    };

    let is_force = request.force;
    tracing::info!(
        reason = %reason,
        force = is_force,
        "shutdown initiated"
    );

    let response = ShutdownResponse {
        result: Some(shutdown_response::Result::ShuttingDown(true)),
    };

    write_tagged_response(writer, framed::TAG_SHUTDOWN_RESPONSE, &response, timeout)
        .await
        .map_err(|e| ShutdownError::ContextValidation(format!("send shutdown response: {e}")))?;

    if is_force {
        // Force shutdown bypasses the dispatch-loop drain: the guest
        // must terminate immediately to satisfy the operator's intent
        // (e.g. emergency resource reclamation, node drain, security
        // incident).  process::exit runs atexit handlers registered by
        // the runtime but skips unwinding and drop of async tasks, which
        // is acceptable because there is no more meaningful work to do
        // after the shutdown acknowledgement has been sent.
        tracing::warn!(reason = %reason, "force shutdown — exiting immediately");
        std::process::exit(0);
    } else {
        tracing::info!(reason = %reason, "graceful shutdown — letting dispatch loop drain");
        // The dispatch loop checks shutting_down at the top of each
        // iteration and will break after processing this message.
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_state_starts_not_shutting_down() {
        let state = ShutdownState::new();
        assert!(!state.shutting_down.load(Ordering::Acquire));
    }

    #[test]
    fn shutdown_state_idempotent() {
        let state = ShutdownState::new();
        assert!(!state.shutting_down.swap(true, Ordering::AcqRel));
        assert!(state.shutting_down.swap(true, Ordering::AcqRel));
        assert!(state.shutting_down.load(Ordering::Acquire));
    }

    #[test]
    fn shutdown_response_has_expected_values() {
        let resp = ShutdownResponse {
            result: Some(shutdown_response::Result::ShuttingDown(true)),
        };
        assert!(matches!(
            resp.result,
            Some(shutdown_response::Result::ShuttingDown(true))
        ));

        let err_resp = ShutdownResponse {
            result: Some(shutdown_response::Result::Error(OperationOutcome {
                status: Some(operation_outcome::Status::Failure(
                    operation_outcome::Failure {
                        code: "AlreadyShuttingDown".into(),
                        message: "shutdown already in progress".into(),
                        retryable: false,
                    },
                )),
            })),
        };
        match err_resp.result {
            Some(shutdown_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "AlreadyShuttingDown");
                }
                _ => panic!("expected failure"),
            },
            _ => panic!("expected error"),
        }
    }
}
