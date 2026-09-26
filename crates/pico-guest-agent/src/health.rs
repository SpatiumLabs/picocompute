//! Health check handler for the guest agent.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;
use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, write_tagged_response};

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum HealthError {
    #[error("context validation failed: {0}")]
    ContextValidation(String),
}

#[derive(Debug, Clone)]
pub(crate) struct HealthState {
    pub degraded: Arc<AtomicBool>,
    pub last_error: Arc<Mutex<Option<(String, std::time::Instant)>>>,
    pub request_count: Arc<AtomicU64>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthState {
    pub(crate) fn new() -> Self {
        Self {
            degraded: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(Mutex::new(None)),
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

pub(crate) async fn handle_health(
    session: &OperationalSession,
    request: HealthRequest,
    writer: &SharedWriter,
    timeout: std::time::Duration,
    health_state: &HealthState,
) -> Result<(), HealthError> {
    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| HealthError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| HealthError::ContextValidation(e.to_string()))?;

    health_state.request_count.fetch_add(1, Ordering::Relaxed);

    let (status, message) = if health_state.degraded.load(Ordering::Acquire) {
        let last_error = health_state.last_error.lock();
        let detail = last_error
            .as_ref()
            .map(|(msg, _)| msg.as_str())
            .unwrap_or("unknown degradation");
        (
            health_response::HealthStatus::Degraded as i32,
            format!("degraded: {detail}"),
        )
    } else {
        (
            health_response::HealthStatus::Ok as i32,
            "all subsystems ok".into(),
        )
    };

    let response = HealthResponse { status, message };

    write_tagged_response(writer, framed::TAG_HEALTH_RESPONSE, &response, timeout)
        .await
        .map_err(|e| HealthError::ContextValidation(format!("send health response: {e}")))?;

    tracing::debug!(
        status = response.status,
        request_count = health_state.request_count.load(Ordering::Relaxed),
        "health check completed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_state_starts_healthy() {
        let state = HealthState::new();
        assert!(!state.degraded.load(Ordering::Acquire));
        assert!(state.last_error.lock().is_none());
    }

    #[test]
    fn health_state_can_be_degraded() {
        let state = HealthState::new();
        // Write last_error *before* setting the release-store on degraded,
        // so an acquire-load of degraded guarantees visibility of last_error.
        *state.last_error.lock() = Some(("disk full".into(), std::time::Instant::now()));
        state.degraded.store(true, Ordering::Release);
        assert!(state.degraded.load(Ordering::Acquire));
        assert_eq!(state.last_error.lock().as_ref().unwrap().0, "disk full");
    }

    #[test]
    fn health_state_can_be_restored() {
        let state = HealthState::new();
        state.degraded.store(true, Ordering::Release);
        // Clear last_error *before* clearing the degraded flag, so an
        // acquire-load of degraded==false sees the cleared last_error.
        *state.last_error.lock() = None;
        state.degraded.store(false, Ordering::Release);
        assert!(!state.degraded.load(Ordering::Acquire));
        assert!(state.last_error.lock().is_none());
    }

    #[test]
    fn request_count_increments() {
        let state = HealthState::new();
        assert_eq!(state.request_count.load(Ordering::Relaxed), 0);
        state.request_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(state.request_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn health_response_status_values() {
        assert_eq!(health_response::HealthStatus::Unspecified as i32, 0);
        assert_eq!(health_response::HealthStatus::Ok as i32, 1);
        assert_eq!(health_response::HealthStatus::Degraded as i32, 2);
        assert_eq!(health_response::HealthStatus::Unhealthy as i32, 3);
    }
}
