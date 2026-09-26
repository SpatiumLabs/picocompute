//! Cancellable control plane shared by cancel/signal/force-cancel-all.
//!
//! Previously `handle_cancel`, `handle_signal`, and `force_cancel_all` each
//! held a copy of the same `ctrl_tx.take()` block. The `take()` consumed the
//! control sender on first use, so a second signal to the same operation
//! fell through to `Unknown`/`OperationNotFound`. All control sends now go
//! through this module, which never consumes the sender: repeat
//! cancel/signal delivery to an active operation is idempotent and returns
//! `Accepted`/`Acknowledged`.
//!
//! ADR-0003 requires `Cancel` to be idempotent with typed
//! accepted/already-terminal/unknown outcomes. This module implements the
//! guest side of that contract: an operation present in the registry
//! acknowledges repeat control; only a missing operation reports unknown.
//! Signal numbers are validated here so invalid values get a typed error
//! instead of an unchecked `libc::kill` call.

use hashbrown::HashMap;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

/// Control signal delivered to a running exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CancelSignal {
    Cancel,
    Signal(i32),
}

/// Per-operation control handle.
///
/// The `ctrl_tx` sender is never taken: clones of the `Arc<Mutex<...>>`
/// wrapper stay in the registry for the life of the operation so repeat
/// sends succeed.
pub(crate) struct ExecHandle {
    #[allow(dead_code)]
    pub operation_id: String,
    pub ctrl_tx: watch::Sender<Option<CancelSignal>>,
    pub start_time: Instant,
}

/// Shared registry of active execs.
pub(crate) type SharedExecMap = Arc<Mutex<HashMap<String, Arc<Mutex<ExecHandle>>>>>;

/// Result of a signal send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignalSend {
    Acknowledged,
    Unknown,
    InvalidSignal(String),
}

/// Maximum valid signal number (platform-specific).
///
/// Linux guests accept real-time signals up to 64 (`_NSIG == 65`). Other
/// targets fall back to 31 (Darwin `_NSIG == 32`; POSIX.1 guarantees at
/// least 31). Signal 0 is never valid here: `kill(pid, 0)` probes liveness
/// without delivering, so it is rejected by [`validate_signal`].
#[cfg(target_os = "linux")]
pub(crate) const MAX_SIGNAL: i32 = 64;
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_SIGNAL: i32 = 31;

/// Validate a signal number before delivery.
///
/// Negative, zero, and out-of-range values are rejected with a typed error
/// instead of reaching `libc::kill`.
pub(crate) fn validate_signal(sig: i32) -> Result<(), String> {
    if (1..=MAX_SIGNAL).contains(&sig) {
        Ok(())
    } else {
        Err(format!("invalid signal {sig}: expected 1..={MAX_SIGNAL}"))
    }
}

/// Register a new operation and return its shared handle plus a control
/// receiver.
///
/// The receiver is created from the channel *before* the handle is
/// published into the map, so `receiver_count >= 1` from the moment the
/// operation becomes visible to `cancel`/`signal`. Every send after
/// registration is therefore stored and observed: a cancel arriving between
/// registration and stream start is seen on the first `has_changed()` poll
/// instead of requiring a second send. Callers must keep the returned
/// receiver alive for the life of the operation (dropping the last receiver
/// makes `watch::Sender::send` fail and the value is not stored).
pub(crate) fn register(
    map: &SharedExecMap,
    operation_id: &str,
) -> (
    Arc<Mutex<ExecHandle>>,
    watch::Receiver<Option<CancelSignal>>,
) {
    let (ctrl_tx, ctrl_rx) = watch::channel(None);
    let handle = Arc::new(Mutex::new(ExecHandle {
        operation_id: operation_id.to_string(),
        ctrl_tx,
        start_time: Instant::now(),
    }));
    map.lock()
        .insert(operation_id.to_string(), Arc::clone(&handle));
    (handle, ctrl_rx)
}

/// Remove an operation from the registry (called once on completion).
pub(crate) fn remove(map: &SharedExecMap, operation_id: &str) {
    map.lock().remove(operation_id);
}

/// Send `Cancel` to one operation.
///
/// Idempotent: repeat cancels to an active operation re-deliver and return
/// `true` (`Accepted`). Returns `false` (`Unknown`) only when the operation
/// is absent (never existed or already completed and removed).
pub(crate) fn cancel(map: &SharedExecMap, operation_id: &str) -> bool {
    let guard = map.lock();
    if let Some(state) = guard.get(operation_id) {
        let state_guard = state.lock();
        // Never `take()` the sender: `watch::Sender::send` is repeatable.
        // A send error only means the exec task dropped its receiver while
        // the entry is still present (completion race); the operation was
        // known, so still report accepted and let the terminal outcome win.
        let _ = state_guard.ctrl_tx.send(Some(CancelSignal::Cancel));
        tracing::info!(operation_id = %operation_id, "cancel signal sent");
        true
    } else {
        false
    }
}

/// Send a Unix signal to one operation.
///
/// Defined repeat behavior: a second signal to the same active operation
/// re-delivers and returns [`SignalSend::Acknowledged`], never `Unknown`.
/// Invalid signal numbers return [`SignalSend::InvalidSignal`] without
/// touching the registry.
pub(crate) fn signal(map: &SharedExecMap, operation_id: &str, sig: i32) -> SignalSend {
    if let Err(msg) = validate_signal(sig) {
        return SignalSend::InvalidSignal(msg);
    }
    let guard = map.lock();
    if let Some(state) = guard.get(operation_id) {
        let state_guard = state.lock();
        let _ = state_guard.ctrl_tx.send(Some(CancelSignal::Signal(sig)));
        tracing::info!(operation_id = %operation_id, signal = sig, "signal sent");
        SignalSend::Acknowledged
    } else {
        SignalSend::Unknown
    }
}

/// Send `Cancel` to every active operation for quiesce-force.
///
/// Returns the operation IDs signalled. Never consumes senders, so a second
/// force-cancel pass over still-active operations re-delivers instead of
/// silently skipping them.
pub(crate) fn force_cancel_all(map: &SharedExecMap) -> Vec<String> {
    let op_ids: Vec<String> = map.lock().keys().cloned().collect();
    let mut signalled = Vec::with_capacity(op_ids.len());
    for op_id in op_ids {
        if cancel(map, &op_id) {
            tracing::info!(operation_id = %op_id, "force cancelled for quiesce");
            signalled.push(op_id);
        }
    }
    signalled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_map() -> SharedExecMap {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// Register and keep the receiver alive: dropping the last receiver
    /// makes `watch::Sender::send` fail, so tests hold `_rx` to mirror the
    /// streaming task holding its receiver in production.
    fn register_held(map: &SharedExecMap, op: &str) -> watch::Receiver<Option<CancelSignal>> {
        let (_handle, rx) = register(map, op);
        rx
    }

    #[test]
    fn second_cancel_to_active_operation_is_accepted() {
        let map = test_map();
        let _rx = register_held(&map, "op-1");
        assert!(cancel(&map, "op-1"));
        // Defined behavior: repeat cancel re-delivers, still accepted.
        assert!(cancel(&map, "op-1"));
    }

    #[test]
    fn second_signal_to_active_operation_is_acknowledged() {
        let map = test_map();
        let _rx = register_held(&map, "op-1");
        assert_eq!(signal(&map, "op-1", 15), SignalSend::Acknowledged);
        // Defined behavior: second signal re-delivers, still acknowledged.
        assert_eq!(signal(&map, "op-1", 15), SignalSend::Acknowledged);
        assert_eq!(signal(&map, "op-1", 9), SignalSend::Acknowledged);
    }

    #[test]
    fn unknown_operation_reports_unknown() {
        let map = test_map();
        assert!(!cancel(&map, "nope"));
        assert_eq!(signal(&map, "nope", 15), SignalSend::Unknown);
    }

    #[test]
    fn invalid_signal_rejected_without_registry_access() {
        let map = test_map();
        let _rx = register_held(&map, "op-1");
        assert!(matches!(
            signal(&map, "op-1", -1),
            SignalSend::InvalidSignal(_)
        ));
        assert!(matches!(
            signal(&map, "op-1", 0),
            SignalSend::InvalidSignal(_)
        ));
        assert!(matches!(
            signal(&map, "op-1", 999),
            SignalSend::InvalidSignal(_)
        ));
    }

    #[test]
    fn force_cancel_all_does_not_consume_senders() {
        let map = test_map();
        let _rx1 = register_held(&map, "op-1");
        let _rx2 = register_held(&map, "op-2");
        let first = force_cancel_all(&map);
        assert_eq!(first.len(), 2);
        // Second pass still sees active operations (re-delivers).
        let second = force_cancel_all(&map);
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn cancel_after_remove_is_unknown() {
        let map = test_map();
        let _rx = register_held(&map, "op-1");
        assert!(cancel(&map, "op-1"));
        remove(&map, "op-1");
        assert!(!cancel(&map, "op-1"));
        assert_eq!(signal(&map, "op-1", 15), SignalSend::Unknown);
    }

    #[test]
    fn cancel_sent_before_stream_start_is_observed() {
        // Regression test for the register-to-subscribe window: the receiver
        // returned by `register` must observe a send issued immediately
        // after registration, on the first `has_changed()` poll.
        let map = test_map();
        let (_handle, mut rx) = register(&map, "op-early");
        assert!(cancel(&map, "op-early"));
        assert!(
            rx.has_changed().unwrap_or(false),
            "cancel sent after register must be visible without a second send"
        );
        assert_eq!(rx.borrow_and_update().clone(), Some(CancelSignal::Cancel));
    }
}
