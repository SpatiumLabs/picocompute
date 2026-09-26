//! In-memory audit event sink for testing.

use parking_lot::Mutex;

use crate::identity::{AuditEvent, AuditEventKind, SandboxId};

use super::{AuditEventSink, AuditSinkError};

/// In-memory audit event sink for testing.
///
/// Stores all emitted events in a mutex-protected vector. Events are
/// immediately available for inspection after `emit()` returns.
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// Returns a snapshot of all buffered events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().clone()
    }

    /// Read-only access to buffered events without cloning.
    pub fn with_events<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[AuditEvent]) -> R,
    {
        f(&self.events.lock())
    }

    /// Returns the number of buffered events.
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Returns true if no events have been emitted.
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Clears all buffered events.
    pub fn clear(&self) {
        self.events.lock().clear();
    }

    /// Returns events filtered by kind.
    pub fn events_by_kind(&self, kind: AuditEventKind) -> Vec<AuditEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }

    /// Returns events filtered by sandbox ID.
    pub fn events_for_sandbox(&self, sandbox_id: &SandboxId) -> Vec<AuditEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.sandbox_id.as_ref() == Some(sandbox_id))
            .cloned()
            .collect()
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditEventSink for InMemoryAuditSink {
    fn emit(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        tracing::debug!(
            event.id = %event.id,
            event.kind = ?event.kind,
            "audit event buffered in memory"
        );
        self.events.lock().push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_bus::AuditEventBuilder;
    use crate::identity::Hlc;
    use std::sync::Arc;

    fn test_hlc() -> Arc<Hlc> {
        Arc::new(Hlc::new())
    }

    #[test]
    fn in_memory_sink_stores_events() {
        let sink = InMemoryAuditSink::new();
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::LeaseIssued).build();

        sink.emit(event).unwrap();

        assert_eq!(sink.len(), 1);
        assert!(!sink.is_empty());
        assert_eq!(sink.events()[0].kind, AuditEventKind::LeaseIssued);
    }

    #[test]
    fn in_memory_sink_filters_by_kind() {
        let sink = InMemoryAuditSink::new();
        let hlc = test_hlc();

        sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LeaseIssued).build())
            .unwrap();
        sink.emit(
            AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition).build(),
        )
        .unwrap();
        sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::LeaseIssued).build())
            .unwrap();

        assert_eq!(sink.events_by_kind(AuditEventKind::LeaseIssued).len(), 2);
        assert_eq!(
            sink.events_by_kind(AuditEventKind::LifecycleTransition)
                .len(),
            1
        );
    }
}
