//! Async channel-based audit event sink with background delivery.

use tokio::sync::mpsc;
use tracing::warn;

use crate::identity::AuditEvent;

use super::{AuditEventSink, AuditSinkError};

/// Async channel-based audit event sink with background delivery.
///
/// Events are sent to a bounded `tokio::sync::mpsc` channel. A
/// background consumer task drains the channel and delivers events
/// to the final destination (e.g., a regional event log).
///
/// If the channel is full, `emit()` returns
/// [`AuditSinkError::ChannelFull`], enabling the caller to implement
/// retry or hold-for-review behavior.
pub struct ChannelAuditSink {
    sender: mpsc::Sender<AuditEvent>,
}

impl ChannelAuditSink {
    /// Create a new channel sink with the given buffer capacity.
    ///
    /// Returns the sink and a receiver for the background consumer.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<AuditEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Create a sink from an existing sender.
    pub fn from_sender(sender: mpsc::Sender<AuditEvent>) -> Self {
        Self { sender }
    }
}

impl AuditEventSink for ChannelAuditSink {
    fn emit(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        let event_id = event.id.as_str().to_string();
        self.sender.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                warn!(
                    event.id = %event_id,
                    "audit channel full, event dropped"
                );
                AuditSinkError::ChannelFull(event_id)
            }
            mpsc::error::TrySendError::Closed(_) => {
                warn!(
                    event.id = %event_id,
                    "audit channel closed, event dropped"
                );
                AuditSinkError::ChannelClosed
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_bus::AuditEventBuilder;
    use crate::identity::{AuditEventKind, Hlc};
    use std::sync::Arc;

    fn test_hlc() -> Arc<Hlc> {
        Arc::new(Hlc::new())
    }

    #[test]
    fn channel_sink_buffers_events() {
        let (sink, mut rx) = ChannelAuditSink::new(10);
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::PolicyDecision).build();

        sink.emit(event).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.kind, AuditEventKind::PolicyDecision);
    }

    #[test]
    fn channel_sink_returns_error_when_full() {
        let (sink, _rx) = ChannelAuditSink::new(1);
        let hlc = test_hlc();

        sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build())
            .unwrap();

        let result = sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build());
        assert!(matches!(result, Err(AuditSinkError::ChannelFull(_))));
    }
}
