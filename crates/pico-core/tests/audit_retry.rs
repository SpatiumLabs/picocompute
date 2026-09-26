//! Delivery retry and hold-for-review tests for the audit event system.

use pico_core::{
    AuditEvent, AuditEventBuilder, AuditEventKind, AuditEventSink, AuditSinkError,
    ChannelAuditSink, Hlc, InMemoryAuditSink, NoopAuditSink,
};
use std::sync::Arc;

// ---- Retry behavior ----

#[test]
fn channel_full_returns_error_for_retry() {
    let (sink, _rx) = ChannelAuditSink::new(1);
    let hlc = Arc::new(Hlc::new());

    // Fill the channel
    sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build())
        .unwrap();

    // Next send should fail with ChannelFull
    let result = sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build());
    assert!(matches!(result, Err(AuditSinkError::ChannelFull(_))));
}

#[test]
fn retry_after_drain_succeeds() {
    let (sink, mut rx) = ChannelAuditSink::new(1);
    let hlc = Arc::new(Hlc::new());

    sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build())
        .unwrap();

    let result =
        sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build());
    assert!(result.is_err());

    // Drain the channel
    let _ = rx.try_recv().unwrap();

    // Retry should now succeed
    let result = sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build());
    assert!(result.is_ok());
}

#[test]
fn hold_for_review_pattern_works() {
    // Simulate hold-for-review: buffer events and review batch before delivery
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let mut held_events: Vec<AuditEvent> = Vec::new();

    // Buffer 3 events
    for i in 0..3 {
        let event = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .trace_id(format!("trace-{i}"))
            .build();
        held_events.push(event);
    }

    // Review: check all events have trace_id set
    for event in &held_events {
        assert!(event.trace_id.is_some(), "all events must have trace_id");
    }

    // Deliver after review
    for event in held_events {
        sink.emit(event).unwrap();
    }

    assert_eq!(sink.len(), 3);
}

// ---- Channel closed behavior ----

#[test]
fn channel_closed_after_drop_receiver() {
    let (sink, rx) = ChannelAuditSink::new(10);
    let hlc = Arc::new(Hlc::new());

    drop(rx);

    let result = sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build());
    assert!(matches!(result, Err(AuditSinkError::ChannelClosed)));
}

// ---- Noop sink never fails ----

#[test]
fn noop_sink_always_succeeds() {
    let sink = NoopAuditSink;
    let hlc = Arc::new(Hlc::new());

    for _ in 0..100 {
        assert!(
            sink.emit(
                AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build()
            )
            .is_ok()
        );
    }
}

// ---- InMemory sink never blocks ----

#[test]
fn in_memory_sink_handles_high_volume() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());

    for i in 0..1000 {
        sink.emit(
            AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
                .sandbox_id(pico_core::SandboxId::from_string(format!("sbx_{i:04}")))
                .build(),
        )
        .unwrap();
    }

    assert_eq!(sink.len(), 1000);
}
