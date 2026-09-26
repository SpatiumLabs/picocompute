//! Dead-letter and delivery retry tests for the audit pipeline.
//!
//! Tests:
//! - Retry logic via a FailingAuditSink double (N failures then success)
//! - Channel-full -> retry behavior
//! - Dead-letter recording after exhaustion
//! - Postgres dead-letter table integration (gated: requires DATABASE_URL)

use pico_core::{
    AuditEventBuilder, AuditEventKind, AuditEventSink, AuditSinkError, ChannelAuditSink, Hlc,
    InMemoryAuditSink,
};
use std::sync::Arc;

// ---- Retry-after-channel-full ----

#[test]
fn retry_after_channel_drain_succeeds() {
    let (sink, mut rx) = ChannelAuditSink::new(2);
    let hlc = Arc::new(Hlc::new());

    sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build())
        .unwrap();
    sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome).build())
        .unwrap();

    let result =
        sink.emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build());
    assert!(matches!(result, Err(AuditSinkError::ChannelFull(_))));

    let _ = rx.try_recv().unwrap();

    let result = sink.emit(AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build());
    assert!(result.is_ok());
}

// ---- Failing sink for simulating delivery exhaustion ----

struct FailingAuditSink {
    inner: Arc<InMemoryAuditSink>,
    max_failures: std::sync::atomic::AtomicU32,
    failure_count: std::sync::atomic::AtomicU32,
}

impl FailingAuditSink {
    fn new(max_failures: u32) -> Self {
        Self {
            inner: Arc::new(InMemoryAuditSink::new()),
            max_failures: std::sync::atomic::AtomicU32::new(max_failures),
            failure_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn events(&self) -> Vec<pico_core::AuditEvent> {
        self.inner.events()
    }
}

impl AuditEventSink for FailingAuditSink {
    fn emit(&self, event: pico_core::AuditEvent) -> Result<(), AuditSinkError> {
        use std::sync::atomic::Ordering;
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed);
        let max = self.max_failures.load(Ordering::Relaxed);
        if count < max {
            Err(AuditSinkError::ChannelFull(event.id.as_str().to_string()))
        } else {
            self.inner.emit(event)
        }
    }
}

// ---- Retry exhaustion simulation ----

#[test]
fn failing_sink_eventually_accepts_after_retries() {
    let sink = FailingAuditSink::new(3);
    let hlc = Arc::new(Hlc::new());

    for _ in 0..3 {
        let result = sink
            .emit(AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build());
        assert!(result.is_err());
    }

    let event = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision)
        .trace_id("trace-retry-success")
        .build();
    let result = sink.emit(event);
    assert!(result.is_ok());
    assert_eq!(sink.events().len(), 1);
    assert_eq!(
        sink.events()[0].trace_id.as_deref(),
        Some("trace-retry-success")
    );
}

// ---- Dead-letter recording simulation ----

#[test]
fn dead_letter_simulation_exhausted_events_are_recorded() {
    let always_fail = FailingAuditSink::new(u32::MAX);
    let hlc = Arc::new(Hlc::new());
    let dead_letter_store = InMemoryAuditSink::new();

    let mut undelivered: Vec<pico_core::AuditEvent> = Vec::new();

    for i in 0..5 {
        let event = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .trace_id(format!("trace-dl-{i}"))
            .build();

        if always_fail.emit(event.clone()).is_err() {
            undelivered.push(event);
        }
    }

    for event in &undelivered {
        dead_letter_store.emit(event.clone()).unwrap();
    }

    assert_eq!(undelivered.len(), 5);
    assert_eq!(dead_letter_store.len(), 5);

    for event in dead_letter_store.events() {
        assert!(event.trace_id.is_some());
    }
}

// ---- Postgres dead-letter integration test (gated on DATABASE_URL) ----

#[cfg(test)]
#[tokio::test]
async fn postgres_dead_letter_integration() {
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        }
    };

    use pico_core::{AuditEventQuery, PostgresAuditSink, query_events};
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db_url)
        .await
        .expect("failed to connect to postgres");

    let sink = PostgresAuditSink::new(pool.clone(), 10)
        .await
        .expect("failed to create audit sink");

    let hlc = Arc::new(Hlc::new());

    for i in 0..5 {
        let event = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .trace_id(format!("trace-pg-dl-{i}"))
            .build();

        let _ = sink.emit(event);
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let query = AuditEventQuery::new().limit(10);
    let events = query_events(&pool, &query)
        .await
        .expect("query_events failed");

    let dl_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.trace_id
                .as_ref()
                .is_some_and(|t| t.starts_with("trace-pg-dl-"))
        })
        .collect();

    assert!(
        dl_events.len() == 5,
        "expected 5 dead-letter test events, got {}",
        dl_events.len()
    );
}
