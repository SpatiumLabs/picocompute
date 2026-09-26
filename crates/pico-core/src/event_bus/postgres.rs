//! PostgreSQL-backed audit event sink for durable persistence.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::identity::AuditEvent;

use super::metrics::{
    record_audit_delivery, record_audit_delivery_lag, record_audit_outbox_pending,
};
use super::redaction::redact_event;
use super::{AuditEventSink, AuditSinkError};

/// PostgreSQL-backed audit event sink for durable persistence.
///
/// Events are buffered through an internal channel and flushed to
/// PostgreSQL by a background task in configurable batch sizes. The
/// event JSON payload is stored in a `JSONB` column; correlation
/// fields are indexed for querying.
///
/// The table is created automatically on construction if it does not
/// exist. Failed inserts are retried with exponential backoff (up to
/// `max_retries`) and written to a dead-letter table on exhaustion.
pub struct PostgresAuditSink {
    sender: mpsc::Sender<AuditEvent>,
}

/// Configuration for PostgresAuditSink.
pub struct PostgresAuditSinkConfig {
    /// Channel buffer capacity for incoming events.
    pub buffer_capacity: usize,
    /// Maximum number of events to insert in a single batch.
    pub batch_size: usize,
    /// Flush interval for partial batches.
    pub flush_interval: Duration,
    /// Maximum retry attempts for failed inserts.
    pub max_retries: u32,
    /// Base backoff duration for retries.
    pub retry_base_delay: Duration,
}

impl Default for PostgresAuditSinkConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 1024,
            batch_size: 100,
            flush_interval: Duration::from_secs(1),
            max_retries: 3,
            retry_base_delay: Duration::from_millis(100),
        }
    }
}

impl PostgresAuditSink {
    /// DDL that creates the audit events table, dead-letter table, and indexes.
    ///
    /// v2 added columns: operation_id, policy_decision_id, lease_id,
    /// producer, request_id, action, outcome, reason with corresponding
    /// indexes. ALTER TABLE uses IF NOT EXISTS for idempotent migration.
    pub const DDL: &str = r#"
        CREATE SCHEMA IF NOT EXISTS pico;

        CREATE TABLE IF NOT EXISTS pico.audit_events (
            id BIGSERIAL PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            schema_version INTEGER NOT NULL,
            hlc_wall_time_ms BIGINT NOT NULL,
            hlc_logical_counter INTEGER NOT NULL,
            event_kind TEXT NOT NULL,
            sandbox_id TEXT,
            tenant_id TEXT,
            trace_id TEXT,
            operation_id TEXT,
            policy_decision_id TEXT,
            lease_id TEXT,
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            payload JSONB NOT NULL
        );

        -- v2 column additions (idempotent: skips if column already exists)
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'operation_id'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN operation_id TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'policy_decision_id'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN policy_decision_id TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'lease_id'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN lease_id TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'producer'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN producer TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'request_id'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN request_id TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'action'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN action TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'outcome'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN outcome TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'pico' AND table_name = 'audit_events'
                AND column_name = 'reason'
            ) THEN
                ALTER TABLE pico.audit_events ADD COLUMN reason TEXT;
            END IF;
        END$$;

        CREATE TABLE IF NOT EXISTS pico.audit_events_dead_letter (
            id BIGSERIAL PRIMARY KEY,
            event_id TEXT NOT NULL,
            error TEXT NOT NULL,
            retries INTEGER NOT NULL DEFAULT 0,
            payload JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_audit_events_sandbox
            ON pico.audit_events(sandbox_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant
            ON pico.audit_events(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_trace
            ON pico.audit_events(trace_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_kind
            ON pico.audit_events(event_kind);
        CREATE INDEX IF NOT EXISTS idx_audit_events_hlc
            ON pico.audit_events(hlc_wall_time_ms, hlc_logical_counter);
        CREATE INDEX IF NOT EXISTS idx_audit_events_operation
            ON pico.audit_events(operation_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_policy_decision
            ON pico.audit_events(policy_decision_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_lease
            ON pico.audit_events(lease_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_recorded_at
            ON pico.audit_events(recorded_at);

        GRANT USAGE ON SCHEMA pico TO PUBLIC;
        GRANT SELECT, INSERT ON pico.audit_events TO PUBLIC;
        GRANT SELECT, INSERT ON pico.audit_events_dead_letter TO PUBLIC;
    "#;

    /// Create a new Postgres audit sink with default configuration.
    pub async fn new(pool: sqlx::PgPool, capacity: usize) -> Result<Self, sqlx::Error> {
        Self::with_config(
            pool,
            PostgresAuditSinkConfig {
                buffer_capacity: capacity,
                ..Default::default()
            },
        )
        .await
    }

    /// Create a new Postgres audit sink with custom configuration.
    pub async fn with_config(
        pool: sqlx::PgPool,
        config: PostgresAuditSinkConfig,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query(Self::DDL).execute(&pool).await?;

        let (sender, mut receiver) = mpsc::channel::<AuditEvent>(config.buffer_capacity);

        tokio::spawn(async move {
            let mut batch: Vec<AuditEvent> = Vec::with_capacity(config.batch_size);
            let mut flush_tick = tokio::time::interval(config.flush_interval);

            loop {
                tokio::select! {
                    event = receiver.recv() => {
                        match event {
                            Some(event) => {
                                batch.push(event);
                                if batch.len() >= config.batch_size {
                                    Self::insert_batch_with_retry(
                                        &pool,
                                        std::mem::take(&mut batch),
                                        config.max_retries,
                                        config.retry_base_delay,
                                    )
                                    .await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    Self::insert_batch_with_retry(
                                        &pool,
                                        std::mem::take(&mut batch),
                                        config.max_retries,
                                        config.retry_base_delay,
                                    )
                                    .await;
                                }
                                info!("postgres audit sink background task shutting down");
                                return;
                            }
                        }
                    }
                    _ = flush_tick.tick() => {
                        if !batch.is_empty() {
                            Self::insert_batch_with_retry(
                                &pool,
                                std::mem::take(&mut batch),
                                config.max_retries,
                                config.retry_base_delay,
                            )
                            .await;
                        }
                    }
                }
            }
        });

        Ok(Self { sender })
    }

    async fn insert_batch_with_retry(
        pool: &sqlx::PgPool,
        mut events: Vec<AuditEvent>,
        max_retries: u32,
        base_delay: Duration,
    ) {
        if events.is_empty() {
            return;
        }

        record_audit_outbox_pending(events.len() as u64);

        // Defense-in-depth: redact any prohibited content before persistence.
        for event in &mut events {
            redact_event(event);
        }

        let mut attempt = 0;
        loop {
            match Self::insert_batch(pool, &events).await {
                Ok(()) => {
                    debug!(
                        count = events.len(),
                        "audit events batch persisted to postgres"
                    );
                    record_audit_delivery(events.len(), "delivered", None);
                    if let Some(first) = events.first() {
                        record_audit_delivery_lag(lag_seconds(first.hlc_ts.wall_time_ms));
                    }
                    return;
                }
                Err(e) if attempt < max_retries => {
                    attempt += 1;
                    let delay = base_delay * 2u32.pow(attempt);
                    warn!(
                        count = events.len(),
                        attempt = attempt,
                        max_retries = max_retries,
                        error = %e,
                        "batch insert failed, retrying"
                    );
                    record_audit_delivery(events.len(), "retry", Some("insert_failed"));
                    sleep(delay).await;
                }
                Err(e) => {
                    warn!(
                        count = events.len(),
                        attempts = attempt,
                        error = %e,
                        "batch insert exhausted retries, writing to dead-letter"
                    );
                    record_audit_delivery(events.len(), "dead_letter", Some("retries_exhausted"));
                    for event in &events {
                        Self::write_dead_letter(pool, event, &e.to_string()).await;
                    }
                    return;
                }
            }
        }
    }

    async fn insert_batch(pool: &sqlx::PgPool, events: &[AuditEvent]) -> Result<(), sqlx::Error> {
        if events.is_empty() {
            return Ok(());
        }

        let mut qb = sqlx::QueryBuilder::new(
            "INSERT INTO pico.audit_events (event_id, schema_version, \
             hlc_wall_time_ms, hlc_logical_counter, event_kind, sandbox_id, \
             tenant_id, trace_id, operation_id, policy_decision_id, lease_id, \
             producer, request_id, action, outcome, reason, recorded_at, payload) ",
        );
        qb.push_values(events.iter(), |mut b, event| {
            let kind_str =
                serde_json::to_string(&event.kind).unwrap_or_else(|_| format!("{:?}", event.kind));
            let payload = serde_json::to_value(event).unwrap_or_else(|_| serde_json::Value::Null);

            b.push_bind(event.id.as_str());
            b.push_bind(event.schema_version as i32);
            b.push_bind(event.hlc_ts.wall_time_ms);
            b.push_bind(event.hlc_ts.logical_counter as i32);
            b.push_bind(kind_str);
            b.push_bind(event.sandbox_id.as_ref().map(|s| s.as_str()));
            b.push_bind(event.tenant_id.as_ref().map(|t| t.as_str()));
            b.push_bind(event.trace_id.as_deref());
            b.push_bind(event.operation_id.as_ref().map(|o| o.as_str()));
            b.push_bind(event.policy_decision_id.as_deref());
            b.push_bind(event.lease_id.as_deref());
            b.push_bind(event.producer.as_deref());
            b.push_bind(event.request_id.as_deref());
            b.push_bind(event.action.as_deref());
            b.push_bind(event.outcome.as_deref());
            b.push_bind(event.reason.as_deref());
            b.push_bind(&event.recorded_at);
            b.push_bind(payload);
        });
        qb.push(" ON CONFLICT (event_id) DO NOTHING");

        qb.build().execute(pool).await?;
        Ok(())
    }

    async fn write_dead_letter(pool: &sqlx::PgPool, event: &AuditEvent, error: &str) {
        let payload = match serde_json::to_value(event) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    event.id = %event.id,
                    error = %e,
                    "failed to serialize event for dead-letter"
                );
                return;
            }
        };

        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO pico.audit_events_dead_letter (
                event_id, error, retries, payload
            ) VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(event.id.as_str())
        .bind(error)
        .bind(3)
        .bind(&payload)
        .execute(pool)
        .await
        {
            warn!(
                event.id = %event.id,
                error = %e,
                "failed to write event to dead-letter"
            );
        }
    }
}

fn lag_seconds(wall_time_ms: i64) -> f64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let lag_ms = now_ms.saturating_sub(wall_time_ms);
    lag_ms as f64 / 1000.0
}

impl AuditEventSink for PostgresAuditSink {
    fn emit(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        let event_id = event.id.as_str().to_string();
        self.sender.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                warn!(
                    event.id = %event_id,
                    "postgres audit channel full, event dropped"
                );
                AuditSinkError::ChannelFull(event_id)
            }
            mpsc::error::TrySendError::Closed(_) => {
                warn!(
                    event.id = %event_id,
                    "postgres audit channel closed, event dropped"
                );
                AuditSinkError::ChannelClosed
            }
        })
    }
}

/// Configuration for audit event retention.
#[derive(Debug, Clone)]
pub struct AuditRetentionConfig {
    /// Number of days of hot retention in the main table.
    pub hot_retention_days: u32,
    /// Number of days of cold retention before archival.
    pub cold_retention_days: u32,
    /// Number of days to keep dead-letter records.
    pub dead_letter_retention_days: u32,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            hot_retention_days: 30,
            cold_retention_days: 365,
            dead_letter_retention_days: 90,
        }
    }
}

impl AuditRetentionConfig {
    /// Create a new config with the given hot retention days (cold = 365).
    pub fn with_hot_retention(hot_retention_days: u32) -> Self {
        Self {
            hot_retention_days,
            ..Default::default()
        }
    }

    /// Generate SQL for expiring audit events older than the cold retention.
    ///
    /// Returns SQL that can be run as a background cleanup job. The
    /// caller should batch deletes (e.g., `LIMIT 10000`) to avoid
    /// long-running transactions.
    pub fn expire_audit_sql(&self, batch_size: usize) -> String {
        format!(
            "DELETE FROM pico.audit_events \
             WHERE recorded_at < NOW() - INTERVAL '{} days' \
             LIMIT {}",
            self.cold_retention_days, batch_size
        )
    }

    /// Generate SQL for expiring dead-letter events.
    pub fn expire_dead_letter_sql(&self, batch_size: usize) -> String {
        format!(
            "DELETE FROM pico.audit_events_dead_letter \
             WHERE created_at < NOW() - INTERVAL '{} days' \
             LIMIT {}",
            self.dead_letter_retention_days, batch_size
        )
    }
}
