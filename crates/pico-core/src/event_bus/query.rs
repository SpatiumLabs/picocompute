//! Audit event query API for consumer access.
//!
//! Provides [`AuditEventQuery`] for filtering audit events by tenant,
//! sandbox, operation, policy-decision, lease IDs, time range, and
//! event kind with cursor-based pagination.

use crate::identity::{AuditEvent, AuditEventKind};

use sqlx::Row;

/// Filter parameters for querying audit events.
///
/// All filters are `Option` - only non-`None` values constrain the query.
/// Time range uses HLC wall-time for causal ordering; `recorded_at` for
/// display-time filtering.
#[derive(Debug, Clone, Default)]
pub struct AuditEventQuery {
    pub tenant_id: Option<String>,
    pub sandbox_id: Option<String>,
    pub operation_id: Option<String>,
    pub policy_decision_id: Option<String>,
    pub lease_id: Option<String>,
    pub event_kind: Option<AuditEventKind>,
    pub hlc_wall_time_from_ms: Option<i64>,
    pub hlc_wall_time_to_ms: Option<i64>,
    pub recorded_at_from: Option<String>,
    pub recorded_at_to: Option<String>,
    pub limit: usize,
    pub cursor: Option<i64>,
}

impl AuditEventQuery {
    /// Create a new query with a default limit of 100.
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }

    /// Set the tenant filter.
    pub fn tenant_id(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = Some(id.into());
        self
    }

    /// Set the sandbox filter.
    pub fn sandbox_id(mut self, id: impl Into<String>) -> Self {
        self.sandbox_id = Some(id.into());
        self
    }

    /// Set the operation filter.
    pub fn operation_id(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    /// Set the policy decision filter.
    pub fn policy_decision_id(mut self, id: impl Into<String>) -> Self {
        self.policy_decision_id = Some(id.into());
        self
    }

    /// Set the lease filter.
    pub fn lease_id(mut self, id: impl Into<String>) -> Self {
        self.lease_id = Some(id.into());
        self
    }

    /// Set the event kind filter.
    pub fn event_kind(mut self, kind: AuditEventKind) -> Self {
        self.event_kind = Some(kind);
        self
    }

    /// Set the time range via HLC wall-time (ms).
    pub fn hlc_range(mut self, from_ms: i64, to_ms: i64) -> Self {
        self.hlc_wall_time_from_ms = Some(from_ms);
        self.hlc_wall_time_to_ms = Some(to_ms);
        self
    }

    /// Set the time range via recorded_at ISO 8601 strings.
    pub fn recorded_at_range(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.recorded_at_from = Some(from.into());
        self.recorded_at_to = Some(to.into());
        self
    }

    /// Set the page size (default 100, max 1000).
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit.min(1000);
        self
    }

    /// Set the cursor for pagination (uses `id` BIGSERIAL for keyset).
    pub fn cursor(mut self, cursor: i64) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

/// Query audit events from the PostgreSQL audit store.
///
/// Applies filters from the query struct and returns deserialized
/// `AuditEvent` records with cursor pagination. The cursor is the
/// `id` BIGSERIAL primary key for unambiguous keyset pagination.
pub async fn query_events(
    pool: &sqlx::PgPool,
    query: &AuditEventQuery,
) -> Result<Vec<AuditEvent>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT payload FROM pico.audit_events WHERE 1=1",
    );

    if let Some(ref tid) = query.tenant_id {
        qb.push(" AND tenant_id = ");
        qb.push_bind(tid);
    }
    if let Some(ref sid) = query.sandbox_id {
        qb.push(" AND sandbox_id = ");
        qb.push_bind(sid);
    }
    if let Some(ref oid) = query.operation_id {
        qb.push(" AND operation_id = ");
        qb.push_bind(oid);
    }
    if let Some(ref pdc) = query.policy_decision_id {
        qb.push(" AND policy_decision_id = ");
        qb.push_bind(pdc);
    }
    if let Some(ref lid) = query.lease_id {
        qb.push(" AND lease_id = ");
        qb.push_bind(lid);
    }
    if let Some(kind) = query.event_kind {
        let kind_str = serde_json::to_string(&kind).unwrap_or_else(|_| format!("{:?}", kind));
        qb.push(" AND event_kind = ");
        qb.push_bind(kind_str);
    }
    if let Some(from) = query.hlc_wall_time_from_ms {
        qb.push(" AND hlc_wall_time_ms >= ");
        qb.push_bind(from);
    }
    if let Some(to) = query.hlc_wall_time_to_ms {
        qb.push(" AND hlc_wall_time_ms <= ");
        qb.push_bind(to);
    }
    if let Some(ref from) = query.recorded_at_from {
        qb.push(" AND recorded_at >= ");
        qb.push_bind(from);
    }
    if let Some(ref to) = query.recorded_at_to {
        qb.push(" AND recorded_at <= ");
        qb.push_bind(to);
    }
    if let Some(cursor) = query.cursor {
        qb.push(" AND id > ");
        qb.push_bind(cursor);
    }

    qb.push(" ORDER BY id ASC LIMIT ");
    qb.push_bind(query.limit as i64);

    let rows = qb.build().fetch_all(pool).await?;

    let events: Vec<AuditEvent> = rows
        .into_iter()
        .filter_map(|row| {
            let payload: serde_json::Value = row.get("payload");
            serde_json::from_value(payload).ok()
        })
        .collect();

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_builder_defaults() {
        let q = AuditEventQuery::new();
        assert_eq!(q.limit, 100);
        assert!(q.cursor.is_none());
        assert!(q.tenant_id.is_none());
        assert!(q.sandbox_id.is_none());
    }

    #[test]
    fn query_builder_clamps_limit() {
        let q = AuditEventQuery::new().limit(5000);
        assert_eq!(q.limit, 1000);
    }

    #[test]
    fn query_builder_sets_all_filters() {
        let q = AuditEventQuery::new()
            .tenant_id("tnt_001")
            .sandbox_id("sbx_001")
            .operation_id("op_001")
            .policy_decision_id("pdc_001")
            .lease_id("lse_001")
            .hlc_range(1000, 2000)
            .cursor(42)
            .limit(50);

        assert_eq!(q.tenant_id.as_deref(), Some("tnt_001"));
        assert_eq!(q.sandbox_id.as_deref(), Some("sbx_001"));
        assert_eq!(q.operation_id.as_deref(), Some("op_001"));
        assert_eq!(q.policy_decision_id.as_deref(), Some("pdc_001"));
        assert_eq!(q.lease_id.as_deref(), Some("lse_001"));
        assert_eq!(q.hlc_wall_time_from_ms, Some(1000));
        assert_eq!(q.hlc_wall_time_to_ms, Some(2000));
        assert_eq!(q.cursor, Some(42));
        assert_eq!(q.limit, 50);
    }
}
