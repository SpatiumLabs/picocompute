//! Audit event bus for emitting and delivering lifecycle audit events.
//!
//! Provides the [`AuditEventSink`] trait for emitting events, an
//! [`AuditEventBuilder`] for ergonomic construction, and several
//! implementations for different delivery guarantees:
//!
//! - [`InMemoryAuditSink`]: Buffered in-process sink for testing.
//! - [`ChannelAuditSink`]: Async channel-based sink with background
//!   delivery and retry support.
//! - [`PostgresAuditSink`]: Durable PostgreSQL-backed sink with
//!   JSONB payloads and indexed correlation fields.

mod channel;
mod memory;
pub mod metrics;
mod postgres;
mod query;
mod redaction;

pub use channel::ChannelAuditSink;
pub use memory::InMemoryAuditSink;
pub use postgres::{AuditRetentionConfig, PostgresAuditSink, PostgresAuditSinkConfig};
pub use query::{AuditEventQuery, query_events};
pub use redaction::redact_event;

use std::sync::Arc;

use crate::identity::{
    AUDIT_SCHEMA_VERSION, AuditAction, AuditEvent, AuditEventDetails, AuditEventId, AuditEventKind,
    AuditOutcome, AuditProducer, FencingToken, Hlc, OperationId, PrincipalId, SandboxId, ServiceId,
    TenantId,
};
use crate::metadata::FailureInfo;
use crate::types::now_iso;

/// Errors that can occur when emitting audit events.
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    /// The delivery channel is full; the event could not be buffered.
    #[error("audit sink channel full: event {0} dropped")]
    ChannelFull(String),
    /// The delivery channel has been closed; no further events can be sent.
    #[error("audit sink channel closed")]
    ChannelClosed,
    /// Event construction failed.
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

/// Synchronous, non-blocking audit event emission interface.
///
/// Implementations buffer events for asynchronous delivery. The `emit`
/// method never blocks the caller on I/O. If the internal buffer is
/// full, the implementation returns [`AuditSinkError::ChannelFull`],
/// allowing the caller to implement retry or hold-for-review behavior.
pub trait AuditEventSink: Send + Sync {
    /// Emit an audit event for asynchronous delivery.
    ///
    /// Returns `Ok(())` if the event was successfully buffered.
    /// Returns `Err` if the event could not be buffered (channel full
    /// or closed).
    fn emit(&self, event: AuditEvent) -> Result<(), AuditSinkError>;
}

/// Parameters for emitting a placement outcome event.
pub struct PlacementOutcomeParams {
    pub sandbox_id: String,
    pub tenant_id: Option<TenantId>,
    pub cell_id: Option<String>,
    pub host_id: Option<String>,
    pub reason: String,
    pub score: Option<f64>,
    pub candidates_evaluated: usize,
    /// Request trace for create-path correlation. `None` for standalone
    /// scheduler calls that are not on the API create path.
    pub trace_id: Option<String>,
    /// Operation identity for retry convergence and audit correlation.
    pub operation_id: Option<OperationId>,
    /// Client idempotency key when the placement is on the create path.
    pub idempotency_key: Option<String>,
}

/// Emit a placement outcome event.
///
/// Shared by [`RegionalScheduler`] and [`CellScheduler`] to avoid
/// duplicating the event construction logic.
pub fn emit_placement_outcome(
    sink: &(dyn AuditEventSink + Send + Sync),
    hlc: &Arc<Hlc>,
    params: PlacementOutcomeParams,
) {
    let mut builder = AuditEventBuilder::new(Arc::clone(hlc), AuditEventKind::PlacementOutcome)
        .sandbox_id(SandboxId::from_string(&params.sandbox_id))
        .action(AuditAction::Place)
        .producer(AuditProducer::Scheduler);
    if let Some(tid) = params.tenant_id {
        builder = builder.tenant_id(tid);
    }
    if let Some(trace_id) = params.trace_id {
        builder = builder.trace_id(trace_id);
    }
    if let Some(op_id) = params.operation_id {
        builder = builder.operation_id(op_id);
    }
    if let Some(key) = params.idempotency_key {
        builder = builder.idempotency_key(key);
    }
    let _ = sink.emit(
        builder
            .reason(params.reason.clone())
            .details(AuditEventDetails::PlacementOutcome {
                cell_id: params.cell_id,
                host_id: params.host_id,
                reason: params.reason,
                score: params.score,
                candidates_evaluated: params.candidates_evaluated,
            })
            .build(),
    );
}

/// Emit a lease enforced event when a data-plane component validates
/// and accepts a lease.
pub fn emit_lease_enforced(
    sink: &(dyn AuditEventSink + Send + Sync),
    hlc: &Arc<Hlc>,
    lease_id: impl Into<String>,
    enforcing_component: impl Into<String>,
    sandbox_id: impl Into<String>,
    tenant_id: impl Into<String>,
    policy_decision_id: Option<String>,
) {
    let lid: String = lease_id.into();
    let comp: String = enforcing_component.into();
    let sbx: String = sandbox_id.into();
    let tnt: String = tenant_id.into();
    let mut builder = AuditEventBuilder::new(Arc::clone(hlc), AuditEventKind::LeaseEnforced)
        .sandbox_id(SandboxId::from_string(&sbx))
        .tenant_id(TenantId::from_string(&tnt))
        .lease_id(lid.clone())
        .producer(comp.clone())
        .action(AuditAction::EnforceLease)
        .outcome(AuditOutcome::Enforced)
        .details(AuditEventDetails::LeaseEnforcement {
            lease_id: lid,
            enforcing_component: comp,
            sandbox_id: sbx,
            tenant_id: tnt,
            policy_decision_id: policy_decision_id.clone(),
        });
    if let Some(ref pdc_id) = policy_decision_id {
        builder = builder.policy_decision_id(pdc_id.clone());
    }
    let _ = sink.emit(builder.build());
}

/// Parameters for emitting a credential issuance or denial event.
pub struct CredentialIssuanceParams {
    /// The action that occurred (e.g., "issue", "refresh", "deny", "revoke").
    pub action: String,
    /// The canonical outcome (e.g., "issued", "denied", "success").
    pub outcome: String,
    /// Diagnostic reason, if any. Sensitive values will be redacted.
    pub reason: Option<String>,
    /// The credential type (e.g., "aws", "gcp").
    pub credential_type: String,
    /// Lease ID that authorized the operation, if any.
    pub lease_id: Option<String>,
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Owning tenant.
    pub tenant_id: TenantId,
}

/// Emit a snapshot metadata access event (read or list).
///
/// Used by [`AuditLoggedSnapshotRepository`] to record every snapshot
/// metadata read and list operation for audit purposes.
#[expect(
    clippy::too_many_arguments,
    reason = "emit functions carry all structured fields for the event; each maps to an AuditEvent field"
)]
pub fn emit_snapshot_metadata_access(
    sink: &(dyn AuditEventSink + Send + Sync),
    hlc: &Arc<Hlc>,
    operation: &str,
    outcome: &str,
    snapshot_id: Option<&str>,
    tenant_id: Option<&str>,
    filter: Option<&str>,
    result_count: Option<usize>,
    service: &str,
    principal: Option<&PrincipalId>,
    reason: Option<&str>,
) {
    let mut builder =
        AuditEventBuilder::new(Arc::clone(hlc), AuditEventKind::SnapshotMetadataAccess)
            .action(operation)
            .outcome(outcome)
            .producer(service)
            .details(AuditEventDetails::SnapshotMetadataAccess {
                operation: operation.to_string(),
                outcome: outcome.to_string(),
                snapshot_id: snapshot_id.map(String::from),
                tenant_id: tenant_id.map(String::from),
                filter: filter.map(String::from),
                result_count,
            });
    if let Some(tid) = tenant_id {
        builder = builder.tenant_id(TenantId::from_string(tid));
    }
    if let Some(p) = principal {
        builder = builder.principal(p.clone());
    }
    if let Some(r) = reason {
        builder = builder.reason(r);
    }
    let _ = sink.emit(builder.build());
}

/// Emit a credential issuance or denial event.
///
/// Used by the host-agent after credential refresh on restore/resume
/// and by the policy engine when credential access is denied.
pub fn emit_credential_issuance(
    sink: &(dyn AuditEventSink + Send + Sync),
    hlc: &Arc<Hlc>,
    params: CredentialIssuanceParams,
) {
    let mut builder = AuditEventBuilder::new(Arc::clone(hlc), AuditEventKind::CredentialIssuance)
        .sandbox_id(params.sandbox_id.clone())
        .tenant_id(params.tenant_id.clone())
        .action(&params.action)
        .outcome(&params.outcome)
        .details(AuditEventDetails::CredentialIssuance {
            action: params.action,
            outcome: params.outcome,
            reason: params.reason,
            credential_type: params.credential_type,
            lease_id: params.lease_id.clone(),
        });
    if let Some(ref lid) = params.lease_id {
        builder = builder.lease_id(lid.clone());
    }
    let _ = sink.emit(builder.build());
}

/// Ergonomic builder for constructing [`AuditEvent`] instances.
///
/// Uses the builder pattern to set optional fields. The HLC timestamp
/// and event ID are generated automatically when `build()` is called.
pub struct AuditEventBuilder {
    hlc: Arc<Hlc>,
    kind: AuditEventKind,
    sandbox_id: Option<SandboxId>,
    tenant_id: Option<TenantId>,
    from_state: Option<String>,
    to_state: Option<String>,
    principal: Option<PrincipalId>,
    service: Option<ServiceId>,
    operation_id: Option<OperationId>,
    trace_id: Option<String>,
    idempotency_key: Option<String>,
    failure: Option<FailureInfo>,
    details: Option<AuditEventDetails>,
    epoch: Option<u64>,
    fencing_token: Option<FencingToken>,
    producer: Option<String>,
    request_id: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    reason: Option<String>,
    policy_decision_id: Option<String>,
    lease_id: Option<String>,
}

impl AuditEventBuilder {
    /// Create a new builder for the given event kind with an HLC generator.
    pub fn new(hlc: Arc<Hlc>, kind: AuditEventKind) -> Self {
        Self {
            hlc,
            kind,
            sandbox_id: None,
            tenant_id: None,
            from_state: None,
            to_state: None,
            principal: None,
            service: None,
            operation_id: None,
            trace_id: None,
            idempotency_key: None,
            failure: None,
            details: None,
            epoch: None,
            fencing_token: None,
            producer: None,
            request_id: None,
            action: None,
            outcome: None,
            reason: None,
            policy_decision_id: None,
            lease_id: None,
        }
    }

    pub fn sandbox_id(mut self, id: SandboxId) -> Self {
        self.sandbox_id = Some(id);
        self
    }

    pub fn tenant_id(mut self, id: TenantId) -> Self {
        self.tenant_id = Some(id);
        self
    }

    pub fn from_state(mut self, state: impl Into<String>) -> Self {
        self.from_state = Some(state.into());
        self
    }

    pub fn to_state(mut self, state: impl Into<String>) -> Self {
        self.to_state = Some(state.into());
        self
    }

    pub fn principal(mut self, id: PrincipalId) -> Self {
        self.principal = Some(id);
        self
    }

    pub fn service(mut self, id: ServiceId) -> Self {
        self.service = Some(id);
        self
    }

    pub fn operation_id(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn failure(mut self, info: FailureInfo) -> Self {
        self.failure = Some(info);
        self
    }

    pub fn details(mut self, details: AuditEventDetails) -> Self {
        self.details = Some(details);
        self
    }

    pub fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(epoch);
        self
    }

    pub fn fencing_token(mut self, token: FencingToken) -> Self {
        self.fencing_token = Some(token);
        self
    }

    pub fn producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = Some(producer.into());
        self
    }

    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn policy_decision_id(mut self, id: impl Into<String>) -> Self {
        self.policy_decision_id = Some(id.into());
        self
    }

    pub fn lease_id(mut self, id: impl Into<String>) -> Self {
        self.lease_id = Some(id.into());
        self
    }

    /// Build the audit event, generating an ID and HLC timestamp.
    pub fn build(self) -> AuditEvent {
        let hlc_ts = self.hlc.next_timestamp();
        AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            id: AuditEventId::generate(),
            hlc_ts,
            kind: self.kind,
            sandbox_id: self.sandbox_id,
            tenant_id: self.tenant_id,
            from_state: self.from_state,
            to_state: self.to_state,
            principal: self.principal,
            service: self.service,
            operation_id: self.operation_id,
            trace_id: self.trace_id,
            idempotency_key: self.idempotency_key,
            failure: self.failure,
            details: self.details,
            recorded_at: now_iso(),
            epoch: self.epoch,
            fencing_token: self.fencing_token,
            producer: self.producer,
            request_id: self.request_id,
            action: self.action,
            outcome: self.outcome,
            reason: self.reason,
            policy_decision_id: self.policy_decision_id,
            lease_id: self.lease_id,
        }
    }
}

/// No-op audit event sink that discards all events.
///
/// Useful as a default when no audit sink is configured.
pub struct NoopAuditSink;

impl AuditEventSink for NoopAuditSink {
    fn emit(&self, _event: AuditEvent) -> Result<(), AuditSinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AuditEventKind;

    fn test_hlc() -> Arc<Hlc> {
        Arc::new(Hlc::new())
    }

    #[test]
    fn builder_creates_event_with_schema_version() {
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::LifecycleTransition)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .from_state("Pending")
            .to_state("Scheduled")
            .build();

        assert_eq!(event.schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(event.kind, AuditEventKind::LifecycleTransition);
        assert_eq!(event.sandbox_id, Some(SandboxId::from_string("sbx_test")));
        assert_eq!(event.from_state.as_deref(), Some("Pending"));
        assert_eq!(event.to_state.as_deref(), Some("Scheduled"));
    }

    #[test]
    fn builder_generates_unique_ids() {
        let hlc = test_hlc();
        let e1 = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build();
        let e2 = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build();

        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn builder_sets_all_optional_fields() {
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::PlacementOutcome)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .tenant_id(TenantId::from_string("tnt_test"))
            .principal(PrincipalId::new("user-1"))
            .service(ServiceId::new("scheduler"))
            .trace_id("trace-abc")
            .epoch(5)
            .details(AuditEventDetails::PlacementOutcome {
                cell_id: Some("cel_1".into()),
                host_id: Some("hst_1".into()),
                reason: "best_score".into(),
                score: Some(0.85),
                candidates_evaluated: 3,
            })
            .build();

        assert_eq!(event.tenant_id, Some(TenantId::from_string("tnt_test")));
        assert_eq!(event.principal, Some(PrincipalId::new("user-1")));
        assert_eq!(event.trace_id.as_deref(), Some("trace-abc"));
        assert_eq!(event.epoch, Some(5));
        assert!(matches!(
            event.details,
            Some(AuditEventDetails::PlacementOutcome { .. })
        ));
    }

    #[test]
    fn event_serialization_roundtrip() {
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::PolicyDecision)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .tenant_id(TenantId::from_string("tnt_test"))
            .details(AuditEventDetails::PolicyDecision {
                decision_id: "pdc_123".into(),
                action: "Create".into(),
                outcome: "Allow".into(),
                policy_epoch: 1,
                reason: None,
            })
            .build();

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.schema_version, event.schema_version);
        assert_eq!(deserialized.kind, event.kind);
        assert_eq!(deserialized.sandbox_id, event.sandbox_id);
        assert_eq!(deserialized.details, event.details);
    }

    #[test]
    fn noop_sink_discards_events() {
        let sink = NoopAuditSink;
        let event = AuditEventBuilder::new(test_hlc(), AuditEventKind::PolicyDecision)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .build();

        assert!(sink.emit(event).is_ok());
    }
}
