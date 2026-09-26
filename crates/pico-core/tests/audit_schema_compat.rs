//! Schema compatibility tests for audit event v1 → v2 migration.
//!
//! Validates:
//! - v1 JSON events deserialize correctly under v2 schema
//! - New v2 fields default to None in deserialized v1 events
//! - v2 events serialize/deserialize roundtrip preserving new fields
//! - v1 schema events from fixtures are forward-compatible

use pico_core::{
    AUDIT_SCHEMA_VERSION, AuditAction, AuditEvent, AuditEventBuilder, AuditEventDetails,
    AuditEventKind, AuditOutcome, AuditProducer, Hlc, SandboxId, TenantId,
};
use std::sync::Arc;

// ---- v1 JSON fixture deserializes under v2 schema ----

#[test]
fn v1_event_json_deserializes_with_v2_schema() {
    let v1_json = r#"{
        "schema_version": 1,
        "id": "evt_01JXYZAAAAAAAAAAAAAAAAAAAAAAAA",
        "hlc_ts": {
            "wall_time_ms": 1710000000000,
            "logical_counter": 0
        },
        "kind": "lifecycle_transition",
        "sandbox_id": "sbx_01JXYZAAAAAAAAAAAAAA",
        "tenant_id": "tnt_01JXYZAAAAAAAAAAAAAA",
        "from_state": "Pending",
        "to_state": "Scheduled",
        "principal": "user:alice",
        "service": "scheduler",
        "operation_id": "op_01JXYZAAAAAAAAAAAAAA",
        "trace_id": "trace-abc",
        "idempotency_key": null,
        "failure": null,
        "details": {
            "type": "lifecycle_transition",
            "fencing_token": null
        },
        "recorded_at": "2026-01-01T00:00:00Z",
        "epoch": 1,
        "fencing_token": null
    }"#;

    let event: AuditEvent =
        serde_json::from_str(v1_json).expect("v1 JSON must deserialize under v2");

    assert_eq!(event.schema_version, 1);
    assert_eq!(event.kind, AuditEventKind::LifecycleTransition);
    assert_eq!(event.from_state.as_deref(), Some("Pending"));
    assert_eq!(event.to_state.as_deref(), Some("Scheduled"));
    assert_eq!(event.epoch, Some(1));

    // v2 fields should default to None for v1 input
    assert!(event.producer.is_none());
    assert!(event.request_id.is_none());
    assert!(event.action.is_none());
    assert!(event.outcome.is_none());
    assert!(event.reason.is_none());
    assert!(event.policy_decision_id.is_none());
    assert!(event.lease_id.is_none());
}

// ---- v2 event with all new fields roundtrips ----

#[test]
fn v2_event_with_new_fields_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::LeaseEnforced)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .producer(AuditProducer::NetworkAgent)
        .request_id("req_001")
        .action(AuditAction::EnforceLease)
        .outcome(AuditOutcome::Enforced)
        .reason("valid")
        .policy_decision_id("pdc_001")
        .lease_id("lse_001")
        .details(AuditEventDetails::LeaseEnforcement {
            lease_id: "lse_001".into(),
            enforcing_component: "network-agent".into(),
            sandbox_id: "sbx_test".into(),
            tenant_id: "tnt_test".into(),
            policy_decision_id: Some("pdc_001".into()),
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();

    assert_eq!(back.producer.as_deref(), Some("network-agent"));
    assert_eq!(back.request_id.as_deref(), Some("req_001"));
    assert_eq!(back.action.as_deref(), Some("enforce_lease"));
    assert_eq!(back.outcome.as_deref(), Some("enforced"));
    assert_eq!(back.reason.as_deref(), Some("valid"));
    assert_eq!(back.policy_decision_id.as_deref(), Some("pdc_001"));
    assert_eq!(back.lease_id.as_deref(), Some("lse_001"));
    assert_eq!(back.schema_version, AUDIT_SCHEMA_VERSION);
    assert_eq!(back.kind, AuditEventKind::LeaseEnforced);
}

// ---- v1 event with minimal fields works ----

#[test]
fn minimal_v1_event_still_deserializes() {
    let v1_minimal = r#"{
        "schema_version": 1,
        "id": "evt_minimal",
        "hlc_ts": {
            "wall_time_ms": 1710000000000,
            "logical_counter": 0
        },
        "kind": "policy_decision",
        "sandbox_id": null,
        "tenant_id": null,
        "from_state": null,
        "to_state": null,
        "principal": null,
        "service": null,
        "operation_id": null,
        "trace_id": null,
        "idempotency_key": null,
        "failure": null,
        "details": null,
        "recorded_at": "2026-01-01T00:00:00Z",
        "epoch": null,
        "fencing_token": null
    }"#;

    let event: AuditEvent =
        serde_json::from_str(v1_minimal).expect("minimal v1 event must deserialize");

    assert_eq!(event.schema_version, 1);
    assert_eq!(event.kind, AuditEventKind::PolicyDecision);
    assert!(event.sandbox_id.is_none());
    assert!(event.producer.is_none());
}

// ---- All new AuditEventKind values serialize with v2 schema ----

#[test]
fn all_new_kinds_have_schema_version_2() {
    let hlc = Arc::new(Hlc::new());
    let new_kinds = [
        AuditEventKind::LeaseEnforced,
        AuditEventKind::NetworkEnforcement,
        AuditEventKind::CredentialIssuance,
        AuditEventKind::SnapshotOperation,
        AuditEventKind::CleanupDisposition,
        AuditEventKind::AuditDelivery,
    ];

    for kind in &new_kinds {
        let event = AuditEventBuilder::new(Arc::clone(&hlc), *kind).build();
        assert_eq!(
            event.schema_version, AUDIT_SCHEMA_VERSION,
            "kind {:?} must have schema_version {}",
            kind, AUDIT_SCHEMA_VERSION
        );
        assert_eq!(event.kind, *kind);
    }
}

// ---- v1 state transition events preserved ----

#[test]
fn lifecycle_transition_v1_is_forward_compatible() {
    let v1_lifecycle = r#"{
        "schema_version": 1,
        "id": "evt_lifecycle",
        "hlc_ts": {
            "wall_time_ms": 1710000000000,
            "logical_counter": 0
        },
        "kind": "lifecycle_transition",
        "sandbox_id": "sbx_test",
        "tenant_id": "tnt_test",
        "from_state": "Scheduled",
        "to_state": "Preparing",
        "principal": null,
        "service": "host-agent",
        "operation_id": "op_001",
        "trace_id": "trace-001",
        "idempotency_key": null,
        "failure": null,
        "details": {
            "type": "lifecycle_transition",
            "fencing_token": null
        },
        "recorded_at": "2026-06-01T12:00:00Z",
        "epoch": 2,
        "fencing_token": null
    }"#;

    let event: AuditEvent =
        serde_json::from_str(v1_lifecycle).expect("v1 lifecycle must deserialize");

    assert_eq!(event.from_state.as_deref(), Some("Scheduled"));
    assert_eq!(event.to_state.as_deref(), Some("Preparing"));
    assert_eq!(
        event.service.as_ref().map(|s| s.as_str()),
        Some("host-agent")
    );
    assert_eq!(
        event.operation_id.as_ref().map(|o| o.as_str()),
        Some("op_001")
    );
    assert!(event.policy_decision_id.is_none());
}
