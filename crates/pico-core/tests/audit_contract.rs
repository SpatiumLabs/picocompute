//! Contract tests for the audit event schema.
//!
//! Validates:
//! - Event schema version is present and correct
//! - All event kinds serialize/deserialize correctly
//! - Event details variants correspond to the correct event kinds
//! - Mandatory correlation fields are populated
//! - HLC timestamps provide causal ordering
//! - Secrets are never present in serialized output

#![allow(
    dead_code,
    reason = "contract schema types hold all fields for deserialization"
)]

use pico_core::{
    AUDIT_SCHEMA_VERSION, AuditEvent, AuditEventBuilder, AuditEventDetails, AuditEventKind,
    AuditEventSink, FencingToken, Hlc, InMemoryAuditSink, SandboxId, TenantId,
};
use std::sync::Arc;

// ---- Schema version contract ----

#[test]
fn all_events_use_current_schema_version() {
    let hlc = Arc::new(Hlc::new());
    let events = vec![
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition).build(),
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LeaseIssued).build(),
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build(),
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::QuotaRejection).build(),
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome).build(),
    ];

    for event in &events {
        assert_eq!(
            event.schema_version, AUDIT_SCHEMA_VERSION,
            "event kind {:?} has wrong schema version",
            event.kind
        );
    }
}

// ---- Serialization roundtrip for every event kind ----

#[test]
fn lifecycle_transition_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .from_state("Pending")
        .to_state("Scheduled")
        .details(AuditEventDetails::LifecycleTransition {
            fencing_token: Some(FencingToken {
                epoch: 1,
                sequence: 0,
            }),
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::LifecycleTransition);
    assert_eq!(back.from_state.as_deref(), Some("Pending"));
    assert_eq!(back.to_state.as_deref(), Some("Scheduled"));
    assert!(matches!(
        back.details,
        Some(AuditEventDetails::LifecycleTransition { .. })
    ));
}

#[test]
fn policy_decision_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .details(AuditEventDetails::PolicyDecision {
            decision_id: "pdc_001".into(),
            action: "Create".into(),
            outcome: "Allow".into(),
            policy_epoch: 1,
            reason: None,
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::PolicyDecision);
    assert!(matches!(
        back.details,
        Some(AuditEventDetails::PolicyDecision { .. })
    ));
}

#[test]
fn policy_decision_deny_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .details(AuditEventDetails::PolicyDecision {
            decision_id: "pdc_002".into(),
            action: "Create".into(),
            outcome: "Deny".into(),
            policy_epoch: 2,
            reason: Some("policy denied: principal not authorized".into()),
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::PolicyDecision);
}

#[test]
fn quota_rejection_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::QuotaRejection)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .details(AuditEventDetails::QuotaRejection {
            decision_id: "pdc_003".into(),
            resource: "vcpus".into(),
            limit: 10,
            current: 10,
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::QuotaRejection);
}

#[test]
fn placement_outcome_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PlacementOutcome)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .details(AuditEventDetails::PlacementOutcome {
            cell_id: Some("cel_001".into()),
            host_id: Some("hst_001".into()),
            reason: "BestScore".into(),
            score: Some(0.92),
            candidates_evaluated: 5,
            sampled: false,
            sample_size: 5,
            eligible: 5,
            overlay_adjusted: false,
            service_class: pico_core::ServiceClass::LatencySensitive,
            overcommit_applied: false,
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::PlacementOutcome);
}

#[test]
fn placement_outcome_reads_events_without_selection_fields() {
    // Events recorded before selection detail existed must still decode,
    // with the new fields defaulting to the un-sampled, un-adjusted state.
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PlacementOutcome)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .details(AuditEventDetails::PlacementOutcome {
            cell_id: Some("cel_001".into()),
            host_id: Some("hst_001".into()),
            reason: "BestScore".into(),
            score: Some(0.92),
            candidates_evaluated: 5,
            sampled: false,
            sample_size: 5,
            eligible: 5,
            overlay_adjusted: false,
            service_class: pico_core::ServiceClass::LatencySensitive,
            overcommit_applied: false,
        })
        .build();

    let mut json = serde_json::to_value(&event).unwrap();
    let details = json
        .get_mut("details")
        .expect("placement event carries details");
    for field in ["sampled", "sample_size", "eligible", "overlay_adjusted"] {
        details
            .as_object_mut()
            .expect("details decode as object")
            .remove(field);
    }
    let back: AuditEvent = serde_json::from_value(json).unwrap();
    assert!(matches!(
        back.details,
        Some(AuditEventDetails::PlacementOutcome {
            sampled: false,
            overlay_adjusted: false,
            service_class: pico_core::ServiceClass::LatencySensitive,
            overcommit_applied: false,
            ..
        })
    ));
}

#[test]
fn lease_operation_roundtrips_for_all_lease_kinds() {
    let hlc = Arc::new(Hlc::new());
    let lease_kinds = [
        AuditEventKind::LeaseIssued,
        AuditEventKind::LeaseRenewed,
        AuditEventKind::LeaseExpired,
        AuditEventKind::LeaseRevoked,
        AuditEventKind::LeaseDenied,
    ];

    for kind in &lease_kinds {
        let event = AuditEventBuilder::new(Arc::clone(&hlc), *kind)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .tenant_id(TenantId::from_string("tnt_test"))
            .details(AuditEventDetails::LeaseOperation {
                lease_id: "lse_001".into(),
                action: "exec".into(),
                policy_decision_id: Some("pdc_001".into()),
                reason: None,
            })
            .build();

        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, *kind);
    }
}

#[test]
fn runtime_outcome_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::RuntimeOutcome)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .details(AuditEventDetails::RuntimeOutcome {
            operation: "prepare".into(),
            success: true,
            error: None,
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::RuntimeOutcome);
}

#[test]
fn host_disabled_roundtrips() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::HostDisabled)
        .details(AuditEventDetails::HostDisabled {
            host_id: "hst_001".into(),
            reason: "health_check_failed".into(),
        })
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.kind, AuditEventKind::HostDisabled);
}

// ---- No secrets contract ----

#[test]
fn event_json_contains_no_secret_keywords() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .build();

    let json = serde_json::to_string(&event).unwrap();
    let lower = json.to_lowercase();

    assert!(
        !lower.contains("password"),
        "event JSON contains 'password': {json}"
    );
    assert!(
        !lower.contains("secret"),
        "event JSON contains 'secret': {json}"
    );
}

// ---- Correlation fields ----

#[test]
fn events_preserve_trace_id_for_correlation() {
    let hlc = Arc::new(Hlc::new());
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision)
        .sandbox_id(SandboxId::from_string("sbx_test"))
        .tenant_id(TenantId::from_string("tnt_test"))
        .trace_id("trace-abc-123")
        .build();

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("trace-abc-123"), "trace_id missing from JSON");
    assert_eq!(event.trace_id.as_deref(), Some("trace-abc-123"));
}

#[test]
fn events_carry_sandbox_id_for_correlation() {
    let hlc = Arc::new(Hlc::new());
    let sbx = SandboxId::from_string("sbx_test");
    let event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
        .sandbox_id(sbx.clone())
        .build();

    assert_eq!(event.sandbox_id, Some(sbx));
}

#[test]
fn events_carry_tenant_id_for_correlation() {
    let hlc = Arc::new(Hlc::new());
    let tnt = TenantId::from_string("tnt_test");
    let event = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision)
        .tenant_id(tnt.clone())
        .build();

    assert_eq!(event.tenant_id, Some(tnt));
}

// ---- HLC causal ordering ----

#[test]
fn consecutive_events_from_same_hlc_are_monotonically_ordered() {
    let hlc = Arc::new(Hlc::new());
    let e1 = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build();
    let e2 = AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision).build();
    let e3 = AuditEventBuilder::new(hlc, AuditEventKind::PolicyDecision).build();

    assert!(
        e1.hlc_ts <= e2.hlc_ts,
        "events not monotonically ordered: e1={}, e2={}",
        e1.hlc_ts,
        e2.hlc_ts
    );
    assert!(
        e2.hlc_ts <= e3.hlc_ts,
        "events not monotonically ordered: e2={}, e3={}",
        e2.hlc_ts,
        e3.hlc_ts
    );
}

// ---- InMemorySink stores events ----

#[test]
fn sink_preserves_event_count() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());

    for i in 0..5 {
        let _ = sink.emit(
            AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
                .sandbox_id(SandboxId::from_string(format!("sbx_{i:02}")))
                .build(),
        );
    }

    assert_eq!(sink.len(), 5);
    assert_eq!(sink.events().len(), 5);
}

#[test]
fn sink_filters_by_sandbox() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let sbx_a = SandboxId::from_string("sbx_aaa");
    let sbx_b = SandboxId::from_string("sbx_bbb");

    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition)
            .sandbox_id(sbx_a.clone())
            .build(),
    );
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition)
            .sandbox_id(sbx_b.clone())
            .build(),
    );
    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .sandbox_id(sbx_a.clone())
            .build(),
    );

    assert_eq!(sink.events_for_sandbox(&sbx_a).len(), 2);
    assert_eq!(sink.events_for_sandbox(&sbx_b).len(), 1);
}
