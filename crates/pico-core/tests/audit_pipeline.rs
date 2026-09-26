//! Pipeline integration tests for the audit event system.
//!
//! Validates:
//! - Policy → lease-issued → lease-enforced correlation chain
//! - Redaction strips sensitive content before persistence
//! - All new event kinds emit with correct structure
//! - Query builder filters behave correctly
//! - Retention config generates expected SQL

use pico_core::{
    AuditAction, AuditEventBuilder, AuditEventDetails, AuditEventKind, AuditEventQuery,
    AuditEventSink, AuditOutcome, AuditProducer, AuditRetentionConfig, Hlc, InMemoryAuditSink,
    LeaseManager, SandboxId, TenantId, redact_event,
};
use std::sync::Arc;

// ---- Correlation: policy → lease issued → lease enforced ----

#[test]
fn policy_to_lease_enforced_correlation_chain() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let sbx = SandboxId::from_string("sbx_corr_v2");
    let tnt = TenantId::from_string("tnt_corr_v2");
    let trace = "trace-policy-lease";

    // 1. Policy decision
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .trace_id(trace)
            .policy_decision_id("pdc_v2_001")
            .outcome(AuditOutcome::Allow)
            .details(AuditEventDetails::PolicyDecision {
                decision_id: "pdc_v2_001".into(),
                action: "Create".into(),
                outcome: "Allow".into(),
                policy_epoch: 1,
                reason: None,
            })
            .build(),
    );

    // 2. Lease issued
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LeaseIssued)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .trace_id(trace)
            .lease_id("lse_v2_001")
            .policy_decision_id("pdc_v2_001")
            .details(AuditEventDetails::LeaseOperation {
                lease_id: "lse_v2_001".into(),
                action: "exec".into(),
                policy_decision_id: Some("pdc_v2_001".into()),
                reason: None,
            })
            .build(),
    );

    // 3. Lease enforced (data-plane validation succeeded)
    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::LeaseEnforced)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .trace_id(trace)
            .lease_id("lse_v2_001")
            .policy_decision_id("pdc_v2_001")
            .producer(AuditProducer::NetworkAgent)
            .action(AuditAction::EnforceLease)
            .outcome(AuditOutcome::Enforced)
            .details(AuditEventDetails::LeaseEnforcement {
                lease_id: "lse_v2_001".into(),
                enforcing_component: "network-agent".into(),
                sandbox_id: "sbx_corr_v2".into(),
                tenant_id: "tnt_corr_v2".into(),
                policy_decision_id: Some("pdc_v2_001".into()),
            })
            .build(),
    );

    let events = sink.events();

    // Find indices
    let policy_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::PolicyDecision)
        .unwrap();
    let issued_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseIssued)
        .unwrap();
    let enforced_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseEnforced)
        .unwrap();

    assert!(
        policy_idx < issued_idx,
        "PolicyDecision ({policy_idx}) must precede LeaseIssued ({issued_idx})"
    );
    assert!(
        issued_idx < enforced_idx,
        "LeaseIssued ({issued_idx}) must precede LeaseEnforced ({enforced_idx})"
    );

    // Verify shared correlation fields
    let enforced = &events[enforced_idx];
    assert_eq!(enforced.lease_id.as_deref(), Some("lse_v2_001"));
    assert_eq!(enforced.policy_decision_id.as_deref(), Some("pdc_v2_001"));
    assert_eq!(enforced.outcome.as_deref(), Some("enforced"));
}

// ---- LeaseManager validates and enforces ----

#[test]
fn lease_manager_validates_and_emits_enforced() {
    use pico_core::{
        LeaseAction, LeaseScope, PolicyDecision, PolicyDecisionId, PolicyOutcome, PrincipalId,
    };

    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tnt = TenantId::from_string("tnt_enf");
    let pid = PrincipalId::new("user:enforcer");
    let sbx = SandboxId::from_string("sbx_enf");

    let lease = manager.issue(
        tnt.clone(),
        pid.clone(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &PolicyDecision {
            decision_id: PolicyDecisionId::generate(),
            outcome: PolicyOutcome::Allow,
            policy_epoch: 1,
        },
        300,
    );

    // Validate - should succeed and emit LeaseEnforced
    let result = manager.validate(&lease.lease_id, &sbx, &tnt, LeaseAction::Exec, 1);
    assert!(result.is_ok());

    // Check LeaseEnforced event
    let enforced_events = sink.events_by_kind(AuditEventKind::LeaseEnforced);
    assert!(
        !enforced_events.is_empty(),
        "LeaseEnforced event must be emitted on validation success"
    );
    assert_eq!(enforced_events[0].outcome.as_deref(), Some("enforced"));
}

// ---- Redaction: sensitive content stripping ----

#[test]
fn redaction_strips_url_from_reason() {
    let hlc = Arc::new(Hlc::new());
    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
        .reason("failed to fetch https://internal.example.com/secret")
        .build();

    redact_event(&mut event);
    assert_eq!(event.reason.as_deref(), Some("[redacted]"));
}

#[test]
fn redaction_preserves_safe_structural_reasons() {
    let hlc = Arc::new(Hlc::new());
    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
        .reason("quota_exceeded: vcpus limit reached")
        .build();

    redact_event(&mut event);
    assert_eq!(
        event.reason.as_deref(),
        Some("quota_exceeded: vcpus limit reached")
    );
}

#[test]
fn redaction_handles_new_event_kind_details() {
    let hlc = Arc::new(Hlc::new());
    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::NetworkEnforcement)
        .details(AuditEventDetails::NetworkEnforcement {
            action: "egress_allow".into(),
            destination: Some("10.0.0.1:443".into()),
            outcome: "allow".into(),
            reason: Some("dashboard access".into()),
            lease_id: Some("lse_001".into()),
        })
        .build();

    redact_event(&mut event);
    // Network enforcement details don't contain user content, should be unchanged
    let details = event.details.unwrap();
    match details {
        AuditEventDetails::NetworkEnforcement { outcome, .. } => {
            assert_eq!(outcome, "allow");
        }
        _ => panic!("expected NetworkEnforcement details"),
    }
}

// ---- All new event kinds emit valid events ----

#[test]
fn all_event_kinds_emit_with_valid_structure() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());

    // LeaseEnforced
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LeaseEnforced)
            .lease_id("lse_test")
            .producer(AuditProducer::NetworkAgent)
            .outcome(AuditOutcome::Enforced)
            .details(AuditEventDetails::LeaseEnforcement {
                lease_id: "lse_test".into(),
                enforcing_component: "network-agent".into(),
                sandbox_id: "sbx_test".into(),
                tenant_id: "tnt_test".into(),
                policy_decision_id: None,
            })
            .build(),
    );

    // NetworkEnforcement
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::NetworkEnforcement)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .action(AuditAction::EgressDeny)
            .outcome(AuditOutcome::Denied)
            .reason("destination not in policy")
            .details(AuditEventDetails::NetworkEnforcement {
                action: "egress_deny".into(),
                destination: Some("8.8.8.8:443".into()),
                outcome: "denied".into(),
                reason: Some("destination not in policy".into()),
                lease_id: None,
            })
            .build(),
    );

    // CredentialIssuance
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::CredentialIssuance)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .action(AuditAction::Issue)
            .outcome(AuditOutcome::Issued)
            .details(AuditEventDetails::CredentialIssuance {
                action: "issue".into(),
                outcome: "issued".into(),
                reason: None,
                credential_type: "short_lived_token".into(),
                lease_id: None,
            })
            .build(),
    );

    // SnapshotOperation
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::SnapshotOperation)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .action(AuditAction::Create)
            .outcome(AuditOutcome::Success)
            .details(AuditEventDetails::SnapshotOperation {
                operation: "create".into(),
                outcome: "success".into(),
                reason: None,
                snapshot_id: Some("snap_001".into()),
                parent_snapshot_id: None,
                state_profile: Some("filesystem".into()),
            })
            .build(),
    );

    // CleanupDisposition
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::CleanupDisposition)
            .sandbox_id(SandboxId::from_string("sbx_test"))
            .action(AuditAction::Cleanup)
            .outcome(AuditOutcome::Resolved)
            .details(AuditEventDetails::CleanupDisposition {
                disposition: "cleaned".into(),
                reason: "stale namespace removed".into(),
                affected_resources: Some(vec!["namespace_a".into()]),
                quarantine: false,
            })
            .build(),
    );

    // AuditDelivery
    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::AuditDelivery)
            .producer(AuditProducer::AuditSink)
            .outcome(AuditOutcome::Delivered)
            .details(AuditEventDetails::AuditDelivery {
                outcome: "delivered".into(),
                reason: None,
                batch_size: Some(100),
                retry_count: Some(0),
            })
            .build(),
    );

    let events = sink.events();
    assert_eq!(events.len(), 6, "expected 6 events for all new kinds");
    assert!(sink.events_by_kind(AuditEventKind::LeaseEnforced).len() == 1);
    assert!(
        sink.events_by_kind(AuditEventKind::NetworkEnforcement)
            .len()
            == 1
    );
    assert!(
        sink.events_by_kind(AuditEventKind::CredentialIssuance)
            .len()
            == 1
    );
    assert!(sink.events_by_kind(AuditEventKind::SnapshotOperation).len() == 1);
    assert!(
        sink.events_by_kind(AuditEventKind::CleanupDisposition)
            .len()
            == 1
    );
    assert!(sink.events_by_kind(AuditEventKind::AuditDelivery).len() == 1);
}

// ---- Retention config generates correct SQL ----

#[test]
fn retention_expire_sql_generates_correctly() {
    let config = AuditRetentionConfig {
        hot_retention_days: 30,
        cold_retention_days: 365,
        dead_letter_retention_days: 90,
    };

    let audit_sql = config.expire_audit_sql(1000);
    assert!(audit_sql.contains("DELETE FROM pico.audit_events"));
    assert!(audit_sql.contains("365 days"));
    assert!(audit_sql.contains("LIMIT 1000"));

    let dl_sql = config.expire_dead_letter_sql(500);
    assert!(dl_sql.contains("DELETE FROM pico.audit_events_dead_letter"));
    assert!(dl_sql.contains("90 days"));
    assert!(dl_sql.contains("LIMIT 500"));
}

#[test]
fn retention_default_365_days() {
    let config = AuditRetentionConfig::default();
    assert_eq!(config.cold_retention_days, 365);
    assert_eq!(config.hot_retention_days, 30);
    assert_eq!(config.dead_letter_retention_days, 90);
}

// ---- Query builder ----

#[test]
fn query_builder_sets_all_filters() {
    use pico_core::AuditEventKind;

    let q = AuditEventQuery::new()
        .tenant_id("tnt_001")
        .sandbox_id("sbx_001")
        .operation_id("op_001")
        .policy_decision_id("pdc_001")
        .lease_id("lse_001")
        .event_kind(AuditEventKind::LeaseEnforced)
        .hlc_range(1000, 2000)
        .cursor(42)
        .limit(50);

    assert_eq!(q.tenant_id.as_deref(), Some("tnt_001"));
    assert_eq!(q.sandbox_id.as_deref(), Some("sbx_001"));
    assert_eq!(q.operation_id.as_deref(), Some("op_001"));
    assert_eq!(q.policy_decision_id.as_deref(), Some("pdc_001"));
    assert_eq!(q.lease_id.as_deref(), Some("lse_001"));
    assert_eq!(q.event_kind, Some(AuditEventKind::LeaseEnforced));
    assert_eq!(q.hlc_wall_time_from_ms, Some(1000));
    assert_eq!(q.hlc_wall_time_to_ms, Some(2000));
    assert_eq!(q.cursor, Some(42));
    assert_eq!(q.limit, 50);
}

#[test]
fn query_limit_clamped_at_1000() {
    let q = AuditEventQuery::new().limit(5000);
    assert_eq!(q.limit, 1000);
}

// ---- Lease denied → enforced ordering through manager ----

#[test]
fn lease_manager_denied_and_enforced_produce_both_events() {
    use pico_core::{
        LeaseAction, LeaseScope, PolicyDecision, PolicyDecisionId, PolicyOutcome, PrincipalId,
    };

    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tnt = TenantId::from_string("tnt_both");
    let pid = PrincipalId::new("user:both");
    let sbx = SandboxId::from_string("sbx_both");

    let lease = manager.issue(
        tnt.clone(),
        pid.clone(),
        sbx.clone(),
        LeaseAction::PortForward,
        LeaseScope::unbounded(),
        &PolicyDecision {
            decision_id: PolicyDecisionId::generate(),
            outcome: PolicyOutcome::Allow,
            policy_epoch: 1,
        },
        300,
    );

    // Validate with wrong tenant → should deny
    let wrong_tnt = TenantId::from_string("tnt_wrong");
    let deny_result = manager.validate(
        &lease.lease_id,
        &sbx,
        &wrong_tnt,
        LeaseAction::PortForward,
        1,
    );
    assert!(deny_result.is_err());

    // Validate correctly → should enforce
    let enforce_result = manager.validate(&lease.lease_id, &sbx, &tnt, LeaseAction::PortForward, 1);
    assert!(enforce_result.is_ok());

    let denied = sink.events_by_kind(AuditEventKind::LeaseDenied);
    let enforced = sink.events_by_kind(AuditEventKind::LeaseEnforced);
    assert!(!denied.is_empty(), "must emit LeaseDenied");
    assert!(!enforced.is_empty(), "must emit LeaseEnforced");
}
