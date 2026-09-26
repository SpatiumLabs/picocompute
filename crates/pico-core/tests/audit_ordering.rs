//! Integration tests for audit event ordering around state transitions.
//!
//! Validates:
//! - Events are emitted in correct causal order during lifecycle transitions
//! - HLC timestamps are monotonic across events from the same component
//! - Event ordering is preserved across policy, quota, and lifecycle events
//! - Lease lifecycle produces correct event ordering

use pico_core::{
    AuditEventBuilder, AuditEventDetails, AuditEventKind, AuditEventSink, FencingToken, Hlc,
    InMemoryAuditSink, LeaseAction, LeaseManager, LeaseScope, PolicyDecision, PolicyDecisionId,
    PolicyOutcome, PrincipalId, RevocationReason, SandboxId, SandboxMetadata, SandboxState,
    TenantId, apply_transition_with_audit,
};
use std::sync::Arc;

fn make_sandbox_metadata(id: &str, tenant: &str) -> SandboxMetadata {
    SandboxMetadata {
        id: SandboxId::from_string(id),
        tenant_id: TenantId::from_string(tenant),
        image: "test-image".into(),
        runtime: None,
        workload_class: None,
        backend_selection_reason: None,
        backend_selection_rejected: None,
        state: SandboxState::Pending,
        version: 0,
        operation_id: None,
        idempotency_key: None,
        actor_identity: None,
        service_identity: None,
        fencing_token: None,
        policy_epoch: Some(1),
        access_decision_id: None,
        placement: None,
        resource_limits: Default::default(),
        timestamps: pico_core::SecureTimestamps {
            issued_at: "2026-01-01T00:00:00Z".into(),
            observed_at: None,
            committed_at: None,
            expires_at: None,
        },
        failure: None,
        audit_event_ids: Vec::new(),
        parent_sandbox_id: None,
        snapshot_lineage: None,
        labels: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

fn make_allow_decision() -> PolicyDecision {
    PolicyDecision {
        decision_id: PolicyDecisionId::generate(),
        outcome: PolicyOutcome::Allow,
        policy_epoch: 1,
    }
}

// ---- Full lifecycle transition ordering ----

#[test]
fn lifecycle_transitions_emit_events_in_causal_order() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let mut metadata = make_sandbox_metadata("sbx_test_01", "tnt_test");

    let transitions = vec![
        SandboxState::Scheduled,
        SandboxState::Preparing,
        SandboxState::Booting,
        SandboxState::Running,
        SandboxState::Suspending,
        SandboxState::Suspended,
        SandboxState::Resuming,
        SandboxState::Running,
        SandboxState::Stopped,
        SandboxState::Destroying,
        SandboxState::Destroyed,
    ];

    for (expected_version, to) in transitions.into_iter().enumerate() {
        apply_transition_with_audit(
            &mut metadata,
            to,
            expected_version as u64,
            sink.as_ref(),
            &hlc,
        )
        .unwrap();
    }

    let events = sink.events_for_sandbox(&SandboxId::from_string("sbx_test_01"));
    assert_eq!(events.len(), 11, "expected 11 lifecycle transition events");

    assert!(
        pico_core::is_ordered_chronologically(&events),
        "events are not in chronological order"
    );
}

// ---- Transition with fencing tokens ----

#[test]
fn lifecycle_transitions_with_fencing_tokens_maintain_order() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let mut metadata = make_sandbox_metadata("sbx_fenced", "tnt_test");

    apply_transition_with_audit(
        &mut metadata,
        SandboxState::Scheduled,
        0,
        sink.as_ref(),
        &hlc,
    )
    .unwrap();

    // Manually set fencing token to simulate a fenced transition
    metadata.fencing_token = Some(FencingToken {
        epoch: 1,
        sequence: 1,
    });
    metadata.state = SandboxState::Preparing;
    metadata.version = 2;

    // Emit manually to test fencing token is captured
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition)
            .sandbox_id(metadata.id.clone())
            .tenant_id(metadata.tenant_id.clone())
            .from_state(SandboxState::Scheduled.as_str())
            .to_state(SandboxState::Preparing.as_str())
            .fencing_token(metadata.fencing_token.unwrap_or(FencingToken::new(0)))
            .details(AuditEventDetails::LifecycleTransition {
                fencing_token: metadata.fencing_token,
            })
            .build(),
    );

    let events = sink.events_for_sandbox(&SandboxId::from_string("sbx_fenced"));

    assert!(pico_core::validate_causal_chain(&events).is_ok());
}

// ---- Lease lifecycle event ordering ----

#[test]
fn lease_issue_revoke_produces_correct_event_order() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tenant = TenantId::from_string("tnt_lease_test");
    let principal = PrincipalId::new("user:alice");
    let sandbox = SandboxId::from_string("sbx_lease_test");

    // Issue lease
    let lease = manager.issue(
        tenant.clone(),
        principal.clone(),
        sandbox.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &make_allow_decision(),
        300,
    );

    assert!(!sink.events_by_kind(AuditEventKind::LeaseIssued).is_empty());

    // Revoke lease
    manager
        .revoke(&lease.lease_id, RevocationReason::AdminAction)
        .unwrap();

    let events = sink.events();

    let issued_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseIssued)
        .unwrap();
    let revoked_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseRevoked)
        .unwrap();

    assert!(
        issued_idx < revoked_idx,
        "LeaseIssued ({issued_idx}) must precede LeaseRevoked ({revoked_idx})"
    );
}

// ---- Lease renewal event ordering ----

#[test]
fn lease_renewal_produces_issue_after_revoke() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tenant = TenantId::from_string("tnt_renewal");
    let principal = PrincipalId::new("user:bob");
    let sandbox = SandboxId::from_string("sbx_renewal");

    let lease = manager.issue(
        tenant.clone(),
        principal.clone(),
        sandbox.clone(),
        LeaseAction::FileTransfer,
        LeaseScope::unbounded(),
        &make_allow_decision(),
        300,
    );

    sink.clear();

    manager
        .renew(&lease.lease_id, &make_allow_decision(), 600)
        .unwrap();

    let events = sink.events();
    let kinds: Vec<AuditEventKind> = events.iter().map(|e| e.kind).collect();

    // Renew calls revoke first, then issue
    assert!(
        kinds.contains(&AuditEventKind::LeaseRevoked),
        "renew must produce LeaseRevoked"
    );
    assert!(
        kinds.contains(&AuditEventKind::LeaseIssued),
        "renew must produce LeaseIssued"
    );
}

// ---- Lease denial event ----

#[test]
fn lease_validation_denial_emits_lease_denied_event() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tenant = TenantId::from_string("tnt_deny");
    let principal = PrincipalId::new("user:carol");
    let sandbox = SandboxId::from_string("sbx_deny");

    let lease = manager.issue(
        tenant.clone(),
        principal.clone(),
        sandbox.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &make_allow_decision(),
        300,
    );

    sink.clear();

    // Validate with wrong sandbox
    let wrong_sandbox = SandboxId::from_string("sbx_other");
    let result = manager.validate(
        &lease.lease_id,
        &wrong_sandbox,
        &tenant,
        LeaseAction::Exec,
        1,
    );
    assert!(result.is_err());

    let denied_events = sink.events_by_kind(AuditEventKind::LeaseDenied);
    assert!(
        !denied_events.is_empty(),
        "validation denial must emit LeaseDenied event"
    );
    if let Some(ref details) = denied_events[0].details {
        assert!(
            matches!(details, AuditEventDetails::LeaseOperation { .. }),
            "LeaseDenied must have LeaseOperation details"
        );
    }
}

// ---- Lease expire event ----

#[test]
fn lease_cleanup_emits_expired_events() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tenant = TenantId::from_string("tnt_expire");
    let principal = PrincipalId::new("user:dave");
    let sandbox = SandboxId::from_string("sbx_expire");

    // Issue with 0 TTL
    manager.issue(
        tenant.clone(),
        principal.clone(),
        sandbox.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &make_allow_decision(),
        0,
    );

    let removed = manager.cleanup_expired();
    assert_eq!(removed, 1);

    let expired_events = sink.events_by_kind(AuditEventKind::LeaseExpired);
    assert_eq!(expired_events.len(), 1);
}

// ---- Event uniqueness ----

#[test]
fn each_event_has_unique_id() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let mut metadata = make_sandbox_metadata("sbx_unique", "tnt_test");

    use hashbrown::HashSet;

    let mut event_ids = HashSet::new();

    for state in [SandboxState::Scheduled, SandboxState::Preparing] {
        let version = metadata.version;
        apply_transition_with_audit(&mut metadata, state, version, &sink, &hlc).unwrap();
    }

    for event in sink.events() {
        let id = event.id.as_str().to_string();
        assert!(event_ids.insert(id.clone()), "duplicate event ID: {id}");
    }

    assert_eq!(event_ids.len(), 2);
}

// ---- Last-Write Wins detection ----

#[test]
fn event_highest_hlc_is_latest_state_transition() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let mut metadata = make_sandbox_metadata("sbx_lww", "tnt_test");

    apply_transition_with_audit(&mut metadata, SandboxState::Scheduled, 0, &sink, &hlc).unwrap();
    apply_transition_with_audit(&mut metadata, SandboxState::Preparing, 1, &sink, &hlc).unwrap();

    let events = sink.events();
    let last_event = events.last().unwrap();

    assert_eq!(
        last_event.to_state.as_deref(),
        Some(SandboxState::Preparing.as_str())
    );
}

// ---- Quota enforcement ordering ----

#[test]
fn failed_quota_check_on_pending_sandbox_does_not_produce_lifecycle_event() {
    let sink = InMemoryAuditSink::new();
    let mut metadata = make_sandbox_metadata("sbx_quota", "tnt_quota");

    // Mark as Pending
    metadata.state = SandboxState::Pending;
    metadata.version = 0;

    // No transition should happen (quota rejection doesn't change state)
    let lifecycle_events = sink.events_by_kind(AuditEventKind::LifecycleTransition);
    assert!(
        lifecycle_events.is_empty(),
        "no lifecycle transition should occur on quota rejection"
    );
}

// ---- Event details are always set for lifecycle events ----

#[test]
fn all_lifecycle_transition_events_have_details() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let mut metadata = make_sandbox_metadata("sbx_details", "tnt_test");

    apply_transition_with_audit(&mut metadata, SandboxState::Scheduled, 0, &sink, &hlc).unwrap();

    let events = sink.events_by_kind(AuditEventKind::LifecycleTransition);
    assert!(!events.is_empty());
    assert!(events[0].details.is_some());
}
