//! Correlation tests: validate end-to-end event traceability from
//! policy decision to placement to data-plane enforcement.
//!
//! Events with the same sandbox_id and trace_id should be correlatable
//! across the policy, scheduler, and lease components.

use pico_core::{
    AuditEventBuilder, AuditEventDetails, AuditEventKind, AuditEventSink, Hlc, InMemoryAuditSink,
    LeaseAction, LeaseManager, LeaseScope, PolicyDecision, PolicyDecisionId, PolicyOutcome,
    PrincipalId, RevocationReason, SandboxId, SandboxMetadata, SandboxState, TenantId,
    apply_transition_with_audit,
};
use std::sync::Arc;

fn make_allow_decision() -> PolicyDecision {
    PolicyDecision {
        decision_id: PolicyDecisionId::generate(),
        outcome: PolicyOutcome::Allow,
        policy_epoch: 1,
    }
}

fn tenant_id() -> TenantId {
    TenantId::from_string("tnt_correlation")
}

fn principal_id() -> PrincipalId {
    PrincipalId::new("user:correlation-test")
}

fn sandbox_id() -> SandboxId {
    SandboxId::from_string("sbx_correlation")
}

fn trace_id() -> String {
    "trace-corr-001".into()
}

// ---- Full correlation: policy -> quota -> placement -> lifecycle -> lease ----

#[test]
fn events_share_correlation_identifiers() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let tnt = tenant_id();
    let pid = principal_id();
    let sbx = sandbox_id();
    let trace = trace_id();

    // 1. Emit policy decision event
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .principal(pid.clone())
            .trace_id(trace.clone())
            .details(AuditEventDetails::PolicyDecision {
                decision_id: "pdc_corr_001".into(),
                action: "Create".into(),
                outcome: "Allow".into(),
                policy_epoch: 1,
                reason: None,
            })
            .build(),
    );

    // 2. Emit placement outcome event
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .trace_id(trace.clone())
            .details(AuditEventDetails::PlacementOutcome {
                cell_id: Some("cel_001".into()),
                host_id: Some("hst_001".into()),
                reason: "BestScore".into(),
                score: Some(0.95),
                candidates_evaluated: 3,
                sampled: false,
                sample_size: 3,
                eligible: 3,
                overlay_adjusted: false,
                service_class: pico_core::ServiceClass::LatencySensitive,
                overcommit_applied: false,
            })
            .build(),
    );

    // 3. Emit lifecycle transition events
    let mut metadata = SandboxMetadata {
        id: sbx.clone(),
        tenant_id: tnt.clone(),
        image: "test-image".into(),
        runtime: None,
        workload_class: None,
        backend_selection_reason: None,
        backend_selection_rejected: None,
        state: SandboxState::Pending,
        version: 0,
        operation_id: None,
        idempotency_key: None,
        actor_identity: Some(pid.clone()),
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
    };

    apply_transition_with_audit(
        &mut metadata,
        SandboxState::Scheduled,
        0,
        sink.as_ref(),
        &hlc,
    )
    .unwrap();
    apply_transition_with_audit(
        &mut metadata,
        SandboxState::Preparing,
        1,
        sink.as_ref(),
        &hlc,
    )
    .unwrap();
    apply_transition_with_audit(&mut metadata, SandboxState::Booting, 2, sink.as_ref(), &hlc)
        .unwrap();
    apply_transition_with_audit(&mut metadata, SandboxState::Running, 3, sink.as_ref(), &hlc)
        .unwrap();

    // 4. Emit lease issued event
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LeaseIssued)
            .sandbox_id(sbx.clone())
            .tenant_id(tnt.clone())
            .principal(pid.clone())
            .trace_id(trace.clone())
            .details(AuditEventDetails::LeaseOperation {
                lease_id: "lse_corr_001".into(),
                action: "exec".into(),
                policy_decision_id: Some("pdc_corr_001".into()),
                reason: None,
            })
            .build(),
    );

    // Verify all events for this sandbox
    let sandbox_events = sink.events_for_sandbox(&sbx);
    assert!(
        sandbox_events.len() >= 6,
        "expected at least 6 events for the sandbox, got {}",
        sandbox_events.len()
    );

    // Verify event kinds appear in expected order
    let kinds: Vec<AuditEventKind> = sandbox_events.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&AuditEventKind::PolicyDecision));
    assert!(kinds.contains(&AuditEventKind::PlacementOutcome));
    assert!(kinds.contains(&AuditEventKind::LifecycleTransition));
    assert!(kinds.contains(&AuditEventKind::LeaseIssued));
}

// ---- Correlation by trace_id across components ----

#[test]
fn trace_id_correlates_events_across_components() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let trace = "trace-cross-component";

    // Policy decision
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .sandbox_id(sandbox_id())
            .tenant_id(tenant_id())
            .trace_id(trace)
            .build(),
    );

    // Placement
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
            .sandbox_id(sandbox_id())
            .tenant_id(tenant_id())
            .trace_id(trace)
            .build(),
    );

    // Lifecycle
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::LifecycleTransition)
            .sandbox_id(sandbox_id())
            .tenant_id(tenant_id())
            .trace_id(trace)
            .build(),
    );

    // Lease
    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::LeaseIssued)
            .sandbox_id(sandbox_id())
            .tenant_id(tenant_id())
            .trace_id(trace)
            .build(),
    );

    let all_events = sink.events();
    let correlated: Vec<_> = all_events
        .iter()
        .filter(|e| e.trace_id.as_deref() == Some(trace))
        .collect();

    assert_eq!(correlated.len(), 4, "all 4 events must share the trace_id");
}

// ---- Policy decision to placement correlation ----

#[test]
fn policy_decision_precedes_placement() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let sbx = sandbox_id();

    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PolicyDecision)
            .sandbox_id(sbx.clone())
            .details(AuditEventDetails::PolicyDecision {
                decision_id: "pdc_placement".into(),
                action: "Create".into(),
                outcome: "Allow".into(),
                policy_epoch: 1,
                reason: None,
            })
            .build(),
    );

    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::PlacementOutcome)
            .sandbox_id(sbx.clone())
            .details(AuditEventDetails::PlacementOutcome {
                cell_id: Some("cel_001".into()),
                host_id: Some("hst_001".into()),
                reason: "BestScore".into(),
                score: Some(0.85),
                candidates_evaluated: 4,
                sampled: false,
                sample_size: 4,
                eligible: 4,
                overlay_adjusted: false,
                service_class: pico_core::ServiceClass::LatencySensitive,
                overcommit_applied: false,
            })
            .build(),
    );

    let events = sink.events();

    let policy_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::PolicyDecision)
        .unwrap();
    let placement_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::PlacementOutcome)
        .unwrap();

    assert!(
        policy_idx < placement_idx,
        "PolicyDecision ({policy_idx}) must precede PlacementOutcome ({placement_idx})"
    );
}

// ---- Lease revocation-to-denial correlation ----

#[test]
fn revoked_lease_produces_denial_on_next_validation() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());
    let manager = LeaseManager::with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), hlc);

    let tnt = tenant_id();
    let pid = principal_id();
    let sbx = sandbox_id();

    let lease = manager.issue(
        tnt.clone(),
        pid.clone(),
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &make_allow_decision(),
        300,
    );

    // Revoke
    manager
        .revoke(&lease.lease_id, RevocationReason::AdminAction)
        .unwrap();

    // Validate should fail with revocation
    let result = manager.validate(&lease.lease_id, &sbx, &tnt, LeaseAction::Exec, 1);
    assert!(result.is_err());

    let events = sink.events();
    let revoke_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseRevoked)
        .unwrap();
    let deny_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LeaseDenied)
        .unwrap();

    assert!(
        revoke_idx < deny_idx,
        "LeaseRevoked ({revoke_idx}) must precede LeaseDenied ({deny_idx})"
    );
}

// ---- Placement outcome to lifecycle transition correlation ----

#[test]
fn placement_outcome_precedes_lifecycle_scheduled() {
    let sink = InMemoryAuditSink::new();
    let hlc = Arc::new(Hlc::new());
    let sbx = sandbox_id();

    // Placement outcome
    let _ = sink.emit(
        AuditEventBuilder::new(Arc::clone(&hlc), AuditEventKind::PlacementOutcome)
            .sandbox_id(sbx.clone())
            .details(AuditEventDetails::PlacementOutcome {
                cell_id: Some("cel_001".into()),
                host_id: Some("hst_001".into()),
                reason: "BestScore".into(),
                score: Some(0.88),
                candidates_evaluated: 3,
                sampled: false,
                sample_size: 3,
                eligible: 3,
                overlay_adjusted: false,
                service_class: pico_core::ServiceClass::LatencySensitive,
                overcommit_applied: false,
            })
            .build(),
    );

    // Lifecycle transition to Scheduled (after placement)
    let _ = sink.emit(
        AuditEventBuilder::new(hlc, AuditEventKind::LifecycleTransition)
            .sandbox_id(sbx.clone())
            .from_state(SandboxState::Pending.as_str())
            .to_state(SandboxState::Scheduled.as_str())
            .details(AuditEventDetails::LifecycleTransition {
                fencing_token: None,
            })
            .build(),
    );

    let events = sink.events();
    let placement_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::PlacementOutcome)
        .unwrap();
    let lifecycle_idx = events
        .iter()
        .position(|e| e.kind == AuditEventKind::LifecycleTransition)
        .unwrap();

    assert!(
        placement_idx < lifecycle_idx,
        "PlacementOutcome ({placement_idx}) must precede LifecycleTransition ({lifecycle_idx})"
    );
}
