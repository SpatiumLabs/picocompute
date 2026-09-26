//! Integration tests for the SecretsCoordinator.
//!
//! Validates:
//! - Coordinator creation with mock broker, lease manager, audit sink
//! - Revoke emits CredentialRevoked audit event (destroy cleanup)
//! - Multiple revocations work correctly
//! - Revoke with no lease still emits audit
//! - Revoke after lease manager revoke emits correct combined events

use std::sync::Arc;

use pico_core::policy::PolicyEngine;
use pico_core::secrets::SecretsBroker;
use pico_core::secrets::mock::MockSecretsBroker;
use pico_core::{
    AuditEventDetails, AuditEventKind, Hlc, InMemoryAuditSink, LeaseAction, LeaseManager,
    LeaseScope, PolicyAction, PrincipalId, RevocationReason, SandboxId, TenantId,
};

use pico_host_agent::secrets::SecretsCoordinator;

const DEFAULT_LEASE_TTL_SECS: u64 = 3600;

fn test_hlc() -> Arc<Hlc> {
    Arc::new(Hlc::new())
}

fn test_policy_engine() -> PolicyEngine {
    let engine = PolicyEngine::new();
    engine
        .load_policies("permit(principal, action, resource);\n")
        .unwrap();
    engine
}

fn make_coordinator() -> (
    SecretsCoordinator,
    Arc<InMemoryAuditSink>,
    Arc<LeaseManager>,
) {
    let sink = Arc::new(InMemoryAuditSink::new());
    let broker = Arc::new(MockSecretsBroker::new());
    let lease_mgr = Arc::new(LeaseManager::new());
    let coordinator = SecretsCoordinator::new(
        broker as Arc<dyn SecretsBroker>,
        Arc::clone(&lease_mgr),
        Arc::<InMemoryAuditSink>::clone(&sink) as Arc<dyn pico_core::event_bus::AuditEventSink>,
        test_hlc(),
    );
    (coordinator, sink, lease_mgr)
}

// ──── Revoke: destroy cleanup emits revocation audit ────

#[tokio::test]
async fn revoke_emits_credential_revoked_audit() {
    let (coordinator, sink, lease_mgr) = make_coordinator();
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_revoke_test");
    let sandbox = SandboxId::from_string("sbx_revoke_test");
    let principal = PrincipalId::new("user:revoke");
    let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

    let lease = lease_mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        LeaseScope::unbounded(),
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    coordinator
        .revoke(
            &tenant,
            &sandbox,
            Some(&lease.lease_id),
            RevocationReason::ResourceRemoved,
        )
        .await
        .unwrap();

    let events = sink.events();
    assert_eq!(
        events.len(),
        1,
        "revoke should emit exactly one audit event"
    );
    assert_eq!(events[0].kind, AuditEventKind::CredentialRevoked);
    assert_eq!(
        events[0].sandbox_id.as_ref().map(|s| s.as_str()),
        Some("sbx_revoke_test")
    );
    assert_eq!(
        events[0].tenant_id.as_ref().map(|t| t.as_str()),
        Some("tnt_revoke_test")
    );
    assert_eq!(events[0].outcome.as_deref(), Some("revoked"));
    assert_eq!(events[0].lease_id.as_deref(), Some(lease.lease_id.as_str()));
    assert_eq!(events[0].producer.as_deref(), Some("host-agent"));

    // Verify details
    match &events[0].details {
        Some(AuditEventDetails::CredentialIssuance {
            action,
            outcome,
            reason,
            credential_type,
            lease_id: detail_lease_id,
        }) => {
            assert_eq!(action, "credential_access");
            assert_eq!(outcome, "revoked");
            assert!(reason.is_some());
            assert_eq!(credential_type, "");
            assert_eq!(detail_lease_id.as_deref(), Some(lease.lease_id.as_str()));
        }
        other => panic!("expected CredentialIssuance details, got {other:?}"),
    }
}

#[tokio::test]
async fn revoke_without_lease_emits_audit() {
    let (coordinator, sink, _lease_mgr) = make_coordinator();

    coordinator
        .revoke(
            &TenantId::from_string("tnt_no_lease"),
            &SandboxId::from_string("sbx_no_lease"),
            None,
            RevocationReason::ResourceRemoved,
        )
        .await
        .unwrap();

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, AuditEventKind::CredentialRevoked);
    assert_eq!(events[0].lease_id.as_deref(), Some(""));
}

#[tokio::test]
async fn multiple_revokes_emit_separate_audit_events() {
    let (coordinator, sink, _lease_mgr) = make_coordinator();

    coordinator
        .revoke(
            &TenantId::from_string("tnt_1"),
            &SandboxId::from_string("sbx_1"),
            None,
            RevocationReason::ResourceRemoved,
        )
        .await
        .unwrap();

    coordinator
        .revoke(
            &TenantId::from_string("tnt_2"),
            &SandboxId::from_string("sbx_2"),
            None,
            RevocationReason::AdminAction,
        )
        .await
        .unwrap();

    let events = sink.events();
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(event.kind, AuditEventKind::CredentialRevoked);
    }
    // Distinct sandboxes
    let sbx_1 = &events[0];
    let sbx_2 = &events[1];
    assert_ne!(sbx_1.sandbox_id, sbx_2.sandbox_id);
}

// ──── Coordinator creation and basic operation ────

#[tokio::test]
async fn coordinator_can_be_constructed_with_valid_backends() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let broker = Arc::new(MockSecretsBroker::new());
    let lease_mgr = Arc::new(LeaseManager::new());

    let _coordinator = SecretsCoordinator::new(
        broker as Arc<dyn SecretsBroker>,
        lease_mgr,
        sink as Arc<dyn pico_core::event_bus::AuditEventSink>,
        test_hlc(),
    );
}

// ──── Revoke with lease validation integration ────

#[tokio::test]
async fn revoke_after_lease_manager_revoke_emits_correct_events() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let lease_mgr = Arc::new(LeaseManager::with_audit_sink(
        Arc::<InMemoryAuditSink>::clone(&sink),
        test_hlc(),
    ));
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_lse_rev");
    let sandbox = SandboxId::from_string("sbx_lse_rev");
    let principal = PrincipalId::new("user:grace");
    let decision = engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec);

    let lease = lease_mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // Coordinator revoke should also revoke the lease in the manager.
    let broker = Arc::new(MockSecretsBroker::new());
    let coordinator = SecretsCoordinator::new(
        broker as Arc<dyn SecretsBroker>,
        Arc::clone(&lease_mgr),
        Arc::<InMemoryAuditSink>::clone(&sink) as Arc<dyn pico_core::event_bus::AuditEventSink>,
        test_hlc(),
    );

    coordinator
        .revoke(
            &tenant,
            &sandbox,
            Some(&lease.lease_id),
            RevocationReason::ResourceRemoved,
        )
        .await
        .unwrap();

    // Verify we have LeaseIssued, LeaseRevoked (from coordinator's call to lease mgr),
    // and CredentialRevoked (from coordinator)
    let all_events = sink.events();
    let revoked_creds = sink.events_by_kind(AuditEventKind::CredentialRevoked);
    let lease_revoked = sink.events_by_kind(AuditEventKind::LeaseRevoked);

    assert!(
        !revoked_creds.is_empty(),
        "coordinator revoke should emit CredentialRevoked"
    );
    assert!(
        !lease_revoked.is_empty(),
        "coordinator revoke should revoke lease and emit LeaseRevoked"
    );
    assert_eq!(all_events.len(), 3, "expected 3 events total");
}
