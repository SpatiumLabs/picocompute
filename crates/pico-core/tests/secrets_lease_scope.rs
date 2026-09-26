//! Integration tests for lease scope validation of credential types.
//!
//! Validates:
//! - LeaseAction::CredentialAccess validates correctly
//! - Credential type scope filtering works (allowed vs. denied)
//! - Unbounded scope allows any credential type
//! - Multiple credential types in a single scope

use pico_core::{
    LeaseAction, LeaseManager, LeaseScope, LeaseValidationError, PolicyDecision, PrincipalId,
    RevocationReason, SandboxId, TenantId,
};

use pico_core::policy::PolicyEngine;

const DEFAULT_LEASE_TTL_SECS: u64 = 3600;

fn test_policy_engine() -> PolicyEngine {
    let engine = PolicyEngine::new();
    engine
        .load_policies(
            r#"
permit(principal, action, resource);
"#,
        )
        .unwrap();
    engine
}

fn allow_decision(engine: &PolicyEngine) -> PolicyDecision {
    let principal = PrincipalId::new("user:test");
    let tenant = TenantId::generate();
    engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec)
}

// ──── CredentialAccess lease validates correctly ────

#[test]
fn credential_access_lease_validates_for_matching_scope() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec!["aws".into(), "gcp".into()],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // Validate with allowed credential type
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );
    assert!(result.is_ok(), "aws should be allowed in scope: {result:?}");
}

#[test]
fn credential_access_lease_rejects_wrong_action() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec!["aws".into()],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // Validate with wrong action (Exec instead of CredentialAccess)
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::Exec,
        &LeaseScope::unbounded(),
        decision.policy_epoch,
    );
    assert!(
        matches!(result, Err(LeaseValidationError::WrongAction { .. })),
        "should reject wrong action"
    );
}

// ──── Credential type scope filtering ────

#[test]
fn credential_type_scope_filters_allowed_types() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec!["aws".into()],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // "aws" is in scope - allowed
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );
    assert!(result.is_ok(), "aws should pass scope check");

    // "gcp" is NOT in scope - rejected
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["gcp".into()],
        },
        decision.policy_epoch,
    );
    assert!(
        matches!(result, Err(LeaseValidationError::ScopeExceeded { .. })),
        "gcp should be rejected: {result:?}"
    );
}

#[test]
fn unbounded_scope_allows_any_credential_type() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        LeaseScope::unbounded(),
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // With unbounded scope, any credential type should be allowed
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["any_arbitrary_type".into()],
        },
        decision.policy_epoch,
    );
    assert!(
        result.is_ok(),
        "unbounded scope should allow any credential type"
    );
}

#[test]
fn multiple_credential_types_in_scope_work() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec!["aws".into(), "gcp".into(), "azure".into()],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // Each allowed type should pass
    for ct in &["aws", "gcp", "azure"] {
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![(*ct).to_string()],
            },
            decision.policy_epoch,
        );
        assert!(result.is_ok(), "{ct} should be allowed");
    }

    // Multiple at once
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into(), "gcp".into()],
        },
        decision.policy_epoch,
    );
    assert!(result.is_ok(), "multiple types should be allowed");

    // But if one is disallowed, the whole request fails
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into(), "datadog".into()],
        },
        decision.policy_epoch,
    );
    assert!(
        matches!(result, Err(LeaseValidationError::ScopeExceeded { .. })),
        "mixed request with disallowed type should be rejected"
    );
}

// ──── Empty credential_types in lease scope means no restriction ────

#[test]
fn empty_credential_types_scope_allows_any() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:alice");

    let scope = LeaseScope {
        ports: vec![],
        paths: vec![],
        egress_cidrs: vec![],
        credential_types: vec![],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // An empty credential_types vec means no type restriction is enforced -
    // any credential type request passes the scope check.
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );

    assert!(
        result.is_ok(),
        "empty credential_types should allow all credentials"
    );
}

// ──── Lease with CredentialAccess validates with full scope checks ────

#[test]
fn credential_access_scope_validates_correctly_against_lease() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();
    let decision = allow_decision(&engine);
    let tenant = TenantId::generate();
    let sandbox = SandboxId::generate();
    let principal = PrincipalId::new("user:bob");

    let lease_scope = LeaseScope {
        ports: vec![8080, 443],
        paths: vec!["/workspace/".into()],
        egress_cidrs: vec!["10.0.0.0/8".into()],
        credential_types: vec!["aws".into(), "gcp".into()],
    };

    let lease = mgr.issue(
        tenant.clone(),
        principal,
        sandbox.clone(),
        LeaseAction::CredentialAccess,
        lease_scope,
        &decision,
        DEFAULT_LEASE_TTL_SECS,
    );

    // All fields match and credential type is in scope
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![8080],
            paths: vec!["/workspace/output.txt".into()],
            egress_cidrs: vec!["10.0.0.0/8".into()],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );
    assert!(result.is_ok());

    // All match except credential type is out of scope
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![8080],
            paths: vec!["/workspace/output.txt".into()],
            egress_cidrs: vec!["10.0.0.0/8".into()],
            credential_types: vec!["azure".into()],
        },
        decision.policy_epoch,
    );
    assert!(
        matches!(result, Err(LeaseValidationError::ScopeExceeded { .. })),
        "credential type azure should be out of scope"
    );
}

// ──── Lease validation rejection: revoked ────

#[test]
fn revoked_lease_is_rejected_during_credential_access() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_rev_int");
    let sandbox = SandboxId::from_string("sbx_rev_int");
    let principal = PrincipalId::new("user:carol");
    let decision = engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec);

    let lease = mgr.issue(
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

    mgr.revoke(&lease.lease_id, RevocationReason::AdminAction)
        .unwrap();

    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );

    assert!(
        matches!(result, Err(LeaseValidationError::Revoked { .. })),
        "revoked lease should be rejected"
    );
}

// ──── Lease validation rejection: expired ────

#[test]
fn expired_lease_ttl_0_is_rejected_during_credential_access() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_exp_int");
    let sandbox = SandboxId::from_string("sbx_exp_int");
    let principal = PrincipalId::new("user:dave");
    let decision = engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec);

    let lease = mgr.issue(
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
        0,
    );

    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );

    assert!(
        matches!(result, Err(LeaseValidationError::Expired { .. })),
        "expired lease (TTL 0) should be rejected: {result:?}"
    );
}

// ──── Lease validation rejection: wrong tenant ────

#[test]
fn wrong_tenant_lease_is_rejected() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_correct");
    let wrong_tenant = TenantId::from_string("tnt_wrong");
    let sandbox = SandboxId::from_string("sbx_wt");
    let principal = PrincipalId::new("user:eve");
    let decision = engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec);

    let lease = mgr.issue(
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

    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &wrong_tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        decision.policy_epoch,
    );

    assert!(
        matches!(result, Err(LeaseValidationError::WrongTenant { .. })),
        "wrong tenant should be rejected"
    );
}

// ──── Lease validation rejection: stale policy epoch ────

#[test]
fn stale_policy_epoch_is_rejected() {
    let mgr = LeaseManager::new();
    let engine = test_policy_engine();

    let tenant = TenantId::from_string("tnt_stale");
    let sandbox = SandboxId::from_string("sbx_stale");
    let principal = PrincipalId::new("user:frank");
    let decision = engine.evaluate(&principal, &tenant, pico_core::policy::PolicyAction::Exec);

    let lease = mgr.issue(
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

    let newer_epoch = decision.policy_epoch + 10;
    let result = mgr.validate_with_scope(
        &lease.lease_id,
        &sandbox,
        &tenant,
        LeaseAction::CredentialAccess,
        &LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        },
        newer_epoch,
    );

    assert!(
        matches!(result, Err(LeaseValidationError::StalePolicyEpoch { .. })),
        "stale policy epoch should be rejected"
    );
}
