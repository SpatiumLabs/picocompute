//! Cedar-backed policy evaluation engine.
//!
//! Evaluates authorization requests against a pre-loaded policy set.
//! Supports allow and deny decisions with policy epoch tracking
//! for staleness detection.

use parking_lot::RwLock;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};

use crate::identity::{PolicyDecisionId, PrincipalId, TenantId};

/// Actions that can be authorized by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Create,
    Exec,
    FileAccess,
    Stop,
    Destroy,
    Suspend,
    Resume,
    PortForward,
    CredentialAccess,
    EgressException,
    SnapshotOperation,
}

impl PolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Exec => "Exec",
            Self::FileAccess => "FileAccess",
            Self::Stop => "Stop",
            Self::Destroy => "Destroy",
            Self::Suspend => "Suspend",
            Self::Resume => "Resume",
            Self::PortForward => "PortForward",
            Self::CredentialAccess => "CredentialAccess",
            Self::EgressException => "EgressException",
            Self::SnapshotOperation => "SnapshotOperation",
        }
    }

    /// Maps a policy action onto the data-plane lease it issues, if any.
    ///
    /// Lifecycle actions (create/stop/suspend/resume/destroy) are admitted at
    /// the API and do not produce a lease.
    pub fn to_lease_action(self) -> Option<crate::leases::LeaseAction> {
        match self {
            Self::Exec => Some(crate::leases::LeaseAction::Exec),
            Self::FileAccess => Some(crate::leases::LeaseAction::FileTransfer),
            Self::PortForward => Some(crate::leases::LeaseAction::PortForward),
            Self::CredentialAccess => Some(crate::leases::LeaseAction::CredentialAccess),
            Self::EgressException => Some(crate::leases::LeaseAction::EgressException),
            Self::SnapshotOperation => Some(crate::leases::LeaseAction::SnapshotOperation),
            Self::Create | Self::Stop | Self::Destroy | Self::Suspend | Self::Resume => None,
        }
    }
}

/// Default Cedar policy used when no tenant policy is configured.
pub const DEFAULT_PERMIT_POLICY: &str = r#"
permit(
    principal,
    action,
    resource
);
"#;

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    Allow,
    Deny { reason: String },
}

/// Result of a policy engine evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision_id: PolicyDecisionId,
    pub outcome: PolicyOutcome,
    pub policy_epoch: u64,
}

/// Cedar-backed policy engine.
///
/// Entity type names are constructed once at initialization to avoid
/// repeated string parsing and allocation on every evaluation.
pub struct PolicyEngine {
    authorizer: Authorizer,
    policies: RwLock<PolicySet>,
    policy_epoch: AtomicU64,
    principal_type: EntityTypeName,
    tenant_type: EntityTypeName,
    action_type: EntityTypeName,
}

impl PolicyEngine {
    /// Create a new policy engine with an empty policy set.
    pub fn new() -> Self {
        Self {
            authorizer: Authorizer::new(),
            policies: RwLock::new(PolicySet::new()),
            policy_epoch: AtomicU64::new(0),
            principal_type: EntityTypeName::from_str("PicoCompute::Principal")
                .expect("invalid hardcoded entity type name"),
            tenant_type: EntityTypeName::from_str("PicoCompute::Tenant")
                .expect("invalid hardcoded entity type name"),
            action_type: EntityTypeName::from_str("PicoCompute::Action")
                .expect("invalid hardcoded entity type name"),
        }
    }

    /// Load policies from a Cedar policy string.
    /// Parses the policies and replaces the current policy set.
    /// Increments the policy epoch on successful load.
    pub fn load_policies(&self, policy_text: &str) -> Result<(), String> {
        let new_policies = PolicySet::from_str(policy_text)
            .map_err(|e| format!("failed to parse policies: {e}"))?;
        *self.policies.write() = new_policies;
        self.policy_epoch.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Get the current policy epoch.
    pub fn get_epoch(&self) -> u64 {
        self.policy_epoch.load(Ordering::Acquire)
    }

    /// Evaluate an authorization request.
    ///
    /// Builds Cedar entities from the principal and tenant context,
    /// then evaluates against the loaded policy set.
    pub fn evaluate(
        &self,
        principal_id: &PrincipalId,
        tenant_id: &TenantId,
        action: PolicyAction,
    ) -> PolicyDecision {
        let decision_id = PolicyDecisionId::generate();
        let epoch = self.get_epoch();

        let principal_uid = EntityUid::from_type_name_and_id(
            self.principal_type.clone(),
            EntityId::new(principal_id.as_str()),
        );
        let tenant_uid = EntityUid::from_type_name_and_id(
            self.tenant_type.clone(),
            EntityId::new(tenant_id.as_str()),
        );
        let action_uid = EntityUid::from_type_name_and_id(
            self.action_type.clone(),
            EntityId::new(action.as_str()),
        );

        let principal = Entity::new(
            principal_uid.clone(),
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        )
        .expect("entity construction with empty attrs should not fail");
        let tenant = Entity::new(
            tenant_uid.clone(),
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        )
        .expect("entity construction with empty attrs should not fail");
        let action_entity = Entity::new(
            action_uid.clone(),
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        )
        .expect("entity construction with empty attrs should not fail");

        let entities = Entities::from_entities([principal, tenant, action_entity], None)
            .expect("entity set with empty schema should not fail");

        let request = Request::new(
            principal_uid,
            action_uid,
            tenant_uid,
            Context::empty(),
            None,
        )
        .expect("request with valid entity UIDs should not fail");

        let policies = self.policies.read();
        let answer = self
            .authorizer
            .is_authorized(&request, &policies, &entities);

        let outcome = match answer.decision() {
            Decision::Allow => PolicyOutcome::Allow,
            Decision::Deny => PolicyOutcome::Deny {
                reason: format!(
                    "policy denied: {}",
                    answer
                        .diagnostics()
                        .errors()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            },
        };

        PolicyDecision {
            decision_id,
            outcome,
            policy_epoch: epoch,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_allow_policy() -> &'static str {
        r#"
permit(
    principal,
    action,
    resource
);
"#
    }

    fn create_only_policy() -> &'static str {
        r#"
permit(
    principal,
    action == PicoCompute::Action::"Create",
    resource
);
"#
    }

    #[test]
    fn suspend_and_resume_are_lifecycle_policy_actions() {
        assert_eq!(PolicyAction::Suspend.as_str(), "Suspend");
        assert_eq!(PolicyAction::Resume.as_str(), "Resume");
        assert_eq!(PolicyAction::Suspend.to_lease_action(), None);
        assert_eq!(PolicyAction::Resume.to_lease_action(), None);
    }

    #[test]
    fn policy_engine_allow_when_permitted() {
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let principal = PrincipalId::new("test-principal");
        let tenant = TenantId::generate();

        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Create);
        assert_eq!(decision.outcome, PolicyOutcome::Allow);
        assert_eq!(decision.policy_epoch, 1);
    }

    #[test]
    fn policy_engine_deny_when_not_permitted() {
        let engine = PolicyEngine::new();
        engine.load_policies(create_only_policy()).unwrap();

        let principal = PrincipalId::new("test-principal");
        let tenant = TenantId::generate();

        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);
        assert!(matches!(decision.outcome, PolicyOutcome::Deny { .. }));
    }

    #[test]
    fn policy_epoch_increments_on_load() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.get_epoch(), 0);

        engine.load_policies(default_allow_policy()).unwrap();
        assert_eq!(engine.get_epoch(), 1);

        engine.load_policies(create_only_policy()).unwrap();
        assert_eq!(engine.get_epoch(), 2);
    }

    #[test]
    fn policy_engine_rejects_invalid_policy() {
        let engine = PolicyEngine::new();
        let result = engine.load_policies("not valid cedar");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse"));
    }

    #[test]
    fn decision_id_is_unique() {
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let principal = PrincipalId::new("test-principal");
        let tenant = TenantId::generate();

        let d1 = engine.evaluate(&principal, &tenant, PolicyAction::Create);
        let d2 = engine.evaluate(&principal, &tenant, PolicyAction::Create);
        assert_ne!(d1.decision_id, d2.decision_id);
    }
}
