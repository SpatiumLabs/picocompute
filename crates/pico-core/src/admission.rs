//! Admission: policy + quota + signed access lease.
//!
//! One interface for control-plane issuance. Edge and host enforce the
//! resulting lease artifact through [`crate::LeaseAuthority`].

use std::sync::Arc;

use crate::error::SandboxError;
use crate::identity::{PrincipalId, SandboxId, TenantId};
use crate::lease_token::{LeaseAuthority, encode_lease_blob};
use crate::leases::{AccessLease, DEFAULT_LEASE_TTL_SECS, LeaseAction, LeaseManager, LeaseScope};
use crate::policy::{PolicyEngine, PolicyOutcome};
use crate::quota::QuotaEngine;

/// Request to admit a principal for a data-plane action.
pub struct AdmitRequest {
    /// Tenant that owns the sandbox.
    pub tenant_id: TenantId,
    /// Authenticated caller.
    pub principal: PrincipalId,
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Data-plane action to authorize.
    pub action: LeaseAction,
    /// Bounds on the issued lease.
    pub scope: LeaseScope,
    /// Lease lifetime in seconds. `None` uses [`DEFAULT_LEASE_TTL_SECS`].
    pub ttl_secs: Option<u64>,
    /// When set, quota is checked before issuance (sandbox create).
    pub quota: Option<QuotaAdmit>,
}

/// Quota inputs for create admission.
pub struct QuotaAdmit {
    /// Requested vCPUs.
    pub vcpus: u32,
    /// Requested memory in MiB.
    pub memory_mb: u64,
}

/// Control-plane admission: evaluate policy, check quota, issue a signed lease.
pub struct Admission {
    policy: Arc<PolicyEngine>,
    quota: Arc<QuotaEngine>,
    leases: LeaseManager,
    authority: LeaseAuthority,
}

impl Admission {
    /// Creates an admission module.
    pub fn new(
        policy: Arc<PolicyEngine>,
        quota: Arc<QuotaEngine>,
        authority: LeaseAuthority,
    ) -> Self {
        Self {
            policy,
            quota,
            leases: LeaseManager::new(),
            authority,
        }
    }

    /// Returns the lease authority used to sign and verify.
    pub fn authority(&self) -> &LeaseAuthority {
        &self.authority
    }

    /// Returns the current policy epoch.
    pub fn policy_epoch(&self) -> u64 {
        self.policy.get_epoch()
    }

    /// Policy engine used at admission.
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Quota engine used at admission.
    pub fn quota(&self) -> &QuotaEngine {
        &self.quota
    }

    /// Evaluates policy (and quota when requested), then issues a signed lease.
    pub fn admit(&self, req: AdmitRequest) -> Result<AccessLease, SandboxError> {
        let policy_action =
            req.action
                .to_policy_action()
                .ok_or_else(|| SandboxError::PolicyDenied {
                    reason: format!(
                        "action {} cannot be admitted as a lease",
                        req.action.as_str()
                    ),
                })?;

        let decision = self
            .policy
            .evaluate(&req.principal, &req.tenant_id, policy_action);
        match &decision.outcome {
            PolicyOutcome::Allow => {}
            PolicyOutcome::Deny { reason } => {
                return Err(SandboxError::PolicyDenied {
                    reason: reason.clone(),
                });
            }
        }

        if let Some(quota) = &req.quota {
            let quota_decision =
                self.quota
                    .check_create(&req.tenant_id, quota.vcpus, quota.memory_mb);
            if !quota_decision.allowed {
                return Err(SandboxError::QuotaExceeded {
                    resource: quota_decision.resource.clone().unwrap_or_default(),
                    limit: quota_decision.limit,
                    current: quota_decision.current,
                });
            }
        }

        let ttl = req.ttl_secs.unwrap_or(DEFAULT_LEASE_TTL_SECS);
        let mut lease = self.leases.issue(
            req.tenant_id,
            req.principal,
            req.sandbox_id,
            req.action,
            req.scope,
            &decision,
            ttl,
        );
        self.authority
            .sign(&mut lease)
            .map_err(|e| SandboxError::Other(format!("failed to sign lease: {e}")))?;
        Ok(lease)
    }

    /// Encodes a signed lease as a transferable blob.
    pub fn encode(&self, lease: &AccessLease) -> Result<String, SandboxError> {
        encode_lease_blob(lease)
            .map_err(|e| SandboxError::Other(format!("failed to encode lease: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease_token::EnforceContext;
    use crate::policy::DEFAULT_PERMIT_POLICY;
    use crate::quota::QuotaLimits;

    fn admission_with_policy(policy_text: &str) -> Admission {
        let policy = Arc::new(PolicyEngine::new());
        policy.load_policies(policy_text).unwrap();
        Admission::new(
            policy,
            Arc::new(QuotaEngine::new()),
            LeaseAuthority::generate(),
        )
    }

    fn admit_exec(admission: &Admission) -> Result<AccessLease, SandboxError> {
        admission.admit(AdmitRequest {
            tenant_id: TenantId::generate(),
            principal: PrincipalId::new("user:alice"),
            sandbox_id: SandboxId::generate(),
            action: LeaseAction::Exec,
            scope: LeaseScope::unbounded(),
            ttl_secs: Some(300),
            quota: None,
        })
    }

    #[test]
    fn permit_issues_signed_lease_enforcers_accept() {
        let admission = admission_with_policy(DEFAULT_PERMIT_POLICY);
        let lease = admit_exec(&admission).unwrap();
        assert!(lease.signature.is_some());

        let blob = admission.encode(&lease).unwrap();
        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::Exec,
            scope: &LeaseScope::unbounded(),
            policy_epoch: lease.policy_epoch,
        };
        assert!(admission.authority().enforce_blob(&blob, &ctx).is_ok());
    }

    #[test]
    fn deny_does_not_issue_lease() {
        let admission = admission_with_policy(
            r#"
forbid(
    principal,
    action == PicoCompute::Action::"Exec",
    resource
) when { true };
"#,
        );
        let err = admit_exec(&admission).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyDenied { .. }));
    }

    #[test]
    fn quota_blocks_create_admission() {
        let policy = Arc::new(PolicyEngine::new());
        policy.load_policies(DEFAULT_PERMIT_POLICY).unwrap();
        let quota = Arc::new(QuotaEngine::new());
        let tenant = TenantId::generate();
        quota.set_limits(
            tenant.clone(),
            QuotaLimits {
                max_sandboxes: 0,
                max_vcpus: 0,
                max_memory_mb: 0,
                ..Default::default()
            },
        );
        let admission = Admission::new(policy, quota, LeaseAuthority::generate());
        let err = admission
            .admit(AdmitRequest {
                tenant_id: tenant,
                principal: PrincipalId::new("user:alice"),
                sandbox_id: SandboxId::generate(),
                action: LeaseAction::Exec,
                scope: LeaseScope::unbounded(),
                ttl_secs: None,
                quota: Some(QuotaAdmit {
                    vcpus: 1,
                    memory_mb: 128,
                }),
            })
            .unwrap_err();
        assert!(matches!(err, SandboxError::QuotaExceeded { .. }));
    }

    #[test]
    fn policy_action_maps_to_lease_action() {
        assert_eq!(
            crate::policy::PolicyAction::FileAccess.to_lease_action(),
            Some(LeaseAction::FileTransfer)
        );
        assert!(
            crate::policy::PolicyAction::Create
                .to_lease_action()
                .is_none()
        );
        assert_eq!(
            LeaseAction::PortForward.to_policy_action(),
            Some(crate::policy::PolicyAction::PortForward)
        );
    }
}
