//! Package-mirror policy classes via DNS proxy plus lease model.
//!
//! DSec anecdotes include Go-proxy code pulls, mirror and port scanning,
//! and exfiltration over approved egress. Mirrors are explicit policy
//! classes (PyPI, NPM, Go proxy), not ambient egress. Each class maps to
//! DNS suffix rules plus lease-bound egress, with dynamic per-stage
//! policy updates bound to the current policy epoch.

use crate::dns::{DnsAction, DnsPatternType, DnsPolicy, DnsRule, normalize_dns_name};

/// Package-mirror policy class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MirrorClass {
    Pypi,
    Npm,
    GoProxy,
}

impl MirrorClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pypi => "pypi",
            Self::Npm => "npm",
            Self::GoProxy => "go-proxy",
        }
    }

    /// DNS suffixes owned by this mirror class.
    #[must_use]
    pub fn suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Pypi => &["pypi.org", "files.pythonhosted.org"],
            Self::Npm => &["registry.npmjs.org", "registry.yarnpkg.com"],
            Self::GoProxy => &["proxy.golang.org", "goproxy.io", "index.golang.org"],
        }
    }
}

/// Pipeline stage with its own mirror allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipelineStage {
    Build,
    Install,
    Run,
}

impl PipelineStage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Install => "install",
            Self::Run => "run",
        }
    }
}

/// Per-stage mirror policy bound to a policy epoch and optional lease.
#[derive(Debug, Clone)]
pub struct MirrorPolicy {
    pub sandbox_id: String,
    pub tenant_id: String,
    pub policy_decision_id: String,
    pub policy_epoch: u64,
    pub stage: PipelineStage,
    pub allowed_classes: Vec<MirrorClass>,
    pub lease_id: Option<String>,
}

impl MirrorPolicy {
    /// Returns true when `domain` is allowed for the current stage.
    ///
    /// Matching uses [`normalize_dns_name`], the same normalization as
    /// [`DnsPolicy::evaluate`], so allow checks compose without
    /// case or trailing-dot bypasses.
    #[must_use]
    pub fn allows(&self, domain: &str) -> bool {
        let normalized = normalize_dns_name(domain);
        if normalized.is_empty() {
            return false;
        }
        for class in &self.allowed_classes {
            for suffix in class.suffixes() {
                let normalized_suffix = normalize_dns_name(suffix);
                if normalized == normalized_suffix
                    || normalized.ends_with(&format!(".{normalized_suffix}"))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Mirror access always requires a current lease.
    #[must_use]
    pub fn requires_lease(&self) -> bool {
        !self.allowed_classes.is_empty()
    }

    /// Returns true when this policy carries the lease that authorizes it.
    #[must_use]
    pub fn has_lease(&self) -> bool {
        self.lease_id
            .as_ref()
            .is_some_and(|lease| !lease.trim().is_empty())
    }

    /// Converts this policy to a [`DnsPolicy`] with default deny.
    ///
    /// Patterns use bare suffixes so apex and subdomains match.
    /// Identity fields carry over so DNS audit
    /// attributes mirror decisions to tenant, sandbox, and epoch.
    #[must_use]
    pub fn to_dns_policy(&self) -> DnsPolicy {
        DnsPolicy {
            tenant_id: self.tenant_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            policy_decision_id: self.policy_decision_id.clone(),
            policy_epoch: self.policy_epoch,
            workload_class: Some(format!("mirror-{}", self.stage.as_str())),
            rules: self.dns_rules(),
            default_action: DnsAction::Deny,
        }
    }

    /// Converts this policy to ordered DNS rules (first-wins).
    ///
    /// Patterns use bare suffixes (`pypi.org`) so both the apex and
    /// subdomains match, the same semantics as [`Self::allows`].
    #[must_use]
    pub fn dns_rules(&self) -> Vec<DnsRule> {
        let mut rules = Vec::new();
        for class in &self.allowed_classes {
            for suffix in class.suffixes() {
                rules.push(DnsRule {
                    action: DnsAction::Allow,
                    pattern: (*suffix).to_string(),
                    pattern_type: DnsPatternType::Suffix,
                    record_types: None,
                });
            }
        }
        rules
    }

    /// Validates a stage transition.
    ///
    /// The next policy must carry the same tenant and sandbox, a strictly
    /// greater policy epoch, and its own explicit `allowed_classes`.
    /// Allowances are never inherited: the caller must set the next
    /// stage's classes explicitly (empty for deny).
    pub fn transition_to(&self, next: &MirrorPolicy) -> Result<(), MirrorPolicyError> {
        if next.sandbox_id != self.sandbox_id {
            return Err(MirrorPolicyError::SandboxMismatch);
        }
        if next.tenant_id != self.tenant_id {
            return Err(MirrorPolicyError::TenantMismatch);
        }
        if next.policy_epoch <= self.policy_epoch {
            return Err(MirrorPolicyError::StaleEpoch {
                current: self.policy_epoch,
                next: next.policy_epoch,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorPolicyError {
    #[error("mirror policy sandbox mismatch")]
    SandboxMismatch,
    #[error("mirror policy tenant mismatch")]
    TenantMismatch,
    #[error("stale policy epoch: current {current}, next {next}")]
    StaleEpoch { current: u64, next: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(stage: PipelineStage, classes: Vec<MirrorClass>, epoch: u64) -> MirrorPolicy {
        MirrorPolicy {
            sandbox_id: "sbx".into(),
            tenant_id: "tnt".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: epoch,
            stage,
            allowed_classes: classes,
            lease_id: Some("lse".into()),
        }
    }

    #[test]
    fn class_and_stage_names() {
        assert_eq!(MirrorClass::Pypi.as_str(), "pypi");
        assert_eq!(MirrorClass::Npm.as_str(), "npm");
        assert_eq!(MirrorClass::GoProxy.as_str(), "go-proxy");
        assert_eq!(PipelineStage::Build.as_str(), "build");
        assert_eq!(PipelineStage::Install.as_str(), "install");
        assert_eq!(PipelineStage::Run.as_str(), "run");
    }

    #[test]
    fn pypi_class_allows_only_pypi_suffixes() {
        let p = policy(PipelineStage::Install, vec![MirrorClass::Pypi], 1);
        assert!(p.allows("pypi.org"));
        assert!(p.allows("files.pythonhosted.org"));
        assert!(p.allows("a.files.pythonhosted.org"));
        assert!(!p.allows("proxy.golang.org"));
        assert!(!p.allows("registry.npmjs.org"));
    }

    #[test]
    fn allows_matches_dns_policy_evaluation() {
        let p = policy(
            PipelineStage::Install,
            vec![MirrorClass::Pypi, MirrorClass::GoProxy],
            1,
        );
        let dns = p.to_dns_policy();
        for domain in [
            "pypi.org",
            "PYPI.ORG.",
            "files.pythonhosted.org",
            "proxy.golang.org",
            "a.proxy.golang.org.",
        ] {
            assert!(p.allows(domain), "{domain} should be allowed");
            assert!(
                dns.evaluate(domain, "A").allowed,
                "{domain} should evaluate allowed"
            );
        }
        for domain in ["evil-mirror.example.com", "169.254.169.254", ""] {
            assert!(!p.allows(domain), "{domain} should be denied");
            assert!(
                !dns.evaluate(domain, "A").allowed,
                "{domain} should evaluate denied"
            );
        }
    }

    #[test]
    fn go_proxy_pull_requires_explicit_class() {
        let denied = policy(PipelineStage::Install, vec![MirrorClass::Pypi], 1);
        assert!(!denied.allows("proxy.golang.org"));
        let allowed = policy(
            PipelineStage::Install,
            vec![MirrorClass::Pypi, MirrorClass::GoProxy],
            1,
        );
        assert!(allowed.allows("proxy.golang.org"));
    }

    #[test]
    fn run_stage_denies_mirrors_by_default() {
        let p = policy(PipelineStage::Run, vec![], 2);
        assert!(!p.allows("pypi.org"));
        assert!(!p.allows("proxy.golang.org"));
        assert!(p.dns_rules().is_empty());
        assert!(!p.requires_lease());
    }

    #[test]
    fn mirror_access_requires_lease() {
        let p = policy(PipelineStage::Install, vec![MirrorClass::Pypi], 1);
        assert!(p.requires_lease());
        assert!(p.has_lease());
        let mut without_lease = p.clone();
        without_lease.lease_id = None;
        assert!(!without_lease.has_lease());
    }

    #[test]
    fn mirror_scan_without_lease_class_is_denied() {
        let p = policy(PipelineStage::Build, vec![MirrorClass::Npm], 1);
        // Port or mirror scan targets are not mirror suffixes.
        assert!(!p.allows("evil-mirror.example.com"));
        assert!(!p.allows("169.254.169.254"));
        assert!(p.allows("registry.npmjs.org"));
    }

    #[test]
    fn dynamic_stage_transition_requires_fresh_epoch() {
        let build = policy(PipelineStage::Build, vec![MirrorClass::Pypi], 1);
        let install = policy(PipelineStage::Install, vec![MirrorClass::GoProxy], 2);
        assert!(build.transition_to(&install).is_ok());
        let stale = policy(PipelineStage::Run, vec![], 1);
        assert!(build.transition_to(&stale).is_err());
    }

    #[test]
    fn stage_transition_rejects_tenant_mismatch() {
        let build = policy(PipelineStage::Build, vec![MirrorClass::Pypi], 1);
        let mut other_tenant = policy(PipelineStage::Install, vec![MirrorClass::Pypi], 2);
        other_tenant.tenant_id = "other".into();
        assert_eq!(
            build.transition_to(&other_tenant),
            Err(MirrorPolicyError::TenantMismatch)
        );
    }

    #[test]
    fn dns_rules_use_bare_suffix_convention() {
        let p = policy(
            PipelineStage::Install,
            vec![MirrorClass::Pypi, MirrorClass::GoProxy],
            1,
        );
        let rules = p.dns_rules();
        assert!(rules.iter().any(|r| r.pattern == "pypi.org"));
        assert!(rules.iter().any(|r| r.pattern == "proxy.golang.org"));
        assert!(rules.iter().all(|r| r.action == DnsAction::Allow));
        assert_eq!(p.to_dns_policy().policy_epoch, 1);
    }
}
