//! Package-mirror policy classes via DNS proxy plus lease model.
//!
//! DSec anecdotes include Go-proxy code pulls, mirror and port scanning,
//! and exfiltration over approved egress. Mirrors are explicit policy
//! classes (PyPI, NPM, Go proxy), not ambient egress. Each class maps to
//! DNS suffix rules plus lease-bound egress, with dynamic per-stage
//! policy updates bound to the current policy epoch.

use crate::dns::{DnsAction, DnsPatternType, DnsRule};

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
    #[must_use]
    pub fn allows(&self, domain: &str) -> bool {
        let normalized = domain.trim().trim_end_matches('.').to_lowercase();
        if normalized.is_empty() {
            return false;
        }
        // Run stage denies mirrors by default; build and install allow
        // only their explicitly enabled classes.
        if self.stage == PipelineStage::Run && self.allowed_classes.is_empty() {
            return false;
        }
        for class in &self.allowed_classes {
            for suffix in class.suffixes() {
                if normalized == *suffix || normalized.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            }
        }
        false
    }

    /// Converts this policy to ordered DNS rules (first-wins).
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

    /// Validates a stage transition: epochs must advance and the new
    /// policy must not inherit stale mirror allowances implicitly.
    pub fn transition_to(&self, next: &MirrorPolicy) -> Result<(), MirrorPolicyError> {
        if next.sandbox_id != self.sandbox_id {
            return Err(MirrorPolicyError::SandboxMismatch);
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
    fn pypi_class_allows_only_pypi_suffixes() {
        let p = policy(PipelineStage::Install, vec![MirrorClass::Pypi], 1);
        assert!(p.allows("pypi.org"));
        assert!(p.allows("files.pythonhosted.org"));
        assert!(p.allows("a.files.pythonhosted.org"));
        assert!(!p.allows("proxy.golang.org"));
        assert!(!p.allows("registry.npmjs.org"));
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
    fn dns_rules_cover_every_allowed_suffix() {
        let p = policy(
            PipelineStage::Install,
            vec![MirrorClass::Pypi, MirrorClass::GoProxy],
            1,
        );
        let rules = p.dns_rules();
        assert!(rules.iter().any(|r| r.pattern == "pypi.org"));
        assert!(rules.iter().any(|r| r.pattern == "proxy.golang.org"));
        assert!(rules.iter().all(|r| r.action == DnsAction::Allow));
    }
}
