//! Credential lifecycle policy for snapshot capture, restore, and fork.
//!
//! Implements: Keep runtime credentials out of checkpoints.
//! Defines credential exclusion from snapshots, refresh behavior after
//! restore, and fork inheritance policy so that runtime secrets never
//! leak into durable snapshot artifacts.

use serde::{Deserialize, Serialize};

use crate::mount::MountContract;

/// Policy controlling credential behavior during snapshot and restore.
///
/// Every snapshot metadata record carries this policy to ensure
/// consistent credential handling across capture, restore, and fork.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSnapshotPolicy {
    /// Whether to exclude credentials from snapshots.
    /// Always `true` in production; `false` only for development.
    pub exclude_from_snapshot: bool,

    /// Whether to refresh credentials after restore.
    /// When `true`, the restore path contacts the secrets broker
    /// to replace any credentials that were excluded at capture time.
    pub refresh_after_restore: bool,

    /// Controls credential inheritance for forked sandboxes.
    /// See [`ForkCredentialPolicy`] for the available modes.
    #[serde(default)]
    pub fork_credential_policy: ForkCredentialPolicy,

    /// Credential types that are permitted to be refreshed.
    /// When empty, all credential types are permitted.
    #[serde(default)]
    pub allowed_credential_types: Vec<String>,

    /// Require a valid access lease before refreshing credentials.
    /// Default: `true` in production.
    pub require_lease_for_refresh: bool,
}

impl Default for CredentialSnapshotPolicy {
    fn default() -> Self {
        Self {
            exclude_from_snapshot: true,
            refresh_after_restore: true,
            fork_credential_policy: ForkCredentialPolicy::None,
            allowed_credential_types: Vec::new(),
            require_lease_for_refresh: true,
        }
    }
}

impl CredentialSnapshotPolicy {
    /// Production-ready policy: exclude, refresh, no fork inheritance.
    pub fn production() -> Self {
        Self::default()
    }

    /// Development policy: still excludes but allows full fork inheritance.
    pub fn development() -> Self {
        Self {
            fork_credential_policy: ForkCredentialPolicy::InheritAll,
            ..Self::default()
        }
    }

    /// Returns true if a credential type is allowed for refresh.
    pub fn allows_credential_type(&self, credential_type: &str) -> bool {
        self.allowed_credential_types.is_empty()
            || self
                .allowed_credential_types
                .iter()
                .any(|ct| ct == credential_type)
    }

    /// Returns true if the given mount contract enforces credential exclusion.
    pub fn validates_mount_contract(&self, contract: &MountContract) -> bool {
        if !self.exclude_from_snapshot {
            return true;
        }
        let excluded = contract.snapshot_excluded_classes();
        excluded.iter().any(|m| m == "secret")
    }

    /// Verifies that an excluded_mounts list includes the secret class.
    pub fn secret_class_is_excluded(&self, excluded_mounts: &[String]) -> bool {
        if !self.exclude_from_snapshot {
            return true;
        }
        excluded_mounts.iter().any(|m| m == "secret")
    }
}

/// Outcome of a credential refresh operation after restore or fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRefreshOutcome {
    /// Credentials were successfully refreshed.
    Refreshed {
        /// Number of credentials refreshed.
        credential_count: usize,
        /// Lease ID that authorized the refresh, if any.
        lease_id: Option<String>,
    },
    /// Credential refresh was denied by policy or lease scope.
    Denied {
        /// Human-readable reason for denial.
        reason: String,
    },
    /// Credential refresh was skipped by policy.
    Skipped {
        /// Reason why refresh was skipped.
        reason: String,
    },
    /// Credential refresh failed due to broker unavailability.
    Unavailable {
        /// Human-readable reason for unavailability.
        reason: String,
    },
}

impl CredentialRefreshOutcome {
    /// Returns true if credentials were successfully refreshed.
    pub fn is_refreshed(&self) -> bool {
        matches!(self, Self::Refreshed { .. })
    }

    /// Returns true if the outcome is terminal (denied or unavailable).
    pub fn is_terminal_failure(&self) -> bool {
        matches!(self, Self::Denied { .. } | Self::Unavailable { .. })
    }

    /// Returns a human-readable description of the outcome.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Refreshed { .. } => "refreshed",
            Self::Denied { .. } => "denied",
            Self::Skipped { .. } => "skipped",
            Self::Unavailable { .. } => "unavailable",
        }
    }
}

/// Fork credential inheritance policy.
///
/// Controls whether a forked sandbox receives the parent's credentials
/// or must acquire its own.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForkCredentialPolicy {
    /// Forked child does not inherit credentials.
    /// The child must request its own credentials through the broker.
    #[default]
    None,
    /// Forked child inherits all parent credentials.
    InheritAll,
    /// Forked child inherits only explicitly permitted credential types.
    InheritPermitted,
    /// Forked child inherits credentials from a specific snapshot.
    InheritFromSnapshot,
}

impl ForkCredentialPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InheritAll => "inherit_all",
            Self::InheritPermitted => "inherit_permitted",
            Self::InheritFromSnapshot => "inherit_from_snapshot",
        }
    }
}

impl std::fmt::Display for ForkCredentialPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of validating a snapshot for credential exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialExclusionResult {
    /// Whether credential exclusion was enforced.
    pub enforced: bool,
    /// Mount classes excluded from the snapshot.
    pub excluded_mount_classes: Vec<String>,
    /// Whether the secret class was explicitly excluded.
    pub secret_class_excluded: bool,
    /// Any violation details (only present when exclusion failed).
    pub violations: Vec<String>,
}

impl CredentialExclusionResult {
    /// Creates a successful exclusion result.
    pub fn success(excluded_mount_classes: Vec<String>) -> Self {
        let secret_class_excluded = excluded_mount_classes.iter().any(|m| m == "secret");
        Self {
            enforced: true,
            excluded_mount_classes,
            secret_class_excluded,
            violations: Vec::new(),
        }
    }

    /// Creates a failed exclusion result with violations.
    pub fn failure(violations: Vec<String>) -> Self {
        Self {
            enforced: false,
            excluded_mount_classes: Vec::new(),
            secret_class_excluded: false,
            violations,
        }
    }

    /// Returns true if the snapshot passes credential exclusion validation.
    pub fn is_valid(&self) -> bool {
        self.enforced && self.violations.is_empty() && self.secret_class_excluded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::{MountClass, MountContract, MountEntry, PathLifecycle};

    #[test]
    fn production_policy_excludes_credentials() {
        let policy = CredentialSnapshotPolicy::production();
        assert!(policy.exclude_from_snapshot);
        assert!(policy.refresh_after_restore);
        assert_eq!(policy.fork_credential_policy, ForkCredentialPolicy::None);
        assert!(policy.require_lease_for_refresh);
    }

    #[test]
    fn development_policy_allows_fork_inheritance() {
        let policy = CredentialSnapshotPolicy::development();
        assert!(policy.exclude_from_snapshot);
        assert!(policy.refresh_after_restore);
        assert_eq!(
            policy.fork_credential_policy,
            ForkCredentialPolicy::InheritAll
        );
    }

    #[test]
    fn allows_credential_type_with_empty_list() {
        let policy = CredentialSnapshotPolicy::default();
        assert!(policy.allows_credential_type("aws"));
        assert!(policy.allows_credential_type("gcp"));
        assert!(policy.allows_credential_type("any_arbitrary_type"));
    }

    #[test]
    fn allows_credential_type_with_specific_list() {
        let policy = CredentialSnapshotPolicy {
            allowed_credential_types: vec!["aws".into(), "gcp".into()],
            ..Default::default()
        };
        assert!(policy.allows_credential_type("aws"));
        assert!(policy.allows_credential_type("gcp"));
        assert!(!policy.allows_credential_type("azure"));
    }

    #[test]
    fn validates_mount_contract_with_secret_exclusion() {
        let policy = CredentialSnapshotPolicy::default();
        let contract = MountContract {
            version: "1".into(),
            mounts: vec![
                MountEntry {
                    path: "/workspace".into(),
                    class: MountClass::Workspace,
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                },
                MountEntry {
                    path: "/run/pico/secrets".into(),
                    class: MountClass::Secret,
                    writable: false,
                    lifecycle: PathLifecycle::Ephemeral,
                },
            ],
        };
        assert!(policy.validates_mount_contract(&contract));
    }

    #[test]
    fn validates_mount_contract_without_secret_exclusion() {
        let policy = CredentialSnapshotPolicy::default();
        let contract = MountContract {
            version: "1".into(),
            mounts: vec![MountEntry {
                path: "/workspace".into(),
                class: MountClass::Workspace,
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            }],
        };
        assert!(!policy.validates_mount_contract(&contract));
    }

    #[test]
    fn validates_mount_contract_when_exclude_is_false() {
        let policy = CredentialSnapshotPolicy {
            exclude_from_snapshot: false,
            ..Default::default()
        };
        let contract = MountContract {
            version: "1".into(),
            mounts: vec![],
        };
        assert!(policy.validates_mount_contract(&contract));
    }

    #[test]
    fn secret_class_is_excluded_detects_secret() {
        let policy = CredentialSnapshotPolicy::default();
        assert!(policy.secret_class_is_excluded(&["secret".into(), "runtime_tmp".into()]));
        assert!(!policy.secret_class_is_excluded(&["workspace".into()]));
        assert!(!policy.secret_class_is_excluded(&[]));
    }

    #[test]
    fn secret_class_is_excluded_when_exclude_false() {
        let policy = CredentialSnapshotPolicy {
            exclude_from_snapshot: false,
            ..Default::default()
        };
        assert!(policy.secret_class_is_excluded(&[]));
    }

    #[test]
    fn credential_exclusion_result_success() {
        let result =
            CredentialExclusionResult::success(vec!["secret".into(), "runtime_tmp".into()]);
        assert!(result.is_valid());
        assert!(result.enforced);
        assert!(result.secret_class_excluded);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn credential_exclusion_result_failure() {
        let result =
            CredentialExclusionResult::failure(vec!["secret mount class not excluded".into()]);
        assert!(!result.is_valid());
        assert!(!result.enforced);
        assert!(!result.secret_class_excluded);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn credential_exclusion_result_success_without_secret() {
        let result = CredentialExclusionResult::success(vec!["runtime_tmp".into()]);
        assert!(!result.is_valid());
        assert!(result.enforced);
        assert!(!result.secret_class_excluded);
    }

    #[test]
    fn credential_refresh_outcome_refreshed() {
        let outcome = CredentialRefreshOutcome::Refreshed {
            credential_count: 3,
            lease_id: Some("lse_abc".into()),
        };
        assert!(outcome.is_refreshed());
        assert!(!outcome.is_terminal_failure());
        assert_eq!(outcome.as_str(), "refreshed");
    }

    #[test]
    fn credential_refresh_outcome_denied() {
        let outcome = CredentialRefreshOutcome::Denied {
            reason: "no valid lease".into(),
        };
        assert!(!outcome.is_refreshed());
        assert!(outcome.is_terminal_failure());
        assert_eq!(outcome.as_str(), "denied");
    }

    #[test]
    fn credential_refresh_outcome_skipped() {
        let outcome = CredentialRefreshOutcome::Skipped {
            reason: "refresh disabled by policy".into(),
        };
        assert!(!outcome.is_refreshed());
        assert!(!outcome.is_terminal_failure());
        assert_eq!(outcome.as_str(), "skipped");
    }

    #[test]
    fn credential_refresh_outcome_unavailable() {
        let outcome = CredentialRefreshOutcome::Unavailable {
            reason: "broker unreachable".into(),
        };
        assert!(!outcome.is_refreshed());
        assert!(outcome.is_terminal_failure());
        assert_eq!(outcome.as_str(), "unavailable");
    }

    #[test]
    fn fork_credential_policy_as_str() {
        assert_eq!(ForkCredentialPolicy::None.as_str(), "none");
        assert_eq!(ForkCredentialPolicy::InheritAll.as_str(), "inherit_all");
        assert_eq!(
            ForkCredentialPolicy::InheritPermitted.as_str(),
            "inherit_permitted"
        );
        assert_eq!(
            ForkCredentialPolicy::InheritFromSnapshot.as_str(),
            "inherit_from_snapshot"
        );
    }

    #[test]
    fn fork_credential_policy_display() {
        assert_eq!(format!("{}", ForkCredentialPolicy::None), "none");
    }

    #[test]
    fn credential_snapshot_policy_serde_roundtrip() {
        let policy = CredentialSnapshotPolicy {
            exclude_from_snapshot: true,
            refresh_after_restore: true,
            fork_credential_policy: ForkCredentialPolicy::None,
            allowed_credential_types: vec!["aws".into(), "gcp".into()],
            require_lease_for_refresh: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: CredentialSnapshotPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn credential_snapshot_policy_default_serde() {
        let json = serde_json::to_string(&CredentialSnapshotPolicy::default()).unwrap();
        let back: CredentialSnapshotPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CredentialSnapshotPolicy::default());
    }

    #[test]
    fn fork_credential_policy_serde_roundtrip() {
        for policy in &[
            ForkCredentialPolicy::None,
            ForkCredentialPolicy::InheritAll,
            ForkCredentialPolicy::InheritPermitted,
            ForkCredentialPolicy::InheritFromSnapshot,
        ] {
            let json = serde_json::to_string(policy).unwrap();
            let back: ForkCredentialPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*policy, back);
        }
    }
}
