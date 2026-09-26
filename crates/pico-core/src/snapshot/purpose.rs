//! Snapshot purpose classification.
//!
//! Defines the user-visible purpose of a snapshot as distinct from
//! the state profile that describes what the artifact preserves.

use serde::{Deserialize, Serialize};

/// User-visible snapshot purpose per ADR-0007.
///
/// Describes why an artifact exists. Separate from [`super::profile::SnapshotProfile`],
/// which describes what the artifact preserves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPurpose {
    /// Immutable, platform-produced warm-start point derived from a verified
    /// image and initialization sequence. Contains no tenant session, active
    /// exec, credential, lease, or live network authority.
    Base,
    /// Internal backend-bound capture artifact used to implement another
    /// snapshot purpose. Records runtime and device evidence but is not a
    /// standalone portable API contract.
    Runtime,
    /// Immutable recovery point for one sandbox workspace and, for lifecycle
    /// suspend/resume, its process memory and runtime device state.
    Session,
    /// Immutable branching point from which one or more child sandboxes
    /// receive independent writable state.
    Fork,
}

impl SnapshotPurpose {
    /// Returns the purpose as a static string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Runtime => "runtime",
            Self::Session => "session",
            Self::Fork => "fork",
        }
    }

    /// True if this purpose produces a restorable artifact for callers.
    pub fn is_user_restorable(self) -> bool {
        matches!(self, Self::Base | Self::Session | Self::Fork)
    }

    /// Validates this purpose against a restore intent.
    ///
    /// Single purpose gate for restore and fork: `Fork` intent requires
    /// exactly `Fork` purpose, `Restore` intent requires any
    /// user-restorable purpose. Returns `PolicyIncompatible` otherwise
    /// so callers share one gate instead of drifting core plus supervisor
    /// checks.
    pub fn check_for_intent(
        self,
        intent: RestoreIntent,
    ) -> Result<(), super::error::SnapshotError> {
        match intent {
            RestoreIntent::Fork => {
                if self == Self::Fork {
                    Ok(())
                } else {
                    Err(super::error::SnapshotError::PolicyIncompatible {
                        reason: format!(
                            "fork requires fork snapshot purpose, got {}",
                            self.as_str()
                        ),
                    })
                }
            }
            RestoreIntent::Restore => {
                if self.is_user_restorable() {
                    Ok(())
                } else {
                    Err(super::error::SnapshotError::PolicyIncompatible {
                        reason: format!("snapshot purpose {} is not restorable", self.as_str()),
                    })
                }
            }
        }
    }
}

/// Intent of a restore operation.
///
/// Distinguishes plain restore (any user-restorable purpose) from fork
/// (exactly fork purpose). Core owns the purpose gate via
/// [`SnapshotPurpose::check_for_intent`]; supervisors pass intent instead
/// of re-checking purpose inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreIntent {
    /// Plain restore: base, session, or fork artifacts.
    Restore,
    /// Fork: only fork-purpose snapshots branch children.
    Fork,
}

impl RestoreIntent {
    /// Human-readable intent name for logs and audit.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Fork => "fork",
        }
    }
}

impl std::fmt::Display for SnapshotPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Describes the relationship between a snapshot and its parent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LineageType {
    /// No parent snapshot; this is a root or base snapshot.
    Root,
    /// Direct parent-child relationship within the same sandbox.
    Direct,
    /// Forked from a parent sandbox.
    Fork,
    /// Warm-cache reference to a base snapshot for fast restore.
    BaseRef,
}

impl LineageType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Direct => "direct",
            Self::Fork => "fork",
            Self::BaseRef => "base_ref",
        }
    }
}

impl std::fmt::Display for LineageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_as_str() {
        assert_eq!(SnapshotPurpose::Base.as_str(), "base");
        assert_eq!(SnapshotPurpose::Runtime.as_str(), "runtime");
        assert_eq!(SnapshotPurpose::Session.as_str(), "session");
        assert_eq!(SnapshotPurpose::Fork.as_str(), "fork");
    }

    #[test]
    fn purpose_user_restorable() {
        assert!(SnapshotPurpose::Base.is_user_restorable());
        assert!(!SnapshotPurpose::Runtime.is_user_restorable());
        assert!(SnapshotPurpose::Session.is_user_restorable());
        assert!(SnapshotPurpose::Fork.is_user_restorable());
    }

    #[test]
    fn purpose_check_for_restore_intent() {
        assert!(
            SnapshotPurpose::Base
                .check_for_intent(RestoreIntent::Restore)
                .is_ok()
        );
        assert!(
            SnapshotPurpose::Session
                .check_for_intent(RestoreIntent::Restore)
                .is_ok()
        );
        assert!(
            SnapshotPurpose::Fork
                .check_for_intent(RestoreIntent::Restore)
                .is_ok()
        );
        assert!(
            SnapshotPurpose::Runtime
                .check_for_intent(RestoreIntent::Restore)
                .is_err()
        );
    }

    #[test]
    fn purpose_check_for_fork_intent() {
        assert!(
            SnapshotPurpose::Fork
                .check_for_intent(RestoreIntent::Fork)
                .is_ok()
        );
        assert!(
            SnapshotPurpose::Base
                .check_for_intent(RestoreIntent::Fork)
                .is_err()
        );
        assert!(
            SnapshotPurpose::Session
                .check_for_intent(RestoreIntent::Fork)
                .is_err()
        );
        assert!(
            SnapshotPurpose::Runtime
                .check_for_intent(RestoreIntent::Fork)
                .is_err()
        );
    }

    #[test]
    fn purpose_display() {
        assert_eq!(format!("{}", SnapshotPurpose::Base), "base");
        assert_eq!(format!("{}", SnapshotPurpose::Fork), "fork");
    }

    #[test]
    fn purpose_serde_roundtrip() {
        for purpose in &[
            SnapshotPurpose::Base,
            SnapshotPurpose::Runtime,
            SnapshotPurpose::Session,
            SnapshotPurpose::Fork,
        ] {
            let json = serde_json::to_string(purpose).unwrap();
            let back: SnapshotPurpose = serde_json::from_str(&json).unwrap();
            assert_eq!(*purpose, back);
        }
    }

    #[test]
    fn lineage_type_as_str() {
        assert_eq!(LineageType::Root.as_str(), "root");
        assert_eq!(LineageType::Direct.as_str(), "direct");
        assert_eq!(LineageType::Fork.as_str(), "fork");
        assert_eq!(LineageType::BaseRef.as_str(), "base_ref");
    }

    #[test]
    fn lineage_type_serde_roundtrip() {
        for lt in &[
            LineageType::Root,
            LineageType::Direct,
            LineageType::Fork,
            LineageType::BaseRef,
        ] {
            let json = serde_json::to_string(lt).unwrap();
            let back: LineageType = serde_json::from_str(&json).unwrap();
            assert_eq!(*lt, back);
        }
    }
}
