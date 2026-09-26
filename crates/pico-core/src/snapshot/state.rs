//! Snapshot lifecycle state.
//!
//! Tracks the readiness of a snapshot from capture through publication,
//! revocation, and deletion.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a snapshot record.
///
/// Snapshots are immutable once `Ready`. Pre-`Ready` staging states and
/// post-`Ready` revocations are tracked explicitly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    /// Capture is in progress; blobs are being written.
    Staging,
    /// All blobs are durable and integrity evidence is verified.
    Ready,
    /// The snapshot has been revoked and must not be used for restore or fork.
    Revoked,
    /// Snapshot deletion is in progress; blobs are being cleaned up.
    Deleting,
    /// The snapshot and all its blobs have been deleted.
    Deleted,
    /// Capture or publication failed; blobs are quarantined.
    Failed,
}

impl SnapshotState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Ready => "ready",
            Self::Revoked => "revoked",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        }
    }

    /// True if the snapshot is externally restorable.
    ///
    /// Per ADR-0007, a snapshot is restorable only after metadata state is
    /// `Ready`.
    pub fn is_restorable(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// True if this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Deleted | Self::Failed)
    }

    /// True if the snapshot is in a state where it can transition to `Ready`.
    pub fn can_become_ready(self) -> bool {
        matches!(self, Self::Staging)
    }

    /// All valid snapshot lifecycle states.
    pub const ALL: &[SnapshotState] = &[
        Self::Staging,
        Self::Ready,
        Self::Revoked,
        Self::Deleting,
        Self::Deleted,
        Self::Failed,
    ];
}

impl std::fmt::Display for SnapshotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_as_str() {
        assert_eq!(SnapshotState::Staging.as_str(), "staging");
        assert_eq!(SnapshotState::Ready.as_str(), "ready");
        assert_eq!(SnapshotState::Revoked.as_str(), "revoked");
        assert_eq!(SnapshotState::Deleting.as_str(), "deleting");
        assert_eq!(SnapshotState::Deleted.as_str(), "deleted");
        assert_eq!(SnapshotState::Failed.as_str(), "failed");
    }

    #[test]
    fn state_is_restorable() {
        assert!(!SnapshotState::Staging.is_restorable());
        assert!(SnapshotState::Ready.is_restorable());
        assert!(!SnapshotState::Revoked.is_restorable());
        assert!(!SnapshotState::Deleting.is_restorable());
        assert!(!SnapshotState::Deleted.is_restorable());
        assert!(!SnapshotState::Failed.is_restorable());
    }

    #[test]
    fn state_is_terminal() {
        assert!(!SnapshotState::Staging.is_terminal());
        assert!(!SnapshotState::Ready.is_terminal());
        assert!(SnapshotState::Revoked.is_terminal());
        assert!(!SnapshotState::Deleting.is_terminal());
        assert!(SnapshotState::Deleted.is_terminal());
        assert!(SnapshotState::Failed.is_terminal());
    }

    #[test]
    fn state_can_become_ready() {
        assert!(SnapshotState::Staging.can_become_ready());
        assert!(!SnapshotState::Ready.can_become_ready());
        assert!(!SnapshotState::Failed.can_become_ready());
    }

    #[test]
    fn state_serde_roundtrip() {
        for state in SnapshotState::ALL {
            let json = serde_json::to_string(state).unwrap();
            let back: SnapshotState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }
}
