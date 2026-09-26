//! Snapshot state profile.
//!
//! Defines which state classes a snapshot preserves, as an explicit
//! capability contract rather than a backend-specific mode.

use serde::{Deserialize, Serialize};

/// Semantic state profile per ADR-0007.
///
/// Describes what a snapshot preserves. Backend-specific details
/// are not exposed through this type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotProfile {
    /// Immutable image references, committed workspace point, declared
    /// persistent mounts, and snapshot metadata. The portable v1 baseline.
    Filesystem,
    /// Everything in `Filesystem`, plus backend runtime state, guest memory,
    /// and declared restorable device state. Capability-gated.
    Memory,
}

impl SnapshotProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Memory => "memory",
        }
    }

    /// True if this profile preserves process memory and runtime device state.
    pub fn preserves_memory(self) -> bool {
        matches!(self, Self::Memory)
    }

    /// Minimum profile that can support lifecycle suspend/resume.
    ///
    /// Per ADR-0007, lifecycle suspend and resume require the `Memory` profile
    /// because `Suspended` preserves VM memory and device state.
    pub fn supports_lifecycle_suspend(self) -> bool {
        matches!(self, Self::Memory)
    }
}

impl std::fmt::Display for SnapshotProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_as_str() {
        assert_eq!(SnapshotProfile::Filesystem.as_str(), "filesystem");
        assert_eq!(SnapshotProfile::Memory.as_str(), "memory");
    }

    #[test]
    fn profile_preserves_memory() {
        assert!(!SnapshotProfile::Filesystem.preserves_memory());
        assert!(SnapshotProfile::Memory.preserves_memory());
    }

    #[test]
    fn profile_supports_lifecycle_suspend() {
        assert!(!SnapshotProfile::Filesystem.supports_lifecycle_suspend());
        assert!(SnapshotProfile::Memory.supports_lifecycle_suspend());
    }

    #[test]
    fn profile_serde_roundtrip() {
        let fs = SnapshotProfile::Filesystem;
        let json = serde_json::to_string(&fs).unwrap();
        assert_eq!(json, r#""filesystem""#);
        let back: SnapshotProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(fs, back);

        let mem = SnapshotProfile::Memory;
        let json = serde_json::to_string(&mem).unwrap();
        assert_eq!(json, r#""memory""#);
        let back: SnapshotProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(mem, back);
    }
}
