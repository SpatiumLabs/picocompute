//! Ioctl allowlist review for extent-aliasing vectors.
//!
//! DSec anecdotes include `XFS_IOC_SWAPEXT` extent-swap corruption.
//! The default posture denies extent-swap and clone-range classes at
//! profile-review time; backend profiles name an exact allowed set and
//! additions require reviewed compatibility evidence plus negative tests.
//!
//! This module is a static review helper, not a runtime match against
//! [`crate::ebpf::syscall::SyscallEvent`]: the syscall audit layer tracks
//! syscall numbers such as `open` and `mount`, while extent-swap and
//! clone-range are ioctl request codes carried in the ioctl argument.
//! Runtime filtering by request code belongs in seccomp arg filters or
//! eBPF ioctl inspection; this module gates which symbolic names a
//! profile may allow.

/// Ioctl classes denied by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedIoctlClass {
    ExtentSwap,
    CloneRange,
    SnapshotCreate,
}

impl DeniedIoctlClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExtentSwap => "extent-swap",
            Self::CloneRange => "clone-range",
            Self::SnapshotCreate => "snapshot-create",
        }
    }
}

/// Symbolic ioctl names denied by default.
///
/// Numeric request codes differ per architecture, so review matches on
/// audited symbolic names from profile manifests and compatibility cases.
pub const DENIED_IOCTLS: &[(&str, DeniedIoctlClass)] = &[
    ("XFS_IOC_SWAPEXT", DeniedIoctlClass::ExtentSwap),
    ("FICLONE", DeniedIoctlClass::CloneRange),
    ("FICLONERANGE", DeniedIoctlClass::CloneRange),
    ("FIDEDUPERANGE", DeniedIoctlClass::CloneRange),
    ("BTRFS_IOC_SNAP_CREATE_V2", DeniedIoctlClass::SnapshotCreate),
];

/// Returns the denied class when `ioctl_name` must be blocked.
#[must_use]
pub fn denied_class(ioctl_name: &str) -> Option<DeniedIoctlClass> {
    DENIED_IOCTLS
        .iter()
        .find(|(name, _)| *name == ioctl_name)
        .map(|(_, class)| *class)
}

/// Returns true when `ioctl_name` is allowed under an explicit allowlist.
///
/// Empty allowlists deny everything in [`DENIED_IOCTLS`]; non-empty
/// allowlists permit only the named entries and still deny any other
/// extent-swap or clone-range ioctl.
#[must_use]
pub fn is_allowed(ioctl_name: &str, allowlist: &[&str]) -> bool {
    if denied_class(ioctl_name).is_none() {
        return true;
    }
    allowlist.contains(&ioctl_name)
}

/// Review a backend profile allowlist.
///
/// Returns the denied entries the profile would permit. An empty result
/// means the profile allows no extent-aliasing ioctls.
pub fn review_profile_allowlist<'a>(allowlist: &'a [&'a str]) -> Vec<(&'a str, DeniedIoctlClass)> {
    allowlist
        .iter()
        .filter_map(|name| denied_class(name).map(|class| (*name, class)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swapext_class_is_denied_by_default() {
        assert_eq!(
            denied_class("XFS_IOC_SWAPEXT"),
            Some(DeniedIoctlClass::ExtentSwap)
        );
        assert_eq!(DeniedIoctlClass::ExtentSwap.as_str(), "extent-swap");
        assert!(!is_allowed("XFS_IOC_SWAPEXT", &[]));
    }

    #[test]
    fn clone_range_class_is_denied_by_default() {
        assert_eq!(
            denied_class("FICLONERANGE"),
            Some(DeniedIoctlClass::CloneRange)
        );
        assert_eq!(DeniedIoctlClass::CloneRange.as_str(), "clone-range");
        assert_eq!(DeniedIoctlClass::SnapshotCreate.as_str(), "snapshot-create");
        assert!(!is_allowed("FICLONE", &[]));
        assert!(!is_allowed("FIDEDUPERANGE", &[]));
    }

    #[test]
    fn explicit_allowlist_permits_only_named_entry() {
        assert!(is_allowed("XFS_IOC_SWAPEXT", &["XFS_IOC_SWAPEXT"]));
        // Allowlisting one extent-swap ioctl does not open the whole class.
        assert!(!is_allowed("FICLONERANGE", &["XFS_IOC_SWAPEXT"]));
    }

    #[test]
    fn benign_ioctls_remain_allowed() {
        assert!(is_allowed("TCGETS", &[]));
        assert!(is_allowed("FIONREAD", &[]));
    }

    #[test]
    fn profile_review_lists_permitted_denied_entries() {
        assert!(review_profile_allowlist(&[]).is_empty());
        let flagged = review_profile_allowlist(&["XFS_IOC_SWAPEXT", "TCGETS"]);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].0, "XFS_IOC_SWAPEXT");
        assert_eq!(flagged[0].1, DeniedIoctlClass::ExtentSwap);
    }
}
