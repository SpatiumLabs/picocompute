//! Ioctl allowlist review for extent-aliasing vectors.
//!
//! DSec anecdotes include `XFS_IOC_SWAPEXT` extent-swap corruption.
//! The default posture denies extent-swap and clone-range classes;
//! backend profiles name an exact allowed set and additions require
//! reviewed compatibility evidence plus negative tests.

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
/// Numeric values differ per architecture, so policy matches on audited
/// symbolic names emitted by the syscall audit layer.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swapext_class_is_denied_by_default() {
        assert_eq!(
            denied_class("XFS_IOC_SWAPEXT"),
            Some(DeniedIoctlClass::ExtentSwap)
        );
        assert!(!is_allowed("XFS_IOC_SWAPEXT", &[]));
    }

    #[test]
    fn clone_range_class_is_denied_by_default() {
        assert_eq!(
            denied_class("FICLONERANGE"),
            Some(DeniedIoctlClass::CloneRange)
        );
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
}
