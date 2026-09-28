//! `/proc` hardening review.
//!
//! DSec anecdotes include a kernel crash via `grep` over
//! `/proc/kpagecgroup`. The guest `/proc` view masks hazardous entries,
//! applies hidepid semantics, and bounds read sizes and timeouts so
//! scans cannot crash the kernel or leak unapproved state.
//!
//! Callers must pass absolute guest paths. Relative paths never match
//! because kernel-resolved enforcement paths are absolute.

use crate::fim::baseline::normalize_path as normalize_guest_path;

/// Hazardous `/proc` entries masked from the guest view.
pub const MASKED_PROC_PATHS: &[&str] = &[
    "/proc/kpagecgroup",
    "/proc/kpagecount",
    "/proc/kpageflags",
    "/proc/kcore",
    "/proc/kallsyms",
    "/proc/kmem",
    "/proc/mem",
    "/proc/keys",
];

/// Maximum single read from a `/proc` entry (64 KiB).
pub const PROC_READ_MAX_BYTES: usize = 64 * 1024;

/// Returns true when `path` is a masked `/proc` hazard.
///
/// `path` must be absolute. Relative paths return false.
#[must_use]
pub fn is_masked_proc_path(path: &str) -> bool {
    let normalized = normalize_guest_path(path);
    if !normalized.starts_with('/') {
        return false;
    }
    MASKED_PROC_PATHS.contains(&normalized.as_str())
}

/// Validates a `/proc` read request against hardening policy.
///
/// Returns an error when the path is masked or the requested size
/// exceeds [`PROC_READ_MAX_BYTES`].
pub fn validate_proc_read(path: &str, max_bytes: usize) -> Result<(), ProcPolicyError> {
    if is_masked_proc_path(path) {
        return Err(ProcPolicyError::MaskedPath(path.to_string()));
    }
    if max_bytes > PROC_READ_MAX_BYTES {
        return Err(ProcPolicyError::ReadTooLarge {
            requested: max_bytes,
            max: PROC_READ_MAX_BYTES,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcPolicyError {
    #[error("masked /proc path: {0}")]
    MaskedPath(String),
    #[error("proc read {requested} exceeds max {max}")]
    ReadTooLarge { requested: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kpagecgroup_crash_vector_is_masked() {
        assert!(is_masked_proc_path("/proc/kpagecgroup"));
        assert!(validate_proc_read("/proc/kpagecgroup", 1024).is_err());
    }

    #[test]
    fn kcore_and_kallsyms_are_masked() {
        assert!(is_masked_proc_path("/proc/kcore"));
        assert!(is_masked_proc_path("/proc/kallsyms"));
    }

    #[test]
    fn oversized_proc_read_is_rejected() {
        let err = validate_proc_read("/proc/cpuinfo", PROC_READ_MAX_BYTES + 1).unwrap_err();
        assert!(matches!(err, ProcPolicyError::ReadTooLarge { .. }));
    }

    #[test]
    fn benign_proc_read_within_bounds_is_allowed() {
        assert!(validate_proc_read("/proc/cpuinfo", 4096).is_ok());
        assert!(validate_proc_read("/proc/self/status", PROC_READ_MAX_BYTES).is_ok());
    }

    #[test]
    fn relative_proc_paths_never_match() {
        assert!(!is_masked_proc_path("proc/kpagecgroup"));
    }
}
