//! Host-owned guest path protections.
//!
//! DSec agent-misbehavior anecdotes show workloads forging RPCs to agent
//! sockets, scraping logs for residual answers, and overwriting image
//! binaries such as `/bin/bash`. These paths are host-owned inside the
//! guest view: the workload must not create, replace, or write them
//! outside the authenticated host session.
//!
//! Callers must pass absolute guest paths. Relative paths never match
//! because kernel-resolved enforcement paths are absolute.

use serde::{Deserialize, Serialize};

use crate::fim::IntegrityBaseline;
use crate::fim::baseline::normalize_path as normalize_guest_path;

/// Unix socket paths owned by the host agent session.
pub const HOST_OWNED_SOCKET_PATHS: &[&str] = &[
    "/run/pico/agent.sock",
    "/run/pico/sandboxd.sock",
    "/var/run/pico/sandboxd.sock",
];

/// Log paths that may retain residual answers from prior operations.
pub const HOST_OWNED_LOG_PATHS: &[&str] = &[
    "/var/log/pico",
    "/var/log/pico/agent.log",
    "/run/pico/agent.log",
];

/// Image binaries that must remain immutable at runtime.
pub const HOST_OWNED_BINARY_PREFIXES: &[&str] = &["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

/// Directory prefixes that are host-owned in full.
pub const HOST_OWNED_DIR_PREFIXES: &[&str] = &["/var/log/pico"];

/// Exact image binaries covered by anecdote evidence.
pub const HOST_OWNED_BINARY_EXACT: &[&str] = &["/bin/bash", "/bin/sh"];

/// Workload-writable scratch dir under `/run/pico`.
pub const WORKLOAD_SCRATCH_DIR: &str = "/run/pico/tmp";

/// Returns true when `path` is host-owned and must not be writable
/// by tenant workload code.
///
/// `path` must be absolute. Relative paths return false.
#[must_use]
pub fn is_host_owned(path: &str) -> bool {
    let normalized = normalize_guest_path(path);
    if normalized.is_empty() || !normalized.starts_with('/') {
        return false;
    }
    if HOST_OWNED_SOCKET_PATHS.contains(&normalized.as_str())
        || HOST_OWNED_LOG_PATHS.contains(&normalized.as_str())
        || HOST_OWNED_BINARY_EXACT.contains(&normalized.as_str())
    {
        return true;
    }
    for prefix in HOST_OWNED_BINARY_PREFIXES
        .iter()
        .chain(HOST_OWNED_DIR_PREFIXES.iter())
    {
        if normalized == *prefix || normalized.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }
    // `/run/pico` as a whole is host-owned except the explicit
    // workload scratch areas managed by the mount contract.
    if normalized == "/run/pico" || normalized.starts_with("/run/pico/") {
        return !is_workload_scratch(&normalized);
    }
    false
}

/// Workload-writable scratch areas under `/run/pico`.
fn is_workload_scratch(path: &str) -> bool {
    path == WORKLOAD_SCRATCH_DIR || path.starts_with(&format!("{WORKLOAD_SCRATCH_DIR}/"))
}

/// Integrity baseline entries covering host-owned guest paths.
///
/// Convert into [`IntegrityBaseline`] with [`Self::to_integrity_baseline`]
/// for use with [`crate::fim::FileIntegrityChecker`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuestHostOwnedBaseline {
    extra_exact: Vec<String>,
    extra_prefixes: Vec<String>,
}

impl GuestHostOwnedBaseline {
    #[must_use]
    pub fn system_with_guest_paths() -> Self {
        Self {
            extra_exact: HOST_OWNED_SOCKET_PATHS
                .iter()
                .chain(HOST_OWNED_BINARY_EXACT.iter())
                .map(|s| (*s).to_string())
                .collect(),
            extra_prefixes: HOST_OWNED_DIR_PREFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    #[must_use]
    pub fn is_protected(&self, path: &str) -> bool {
        if is_host_owned(path) {
            return true;
        }
        let normalized = normalize_guest_path(path);
        if self.extra_exact.iter().any(|p| p == &normalized) {
            return true;
        }
        self.extra_prefixes
            .iter()
            .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
    }

    /// Merge host-owned guest paths into a FIM [`IntegrityBaseline`].
    #[must_use]
    pub fn to_integrity_baseline(&self) -> IntegrityBaseline {
        let mut baseline = IntegrityBaseline::system_default();
        for path in &self.extra_exact {
            baseline.add_exact(path);
        }
        for prefix in &self.extra_prefixes {
            baseline.add_prefix(prefix);
        }
        for path in HOST_OWNED_SOCKET_PATHS
            .iter()
            .chain(HOST_OWNED_BINARY_EXACT.iter())
        {
            baseline.add_exact(path);
        }
        baseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_socket_paths_are_host_owned() {
        for path in HOST_OWNED_SOCKET_PATHS {
            assert!(is_host_owned(path), "{path} must be host-owned");
        }
        // Forged socket replacement must be treated as tamper.
        assert!(is_host_owned("/run/pico/agent.sock"));
    }

    #[test]
    fn log_paths_retain_residual_answers_and_are_protected() {
        assert!(is_host_owned("/var/log/pico/agent.log"));
        assert!(is_host_owned("/var/log/pico/tool-output-123.log"));
        let baseline = GuestHostOwnedBaseline::system_with_guest_paths();
        assert!(baseline.is_protected("/var/log/pico/agent.log"));
    }

    #[test]
    fn bash_overwrite_is_tamper() {
        assert!(is_host_owned("/bin/bash"));
        assert!(is_host_owned("/bin/sh"));
        assert!(is_host_owned("/usr/bin/sudo"));
    }

    #[test]
    fn workload_scratch_remains_writable() {
        assert!(!is_host_owned("/run/pico/tmp/scratch"));
        assert!(!is_host_owned("/workspace/output.txt"));
        let baseline = GuestHostOwnedBaseline::system_with_guest_paths();
        assert!(!baseline.is_protected("/run/pico/tmp/scratch"));
        assert!(!baseline.is_protected("/run/pico/tmp/"));
        assert!(baseline.is_protected("/run/pico/agent.sock"));
    }

    #[test]
    fn normalization_collapses_slashes() {
        assert!(is_host_owned("//run//pico//agent.sock"));
    }

    #[test]
    fn relative_paths_never_match() {
        assert!(!is_host_owned("run/pico/agent.sock"));
        assert!(!is_host_owned(""));
    }

    #[test]
    fn baseline_converts_to_fim_baseline() {
        let baseline = GuestHostOwnedBaseline::system_with_guest_paths().to_integrity_baseline();
        assert!(baseline.is_protected("/run/pico/agent.sock"));
        assert!(baseline.is_protected("/var/log/pico/agent.log"));
        assert!(baseline.is_protected("/etc/passwd"));
    }
}
