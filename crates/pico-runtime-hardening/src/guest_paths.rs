//! Host-owned guest path protections.
//!
//! DSec agent-misbehavior anecdotes show workloads forging RPCs to agent
//! sockets, scraping logs for residual answers, and overwriting image
//! binaries such as `/bin/bash`. These paths are host-owned inside the
//! guest view: the workload must not create, replace, or write them
//! outside the authenticated host session.

use serde::{Deserialize, Serialize};

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

/// Exact image binaries covered by anecdote evidence.
pub const HOST_OWNED_BINARY_EXACT: &[&str] = &["/bin/bash", "/bin/sh"];

/// Returns true when `path` is host-owned and must not be writable
/// by tenant workload code.
#[must_use]
pub fn is_host_owned(path: &str) -> bool {
    let normalized = normalize(path);
    if normalized.is_empty() {
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
        .chain(HOST_OWNED_LOG_PATHS.iter().take(1))
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
    path == "/run/pico/tmp" || path.starts_with("/run/pico/tmp/")
}

/// Integrity baseline entries covering host-owned guest paths.
///
/// Merged with [`crate::fim::IntegrityBaseline::system_default`] by the
/// caller to enforce socket and log tamper protections.
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
            extra_prefixes: vec!["/var/log/pico".to_string(), "/run/pico".to_string()],
        }
    }

    #[must_use]
    pub fn is_protected(&self, path: &str) -> bool {
        if is_host_owned(path) {
            return true;
        }
        let normalized = normalize(path);
        if self.extra_exact.iter().any(|p| p == &normalized) {
            return true;
        }
        self.extra_prefixes
            .iter()
            .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
    }
}

fn normalize(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_slash = false;
    for ch in trimmed.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    if out.len() > 1 {
        out = out.trim_end_matches('/').to_string();
    }
    out
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
    }

    #[test]
    fn normalization_collapses_slashes() {
        assert!(is_host_owned("//run//pico//agent.sock"));
    }
}
