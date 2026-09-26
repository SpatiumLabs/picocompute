//! Integrity baselines: protected paths that sandboxes must not modify.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Set of paths that constitute a sandbox integrity baseline.
///
/// Paths may be exact files (`/etc/passwd`) or directory prefixes
/// (`/usr/bin`, `/usr/lib`). Prefix matching treats the path as protected
/// when the observed path equals the prefix or starts with `prefix/`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrityBaseline {
    exact: HashSet<String>,
    prefixes: Vec<String>,
}

impl IntegrityBaseline {
    /// Empty baseline (no protected paths).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Default system paths that should not be modified inside a guest.
    ///
    /// Covers credential files, system binaries, and shared libraries that
    /// an image SBOM would also treat as integrity-critical.
    #[must_use]
    pub fn system_default() -> Self {
        let mut baseline = Self::empty();
        for path in DEFAULT_EXACT_PATHS {
            baseline.exact.insert((*path).to_string());
        }
        for path in DEFAULT_PREFIX_PATHS {
            baseline.add_prefix(path);
        }
        baseline
    }

    /// Build a baseline from explicit paths (exact files and directories).
    ///
    /// Directory-looking paths (no extension and not a known credential file)
    /// are treated as prefixes; callers can force prefix semantics by ending
    /// the path with `/`.
    #[must_use]
    pub fn from_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut baseline = Self::empty();
        for path in paths {
            let p = normalize_path(path.as_ref());
            if p.is_empty() || p == "/" {
                continue;
            }
            if p.ends_with('/') || looks_like_directory(&p) {
                baseline.add_prefix(p.trim_end_matches('/'));
            } else {
                baseline.exact.insert(p);
            }
        }
        baseline
    }

    /// Merge image-manifest / SBOM paths into the system default baseline.
    #[must_use]
    pub fn system_with_image_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut baseline = Self::system_default();
        let extra = Self::from_paths(paths);
        baseline.exact.extend(extra.exact);
        for p in extra.prefixes {
            baseline.add_prefix(&p);
        }
        baseline
    }

    /// Add an exact protected path.
    pub fn add_exact(&mut self, path: &str) {
        let p = normalize_path(path);
        if !p.is_empty() {
            self.exact.insert(p);
        }
    }

    /// Add a protected directory prefix.
    pub fn add_prefix(&mut self, path: &str) {
        let p = normalize_path(path).trim_end_matches('/').to_string();
        if p.is_empty() || p == "/" {
            return;
        }
        if !self.prefixes.iter().any(|existing| existing == &p) {
            self.prefixes.push(p);
            self.prefixes.sort_unstable();
        }
    }

    /// Returns true when `path` is covered by this baseline.
    #[must_use]
    pub fn is_protected(&self, path: &str) -> bool {
        let p = normalize_path(path);
        if p.is_empty() {
            return false;
        }
        if self.exact.contains(&p) {
            return true;
        }
        for prefix in &self.prefixes {
            if p == *prefix || p.starts_with(&format!("{prefix}/")) {
                return true;
            }
        }
        false
    }

    /// Number of exact + prefix entries (for diagnostics).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.exact.len() + self.prefixes.len()
    }

    /// Exact protected paths.
    pub fn exact_paths(&self) -> impl Iterator<Item = &str> {
        self.exact.iter().map(String::as_str)
    }

    /// Protected directory prefixes.
    pub fn prefix_paths(&self) -> impl Iterator<Item = &str> {
        self.prefixes.iter().map(String::as_str)
    }

    /// Flatten all entries for BPF map loading (exact paths + prefixes).
    ///
    /// Prefixes are stored without a trailing slash; the eBPF matcher uses
    /// the same equality/prefix rules as [`Self::is_protected`].
    #[must_use]
    pub fn bpf_path_entries(&self) -> Vec<String> {
        let mut out: Vec<String> = self.exact.iter().cloned().collect();
        out.extend(self.prefixes.iter().cloned());
        out.sort_unstable();
        out.dedup();
        out
    }
}

const DEFAULT_EXACT_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
];

const DEFAULT_PREFIX_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
];

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Collapse duplicate slashes without resolving `..` (guest paths only).
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

fn looks_like_directory(path: &str) -> bool {
    matches!(
        path,
        "/usr/bin"
            | "/usr/sbin"
            | "/usr/lib"
            | "/usr/lib64"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/lib64"
            | "/boot"
            | "/etc"
            | "/opt"
            | "/var"
    ) || path.ends_with("/bin")
        || path.ends_with("/sbin")
        || path.ends_with("/lib")
        || path.ends_with("/lib64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_default_protects_passwd() {
        let b = IntegrityBaseline::system_default();
        assert!(b.is_protected("/etc/passwd"));
        assert!(b.is_protected("/etc/shadow"));
        assert!(b.is_protected("/usr/bin/ls"));
        assert!(b.is_protected("/usr/lib/libc.so.6"));
        assert!(!b.is_protected("/tmp/scratch"));
        assert!(!b.is_protected("/home/user/file"));
        assert!(!b.is_protected("/var/log/app.log"));
    }

    #[test]
    fn prefix_does_not_match_sibling() {
        let b = IntegrityBaseline::system_default();
        // `/bin` must not match `/binary` or `/binutils`
        assert!(!b.is_protected("/binary"));
        assert!(!b.is_protected("/binutils"));
        assert!(b.is_protected("/bin/sh"));
    }

    #[test]
    fn from_paths_and_merge() {
        let b = IntegrityBaseline::system_with_image_paths(["/opt/app/bin", "/etc/app.conf"]);
        assert!(b.is_protected("/etc/passwd"));
        assert!(b.is_protected("/etc/app.conf"));
        assert!(b.is_protected("/opt/app/bin/tool"));
    }

    #[test]
    fn normalize_collapses_slashes() {
        let b = IntegrityBaseline::from_paths(["//etc//passwd"]);
        assert!(b.is_protected("/etc/passwd"));
        assert!(b.is_protected("//etc/passwd"));
    }

    #[test]
    fn bpf_entries_include_exact_and_prefix() {
        let b = IntegrityBaseline::system_default();
        let entries = b.bpf_path_entries();
        assert!(entries.iter().any(|p| p == "/etc/passwd"));
        assert!(entries.iter().any(|p| p == "/usr/bin"));
    }
}
