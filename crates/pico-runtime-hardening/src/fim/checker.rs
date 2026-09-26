//! Userspace file integrity checker.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::RwLock;

use super::baseline::IntegrityBaseline;
use super::types::{
    FimAlert, FimHook, FimMode, FimOperation, FimProcessInfo, open_flags_write_intent,
};
use crate::ebpf::syscall::{SYSCALL_OPEN, SYSCALL_OPENAT, SyscallEvent};

/// Per-sandbox FIM registration state.
#[derive(Debug, Clone)]
struct SandboxFimState {
    cgroup_id: u64,
    mode: FimMode,
    baseline: IntegrityBaseline,
}

/// Userspace file integrity checker.
///
/// Evaluates observed path operations against per-sandbox baselines and
/// produces [`FimAlert`]s. Works without eBPF (syscall-audit bridge) and is
/// also driven by LSM ring-buffer events on Linux.
pub struct FileIntegrityChecker {
    sandboxes: RwLock<HashMap<String, SandboxFimState>>,
    cgroup_index: RwLock<HashMap<u64, String>>,
    default_baseline: IntegrityBaseline,
    default_mode: AtomicU8,
    alert_count: AtomicU64,
    denied_count: AtomicU64,
    /// LSM events where path resolution returned empty (fail-open posture).
    path_resolution_failures: AtomicU64,
    /// Protected-path BPF map insert failures / truncations.
    map_insert_failures: AtomicU64,
    /// Paths dropped because per-sandbox cap was hit.
    paths_capped: AtomicU64,
}

impl FileIntegrityChecker {
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(IntegrityBaseline::system_default(), FimMode::Audit)
    }

    #[must_use]
    pub fn new(default_baseline: IntegrityBaseline, default_mode: FimMode) -> Self {
        Self {
            sandboxes: RwLock::new(HashMap::new()),
            cgroup_index: RwLock::new(HashMap::new()),
            default_baseline,
            default_mode: AtomicU8::new(default_mode as u8),
            alert_count: AtomicU64::new(0),
            denied_count: AtomicU64::new(0),
            path_resolution_failures: AtomicU64::new(0),
            map_insert_failures: AtomicU64::new(0),
            paths_capped: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn default_mode(&self) -> FimMode {
        FimMode::from_u8(self.default_mode.load(Ordering::Relaxed))
    }

    /// Update the default mode without dropping existing sandbox registrations.
    pub fn set_default_mode(&self, mode: FimMode) {
        self.default_mode.store(mode as u8, Ordering::Relaxed);
    }

    pub fn register_sandbox_default(&self, sandbox_id: &str, cgroup_id: u64) {
        self.register_sandbox(sandbox_id, cgroup_id, self.default_mode(), None);
    }

    pub fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: u64,
        mode: FimMode,
        baseline: Option<IntegrityBaseline>,
    ) {
        let state = SandboxFimState {
            cgroup_id,
            mode,
            baseline: baseline.unwrap_or_else(|| self.default_baseline.clone()),
        };
        self.sandboxes.write().insert(sandbox_id.to_string(), state);
        self.cgroup_index
            .write()
            .insert(cgroup_id, sandbox_id.to_string());
    }

    pub fn unregister_sandbox(&self, sandbox_id: &str) {
        let mut sandboxes = self.sandboxes.write();
        if let Some(state) = sandboxes.remove(sandbox_id) {
            self.cgroup_index.write().remove(&state.cgroup_id);
        }
    }

    #[must_use]
    pub fn sandbox_for_cgroup(&self, cgroup_id: u64) -> Option<String> {
        self.cgroup_index.read().get(&cgroup_id).cloned()
    }

    #[must_use]
    pub fn active_sandbox_count(&self) -> usize {
        self.sandboxes.read().len()
    }

    #[must_use]
    pub fn alert_count(&self) -> u64 {
        self.alert_count.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn denied_count(&self) -> u64 {
        self.denied_count.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn path_resolution_failures(&self) -> u64 {
        self.path_resolution_failures.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn map_insert_failures(&self) -> u64 {
        self.map_insert_failures.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn paths_capped(&self) -> u64 {
        self.paths_capped.load(Ordering::Relaxed)
    }

    pub fn record_path_resolution_failure(&self) {
        self.path_resolution_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_map_insert_failure(&self) {
        self.map_insert_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_paths_capped(&self, n: u64) {
        self.paths_capped.fetch_add(n, Ordering::Relaxed);
    }

    /// Snapshot of counters for metrics export.
    #[must_use]
    pub fn stats(&self) -> FimStats {
        FimStats {
            active_sandboxes: self.active_sandbox_count(),
            alerts: self.alert_count(),
            denied: self.denied_count(),
            path_resolution_failures: self.path_resolution_failures(),
            map_insert_failures: self.map_insert_failures(),
            paths_capped: self.paths_capped(),
            dropped_events: 0, // populated by the eBPF monitor when available
        }
    }

    /// Evaluate a path operation for a known sandbox.
    pub fn check(
        &self,
        sandbox_id: &str,
        path: &str,
        operation: FimOperation,
        hook: FimHook,
        proc: FimProcessInfo,
    ) -> Option<FimAlert> {
        let sandboxes = self.sandboxes.read();
        let state = sandboxes.get(sandbox_id)?;
        if !state.baseline.is_protected(path) {
            return None;
        }

        let denied = state.mode == FimMode::Enforce;
        let detail = match operation {
            FimOperation::Write => "write_to_protected_path",
            FimOperation::Unlink => "unlink_protected_path",
        };

        let alert = FimAlert {
            sandbox_id: sandbox_id.to_string(),
            path: path.to_string(),
            hook,
            mode: state.mode,
            pid: proc.pid,
            tid: proc.tid,
            uid: proc.uid,
            gid: proc.gid,
            cgroup_id: proc.cgroup_id,
            timestamp_ns: proc.timestamp_ns,
            denied,
            detail: detail.to_string(),
        };

        self.alert_count.fetch_add(1, Ordering::Relaxed);
        if denied {
            self.denied_count.fetch_add(1, Ordering::Relaxed);
        }
        Some(alert)
    }

    /// Evaluate a raw LSM / ring-buffer event that already carries a path.
    pub fn check_raw_event(
        &self,
        sandbox_id: &str,
        path: &str,
        hook: FimHook,
        proc: FimProcessInfo,
        kernel_denied: bool,
    ) -> Option<FimAlert> {
        let operation = match hook {
            FimHook::InodeUnlink => FimOperation::Unlink,
            _ => FimOperation::Write,
        };
        let mut alert = self.check(sandbox_id, path, operation, hook, proc)?;
        if kernel_denied && !alert.denied {
            alert.denied = true;
            self.denied_count.fetch_add(1, Ordering::Relaxed);
        }
        Some(alert)
    }

    /// Bridge syscall audit enter events (`open`/`openat` write intent only).
    pub fn observe_syscall_event(
        &self,
        sandbox_id: &str,
        event: &SyscallEvent,
    ) -> Option<FimAlert> {
        if !event.is_enter {
            return None;
        }
        if event.syscall_nr != SYSCALL_OPEN && event.syscall_nr != SYSCALL_OPENAT {
            return None;
        }
        let path = event.string_arg0.as_deref()?;
        if path.is_empty() {
            return None;
        }

        let flags = if event.syscall_nr == SYSCALL_OPEN {
            event.arg1
        } else {
            event.arg2
        };
        if !open_flags_write_intent(flags) {
            return None;
        }

        self.check(
            sandbox_id,
            path,
            FimOperation::Write,
            FimHook::SyscallOpen,
            FimProcessInfo {
                pid: event.pid,
                tid: event.tid,
                uid: event.uid,
                gid: event.gid,
                cgroup_id: event.cgroup_id,
                timestamp_ns: event.timestamp_ns,
            },
        )
    }

    pub fn bpf_config_for(&self, sandbox_id: &str) -> Option<(u64, FimMode, Vec<String>)> {
        let sandboxes = self.sandboxes.read();
        let state = sandboxes.get(sandbox_id)?;
        Some((
            state.cgroup_id,
            state.mode,
            state.baseline.bpf_path_entries(),
        ))
    }
}

impl Default for FileIntegrityChecker {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Counters suitable for host metrics / diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FimStats {
    pub active_sandboxes: usize,
    pub alerts: u64,
    pub denied: u64,
    pub path_resolution_failures: u64,
    pub map_insert_failures: u64,
    pub paths_capped: u64,
    /// FIM ring-buffer entries dropped (undersized / corrupt).
    pub dropped_events: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::syscall::SyscallEvent;

    fn write_open_event(path: &str, flags: u64) -> SyscallEvent {
        SyscallEvent {
            cgroup_id: 42,
            pid: 100,
            tid: 100,
            uid: 0,
            gid: 0,
            syscall_name: "openat".into(),
            syscall_nr: SYSCALL_OPENAT,
            timestamp_ns: 1_000,
            arg0: 0,
            arg1: 0,
            arg2: flags,
            arg3: 0,
            retval: -1,
            string_arg0: Some(path.into()),
            string_arg1: None,
            is_enter: true,
        }
    }

    #[test]
    fn alerts_on_passwd_write_via_syscall_bridge() {
        let checker = FileIntegrityChecker::with_defaults();
        checker.register_sandbox("sb-1", 42, FimMode::Audit, None);

        let alert = checker
            .observe_syscall_event("sb-1", &write_open_event("/etc/passwd", 0o1))
            .expect("alert");
        assert_eq!(alert.path, "/etc/passwd");
        assert_eq!(alert.sandbox_id, "sb-1");
        assert_eq!(alert.pid, 100);
        assert!(!alert.denied);
        assert_eq!(checker.alert_count(), 1);
    }

    #[test]
    fn enforce_mode_marks_denied() {
        let checker = FileIntegrityChecker::with_defaults();
        checker.register_sandbox("sb-1", 42, FimMode::Enforce, None);

        let alert = checker
            .check(
                "sb-1",
                "/etc/passwd",
                FimOperation::Write,
                FimHook::FileOpen,
                FimProcessInfo {
                    pid: 7,
                    tid: 7,
                    uid: 0,
                    gid: 0,
                    cgroup_id: 42,
                    timestamp_ns: 99,
                },
            )
            .expect("alert");
        assert!(alert.denied);
        assert_eq!(alert.mode, FimMode::Enforce);
        assert_eq!(checker.denied_count(), 1);
    }

    #[test]
    fn read_only_open_does_not_alert() {
        let checker = FileIntegrityChecker::with_defaults();
        checker.register_sandbox("sb-1", 42, FimMode::Audit, None);
        assert!(
            checker
                .observe_syscall_event("sb-1", &write_open_event("/etc/passwd", 0))
                .is_none()
        );
    }

    #[test]
    fn unlink_protected_path_alerts() {
        let checker = FileIntegrityChecker::with_defaults();
        checker.register_sandbox("sb-1", 42, FimMode::Audit, None);
        let alert = checker
            .check(
                "sb-1",
                "/usr/bin/ls",
                FimOperation::Unlink,
                FimHook::InodeUnlink,
                FimProcessInfo {
                    pid: 1,
                    tid: 1,
                    uid: 0,
                    gid: 0,
                    cgroup_id: 42,
                    timestamp_ns: 1,
                },
            )
            .expect("alert");
        assert_eq!(alert.detail, "unlink_protected_path");
    }

    #[test]
    fn unregistered_sandbox_is_ignored() {
        let checker = FileIntegrityChecker::with_defaults();
        assert!(
            checker
                .check(
                    "missing",
                    "/etc/passwd",
                    FimOperation::Write,
                    FimHook::FileOpen,
                    FimProcessInfo {
                        pid: 1,
                        tid: 1,
                        uid: 0,
                        gid: 0,
                        cgroup_id: 1,
                        timestamp_ns: 1,
                    },
                )
                .is_none()
        );
    }

    #[test]
    fn custom_baseline() {
        let baseline = IntegrityBaseline::from_paths(["/data/secret.key"]);
        let checker = FileIntegrityChecker::new(baseline, FimMode::Audit);
        checker.register_sandbox("sb-1", 1, FimMode::Audit, None);
        let proc = FimProcessInfo {
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            cgroup_id: 1,
            timestamp_ns: 1,
        };
        assert!(
            checker
                .check(
                    "sb-1",
                    "/data/secret.key",
                    FimOperation::Write,
                    FimHook::FileOpen,
                    proc,
                )
                .is_some()
        );
        assert!(
            checker
                .check(
                    "sb-1",
                    "/etc/passwd",
                    FimOperation::Write,
                    FimHook::FileOpen,
                    proc,
                )
                .is_none()
        );
    }
}
