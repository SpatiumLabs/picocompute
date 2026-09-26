//! Host-side lifecycle wiring for file integrity monitoring.
//!
//! Registers sandbox cgroups with the FIM checker (and BPF LSM maps when
//! available). Mode defaults to audit; set `PICO_FIM_MODE=enforce` to deny
//! protected-path writes in the kernel on path-bearing `file_open` matches.
//!
//! Wire the syscall-audit bridge after both services start:
//! `syscall_audit.set_fim_observer(file_integrity.syscall_observer())`.

use std::sync::Arc;

use parking_lot::Mutex;
use pico_runtime_hardening::ebpf::EbpfFileIntegrityMonitor;
use pico_runtime_hardening::ebpf::SyscallFimObserver;
use pico_runtime_hardening::ebpf::syscall::SyscallEvent;
use pico_runtime_hardening::fim::{
    FileIntegrityChecker, FimAlert, FimMode, FimStats, IntegrityBaseline,
};
use tokio::sync::watch;
use tracing::{info, warn};

pub struct FileIntegrityService {
    inner: Mutex<Inner>,
    default_mode: FimMode,
}

struct Inner {
    monitor: Option<EbpfFileIntegrityMonitor>,
    checker: Arc<FileIntegrityChecker>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl FileIntegrityService {
    /// Best-effort start: userspace checker always; BPF LSM when the host supports it.
    pub fn try_start() -> Arc<Self> {
        let default_mode = parse_fim_mode();
        let enabled = std::env::var("PICO_FIM")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        if !enabled {
            info!("file integrity monitoring disabled via PICO_FIM");
            return Arc::new(Self {
                inner: Mutex::new(Inner {
                    monitor: None,
                    checker: Arc::new(FileIntegrityChecker::new(
                        IntegrityBaseline::system_default(),
                        default_mode,
                    )),
                    shutdown_tx: None,
                }),
                default_mode,
            });
        }

        let checker = Arc::new(FileIntegrityChecker::new(
            IntegrityBaseline::system_default(),
            default_mode,
        ));

        match EbpfFileIntegrityMonitor::load() {
            Ok(mut mon) => {
                mon.set_default_mode(default_mode);
                let mon_checker = mon.checker();
                let (tx, rx) = watch::channel(false);
                match mon.run_consumer(rx) {
                    Ok((_ring, _consumer)) => {
                        info!(
                            mode = default_mode.as_str(),
                            "file integrity LSM consumer started"
                        );
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            "file integrity ringbuf consumer unavailable; userspace checker only"
                        );
                    }
                }
                Arc::new(Self {
                    inner: Mutex::new(Inner {
                        monitor: Some(mon),
                        checker: mon_checker,
                        shutdown_tx: Some(tx),
                    }),
                    default_mode,
                })
            }
            Err(err) => {
                warn!(
                    error = %err,
                    mode = default_mode.as_str(),
                    "file integrity eBPF monitor not loaded; userspace checker active"
                );
                Arc::new(Self {
                    inner: Mutex::new(Inner {
                        monitor: None,
                        checker,
                        shutdown_tx: None,
                    }),
                    default_mode,
                })
            }
        }
    }

    pub fn default_mode(&self) -> FimMode {
        self.default_mode
    }

    pub fn checker(&self) -> Arc<FileIntegrityChecker> {
        Arc::clone(&self.inner.lock().checker)
    }

    #[must_use]
    pub fn stats(&self) -> FimStats {
        self.inner.lock().checker.stats()
    }

    /// Observer suitable for [`crate::syscall_audit::SyscallAuditService::set_fim_observer`].
    pub fn syscall_observer(self: &Arc<Self>) -> SyscallFimObserver {
        let this = Arc::clone(self);
        Arc::new(move |sandbox_id: &str, event: &SyscallEvent| {
            let _ = this.observe_syscall_event(sandbox_id, event);
        })
    }

    /// Register a sandbox. Optional `image_paths` merge into the system baseline.
    pub fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: u64,
        image_paths: Option<&[String]>,
    ) {
        let baseline = match image_paths {
            Some(paths) if !paths.is_empty() => {
                Some(IntegrityBaseline::system_with_image_paths(paths))
            }
            _ => None,
        };

        let mut inner = self.inner.lock();
        if let Some(mon) = inner.monitor.as_mut() {
            if let Err(err) =
                mon.register_sandbox(sandbox_id, cgroup_id, self.default_mode, baseline.clone())
            {
                warn!(
                    sandbox_id,
                    cgroup_id,
                    error = %err,
                    "failed to register sandbox for file integrity (eBPF)"
                );
                inner
                    .checker
                    .register_sandbox(sandbox_id, cgroup_id, self.default_mode, baseline);
                return;
            }
        } else {
            inner
                .checker
                .register_sandbox(sandbox_id, cgroup_id, self.default_mode, baseline);
        }

        info!(
            sandbox_id,
            cgroup_id,
            mode = self.default_mode.as_str(),
            "sandbox registered for file integrity monitoring"
        );
    }

    pub fn unregister_sandbox(&self, sandbox_id: &str, cgroup_id: u64) {
        let mut inner = self.inner.lock();
        if let Some(mon) = inner.monitor.as_mut() {
            if let Err(err) = mon.unregister_sandbox(sandbox_id, cgroup_id) {
                warn!(
                    sandbox_id,
                    cgroup_id,
                    error = %err,
                    "failed to unregister sandbox file integrity"
                );
            }
        } else {
            inner.checker.unregister_sandbox(sandbox_id);
        }
    }

    /// Bridge syscall audit open/openat events into FIM alerts.
    pub fn observe_syscall_event(
        &self,
        sandbox_id: &str,
        event: &SyscallEvent,
    ) -> Option<FimAlert> {
        let inner = self.inner.lock();
        let alert = inner.checker.observe_syscall_event(sandbox_id, event)?;
        if let Some(mon) = inner.monitor.as_ref() {
            mon.emit_alert(&alert);
        } else {
            pico_runtime_hardening::telemetry::emit_file_integrity_alert(&alert);
        }
        Some(alert)
    }

    pub fn active(&self) -> bool {
        true
    }
}

impl Drop for FileIntegrityService {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if let Some(tx) = inner.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

fn parse_fim_mode() -> FimMode {
    match std::env::var("PICO_FIM_MODE") {
        Ok(v) if v.eq_ignore_ascii_case("enforce") || v == "1" => FimMode::Enforce,
        _ => FimMode::Audit,
    }
}

/// Build optional image/SBOM integrity path extras for a sandbox.
///
/// Sources (merged, de-duplicated):
/// * `PICO_FIM_EXTRA_PATHS` (comma or colon separated host-wide extras)
/// * Guest-agent install paths when `image_id` is present
/// * Explicit `extra` slice (e.g. future SBOM-derived paths)
pub fn integrity_paths_for_image(
    image_id: Option<&str>,
    extra: Option<&[String]>,
) -> Option<Vec<String>> {
    let mut paths: Vec<String> = Vec::new();

    if let Ok(env_paths) = std::env::var("PICO_FIM_EXTRA_PATHS") {
        for p in env_paths.split([',', ':']) {
            let t = p.trim();
            if !t.is_empty() {
                paths.push(t.to_string());
            }
        }
    }

    if image_id.is_some() {
        // Convention paths for PicoCompute guest images (SBOM-adjacent integrity).
        for p in [
            "/usr/local/bin/pico-guest-agent",
            "/opt/pico/guest-agent",
            "/usr/bin/pico-guest-agent",
        ] {
            paths.push(p.to_string());
        }
    }

    if let Some(extra) = extra {
        for p in extra {
            if !p.is_empty() {
                paths.push(p.clone());
            }
        }
    }

    paths.sort_unstable();
    paths.dedup();
    if paths.is_empty() { None } else { Some(paths) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_runtime_hardening::ebpf::syscall::{SYSCALL_OPENAT, SyscallEvent};
    use pico_runtime_hardening::fim::O_WRONLY;

    #[test]
    fn try_start_and_alert_on_passwd_write() {
        let svc = FileIntegrityService::try_start();
        svc.register_sandbox("sb-fim", 99, None);

        let event = SyscallEvent {
            cgroup_id: 99,
            pid: 10,
            tid: 10,
            uid: 0,
            gid: 0,
            syscall_name: "openat".into(),
            syscall_nr: SYSCALL_OPENAT,
            timestamp_ns: 123,
            arg0: 0,
            arg1: 0,
            arg2: O_WRONLY,
            arg3: 0,
            retval: -1,
            string_arg0: Some("/etc/passwd".into()),
            string_arg1: None,
            is_enter: true,
        };

        let alert = svc
            .observe_syscall_event("sb-fim", &event)
            .expect("passwd write must alert");
        assert_eq!(alert.path, "/etc/passwd");
        assert_eq!(alert.sandbox_id, "sb-fim");
        assert_eq!(alert.pid, 10);

        svc.unregister_sandbox("sb-fim", 99);
    }

    #[test]
    fn image_paths_extend_baseline() {
        let svc = FileIntegrityService::try_start();
        let paths = vec!["/opt/app/bin".to_string()];
        svc.register_sandbox("sb-img", 1, Some(&paths));
        let event = SyscallEvent {
            cgroup_id: 1,
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_name: "openat".into(),
            syscall_nr: SYSCALL_OPENAT,
            timestamp_ns: 1,
            arg0: 0,
            arg1: 0,
            arg2: O_WRONLY,
            arg3: 0,
            retval: -1,
            string_arg0: Some("/opt/app/bin/tool".into()),
            string_arg1: None,
            is_enter: true,
        };
        assert!(svc.observe_syscall_event("sb-img", &event).is_some());
        svc.unregister_sandbox("sb-img", 1);
    }

    #[test]
    fn integrity_paths_for_image_includes_guest_agent() {
        let paths = integrity_paths_for_image(Some("img-alpine"), None).expect("paths");
        assert!(paths.iter().any(|p| p.contains("pico-guest-agent")));
    }

    #[test]
    fn syscall_observer_bridges_openat() {
        let svc = FileIntegrityService::try_start();
        svc.register_sandbox("sb-bridge", 3, None);
        let obs = svc.syscall_observer();
        let event = SyscallEvent {
            cgroup_id: 3,
            pid: 2,
            tid: 2,
            uid: 0,
            gid: 0,
            syscall_name: "openat".into(),
            syscall_nr: SYSCALL_OPENAT,
            timestamp_ns: 1,
            arg0: 0,
            arg1: 0,
            arg2: O_WRONLY,
            arg3: 0,
            retval: -1,
            string_arg0: Some("/etc/shadow".into()),
            string_arg1: None,
            is_enter: true,
        };
        obs("sb-bridge", &event);
        assert!(svc.stats().alerts >= 1);
        svc.unregister_sandbox("sb-bridge", 3);
    }
}
