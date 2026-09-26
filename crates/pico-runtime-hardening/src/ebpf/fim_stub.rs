//! Non-Linux / no-feature stub for the FIM eBPF monitor.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::fim::RawFimEvent;
use crate::fim::{
    FileIntegrityChecker, FimAlert, FimHook, FimMode, FimProcessInfo, FimStats, IntegrityBaseline,
};
use crate::telemetry::emit_file_integrity_alert;

/// Stub FIM monitor: full userspace checker, no BPF LSM attach.
pub struct EbpfFileIntegrityMonitor {
    checker: Arc<FileIntegrityChecker>,
}

impl EbpfFileIntegrityMonitor {
    pub fn load() -> Result<Self, String> {
        Ok(Self {
            checker: Arc::new(FileIntegrityChecker::with_defaults()),
        })
    }

    pub fn with_checker(checker: Arc<FileIntegrityChecker>) -> Self {
        Self { checker }
    }

    pub fn checker(&self) -> Arc<FileIntegrityChecker> {
        Arc::clone(&self.checker)
    }

    pub fn set_default_mode(&self, mode: FimMode) {
        self.checker.set_default_mode(mode);
    }

    #[must_use]
    pub fn stats(&self) -> FimStats {
        self.checker.stats()
    }

    pub fn register_sandbox(
        &mut self,
        sandbox_id: &str,
        cgroup_id: u64,
        mode: FimMode,
        baseline: Option<IntegrityBaseline>,
    ) -> Result<(), String> {
        self.checker
            .register_sandbox(sandbox_id, cgroup_id, mode, baseline);
        Ok(())
    }

    pub fn unregister_sandbox(&mut self, sandbox_id: &str, _cgroup_id: u64) -> Result<(), String> {
        self.checker.unregister_sandbox(sandbox_id);
        Ok(())
    }

    pub fn configure_bpf(
        &mut self,
        _cgroup_id: u64,
        _enabled: bool,
        _mode: FimMode,
        _paths: &[String],
    ) -> Result<(), String> {
        Err("eBPF file integrity not available on this platform".into())
    }

    pub fn run_consumer(
        &mut self,
        _shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(std::thread::JoinHandle<()>, tokio::task::JoinHandle<()>), String> {
        Err("eBPF file integrity not available on this platform".into())
    }

    pub fn handle_raw_event(&self, event: &RawFimEvent) -> Option<FimAlert> {
        let sandbox_id = self
            .checker
            .sandbox_for_cgroup(event.cgroup_id)
            .unwrap_or_else(|| format!("cgroup-{}", event.cgroup_id));
        let path = event.path_string();
        if path.is_empty() {
            if event.hook == FimHook::FileOpen as u8 {
                self.checker.record_path_resolution_failure();
            }
            return None;
        }
        let alert = self.checker.check_raw_event(
            &sandbox_id,
            &path,
            FimHook::from_u8(event.hook),
            FimProcessInfo {
                pid: event.pid,
                tid: event.tid,
                uid: event.uid,
                gid: event.gid,
                cgroup_id: event.cgroup_id,
                timestamp_ns: event.timestamp_ns,
            },
            event.denied != 0,
        )?;
        emit_file_integrity_alert(&alert);
        Some(alert)
    }

    pub fn emit_alert(&self, alert: &FimAlert) {
        emit_file_integrity_alert(alert);
    }

    pub fn active_sandbox_count(&self) -> usize {
        self.checker.active_sandbox_count()
    }

    pub fn dropped_events(&self) -> u64 {
        0
    }

    #[expect(
        dead_code,
        reason = "mirrors linux API; unused when ringbuf path is unavailable"
    )]
    pub(crate) fn run_event_loop(
        &mut self,
        _tx: mpsc::UnboundedSender<RawFimEvent>,
        _shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<std::thread::JoinHandle<()>, String> {
        Err("eBPF file integrity not available on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::fim::{FIM_MAX_PATH_LEN, RawFimEvent};
    #[test]
    fn load_and_register_userspace() {
        let mut mon = EbpfFileIntegrityMonitor::load().expect("load");
        mon.register_sandbox("sb", 7, FimMode::Audit, None)
            .expect("register");
        assert_eq!(mon.active_sandbox_count(), 1);
        assert!(mon.configure_bpf(7, true, FimMode::Audit, &[]).is_err());
        mon.unregister_sandbox("sb", 7).expect("unregister");
        assert_eq!(mon.active_sandbox_count(), 0);
    }

    #[test]
    fn handle_raw_event_alerts_on_passwd() {
        let mut mon = EbpfFileIntegrityMonitor::load().expect("load");
        mon.register_sandbox("sb-1", 42, FimMode::Enforce, None)
            .expect("register");

        let mut ev = RawFimEvent {
            cgroup_id: 42,
            pid: 9,
            tid: 9,
            uid: 0,
            gid: 0,
            hook: FimHook::FileOpen as u8,
            denied: 1,
            _pad: [0; 2],
            timestamp_ns: 100,
            path_buf: [0; FIM_MAX_PATH_LEN],
            path_len: 0,
            _pad2: [0; 4],
        };
        let p = b"/etc/passwd";
        ev.path_buf[..p.len()].copy_from_slice(p);
        ev.path_len = p.len() as u32;

        let alert = mon.handle_raw_event(&ev).expect("alert");
        assert_eq!(alert.sandbox_id, "sb-1");
        assert_eq!(alert.path, "/etc/passwd");
        assert!(alert.denied);
        assert_eq!(alert.pid, 9);
    }
}
