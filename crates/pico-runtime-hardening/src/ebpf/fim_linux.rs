//! Linux eBPF LSM loader for file integrity monitoring.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use aya::{
    Btf, Ebpf, Pod, include_bytes_aligned,
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    programs::Lsm,
};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::fim::{
    FIM_BPF_PATH_KEY_LEN, FIM_MAX_PATHS_PER_SANDBOX, FimPathKey, FimSandboxConfig, RawFimEvent,
};
use crate::fim::{
    FileIntegrityChecker, FimAlert, FimHook, FimMode, FimProcessInfo, FimStats, IntegrityBaseline,
};
use crate::telemetry::emit_file_integrity_alert;

unsafe impl Pod for FimSandboxConfig {}
unsafe impl Pod for FimPathKey {}
unsafe impl Pod for RawFimEvent {}

const LSM_HOOKS: &[(&str, &str)] = &[
    ("pico_lsm_file_open", "file_open"),
    ("pico_lsm_inode_permission", "inode_permission"),
    ("pico_lsm_inode_unlink", "inode_unlink"),
];

/// eBPF-backed file integrity monitor (BPF LSM + userspace checker).
pub struct EbpfFileIntegrityMonitor {
    bpf: Ebpf,
    checker: Arc<FileIntegrityChecker>,
    /// Paths currently installed in the PROTECTED_PATHS map, keyed by cgroup.
    installed_paths: HashMap<u64, Vec<String>>,
    active_sandboxes: Arc<RwLock<HashMap<String, u64>>>,
    /// FIM ring-buffer entries dropped (undersized), exposed for metrics.
    dropped_events: Arc<AtomicU64>,
}

impl EbpfFileIntegrityMonitor {
    pub fn load() -> Result<Self, String> {
        let bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pico_syscall_audit.bpf.o"));

        if bytes.is_empty() || bytes.len() < 64 {
            return Err("eBPF bytecode is empty (stub build)".into());
        }

        let mut bpf = Ebpf::load(bytes).map_err(|e| format!("failed to load eBPF ELF: {e}"))?;
        let btf = Btf::from_sys_fs().map_err(|e| format!("failed to load host BTF: {e}"))?;

        for (prog_name, hook_name) in LSM_HOOKS {
            let program: &mut Lsm = bpf
                .program_mut(prog_name)
                .ok_or_else(|| format!("{prog_name} program not found in eBPF bytecode"))?
                .try_into()
                .map_err(|e| format!("{prog_name} is not an LSM program: {e}"))?;
            program
                .load(hook_name, &btf)
                .map_err(|e| format!("failed to load LSM hook {hook_name}: {e}"))?;
            let link_id = program
                .attach()
                .map_err(|e| format!("failed to attach LSM hook {hook_name}: {e}"))?;
            info!(
                program = prog_name,
                hook = hook_name,
                link_id = ?link_id,
                "attached BPF LSM file integrity hook"
            );
        }

        info!("eBPF file integrity monitor loaded");
        Ok(Self {
            bpf,
            checker: Arc::new(FileIntegrityChecker::with_defaults()),
            installed_paths: HashMap::new(),
            active_sandboxes: Arc::new(RwLock::new(HashMap::new())),
            dropped_events: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn with_checker(checker: Arc<FileIntegrityChecker>) -> Result<Self, String> {
        let mut mon = Self::load()?;
        mon.checker = checker;
        Ok(mon)
    }

    pub fn checker(&self) -> Arc<FileIntegrityChecker> {
        Arc::clone(&self.checker)
    }

    /// Update default mode without dropping existing sandbox registrations.
    pub fn set_default_mode(&self, mode: FimMode) {
        self.checker.set_default_mode(mode);
    }

    #[must_use]
    pub fn stats(&self) -> FimStats {
        let s = self.checker.stats();
        FimStats {
            dropped_events: self.dropped_events(),
            ..s
        }
    }

    /// Register sandbox in userspace and program BPF maps.
    pub fn register_sandbox(
        &mut self,
        sandbox_id: &str,
        cgroup_id: u64,
        mode: FimMode,
        baseline: Option<IntegrityBaseline>,
    ) -> Result<(), String> {
        self.checker
            .register_sandbox(sandbox_id, cgroup_id, mode, baseline);
        self.active_sandboxes
            .write()
            .insert(sandbox_id.to_string(), cgroup_id);

        let paths = self
            .checker
            .bpf_config_for(sandbox_id)
            .map(|(_, _, p)| p)
            .unwrap_or_default();
        self.configure_bpf(cgroup_id, true, mode, &paths)?;
        Ok(())
    }

    pub fn unregister_sandbox(&mut self, sandbox_id: &str, cgroup_id: u64) -> Result<(), String> {
        self.checker.unregister_sandbox(sandbox_id);
        self.active_sandboxes.write().remove(sandbox_id);
        self.configure_bpf(cgroup_id, false, FimMode::Audit, &[])?;
        Ok(())
    }

    /// Update `FIM_CONFIG` and `PROTECTED_PATHS` for a cgroup.
    pub fn configure_bpf(
        &mut self,
        cgroup_id: u64,
        enabled: bool,
        mode: FimMode,
        paths: &[String],
    ) -> Result<(), String> {
        {
            let mut config_map: BpfHashMap<&mut MapData, u64, FimSandboxConfig> =
                BpfHashMap::try_from(
                    self.bpf
                        .map_mut("FIM_CONFIG")
                        .ok_or_else(|| "FIM_CONFIG map not found".to_string())?,
                )
                .map_err(|e| format!("failed to open FIM_CONFIG map: {e}"))?;

            if enabled {
                let config = FimSandboxConfig {
                    enabled: 1,
                    mode: mode as u8,
                    _pad: [0u8; 6],
                };
                config_map
                    .insert(cgroup_id, config, 0)
                    .map_err(|e| format!("failed to insert FIM_CONFIG: {e}"))?;
            } else {
                let _ = config_map.remove(&cgroup_id);
            }
        }

        self.sync_protected_paths(cgroup_id, if enabled { paths } else { &[] })?;

        debug!(
            cgroup_id,
            enabled,
            mode = mode.as_str(),
            path_count = paths.len(),
            "FIM BPF config updated"
        );
        Ok(())
    }

    fn sync_protected_paths(&mut self, cgroup_id: u64, paths: &[String]) -> Result<(), String> {
        let mut path_map: BpfHashMap<&mut MapData, FimPathKey, u8> = BpfHashMap::try_from(
            self.bpf
                .map_mut("PROTECTED_PATHS")
                .ok_or_else(|| "PROTECTED_PATHS map not found".to_string())?,
        )
        .map_err(|e| format!("failed to open PROTECTED_PATHS map: {e}"))?;

        if let Some(old) = self.installed_paths.remove(&cgroup_id) {
            for p in old {
                let key = FimPathKey::from_path(cgroup_id, &p);
                let _ = path_map.remove(&key);
            }
        }

        if paths.len() > FIM_MAX_PATHS_PER_SANDBOX {
            let excess = (paths.len() - FIM_MAX_PATHS_PER_SANDBOX) as u64;
            self.checker.record_paths_capped(excess);
            warn!(
                cgroup_id,
                path_count = paths.len(),
                cap = FIM_MAX_PATHS_PER_SANDBOX,
                "FIM protected paths truncated to per-sandbox cap"
            );
        }

        let mut installed = Vec::with_capacity(paths.len().min(FIM_MAX_PATHS_PER_SANDBOX));
        for path in paths.iter().take(FIM_MAX_PATHS_PER_SANDBOX) {
            if path.len() > FIM_BPF_PATH_KEY_LEN {
                warn!(
                    cgroup_id,
                    path_len = path.len(),
                    key_len = FIM_BPF_PATH_KEY_LEN,
                    "FIM path exceeds BPF key length; truncated in map key"
                );
            }
            let key = FimPathKey::from_path(cgroup_id, path);
            match path_map.insert(key, 1u8, 0) {
                Ok(()) => installed.push(path.clone()),
                Err(e) => {
                    self.checker.record_map_insert_failure();
                    warn!(
                        cgroup_id,
                        path = %path,
                        error = %e,
                        "failed to insert FIM protected path into BPF map"
                    );
                }
            }
        }
        if !installed.is_empty() {
            self.installed_paths.insert(cgroup_id, installed);
        }
        Ok(())
    }

    pub(crate) fn run_event_loop(
        &mut self,
        tx: mpsc::UnboundedSender<RawFimEvent>,
        shutdown: tokio::sync::watch::Receiver<bool>,
        dropped: Arc<AtomicU64>,
    ) -> Result<std::thread::JoinHandle<()>, String> {
        let ring_buf_map = self
            .bpf
            .take_map("FIM_RING_BUF")
            .ok_or_else(|| "FIM_RING_BUF map not found".to_string())?;

        let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(ring_buf_map)
            .map_err(|e| format!("failed to create FIM ring buffer reader: {e}"))?;

        let handle = thread::Builder::new()
            .name("ebpf-fim-ringbuf".into())
            .spawn(move || {
                info!("eBPF FIM ring buffer consumer thread started");
                loop {
                    if *shutdown.borrow() {
                        info!("shutdown signal received, stopping FIM ring buffer consumer");
                        break;
                    }

                    let mut consumed = false;
                    while let Some(item) = ring_buf.next() {
                        consumed = true;
                        let data: &[u8] = &item;
                        if data.len() < std::mem::size_of::<RawFimEvent>() {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            warn!(len = data.len(), "FIM ring buffer entry too small");
                            continue;
                        }
                        let raw = unsafe { *(data.as_ptr() as *const RawFimEvent) };
                        if tx.send(raw).is_err() {
                            warn!("FIM event channel closed");
                            return;
                        }
                    }

                    if !consumed {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                info!("eBPF FIM ring buffer consumer thread stopped");
            })
            .map_err(|e| format!("failed to spawn FIM ring buffer thread: {e}"))?;

        Ok(handle)
    }

    pub fn run_consumer(
        &mut self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(std::thread::JoinHandle<()>, tokio::task::JoinHandle<()>), String> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let checker = Arc::clone(&self.checker);
        let sandboxes = Arc::clone(&self.active_sandboxes);
        let dropped = Arc::clone(&self.dropped_events);
        let ring_thread = self.run_event_loop(tx, shutdown, dropped)?;

        let consumer = tokio::spawn(async move {
            info!("eBPF FIM consumer task started");
            while let Some(event) = rx.recv().await {
                let sandbox_id = {
                    let guard = sandboxes.read();
                    guard
                        .iter()
                        .find(|(_, cid)| **cid == event.cgroup_id)
                        .map(|(id, _)| id.clone())
                        .or_else(|| checker.sandbox_for_cgroup(event.cgroup_id))
                        .unwrap_or_else(|| format!("cgroup-{}", event.cgroup_id))
                };

                let path = event.path_string();
                if path.is_empty() {
                    if event.hook == FimHook::FileOpen as u8 {
                        checker.record_path_resolution_failure();
                        warn!(
                            cgroup_id = event.cgroup_id,
                            pid = event.pid,
                            "FIM file_open path resolution failed; fail-open (no deny)"
                        );
                    } else {
                        debug!(
                            cgroup_id = event.cgroup_id,
                            hook = event.hook,
                            "FIM event without path; skipping baseline match"
                        );
                    }
                    continue;
                }

                if let Some(alert) = checker.check_raw_event(
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
                ) {
                    emit_file_integrity_alert(&alert);
                }
            }
            info!("eBPF FIM consumer task stopped");
        });

        Ok((ring_thread, consumer))
    }

    pub fn handle_raw_event(&self, event: &RawFimEvent) -> Option<FimAlert> {
        let sandbox_id = self
            .checker
            .sandbox_for_cgroup(event.cgroup_id)
            .unwrap_or_else(|| format!("cgroup-{}", event.cgroup_id));
        let path = event.path_string();
        if path.is_empty() {
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
        self.active_sandboxes.read().len()
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

impl Drop for EbpfFileIntegrityMonitor {
    fn drop(&mut self) {
        info!(
            sandbox_count = self.active_sandbox_count(),
            alerts = self.checker.alert_count(),
            dropped_events = self.dropped_events(),
            "eBPF file integrity monitor shutting down"
        );
    }
}
