use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::Arc, thread, time::Duration};

use aya::{
    Ebpf, Pod, include_bytes_aligned,
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    programs::RawTracePoint,
};
use parking_lot::RwLock;
use pico_telemetry::events::SecurityEvent;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::SyscallFimObserver;
use super::syscall::{
    MONITORED_SYSCALL_COUNT, RawSyscallEvent, SandboxAuditConfig, SyscallCountKey, SyscallEvent,
};
use crate::anomaly::{AnomalyDetector, DetectorConfig};
use crate::telemetry::emit_behavioral_anomaly;

unsafe impl Pod for SandboxAuditConfig {}
unsafe impl Pod for SyscallCountKey {}

pub struct EbpfSyscallMonitor {
    bpf: Ebpf,
    active_sandboxes: Arc<RwLock<HashMap<String, u64>>>,
    sandbox_types: Arc<RwLock<HashMap<String, String>>>,
    anomaly_detector: Arc<AnomalyDetector>,
    dropped_events: Arc<AtomicU64>,
    /// FIM bridge; may be installed after the consumer starts.
    fim_observer: Arc<RwLock<Option<SyscallFimObserver>>>,
}

impl EbpfSyscallMonitor {
    pub fn load() -> Result<Self, String> {
        let bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pico_syscall_audit.bpf.o"));

        if bytes.is_empty() || bytes.len() < 64 {
            return Err("eBPF bytecode is empty (stub build)".into());
        }

        let mut bpf = Ebpf::load(bytes).map_err(|e| format!("failed to load eBPF ELF: {e}"))?;

        let sys_enter: &mut RawTracePoint = bpf
            .program_mut("pico_tp_sys_enter")
            .ok_or_else(|| "pico_tp_sys_enter program not found in eBPF bytecode".to_string())?
            .try_into()
            .map_err(|e| format!("pico_tp_sys_enter is not a raw tracepoint: {e}"))?;
        sys_enter
            .load()
            .map_err(|e| format!("failed to load sys_enter tracepoint: {e}"))?;
        let link_id = sys_enter
            .attach("sys_enter")
            .map_err(|e| format!("failed to attach sys_enter tracepoint: {e}"))?;
        info!(link_id = ?link_id, "attached pico_tp_sys_enter raw tracepoint");

        let sys_exit: &mut RawTracePoint = bpf
            .program_mut("pico_tp_sys_exit")
            .ok_or_else(|| "pico_tp_sys_exit program not found in eBPF bytecode".to_string())?
            .try_into()
            .map_err(|e| format!("pico_tp_sys_exit is not a raw tracepoint: {e}"))?;
        sys_exit
            .load()
            .map_err(|e| format!("failed to load sys_exit tracepoint: {e}"))?;
        let link_id = sys_exit
            .attach("sys_exit")
            .map_err(|e| format!("failed to attach sys_exit tracepoint: {e}"))?;
        info!(link_id = ?link_id, "attached pico_tp_sys_exit raw tracepoint");

        info!("eBPF syscall audit monitor loaded");
        Ok(Self {
            bpf,
            active_sandboxes: Arc::new(RwLock::new(HashMap::new())),
            sandbox_types: Arc::new(RwLock::new(HashMap::new())),
            anomaly_detector: Arc::new(AnomalyDetector::with_defaults()),
            dropped_events: Arc::new(AtomicU64::new(0)),
            fim_observer: Arc::new(RwLock::new(None)),
        })
    }

    /// Install or replace the FIM observer (safe after `run_consumer`).
    pub fn set_fim_observer(&self, observer: SyscallFimObserver) {
        *self.fim_observer.write() = Some(observer);
    }

    /// Manually feed a syscall event through the FIM observer (tests / bridge).
    pub fn observe_fim(&self, sandbox_id: &str, event: &SyscallEvent) {
        if let Some(obs) = self.fim_observer.read().as_ref() {
            obs(sandbox_id, event);
        }
    }

    /// Replace anomaly detector config. Call before `run_consumer`.
    pub fn set_anomaly_config(&mut self, config: DetectorConfig) {
        self.anomaly_detector = Arc::new(AnomalyDetector::new(config));
    }

    pub fn anomaly_detector(&self) -> Arc<AnomalyDetector> {
        Arc::clone(&self.anomaly_detector)
    }

    pub fn configure_sandbox(
        &mut self,
        cgroup_id: u64,
        enabled: bool,
        sample_rate: u32,
    ) -> Result<(), String> {
        let mut config_map: BpfHashMap<&mut MapData, u64, SandboxAuditConfig> =
            BpfHashMap::try_from(
                self.bpf
                    .map_mut("AUDIT_CONFIG")
                    .ok_or_else(|| "AUDIT_CONFIG map not found".to_string())?,
            )
            .map_err(|e| format!("failed to open AUDIT_CONFIG map: {e}"))?;

        let config = SandboxAuditConfig {
            enabled: u8::from(enabled),
            _pad: [0u8; 3],
            sample_rate,
        };

        config_map
            .insert(cgroup_id, config, 0)
            .map_err(|e| format!("failed to insert sandbox audit config: {e}"))?;

        debug!(
            cgroup_id,
            enabled, sample_rate, "sandbox audit config updated"
        );
        Ok(())
    }

    pub fn remove_sandbox(&mut self, cgroup_id: u64) -> Result<(), String> {
        let mut config_map: BpfHashMap<&mut MapData, u64, SandboxAuditConfig> =
            BpfHashMap::try_from(
                self.bpf
                    .map_mut("AUDIT_CONFIG")
                    .ok_or_else(|| "AUDIT_CONFIG map not found".to_string())?,
            )
            .map_err(|e| format!("failed to open AUDIT_CONFIG map: {e}"))?;

        config_map
            .remove(&cgroup_id)
            .map_err(|e| format!("failed to remove sandbox audit config: {e}"))?;

        info!(cgroup_id, "sandbox audit config removed");
        Ok(())
    }

    pub(crate) fn run_event_loop(
        &mut self,
        tx: mpsc::UnboundedSender<SyscallEvent>,
        shutdown: tokio::sync::watch::Receiver<bool>,
        dropped: Arc<AtomicU64>,
    ) -> Result<std::thread::JoinHandle<()>, String> {
        let ring_buf_map = self
            .bpf
            .take_map("RING_BUF")
            .ok_or_else(|| "RING_BUF map not found".to_string())?;

        let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(ring_buf_map)
            .map_err(|e| format!("failed to create ring buffer reader: {e}"))?;

        let handle = thread::Builder::new()
            .name("ebpf-syscall-ringbuf".into())
            .spawn(move || {
                info!("eBPF ring buffer consumer thread started");

                loop {
                    if *shutdown.borrow() {
                        info!("shutdown signal received, stopping ring buffer consumer");
                        break;
                    }

                    let mut consumed = false;
                    while let Some(item) = ring_buf.next() {
                        consumed = true;
                        let data: &[u8] = &item;
                        if data.len() < std::mem::size_of::<RawSyscallEvent>() {
                            warn!(
                                len = data.len(),
                                "ring buffer entry too small for RawSyscallEvent"
                            );
                            dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        let raw = unsafe { &*(data.as_ptr() as *const RawSyscallEvent) };
                        let event = SyscallEvent::from_raw(*raw);

                        debug!(
                            syscall = %event.syscall_name,
                            pid = event.pid,
                            cgroup_id = event.cgroup_id,
                            is_enter = event.is_enter,
                            "syscall event read from ring buffer"
                        );

                        if tx.send(event).is_err() {
                            warn!("event channel closed, stopping ring buffer consumer");
                            dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }

                    if !consumed {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                info!("eBPF ring buffer consumer thread stopped");
            })
            .map_err(|e| format!("failed to spawn ring buffer thread: {e}"))?;

        Ok(handle)
    }

    pub fn run_consumer(
        &mut self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(std::thread::JoinHandle<()>, tokio::task::JoinHandle<()>), String> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let dropped = Arc::clone(&self.dropped_events);
        let sandboxes = Arc::clone(&self.active_sandboxes);
        let sandbox_types = Arc::clone(&self.sandbox_types);
        let detector = Arc::clone(&self.anomaly_detector);
        let fim_observer = Arc::clone(&self.fim_observer);
        let ring_thread = self.run_event_loop(tx, shutdown, dropped)?;

        let consumer = tokio::spawn(async move {
            info!("eBPF syscall audit consumer task started");
            while let Some(event) = rx.recv().await {
                let sandbox_id = resolve_sandbox_id(&sandboxes, event.cgroup_id);

                SecurityEvent::syscall_audit_event(
                    &sandbox_id,
                    &event.syscall_name,
                    event.pid,
                    event.tid,
                    event.uid,
                    event.gid,
                    event.arg0,
                    event.arg1,
                    event.arg2,
                    event.arg3,
                    event.retval,
                    event.timestamp_ns,
                    event.string_arg0.as_ref().map(|s| s.to_string()),
                    event.is_enter,
                )
                .emit();

                ensure_sandbox_registered(&detector, &sandbox_types, &sandbox_id);
                for anomaly in detector.observe(&sandbox_id, &event) {
                    emit_behavioral_anomaly(&anomaly);
                }

                // Feed open/openat write-intent events into FIM.
                if let Some(obs) = fim_observer.read().as_ref() {
                    obs(&sandbox_id, &event);
                }
            }
            info!("eBPF syscall audit consumer task stopped");
        });

        Ok((ring_thread, consumer))
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn associate_sandbox(&self, sandbox_id: &str, cgroup_id: u64) {
        self.active_sandboxes
            .write()
            .insert(sandbox_id.to_string(), cgroup_id);
    }

    /// Associate a sandbox with a type key used for shared baseline learning.
    ///
    /// Prefer [`Self::register_sandbox_audit`] at create time so cgroup and type
    /// are set together. Use [`crate::anomaly::sandbox_type_key`] for the key.
    pub fn associate_sandbox_type(&self, sandbox_id: &str, sandbox_type: &str) {
        self.sandbox_types
            .write()
            .insert(sandbox_id.to_string(), sandbox_type.to_string());
        self.anomaly_detector
            .register_sandbox(sandbox_id, sandbox_type);
    }

    /// Canonical sandbox create-path registration for audit + anomaly detection.
    ///
    /// Call from host/runtime lifecycle when the sandbox cgroup is known:
    /// 1. `sandbox_type` from [`crate::anomaly::sandbox_type_key`]
    /// 2. enable audit config in BPF
    /// 3. map sandbox id to cgroup for event correlation
    pub fn register_sandbox_audit(
        &mut self,
        sandbox_id: &str,
        cgroup_id: u64,
        sandbox_type: &str,
        enabled: bool,
        sample_rate: u32,
    ) -> Result<(), String> {
        self.configure_sandbox(cgroup_id, enabled, sample_rate)?;
        self.associate_sandbox(sandbox_id, cgroup_id);
        self.associate_sandbox_type(sandbox_id, sandbox_type);
        Ok(())
    }

    /// Tear down audit config and detector state for a destroyed sandbox.
    pub fn unregister_sandbox_audit(
        &mut self,
        sandbox_id: &str,
        cgroup_id: u64,
    ) -> Result<(), String> {
        let remove_result = self.remove_sandbox(cgroup_id);
        self.dissociate_sandbox(sandbox_id);
        remove_result
    }

    pub fn dissociate_sandbox(&self, sandbox_id: &str) {
        self.active_sandboxes.write().remove(sandbox_id);
        self.sandbox_types.write().remove(sandbox_id);
        self.anomaly_detector.unregister_sandbox(sandbox_id);
    }

    pub fn active_sandbox_count(&self) -> usize {
        self.active_sandboxes.read().len()
    }

    /// Read one per-sandbox histogram counter from the `SYSCALL_COUNTS` BPF map.
    pub fn syscall_count(&self, cgroup_id: u64, syscall_nr: u32) -> Result<u64, String> {
        let map = self
            .bpf
            .map("SYSCALL_COUNTS")
            .ok_or_else(|| "SYSCALL_COUNTS map not found".to_string())?;
        let counts: BpfHashMap<&MapData, SyscallCountKey, u64> = BpfHashMap::try_from(map)
            .map_err(|e| format!("failed to open SYSCALL_COUNTS map: {e}"))?;
        let key = SyscallCountKey {
            cgroup_id,
            syscall_nr,
            _pad: 0,
        };
        match counts.get(&key, 0) {
            Ok(v) => Ok(v),
            Err(_) => Ok(0),
        }
    }

    /// Snapshot histogram counts for every monitored syscall type id.
    pub fn syscall_histogram(&self, cgroup_id: u64) -> Result<Vec<(u32, u64)>, String> {
        let mut out = Vec::with_capacity(MONITORED_SYSCALL_COUNT);
        for nr in 0..MONITORED_SYSCALL_COUNT as u32 {
            out.push((nr, self.syscall_count(cgroup_id, nr)?));
        }
        Ok(out)
    }
}

fn resolve_sandbox_id(sandboxes: &Arc<RwLock<HashMap<String, u64>>>, cgroup_id: u64) -> String {
    let guard = sandboxes.read();
    for (sandbox_id, cid) in guard.iter() {
        if *cid == cgroup_id {
            return sandbox_id.clone();
        }
    }
    format!("cgroup-{cgroup_id}")
}

fn ensure_sandbox_registered(
    detector: &AnomalyDetector,
    sandbox_types: &RwLock<HashMap<String, String>>,
    sandbox_id: &str,
) {
    if detector.is_registered(sandbox_id) {
        return;
    }
    let type_key = sandbox_types
        .read()
        .get(sandbox_id)
        .cloned()
        .unwrap_or_else(|| sandbox_id.to_string());
    detector.register_sandbox(sandbox_id, &type_key);
}

impl Drop for EbpfSyscallMonitor {
    fn drop(&mut self) {
        let drops = self.dropped_events();
        info!(
            sandbox_count = self.active_sandbox_count(),
            dropped_events = drops,
            "eBPF syscall audit monitor shutting down"
        );
    }
}
