use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{thread, time::Duration};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    programs::{PerfEvent, RawTracePoint, TracePoint},
};
use parking_lot::{Mutex, RwLock};
use pico_core::SandboxId;
use tracing::{debug, info, warn};

use super::types::{ObservabilityBpfConfig, SyscallLatencyEventBpf};
use crate::{
    CgroupId, CpuSampleEvent, IoSampleEvent, MemorySnapshot, ObservabilityBackend,
    ObservabilityError, SyscallLatencyEvent,
};

pub(super) struct EbpfObservabilityBackend {
    bpf: Mutex<Ebpf>,
    sandboxes: Arc<RwLock<HashMap<SandboxId, CgroupId>>>,
    cgroup_ids: Arc<RwLock<HashMap<CgroupId, SandboxId>>>,
    latency_events: Arc<Mutex<Vec<SyscallLatencyEvent>>>,
    latency_thread: Option<thread::JoinHandle<()>>,
    latency_shutdown: Arc<AtomicU64>,
}

impl EbpfObservabilityBackend {
    pub(super) fn load() -> Result<Self, String> {
        let bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pico_observability.bpf.o"));

        if bytes.is_empty() || bytes.len() < 64 {
            return Err("eBPF bytecode is empty (stub build)".into());
        }

        let mut bpf = Ebpf::load(bytes).map_err(|e| format!("failed to load eBPF ELF: {e}"))?;

        {
            let prog: &mut PerfEvent = bpf
                .program_mut("pico_perf_cpu")
                .ok_or_else(|| "pico_perf_cpu program not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_perf_cpu is not a perf event: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_perf_cpu: {e}"))?;
        }

        {
            let prog: &mut TracePoint = bpf
                .program_mut("pico_tp_block_io_issue")
                .ok_or_else(|| "pico_tp_block_io_issue not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_block_io_issue is not a tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_block_io_issue: {e}"))?;
        }

        {
            let prog: &mut TracePoint = bpf
                .program_mut("pico_tp_block_io_complete")
                .ok_or_else(|| "pico_tp_block_io_complete not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_block_io_complete is not a tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_block_io_complete: {e}"))?;
        }

        {
            let prog: &mut RawTracePoint = bpf
                .program_mut("pico_tp_syscall_enter")
                .ok_or_else(|| "pico_tp_syscall_enter not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_syscall_enter is not a raw tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_syscall_enter: {e}"))?;
            prog.attach("sys_enter")
                .map_err(|e| format!("failed to attach pico_tp_syscall_enter: {e}"))?;
        }

        {
            let prog: &mut RawTracePoint = bpf
                .program_mut("pico_tp_syscall_exit")
                .ok_or_else(|| "pico_tp_syscall_exit not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_syscall_exit is not a raw tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_syscall_exit: {e}"))?;
            prog.attach("sys_exit")
                .map_err(|e| format!("failed to attach pico_tp_syscall_exit: {e}"))?;
        }

        info!("eBPF observability backend loaded");

        let latency_events: Arc<Mutex<Vec<SyscallLatencyEvent>>> = Arc::new(Mutex::new(Vec::new()));

        let sandboxes = Arc::new(RwLock::new(HashMap::new()));
        let cgroup_ids = Arc::new(RwLock::new(HashMap::new()));
        let shutdown = Arc::new(AtomicU64::new(0));

        let latency_thread = spawn_latency_ring_buf_thread(
            &mut bpf,
            latency_events.clone(),
            cgroup_ids.clone(),
            shutdown.clone(),
        )?;

        Ok(Self {
            bpf: Mutex::new(bpf),
            sandboxes,
            cgroup_ids,
            latency_events,
            latency_thread: Some(latency_thread),
            latency_shutdown: shutdown,
        })
    }

    fn update_config(
        &self,
        sandbox_id: &str,
        f: impl FnOnce(&mut ObservabilityBpfConfig),
    ) -> Result<(), ObservabilityError> {
        let cgroup_id = self
            .sandboxes
            .read()
            .get(&SandboxId::from_string(sandbox_id))
            .copied()
            .ok_or_else(|| {
                ObservabilityError::SandboxNotRegistered(Box::new(SandboxId::from_string(
                    sandbox_id,
                )))
            })?;

        let mut guard = self.bpf.lock();
        let mut config_map: BpfHashMap<&mut MapData, u64, ObservabilityBpfConfig> =
            BpfHashMap::try_from(guard.map_mut("OBSERVABILITY_CONFIG").ok_or_else(|| {
                ObservabilityError::Unavailable("OBSERVABILITY_CONFIG map not found".into())
            })?)
            .map_err(|e| ObservabilityError::Unavailable(e.to_string()))?;

        let default_config = ObservabilityBpfConfig {
            cpu_sampling_enabled: 0,
            io_tracing_enabled: 0,
            syscall_latency_enabled: 0,
            syscall_sample_rate: 0,
            sample_rate: 0,
        };
        let mut config = match config_map.get(&cgroup_id, 0) {
            Ok(val) => val,
            Err(aya::maps::MapError::KeyNotFound) => default_config,
            Err(e) => {
                return Err(ObservabilityError::Unavailable(e.to_string()));
            }
        };

        f(&mut config);

        config_map
            .insert(cgroup_id, config, 0)
            .map_err(|e| ObservabilityError::Unavailable(e.to_string()))?;

        Ok(())
    }
}

impl Drop for EbpfObservabilityBackend {
    fn drop(&mut self) {
        self.latency_shutdown.store(1, Ordering::Release);
        if let Some(handle) = self.latency_thread.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_latency_ring_buf_thread(
    bpf: &mut Ebpf,
    latency_events: Arc<Mutex<Vec<SyscallLatencyEvent>>>,
    cgroup_ids: Arc<RwLock<HashMap<CgroupId, SandboxId>>>,
    shutdown: Arc<AtomicU64>,
) -> Result<thread::JoinHandle<()>, String> {
    let ring_buf_map = bpf
        .take_map("SYSCALL_LATENCY_EVENTS")
        .ok_or_else(|| "SYSCALL_LATENCY_EVENTS map not found".to_string())?;

    let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(ring_buf_map)
        .map_err(|e| format!("failed to create ring buffer reader: {e}"))?;

    thread::Builder::new()
        .name("ebpf-syscall-latency-ringbuf".into())
        .spawn(move || {
            info!("eBPF syscall latency ring buffer consumer started");

            loop {
                if shutdown.load(Ordering::Acquire) != 0 {
                    info!("shutdown signal received, stopping latency ring buffer consumer");
                    break;
                }

                let mut consumed = false;
                while let Some(item) = ring_buf.next() {
                    consumed = true;
                    let data: &[u8] = &item;
                    if data.len() < std::mem::size_of::<SyscallLatencyEventBpf>() {
                        warn!(
                            len = data.len(),
                            "ring buffer entry too small for SyscallLatencyEventBpf"
                        );
                        continue;
                    }

                    let raw = unsafe { &*(data.as_ptr() as *const SyscallLatencyEventBpf) };
                    let cgroup_ids = cgroup_ids.read();

                    let event = SyscallLatencyEvent {
                        sandbox_id: cgroup_ids.get(&raw.cgroup_id).cloned().unwrap_or_else(|| {
                            SandboxId::from_string(format!("cgroup-{}", raw.cgroup_id))
                        }),
                        cgroup_id: raw.cgroup_id,
                        pid: raw.pid,
                        tid: raw.tid,
                        syscall_type: raw.syscall_type,
                        enter_ts_ns: raw.enter_ts_ns,
                        latency_ns: raw.latency_ns,
                    };
                    latency_events.lock().push(event);
                }

                if !consumed {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            info!("eBPF syscall latency ring buffer consumer stopped");
        })
        .map_err(|e| format!("failed to spawn latency ring buffer thread: {e}"))
}

impl ObservabilityBackend for EbpfObservabilityBackend {
    fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: CgroupId,
        _cgroup_path: &Path,
    ) -> Result<(), ObservabilityError> {
        let mut guard = self.bpf.lock();
        let mut config_map: BpfHashMap<&mut MapData, u64, ObservabilityBpfConfig> =
            BpfHashMap::try_from(guard.map_mut("OBSERVABILITY_CONFIG").ok_or_else(|| {
                ObservabilityError::Unavailable("OBSERVABILITY_CONFIG map not found".into())
            })?)
            .map_err(|e| ObservabilityError::Unavailable(e.to_string()))?;

        let config = ObservabilityBpfConfig {
            cpu_sampling_enabled: 1,
            io_tracing_enabled: 0,
            syscall_latency_enabled: 0,
            syscall_sample_rate: 0,
            sample_rate: 99,
        };

        config_map
            .insert(cgroup_id, config, 0)
            .map_err(|e| ObservabilityError::Unavailable(e.to_string()))?;

        self.sandboxes
            .write()
            .insert(SandboxId::from_string(sandbox_id), cgroup_id);
        self.cgroup_ids
            .write()
            .insert(cgroup_id, SandboxId::from_string(sandbox_id));

        debug!(
            sandbox_id = %sandbox_id,
            cgroup_id,
            "registered sandbox for eBPF observability"
        );
        Ok(())
    }

    fn unregister_sandbox(&self, sandbox_id: &str) -> Result<(), ObservabilityError> {
        let id = SandboxId::from_string(sandbox_id);
        if let Some(cgroup_id) = self.sandboxes.write().remove(&id) {
            self.cgroup_ids.write().remove(&cgroup_id);
            let mut guard = self.bpf.lock();
            let mut config_map: BpfHashMap<&mut MapData, u64, ObservabilityBpfConfig> =
                BpfHashMap::try_from(guard.map_mut("OBSERVABILITY_CONFIG").ok_or_else(|| {
                    ObservabilityError::Unavailable("OBSERVABILITY_CONFIG map not found".into())
                })?)
                .map_err(|e| ObservabilityError::Unavailable(e.to_string()))?;
            let _ = config_map.remove(&cgroup_id);
        }
        Ok(())
    }

    fn poll_memory(&self, sandbox_id: &str) -> Result<MemorySnapshot, ObservabilityError> {
        // A malicious id must not escape /sys/fs/cgroup/sandbox via `..`.
        // The explicit `contains` guard is what static analysis recognizes.
        if sandbox_id.contains("..") || sandbox_id.contains('/') || sandbox_id.contains('\\') {
            return Err(ObservabilityError::Unavailable(format!(
                "invalid sandbox id: {sandbox_id}"
            )));
        }
        let cgroup_path = Path::new("/sys/fs/cgroup/sandbox").join(sandbox_id);

        let current_bytes = read_cgroup_u64(&cgroup_path, "memory.current")?;
        let swap_bytes = read_cgroup_u64(&cgroup_path, "memory.swap.current")?;
        let oom_kill_count = read_cgroup_oom_kills(&cgroup_path)?;
        let pressure = read_cgroup_memory_pressure(&cgroup_path);

        let anon_bytes = read_cgroup_stat_field(&cgroup_path, "anon");
        let file_bytes = read_cgroup_stat_field(&cgroup_path, "file");
        let rss_bytes = anon_bytes + file_bytes;

        Ok(MemorySnapshot {
            sandbox_id: SandboxId::from_string(sandbox_id),
            current_bytes,
            rss_bytes,
            anon_bytes,
            file_bytes,
            swap_bytes,
            oom_kill_count,
            memory_pressure_some_avg10: pressure,
        })
    }

    fn enable_cpu_profiling(
        &self,
        sandbox_id: &str,
        sample_hz: u32,
    ) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.cpu_sampling_enabled = 1;
            config.sample_rate = sample_hz;
        })
    }

    fn disable_cpu_profiling(&self, sandbox_id: &str) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.cpu_sampling_enabled = 0;
            config.sample_rate = 0;
        })
    }

    fn enable_io_tracing(&self, sandbox_id: &str) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.io_tracing_enabled = 1;
        })
    }

    fn disable_io_tracing(&self, sandbox_id: &str) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.io_tracing_enabled = 0;
        })
    }

    fn enable_syscall_latency(
        &self,
        sandbox_id: &str,
        sample_rate: u8,
    ) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.syscall_latency_enabled = 1;
            config.syscall_sample_rate = sample_rate;
        })
    }

    fn disable_syscall_latency(&self, sandbox_id: &str) -> Result<(), ObservabilityError> {
        self.update_config(sandbox_id, |config| {
            config.syscall_latency_enabled = 0;
        })
    }

    fn drain_cpu_samples(&self) -> Vec<CpuSampleEvent> {
        Vec::new()
    }

    fn drain_io_events(&self) -> Vec<IoSampleEvent> {
        Vec::new()
    }

    fn drain_syscall_latency_events(&self) -> Vec<SyscallLatencyEvent> {
        self.latency_events.lock().drain(..).collect()
    }

    fn is_available(&self) -> bool {
        true
    }
}

fn read_cgroup_u64(cgroup_path: &Path, file: &str) -> Result<u64, ObservabilityError> {
    let path = cgroup_path.join(file);
    let contents = fs::read_to_string(&path).map_err(|e| {
        ObservabilityError::Unavailable(format!("failed to read {}: {e}", path.display()))
    })?;
    let value = contents.trim();
    if value == "max" {
        return Ok(u64::MAX);
    }
    value.parse::<u64>().map_err(|e| {
        ObservabilityError::Unavailable(format!("failed to parse {}: {e}", path.display()))
    })
}

fn read_cgroup_oom_kills(cgroup_path: &Path) -> Result<u64, ObservabilityError> {
    let path = cgroup_path.join("memory.events");
    let contents = fs::read_to_string(&path).map_err(|e| {
        ObservabilityError::Unavailable(format!("failed to read {}: {e}", path.display()))
    })?;
    for line in contents.lines() {
        if let Some(count_str) = line.strip_prefix("oom_kill ") {
            return count_str.trim().parse::<u64>().map_err(|e| {
                ObservabilityError::Unavailable(format!("failed to parse oom_kill: {e}"))
            });
        }
    }
    Ok(0)
}

fn read_cgroup_stat_field(cgroup_path: &Path, field_name: &str) -> u64 {
    let path = cgroup_path.join("memory.stat");
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    for line in contents.lines() {
        if let Some(val_str) = line.strip_prefix(field_name)
            && let Ok(val) = val_str.trim().parse::<u64>()
        {
            return val;
        }
    }
    0
}

fn read_cgroup_memory_pressure(cgroup_path: &Path) -> f64 {
    let path = cgroup_path.join("memory.pressure");
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return 0.0,
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("avg10=") {
                    return val.parse::<f64>().unwrap_or(0.0);
                }
            }
        }
    }
    0.0
}
