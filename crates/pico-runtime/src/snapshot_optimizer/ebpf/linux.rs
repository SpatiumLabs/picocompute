use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{thread, time::Duration};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    programs::TracePoint,
};
use parking_lot::{Mutex, RwLock};
use pico_core::SandboxId;
use tracing::{debug, info, warn};

use super::types::{DirtyPageEventBpf, IoHeatmapEventBpf, SnapshotBpfConfig};
use crate::snapshot_optimizer::{
    CgroupId, DirtyPageEvent, IoHeatmapEvent, SnapshotOptimizationError,
};

pub(super) struct EbpfSnapshotOptimizationBackend {
    bpf: Mutex<Ebpf>,
    sandboxes: Arc<RwLock<HashMap<SandboxId, CgroupId>>>,
    cgroup_ids: Arc<RwLock<HashMap<CgroupId, SandboxId>>>,
    dirty_page_events: Arc<Mutex<Vec<DirtyPageEvent>>>,
    io_events: Arc<Mutex<Vec<IoHeatmapEvent>>>,
    dirty_page_thread: Option<thread::JoinHandle<()>>,
    io_thread: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicU64>,
}

impl EbpfSnapshotOptimizationBackend {
    pub(super) fn load() -> Result<Self, String> {
        let bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pico_snapshot.bpf.o"));

        if bytes.is_empty() || bytes.len() < 64 {
            return Err("eBPF bytecode is empty (stub build)".into());
        }

        let mut bpf = Ebpf::load(bytes).map_err(|e| format!("failed to load eBPF ELF: {e}"))?;

        {
            let prog: &mut TracePoint = bpf
                .program_mut("pico_tp_page_fault")
                .ok_or_else(|| "pico_tp_page_fault program not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_page_fault is not a tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_page_fault: {e}"))?;
            prog.attach("exceptions", "page_fault_user")
                .map_err(|e| format!("failed to attach pico_tp_page_fault: {e}"))?;
        }

        {
            let prog: &mut TracePoint = bpf
                .program_mut("pico_tp_block_rq_issue")
                .ok_or_else(|| "pico_tp_block_rq_issue not found".to_string())?
                .try_into()
                .map_err(|e| format!("pico_tp_block_rq_issue is not a tracepoint: {e}"))?;
            prog.load()
                .map_err(|e| format!("failed to load pico_tp_block_rq_issue: {e}"))?;
            prog.attach("block", "block_rq_issue")
                .map_err(|e| format!("failed to attach pico_tp_block_rq_issue: {e}"))?;
        }

        info!("eBPF snapshot optimization backend loaded");

        let dirty_page_events: Arc<Mutex<Vec<DirtyPageEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let io_events: Arc<Mutex<Vec<IoHeatmapEvent>>> = Arc::new(Mutex::new(Vec::new()));

        let sandboxes = Arc::new(RwLock::new(HashMap::new()));
        let cgroup_ids = Arc::new(RwLock::new(HashMap::new()));
        let shutdown = Arc::new(AtomicU64::new(0));

        let dirty_page_thread = spawn_dirty_page_ring_buf_thread(
            &mut bpf,
            dirty_page_events.clone(),
            cgroup_ids.clone(),
            shutdown.clone(),
        )?;

        let io_thread = spawn_io_ring_buf_thread(
            &mut bpf,
            io_events.clone(),
            cgroup_ids.clone(),
            shutdown.clone(),
        )?;

        Ok(Self {
            bpf: Mutex::new(bpf),
            sandboxes,
            cgroup_ids,
            dirty_page_events,
            io_events,
            dirty_page_thread: Some(dirty_page_thread),
            io_thread: Some(io_thread),
            shutdown,
        })
    }
}

impl Drop for EbpfSnapshotOptimizationBackend {
    fn drop(&mut self) {
        self.shutdown.store(1, Ordering::Release);
        if let Some(handle) = self.dirty_page_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.io_thread.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_dirty_page_ring_buf_thread(
    bpf: &mut Ebpf,
    dirty_page_events: Arc<Mutex<Vec<DirtyPageEvent>>>,
    cgroup_ids: Arc<RwLock<HashMap<CgroupId, SandboxId>>>,
    shutdown: Arc<AtomicU64>,
) -> Result<thread::JoinHandle<()>, String> {
    let ring_buf_map = bpf
        .take_map("DIRTY_PAGE_EVENTS")
        .ok_or_else(|| "DIRTY_PAGE_EVENTS map not found".to_string())?;

    let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(ring_buf_map)
        .map_err(|e| format!("failed to create dirty page ring buffer reader: {e}"))?;

    thread::Builder::new()
        .name("ebpf-dirty-page-ringbuf".into())
        .spawn(move || {
            info!("eBPF dirty page ring buffer consumer started");

            loop {
                if shutdown.load(Ordering::Acquire) != 0 {
                    info!("shutdown signal received, stopping dirty page ring buffer consumer");
                    break;
                }

                let mut consumed = false;
                while let Some(item) = ring_buf.next() {
                    consumed = true;
                    let data: &[u8] = &item;
                    if data.len() < std::mem::size_of::<DirtyPageEventBpf>() {
                        warn!(
                            len = data.len(),
                            "ring buffer entry too small for DirtyPageEventBpf"
                        );
                        continue;
                    }

                    let raw = unsafe { &*(data.as_ptr() as *const DirtyPageEventBpf) };
                    let cgroup_ids = cgroup_ids.read();

                    let event = DirtyPageEvent {
                        sandbox_id: cgroup_ids.get(&raw.cgroup_id).cloned().unwrap_or_else(|| {
                            SandboxId::from_string(format!("cgroup-{}", raw.cgroup_id))
                        }),
                        cgroup_id: raw.cgroup_id,
                        pid: raw.pid,
                        tid: raw.tid,
                        page_offset: raw.page_offset,
                        address: raw.address,
                        is_write: raw.is_write != 0,
                        timestamp_ns: raw.timestamp_ns,
                    };
                    dirty_page_events.lock().push(event);
                }

                if !consumed {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            info!("eBPF dirty page ring buffer consumer stopped");
        })
        .map_err(|e| format!("failed to spawn dirty page ring buffer thread: {e}"))
}

fn spawn_io_ring_buf_thread(
    bpf: &mut Ebpf,
    io_events: Arc<Mutex<Vec<IoHeatmapEvent>>>,
    cgroup_ids: Arc<RwLock<HashMap<CgroupId, SandboxId>>>,
    shutdown: Arc<AtomicU64>,
) -> Result<thread::JoinHandle<()>, String> {
    let ring_buf_map = bpf
        .take_map("IO_HEATMAP_EVENTS")
        .ok_or_else(|| "IO_HEATMAP_EVENTS map not found".to_string())?;

    let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(ring_buf_map)
        .map_err(|e| format!("failed to create I/O ring buffer reader: {e}"))?;

    thread::Builder::new()
        .name("ebpf-io-heatmap-ringbuf".into())
        .spawn(move || {
            info!("eBPF I/O heatmap ring buffer consumer started");

            loop {
                if shutdown.load(Ordering::Acquire) != 0 {
                    info!("shutdown signal received, stopping I/O heatmap ring buffer consumer");
                    break;
                }

                let mut consumed = false;
                while let Some(item) = ring_buf.next() {
                    consumed = true;
                    let data: &[u8] = &item;
                    if data.len() < std::mem::size_of::<IoHeatmapEventBpf>() {
                        warn!(
                            len = data.len(),
                            "ring buffer entry too small for IoHeatmapEventBpf"
                        );
                        continue;
                    }

                    let raw = unsafe { &*(data.as_ptr() as *const IoHeatmapEventBpf) };
                    let cgroup_ids = cgroup_ids.read();

                    let event = IoHeatmapEvent {
                        sandbox_id: cgroup_ids.get(&raw.cgroup_id).cloned().unwrap_or_else(|| {
                            SandboxId::from_string(format!("cgroup-{}", raw.cgroup_id))
                        }),
                        cgroup_id: raw.cgroup_id,
                        pid: raw.pid,
                        tid: raw.tid,
                        device_major: raw.device_major,
                        device_minor: raw.device_minor,
                        sector: raw.sector,
                        nr_sectors: raw.nr_sectors,
                        is_read: raw.is_read != 0,
                        timestamp_ns: raw.timestamp_ns,
                    };
                    io_events.lock().push(event);
                }

                if !consumed {
                    thread::sleep(Duration::from_millis(1));
                }
            }

            info!("eBPF I/O heatmap ring buffer consumer stopped");
        })
        .map_err(|e| format!("failed to spawn I/O ring buffer thread: {e}"))
}

impl crate::snapshot_optimizer::SnapshotOptimizationBackend for EbpfSnapshotOptimizationBackend {
    fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: CgroupId,
        _cgroup_path: &Path,
    ) -> Result<(), SnapshotOptimizationError> {
        let mut guard = self.bpf.lock();
        let mut config_map: BpfHashMap<&mut MapData, u64, SnapshotBpfConfig> =
            BpfHashMap::try_from(guard.map_mut("SNAPSHOT_CONFIG").ok_or_else(|| {
                SnapshotOptimizationError::Unavailable("SNAPSHOT_CONFIG map not found".into())
            })?)
            .map_err(|e| SnapshotOptimizationError::Unavailable(e.to_string()))?;

        let config = SnapshotBpfConfig {
            dirty_page_tracking_enabled: 1,
            io_tracking_enabled: 1,
            _pad: [0u8; 6],
        };

        config_map
            .insert(cgroup_id, config, 0)
            .map_err(|e| SnapshotOptimizationError::Unavailable(e.to_string()))?;

        self.sandboxes
            .write()
            .insert(SandboxId::from_string(sandbox_id), cgroup_id);
        self.cgroup_ids
            .write()
            .insert(cgroup_id, SandboxId::from_string(sandbox_id));

        debug!(
            sandbox_id = %sandbox_id,
            cgroup_id,
            "registered sandbox for eBPF snapshot optimization"
        );
        Ok(())
    }

    fn unregister_sandbox(&self, sandbox_id: &str) -> Result<(), SnapshotOptimizationError> {
        let id = SandboxId::from_string(sandbox_id);
        if let Some(cgroup_id) = self.sandboxes.write().remove(&id) {
            self.cgroup_ids.write().remove(&cgroup_id);
            let mut guard = self.bpf.lock();
            let mut config_map: BpfHashMap<&mut MapData, u64, SnapshotBpfConfig> =
                BpfHashMap::try_from(guard.map_mut("SNAPSHOT_CONFIG").ok_or_else(|| {
                    SnapshotOptimizationError::Unavailable("SNAPSHOT_CONFIG map not found".into())
                })?)
                .map_err(|e| SnapshotOptimizationError::Unavailable(e.to_string()))?;
            let _ = config_map.remove(&cgroup_id);
        }
        Ok(())
    }

    fn drain_dirty_page_events(&self) -> Vec<DirtyPageEvent> {
        self.dirty_page_events.lock().drain(..).collect()
    }

    fn drain_io_events(&self) -> Vec<IoHeatmapEvent> {
        self.io_events.lock().drain(..).collect()
    }

    fn is_available(&self) -> bool {
        true
    }
}
