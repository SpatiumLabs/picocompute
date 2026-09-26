#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(any(feature = "arch-x86_64", feature = "arch-aarch64")))]
compile_error!(
    "pico-snapshot-ebpf requires exactly one arch feature: \
     --features arch-x86_64 (for x86_64 hosts) or \
     --features arch-aarch64 (for aarch64/arm64 hosts)"
);

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{HashMap, RingBuf};

const RING_BUF_SIZE: u32 = 256 * 1024;

#[repr(C)]
#[derive(Copy, Clone)]
struct SnapshotBpfConfig {
    dirty_page_tracking_enabled: u8,
    io_tracking_enabled: u8,
    _pad: [u8; 6],
}

unsafe impl aya_ebpf::Pod for SnapshotBpfConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
struct DirtyPageEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    page_offset: u64,
    address: u64,
    is_write: u8,
    _pad: [u8; 7],
    timestamp_ns: u64,
}

unsafe impl aya_ebpf::Pod for DirtyPageEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoHeatmapEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    device_major: u32,
    device_minor: u32,
    sector: u64,
    nr_sectors: u32,
    is_read: u8,
    _pad: [u8; 3],
    timestamp_ns: u64,
}

unsafe impl aya_ebpf::Pod for IoHeatmapEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
struct DirtyPageKey {
    cgroup_id: u64,
    page_offset: u64,
}

unsafe impl aya_ebpf::Pod for DirtyPageKey {}

#[repr(C)]
#[derive(Copy, Clone)]
struct DirtyPageValue {
    last_access_ns: u64,
    access_count: u64,
}

unsafe impl aya_ebpf::Pod for DirtyPageValue {}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoHeatmapKey {
    cgroup_id: u64,
    sector_bucket: u64,
}

unsafe impl aya_ebpf::Pod for IoHeatmapKey {}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoHeatmapValue {
    read_count: u64,
    write_count: u64,
    last_access_ns: u64,
}

unsafe impl aya_ebpf::Pod for IoHeatmapValue {}

#[map]
static SNAPSHOT_CONFIG: HashMap<u64, SnapshotBpfConfig> =
    HashMap::with_max_entries(1024, 0);

#[map]
static DIRTY_PAGE_TRACKER: HashMap<DirtyPageKey, DirtyPageValue> =
    HashMap::with_max_entries(65536, 0);

#[map]
static DIRTY_PAGE_EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

#[map]
static IO_HEATMAP: HashMap<IoHeatmapKey, IoHeatmapValue> =
    HashMap::with_max_entries(16384, 0);

#[map]
static IO_HEATMAP_EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

// Tracepoint format (Linux 6.x exceptions:page_fault_user):
//   offset 0: common_type(u16) 2:common_flags(u8) 3:common_preempt_count(u8)
//   offset 4: common_pid(i32) 8:address(u64) 16:ip(u64) 24:error_code(u64)
#[tracepoint]
fn pico_tp_page_fault(ctx: aya_ebpf::programs::TracePointContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    match unsafe { SNAPSHOT_CONFIG.get(&cgroup_id) } {
        Some(c) if c.dirty_page_tracking_enabled == 1 => {}
        _ => return 0,
    };

    let address: u64 = ctx.read_at(8).unwrap_or(0);
    let error_code: u64 = ctx.read_at(24).unwrap_or(0);
    let is_write = ((error_code >> 1) & 1) == 1;
    let page_size: u64 = 4096;
    let page_offset = address / page_size;

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let key = DirtyPageKey {
        cgroup_id,
        page_offset,
    };

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let value = DirtyPageValue {
        last_access_ns: now_ns,
        access_count: 1,
    };

    if let Some(existing) = unsafe { DIRTY_PAGE_TRACKER.get(&key) } {
        let updated = DirtyPageValue {
            last_access_ns: now_ns,
            access_count: existing.access_count + 1,
        };
        let _ = unsafe { DIRTY_PAGE_TRACKER.insert(&key, &updated, 0) };
    } else {
        let _ = unsafe { DIRTY_PAGE_TRACKER.insert(&key, &value, 0) };
    }

    let event = DirtyPageEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        page_offset,
        address,
        is_write: if is_write { 1 } else { 0 },
        _pad: [0u8; 7],
        timestamp_ns: now_ns,
    };

    if let Some(mut entry) = DIRTY_PAGE_EVENTS.reserve::<DirtyPageEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
    0
}

// Tracepoint format (Linux 6.x block:block_rq_issue):
//   offset 0: common_type(u16) 2:common_flags(u8) 3:common_preempt_count(u8)
//   offset 4: common_pid(i32) 8:dev(u32 as dev_t) 16:sector(u64)
//   offset 24:nr_sector(u32) 28:bytes(u32) 32:rwbs(u64 char[8]) 40:cmd(__data_loc)
// dev_t decoding: major = dev >> 20, minor = dev & 0xFFFFF
#[tracepoint]
fn pico_tp_block_rq_issue(ctx: aya_ebpf::programs::TracePointContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    match unsafe { SNAPSHOT_CONFIG.get(&cgroup_id) } {
        Some(c) if c.io_tracking_enabled == 1 => {}
        _ => return 0,
    };

    let dev: u32 = ctx.read_at(8).unwrap_or(0).min(u32::MAX as u64) as u32;
    let sector: u64 = ctx.read_at(16).unwrap_or(0);
    let nr_sectors: u32 = ctx.read_at(24).unwrap_or(0).min(u32::MAX as u64) as u32;
    let rwbs: u64 = ctx.read_at(32).unwrap_or(0);
    let is_read = if (rwbs as u32 & 1) == 0 { 1 } else { 0 };

    let dev_major = dev >> 20;
    let dev_minor = dev & 0xFFFFF;

    let sector_bucket = sector / 2048;

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let key = IoHeatmapKey {
        cgroup_id,
        sector_bucket,
    };

    let now_ns = unsafe { bpf_ktime_get_ns() };

    if let Some(existing) = unsafe { IO_HEATMAP.get(&key) } {
        let updated = IoHeatmapValue {
            read_count: if is_read != 0 {
                existing.read_count + 1
            } else {
                existing.read_count
            },
            write_count: if is_read == 0 {
                existing.write_count + 1
            } else {
                existing.write_count
            },
            last_access_ns: now_ns,
        };
        let _ = unsafe { IO_HEATMAP.insert(&key, &updated, 0) };
    } else {
        let value = IoHeatmapValue {
            read_count: if is_read != 0 { 1 } else { 0 },
            write_count: if is_read == 0 { 1 } else { 0 },
            last_access_ns: now_ns,
        };
        let _ = unsafe { IO_HEATMAP.insert(&key, &value, 0) };
    }

    let event = IoHeatmapEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        device_major: dev_major,
        device_minor: dev_minor,
        sector,
        nr_sectors,
        is_read,
        _pad: [0u8; 3],
        timestamp_ns: now_ns,
    };

    if let Some(mut entry) = IO_HEATMAP_EVENTS.reserve::<IoHeatmapEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
