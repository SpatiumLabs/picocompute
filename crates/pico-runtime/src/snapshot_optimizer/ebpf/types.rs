//! BPF struct types shared between the eBPF program and userspace loader.
//!
//! These types must be `#[repr(C)]` and implement `aya::Pod` for safe
//! zero-copy access across the BPF-userspace boundary.

/// Per-cgroup snapshot optimization configuration stored in the BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SnapshotBpfConfig {
    pub dirty_page_tracking_enabled: u8,
    pub io_tracking_enabled: u8,
    pub _pad: [u8; 6],
}

unsafe impl aya::Pod for SnapshotBpfConfig {}

/// Dirty page event delivered from BPF to userspace via ring buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DirtyPageEventBpf {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub page_offset: u64,
    pub address: u64,
    pub is_write: u8,
    pub _pad: [u8; 7],
    pub timestamp_ns: u64,
}

unsafe impl aya::Pod for DirtyPageEventBpf {}

/// I/O heatmap event delivered from BPF to userspace via ring buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoHeatmapEventBpf {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub device_major: u32,
    pub device_minor: u32,
    pub sector: u64,
    pub nr_sectors: u32,
    pub is_read: u8,
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
}

unsafe impl aya::Pod for IoHeatmapEventBpf {}

/// Key for the dirty page tracking BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DirtyPageKeyBpf {
    pub cgroup_id: u64,
    pub page_offset: u64,
}

unsafe impl aya::Pod for DirtyPageKeyBpf {}

/// Value for the dirty page tracking BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DirtyPageValueBpf {
    pub last_access_ns: u64,
    pub access_count: u64,
}

unsafe impl aya::Pod for DirtyPageValueBpf {}

/// Key for the I/O heatmap BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoHeatmapKeyBpf {
    pub cgroup_id: u64,
    pub sector_bucket: u64,
}

unsafe impl aya::Pod for IoHeatmapKeyBpf {}

/// Value for the I/O heatmap BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoHeatmapValueBpf {
    pub read_count: u64,
    pub write_count: u64,
    pub last_access_ns: u64,
}

unsafe impl aya::Pod for IoHeatmapValueBpf {}
