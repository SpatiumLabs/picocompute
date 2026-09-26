//! BPF struct types shared between the eBPF program and userspace loader.
//!
//! These types must be `#[repr(C)]` and implement `aya::Pod` for safe
//! zero-copy access across the BPF-userspace boundary.

/// Per-cgroup observability configuration stored in the BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ObservabilityBpfConfig {
    /// Whether CPU sampling is enabled for this cgroup.
    pub cpu_sampling_enabled: u8,
    /// Whether I/O tracing is enabled for this cgroup.
    pub io_tracing_enabled: u8,
    /// Whether syscall latency tracing is enabled for this cgroup.
    pub syscall_latency_enabled: u8,
    /// Per-cgroup syscall event sampling rate, 0 or 1 = record 100%,
    /// N > 1 = record ~1-in-N events to reduce ring buffer pressure.
    pub syscall_sample_rate: u8,
    /// CPU sampling frequency in Hz.
    pub sample_rate: u32,
}

unsafe impl aya::Pod for ObservabilityBpfConfig {}

/// CPU profiling sample delivered from BPF to userspace via perf event array.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CpuSampleBpf {
    /// Kernel cgroup ID of the sampled task.
    pub cgroup_id: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Alignment padding.
    pub _pad0: [u8; 4],
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Number of valid frames in the stack trace.
    pub stack_len: u32,
    /// Alignment padding.
    pub _pad1: [u8; 4],
    /// Instruction pointer addresses forming the stack trace.
    pub stack: [u64; 127],
}

unsafe impl aya::Pod for CpuSampleBpf {}

/// Block I/O event delivered from BPF to userspace via ring buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IoEventBpf {
    /// Kernel cgroup ID of the task.
    pub cgroup_id: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Start timestamp in nanoseconds.
    pub timestamp_ns_start: u64,
    /// Completion timestamp in nanoseconds.
    pub timestamp_ns_end: u64,
    /// Block device major number.
    pub device_major: u32,
    /// Block device minor number.
    pub device_minor: u32,
    /// Starting sector of the I/O request.
    pub sector: u64,
    /// Number of sectors in the request.
    pub nr_sectors: u32,
    /// Non-zero if this is a read operation.
    pub is_read: u8,
    /// Alignment padding.
    pub _pad: [u8; 3],
}

unsafe impl aya::Pod for IoEventBpf {}

/// Syscall latency event delivered from BPF to userspace via ring buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SyscallLatencyEventBpf {
    /// Kernel cgroup ID of the task.
    pub cgroup_id: u64,
    /// Process ID (tgid in kernel terms).
    pub pid: u32,
    /// Thread ID (pid in kernel terms).
    pub tid: u32,
    /// Syscall type identifier matching pico-observability-ebpf SYSCALL_* constants.
    pub syscall_type: u8,
    /// Alignment padding.
    pub _pad: [u8; 3],
    /// Enter timestamp in nanoseconds (monotonic clock).
    pub enter_ts_ns: u64,
    /// Latency in nanoseconds (exit_ts - enter_ts).
    pub latency_ns: u64,
}

unsafe impl aya::Pod for SyscallLatencyEventBpf {}
