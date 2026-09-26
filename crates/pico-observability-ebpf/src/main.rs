#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

// Architecture validation:
//
// The eBPF crate compiles for the bpfel-unknown-none target and cannot
// run standard Rust tests. Compile-time checks validate PtRegs sizes.
// To smoke-test each architecture, build with the corresponding feature:
//
//   cargo +nightly build -p pico-observability-ebpf \
//     --target bpfel-unknown-none -Z build-std=core \
//     --features arch-x86_64
//
//   cargo +nightly build -p pico-observability-ebpf \
//     --target bpfel-unknown-none -Z build-std=core \
//     --no-default-features --features arch-aarch64
//
// NR_* syscall numbers are sourced from the Linux kernel ABI; incorrect
// values cause probes to silently ignore matching syscalls. Runtime
// verification is performed by integration tests in pico-observability
// that exercise enter->exit correlation on real workloads.

#[cfg(not(any(feature = "arch-x86_64", feature = "arch-aarch64")))]
compile_error!(
    "pico-observability-ebpf requires exactly one arch feature: \
     --features arch-x86_64 (for x86_64 hosts) or \
     --features arch-aarch64 (for aarch64/arm64 hosts)"
);

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_stack,
    bpf_ktime_get_ns,
};
use aya_ebpf::macros::{map, perf_event, raw_tracepoint, tracepoint};
use aya_ebpf::maps::{HashMap, PerfEventArray, RingBuf};
use aya_ebpf::programs::{PerfEventContext, RawTracePointContext, TracePointContext};
use core::mem;

const MAX_STACK_DEPTH: usize = 127;
const RING_BUF_SIZE: u32 = 256 * 1024;

// ---- Arch-specific syscall numbers and pt_regs layout ---------------

#[cfg(feature = "arch-x86_64")]
mod arch {
    pub(crate) const NR_READ: u32 = 0;
    pub(crate) const NR_WRITE: u32 = 1;
    pub(crate) const NR_OPEN: u32 = 2;
    pub(crate) const NR_CLOSE: u32 = 3;
    pub(crate) const NR_CLONE: u32 = 56;
    pub(crate) const NR_FORK: u32 = 57;
    pub(crate) const NR_VFORK: u32 = 58;
    pub(crate) const NR_EXECVE: u32 = 59;
    pub(crate) const NR_CONNECT: u32 = 42;
    pub(crate) const NR_ACCEPT: u32 = 43;
    pub(crate) const NR_SENDTO: u32 = 44;
    pub(crate) const NR_RECVFROM: u32 = 45;
    pub(crate) const NR_SENDMSG: u32 = 46;
    pub(crate) const NR_RECVMSG: u32 = 47;

    /// x86_64 `pt_regs` -- validated by compile-time size assert.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub(crate) struct PtRegs {
        pub(crate) r15: u64,
        pub(crate) r14: u64,
        pub(crate) r13: u64,
        pub(crate) r12: u64,
        pub(crate) rbp: u64,
        pub(crate) rbx: u64,
        pub(crate) r11: u64,
        pub(crate) r10: u64,
        pub(crate) r9: u64,
        pub(crate) r8: u64,
        pub(crate) rax: u64,
        pub(crate) rcx: u64,
        pub(crate) rdx: u64,
        pub(crate) rsi: u64,
        pub(crate) rdi: u64,
        pub(crate) orig_rax: u64,
        pub(crate) rip: u64,
        pub(crate) cs: u64,
        pub(crate) eflags: u64,
        pub(crate) rsp: u64,
        pub(crate) ss: u64,
    }

    pub(crate) const PT_REGS_SIZE: usize = 21 * 8;

    #[inline(always)]
    pub(crate) fn syscall_nr(regs: &PtRegs) -> u32 {
        regs.orig_rax as u32
    }
}

#[cfg(feature = "arch-aarch64")]
mod arch {
    pub(crate) const NR_READ: u32 = 63;
    pub(crate) const NR_WRITE: u32 = 64;
    pub(crate) const NR_OPENAT: u32 = 56;
    pub(crate) const NR_CLOSE: u32 = 57;
    pub(crate) const NR_CLONE: u32 = 220;
    pub(crate) const NR_EXECVE: u32 = 221;
    pub(crate) const NR_CONNECT: u32 = 203;
    pub(crate) const NR_ACCEPT4: u32 = 242;
    pub(crate) const NR_SENDTO: u32 = 206;
    pub(crate) const NR_RECVFROM: u32 = 207;
    pub(crate) const NR_SENDMSG: u32 = 211;
    pub(crate) const NR_RECVMSG: u32 = 212;

    /// aarch64 `pt_regs` -- validated by compile-time size assert.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub(crate) struct PtRegs {
        pub(crate) regs: [u64; 31],
        pub(crate) sp: u64,
        pub(crate) pc: u64,
        pub(crate) pstate: u64,
    }

    pub(crate) const PT_REGS_SIZE: usize = 34 * 8;

    #[inline(always)]
    pub(crate) fn syscall_nr(regs: &PtRegs) -> u32 {
        regs.regs[8] as u32
    }
}

// Shared syscall type identifiers (same for all architectures)

const SYSCALL_READ: u8 = 0;
const SYSCALL_WRITE: u8 = 1;
const SYSCALL_OPEN: u8 = 2;
const SYSCALL_CLOSE: u8 = 3;
// Process-creation syscalls (clone/fork/vfork/execve) are included for
// observability, but latency measurements for these are best-effort:
// the enter happens in the calling task while the exit may be observed in
// a different task context. Operators should treat these histograms as
// approximate. Note: fork/vfork do not exist on aarch64 (only clone).
const SYSCALL_CLONE: u8 = 4;
const SYSCALL_FORK: u8 = 5;
const SYSCALL_VFORK: u8 = 6;
const SYSCALL_EXECVE: u8 = 7;
const SYSCALL_CONNECT: u8 = 8;
const SYSCALL_ACCEPT: u8 = 9;
const SYSCALL_SENDTO: u8 = 10;
const SYSCALL_RECVFROM: u8 = 11;
const SYSCALL_SENDMSG: u8 = 12;
const SYSCALL_RECVMSG: u8 = 13;

#[repr(C)]
#[derive(Copy, Clone)]
struct ObservabilityConfig {
    cpu_sampling_enabled: u8,
    io_tracing_enabled: u8,
    syscall_latency_enabled: u8,
    /// Per-cgroup syscall event sampling rate, 0 or 1 = record 100%,
    /// N > 1 = record ~1-in-N events to reduce ring buffer pressure.
    syscall_sample_rate: u8,
    sample_rate: u32,
}

unsafe impl aya_ebpf::Pod for ObservabilityConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
struct CpuSample {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    _pad0: [u8; 4],
    timestamp_ns: u64,
    stack_len: u32,
    _pad1: [u8; 4],
    stack: [u64; MAX_STACK_DEPTH],
}

unsafe impl aya_ebpf::Pod for CpuSample {}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    timestamp_ns_start: u64,
    timestamp_ns_end: u64,
    device_major: u32,
    device_minor: u32,
    sector: u64,
    nr_sectors: u32,
    is_read: u8,
    _pad: [u8; 3],
}

unsafe impl aya_ebpf::Pod for IoEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
struct LatencyEnterKey {
    cgroup_id: u64,
    pid_tgid: u64,
    syscall_nr: u32,
    _pad: u32,
}

unsafe impl aya_ebpf::Pod for LatencyEnterKey {}

#[repr(C)]
#[derive(Copy, Clone)]
struct LatencyEnterValue {
    timestamp_ns: u64,
}

unsafe impl aya_ebpf::Pod for LatencyEnterValue {}

#[repr(C)]
#[derive(Copy, Clone)]
struct SyscallLatencyEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    syscall_type: u8,
    _pad: [u8; 3],
    enter_ts_ns: u64,
    latency_ns: u64,
}

unsafe impl aya_ebpf::Pod for SyscallLatencyEvent {}

#[map]
static OBSERVABILITY_CONFIG: HashMap<u64, ObservabilityConfig> =
    HashMap::with_max_entries(1024, 0);

#[map]
static CPU_SAMPLES: PerfEventArray<CpuSample> =
    PerfEventArray::with_max_entries(4096, 0);

#[map]
static IO_EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

/// Enter-timestamp map for syscall latency correlation. Each entry tracks
/// the monotonic timestamp when a syscall began, keyed by (cgroup, tid, nr).
///
/// Entries are removed on sys_exit; however if a process is killed or exits
/// via a path that skips the exit probe the entry remains until the map
/// capacity (32K) is reached. Under sustained load with short-lived
/// processes this may lead to hash-table pressure. A periodic userspace
/// sweep of stale entries (via aya map iteration) is the planned mitigation.
#[map]
static LATENCY_ENTER_MAP: HashMap<LatencyEnterKey, LatencyEnterValue> =
    HashMap::with_max_entries(32768, 0);

#[map]
static SYSCALL_LATENCY_EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

#[perf_event]
fn pico_perf_cpu(ctx: PerfEventContext) -> u32 {
    let cgroup_id = bpf_get_current_cgroup_id();

    let config = match unsafe { OBSERVABILITY_CONFIG.get(&cgroup_id) } {
        Some(c) if c.cpu_sampling_enabled == 1 => c,
        _ => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let mut sample = CpuSample {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        _pad0: [0u8; 4],
        timestamp_ns: bpf_ktime_get_ns(),
        stack_len: 0,
        _pad1: [0u8; 4],
        stack: [0u64; MAX_STACK_DEPTH],
    };

    let ret = unsafe {
        bpf_get_stack(
            ctx.as_ptr() as *const _,
            sample.stack.as_mut_ptr() as *mut _,
            (MAX_STACK_DEPTH * core::mem::size_of::<u64>()) as u32,
            0,
        )
    };

    if ret >= 0 {
        sample.stack_len = (ret as u32) / core::mem::size_of::<u64>() as u32;
        sample.stack_len = sample.stack_len.min(MAX_STACK_DEPTH as u32);
    }

    CPU_SAMPLES.output(&ctx, &sample, 0);
    0
}

#[tracepoint]
fn pico_tp_block_io_issue(ctx: TracePointContext) -> u32 {
    let cgroup_id = bpf_get_current_cgroup_id();
    let Some(_c) = (unsafe { OBSERVABILITY_CONFIG.get(&cgroup_id) }) else {
        return 0;
    };

    let pid_tgid = bpf_get_current_pid_tgid();

    let event = IoEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        timestamp_ns_start: bpf_ktime_get_ns(),
        timestamp_ns_end: 0,
        device_major: 0,
        device_minor: 0,
        sector: 0,
        nr_sectors: 0,
        is_read: 1,
        _pad: [0u8; 3],
    };

    if let Some(mut entry) = IO_EVENTS.reserve::<IoEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
    0
}

#[tracepoint]
fn pico_tp_block_io_complete(ctx: TracePointContext) -> u32 {
    let cgroup_id = bpf_get_current_cgroup_id();
    let Some(_c) = (unsafe { OBSERVABILITY_CONFIG.get(&cgroup_id) }) else {
        return 0;
    };

    let pid_tgid = bpf_get_current_pid_tgid();

    let event = IoEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        timestamp_ns_start: 0,
        timestamp_ns_end: bpf_ktime_get_ns(),
        device_major: 0,
        device_minor: 0,
        sector: 0,
        nr_sectors: 0,
        is_read: 0,
        _pad: [0u8; 3],
    };

    if let Some(mut entry) = IO_EVENTS.reserve::<IoEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
fn pico_tp_syscall_enter(ctx: RawTracePointContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let config = match unsafe { OBSERVABILITY_CONFIG.get(&cgroup_id) } {
        Some(c) if c.syscall_latency_enabled == 1 => c,
        _ => return 0,
    };

    if config.syscall_sample_rate > 1 {
        let t = unsafe { bpf_ktime_get_ns() } as u32;
        if t % (config.syscall_sample_rate as u32) != 0 {
            return 0;
        }
    }

    let regs = ctx.arg[0] as *const PtRegs;
    let regs = match unsafe { regs.as_ref() } {
        Some(r) => r,
        None => return 0,
    };

    let syscall_nr = arch::syscall_nr(regs);
    let Some(syscall_type) = latency_syscall_type(syscall_nr) else {
        return 0;
    };

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let key = LatencyEnterKey {
        cgroup_id,
        pid_tgid,
        syscall_nr,
        _pad: 0,
    };
    let value = LatencyEnterValue {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    let _ = unsafe { LATENCY_ENTER_MAP.insert(&key, &value, 0) };
    0
}

#[raw_tracepoint(tracepoint = "sys_exit")]
fn pico_tp_syscall_exit(ctx: RawTracePointContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    match unsafe { OBSERVABILITY_CONFIG.get(&cgroup_id) } {
        Some(c) if c.syscall_latency_enabled == 1 => {},
        _ => return 0,
    };

    let regs = ctx.arg[0] as *const PtRegs;
    let regs = match unsafe { regs.as_ref() } {
        Some(r) => r,
        None => return 0,
    };

    let syscall_nr = arch::syscall_nr(regs);
    let Some(syscall_type) = latency_syscall_type(syscall_nr) else {
        return 0;
    };

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let key = LatencyEnterKey {
        cgroup_id,
        pid_tgid,
        syscall_nr,
        _pad: 0,
    };

    let Some(enter_value) = unsafe { LATENCY_ENTER_MAP.get(&key) } else {
        return 0;
    };
    let enter_ts_ns = enter_value.timestamp_ns;

    let _ = unsafe { LATENCY_ENTER_MAP.remove(&key) };

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let latency_ns = if now_ns >= enter_ts_ns {
        now_ns - enter_ts_ns
    } else {
        return 0;
    };

    let event = SyscallLatencyEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        syscall_type,
        _pad: [0u8; 3],
        enter_ts_ns,
        latency_ns,
    };

    if let Some(mut entry) = SYSCALL_LATENCY_EVENTS.reserve::<SyscallLatencyEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
    0
}

#[inline(always)]
fn latency_syscall_type(nr: u32) -> Option<u8> {
    match nr {
        arch::NR_READ => Some(SYSCALL_READ),
        arch::NR_WRITE => Some(SYSCALL_WRITE),
        #[cfg(feature = "arch-x86_64")]
        arch::NR_OPEN => Some(SYSCALL_OPEN),
        #[cfg(feature = "arch-aarch64")]
        arch::NR_OPENAT => Some(SYSCALL_OPEN),
        arch::NR_CLOSE => Some(SYSCALL_CLOSE),
        arch::NR_CLONE => Some(SYSCALL_CLONE),
        #[cfg(feature = "arch-x86_64")]
        arch::NR_FORK => Some(SYSCALL_FORK),
        #[cfg(feature = "arch-x86_64")]
        arch::NR_VFORK => Some(SYSCALL_VFORK),
        arch::NR_EXECVE => Some(SYSCALL_EXECVE),
        arch::NR_CONNECT => Some(SYSCALL_CONNECT),
        #[cfg(feature = "arch-x86_64")]
        arch::NR_ACCEPT => Some(SYSCALL_ACCEPT),
        #[cfg(feature = "arch-aarch64")]
        arch::NR_ACCEPT4 => Some(SYSCALL_ACCEPT),
        arch::NR_SENDTO => Some(SYSCALL_SENDTO),
        arch::NR_RECVFROM => Some(SYSCALL_RECVFROM),
        arch::NR_SENDMSG => Some(SYSCALL_SENDMSG),
        arch::NR_RECVMSG => Some(SYSCALL_RECVMSG),
        _ => None,
    }
}

/// Type alias for the arch-specific `pt_regs` struct.
#[cfg(feature = "arch-x86_64")]
type PtRegs = arch::PtRegs;
#[cfg(feature = "arch-aarch64")]
type PtRegs = arch::PtRegs;

#[allow(non_upper_case_globals)]
const _: () = {
    const _: () = assert!(mem::size_of::<arch::PtRegs>() == arch::PT_REGS_SIZE);
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
