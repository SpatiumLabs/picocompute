#![deny(missing_docs)]

//! Per-sandbox observability via eBPF and cgroup-based metrics.
//!
//! Provides CPU profiling, memory tracking, I/O wait time measurement,
//! and syscall latency histograms without requiring guest cooperation.
//! Falls back to cgroup polling when the eBPF backend is unavailable.

/// eBPF backend loader module.
pub mod ebpf;
/// Helper functions for recording observability metrics.
pub mod metrics;

use std::sync::Arc;

use parking_lot::RwLock;
use pico_core::SandboxId;
use pico_telemetry::metrics::{Counter, Gauge, Histogram, Labels, attr};
use std::sync::LazyLock;
use thiserror::Error;

/// Errors returned by observability operations.
#[derive(Debug, Clone, Error)]
pub enum ObservabilityError {
    /// The eBPF backend is unavailable on this host.
    #[error("eBPF observability not available: {0}")]
    Unavailable(String),
    /// The requested sandbox has not been registered for observability.
    #[error("sandbox {0} not registered")]
    SandboxNotRegistered(Box<SandboxId>),
}

/// Kernel cgroup identifier used for eBPF correlation.
pub type CgroupId = u64;
/// Stack trace represented as a vector of instruction pointers.
pub type StackTrace = Vec<u64>;

/// A CPU profiling sample captured by the eBPF perf-event program.
#[derive(Debug, Clone)]
pub struct CpuSampleEvent {
    /// The sandbox that was sampled.
    pub sandbox_id: SandboxId,
    /// Kernel cgroup ID of the sampled task.
    pub cgroup_id: CgroupId,
    /// Process ID of the sampled task.
    pub pid: u32,
    /// Thread ID of the sampled task.
    pub tid: u32,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Number of valid frames in the stack trace.
    pub stack_len: u32,
    /// Instruction pointer addresses forming the stack trace.
    pub stack: [u64; 127],
}

/// A point-in-time snapshot of sandbox memory usage from cgroup controllers.
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    /// The sandbox this snapshot belongs to.
    pub sandbox_id: SandboxId,
    /// Current memory usage in bytes (memory.current).
    pub current_bytes: u64,
    /// Resident set size: anonymous + file-backed pages.
    pub rss_bytes: u64,
    /// Anonymous memory pages.
    pub anon_bytes: u64,
    /// File-backed memory pages.
    pub file_bytes: u64,
    /// Swap usage in bytes.
    pub swap_bytes: u64,
    /// Cumulative OOM kill count.
    pub oom_kill_count: u64,
    /// Memory pressure (some avg10) as a percentage 0.0-100.0.
    pub memory_pressure_some_avg10: f64,
}

/// A block I/O event captured by the eBPF tracepoint programs.
///
/// Note: I/O tracepoint attachment is not yet wired; this type is reserved
/// for future use once proper request correlation is implemented.
#[derive(Debug, Clone)]
pub struct IoSampleEvent {
    /// The sandbox that generated the I/O.
    pub sandbox_id: SandboxId,
    /// Kernel cgroup ID of the task.
    pub cgroup_id: CgroupId,
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
    /// Whether this is a read operation.
    pub is_read: bool,
}

/// A syscall latency measurement captured by the eBPF tracepoint programs.
#[derive(Debug, Clone)]
pub struct SyscallLatencyEvent {
    /// The sandbox that executed the syscall.
    pub sandbox_id: SandboxId,
    /// Kernel cgroup ID of the task.
    pub cgroup_id: CgroupId,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Syscall type identifier (see [`latency_syscall_name`]).
    pub syscall_type: u8,
    /// Enter timestamp in nanoseconds (monotonic clock).
    pub enter_ts_ns: u64,
    /// Latency in nanoseconds.
    pub latency_ns: u64,
}

impl SyscallLatencyEvent {
    /// Returns the human-readable syscall name for the type identifier.
    #[must_use]
    pub fn syscall_name(&self) -> &'static str {
        latency_syscall_name(self.syscall_type)
    }
}

/// Type identifier for the `read` syscall.
pub const SYSCALL_TYPE_READ: u8 = 0;
/// Type identifier for the `write` syscall.
pub const SYSCALL_TYPE_WRITE: u8 = 1;
/// Type identifier for the `open` syscall.
pub const SYSCALL_TYPE_OPEN: u8 = 2;
/// Type identifier for the `close` syscall.
pub const SYSCALL_TYPE_CLOSE: u8 = 3;
/// Type identifier for the `clone` syscall.
pub const SYSCALL_TYPE_CLONE: u8 = 4;
/// Type identifier for the `fork` syscall.
pub const SYSCALL_TYPE_FORK: u8 = 5;
/// Type identifier for the `vfork` syscall.
pub const SYSCALL_TYPE_VFORK: u8 = 6;
/// Type identifier for the `execve` syscall.
pub const SYSCALL_TYPE_EXECVE: u8 = 7;
/// Type identifier for the `connect` syscall.
pub const SYSCALL_TYPE_CONNECT: u8 = 8;
/// Type identifier for the `accept` syscall.
pub const SYSCALL_TYPE_ACCEPT: u8 = 9;
/// Type identifier for the `sendto` syscall.
pub const SYSCALL_TYPE_SENDTO: u8 = 10;
/// Type identifier for the `recvfrom` syscall.
pub const SYSCALL_TYPE_RECVFROM: u8 = 11;
/// Type identifier for the `sendmsg` syscall.
pub const SYSCALL_TYPE_SENDMSG: u8 = 12;
/// Type identifier for the `recvmsg` syscall.
pub const SYSCALL_TYPE_RECVMSG: u8 = 13;

/// Returns the human-readable name for a syscall latency type identifier.
#[must_use]
pub fn latency_syscall_name(syscall_type: u8) -> &'static str {
    match syscall_type {
        SYSCALL_TYPE_READ => "read",
        SYSCALL_TYPE_WRITE => "write",
        SYSCALL_TYPE_OPEN => "open",
        SYSCALL_TYPE_CLOSE => "close",
        SYSCALL_TYPE_CLONE => "clone",
        SYSCALL_TYPE_FORK => "fork",
        SYSCALL_TYPE_VFORK => "vfork",
        SYSCALL_TYPE_EXECVE => "execve",
        SYSCALL_TYPE_CONNECT => "connect",
        SYSCALL_TYPE_ACCEPT => "accept",
        SYSCALL_TYPE_SENDTO => "sendto",
        SYSCALL_TYPE_RECVFROM => "recvfrom",
        SYSCALL_TYPE_SENDMSG => "sendmsg",
        SYSCALL_TYPE_RECVMSG => "recvmsg",
        _ => "unknown",
    }
}

/// Configuration for the observability subsystem.
pub struct ObservabilityConfig {
    /// CPU sampling frequency in Hz.
    pub cpu_sampling_hz: u32,
    /// Whether I/O tracing is enabled.
    pub io_tracing_enabled: bool,
    /// Whether syscall latency tracing is enabled.
    pub syscall_latency_enabled: bool,
    /// Per-cgroup syscall event sampling rate, 0 = record 100%, N > 1 = record ~1-in-N.
    pub syscall_sample_rate: u8,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            cpu_sampling_hz: 99,
            io_tracing_enabled: false,
            syscall_latency_enabled: false,
            syscall_sample_rate: 0,
        }
    }
}

/// Global OpenTelemetry metrics for the observability subsystem.
pub static OBSERVABILITY_METRICS: LazyLock<ObservabilityMetrics> =
    LazyLock::new(ObservabilityMetrics::register);

/// Registered OpenTelemetry metrics.
pub struct ObservabilityMetrics {
    /// Total CPU profiling samples collected.
    pub cpu_samples_total: Counter,
    /// Whether CPU profiling is available on this host.
    pub cpu_profile_available: Gauge,
    /// Per-sandbox memory usage in bytes.
    pub memory_usage_bytes: Gauge,
    /// Per-sandbox swap usage in bytes.
    pub memory_swap_bytes: Gauge,
    /// Cumulative OOM kill events.
    pub memory_oom_kills_total: Counter,
    /// Memory pressure gauge (some avg10).
    pub memory_pressure_avg10: Gauge,
    /// I/O read latency histogram.
    pub io_read_latency_seconds: Histogram,
    /// I/O write latency histogram.
    pub io_write_latency_seconds: Histogram,
    /// Total I/O operations observed.
    pub io_operations_total: Counter,
    /// Whether the eBPF observability backend is active.
    pub ebpf_observability_enabled: Gauge,
    /// Per-sandbox, per-syscall latency histogram.
    pub syscall_latency_seconds: Histogram,
}

impl ObservabilityMetrics {
    fn register() -> Self {
        Self {
            cpu_samples_total: Counter::register("pico_cpu_samples_total"),
            cpu_profile_available: Gauge::register("pico_cpu_profile_available"),
            memory_usage_bytes: Gauge::register("pico_observability_memory_usage_bytes"),
            memory_swap_bytes: Gauge::register("pico_observability_memory_swap_bytes"),
            memory_oom_kills_total: Counter::register("pico_observability_memory_oom_kills_total"),
            memory_pressure_avg10: Gauge::register("pico_observability_memory_pressure_avg10"),
            io_read_latency_seconds: Histogram::register(
                "pico_observability_io_read_latency_seconds",
            ),
            io_write_latency_seconds: Histogram::register(
                "pico_observability_io_write_latency_seconds",
            ),
            io_operations_total: Counter::register("pico_observability_io_operations_total"),
            ebpf_observability_enabled: Gauge::register("pico_ebpf_observability_enabled"),
            syscall_latency_seconds: Histogram::register("pico_syscall_latency_seconds"),
        }
    }
}

/// Backend trait for observability data collection.
///
/// Implementations may use eBPF (Linux) or provide a no-op stub (non-Linux).
pub trait ObservabilityBackend: Send + Sync {
    /// Register a sandbox for observability tracking.
    fn register_sandbox(
        &self,
        sandbox_id: &str,
        cgroup_id: CgroupId,
        cgroup_path: &std::path::Path,
    ) -> Result<(), ObservabilityError>;

    /// Unregister a sandbox from observability tracking.
    fn unregister_sandbox(&self, sandbox_id: &str) -> Result<(), ObservabilityError>;

    /// Poll current memory usage for a sandbox from cgroup controllers.
    fn poll_memory(&self, sandbox_id: &str) -> Result<MemorySnapshot, ObservabilityError>;

    /// Enable CPU profiling for a sandbox at the given sample rate.
    fn enable_cpu_profiling(
        &self,
        sandbox_id: &str,
        sample_hz: u32,
    ) -> Result<(), ObservabilityError>;

    /// Disable CPU profiling for a sandbox.
    fn disable_cpu_profiling(&self, sandbox_id: &str) -> Result<(), ObservabilityError>;

    /// Enable I/O tracing for a sandbox.
    fn enable_io_tracing(&self, sandbox_id: &str) -> Result<(), ObservabilityError>;

    /// Disable I/O tracing for a sandbox.
    fn disable_io_tracing(&self, sandbox_id: &str) -> Result<(), ObservabilityError>;

    /// Enable syscall latency tracing for a sandbox.
    ///
    /// `sample_rate` controls how many events are discarded to reduce
    /// ring buffer pressure: 0 or 1 = record 100%, N > 1 = record ~1-in-N.
    fn enable_syscall_latency(
        &self,
        sandbox_id: &str,
        sample_rate: u8,
    ) -> Result<(), ObservabilityError>;

    /// Disable syscall latency tracing for a sandbox.
    fn disable_syscall_latency(&self, sandbox_id: &str) -> Result<(), ObservabilityError>;

    /// Drain all pending CPU samples from the backend.
    fn drain_cpu_samples(&self) -> Vec<CpuSampleEvent>;

    /// Drain all pending I/O events from the backend.
    fn drain_io_events(&self) -> Vec<IoSampleEvent>;

    /// Drain all pending syscall latency events from the backend.
    fn drain_syscall_latency_events(&self) -> Vec<SyscallLatencyEvent>;

    /// Returns true if the backend is available and functional.
    fn is_available(&self) -> bool;
}

/// Coordinates observability across all registered sandboxes.
///
/// Manages sandbox registration lifecycle, periodic metric draining,
/// and fallback to cgroup polling when the eBPF backend is unavailable.
pub struct ObservabilityManager {
    backend: Box<dyn ObservabilityBackend>,
    sandbox_ids: Arc<RwLock<hashbrown::HashMap<String, RegisteredSandbox>>>,
}

/// A sandbox registered with the observability backend.
#[derive(Debug, Clone)]
struct RegisteredSandbox {
    /// Tenant that owns the sandbox, when the caller supplied it.
    ///
    /// Used only to attribute metrics: on a shared host the sandbox-scoped
    /// series is keyed by `tenant_id` instead of `sandbox_id`.
    tenant_id: Option<String>,
}

impl ObservabilityManager {
    /// Creates a new manager, auto-detecting the backend (eBPF on Linux, stub otherwise).
    pub fn new() -> Self {
        let backend: Box<dyn ObservabilityBackend> = ebpf::load_backend();
        let available = backend.is_available();
        crate::metrics::record_ebpf_enabled(available);
        if available {
            OBSERVABILITY_METRICS
                .cpu_profile_available
                .set(1.0, &Labels::host());
        }
        Self {
            backend,
            sandbox_ids: Arc::new(RwLock::new(hashbrown::HashMap::default())),
        }
    }

    /// Register a sandbox with the observability backend.
    ///
    /// `tenant_id` is retained so the memory and syscall-latency series can be
    /// attributed by tenant on a shared host, where `sandbox_id` must not be
    /// published. No-op if the backend is unavailable.
    pub fn register_sandbox(
        &self,
        sandbox_id: &str,
        tenant_id: Option<&str>,
        cgroup_id: CgroupId,
        cgroup_path: &std::path::Path,
    ) {
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self
            .backend
            .register_sandbox(sandbox_id, cgroup_id, cgroup_path)
        {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to register sandbox for eBPF observability"
            );
            return;
        }
        self.sandbox_ids.write().insert(
            sandbox_id.to_string(),
            RegisteredSandbox {
                tenant_id: tenant_id.map(str::to_owned),
            },
        );
        tracing::info!(
            sandbox_id = %sandbox_id,
            cgroup_id,
            "registered sandbox for eBPF observability"
        );
    }

    /// Unregister a sandbox from the observability backend.
    pub fn unregister_sandbox(&self, sandbox_id: &str) {
        self.sandbox_ids.write().remove(sandbox_id);
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self.backend.unregister_sandbox(sandbox_id) {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to unregister sandbox from eBPF observability"
            );
        }
    }

    /// Poll memory usage for a sandbox.
    ///
    /// Returns `None` if the backend is unavailable or the poll fails.
    #[must_use]
    pub fn poll_memory(&self, sandbox_id: &str) -> Option<MemorySnapshot> {
        if !self.backend.is_available() {
            return None;
        }
        match self.backend.poll_memory(sandbox_id) {
            Ok(snapshot) => Some(snapshot),
            Err(e) => {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %e,
                    "failed to poll memory via eBPF"
                );
                None
            }
        }
    }

    /// Drain pending CPU samples and memory snapshots, exporting as OpenTelemetry metrics.
    ///
    /// No-op if the backend is unavailable.
    pub fn drain_and_export_samples(&self) {
        if !self.backend.is_available() {
            return;
        }
        let cpu_samples = self.backend.drain_cpu_samples();
        crate::metrics::record_cpu_sample_collected(cpu_samples.len() as u64);

        self.drain_and_export_syscall_latency();

        // One label set per sandbox, so the four memory series stay consistent
        // with each other under whichever identity policy is in force.
        let sandboxes = self.sandbox_ids.read();
        for (sandbox_id, registered) in sandboxes.iter() {
            if let Some(snapshot) = self.poll_memory(sandbox_id) {
                let labels = Labels::sandbox(sandbox_id.as_str(), registered.tenant_id.as_deref());
                OBSERVABILITY_METRICS
                    .memory_usage_bytes
                    .set(snapshot.current_bytes as f64, &labels);
                OBSERVABILITY_METRICS
                    .memory_swap_bytes
                    .set(snapshot.swap_bytes as f64, &labels);
                OBSERVABILITY_METRICS
                    .memory_oom_kills_total
                    .inc_by(snapshot.oom_kill_count, &labels);
            }
        }
    }

    /// Drain pending syscall latency events and export as OpenTelemetry histograms.
    ///
    /// Sandbox ID resolution happens in the ring buffer consumer thread, so
    /// this drain path uses the pre-resolved `sandbox_id` field directly
    /// without building a separate reverse lookup map.
    pub fn drain_and_export_syscall_latency(&self) {
        if !self.backend.is_available() {
            return;
        }
        // Resolved once so the syscall series and the memory series agree on
        // identity when redaction is on.
        let sandboxes = self.sandbox_ids.read();
        let events = self.backend.drain_syscall_latency_events();
        for event in &events {
            let latency_secs = event.latency_ns as f64 / 1_000_000_000.0;
            let syscall_name = event.syscall_name();
            let tenant_id = sandboxes
                .get(event.sandbox_id.as_str())
                .and_then(|registered| registered.tenant_id.as_deref());
            OBSERVABILITY_METRICS.syscall_latency_seconds.record(
                latency_secs,
                &Labels::sandbox(event.sandbox_id.as_str(), tenant_id)
                    .with(attr::SYSCALL, syscall_name),
            );
        }
    }

    /// Enable syscall latency tracing for a sandbox.
    pub fn enable_syscall_latency(&self, sandbox_id: &str, sample_rate: u8) {
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self.backend.enable_syscall_latency(sandbox_id, sample_rate) {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to enable syscall latency tracing"
            );
        }
    }

    /// Disable syscall latency tracing for a sandbox.
    pub fn disable_syscall_latency(&self, sandbox_id: &str) {
        if !self.backend.is_available() {
            return;
        }
        if let Err(e) = self.backend.disable_syscall_latency(sandbox_id) {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %e,
                "failed to disable syscall latency tracing"
            );
        }
    }

    /// Returns true if the backend is available and functional.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }
}

impl Default for ObservabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_type_constants_are_unique() {
        let types = [
            SYSCALL_TYPE_READ,
            SYSCALL_TYPE_WRITE,
            SYSCALL_TYPE_OPEN,
            SYSCALL_TYPE_CLOSE,
            SYSCALL_TYPE_CLONE,
            SYSCALL_TYPE_FORK,
            SYSCALL_TYPE_VFORK,
            SYSCALL_TYPE_EXECVE,
            SYSCALL_TYPE_CONNECT,
            SYSCALL_TYPE_ACCEPT,
            SYSCALL_TYPE_SENDTO,
            SYSCALL_TYPE_RECVFROM,
            SYSCALL_TYPE_SENDMSG,
            SYSCALL_TYPE_RECVMSG,
        ];
        for (i, &a) in types.iter().enumerate() {
            for (j, &b) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "syscall type constants must be unique");
                }
            }
        }
    }

    #[test]
    fn latency_syscall_name_returns_non_empty_for_all_types() {
        for t in 0u8..=13 {
            let name = latency_syscall_name(t);
            assert!(!name.is_empty(), "type {t} should have a name");
            assert_ne!(name, "unknown", "type {t} should not be unknown");
        }
        assert_eq!(latency_syscall_name(255), "unknown");
    }

    #[test]
    fn syscall_latency_event_syscall_name_matches_type() {
        let event = SyscallLatencyEvent {
            sandbox_id: SandboxId::from_string("test"),
            cgroup_id: 1,
            pid: 2,
            tid: 3,
            syscall_type: SYSCALL_TYPE_READ,
            enter_ts_ns: 100,
            latency_ns: 50,
        };
        assert_eq!(event.syscall_name(), "read");
    }

    #[test]
    fn observability_config_default_has_syscall_latency_disabled() {
        let cfg = ObservabilityConfig::default();
        assert!(!cfg.syscall_latency_enabled);
        assert_eq!(cfg.syscall_sample_rate, 0);
    }

    /// BPF config struct must match the eBPF-side `ObservabilityConfig`
    /// byte-for-byte. Regressions here cause silent data corruption across
    /// the BPF-userspace boundary.
    #[test]
    #[cfg(target_os = "linux")]
    fn bpf_config_struct_has_expected_layout() {
        use crate::ebpf::types::ObservabilityBpfConfig;

        assert_eq!(std::mem::size_of::<ObservabilityBpfConfig>(), 8);
        assert_eq!(std::mem::align_of::<ObservabilityBpfConfig>(), 4);

        let cfg = ObservabilityBpfConfig {
            cpu_sampling_enabled: 1,
            io_tracing_enabled: 0,
            syscall_latency_enabled: 1,
            syscall_sample_rate: 10,
            sample_rate: 99,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &cfg as *const _ as *const u8,
                std::mem::size_of::<ObservabilityBpfConfig>(),
            )
        };
        assert_eq!(bytes[0], 1, "cpu_sampling_enabled at offset 0");
        assert_eq!(bytes[1], 0, "io_tracing_enabled at offset 1");
        assert_eq!(bytes[2], 1, "syscall_latency_enabled at offset 2");
        assert_eq!(bytes[3], 10, "syscall_sample_rate at offset 3");
        let sample_rate_bytes = &bytes[4..8];
        assert_eq!(
            sample_rate_bytes,
            &99u32.to_ne_bytes(),
            "sample_rate at offset 4"
        );
    }

    /// SyscallLatencyEventBpf must match the eBPF-side SyscallLatencyEvent
    /// struct byte-for-byte so ring-buffer reads are correct.
    #[test]
    #[cfg(target_os = "linux")]
    fn syscall_latency_event_bpf_has_expected_layout() {
        use crate::ebpf::types::SyscallLatencyEventBpf;

        assert_eq!(std::mem::size_of::<SyscallLatencyEventBpf>(), 40);
        assert_eq!(std::mem::align_of::<SyscallLatencyEventBpf>(), 8);
        assert_eq!(std::mem::offset_of!(SyscallLatencyEventBpf, cgroup_id), 0);
        assert_eq!(std::mem::offset_of!(SyscallLatencyEventBpf, pid), 8);
        assert_eq!(std::mem::offset_of!(SyscallLatencyEventBpf, tid), 12);
        assert_eq!(
            std::mem::offset_of!(SyscallLatencyEventBpf, syscall_type),
            16
        );
        assert_eq!(
            std::mem::offset_of!(SyscallLatencyEventBpf, enter_ts_ns),
            24
        );
        assert_eq!(std::mem::offset_of!(SyscallLatencyEventBpf, latency_ns), 32);
    }
}
