//! eBPF backend loading and platform abstraction.
//!
//! On Linux, loads the `pico-observability-ebpf` BPF ELF and
//! manages per-cgroup observability configuration. On other platforms,
//! returns a no-op stub.

/// BPF struct type definitions shared between the BPF and userspace sides.
#[cfg(target_os = "linux")]
pub mod types;

#[cfg(target_os = "linux")]
mod linux;
mod stub;

/// Load the appropriate observability backend for the current platform.
///
/// On Linux, attempts to load the eBPF backend. Falls back to the stub
/// if the BPF ELF is unavailable or the load fails.
pub fn load_backend() -> Box<dyn crate::ObservabilityBackend> {
    #[cfg(target_os = "linux")]
    {
        match linux::EbpfObservabilityBackend::load() {
            Ok(backend) => return Box::new(backend),
            Err(e) => {
                tracing::warn!(error = %e, "failed to load eBPF observability backend, using stub");
            }
        }
    }
    Box::new(stub::StubBackend::new())
}
