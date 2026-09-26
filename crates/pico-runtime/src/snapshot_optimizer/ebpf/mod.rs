//! eBPF backend loading and platform abstraction for snapshot optimization.

/// BPF struct type definitions shared between the BPF and userspace sides.
#[cfg(target_os = "linux")]
pub mod types;

#[cfg(target_os = "linux")]
mod linux;
mod stub;

/// Load the appropriate snapshot optimization backend for the current platform.
pub fn load_backend() -> Box<dyn crate::snapshot_optimizer::SnapshotOptimizationBackend> {
    #[cfg(target_os = "linux")]
    {
        match linux::EbpfSnapshotOptimizationBackend::load() {
            Ok(backend) => return Box::new(backend),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load eBPF snapshot optimization backend, using stub"
                );
            }
        }
    }
    Box::new(stub::StubBackend::new())
}
