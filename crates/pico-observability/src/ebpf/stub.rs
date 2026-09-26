use std::path::Path;

use crate::{
    CgroupId, CpuSampleEvent, IoSampleEvent, MemorySnapshot, ObservabilityError,
    SyscallLatencyEvent,
};

pub(super) struct StubBackend {
    _private: (),
}

impl StubBackend {
    #[must_use]
    pub(super) fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for StubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ObservabilityBackend for StubBackend {
    fn register_sandbox(
        &self,
        _sandbox_id: &str,
        _cgroup_id: CgroupId,
        _cgroup_path: &Path,
    ) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn unregister_sandbox(&self, _sandbox_id: &str) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn poll_memory(&self, _sandbox_id: &str) -> Result<MemorySnapshot, ObservabilityError> {
        Err(ObservabilityError::Unavailable(
            "eBPF observability not available on non-Linux".into(),
        ))
    }

    fn enable_cpu_profiling(
        &self,
        _sandbox_id: &str,
        _sample_hz: u32,
    ) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn disable_cpu_profiling(&self, _sandbox_id: &str) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn enable_io_tracing(&self, _sandbox_id: &str) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn disable_io_tracing(&self, _sandbox_id: &str) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn enable_syscall_latency(
        &self,
        _sandbox_id: &str,
        _sample_rate: u8,
    ) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn disable_syscall_latency(&self, _sandbox_id: &str) -> Result<(), ObservabilityError> {
        Ok(())
    }

    fn drain_cpu_samples(&self) -> Vec<CpuSampleEvent> {
        Vec::new()
    }

    fn drain_io_events(&self) -> Vec<IoSampleEvent> {
        Vec::new()
    }

    fn drain_syscall_latency_events(&self) -> Vec<SyscallLatencyEvent> {
        Vec::new()
    }

    fn is_available(&self) -> bool {
        false
    }
}
