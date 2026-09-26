//! Snapshot restore integration for the host agent.
//!
//! Provides [`RestoreHostParams`], the host capability evidence passed to
//! the sandboxd-owned `Restore` RPC by
//! [`super::HostAgent::restore_from_snapshot`]. Validation, blob integrity,
//! COW staging, and backend restore execute inside sandboxd; the host only
//! admits the command, supplies its capabilities, and maps the outcome.

use pico_core::{
    RuntimeType, SandboxError,
    snapshot::{
        error::SnapshotError,
        shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape},
    },
};

/// Host capability parameters needed to validate snapshot compatibility.
///
/// Populated from the host-agent's actual runtime state (adapter metadata,
/// host capacity, detected CPU architecture). These values are compared
/// against the snapshot's recorded capabilities during restore validation.
#[derive(Debug, Clone)]
pub struct RestoreHostParams {
    /// The backend expected to run the restored sandbox.
    pub backend: BackendRecord,
    /// Host CPU architecture and features.
    pub cpu: CpuShape,
    /// Host memory available for the restored sandbox.
    pub memory: MemoryShape,
    /// Host device model.
    pub device: DeviceModel,
    /// Runtime type selected for the sandbox.
    pub runtime: RuntimeType,
}

impl RestoreHostParams {
    /// Builds params for a Firecracker host with the given memory, vCPU,
    /// backend metadata, and CPU architecture.
    ///
    /// The machine type defaults to `"q35"` (Intel Q35 chipset), which is
    /// the standard for Firecracker and QEMU x86_64 guests. Set
    /// `machine_type` to `"virt"` for aarch64 or `"microvm"` for the
    /// Firecracker-specific machine profile if the guest image declares it.
    ///
    /// CPU architecture is detected from [`std::env::consts::ARCH`].
    pub fn for_firecracker(
        memory_mb: u64,
        vcpus: u32,
        backend_version: &str,
        protocol_version: &str,
        guest_agent_version: &str,
    ) -> Self {
        let arch = Self::detect_host_arch();
        // Firecracker x86_64 uses q35; aarch64 uses virt.
        let machine_type = match arch {
            "aarch64" => "virt",
            _ => "q35",
        };
        Self {
            backend: BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: backend_version.into(),
                protocol_version: protocol_version.into(),
                guest_agent_version: Some(guest_agent_version.into()),
            },
            cpu: CpuShape::new(arch),
            memory: MemoryShape { memory_mb, vcpus },
            device: DeviceModel::new(machine_type),
            runtime: RuntimeType::Firecracker,
        }
    }

    /// Detects the host CPU architecture as a string suitable for
    /// [`CpuShape`] compatibility checks.
    fn detect_host_arch() -> &'static str {
        // `std::env::consts::ARCH` gives the Rust target triple's
        // architecture (e.g. "x86_64", "aarch64"). This is the
        // compatibility dimension that snapshot metadata records.
        std::env::consts::ARCH
    }
}

/// Converts a [`SnapshotError`] to a host-agent [`SandboxError`].
///
/// Maps snapshot-specific errors to their closest host-agent equivalents
/// so the caller can use a unified error type.
pub fn snapshot_to_sandbox_error(err: &SnapshotError) -> SandboxError {
    match err {
        SnapshotError::SnapshotNotFound { id } => {
            SandboxError::SandboxNotFound(format!("snapshot not found: {id}"))
        }
        SnapshotError::SnapshotNotReady { id } => {
            SandboxError::NotReady(format!("snapshot not ready: {id}"))
        }
        SnapshotError::BlobMissing { blob_ref } => {
            SandboxError::SandboxNotFound(format!("blob missing: {blob_ref}"))
        }
        SnapshotError::BlobIntegrityMismatch {
            blob_ref,
            expected,
            actual,
        } => SandboxError::Other(format!(
            "blob integrity mismatch for {blob_ref}: expected {expected}, got {actual}"
        )),
        SnapshotError::BackendIncompatible { .. }
        | SnapshotError::CpuIncompatible { .. }
        | SnapshotError::ResourceShapeIncompatible { .. } => {
            SandboxError::NotReady(err.to_string())
        }
        SnapshotError::IntegrityRequired {
            snapshot_id,
            reason,
        } => SandboxError::Other(format!(
            "integrity required for snapshot {snapshot_id}: {reason}"
        )),
        SnapshotError::PartialRestoreCleanup { reason } => {
            SandboxError::Conflict(format!("partial restore cleanup required: {reason}"))
        }
        _ => SandboxError::Other(err.to_string()),
    }
}
