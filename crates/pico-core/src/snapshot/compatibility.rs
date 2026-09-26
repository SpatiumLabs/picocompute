//! Snapshot compatibility validation.
//!
//! Compatibility checks that can be derived from metadata without
//! loading snapshot blobs. Per ADR-0007, validation occurs from
//! trusted metadata before blobs are attached to a runtime.

use serde::{Deserialize, Serialize};

use crate::identity::SandboxId;
use crate::identity::SnapshotId;
use crate::identity::TenantId;
use crate::runtime::RuntimeType;

use super::credential_policy::CredentialSnapshotPolicy;
use super::error::{SnapshotError, SnapshotResult};
use super::profile::SnapshotProfile;
use super::purpose::SnapshotPurpose;
use super::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
use super::state::SnapshotState;

/// A record of all compatibility-relevant metadata for a snapshot.
///
/// This can be queried without loading blobs. Every restore validates
/// against this record before guest execution begins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityRecord {
    /// Schema version of this compatibility record.
    pub schema_version: u32,

    // Identity
    /// The snapshot this record describes.
    pub snapshot_id: SnapshotId,
    /// The tenant that owns this snapshot.
    pub tenant_id: TenantId,
    /// The sandbox that produced this snapshot.
    pub sandbox_id: SandboxId,
    /// Snapshot purpose.
    pub purpose: SnapshotPurpose,
    /// State profile.
    pub profile: SnapshotProfile,

    // Backend
    /// Backend information at snapshot time.
    pub backend: BackendRecord,

    // Shape
    /// CPU requirements.
    pub cpu_shape: CpuShape,
    /// Memory and vCPU requirements.
    pub memory_shape: MemoryShape,
    /// Device model requirements.
    pub device_model: DeviceModel,

    // Image
    /// Image identifier.
    pub image_id: String,
    /// Root filesystem digest.
    #[serde(default)]
    pub rootfs_digest: Option<String>,
    /// Kernel version.
    #[serde(default)]
    pub kernel_version: Option<String>,

    // Exclusions
    /// Mount classes excluded from this snapshot.
    #[serde(default)]
    pub excluded_mount_classes: Vec<String>,

    // Policy
    /// Policy epoch at snapshot time (historical, not restored authority).
    #[serde(default)]
    pub policy_epoch: Option<u64>,
    /// Network identity policy applied at snapshot time.
    #[serde(default)]
    pub network_policy_ref: Option<String>,

    // Workload
    /// Workload class for isolation constraints.
    #[serde(default)]
    pub workload_class: Option<String>,
    /// Isolation floor required.
    #[serde(default)]
    pub isolation_floor: Option<String>,
    /// Data classification level.
    #[serde(default)]
    pub data_classification: Option<String>,

    // Lineage
    /// Snapshot lineage type.
    #[serde(default)]
    pub lineage_type: Option<String>,

    // Credential policy
    /// Credential lifecycle policy for snapshot/restore/fork.
    #[serde(default)]
    pub credential_policy: Option<CredentialSnapshotPolicy>,
}

impl CompatibilityRecord {
    /// Current schema version for the compatibility record format.
    pub const CURRENT_SCHEMA_VERSION: u32 = 2;

    /// Performs all metadata-level compatibility checks against a host environment.
    ///
    /// `current_policy_epoch` is the host's current policy engine epoch.
    /// When the snapshot records a policy epoch (historical evidence from capture
    /// time), we require an exact match to prevent cross-epoch restore attacks.
    ///
    /// Returns Ok(()) if compatible, or a typed SnapshotError describing
    /// the first incompatibility found.
    pub fn check_compatibility(
        &self,
        host_backend: &BackendRecord,
        host_cpu: &CpuShape,
        host_memory: &MemoryShape,
        host_device: &DeviceModel,
        host_runtime: RuntimeType,
        current_policy_epoch: u64,
    ) -> SnapshotResult<()> {
        // Schema version check: reject versions newer than what we support.
        // Older versions (v1) are still restorable with forward-compatible
        // defaults for fields added in later versions.
        if self.schema_version > Self::CURRENT_SCHEMA_VERSION {
            return Err(SnapshotError::UnsupportedSchemaVersion {
                version: self.schema_version,
            });
        }

        // Backend family
        if !self.backend.is_same_family(&host_backend.backend_type) {
            return Err(SnapshotError::BackendIncompatible {
                snapshot_backend: self.backend.backend_type.clone(),
                host_backend: host_backend.backend_type.clone(),
            });
        }

        // Backend version
        if !self
            .backend
            .is_version_compatible(&host_backend.backend_version)
        {
            return Err(SnapshotError::RuntimeVersionIncompatible {
                snapshot_version: self.backend.backend_version.clone(),
                host_version: host_backend.backend_version.clone(),
            });
        }

        // CPU
        if !self.cpu_shape.is_compatible_with(host_cpu) {
            return Err(SnapshotError::CpuIncompatible {
                required: format!("{:?}", self.cpu_shape),
                available: format!("{:?}", host_cpu),
            });
        }

        // Memory
        if !self.memory_shape.fits_on_host(host_memory) {
            return Err(SnapshotError::ResourceShapeIncompatible {
                dimension: "memory/vcpu".into(),
                snapshot_value: format!(
                    "{}MB/{}vCPU",
                    self.memory_shape.memory_mb, self.memory_shape.vcpus
                ),
                host_value: format!("{}MB/{}vCPU", host_memory.memory_mb, host_memory.vcpus),
            });
        }

        // Device model
        if !self.device_model.is_compatible_with(host_device) {
            return Err(SnapshotError::DeviceModelIncompatible {
                snapshot_model: self.device_model.machine_type.clone(),
                host_model: host_device.machine_type.clone(),
            });
        }

        // Protocol version
        if self.backend.protocol_version != host_backend.protocol_version {
            return Err(SnapshotError::ProtocolIncompatible {
                required: self.backend.protocol_version.clone(),
                available: host_backend.protocol_version.clone(),
            });
        }

        // Cross-backend runtime check: verify the host runtime matches the
        // snapshot backend family. This provides an early rejection before
        // the backend-level compatibility check runs.
        if !self.backend.is_same_family(&host_runtime.to_string()) {
            return Err(SnapshotError::BackendIncompatible {
                snapshot_backend: self.backend.backend_type.clone(),
                host_backend: host_runtime.to_string(),
            });
        }

        // Policy epoch cross-check: prevent restoring a snapshot captured
        // under a permissive policy epoch into a restrictive one.
        //
        // The snapshot records the policy epoch at capture time. If the
        // current policy epoch differs, the policy set has changed since
        // the snapshot was taken and we must reject the restore.
        //
        // Snapshots without a recorded policy_epoch (legacy) are allowed
        // through; this is explicitly NOT a security hole because legacy
        // snapshots predate policy-epoch enforcement.
        if let Some(snapshot_epoch) = self.policy_epoch
            && snapshot_epoch != current_policy_epoch
        {
            return Err(SnapshotError::PolicyEpochIncompatible {
                snapshot_epoch,
                current_epoch: current_policy_epoch,
            });
        }

        Ok(())
    }

    /// Validates tenant ownership for a snapshot.
    pub fn check_tenant(&self, request_tenant: &TenantId) -> SnapshotResult<()> {
        if &self.tenant_id != request_tenant {
            return Err(SnapshotError::TenantMismatch {
                snapshot_id: self.snapshot_id.to_string(),
                snapshot_tenant: self.tenant_id.to_string(),
                request_tenant: request_tenant.to_string(),
            });
        }
        Ok(())
    }

    /// Validates that the snapshot is in a restorable state.
    pub fn check_state(&self, state: SnapshotState) -> SnapshotResult<()> {
        match state {
            SnapshotState::Ready => Ok(()),
            SnapshotState::Staging => Err(SnapshotError::SnapshotNotReady {
                id: self.snapshot_id.to_string(),
            }),
            SnapshotState::Revoked => Err(SnapshotError::SnapshotRevoked {
                id: self.snapshot_id.to_string(),
            }),
            SnapshotState::Deleting | SnapshotState::Deleted => {
                Err(SnapshotError::SnapshotNotFound {
                    id: self.snapshot_id.to_string(),
                })
            }
            SnapshotState::Failed => Err(SnapshotError::SnapshotNotReady {
                id: self.snapshot_id.to_string(),
            }),
        }
    }

    /// Validates that the profile supports the requested operation.
    pub fn check_profile_for_operation(&self, requires_memory: bool) -> SnapshotResult<()> {
        if requires_memory && !self.profile.preserves_memory() {
            return Err(SnapshotError::PolicyIncompatible {
                reason: format!(
                    "operation requires memory profile, but snapshot has {} profile",
                    self.profile.as_str()
                ),
            });
        }
        Ok(())
    }

    /// Validates snapshot purpose against restore intent.
    ///
    /// Single purpose gate owned by core: `Fork` intent requires exactly
    /// fork purpose, `Restore` intent requires any user-restorable purpose.
    /// Supervisors pass intent instead of re-checking purpose inline.
    pub fn check_purpose_for_intent(
        &self,
        intent: super::purpose::RestoreIntent,
    ) -> SnapshotResult<()> {
        self.purpose.check_for_intent(intent)
    }
}

/// The current compatibility record schema version as a constant.
pub const COMPATIBILITY_SCHEMA_VERSION: u32 = CompatibilityRecord::CURRENT_SCHEMA_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_compat() -> CompatibilityRecord {
        CompatibilityRecord {
            schema_version: 2,
            snapshot_id: SnapshotId::generate(),
            tenant_id: TenantId::from_string("tnt_test"),
            sandbox_id: SandboxId::generate(),
            purpose: SnapshotPurpose::Session,
            profile: SnapshotProfile::Filesystem,
            backend: BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "1.10.0".into(),
                guest_agent_version: Some("0.5.0".into()),
            },
            cpu_shape: CpuShape {
                architecture: "x86_64".into(),
                vendor: Some("Intel".into()),
                template: None,
                required_features: vec!["sse4_2".into()],
            },
            memory_shape: MemoryShape {
                memory_mb: 2048,
                vcpus: 2,
            },
            device_model: DeviceModel {
                machine_type: "q35".into(),
                config_version: None,
                required_devices: vec!["virtio-net".into(), "virtio-blk".into()],
            },
            image_id: "img_test".into(),
            rootfs_digest: Some("sha256:abc123".into()),
            kernel_version: Some("6.1.0".into()),
            excluded_mount_classes: vec!["secret".into(), "runtime_tmp".into()],
            policy_epoch: Some(1),
            network_policy_ref: None,
            workload_class: Some("interactive".into()),
            isolation_floor: Some("vm".into()),
            data_classification: Some("internal".into()),
            lineage_type: Some("direct".into()),
            credential_policy: Some(CredentialSnapshotPolicy::production()),
        }
    }

    fn make_host_backend() -> BackendRecord {
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "1.10.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        }
    }

    fn make_host_cpu() -> CpuShape {
        CpuShape {
            architecture: "x86_64".into(),
            vendor: Some("Intel".into()),
            template: None,
            required_features: vec!["sse4_2".into(), "avx2".into(), "aes".into()],
        }
    }

    fn make_host_memory() -> MemoryShape {
        MemoryShape {
            memory_mb: 4096,
            vcpus: 4,
        }
    }

    fn make_host_device() -> DeviceModel {
        DeviceModel {
            machine_type: "q35".into(),
            config_version: None,
            required_devices: vec![
                "virtio-net".into(),
                "virtio-blk".into(),
                "virtio-rng".into(),
            ],
        }
    }

    #[test]
    fn full_compatibility_check_passes() {
        let compat = make_compat();
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1, // current_policy_epoch matches snapshot's policy_epoch
        );
        assert!(result.is_ok());
    }

    #[test]
    fn backend_mismatch_is_rejected() {
        let compat = make_compat();
        let mut host = make_host_backend();
        host.backend_type = "qemu".into();
        let result = compat.check_compatibility(
            &host,
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::BackendIncompatible { .. })
        ));
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let compat = make_compat();
        let mut host = make_host_backend();
        host.backend_version = "1.9.0".into();
        let result = compat.check_compatibility(
            &host,
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::RuntimeVersionIncompatible { .. })
        ));
    }

    #[test]
    fn cpu_incompatible_is_rejected() {
        let compat = make_compat();
        let mut host_cpu = make_host_cpu();
        host_cpu.architecture = "aarch64".into();
        let result = compat.check_compatibility(
            &make_host_backend(),
            &host_cpu,
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(result, Err(SnapshotError::CpuIncompatible { .. })));
    }

    #[test]
    fn insufficient_memory_is_rejected() {
        let compat = make_compat();
        let host_mem = MemoryShape {
            memory_mb: 512,
            vcpus: 1,
        };
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &host_mem,
            &make_host_device(),
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::ResourceShapeIncompatible { .. })
        ));
    }

    #[test]
    fn device_model_mismatch_is_rejected() {
        let compat = make_compat();
        let host_dev = DeviceModel::new("pc");
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &host_dev,
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::DeviceModelIncompatible { .. })
        ));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut compat = make_compat();
        compat.schema_version = 99;
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::UnsupportedSchemaVersion { version: 99 })
        ));
    }

    #[test]
    fn tenant_check_passes() {
        let compat = make_compat();
        assert!(
            compat
                .check_tenant(&TenantId::from_string("tnt_test"))
                .is_ok()
        );
    }

    #[test]
    fn tenant_check_fails() {
        let compat = make_compat();
        let result = compat.check_tenant(&TenantId::from_string("tnt_other"));
        assert!(matches!(result, Err(SnapshotError::TenantMismatch { .. })));
    }

    #[test]
    fn state_check_ready_is_ok() {
        let compat = make_compat();
        assert!(compat.check_state(SnapshotState::Ready).is_ok());
    }

    #[test]
    fn state_check_staging_fails() {
        let compat = make_compat();
        let result = compat.check_state(SnapshotState::Staging);
        assert!(matches!(
            result,
            Err(SnapshotError::SnapshotNotReady { .. })
        ));
    }

    #[test]
    fn state_check_revoked_fails() {
        let compat = make_compat();
        let result = compat.check_state(SnapshotState::Revoked);
        assert!(matches!(result, Err(SnapshotError::SnapshotRevoked { .. })));
    }

    #[test]
    fn profile_check_for_memory_operation() {
        let compat = make_compat();
        // Filesystem profile does not support memory operations
        assert!(compat.check_profile_for_operation(true).is_err());
        // Filesystem profile supports non-memory operations
        assert!(compat.check_profile_for_operation(false).is_ok());
    }

    #[test]
    fn profile_check_with_memory_profile() {
        let mut compat = make_compat();
        compat.profile = SnapshotProfile::Memory;
        assert!(compat.check_profile_for_operation(true).is_ok());
        assert!(compat.check_profile_for_operation(false).is_ok());
    }

    #[test]
    fn purpose_gate_unified_for_restore_and_fork() {
        use super::super::purpose::RestoreIntent;
        use super::super::purpose::SnapshotPurpose;

        let mut compat = make_compat();
        compat.purpose = SnapshotPurpose::Fork;
        assert!(
            compat
                .check_purpose_for_intent(RestoreIntent::Restore)
                .is_ok()
        );
        assert!(compat.check_purpose_for_intent(RestoreIntent::Fork).is_ok());

        compat.purpose = SnapshotPurpose::Base;
        assert!(
            compat
                .check_purpose_for_intent(RestoreIntent::Restore)
                .is_ok()
        );
        assert!(
            compat
                .check_purpose_for_intent(RestoreIntent::Fork)
                .is_err()
        );

        compat.purpose = SnapshotPurpose::Runtime;
        assert!(
            compat
                .check_purpose_for_intent(RestoreIntent::Restore)
                .is_err()
        );
        assert!(
            compat
                .check_purpose_for_intent(RestoreIntent::Fork)
                .is_err()
        );
    }

    #[test]
    fn policy_epoch_mismatch_is_rejected() {
        let compat = make_compat();
        // Snapshot has policy_epoch=1, but current epoch is 2
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            2, // current epoch differs
        );
        assert!(matches!(
            result,
            Err(SnapshotError::PolicyEpochIncompatible {
                snapshot_epoch: 1,
                current_epoch: 2,
            })
        ));
    }

    #[test]
    fn policy_epoch_match_passes() {
        let compat = make_compat();
        // Snapshot has policy_epoch=1, current epoch is also 1
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            1, // current epoch matches
        );
        assert!(result.is_ok());
    }

    #[test]
    fn legacy_snapshot_without_policy_epoch_passes() {
        let mut compat = make_compat();
        compat.policy_epoch = None;
        let result = compat.check_compatibility(
            &make_host_backend(),
            &make_host_cpu(),
            &make_host_memory(),
            &make_host_device(),
            RuntimeType::Firecracker,
            99, // any epoch is fine when snapshot has no epoch
        );
        assert!(result.is_ok());
    }

    #[test]
    fn compatibility_record_serde_roundtrip() {
        let compat = make_compat();
        let json = serde_json::to_string(&compat).unwrap();
        let back: CompatibilityRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(compat, back);
    }
}
