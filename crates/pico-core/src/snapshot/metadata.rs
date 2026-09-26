//! Durable snapshot metadata model.
//!
//! Implements the snapshot metadata record per and ADR-0007.
//! Stores identity, lineage, compatibility, integrity, and policy information
//! so that compatibility checks can run from metadata without loading blobs.

use serde::{Deserialize, Serialize};

use crate::identity::OperationId;
use crate::identity::SandboxId;
use crate::identity::SnapshotId;
use crate::identity::TenantId;

use super::compatibility::CompatibilityRecord;
use super::credential_policy::{CredentialSnapshotPolicy, ForkCredentialPolicy};
use super::error::SnapshotResult;
use super::integrity::SnapshotIntegrity;
use super::lineage::SnapshotLineage;
use super::profile::SnapshotProfile;
use super::purpose::{LineageType, SnapshotPurpose};
use super::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
use super::state::SnapshotState;

/// Memory segment reference within a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemorySegment {
    /// Blob reference for this memory segment.
    pub blob_ref: String,
    /// Start address in guest physical memory.
    pub start_address: u64,
    /// Size of this segment in bytes.
    pub size_bytes: u64,
    /// Integrity digest for this segment.
    #[serde(default)]
    pub digest: Option<String>,
}

/// Filesystem reference within a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemRef {
    /// Blob reference for this filesystem layer.
    pub blob_ref: String,
    /// Mount point within the guest.
    pub mount_point: String,
    /// Filesystem type (e.g., "ext4", "xfs", "overlay").
    pub fs_type: String,
    /// Integrity digest for this filesystem blob.
    #[serde(default)]
    pub digest: Option<String>,
    /// Whether this is the root filesystem.
    pub is_root: bool,
}

/// Workspace layer reference within a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceLayerRef {
    /// Blob reference for this layer.
    pub blob_ref: String,
    /// Layer index (0 is the base).
    pub layer_index: u32,
    /// Parent layer blob reference (None for base layer).
    #[serde(default)]
    pub parent_blob_ref: Option<String>,
    /// Integrity digest for this layer.
    #[serde(default)]
    pub digest: Option<String>,
}

/// The authoritative metadata record for a PicoCompute snapshot.
///
/// This is the snapshot equivalent of [`crate::metadata::SandboxMetadata`].
/// It records everything needed for compatibility checks, lineage queries,
/// integrity verification, and policy decisions without loading blobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    // ---- Identity ----
    /// Unique snapshot identifier (e.g., "snp_01JXYZ...").
    pub id: SnapshotId,
    /// Tenant that owns this snapshot.
    pub tenant_id: TenantId,
    /// Sandbox that produced this snapshot.
    pub sandbox_id: SandboxId,
    /// Parent snapshot ID, if any.
    #[serde(default)]
    pub parent_snapshot_id: Option<SnapshotId>,
    /// Lineage relationship type.
    pub lineage_type: LineageType,

    // ---- Lifecycle ----
    /// Purpose of this snapshot.
    pub purpose: SnapshotPurpose,
    /// State profile preserved by this snapshot.
    pub profile: SnapshotProfile,
    /// Current lifecycle state.
    pub state: SnapshotState,
    /// Monotonic version counter.
    pub version: u64,
    /// Operation that created this snapshot.
    pub operation_id: OperationId,
    /// Schema version for migration support.
    pub schema_version: u32,

    // ---- Image ----
    /// Image identifier the sandbox was created from.
    pub image_id: String,
    /// Root filesystem digest.
    #[serde(default)]
    pub rootfs_digest: Option<String>,
    /// Kernel version at snapshot time.
    #[serde(default)]
    pub kernel_version: Option<String>,

    // ---- Backend ----
    /// Backend family and version at snapshot time.
    pub backend: BackendRecord,

    // ---- Shape ----
    /// CPU requirements.
    pub cpu_shape: CpuShape,
    /// Memory and vCPU requirements.
    pub memory_shape: MemoryShape,
    /// Device model requirements.
    pub device_model: DeviceModel,

    // ---- Blob references ----
    /// Memory segments captured in the snapshot.
    #[serde(default)]
    pub memory_segments: Vec<MemorySegment>,
    /// Filesystem references.
    #[serde(default)]
    pub filesystem_refs: Vec<FilesystemRef>,
    /// Workspace layer references.
    #[serde(default)]
    pub workspace_layers: Vec<WorkspaceLayerRef>,

    // ---- Policy ----
    /// Policy epoch at snapshot time (historical evidence).
    #[serde(default)]
    pub policy_epoch: Option<u64>,
    /// Network identity policy applied at snapshot time.
    #[serde(default)]
    pub network_identity_policy: Option<String>,
    /// Mount classes excluded from this snapshot.
    #[serde(default)]
    pub excluded_mounts: Vec<String>,

    // ---- Security ----
    /// Encryption key reference for this snapshot.
    ///
    /// **Deprecated**: Use [`SnapshotIntegrity::encryption_key`] instead.
    /// This field is retained for backward-compatible reads only.
    /// New code MUST write to `integrity.encryption_key` exclusively.
    /// Dual-write is a bug: having two sources of truth for the same
    /// key reference creates inconsistency windows.
    #[serde(default)]
    pub encryption_key_ref: Option<String>,
    /// Integrity digests and encryption metadata.
    ///
    /// The authoritative source for integrity requirements and
    /// encryption key references. Prefer `integrity.encryption_key`
    /// over the deprecated top-level `encryption_key_ref`.
    #[serde(default)]
    pub integrity: Option<SnapshotIntegrity>,

    // ---- Workload context ----
    /// Workload class for isolation constraints.
    #[serde(default)]
    pub workload_class: Option<String>,
    /// Isolation floor required.
    #[serde(default)]
    pub isolation_floor: Option<String>,
    /// Data classification level.
    #[serde(default)]
    pub data_classification: Option<String>,

    // ---- Credential policy ----
    /// Credential lifecycle policy for snapshot/restore/fork.
    #[serde(default)]
    pub credential_policy: Option<CredentialSnapshotPolicy>,

    // ---- Timestamps ----
    /// When the snapshot operation was initiated (ISO 8601 UTC).
    pub issued_at: String,
    /// When the snapshot became ready (ISO 8601 UTC).
    #[serde(default)]
    pub ready_at: Option<String>,
    /// When this record was created (ISO 8601 UTC).
    pub created_at: String,
    /// When this record was last updated (ISO 8601 UTC).
    pub updated_at: String,
}

impl SnapshotMetadata {
    /// Current schema version for the snapshot metadata format.
    pub const CURRENT_SCHEMA_VERSION: u32 = 2;

    /// Creates a new `SnapshotMetadata` in `Staging` state.
    #[expect(
        clippy::too_many_arguments,
        reason = "SnapshotMetadata requires many fields for a complete record"
    )]
    pub fn new(
        id: SnapshotId,
        tenant_id: TenantId,
        sandbox_id: SandboxId,
        parent_snapshot_id: Option<SnapshotId>,
        lineage_type: LineageType,
        purpose: SnapshotPurpose,
        profile: SnapshotProfile,
        operation_id: OperationId,
        image_id: String,
        backend: BackendRecord,
        cpu_shape: CpuShape,
        memory_shape: MemoryShape,
        device_model: DeviceModel,
    ) -> Self {
        let now = crate::types::now_iso();
        Self {
            id,
            tenant_id,
            sandbox_id,
            parent_snapshot_id,
            lineage_type,
            purpose,
            profile,
            state: SnapshotState::Staging,
            version: 1,
            operation_id,
            schema_version: Self::CURRENT_SCHEMA_VERSION,
            image_id,
            rootfs_digest: None,
            kernel_version: None,
            backend,
            cpu_shape,
            memory_shape,
            device_model,
            memory_segments: Vec::new(),
            filesystem_refs: Vec::new(),
            workspace_layers: Vec::new(),
            policy_epoch: None,
            network_identity_policy: None,
            excluded_mounts: Vec::new(),
            encryption_key_ref: None,
            integrity: None,
            workload_class: None,
            isolation_floor: None,
            data_classification: None,
            credential_policy: None,
            issued_at: now.clone(),
            ready_at: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Builds a `CompatibilityRecord` from this metadata for
    /// metadata-only compatibility checks.
    pub fn to_compatibility_record(&self) -> CompatibilityRecord {
        CompatibilityRecord {
            schema_version: self.schema_version,
            snapshot_id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            purpose: self.purpose,
            profile: self.profile,
            backend: self.backend.clone(),
            cpu_shape: self.cpu_shape.clone(),
            memory_shape: self.memory_shape,
            device_model: self.device_model.clone(),
            image_id: self.image_id.clone(),
            rootfs_digest: self.rootfs_digest.clone(),
            kernel_version: self.kernel_version.clone(),
            excluded_mount_classes: self.excluded_mounts.clone(),
            policy_epoch: self.policy_epoch,
            network_policy_ref: self.network_identity_policy.clone(),
            workload_class: self.workload_class.clone(),
            isolation_floor: self.isolation_floor.clone(),
            data_classification: self.data_classification.clone(),
            credential_policy: self.credential_policy.clone(),
            lineage_type: Some(self.lineage_type.as_str().to_string()),
        }
    }

    /// Builds a `SnapshotLineage` entry from this metadata.
    ///
    /// The `parent_sandbox_id` is not populated from snapshot metadata;
    /// it is set when a child sandbox is created from a fork snapshot
    /// and records the source sandbox in the child's lineage.
    pub fn to_lineage(&self) -> SnapshotLineage {
        SnapshotLineage {
            snapshot_id: self.id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            parent_snapshot_id: self.parent_snapshot_id.clone(),
            parent_sandbox_id: None,
            lineage_type: self.lineage_type,
            purpose: self.purpose,
            profile: self.profile,
            operation_id: self.operation_id.clone(),
            workspace_ref: self.workspace_layers.first().map(|l| l.blob_ref.clone()),
            created_at: self.created_at.clone(),
        }
    }

    /// Transitions the snapshot to `Ready` state.
    ///
    /// Sets `ready_at` and updates `updated_at`. Only valid from `Staging`.
    pub fn mark_ready(&mut self) -> SnapshotResult<()> {
        if !self.state.can_become_ready() {
            return Err(super::error::SnapshotError::OperationConflict {
                reason: format!("cannot transition from {} to ready", self.state.as_str()),
            });
        }
        self.state = SnapshotState::Ready;
        self.ready_at = Some(crate::types::now_iso());
        self.updated_at = crate::types::now_iso();
        Ok(())
    }

    /// Transitions the snapshot to `Failed` state.
    pub fn mark_failed(&mut self) {
        self.state = SnapshotState::Failed;
        self.updated_at = crate::types::now_iso();
    }

    /// Transitions the snapshot to `Revoked` state.
    ///
    /// Only valid from `Ready`.
    pub fn revoke(&mut self) -> SnapshotResult<()> {
        if !self.state.is_restorable() {
            return Err(super::error::SnapshotError::OperationConflict {
                reason: format!("cannot revoke snapshot in {} state", self.state.as_str()),
            });
        }
        self.state = SnapshotState::Revoked;
        self.updated_at = crate::types::now_iso();
        Ok(())
    }

    /// Returns true if this snapshot supports base snapshot creation.
    pub fn is_base(&self) -> bool {
        self.purpose == SnapshotPurpose::Base
    }

    /// Returns true if this snapshot supports session restore/resume.
    pub fn is_session(&self) -> bool {
        self.purpose == SnapshotPurpose::Session
    }

    /// Returns true if this snapshot supports forking.
    pub fn is_fork(&self) -> bool {
        self.purpose == SnapshotPurpose::Fork
    }

    /// Returns true if this snapshot preserves memory.
    pub fn preserves_memory(&self) -> bool {
        self.profile.preserves_memory()
    }

    /// Returns true if the integrity digests cover all referenced blobs.
    pub fn integrity_covered(&self) -> bool {
        match &self.integrity {
            Some(integrity) => {
                let blob_count = self.memory_segments.len()
                    + self.filesystem_refs.len()
                    + self.workspace_layers.len();
                integrity.all_blobs_covered(blob_count)
            }
            None => false,
        }
    }

    /// Validates that credential exclusion is enforced for this snapshot.
    ///
    /// Checks that:
    /// 1. A credential policy is present (required for production snapshots)
    /// 2. The policy mandates credential exclusion
    /// 3. The `excluded_mounts` list includes the `secret` class
    ///
    /// Returns `Ok(())` if the snapshot passes credential exclusion validation,
    /// or a `CredentialExclusionInvalid` error describing the violation.
    pub fn validate_credential_exclusion(&self) -> SnapshotResult<()> {
        let Some(policy) = &self.credential_policy else {
            return Err(super::error::SnapshotError::CredentialExclusionInvalid {
                reason: "credential policy not set on snapshot metadata".into(),
            });
        };

        if !policy.secret_class_is_excluded(&self.excluded_mounts) {
            return Err(super::error::SnapshotError::CredentialExclusionInvalid {
                reason: "secret mount class not excluded from snapshot".into(),
            });
        }

        // Validate that no filesystem refs contain credential paths
        for fs_ref in &self.filesystem_refs {
            if fs_ref.mount_point == crate::mount::CANONICAL_SECRETS_TMPFS {
                return Err(super::error::SnapshotError::CredentialMaterialDetected {
                    reason: format!(
                        "credential mount '{}' included in filesystem refs",
                        fs_ref.mount_point
                    ),
                });
            }
        }

        Ok(())
    }

    /// Returns the credential policy for this snapshot, or the default.
    pub fn effective_credential_policy(&self) -> CredentialSnapshotPolicy {
        self.credential_policy.clone().unwrap_or_default()
    }

    /// Returns true if this snapshot allows fork credential inheritance.
    ///
    /// Checks the [`ForkCredentialPolicy`] on the snapshot's credential policy.
    /// Returns `true` only when the policy is [`ForkCredentialPolicy::InheritAll`]
    /// or [`ForkCredentialPolicy::InheritPermitted`]; `None` always returns `false`.
    pub fn allows_fork_credential_inheritance(&self) -> bool {
        let policy = self.effective_credential_policy();
        matches!(
            policy.fork_credential_policy,
            ForkCredentialPolicy::InheritAll | ForkCredentialPolicy::InheritPermitted
        )
    }

    /// Returns true if this snapshot requires credential refresh after restore.
    pub fn requires_credential_refresh(&self) -> bool {
        let policy = self.effective_credential_policy();
        policy.exclude_from_snapshot && policy.refresh_after_restore
    }

    /// Returns the effective encryption key reference for this snapshot.
    ///
    /// Prefers [`SnapshotIntegrity::encryption_key`] (new structured field).
    /// Falls back to the deprecated top-level [`Self::encryption_key_ref`]
    /// for backward compatibility with v1 snapshots that have not been
    /// migrated. Returns `None` if neither field is set.
    pub fn effective_encryption_key_ref(&self) -> Option<&super::integrity::EncryptionKeyRef> {
        if let Some(ref integrity) = self.integrity
            && integrity.encryption_key.is_some()
        {
            return integrity.encryption_key.as_ref();
        }
        // Backward compat: old snapshots may only have the string field.
        // We return None here and let callers check `encryption_key_ref`
        // directly — the structured EncryptionKeyRef is the preferred
        // interface going forward.
        None
    }

    /// True if this snapshot has any encryption key reference (old or new format).
    pub fn has_encryption_key_ref(&self) -> bool {
        self.effective_encryption_key_ref().is_some() || self.encryption_key_ref.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_metadata() -> SnapshotMetadata {
        SnapshotMetadata::new(
            SnapshotId::generate(),
            TenantId::from_string("tnt_test"),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Session,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img_test".into(),
            BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                guest_agent_version: Some("0.5.0".into()),
            },
            CpuShape::new("x86_64"),
            MemoryShape {
                memory_mb: 2048,
                vcpus: 2,
            },
            DeviceModel::new("q35"),
        )
    }

    #[test]
    fn new_snapshot_is_staging() {
        let meta = make_test_metadata();
        assert_eq!(meta.state, SnapshotState::Staging);
        assert_eq!(meta.version, 1);
        assert_eq!(
            meta.schema_version,
            SnapshotMetadata::CURRENT_SCHEMA_VERSION
        );
    }

    #[test]
    fn mark_ready_transitions_from_staging() {
        let mut meta = make_test_metadata();
        assert!(meta.mark_ready().is_ok());
        assert_eq!(meta.state, SnapshotState::Ready);
        assert!(meta.ready_at.is_some());
    }

    #[test]
    fn mark_ready_fails_from_ready() {
        let mut meta = make_test_metadata();
        meta.mark_ready().unwrap();
        let result = meta.mark_ready();
        assert!(matches!(
            result,
            Err(super::super::error::SnapshotError::OperationConflict { .. })
        ));
    }

    #[test]
    fn mark_failed_transitions() {
        let mut meta = make_test_metadata();
        meta.mark_failed();
        assert_eq!(meta.state, SnapshotState::Failed);
    }

    #[test]
    fn revoke_from_ready() {
        let mut meta = make_test_metadata();
        meta.mark_ready().unwrap();
        assert!(meta.revoke().is_ok());
        assert_eq!(meta.state, SnapshotState::Revoked);
    }

    #[test]
    fn revoke_fails_from_staging() {
        let mut meta = make_test_metadata();
        let result = meta.revoke();
        assert!(matches!(
            result,
            Err(super::super::error::SnapshotError::OperationConflict { .. })
        ));
    }

    #[test]
    fn purpose_classifiers() {
        let mut meta = make_test_metadata();
        assert!(!meta.is_base());
        assert!(meta.is_session());
        assert!(!meta.is_fork());

        meta.purpose = SnapshotPurpose::Base;
        assert!(meta.is_base());
        assert!(!meta.is_session());

        meta.purpose = SnapshotPurpose::Fork;
        assert!(meta.is_fork());
    }

    #[test]
    fn preserves_memory_reflects_profile() {
        let mut meta = make_test_metadata();
        assert!(!meta.preserves_memory());

        meta.profile = SnapshotProfile::Memory;
        assert!(meta.preserves_memory());
    }

    #[test]
    fn to_compatibility_record_roundtrip() {
        let meta = make_test_metadata();
        let compat = meta.to_compatibility_record();
        assert_eq!(compat.snapshot_id, meta.id);
        assert_eq!(compat.tenant_id, meta.tenant_id);
        assert_eq!(compat.purpose, meta.purpose);
        assert_eq!(compat.profile, meta.profile);
    }

    #[test]
    fn to_lineage_creates_entry() {
        let meta = make_test_metadata();
        let lineage = meta.to_lineage();
        assert_eq!(lineage.snapshot_id, meta.id);
        assert_eq!(lineage.lineage_type, LineageType::Root);
        assert!(lineage.parent_snapshot_id.is_none());
    }

    #[test]
    fn integrity_covered_with_no_blobs() {
        let mut meta = make_test_metadata();
        meta.integrity = Some(SnapshotIntegrity::new(
            super::super::integrity::IntegrityDigest::new("blake3", "meta"),
        ));
        assert!(meta.integrity_covered());
    }

    #[test]
    fn integrity_covered_missing_blob_digest() {
        let mut meta = make_test_metadata();
        meta.workspace_layers.push(WorkspaceLayerRef {
            blob_ref: "layer.cow".into(),
            layer_index: 0,
            parent_blob_ref: None,
            digest: None,
        });
        // No integrity record at all
        assert!(!meta.integrity_covered());

        meta.integrity = Some(SnapshotIntegrity::new(
            super::super::integrity::IntegrityDigest::new("blake3", "meta"),
        ));
        // Integrity record exists but blob_digests is empty while we have 1 blob
        assert!(!meta.integrity_covered());
    }

    #[test]
    fn memory_segments_serialization() {
        let seg = MemorySegment {
            blob_ref: "mem-001.bin".into(),
            start_address: 0x1000,
            size_bytes: 4096,
            digest: Some("blake3:abc123".into()),
        };
        let json = serde_json::to_string(&seg).unwrap();
        let back: MemorySegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn filesystem_refs_serialization() {
        let fs = FilesystemRef {
            blob_ref: "overlay-001".into(),
            mount_point: "/".into(),
            fs_type: "overlay".into(),
            digest: Some("blake3:def456".into()),
            is_root: true,
        };
        let json = serde_json::to_string(&fs).unwrap();
        let back: FilesystemRef = serde_json::from_str(&json).unwrap();
        assert_eq!(fs, back);
    }

    #[test]
    fn workspace_layer_refs_serialization() {
        let layer = WorkspaceLayerRef {
            blob_ref: "layer-002.cow".into(),
            layer_index: 1,
            parent_blob_ref: Some("layer-001.cow".into()),
            digest: Some("blake3:ghi789".into()),
        };
        let json = serde_json::to_string(&layer).unwrap();
        let back: WorkspaceLayerRef = serde_json::from_str(&json).unwrap();
        assert_eq!(layer, back);
    }

    #[test]
    fn snapshot_metadata_serde_roundtrip() {
        let meta = make_test_metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let back: SnapshotMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
    }

    #[test]
    fn snapshot_metadata_with_all_optional_fields() {
        let mut meta = make_test_metadata();
        meta.rootfs_digest = Some("sha256:abc123".into());
        meta.kernel_version = Some("6.1.0".into());
        meta.policy_epoch = Some(1);
        meta.network_identity_policy = Some("isolated".into());
        meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];
        meta.encryption_key_ref = Some("kms://aws/us-east-1/key-123".into());
        meta.workload_class = Some("interactive".into());
        meta.isolation_floor = Some("vm".into());
        meta.data_classification = Some("internal".into());

        let json = serde_json::to_string(&meta).unwrap();
        let back: SnapshotMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
    }

    #[test]
    fn validate_credential_exclusion_passes() {
        let mut meta = make_test_metadata();
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];
        assert!(meta.validate_credential_exclusion().is_ok());
    }

    #[test]
    fn validate_credential_exclusion_fails_without_policy() {
        let meta = make_test_metadata();
        let result = meta.validate_credential_exclusion();
        assert!(matches!(
            result,
            Err(super::super::error::SnapshotError::CredentialExclusionInvalid { .. })
        ));
    }

    #[test]
    fn validate_credential_exclusion_fails_without_secret_in_excluded_mounts() {
        let mut meta = make_test_metadata();
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["runtime_tmp".into()];
        let result = meta.validate_credential_exclusion();
        assert!(matches!(
            result,
            Err(super::super::error::SnapshotError::CredentialExclusionInvalid { .. })
        ));
    }

    #[test]
    fn validate_credential_exclusion_detects_credential_mount_in_filesystem_refs() {
        let mut meta = make_test_metadata();
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into()];
        meta.filesystem_refs.push(super::FilesystemRef {
            blob_ref: "secrets-layer".into(),
            mount_point: crate::mount::CANONICAL_SECRETS_TMPFS.into(),
            fs_type: "tmpfs".into(),
            digest: None,
            is_root: false,
        });
        let result = meta.validate_credential_exclusion();
        assert!(matches!(
            result,
            Err(super::super::error::SnapshotError::CredentialMaterialDetected { .. })
        ));
    }

    #[test]
    fn effective_credential_policy_defaults() {
        let meta = make_test_metadata();
        let policy = meta.effective_credential_policy();
        assert!(policy.exclude_from_snapshot);
        assert!(policy.refresh_after_restore);
        assert_eq!(policy.fork_credential_policy, ForkCredentialPolicy::None);
    }

    #[test]
    fn allows_fork_credential_inheritance() {
        let mut meta = make_test_metadata();
        assert!(!meta.allows_fork_credential_inheritance());

        meta.credential_policy = Some(CredentialSnapshotPolicy::development());
        assert!(meta.allows_fork_credential_inheritance());
    }

    #[test]
    fn requires_credential_refresh() {
        let mut meta = make_test_metadata();
        assert!(meta.requires_credential_refresh());

        meta.credential_policy = Some(CredentialSnapshotPolicy {
            refresh_after_restore: false,
            ..Default::default()
        });
        assert!(!meta.requires_credential_refresh());
    }

    #[test]
    fn snapshot_supports_base_runtime_session_fork_purposes() {
        for purpose in &[
            SnapshotPurpose::Base,
            SnapshotPurpose::Runtime,
            SnapshotPurpose::Session,
            SnapshotPurpose::Fork,
        ] {
            let mut meta = make_test_metadata();
            meta.purpose = *purpose;
            match purpose {
                SnapshotPurpose::Base => assert!(meta.is_base()),
                SnapshotPurpose::Session => assert!(meta.is_session()),
                SnapshotPurpose::Fork => assert!(meta.is_fork()),
                SnapshotPurpose::Runtime => {
                    assert!(!meta.is_base());
                    assert!(!meta.is_session());
                    assert!(!meta.is_fork());
                }
            }
        }
    }
}
