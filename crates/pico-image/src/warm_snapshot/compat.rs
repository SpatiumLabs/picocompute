//! Warm snapshot compatibility tagging.
//!
//! Produces [`CompatibilityRecord`] entries from image manifests and
//! runtime context so that restore-time compatibility checks can run
//! from metadata alone without loading snapshot blobs.

use pico_core::{
    identity::{OperationId, SandboxId, SnapshotId},
    snapshot::{
        CompatibilityRecord,
        credential_policy::CredentialSnapshotPolicy,
        integrity::SnapshotIntegrity,
        metadata::SnapshotMetadata,
        metadata::{FilesystemRef, MemorySegment, WorkspaceLayerRef},
        profile::SnapshotProfile,
        purpose::{LineageType, SnapshotPurpose},
        shape::BackendRecord,
    },
};

use super::config::WarmSnapshotConfig;
use super::error::{WarmSnapshotError, WarmSnapshotResult};

/// Builds a warm base snapshot metadata record from a configuration and
/// a set of captured artifact references.
///
/// The returned [`SnapshotMetadata`] is in [`SnapshotState::Staging`]
/// and must be promoted to [`SnapshotState::Ready`] after validation.
#[expect(
    clippy::too_many_arguments,
    reason = "warm snapshot metadata construction requires comprehensive inputs for compatibility"
)]
pub fn build_warm_snapshot_metadata(
    config: &WarmSnapshotConfig,
    snapshot_id: SnapshotId,
    sandbox_id: SandboxId,
    operation_id: OperationId,
    filesystem_refs: Vec<FilesystemRef>,
    memory_segments: Vec<MemorySegment>,
    workspace_layers: Vec<WorkspaceLayerRef>,
    integrity: SnapshotIntegrity,
) -> WarmSnapshotResult<SnapshotMetadata> {
    let mut metadata = SnapshotMetadata::new(
        snapshot_id,
        pico_core::identity::TenantId::from_string("pico-image-builder"),
        sandbox_id,
        // Warm base snapshots have no parent; they are roots.
        None,
        LineageType::Root,
        SnapshotPurpose::Base,
        SnapshotProfile::Filesystem,
        operation_id,
        config.image_id().into(),
        config.backend.clone(),
        config.cpu_shape.clone(),
        config.memory_shape,
        config.device_model.clone(),
    );

    metadata.rootfs_digest = Some(config.rootfs_digest().into());
    metadata.kernel_version = config.kernel_version().map(String::from);

    metadata.filesystem_refs = filesystem_refs;
    metadata.memory_segments = memory_segments;
    metadata.workspace_layers = workspace_layers;

    metadata.integrity = Some(integrity);

    metadata.excluded_mounts = config
        .image_manifest
        .snapshot
        .excluded_mount_classes
        .clone();

    metadata.credential_policy = Some(CredentialSnapshotPolicy::production());

    metadata.workload_class = Some("warm-base".into());
    metadata.isolation_floor = Some("vm".into());

    tracing::info!(
        snapshot_id = %metadata.id,
        image_id = %metadata.image_id,
        rootfs_digest = ?metadata.rootfs_digest,
        kernel_version = ?metadata.kernel_version,
        guest_agent_version = ?metadata.backend.guest_agent_version,
        backend = %metadata.backend.backend_type,
        "warm snapshot metadata constructed"
    );

    Ok(metadata)
}

/// Builds a [`CompatibilityRecord`] from snapshot metadata for
/// compatibility validation against a host environment.
pub fn build_compatibility_record(metadata: &SnapshotMetadata) -> CompatibilityRecord {
    metadata.to_compatibility_record()
}

/// Validates that the warm snapshot is compatible with the declared
/// backend, kernel, guest-agent, and image version.
///
/// This runs from metadata alone, without loading blobs.
pub fn validate_warm_snapshot_compatibility(
    metadata: &SnapshotMetadata,
    expected_image_id: &str,
    expected_kernel_version: Option<&str>,
    expected_guest_agent_version: &str,
    expected_backend: &BackendRecord,
) -> WarmSnapshotResult<()> {
    if metadata.image_id != expected_image_id {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "image_id mismatch: metadata has '{}', expected '{}'",
                metadata.image_id, expected_image_id
            ),
        });
    }

    if let Some(ref metadata_kv) = metadata.kernel_version
        && let Some(expected_kv) = expected_kernel_version
        && metadata_kv != expected_kv
    {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "kernel version mismatch: metadata has '{}', expected '{}'",
                metadata_kv, expected_kv
            ),
        });
    }

    let metadata_ga = metadata
        .backend
        .guest_agent_version
        .as_deref()
        .unwrap_or("");
    if metadata_ga != expected_guest_agent_version {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "guest-agent version mismatch: metadata has '{}', expected '{}'",
                metadata_ga, expected_guest_agent_version
            ),
        });
    }

    if !metadata
        .backend
        .is_same_family(&expected_backend.backend_type)
    {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "backend family mismatch: metadata has '{}', expected '{}'",
                metadata.backend.backend_type, expected_backend.backend_type
            ),
        });
    }

    if !metadata
        .backend
        .is_version_compatible(&expected_backend.backend_version)
    {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "backend version mismatch: metadata has '{}', expected '{}'",
                metadata.backend.backend_version, expected_backend.backend_version
            ),
        });
    }

    if metadata.backend.protocol_version != expected_backend.protocol_version {
        return Err(WarmSnapshotError::CompatibilityCheckFailed {
            reason: format!(
                "protocol version mismatch: metadata has '{}', expected '{}'",
                metadata.backend.protocol_version, expected_backend.protocol_version
            ),
        });
    }

    tracing::info!(
        snapshot_id = %metadata.id,
        image_id = %expected_image_id,
        backend = %expected_backend.backend_type,
        guest_agent_version = %expected_guest_agent_version,
        "warm snapshot compatibility validated"
    );

    Ok(())
}

/// Generates an integrity digest over the snapshot metadata and artifact
/// references using blake3.
pub fn compute_snapshot_integrity(
    metadata: &SnapshotMetadata,
    artifact_hashes: &[(&str, &str)],
) -> SnapshotIntegrity {
    use pico_core::snapshot::integrity::{BlobDigest, IntegrityDigest};

    let mut hasher = blake3::Hasher::new();
    hasher.update(metadata.image_id.as_bytes());
    hasher.update(b"\n");
    if let Some(ref d) = metadata.rootfs_digest {
        hasher.update(d.as_bytes());
    }
    hasher.update(b"\n");
    if let Some(ref kv) = metadata.kernel_version {
        hasher.update(kv.as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(metadata.backend.backend_type.as_bytes());
    hasher.update(b"\n");
    hasher.update(metadata.backend.backend_version.as_bytes());

    let metadata_digest_value = hasher.finalize().to_hex().to_string();
    let metadata_digest = IntegrityDigest::new("blake3", metadata_digest_value);

    let blob_digests: Vec<BlobDigest> = artifact_hashes
        .iter()
        .map(|(blob_ref, hash)| BlobDigest {
            blob_ref: blob_ref.to_string(),
            digest: IntegrityDigest::new("blake3", hash.to_string()),
        })
        .collect();

    SnapshotIntegrity {
        metadata_digest,
        blob_digests,
        encryption_key: None,
        integrity_required: true,
    }
}

/// Validates that the snapshot excludes secrets and tenant data.
///
/// This is a defense-in-depth check. It verifies that:
/// 1. The secret mount class is in the excluded list
/// 2. No filesystem refs point to credential paths
/// 3. The excluded mounts list is non-empty
pub fn validate_secret_exclusion(
    excluded_mounts: &[String],
    filesystem_refs: &[FilesystemRef],
) -> WarmSnapshotResult<()> {
    use pico_core::mount::CANONICAL_SECRETS_TMPFS;

    if !excluded_mounts.iter().any(|m| m == "secret") {
        return Err(WarmSnapshotError::CredentialMaterialDetected {
            image_id: "unknown".into(),
            reason: "secret mount class not found in excluded_mounts list".into(),
        });
    }

    for fs_ref in filesystem_refs {
        if fs_ref.mount_point == CANONICAL_SECRETS_TMPFS {
            return Err(WarmSnapshotError::CredentialMaterialDetected {
                image_id: "unknown".into(),
                reason: format!(
                    "credential mount point '{}' found in filesystem references",
                    fs_ref.mount_point
                ),
            });
        }
    }

    tracing::info!(
        excluded_mount_count = %excluded_mounts.len(),
        fs_ref_count = %filesystem_refs.len(),
        "secret exclusion validation passed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArtifactDescriptor, Artifacts, CompatibilityInfo, PicoComputeGuestManifest, PlatformInfo,
        ProtocolInfo, ProtocolVersionRange, ReleaseInfo,
    };
    use pico_core::{
        identity::{OperationId, SandboxId, SnapshotId},
        mount::{MountClass, MountContract, MountEntry, PathLifecycle, SnapshotInfo},
        snapshot::integrity::IntegrityDigest,
        snapshot::state::SnapshotState,
    };

    fn make_test_config() -> WarmSnapshotConfig {
        let manifest = PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test-image-001".into(),
            release: ReleaseInfo {
                version: "1.0.0".into(),
                source_revision: "abc123".into(),
                build_epoch: 1700000000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "x86_64".into(),
            },
            artifacts: Artifacts {
                rootfs: ArtifactDescriptor {
                    format: Some("ext4".into()),
                    media_type: "application/vnd.pico.rootfs.ext4".into(),
                    digest: "sha256:rootfs123".into(),
                    size: 1024000,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: Some(ArtifactDescriptor {
                    format: Some("linux-vmlinux".into()),
                    media_type: "application/vnd.pico.kernel.vmlinux".into(),
                    digest: "sha256:kernel123".into(),
                    size: 8192000,
                    version: Some("6.1.0".into()),
                    cmdline: Some("console=ttyS0".into()),
                    protocol_version: None,
                    capabilities: vec![],
                }),
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "application/vnd.pico.guest-agent".into(),
                    digest: "sha256:agent123".into(),
                    size: 4096000,
                    version: Some("0.5.0".into()),
                    cmdline: None,
                    protocol_version: Some("1.0".into()),
                    capabilities: vec!["exec".into(), "snapshot".into()],
                },
            },
            protocol: ProtocolInfo {
                bootstrap: "pico.guest.bootstrap.v1".into(),
                supported: vec![ProtocolVersionRange {
                    major: 1,
                    min_minor: 0,
                    max_minor: 0,
                }],
                capabilities: vec!["exec".into()],
            },
            compatibility: CompatibilityInfo {
                profile_id: "firecracker-x86_64-v1".into(),
                backends: vec![crate::types::BackendCompatibility {
                    family: "firecracker".into(),
                    runtime_version: "1.10.0".into(),
                    architecture: "x86_64".into(),
                }],
                required_cpu_features: vec![],
                required_devices: vec![],
                required_host_features: vec![],
                kernel_cmdline: Some("console=ttyS0".into()),
            },
            mount_contract: MountContract {
                version: "1.0".into(),
                mounts: vec![
                    MountEntry {
                        path: "/workspace".into(),
                        class: MountClass::Workspace,
                        writable: true,
                        lifecycle: PathLifecycle::Persistent,
                    },
                    MountEntry {
                        path: "/run/pico/secrets".into(),
                        class: MountClass::Secret,
                        writable: false,
                        lifecycle: PathLifecycle::Ephemeral,
                    },
                ],
            },
            snapshot: SnapshotInfo {
                filesystem: true,
                memory: false,
                excluded_mount_classes: vec!["secret".into(), "runtime_tmp".into()],
            },
        };
        WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest)
    }

    fn make_integrity() -> SnapshotIntegrity {
        SnapshotIntegrity::new(IntegrityDigest::new(
            "blake3",
            "abc123def456789abc123def456789",
        ))
    }

    #[test]
    fn build_snapshot_metadata_creates_base_snapshot() {
        let config = make_test_config();
        let snapshot_id = SnapshotId::generate();
        let sandbox_id = SandboxId::generate();
        let op_id = OperationId::generate();
        let integrity = make_integrity();

        let metadata = build_warm_snapshot_metadata(
            &config,
            snapshot_id.clone(),
            sandbox_id.clone(),
            op_id,
            vec![],
            vec![],
            vec![],
            integrity,
        )
        .unwrap();

        assert_eq!(metadata.id, snapshot_id);
        assert_eq!(metadata.sandbox_id, sandbox_id);
        assert_eq!(metadata.purpose, SnapshotPurpose::Base);
        assert_eq!(metadata.profile, SnapshotProfile::Filesystem);
        assert_eq!(metadata.state, SnapshotState::Staging);
        assert!(metadata.is_base());
        assert_eq!(metadata.image_id, "test-image-001");
        assert_eq!(metadata.rootfs_digest, Some("sha256:rootfs123".into()));
        assert_eq!(metadata.kernel_version, Some("6.1.0".into()));
        assert_eq!(metadata.backend.guest_agent_version, Some("0.5.0".into()));
        assert!(!metadata.excluded_mounts.is_empty());
        assert!(metadata.excluded_mounts.iter().any(|m| m == "secret"));
    }

    #[test]
    fn compatibility_validation_passes_with_matching_versions() {
        let config = make_test_config();
        let snapshot_id = SnapshotId::generate();
        let sandbox_id = SandboxId::generate();
        let op_id = OperationId::generate();
        let integrity = make_integrity();

        let metadata = build_warm_snapshot_metadata(
            &config,
            snapshot_id,
            sandbox_id,
            op_id,
            vec![],
            vec![],
            vec![],
            integrity,
        )
        .unwrap();

        let result = validate_warm_snapshot_compatibility(
            &metadata,
            "test-image-001",
            Some("6.1.0"),
            "0.5.0",
            &config.backend,
        );
        assert!(result.is_ok(), "expected compatible: {:?}", result.err());
    }

    #[test]
    fn compatibility_validation_fails_with_mismatched_image_id() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let result = validate_warm_snapshot_compatibility(
            &metadata,
            "different-image",
            Some("6.1.0"),
            "0.5.0",
            &config.backend,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("image_id mismatch")
        );
    }

    #[test]
    fn compatibility_validation_fails_with_mismatched_kernel() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let result = validate_warm_snapshot_compatibility(
            &metadata,
            "test-image-001",
            Some("5.10.0"),
            "0.5.0",
            &config.backend,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("kernel version mismatch")
        );
    }

    #[test]
    fn compatibility_validation_fails_with_mismatched_guest_agent() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let result = validate_warm_snapshot_compatibility(
            &metadata,
            "test-image-001",
            Some("6.1.0"),
            "0.4.0",
            &config.backend,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("guest-agent version mismatch")
        );
    }

    #[test]
    fn compatibility_validation_fails_with_mismatched_backend() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let mut different_backend = config.backend.clone();
        different_backend.backend_type = "qemu".into();

        let result = validate_warm_snapshot_compatibility(
            &metadata,
            "test-image-001",
            Some("6.1.0"),
            "0.5.0",
            &different_backend,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("backend family mismatch")
        );
    }

    #[test]
    fn compute_snapshot_integrity_produces_consistent_hash() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let artifacts = &[("rootfs.ext4", "abc"), ("mem.bin", "def")];
        let integrity1 = compute_snapshot_integrity(&metadata, artifacts);
        let integrity2 = compute_snapshot_integrity(&metadata, artifacts);

        assert_eq!(integrity1.metadata_digest, integrity2.metadata_digest);
        assert_eq!(integrity1.blob_digests.len(), 2);
        assert_eq!(integrity2.blob_digests.len(), 2);
        assert!(integrity1.integrity_required);
    }

    #[test]
    fn secret_exclusion_passes_with_secret_excluded() {
        let excluded = vec!["secret".into(), "runtime_tmp".into()];
        let fs_refs: Vec<FilesystemRef> = vec![];
        assert!(validate_secret_exclusion(&excluded, &fs_refs).is_ok());
    }

    #[test]
    fn secret_exclusion_fails_without_secret_class() {
        let excluded = vec!["runtime_tmp".into()];
        let fs_refs: Vec<FilesystemRef> = vec![];
        let result = validate_secret_exclusion(&excluded, &fs_refs);
        assert!(result.is_err());
    }

    #[test]
    fn secret_exclusion_fails_with_credential_mount_in_fs_refs() {
        let excluded = vec!["secret".into()];
        let fs_refs = vec![FilesystemRef {
            blob_ref: "secrets.blob".into(),
            mount_point: pico_core::mount::CANONICAL_SECRETS_TMPFS.into(),
            fs_type: "tmpfs".into(),
            digest: None,
            is_root: false,
        }];
        let result = validate_secret_exclusion(&excluded, &fs_refs);
        assert!(result.is_err());
    }

    #[test]
    fn build_compatibility_record_from_metadata() {
        let config = make_test_config();
        let metadata = build_warm_snapshot_metadata(
            &config,
            SnapshotId::generate(),
            SandboxId::generate(),
            OperationId::generate(),
            vec![],
            vec![],
            vec![],
            make_integrity(),
        )
        .unwrap();

        let record = build_compatibility_record(&metadata);
        assert_eq!(record.snapshot_id, metadata.id);
        assert_eq!(record.image_id, metadata.image_id);
        assert_eq!(record.purpose, SnapshotPurpose::Base);
        assert_eq!(record.profile, SnapshotProfile::Filesystem);
    }
}
