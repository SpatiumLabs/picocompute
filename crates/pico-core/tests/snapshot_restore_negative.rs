//! Negative restore tests.
//!
//! Pins the four typed rejection paths required by the issue:
//! tampered blob, stale metadata digest, wrong tenant, stale policy epoch.
//! Each test drives `RestoreOrchestrator` end-to-end (validate or prepare)
//! with real temp files so the failure is observed at the restore boundary,
//! not just at a unit helper.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use pico_core::identity::{OperationId, SandboxId, SnapshotId, TenantId};
use pico_core::runtime::RuntimeType;
use pico_core::snapshot::blob::{BlobInfo, BlobLocator};
use pico_core::snapshot::encryption::compute_metadata_digest;
use pico_core::snapshot::error::{SnapshotError, SnapshotResult};
use pico_core::snapshot::integrity::{IntegrityDigest, SnapshotIntegrity};
use pico_core::snapshot::metadata::{FilesystemRef, SnapshotMetadata};
use pico_core::snapshot::profile::SnapshotProfile;
use pico_core::snapshot::purpose::{LineageType, SnapshotPurpose};
use pico_core::snapshot::restore::{RestoreContext, RestoreOrchestrator};
use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

mod common;
use common::InMemorySnapshotRepo as SharedRepo;

// Minimal blob locator backed by temp files on disk.
struct TempFileBlobLocator {
    dir: tempfile::TempDir,
}

impl TempFileBlobLocator {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn write_blob(&self, blob_ref: &str, data: &[u8]) -> std::path::PathBuf {
        let path = self.dir.path().join(blob_ref.replace('/', "_"));
        std::fs::write(&path, data).expect("write blob");
        path
    }
}

#[async_trait]
impl BlobLocator for TempFileBlobLocator {
    async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo> {
        let path = self.dir.path().join(blob_ref.replace('/', "_"));
        if !path.exists() {
            return Err(SnapshotError::BlobMissing {
                blob_ref: blob_ref.to_string(),
            });
        }
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Ok(BlobInfo {
            blob_ref: blob_ref.to_string(),
            path,
            size_bytes: len,
            digest: None,
        })
    }
}

// In-memory locator for metadata-only validate tests (no blob I/O).
struct EmptyLocator;

#[async_trait]
impl BlobLocator for EmptyLocator {
    async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo> {
        Err(SnapshotError::BlobMissing {
            blob_ref: blob_ref.to_string(),
        })
    }
}

struct MapRepo {
    inner: Mutex<Vec<SnapshotMetadata>>,
}

impl MapRepo {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    fn store(&self, meta: &SnapshotMetadata) {
        self.inner.lock().push(meta.clone());
    }
}

#[async_trait]
impl pico_core::snapshot::SnapshotRepository for MapRepo {
    async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
        self.inner
            .lock()
            .iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| SnapshotError::SnapshotNotFound { id: id.to_string() })
    }

    async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
        self.store(metadata);
        Ok(())
    }

    async fn update_snapshot(
        &self,
        metadata: &SnapshotMetadata,
        _expected_version: u64,
    ) -> SnapshotResult<()> {
        let mut guard = self.inner.lock();
        if let Some(existing) = guard.iter_mut().find(|m| m.id == metadata.id) {
            *existing = metadata.clone();
            Ok(())
        } else {
            Err(SnapshotError::SnapshotNotFound {
                id: metadata.id.to_string(),
            })
        }
    }

    async fn list_snapshots(
        &self,
        _tenant_id: &TenantId,
        _purpose: Option<SnapshotPurpose>,
        _state: Option<pico_core::snapshot::SnapshotState>,
        _limit: usize,
        _cursor: Option<String>,
    ) -> SnapshotResult<pico_core::snapshot::SnapshotListPage> {
        Ok(pico_core::snapshot::SnapshotListPage {
            snapshots: self.inner.lock().clone(),
            next_cursor: None,
        })
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
        self.inner.lock().retain(|m| m.id != *id);
        Ok(())
    }
}

fn base_metadata(snapshot_id: SnapshotId, tenant: &str, policy_epoch: u64) -> SnapshotMetadata {
    let mut meta = SnapshotMetadata::new(
        snapshot_id,
        TenantId::from_string(tenant),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Base,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_base".into(),
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
    );
    // v1 schema isolates the specific failure under test from the
    // v2 integrity/exclusion gates, except where a test opts into v2.
    meta.schema_version = 1;
    meta.policy_epoch = Some(policy_epoch);
    let _ = meta.mark_ready();
    meta
}

fn restore_ctx(
    snapshot_id: SnapshotId,
    request_tenant: &str,
    current_epoch: u64,
) -> RestoreContext {
    RestoreContext {
        snapshot_id,
        sandbox_id: SandboxId::generate(),
        operation_id: OperationId::generate(),
        host_backend: BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        host_cpu: CpuShape::new("x86_64"),
        host_memory: MemoryShape {
            memory_mb: 4096,
            vcpus: 4,
        },
        host_device: DeviceModel::new("q35"),
        host_runtime: RuntimeType::Firecracker,
        requires_memory: false,
        request_tenant: TenantId::from_string(request_tenant),
        current_policy_epoch: current_epoch,
        production_mode: false,
    }
}

/// Tampered blob content is rejected with a typed integrity error.
#[tokio::test]
async fn restore_rejects_tampered_blob() {
    let repo = Arc::new(MapRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let snapshot_id = SnapshotId::generate();

    let mut meta = base_metadata(snapshot_id.clone(), "tnt_test", 1);
    let expected = blake3::hash(b"original content").to_hex().to_string();
    meta.filesystem_refs.push(FilesystemRef {
        blob_ref: "rootfs.ext4".into(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{expected}")),
        is_root: true,
    });
    repo.store(&meta);

    // Write different bytes than the recorded digest.
    locator.write_blob("rootfs.ext4", b"tampered content");

    let orchestrator = RestoreOrchestrator::new(repo, locator);
    let ctx = restore_ctx(snapshot_id, "tnt_test", 1);
    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::BlobIntegrityMismatch { .. })),
        "expected BlobIntegrityMismatch, got: {result:?}"
    );
}

/// Metadata mutated after the integrity digest was frozen is rejected.
#[tokio::test]
async fn restore_rejects_stale_metadata_digest() {
    let repo = Arc::new(SharedRepo::new());
    let locator = Arc::new(EmptyLocator);
    let snapshot_id = SnapshotId::generate();

    let mut meta = base_metadata(snapshot_id.clone(), "tnt_test", 1);
    // Opt into v2 integrity plus exclusion so the tamper is caught by the
    // digest check rather than skipped as a v1 snapshot.
    meta.schema_version = 2;
    meta.credential_policy = Some(pico_core::snapshot::CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];
    let digest = compute_metadata_digest(&meta);
    meta.integrity = Some(SnapshotIntegrity {
        metadata_digest: digest,
        blob_digests: vec![],
        encryption_key: None,
        integrity_required: true,
    });

    // Tamper after the digest was frozen.
    meta.image_id = "tampered_image".into();
    repo.store(&meta);

    let orchestrator = RestoreOrchestrator::new(Arc::clone(&repo) as _, locator);
    let ctx = restore_ctx(snapshot_id, "tnt_test", 1);
    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
        "expected IntegrityFailed for stale digest, got: {result:?}"
    );
}

/// Cross-tenant restore is rejected before any blob I/O.
#[tokio::test]
async fn restore_rejects_wrong_tenant() {
    let repo = Arc::new(MapRepo::new());
    let locator = Arc::new(EmptyLocator);
    let snapshot_id = SnapshotId::generate();

    let meta = base_metadata(snapshot_id.clone(), "tnt_a", 1);
    repo.store(&meta);

    let orchestrator = RestoreOrchestrator::new(repo, locator);
    let ctx = restore_ctx(snapshot_id, "tnt_b", 1);
    let result = orchestrator.validate_restore(&ctx).await;
    match result {
        Err(SnapshotError::TenantMismatch {
            snapshot_tenant,
            request_tenant,
            ..
        }) => {
            assert_eq!(snapshot_tenant, "tnt_a");
            assert_eq!(request_tenant, "tnt_b");
        }
        other => panic!("expected TenantMismatch, got: {other:?}"),
    }
}

/// Snapshot from a stale policy epoch is rejected.
#[tokio::test]
async fn restore_rejects_stale_policy_epoch() {
    let repo = Arc::new(MapRepo::new());
    let locator = Arc::new(EmptyLocator);
    let snapshot_id = SnapshotId::generate();

    let meta = base_metadata(snapshot_id.clone(), "tnt_test", 1);
    repo.store(&meta);

    let orchestrator = RestoreOrchestrator::new(repo, locator);
    let ctx = restore_ctx(snapshot_id, "tnt_test", 2);
    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(
            result,
            Err(SnapshotError::PolicyEpochIncompatible {
                snapshot_epoch: 1,
                current_epoch: 2,
            })
        ),
        "expected PolicyEpochIncompatible, got: {result:?}"
    );
}

/// v2 snapshots without exclusion proof are rejected (exclusion receipt gate).
#[tokio::test]
async fn restore_rejects_missing_exclusion_receipt() {
    let repo = Arc::new(MapRepo::new());
    let locator = Arc::new(EmptyLocator);
    let snapshot_id = SnapshotId::generate();

    let mut meta = base_metadata(snapshot_id.clone(), "tnt_test", 1);
    meta.schema_version = 2;
    // Intentionally omit credential policy and secret exclusion.
    let digest = compute_metadata_digest(&meta);
    meta.integrity = Some(SnapshotIntegrity {
        metadata_digest: digest,
        blob_digests: vec![],
        encryption_key: None,
        integrity_required: true,
    });
    // Recompute after integrity is set is not needed: verify_metadata_digest
    // excludes the integrity field itself.
    let fresh = compute_metadata_digest(&meta);
    meta.integrity.as_mut().unwrap().metadata_digest =
        IntegrityDigest::new(fresh.algorithm.clone(), fresh.value.clone());
    repo.store(&meta);

    let orchestrator = RestoreOrchestrator::new(repo, locator);
    let ctx = restore_ctx(snapshot_id, "tnt_test", 1);
    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(
            result,
            Err(SnapshotError::CredentialExclusionInvalid { .. })
                | Err(SnapshotError::CredentialMaterialDetected { .. })
        ),
        "expected exclusion rejection, got: {result:?}"
    );
}
