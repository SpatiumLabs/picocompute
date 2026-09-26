//! Security robustness tests for snapshot encryption and integrity.
//!
//! Tests the full encryption → store → metadata → restore → decrypt pipeline
//! against the 15 misuse vectors identified in the grilling session.
//!
//! These tests use a mock KMS (MockKeyResolver), temporary files for
//! encrypted blobs, and the full RestoreOrchestrator pipeline.

use async_trait::async_trait;
use std::sync::Arc;

mod common;
use common::InMemorySnapshotRepo as InMemoryRepo;

use pico_core::identity::{OperationId, SandboxId, SnapshotId, TenantId};
use pico_core::runtime::RuntimeType;
use pico_core::snapshot::blob::{BlobInfo, BlobLocator};
use pico_core::snapshot::encryption::{
    KeyResolver, compute_blob_digest, compute_metadata_digest, encrypt_blob_for_snapshot,
};
use pico_core::snapshot::error::{SnapshotError, SnapshotResult};
use pico_core::snapshot::integrity::{
    BlobDigest, EncryptionKeyRef, IntegrityDigest, SnapshotIntegrity,
};
use pico_core::snapshot::metadata::{FilesystemRef, SnapshotMetadata};
use pico_core::snapshot::profile::SnapshotProfile;
use pico_core::snapshot::purpose::{LineageType, SnapshotPurpose};
use pico_core::snapshot::restore::{RestoreContext, RestoreOrchestrator};
use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
use std::path::PathBuf;

// ── MockKeyResolver (shared across tests) ──

struct MockKeyResolver {
    key: Vec<u8>,
    fail_on_resolve: bool,
}

impl MockKeyResolver {
    fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            fail_on_resolve: false,
        }
    }

    fn failing() -> Self {
        Self {
            key: vec![0u8; 32],
            fail_on_resolve: true,
        }
    }
}

#[async_trait]
impl KeyResolver for MockKeyResolver {
    async fn resolve_key(&self, key_ref: &EncryptionKeyRef) -> SnapshotResult<Vec<u8>> {
        if self.fail_on_resolve {
            return Err(SnapshotError::KeyUnavailable {
                id: format!("{}:{}", key_ref.kms_id, key_ref.key_id),
            });
        }
        Ok(self.key.clone())
    }
}

// ── TempFileBlobLocator ──

/// A BlobLocator that stores blobs as files in a temp directory.
struct TempFileBlobLocator {
    dir: tempfile::TempDir,
}

impl TempFileBlobLocator {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("failed to create temp dir"),
        }
    }

    /// Writes blob data to a file and returns the path.
    fn write_blob(&self, blob_ref: &str, data: &[u8]) -> PathBuf {
        let path = self.dir.path().join(blob_ref.replace('/', "_"));
        std::fs::write(&path, data).expect("failed to write blob");
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
        let metadata = std::fs::metadata(&path).map_err(|_| SnapshotError::BlobMissing {
            blob_ref: blob_ref.to_string(),
        })?;
        Ok(BlobInfo {
            blob_ref: blob_ref.to_string(),
            path,
            size_bytes: metadata.len(),
            digest: None, // Populated by the caller if needed.
        })
    }
}

// ── Test helpers ──

fn make_tenant_key(tenant_num: u8) -> Vec<u8> {
    (tenant_num..tenant_num + 32).collect::<Vec<_>>()
}

fn make_key_ref() -> EncryptionKeyRef {
    EncryptionKeyRef::new("aws-kms", "arn:aws:kms:us-east-1:key/test-key-1")
}

fn make_base_metadata(
    snapshot_id: SnapshotId,
    tenant_id: &str,
    policy_epoch: u64,
) -> SnapshotMetadata {
    let mut meta = SnapshotMetadata::new(
        snapshot_id,
        TenantId::from_string(tenant_id),
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
    meta.schema_version = 2;
    meta.policy_epoch = Some(policy_epoch);
    // Exclusion receipt: v2 restores require secret exclusion proof.
    meta.credential_policy = Some(pico_core::snapshot::CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];
    let _ = meta.mark_ready();
    meta
}

fn make_restore_ctx(snapshot_id: SnapshotId, policy_epoch: u64) -> RestoreContext {
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
        request_tenant: TenantId::from_string("tnt_test"),
        current_policy_epoch: policy_epoch,
        production_mode: false,
    }
}

/// Encrypts a plaintext blob and records it in the metadata with integrity.
fn encrypt_and_record_blob(
    metadata: &mut SnapshotMetadata,
    blob_ref: &str,
    plaintext: &[u8],
    key: &[u8],
    locator: &TempFileBlobLocator,
    key_ref: &EncryptionKeyRef,
) {
    let blob = encrypt_blob_for_snapshot(
        plaintext,
        key,
        blob_ref,
        &metadata.tenant_id.to_string(),
        &metadata.id.to_string(),
        metadata.policy_epoch.unwrap_or(0),
        &format!("{}:{}", key_ref.kms_id, key_ref.key_id),
    )
    .expect("encryption should succeed");

    // Write encrypted blob to temp storage.
    locator.write_blob(blob_ref, &blob.data);

    // Record in metadata.
    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: blob_ref.to_string(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{}", blob.digest)),
        is_root: true,
    });

    // Update the integrity record.
    let mut digests = metadata
        .integrity
        .as_ref()
        .map(|si| si.blob_digests.clone())
        .unwrap_or_default();
    digests.push(BlobDigest {
        blob_ref: blob_ref.to_string(),
        digest: IntegrityDigest::new("blake3", blob.digest),
    });

    let metadata_digest = compute_metadata_digest(metadata);

    metadata.integrity = Some(SnapshotIntegrity {
        metadata_digest,
        blob_digests: digests,
        encryption_key: Some(key_ref.clone()),
        integrity_required: true,
    });
}

// ── Tests ──

/// Vector 1: Encrypt/decrypt round-trip through full orchestrator.
#[tokio::test]
async fn round_trip_encrypt_decrypt_through_orchestrator() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_resolver = Arc::new(MockKeyResolver::new(key.clone()));
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"hello snapshot world",
        &key,
        &locator,
        &key_ref,
    );

    repo.store(&metadata);

    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id.clone(), policy_epoch);

    let prepared = orchestrator.prepare_restore(&ctx).await.unwrap();

    assert_eq!(prepared.blob_set.filesystem_blobs.len(), 1);
    // Encrypted prepare owns temp guards; decrypted file exists while held.
    assert_eq!(prepared.guards.len(), 1);
    let decrypted_path = prepared.blob_set.filesystem_blobs[0].path.clone();
    assert!(decrypted_path.exists());
    let decrypted = std::fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, b"hello snapshot world");
    // Dropping guards removes decrypted plaintext.
    let (_meta, _blobs, guards) = prepared.into_parts();
    drop(guards);
    assert!(!decrypted_path.exists());
}

/// Vector 2: Wrong key → restore fails.
#[tokio::test]
async fn wrong_key_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let encrypt_key = make_tenant_key(1);
    let decrypt_key = make_tenant_key(99); // different key
    let key_resolver = Arc::new(MockKeyResolver::new(decrypt_key));
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"sensitive data",
        &encrypt_key,
        &locator,
        &key_ref,
    );
    repo.store(&metadata);

    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
        "wrong key should fail: {:?}",
        result.err()
    );
}

/// Vector 3: Tampered ciphertext → restore fails.
#[tokio::test]
async fn tampered_ciphertext_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_resolver = Arc::new(MockKeyResolver::new(key.clone()));
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    // Encrypt, then tamper with the stored ciphertext.
    let blob_ref = "rootfs.ext4";
    let blob = encrypt_blob_for_snapshot(
        b"original data",
        &key,
        blob_ref,
        "tnt_test",
        &snapshot_id.to_string(),
        policy_epoch,
        &format!("{}:{}", key_ref.kms_id, key_ref.key_id),
    )
    .unwrap();

    let mut tampered = blob.data.clone();
    // Flip a bit in the ciphertext (after nonce, before tag).
    let flip_at = 12 + 3; // nonce + 3rd byte of ciphertext
    tampered[flip_at] ^= 0x01;

    locator.write_blob(blob_ref, &tampered);

    // Record the original digest (which won't match tampered bytes).
    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: blob_ref.to_string(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{}", blob.digest)),
        is_root: true,
    });

    let metadata_digest = compute_metadata_digest(&metadata);
    metadata.integrity = Some(SnapshotIntegrity {
        metadata_digest,
        blob_digests: vec![BlobDigest {
            blob_ref: blob_ref.to_string(),
            digest: IntegrityDigest::new("blake3", &blob.digest),
        }],
        encryption_key: Some(key_ref.clone()),
        integrity_required: true,
    });

    repo.store(&metadata);

    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    // Tampered cipheretext → integrity mismatch (pre-KMS check) or
    // AEAD failure (post-KMS). Either way, restore must fail.
    assert!(
        result.is_err(),
        "tampered ciphertext should fail restore: {:?}",
        result.ok()
    );
}

/// Vector 4: Missing integrity block on v2 schema → rejected.
#[tokio::test]
async fn missing_integrity_block_on_v2_schema_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_resolver = Arc::new(MockKeyResolver::new(key));
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    // schema_version is already 2, but we leave integrity: None.

    repo.store(&metadata);

    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityRequired { .. })),
        "v2 snapshot without integrity should be rejected: {:?}",
        result.err()
    );
}

/// Vector 5: Key unavailable → restore fails.
#[tokio::test]
async fn key_unavailable_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"test data",
        &key,
        &locator,
        &key_ref,
    );
    repo.store(&metadata);

    // Key resolver that always fails.
    let failing_resolver = Arc::new(MockKeyResolver::failing());
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(failing_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::KeyUnavailable { .. })),
        "unavailable key should fail: {:?}",
        result.err()
    );
}

/// Vector 6: Cross-tenant restore → rejected by AEAD binding.
#[tokio::test]
async fn cross_tenant_restore_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key_a = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    // Create snapshot for tenant A, encrypted with tenant A's key.
    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_a", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"tenant A data",
        &key_a,
        &locator,
        &key_ref,
    );

    // Now modify metadata to claim tenant B, but keep the same key.
    // The AEAD AAD binds the tenant, so decryption will fail.
    metadata.tenant_id = TenantId::from_string("tnt_b");
    let metadata_digest = compute_metadata_digest(&metadata);
    metadata.integrity.as_mut().unwrap().metadata_digest = metadata_digest;

    repo.store(&metadata);

    // Tenant B tries to restore with the same key.
    let key_resolver = Arc::new(MockKeyResolver::new(key_a.clone()));
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let mut ctx = make_restore_ctx(snapshot_id, policy_epoch);
    // Claim tenant B so the explicit tenant binding passes and the AEAD
    // AAD binding is what rejects the restore.
    ctx.request_tenant = TenantId::from_string("tnt_b");

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        result.is_err(),
        "cross-tenant restore should fail (AAD binding): {:?}",
        result.ok()
    );
}

/// Vector 7: Validate that integrity check runs before decryption.
///
/// This test verifies ordering: if the stored-byte digest doesn't match,
/// the error should be surfaced before any KMS call (KeyUnavailable would
/// mean KMS was called, IntegrityFailed means the pre-KMS check caught it).
#[tokio::test]
async fn pre_kms_integrity_check_runs_before_decryption() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    // Encrypt and write blob.
    let blob = encrypt_blob_for_snapshot(
        b"test data",
        &key,
        "rootfs.ext4",
        "tnt_test",
        &snapshot_id.to_string(),
        policy_epoch,
        &format!("{}:{}", key_ref.kms_id, key_ref.key_id),
    )
    .unwrap();

    locator.write_blob("rootfs.ext4", &blob.data);

    // Record a WRONG digest in metadata (simulates metadata tampering).
    let wrong_digest = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: "rootfs.ext4".into(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(wrong_digest.to_string()),
        is_root: true,
    });

    let metadata_digest = compute_metadata_digest(&metadata);
    metadata.integrity = Some(SnapshotIntegrity {
        metadata_digest,
        blob_digests: vec![BlobDigest {
            blob_ref: "rootfs.ext4".into(),
            digest: IntegrityDigest::new(
                "blake3",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        }],
        encryption_key: Some(key_ref.clone()),
        integrity_required: true,
    });

    repo.store(&metadata);

    // Use a failing key resolver — if KMS is called, it will fail with
    // KeyUnavailable. But the integrity check should fail FIRST with
    // BlobIntegrityMismatch.
    let key_resolver = Arc::new(MockKeyResolver::failing());
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::BlobIntegrityMismatch { .. })),
        "pre-KMS integrity check should fail before decryption: {:?}",
        result.err()
    );
}

/// Vector 8: Truncated ciphertext → restore fails.
#[tokio::test]
async fn truncated_ciphertext_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_resolver = Arc::new(MockKeyResolver::new(key.clone()));
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    // Encrypt full blob, then truncate.
    let blob = encrypt_blob_for_snapshot(
        b"full blob data",
        &key,
        "rootfs.ext4",
        "tnt_test",
        &snapshot_id.to_string(),
        policy_epoch,
        &format!("{}:{}", key_ref.kms_id, key_ref.key_id),
    )
    .unwrap();

    // Truncate to half the size — will fail both integrity and decryption.
    let truncated = &blob.data[..blob.data.len() / 2];
    let truncated_digest = compute_blob_digest(truncated);
    locator.write_blob("rootfs.ext4", truncated);

    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: "rootfs.ext4".into(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{}", truncated_digest)),
        is_root: true,
    });

    let metadata_digest = compute_metadata_digest(&metadata);
    metadata.integrity = Some(SnapshotIntegrity {
        metadata_digest,
        blob_digests: vec![BlobDigest {
            blob_ref: "rootfs.ext4".into(),
            digest: IntegrityDigest::new("blake3", &truncated_digest),
        }],
        encryption_key: Some(key_ref.clone()),
        integrity_required: true,
    });

    repo.store(&metadata);

    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        result.is_err(),
        "truncated ciphertext should fail: {:?}",
        result.ok()
    );
}

/// Vector 9: Metadata digest mismatch → rejected.
#[tokio::test]
async fn metadata_digest_mismatch_rejected() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"test",
        &key,
        &locator,
        &key_ref,
    );

    // Tamper with metadata after digest was computed.
    // Change a field that is covered by the metadata digest but does NOT
    // have its own compatibility check (unlike policy_epoch which triggers
    // PolicyEpochIncompatible first).
    metadata.image_id = "tampered_image_id".into();
    // Metadata digest still reflects the old image_id.

    repo.store(&metadata);

    let key_resolver = Arc::new(MockKeyResolver::new(key));
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
        "metadata digest mismatch should fail: {:?}",
        result.err()
    );
}

/// Vector 10: integrity_required=false with encryption → rejected in production.
#[tokio::test]
async fn integrity_required_false_with_encryption_rejected_in_production() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"test",
        &key,
        &locator,
        &key_ref,
    );

    // Set integrity_required to false — this should be rejected in production.
    metadata.integrity.as_mut().unwrap().integrity_required = false;

    repo.store(&metadata);

    let key_resolver = Arc::new(MockKeyResolver::new(key));
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);

    let mut ctx = make_restore_ctx(snapshot_id, policy_epoch);
    ctx.production_mode = true;

    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityRequired { .. })),
        "integrity_required=false should be rejected in production: {:?}",
        result.err()
    );
}

/// Vector 11: Stale metadata digest (modify encryption_key_ref after digest frozen).
#[tokio::test]
async fn stale_metadata_digest_after_encryption_key_ref_change() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);
    encrypt_and_record_blob(
        &mut metadata,
        "rootfs.ext4",
        b"test",
        &key,
        &locator,
        &key_ref,
    );

    // Modify the deprecated encryption_key_ref string field after integrity
    // was computed. This field IS covered by the metadata digest (unlike
    // integrity.encryption_key which is excluded to avoid circular dependency).
    metadata.encryption_key_ref = Some("kms://aws/us-east-1/tampered-key".into());
    // Metadata digest still reflects the old encryption_key_ref → should fail.

    repo.store(&metadata);

    let key_resolver = Arc::new(MockKeyResolver::new(key));
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.validate_restore(&ctx).await;
    assert!(
        matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
        "stale metadata digest after key ref change should fail: {:?}",
        result.err()
    );
}

/// Vector 12: No key resolver configured → blobs pass through as plaintext.
///
/// When no KeyResolver is attached to the orchestrator, encrypted blobs
/// are returned as-is (no decryption). This is for v1 snapshots or
/// development mode where blobs are stored unencrypted.
#[tokio::test]
async fn no_key_resolver_passes_blobs_through() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    // Write plaintext blob (no encryption).
    let plaintext = b"plaintext blob";
    let digest = compute_blob_digest(plaintext);
    locator.write_blob("rootfs.ext4", plaintext);

    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: "rootfs.ext4".into(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{}", digest)),
        is_root: true,
    });

    // No encryption key ref — plaintext blob with integrity only.
    // schema_version defaults to 2 (current).
    let metadata_digest = compute_metadata_digest(&metadata);
    metadata.integrity = Some(SnapshotIntegrity {
        metadata_digest,
        blob_digests: vec![BlobDigest {
            blob_ref: "rootfs.ext4".into(),
            digest: IntegrityDigest::new("blake3", &digest),
        }],
        encryption_key: None,
        integrity_required: true,
    });

    repo.store(&metadata);

    // No key resolver attached.
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    );
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let prepared = orchestrator.prepare_restore(&ctx).await.unwrap();
    let blob_set = prepared.blob_set;

    // Blob should come back as-is (plaintext).
    let decrypted = std::fs::read(&blob_set.filesystem_blobs[0].path).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Vector 13: Multiple blobs, one decrypts successfully, one fails → atomic failure.
#[tokio::test]
async fn multi_blob_partial_decryption_failure_is_atomic() {
    let repo = Arc::new(InMemoryRepo::new());
    let locator = Arc::new(TempFileBlobLocator::new());
    let key = make_tenant_key(1);
    let key_ref = make_key_ref();
    let snapshot_id = SnapshotId::generate();
    let policy_epoch = 1;

    let mut metadata = make_base_metadata(snapshot_id.clone(), "tnt_test", policy_epoch);

    // Blob 1: correctly encrypted with tenant A's key.
    encrypt_and_record_blob(
        &mut metadata,
        "blob-1.ext4",
        b"blob one data",
        &key,
        &locator,
        &key_ref,
    );

    // Blob 2: write garbage that will fail decryption.
    let garbage = b"not a valid encrypted blob at all";
    let garbage_digest = compute_blob_digest(garbage);
    locator.write_blob("blob-2.ext4", garbage);

    metadata.filesystem_refs.push(FilesystemRef {
        blob_ref: "blob-2.ext4".into(),
        mount_point: "/data".into(),
        fs_type: "ext4".into(),
        digest: Some(format!("blake3:{}", garbage_digest)),
        is_root: false,
    });

    if let Some(ref mut integrity) = metadata.integrity {
        integrity.blob_digests.push(BlobDigest {
            blob_ref: "blob-2.ext4".into(),
            digest: IntegrityDigest::new("blake3", &garbage_digest),
        });
        // Compute digest after all modifications are done.
    }
    // Recompute metadata digest now that all blob digests are populated.
    let updated_digest = compute_metadata_digest(&metadata);
    if let Some(ref mut integrity) = metadata.integrity {
        integrity.metadata_digest = updated_digest;
    }

    repo.store(&metadata);

    let key_resolver = Arc::new(MockKeyResolver::new(key));
    let orchestrator = RestoreOrchestrator::new(
        Arc::<InMemoryRepo>::clone(&repo),
        Arc::<TempFileBlobLocator>::clone(&locator),
    )
    .with_key_resolver(key_resolver);
    let ctx = make_restore_ctx(snapshot_id, policy_epoch);

    let result = orchestrator.prepare_restore(&ctx).await;
    assert!(
        result.is_err(),
        "partial decryption failure should fail atomically: {:?}",
        result.ok()
    );
}
