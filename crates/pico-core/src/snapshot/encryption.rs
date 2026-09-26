//! Snapshot encryption and decryption pipeline.
//!
//! Implements: Add snapshot encryption and integrity checks.
//!
//! Provides:
//! - [`KeyResolver`] trait for KMS abstraction (tenant-scoped keys)
//! - [`EncryptingBlobLocator`] decorator for transparent blob decryption
//! - AEAD encryption/decryption primitives for blob payloads
//! - Metadata and blob integrity digest computation
//!
//! ## Encryption format
//!
//! Each blob is encrypted with AES-256-GCM:
//!
//! ```text
//! [nonce: 12 bytes] [ciphertext || tag: N + 16 bytes]
//! ```
//!
//! AAD binds the blob to tenant, snapshot, and policy epoch:
//!
//! ```text
//! AAD = blob_ref || tenant_id || snapshot_id || policy_epoch || key_id
//! ```
//!
//! ## Integrity model
//!
//! Two-layer integrity (defense-in-depth):
//!
//! 1. **AEAD tag** — proves cryptographic authenticity (ciphertext was
//!    produced by someone holding the key). Lives in the blob store.
//! 2. **Blob digest** — BLAKE3 of the *stored ciphertext* (nonce || ct || tag).
//!    Proves storage integrity without requiring KMS access. Stored in
//!    trusted metadata.
//!
//! ## Metadata integrity
//!
//! `compute_metadata_digest` produces a BLAKE3 hash over the metadata
//! fields that must be immutable after snapshot creation. The digest
//! excludes the `integrity` field (circular dependency) and mutable
//! lifecycle fields (`state`, `ready_at`, `updated_at`).

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload, consts::U12};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;

use super::error::{SnapshotError, SnapshotResult};
use super::integrity::{BlobDigest, EncryptionKeyRef, IntegrityDigest, SnapshotIntegrity};
use super::metadata::SnapshotMetadata;

// ── Chunked AEAD constants ──

/// Maximum blob size that can be encrypted as a single AEAD operation.
///
/// AES-256-GCM has a maximum plaintext size of ~64 GiB (2^39 - 256 bits).
/// This limit is far below that — we use 4 GiB as a practical chunk boundary.
/// When a blob exceeds this size, callers should use chunked encryption.
///
/// Note: chunked AEAD is forward-looking (not yet implemented). These
/// constants serve as documentation of the intended architecture.
pub const MAX_SINGLE_AEAD_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Maximum chunk size for chunked AEAD mode (1 GiB per chunk).
///
/// Forward-looking: chunked AEAD is not yet implemented.
pub const CHUNK_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

/// Size of AES-256-GCM nonce (96 bits = 12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Size of AES-256-GCM authentication tag (128 bits = 16 bytes).
pub const TAG_SIZE: usize = 16;

// ── KeyResolver trait ──

/// Resolves encryption key material from a [`EncryptionKeyRef`].
///
/// Implementations talk to a KMS (AWS KMS, GCP KMS, HashiCorp Vault, etc.)
/// and return the raw key bytes. The key material is never persisted to
/// snapshot metadata — only the [`EncryptionKeyRef`] is stored.
///
/// Tenant-scoped keys are the default: every tenant gets one key, and all
/// snapshots for that tenant share it. The key reference encodes the tenant
/// binding so that cross-tenant restore is rejected at the KMS layer before
/// any blob decryption.
#[async_trait]
pub trait KeyResolver: Send + Sync {
    /// Resolves the raw key bytes for the given key reference.
    ///
    /// Returns a 256-bit (32-byte) key for AES-256-GCM.
    /// Returns [`SnapshotError::KeyUnavailable`] if the key cannot be resolved.
    async fn resolve_key(&self, key_ref: &EncryptionKeyRef) -> SnapshotResult<Vec<u8>>;

    /// Validates that a key reference is resolvable before attempting decryption.
    ///
    /// Used during metadata-only compatibility validation to avoid wasting
    /// time on blob I/O when the key is unavailable. Default implementation
    /// delegates to [`EncryptionKeyRef::is_resolvable`].
    fn validate_key_ref(&self, key_ref: &EncryptionKeyRef) -> SnapshotResult<()> {
        if !key_ref.is_resolvable() {
            return Err(SnapshotError::KeyUnavailable {
                id: format!("{}:{}", key_ref.kms_id, key_ref.key_id),
            });
        }
        Ok(())
    }
}

// ── AAD construction ──

/// Constructs the authenticated additional data (AAD) for AEAD operations.
///
/// The AAD binds the ciphertext to the snapshot's identity context.
/// Any mismatch in AAD during decryption causes AEAD verification failure,
/// preventing cross-tenant, cross-snapshot, or cross-epoch blob reuse.
pub fn build_aead_aad(
    blob_ref: &str,
    tenant_id: &str,
    snapshot_id: &str,
    policy_epoch: u64,
    key_id: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        blob_ref.len()
            + tenant_id.len()
            + snapshot_id.len()
            + 24  // policy_epoch as string
            + key_id.len()
            + 5, // 4 separators + length prefix
    );
    aad.extend_from_slice(b"blob:");
    aad.extend_from_slice(blob_ref.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(b"tenant:");
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(b"snapshot:");
    aad.extend_from_slice(snapshot_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(b"epoch:");
    aad.extend_from_slice(policy_epoch.to_string().as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(b"key:");
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

// ── Cipher initialization ──

/// Validates key length and initializes an AES-256-GCM cipher.
fn init_cipher(key: &[u8]) -> SnapshotResult<Aes256Gcm> {
    if key.len() != 32 {
        return Err(SnapshotError::KeyUnavailable {
            id: format!("invalid key length: {} bytes (expected 32)", key.len()),
        });
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| SnapshotError::KeyUnavailable {
        id: "failed to initialize AES-256-GCM cipher".into(),
    })
}

// ── Blob encryption/decryption ──

/// Encrypts plaintext blob data with AES-256-GCM.
///
/// Returns the encrypted bytes in format: `[nonce (12)] [ciphertext || tag]`.
///
/// # Parameters
/// - `plaintext`: Raw blob data to encrypt.
/// - `key`: 256-bit (32-byte) AES key.
/// - `aad`: Authenticated additional data binding the ciphertext to
///   tenant, snapshot, and policy context.
pub fn encrypt_blob(plaintext: &[u8], key: &[u8], aad: &[u8]) -> SnapshotResult<Vec<u8>> {
    let cipher = init_cipher(key)?;
    let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
    let nonce = Nonce::<U12>::try_from(&nonce_bytes[..]).expect("NONCE_SIZE (12) bytes fits U12");
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            // AES-256-GCM encryption failure with valid inputs indicates
            // an internal cipher error (OOM, implementation bug), not a
            // caller error. IntegrityFailed is used because the operation
            // cannot proceed, but this should be treated as fatal/retryable,
            // not as a tampering signal.
            SnapshotError::IntegrityFailed {
                expected: "valid AEAD encryption".into(),
                actual: "AEAD encryption failed".into(),
            }
        })?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts ciphertext blob data with AES-256-GCM.
///
/// Expects input in format: `[nonce (12)] [ciphertext || tag]`.
///
/// Returns the decrypted plaintext. Fails with [`SnapshotError::IntegrityFailed`]
/// if the AEAD authentication tag does not verify (tampering, wrong key,
/// or AAD mismatch).
///
/// # Parameters
/// - `encrypted`: Encrypted blob bytes (nonce + ciphertext + tag).
/// - `key`: 256-bit (32-byte) AES key.
/// - `aad`: Authenticated additional data — must match exactly what was
///   used during encryption.
pub fn decrypt_blob(encrypted: &[u8], key: &[u8], aad: &[u8]) -> SnapshotResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(SnapshotError::IntegrityFailed {
            expected: format!("at least {} bytes", NONCE_SIZE + TAG_SIZE),
            actual: format!("{} bytes", encrypted.len()),
        });
    }

    let cipher = init_cipher(key)?;
    let nonce = Nonce::<U12>::try_from(&encrypted[..NONCE_SIZE])
        .expect("checked length above ensures 12+ bytes available");
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted[NONCE_SIZE..],
                aad,
            },
        )
        .map_err(|_| SnapshotError::IntegrityFailed {
            expected: "valid AEAD authentication tag".into(),
            actual: "AEAD decryption failed — wrong key, tampered ciphertext, or AAD mismatch"
                .into(),
        })?;

    Ok(plaintext)
}

// ── Blob digest computation ──

/// Computes the BLAKE3 hex digest of blob data.
///
/// For encrypted blobs, this digests the stored ciphertext (nonce || ct || tag),
/// enabling pre-KMS integrity verification: the digest can be checked without
/// accessing the KMS. If the digest doesn't match, the blob is corrupt and
/// there's no point calling KMS.
///
/// The returned string is the hex-encoded BLAKE3 hash (no algorithm prefix).
pub fn compute_blob_digest(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Computes the BLAKE3 hex digest of a file at the given path.
///
/// Reads the entire file into memory and hashes it. For very large files,
/// the caller should use streaming hashing via `blake3::Hasher`.
pub fn compute_file_digest(path: &Path) -> Result<String, std::io::Error> {
    let content = std::fs::read(path)?;
    Ok(compute_blob_digest(&content))
}

// ── Metadata digest computation ──

/// Computes the integrity digest for snapshot metadata.
///
/// Hashes a canonical serialization of the metadata fields that must be
/// immutable after snapshot creation. Excludes:
/// - `integrity` field (circular dependency — the digest is stored in it)
/// - `state`, `ready_at`, `updated_at` (mutable lifecycle fields)
/// - `version` (incremented on updates)
///
/// Canonicalization: we build a `serde_json::Value::Object` and serialize
/// it with `serde_json::to_vec`, which guarantees sorted keys in the output.
/// This is stable within the Rust `serde_json` ecosystem. For cross-language
/// verification, consumers must ensure they reproduce the same key ordering.
//
// TODO(pico-metadata-integrity-bind): the metadata digest covers
// `encryption_key_ref` (the deprecated string) but NOT
// `integrity.encryption_key` (the structured field). When the string
// field is fully deprecated, extend the digest to cover the structured
// key reference through a separate authenticated section (e.g., HMAC
// the non-circular SnapshotIntegrity fields with a metadata-derived key).
pub fn compute_metadata_digest(metadata: &SnapshotMetadata) -> IntegrityDigest {
    // Build a canonical representation of the immutable fields.
    // We use a manual JSON object to avoid coupling to serde field order
    // and to explicitly exclude the mutable/lifecycle fields.
    let canonical = serde_json::json!({
        "schema_version": metadata.schema_version,
        "id": metadata.id.to_string(),
        "tenant_id": metadata.tenant_id.to_string(),
        "sandbox_id": metadata.sandbox_id.to_string(),
        "parent_snapshot_id": metadata.parent_snapshot_id.as_ref().map(|s| s.to_string()),
        "lineage_type": metadata.lineage_type.as_str(),
        "purpose": metadata.purpose.as_str(),
        "profile": metadata.profile.as_str(),
        "operation_id": metadata.operation_id.to_string(),
        "image_id": metadata.image_id,
        "rootfs_digest": metadata.rootfs_digest,
        "kernel_version": metadata.kernel_version,
        "backend": {
            "backend_type": metadata.backend.backend_type,
            "backend_version": metadata.backend.backend_version,
            "protocol_version": metadata.backend.protocol_version,
            "guest_agent_version": metadata.backend.guest_agent_version,
        },
        "cpu_shape": {
            "architecture": metadata.cpu_shape.architecture,
            "vendor": metadata.cpu_shape.vendor,
            "required_features": metadata.cpu_shape.required_features,
        },
        "memory_shape": {
            "memory_mb": metadata.memory_shape.memory_mb,
            "vcpus": metadata.memory_shape.vcpus,
        },
        "device_model": {
            "machine_type": metadata.device_model.machine_type,
            "config_version": metadata.device_model.config_version,
            "required_devices": metadata.device_model.required_devices,
        },
        "memory_segments": metadata.memory_segments.iter().map(|s| serde_json::json!({
            "blob_ref": s.blob_ref,
            "start_address": s.start_address,
            "size_bytes": s.size_bytes,
            "digest": s.digest,
        })).collect::<Vec<_>>(),
        "filesystem_refs": metadata.filesystem_refs.iter().map(|r| serde_json::json!({
            "blob_ref": r.blob_ref,
            "mount_point": r.mount_point,
            "fs_type": r.fs_type,
            "digest": r.digest,
            "is_root": r.is_root,
        })).collect::<Vec<_>>(),
        "workspace_layers": metadata.workspace_layers.iter().map(|l| serde_json::json!({
            "blob_ref": l.blob_ref,
            "layer_index": l.layer_index,
            "parent_blob_ref": l.parent_blob_ref,
            "digest": l.digest,
        })).collect::<Vec<_>>(),
        "policy_epoch": metadata.policy_epoch,
        "network_identity_policy": metadata.network_identity_policy,
        "excluded_mounts": metadata.excluded_mounts,
        "encryption_key_ref": metadata.encryption_key_ref,
        "workload_class": metadata.workload_class,
        "isolation_floor": metadata.isolation_floor,
        "data_classification": metadata.data_classification,
        "credential_policy": metadata.credential_policy.as_ref().map(|p| serde_json::json!({
            "exclude_from_snapshot": p.exclude_from_snapshot,
            "refresh_after_restore": p.refresh_after_restore,
            "fork_credential_policy": p.fork_credential_policy.as_str(),
            "require_lease_for_refresh": p.require_lease_for_refresh,
        })),
        "issued_at": metadata.issued_at,
        "created_at": metadata.created_at,
    });

    // Canonical JSON: sorted keys, no whitespace.
    // Serialization of a serde_json::Value should never fail outside
    // of OOM — if it does, we cannot compute a meaningful digest and
    // must fail closed rather than silently defaulting to BLAKE3("").
    let canonical_bytes =
        serde_json::to_vec(&canonical).expect("metadata digest serialization must not fail");
    let hex_digest = blake3::hash(&canonical_bytes).to_hex().to_string();

    IntegrityDigest::new("blake3", hex_digest)
}

/// Verifies that the metadata digest in [`SnapshotIntegrity`] matches the
/// recomputed digest of the metadata.
///
/// Returns `Ok(())` if the digest matches, or [`SnapshotError::IntegrityFailed`]
/// if it does not. Returns `Ok(())` if there is no integrity record (v1 snapshots).
pub fn verify_metadata_digest(metadata: &SnapshotMetadata) -> SnapshotResult<()> {
    let Some(integrity) = &metadata.integrity else {
        return Ok(()); // No integrity record — v1 snapshot.
    };

    let recomputed = compute_metadata_digest(metadata);

    if recomputed.value != integrity.metadata_digest.value
        || recomputed.algorithm != integrity.metadata_digest.algorithm
    {
        return Err(SnapshotError::IntegrityFailed {
            expected: format!(
                "{}:{}",
                integrity.metadata_digest.algorithm, integrity.metadata_digest.value
            ),
            actual: format!("{}:{}", recomputed.algorithm, recomputed.value),
        });
    }

    Ok(())
}

/// Builds a complete [`SnapshotIntegrity`] record for a snapshot.
///
/// Computes the metadata digest and populates blob digests from the
/// provided blob data map. The caller provides a map from blob_ref to
/// the stored bytes (typically ciphertext for encrypted blobs).
pub fn build_snapshot_integrity(
    metadata: &SnapshotMetadata,
    blob_data: &[(&str, &[u8])],
    encryption_key: Option<EncryptionKeyRef>,
) -> SnapshotIntegrity {
    let metadata_digest = compute_metadata_digest(metadata);

    let blob_digests: Vec<BlobDigest> = blob_data
        .iter()
        .map(|(blob_ref, data)| BlobDigest {
            blob_ref: (*blob_ref).to_string(),
            digest: IntegrityDigest::new("blake3", compute_blob_digest(data)),
        })
        .collect();

    SnapshotIntegrity {
        metadata_digest,
        blob_digests,
        encryption_key,
        integrity_required: true,
    }
}

// ── EncryptingBlobLocator (future) ──
//
// Inline decryption via the BlobLocator trait is deferred: the trait's
// `locate_blob` signature doesn't carry the metadata context needed for
// AEAD AAD construction. Until the trait is extended, decryption is
// orchestrated explicitly in RestoreOrchestrator::decrypt_blob_set.

// ── Write-side helpers ──

/// Result of encrypting a blob during snapshot creation.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    /// The encrypted blob bytes (nonce || ciphertext || tag).
    pub data: Vec<u8>,
    /// BLAKE3 hex digest of the encrypted data (stored bytes).
    pub digest: String,
    /// The AEAD nonce (for audit purposes; also embedded in `data`).
    pub nonce_hex: String,
}

/// Encrypts a plaintext blob for storage in a snapshot.
///
/// Produces an [`EncryptedBlob`] containing the ciphertext and its integrity
/// digest. The digest covers the stored ciphertext (pre-KMS verification
/// compatible). The caller is responsible for writing the encrypted data
/// to storage and recording the digest in metadata.
///
/// # Parameters
/// - `plaintext`: Raw blob data to encrypt.
/// - `key`: 256-bit AES key resolved from KMS.
/// - `blob_ref`: Blob reference for AAD binding.
/// - `tenant_id`: Tenant identifier for AAD binding.
/// - `snapshot_id`: Snapshot identifier for AAD binding.
/// - `policy_epoch`: Policy epoch at capture time for AAD binding.
/// - `key_id`: Key identifier for AAD binding.
pub fn encrypt_blob_for_snapshot(
    plaintext: &[u8],
    key: &[u8],
    blob_ref: &str,
    tenant_id: &str,
    snapshot_id: &str,
    policy_epoch: u64,
    key_id: &str,
) -> SnapshotResult<EncryptedBlob> {
    let aad = build_aead_aad(blob_ref, tenant_id, snapshot_id, policy_epoch, key_id);
    let encrypted = encrypt_blob(plaintext, key, &aad)?;
    let digest = compute_blob_digest(&encrypted);

    let nonce_hex = hex::encode(&encrypted[..NONCE_SIZE]);

    Ok(EncryptedBlob {
        data: encrypted,
        digest,
        nonce_hex,
    })
}

/// Decrypts a blob during snapshot restore.
///
/// Reads the encrypted file from `path`, decrypts it using the resolved key
/// and the AAD context, and writes the decrypted plaintext to a new temporary
/// file. Returns the path to the decrypted temporary file.
///
/// # Parameters
/// - `path`: Path to the encrypted blob on disk.
/// - `key`: 256-bit AES key resolved from KMS.
/// - `blob_ref`: Blob reference for AAD binding.
/// - `tenant_id`: Tenant identifier for AAD binding.
/// - `snapshot_id`: Snapshot identifier for AAD binding.
/// - `policy_epoch`: Policy epoch at capture time for AAD binding.
/// - `key_id`: Key identifier for AAD binding.
pub fn decrypt_blob_file(
    path: &Path,
    key: &[u8],
    blob_ref: &str,
    tenant_id: &str,
    snapshot_id: &str,
    policy_epoch: u64,
    key_id: &str,
) -> SnapshotResult<DecryptedTempGuard> {
    let encrypted = std::fs::read(path).map_err(|e| SnapshotError::BlobMissing {
        blob_ref: format!("{}: {}", blob_ref, e),
    })?;

    let aad = build_aead_aad(blob_ref, tenant_id, snapshot_id, policy_epoch, key_id);
    let plaintext = decrypt_blob(&encrypted, key, &aad)?;

    // Write decrypted content to a temp file.
    // Use a UUID subdirectory to avoid collisions between concurrent
    // restore operations on the same host.
    // The returned DecryptedTempGuard removes the file on drop.
    let temp_dir = std::env::temp_dir()
        .join("pico-snapshot-decrypt")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&temp_dir).map_err(|e| SnapshotError::BlobMissing {
        blob_ref: format!("failed to create temp dir: {}", e),
    })?;

    // Hash the blob_ref for the temp filename to avoid collisions
    // and path traversal from arbitrary ref strings.
    let name_hash = blake3::hash(blob_ref.as_bytes()).to_hex();
    let temp_path = temp_dir.join(format!("{name_hash}.decrypted"));
    std::fs::write(&temp_path, &plaintext).map_err(|e| SnapshotError::BlobMissing {
        blob_ref: format!("failed to write decrypted blob: {}", e),
    })?;

    Ok(DecryptedTempGuard::new(temp_path))
}

// ── Temp file cleanup ──

/// Guard that removes decrypted temporary files and their parent
/// directory on drop.
pub struct DecryptedTempGuard {
    path: PathBuf,
}

impl DecryptedTempGuard {
    /// Creates a new guard for the given path.
    /// The file at `path` and its parent directory will be removed
    /// when this guard is dropped.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the path to the decrypted file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DecryptedTempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        // Best-effort: also remove the parent UUID directory.
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

// ── Hex encoding helper (no external crate needed) ──

mod hex {
    /// Encodes a byte slice as a hex string (lowercase).
    pub(super) fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEX_CHARS[(*b >> 4) as usize] as char);
            s.push(HEX_CHARS[(*b & 0x0f) as usize] as char);
        }
        s
    }

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{OperationId, SandboxId, SnapshotId, TenantId};
    use crate::snapshot::integrity::{EncryptionKeyRef, SnapshotIntegrity};
    use crate::snapshot::metadata::SnapshotMetadata;
    use crate::snapshot::profile::SnapshotProfile;
    use crate::snapshot::purpose::{LineageType, SnapshotPurpose};
    use crate::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

    // ── Test helpers ──

    fn make_test_key() -> Vec<u8> {
        // 32 bytes of deterministic "random" for testing
        (0..32).map(|i| i as u8).collect::<Vec<_>>()
    }

    fn make_different_key() -> Vec<u8> {
        (1..33).map(|i| i as u8).collect::<Vec<_>>()
    }

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

    // ── Encrypt/decrypt round-trip ──

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = make_test_key();
        let plaintext = b"Hello, PicoCompute snapshot encryption!";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_blob(&encrypted, &key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_blob_has_different_nonces() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let enc1 = encrypt_blob(plaintext, &key, &aad).unwrap();
        let enc2 = encrypt_blob(plaintext, &key, &aad).unwrap();

        // Same plaintext, same key, same AAD — but nonces must differ.
        let nonce1 = &enc1[..NONCE_SIZE];
        let nonce2 = &enc2[..NONCE_SIZE];
        assert_ne!(nonce1, nonce2, "nonces must be unique");

        // Both must decrypt to the same plaintext.
        assert_eq!(decrypt_blob(&enc1, &key, &aad).unwrap(), plaintext);
        assert_eq!(decrypt_blob(&enc2, &key, &aad).unwrap(), plaintext);
    }

    // ── Tamper detection ──

    #[test]
    fn wrong_key_rejected() {
        let key_a = make_test_key();
        let key_b = make_different_key();
        let plaintext = b"sensitive data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key_a, &aad).unwrap();
        let result = decrypt_blob(&encrypted, &key_b, &aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "wrong key should fail AEAD verification"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = make_test_key();
        let plaintext = b"sensitive data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let mut encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();
        // Flip a bit in the ciphertext (after the nonce).
        if let Some(byte) = encrypted.get_mut(NONCE_SIZE + 5) {
            *byte ^= 0x01;
        }

        let result = decrypt_blob(&encrypted, &key, &aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "tampered ciphertext should fail AEAD verification"
        );
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();
        // Truncate to just the nonce.
        let truncated = &encrypted[..NONCE_SIZE];

        let result = decrypt_blob(truncated, &key, &aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "truncated ciphertext should be rejected"
        );
    }

    #[test]
    fn aead_tag_stripped_rejected() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();
        // Strip the last 16 bytes (AEAD tag).
        let stripped = &encrypted[..encrypted.len() - TAG_SIZE];

        let result = decrypt_blob(stripped, &key, &aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "stripped AEAD tag should be rejected"
        );
    }

    // ── AAD binding tests ──

    #[test]
    fn wrong_aad_rejected() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad_encrypt = build_aead_aad("blob-001", "tnt_a", "snp_1", 1, "key-1");
        let aad_decrypt = build_aead_aad("blob-001", "tnt_b", "snp_1", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad_encrypt).unwrap();
        let result = decrypt_blob(&encrypted, &key, &aad_decrypt);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "wrong tenant in AAD should fail"
        );
    }

    #[test]
    fn cross_tenant_aad_rejected() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();

        // Attempt decrypt with different tenant in AAD.
        let wrong_aad = build_aead_aad("blob-001", "tnt_evil", "snp_test", 1, "key-1");
        let result = decrypt_blob(&encrypted, &key, &wrong_aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "cross-tenant AAD should fail"
        );
    }

    #[test]
    fn wrong_policy_epoch_in_aad_rejected() {
        let key = make_test_key();
        let plaintext = b"test data";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();

        // Attempt decrypt with different policy epoch in AAD.
        let wrong_aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 42, "key-1");
        let result = decrypt_blob(&encrypted, &key, &wrong_aad);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "wrong policy epoch in AAD should fail"
        );
    }

    // ── Blob digest tests ──

    #[test]
    fn blob_digest_is_stable() {
        let data = b"stable test data for digest";
        let d1 = compute_blob_digest(data);
        let d2 = compute_blob_digest(data);
        assert_eq!(d1, d2, "digest must be deterministic");
    }

    #[test]
    fn blob_digest_differs_for_different_data() {
        let d1 = compute_blob_digest(b"data one");
        let d2 = compute_blob_digest(b"data two");
        assert_ne!(d1, d2);
    }

    #[test]
    fn blob_digest_covers_encrypted_data() {
        let key = make_test_key();
        let plaintext = b"test";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted1 = encrypt_blob(plaintext, &key, &aad).unwrap();
        let encrypted2 = encrypt_blob(plaintext, &key, &aad).unwrap();

        // Different nonces → different ciphertext → different digests.
        let d1 = compute_blob_digest(&encrypted1);
        let d2 = compute_blob_digest(&encrypted2);
        assert_ne!(
            d1, d2,
            "different nonces produce different stored-byte digests"
        );
    }

    // ── Metadata digest tests ──

    #[test]
    fn metadata_digest_is_deterministic() {
        let meta = make_test_metadata();
        let d1 = compute_metadata_digest(&meta);
        let d2 = compute_metadata_digest(&meta);
        assert_eq!(d1.value, d2.value);
        assert_eq!(d1.algorithm, "blake3");
    }

    #[test]
    fn metadata_digest_canonicalization_is_stable() {
        // Verify that digests are stable across multiple computations
        // of the same logical metadata. This catches regressions in
        // serde_json key ordering or field collection changes.
        let meta = make_test_metadata();
        let d1 = compute_metadata_digest(&meta);
        let d2 = compute_metadata_digest(&meta);
        assert_eq!(d1.value, d2.value, "same metadata must produce same digest");
        assert_eq!(d1.algorithm, d2.algorithm);
    }

    #[test]
    fn metadata_digest_differs_for_different_metadata() {
        let m1 = make_test_metadata();
        let mut m2 = make_test_metadata();
        m2.policy_epoch = Some(99);

        let d1 = compute_metadata_digest(&m1);
        let d2 = compute_metadata_digest(&m2);
        assert_ne!(d1.value, d2.value);
    }

    #[test]
    fn verify_metadata_digest_passes() {
        let mut meta = make_test_metadata();
        let digest = compute_metadata_digest(&meta);
        meta.integrity = Some(SnapshotIntegrity::new(digest));

        assert!(verify_metadata_digest(&meta).is_ok());
    }

    #[test]
    fn verify_metadata_digest_fails_on_mismatch() {
        let mut meta = make_test_metadata();
        let wrong_digest = IntegrityDigest::new("blake3", "deadbeef");
        meta.integrity = Some(SnapshotIntegrity::new(wrong_digest));

        let result = verify_metadata_digest(&meta);
        assert!(
            matches!(result, Err(SnapshotError::IntegrityFailed { .. })),
            "mismatched metadata digest should fail"
        );
    }

    #[test]
    fn verify_metadata_digest_passes_without_integrity() {
        let meta = make_test_metadata();
        // No integrity block → v1 snapshot → passes.
        assert!(verify_metadata_digest(&meta).is_ok());
    }

    // ── build_snapshot_integrity tests ──

    #[test]
    fn build_integrity_covers_all_blobs() {
        let meta = make_test_metadata();
        let key = make_test_key();
        let aad = build_aead_aad(
            "blob-1",
            "tnt_test",
            meta.id.to_string().as_str(),
            1,
            "key-1",
        );
        let encrypted = encrypt_blob(b"data one", &key, &aad).unwrap();
        let encrypted2 = encrypt_blob(b"data two", &key, &aad).unwrap();

        let si = build_snapshot_integrity(
            &meta,
            &[
                ("blob-1", encrypted.as_slice()),
                ("blob-2", encrypted2.as_slice()),
            ],
            Some(EncryptionKeyRef::new("aws-kms", "key-1")),
        );

        assert!(si.integrity_required);
        assert_eq!(si.blob_digests.len(), 2);
        assert!(si.encryption_satisfied());
        assert!(si.all_blobs_covered(2));
    }

    // ── encrypt_blob_for_snapshot tests ──

    #[test]
    fn encrypt_for_snapshot_produces_valid_blob() {
        let key = make_test_key();
        let plaintext = b"snapshot blob data";
        let blob = encrypt_blob_for_snapshot(
            plaintext, &key, "blob-001", "tnt_test", "snp_test", 1, "key-1",
        )
        .unwrap();

        assert!(!blob.data.is_empty());
        assert_eq!(blob.data.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
        assert!(!blob.digest.is_empty());
        assert_eq!(blob.nonce_hex.len(), NONCE_SIZE * 2);

        // Verify decryptability.
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");
        let decrypted = decrypt_blob(&blob.data, &key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Verify digest matches stored bytes.
        assert_eq!(blob.digest, compute_blob_digest(&blob.data));
    }

    // ── KeyResolver validation tests ──

    struct MockKeyResolver {
        key: Vec<u8>,
        fail_on_resolve: bool,
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

        fn validate_key_ref(&self, key_ref: &EncryptionKeyRef) -> SnapshotResult<()> {
            if key_ref.is_resolvable() && !self.fail_on_resolve {
                Ok(())
            } else {
                Err(SnapshotError::KeyUnavailable {
                    id: format!("{}:{}", key_ref.kms_id, key_ref.key_id),
                })
            }
        }
    }

    #[tokio::test]
    async fn key_resolver_resolves_valid_key() {
        let resolver = MockKeyResolver {
            key: make_test_key(),
            fail_on_resolve: false,
        };
        let key_ref = EncryptionKeyRef::new("aws-kms", "key-1");
        let key = resolver.resolve_key(&key_ref).await.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn key_resolver_fails_when_key_unavailable() {
        let resolver = MockKeyResolver {
            key: make_test_key(),
            fail_on_resolve: true,
        };
        let key_ref = EncryptionKeyRef::new("aws-kms", "key-1");
        let result = resolver.resolve_key(&key_ref).await;
        assert!(matches!(result, Err(SnapshotError::KeyUnavailable { .. })));
    }

    #[tokio::test]
    async fn key_resolver_validate_rejects_invalid_ref() {
        let resolver = MockKeyResolver {
            key: make_test_key(),
            fail_on_resolve: false,
        };
        let empty_ref = EncryptionKeyRef::new("", "");
        let result = resolver.validate_key_ref(&empty_ref);
        assert!(matches!(result, Err(SnapshotError::KeyUnavailable { .. })));
    }

    // ── Reject empty plaintext with valid padding ──

    #[test]
    fn empty_plaintext_round_trip() {
        let key = make_test_key();
        let plaintext = b"";
        let aad = build_aead_aad("blob-001", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(plaintext, &key, &aad).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + TAG_SIZE); // empty msg + tag
        let decrypted = decrypt_blob(&encrypted, &key, &aad).unwrap();
        assert!(decrypted.is_empty());
    }

    // ── Large blob (64 KiB) round-trip ──

    #[test]
    fn large_blob_round_trip() {
        let key = make_test_key();
        let plaintext = vec![0xAB; 64 * 1024]; // 64 KiB
        let aad = build_aead_aad("large-blob", "tnt_test", "snp_test", 1, "key-1");

        let encrypted = encrypt_blob(&plaintext, &key, &aad).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
        let decrypted = decrypt_blob(&encrypted, &key, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── AAD construction stability ──

    #[test]
    fn aad_construction_is_deterministic() {
        let aad1 = build_aead_aad("blob-1", "tnt_a", "snp_1", 5, "key-x");
        let aad2 = build_aead_aad("blob-1", "tnt_a", "snp_1", 5, "key-x");
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn aad_differs_for_different_bindings() {
        let aad1 = build_aead_aad("blob-1", "tnt_a", "snp_1", 5, "key-x");
        let aad2 = build_aead_aad("blob-1", "tnt_b", "snp_1", 5, "key-x"); // diff tenant
        assert_ne!(aad1, aad2);
    }
}
