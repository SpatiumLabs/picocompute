//! Snapshot integrity and encryption references.
//!
//! Integrity digests and encryption key references that must be verifiable
//! from metadata without loading snapshot blobs.

use serde::{Deserialize, Serialize};

/// Integrity digest reference for a snapshot.
///
/// Stored in metadata so compatibility checks can verify integrity without
/// loading snapshot blobs. The digest covers all metadata and blob references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityDigest {
    /// Hash algorithm used (e.g., "blake3", "sha256").
    pub algorithm: String,
    /// Hex-encoded digest value.
    pub value: String,
}

impl IntegrityDigest {
    /// Creates a new integrity digest.
    pub fn new(algorithm: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            value: value.into(),
        }
    }

    /// Returns true if this digest is using blake3.
    pub fn is_blake3(&self) -> bool {
        self.algorithm == "blake3"
    }
}

/// Encryption key reference for a snapshot.
///
/// Does not contain the key material itself. References the key management
/// system so that restore can verify key availability from metadata alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptionKeyRef {
    /// Key management service identifier.
    pub kms_id: String,
    /// Key identifier within the KMS.
    pub key_id: String,
    /// Key version or rotation identifier.
    #[serde(default)]
    pub key_version: Option<String>,
    /// Region where the key is stored (for latency-aware scheduling).
    #[serde(default)]
    pub region: Option<String>,
}

impl EncryptionKeyRef {
    /// Creates a new encryption key reference.
    pub fn new(kms_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            kms_id: kms_id.into(),
            key_id: key_id.into(),
            key_version: None,
            region: None,
        }
    }

    /// True if the key reference is populated enough to attempt a restore.
    pub fn is_resolvable(&self) -> bool {
        !self.kms_id.is_empty() && !self.key_id.is_empty()
    }
}

/// Combined integrity and encryption references for a snapshot.
///
/// Part of the snapshot metadata. Validated during compatibility
/// checks before blobs are loaded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotIntegrity {
    /// Integrity digest covering all snapshot metadata and blob references.
    pub metadata_digest: IntegrityDigest,
    /// Per-blob integrity digests, keyed by blob reference.
    #[serde(default)]
    pub blob_digests: Vec<BlobDigest>,
    /// Encryption key reference for tenant-bound encrypted blobs.
    #[serde(default)]
    pub encryption_key: Option<EncryptionKeyRef>,
    /// Whether the snapshot must pass integrity verification before restore.
    /// Always true for production; false only for development.
    pub integrity_required: bool,
}

/// Per-blob integrity digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobDigest {
    /// Blob reference (e.g., storage path or object key).
    pub blob_ref: String,
    /// Digest algorithm and value.
    pub digest: IntegrityDigest,
}

impl SnapshotIntegrity {
    /// Creates a new integrity record with a metadata digest.
    pub fn new(metadata_digest: IntegrityDigest) -> Self {
        Self {
            metadata_digest,
            blob_digests: Vec::new(),
            encryption_key: None,
            integrity_required: true,
        }
    }

    /// Returns true if all blobs have associated digests.
    pub fn all_blobs_covered(&self, blob_count: usize) -> bool {
        self.blob_digests.len() >= blob_count
    }

    /// Returns true if this snapshot requires an encryption key and one is present.
    pub fn encryption_satisfied(&self) -> bool {
        matches!(&self.encryption_key, Some(key) if key.is_resolvable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_digest_construction() {
        let d = IntegrityDigest::new("blake3", "abc123def456");
        assert_eq!(d.algorithm, "blake3");
        assert_eq!(d.value, "abc123def456");
        assert!(d.is_blake3());
    }

    #[test]
    fn integrity_digest_is_not_blake3() {
        let d = IntegrityDigest::new("sha256", "abc123");
        assert!(!d.is_blake3());
    }

    #[test]
    fn encryption_key_ref_is_resolvable() {
        let key = EncryptionKeyRef::new("aws-kms", "arn:aws:kms:...");
        assert!(key.is_resolvable());

        let empty = EncryptionKeyRef::new("", "");
        assert!(!empty.is_resolvable());
    }

    #[test]
    fn snapshot_integrity_all_blobs_covered() {
        let mut si = SnapshotIntegrity::new(IntegrityDigest::new("blake3", "meta"));
        assert!(si.all_blobs_covered(0));

        si.blob_digests.push(BlobDigest {
            blob_ref: "workspace.cow".into(),
            digest: IntegrityDigest::new("blake3", "ws123"),
        });
        assert!(si.all_blobs_covered(1));
        assert!(!si.all_blobs_covered(2));
    }

    #[test]
    fn snapshot_integrity_encryption_satisfied() {
        let mut si = SnapshotIntegrity::new(IntegrityDigest::new("blake3", "meta"));
        assert!(!si.encryption_satisfied());

        si.encryption_key = Some(EncryptionKeyRef::new("aws-kms", "key-123"));
        assert!(si.encryption_satisfied());
    }

    #[test]
    fn integrity_serde_roundtrip() {
        let si = SnapshotIntegrity {
            metadata_digest: IntegrityDigest::new("blake3", "abc123"),
            blob_digests: vec![BlobDigest {
                blob_ref: "mem.snapshot".into(),
                digest: IntegrityDigest::new("blake3", "def456"),
            }],
            encryption_key: Some(EncryptionKeyRef::new("aws-kms", "key-1")),
            integrity_required: true,
        };
        let json = serde_json::to_string(&si).unwrap();
        let back: SnapshotIntegrity = serde_json::from_str(&json).unwrap();
        assert_eq!(si, back);
    }
}
