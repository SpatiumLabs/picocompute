//! Snapshot blob storage abstraction.
//!
//! Defines the interface for locating and resolving snapshot blob references
//! so that the restore path can retrieve filesystem and memory blobs without
//! coupling to a specific storage backend.

use async_trait::async_trait;

use super::error::SnapshotResult;

/// Resolved blob information returned by a [`BlobLocator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    /// The opaque blob reference used to locate this blob.
    pub blob_ref: String,
    /// Filesystem path where the blob can be read.
    pub path: std::path::PathBuf,
    /// Size of the blob in bytes.
    pub size_bytes: u64,
    /// Expected integrity digest, if any.
    pub digest: Option<String>,
}

/// A resolved set of blobs for a snapshot restore operation.
///
/// Produced by a [`BlobLocator`] after resolving all blob references
/// from a [`SnapshotMetadata`](super::metadata::SnapshotMetadata).
#[derive(Debug, Clone)]
pub struct BlobSet {
    /// Resolved filesystem blobs.
    pub filesystem_blobs: Vec<BlobInfo>,
    /// Resolved memory segment blobs.
    pub memory_blobs: Vec<BlobInfo>,
    /// Resolved workspace layer blobs.
    pub workspace_blobs: Vec<BlobInfo>,
}

impl BlobSet {
    /// Returns true if no blobs are present.
    pub fn is_empty(&self) -> bool {
        self.filesystem_blobs.is_empty()
            && self.memory_blobs.is_empty()
            && self.workspace_blobs.is_empty()
    }

    /// Total number of blobs in this set.
    pub fn len(&self) -> usize {
        self.filesystem_blobs.len() + self.memory_blobs.len() + self.workspace_blobs.len()
    }

    /// Returns the root filesystem blob, if present.
    pub fn root_fs_blob(&self) -> Option<&BlobInfo> {
        self.filesystem_blobs.first()
    }
}

/// Locates and resolves snapshot blob references to readable paths.
///
/// Implementations may retrieve blobs from local cache, object storage,
/// or a content-addressable store.
#[async_trait]
pub trait BlobLocator: Send + Sync {
    /// Resolves a single blob reference to a [`BlobInfo`].
    ///
    /// Returns `SnapshotNotFound` if the blob cannot be located.
    async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo>;

    /// Resolves multiple blob references concurrently.
    ///
    /// The default implementation resolves sequentially; backends should
    /// override with concurrent resolution when possible.
    async fn locate_blobs(&self, blob_refs: &[String]) -> SnapshotResult<Vec<BlobInfo>> {
        let mut results = Vec::with_capacity(blob_refs.len());
        for blob_ref in blob_refs {
            results.push(self.locate_blob(blob_ref).await?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_set_is_empty() {
        let set = BlobSet {
            filesystem_blobs: vec![],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn blob_set_len_counts_all_categories() {
        let set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "fs-1".into(),
                path: "/tmp/fs-1".into(),
                size_bytes: 100,
                digest: None,
            }],
            memory_blobs: vec![
                BlobInfo {
                    blob_ref: "mem-1".into(),
                    path: "/tmp/mem-1".into(),
                    size_bytes: 200,
                    digest: None,
                },
                BlobInfo {
                    blob_ref: "mem-2".into(),
                    path: "/tmp/mem-2".into(),
                    size_bytes: 300,
                    digest: None,
                },
            ],
            workspace_blobs: vec![],
        };
        assert!(!set.is_empty());
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn blob_info_equality() {
        let a = BlobInfo {
            blob_ref: "ref-1".into(),
            path: "/tmp/a".into(),
            size_bytes: 42,
            digest: Some("blake3:abc".into()),
        };
        let b = BlobInfo {
            blob_ref: "ref-1".into(),
            path: "/tmp/a".into(),
            size_bytes: 42,
            digest: Some("blake3:abc".into()),
        };
        assert_eq!(a, b);
    }
}
