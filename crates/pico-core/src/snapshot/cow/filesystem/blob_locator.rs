//! Blob locator backed by a COW filesystem engine's data directory.
//!
//! Resolves snapshot blob references to filesystem paths by looking up
//! layer data directories in the engine's content-addressed store.
//! Used by [`RestoreOrchestrator`](crate::snapshot::RestoreOrchestrator)
//! to locate blob data for integrity verification and restore execution.

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use crate::snapshot::blob::{BlobInfo, BlobLocator};
use crate::snapshot::error::{SnapshotError, SnapshotResult};

use super::blob_store::BlobStore;

/// Resolves blob references against a COW filesystem engine's data store.
///
/// Each blob reference maps to a directory under the engine's `data/` root.
/// The locator produces a [`BlobInfo`] with the resolved path, size, and
/// digest from the blob store.
///
/// ## Example
///
/// ```rust,ignore
/// use pico_core::snapshot::cow::filesystem::{CowBlobLocator, CowFilesystemEngine};
///
/// let engine = CowFilesystemEngine::open("/var/lib/pico/cow")?;
/// let locator = CowBlobLocator::new(engine.root().join("data"));
/// let info = locator.locate_blob("blob_root_wsp_abc").await?;
/// ```
#[derive(Debug, Clone)]
pub struct CowBlobLocator {
    /// Root directory for all layer data (engine's `data/` directory).
    data_root: PathBuf,
    /// The blob store for computing digests and sizes.
    blob_store: BlobStore,
}

impl CowBlobLocator {
    /// Creates a new blob locator rooted at the given data directory.
    ///
    /// The `data_root` should be the engine's `data/` directory, where
    /// each subdirectory is a content-addressed blob.
    pub fn new(data_root: impl AsRef<Path>) -> Self {
        let data_root = data_root.as_ref().to_path_buf();
        let blob_store = BlobStore::new(&data_root);
        Self {
            data_root,
            blob_store,
        }
    }

    /// Returns the data root path.
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// Computes the total size of a directory recursively.
    fn dir_size(dir: &Path) -> Result<u64, std::io::Error> {
        if !dir.exists() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                total += Self::dir_size(&path)?;
            } else if path.is_file() {
                total += entry.metadata()?.len();
            }
            // Symlinks contribute 0 to size
        }
        Ok(total)
    }

    /// Resolves a blob reference to a [`BlobInfo`] without failing when the
    /// blob data directory is empty. Returns `Ok(None)` when the blob exists
    /// but has no data yet.
    fn try_resolve(&self, blob_ref: &str) -> SnapshotResult<Option<BlobInfo>> {
        let dir = self.data_root.join(blob_ref);
        if !dir.exists() {
            return Ok(None);
        }

        let size_bytes = Self::dir_size(&dir).map_err(|e| SnapshotError::BlobStoreUnavailable {
            reason: format!("failed to read blob directory {}: {e}", dir.display()),
        })?;

        let digest = self.blob_store.compute_dir_digest(&dir).ok();

        Ok(Some(BlobInfo {
            blob_ref: blob_ref.to_string(),
            path: dir,
            size_bytes,
            digest,
        }))
    }
}

#[async_trait]
impl BlobLocator for CowBlobLocator {
    async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo> {
        match self.try_resolve(blob_ref)? {
            Some(info) => Ok(info),
            None => Err(SnapshotError::BlobMissing {
                blob_ref: blob_ref.to_string(),
            }),
        }
    }

    async fn locate_blobs(&self, blob_refs: &[String]) -> SnapshotResult<Vec<BlobInfo>> {
        let mut results = Vec::with_capacity(blob_refs.len());
        for blob_ref in blob_refs {
            match self.try_resolve(blob_ref)? {
                Some(info) => results.push(info),
                None => {
                    return Err(SnapshotError::BlobMissing {
                        blob_ref: blob_ref.to_string(),
                    });
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (CowBlobLocator, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let data_root = tmp.path().join("data");
        let locator = CowBlobLocator::new(&data_root);
        (locator, tmp)
    }

    #[tokio::test]
    async fn locate_missing_blob_returns_error() {
        let (locator, _tmp) = make_store();
        let result = locator.locate_blob("nonexistent_blob").await;
        assert!(
            matches!(result, Err(SnapshotError::BlobMissing { .. })),
            "expected BlobMissing, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn locate_blob_returns_info() {
        let (locator, _tmp) = make_store();
        let blob_ref = "test_blob_1";

        // Create the blob data directory with a file
        let dir = locator.data_root().join(blob_ref);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hello.txt"), b"hello world").unwrap();

        let info = locator.locate_blob(blob_ref).await.unwrap();
        assert_eq!(info.blob_ref, blob_ref);
        assert!(info.path.exists());
        assert!(info.size_bytes > 0);
        assert!(info.digest.is_some());
    }

    #[tokio::test]
    async fn locate_empty_blob_returns_info_with_zero_size() {
        let (locator, _tmp) = make_store();
        let blob_ref = "empty_blob";

        let dir = locator.data_root().join(blob_ref);
        std::fs::create_dir_all(&dir).unwrap();

        let info = locator.locate_blob(blob_ref).await.unwrap();
        assert_eq!(info.blob_ref, blob_ref);
        assert_eq!(info.size_bytes, 0);
        // Empty directory produces the empty-input hash
        assert_eq!(
            info.digest.as_deref(),
            Some(blake3::hash(b"").to_hex().to_string()).as_deref()
        );
    }

    #[tokio::test]
    async fn locate_blobs_batch_returns_all() {
        let (locator, _tmp) = make_store();

        for name in &["a", "b", "c"] {
            let dir = locator.data_root().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("data.txt"), format!("blob {name}")).unwrap();
        }

        let refs: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let infos = locator.locate_blobs(&refs).await.unwrap();
        assert_eq!(infos.len(), 3);
        assert_eq!(infos[0].blob_ref, "a");
        assert_eq!(infos[1].blob_ref, "b");
        assert_eq!(infos[2].blob_ref, "c");
    }

    #[tokio::test]
    async fn locate_blobs_fails_if_any_missing() {
        let (locator, _tmp) = make_store();

        // Only create "a"
        let dir = locator.data_root().join("a");
        std::fs::create_dir_all(&dir).unwrap();

        let refs: Vec<String> = ["a", "missing"].iter().map(|s| s.to_string()).collect();
        let result = locator.locate_blobs(&refs).await;
        assert!(
            matches!(result, Err(SnapshotError::BlobMissing { .. })),
            "expected BlobMissing, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn digest_is_stable_for_same_content() {
        let (locator, _tmp) = make_store();

        // Two blobs with identical content produce the same digest
        for name in &["blob_x", "blob_y"] {
            let dir = locator.data_root().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("f.txt"), b"identical content").unwrap();
        }

        let info_x = locator.locate_blob("blob_x").await.unwrap();
        let info_y = locator.locate_blob("blob_y").await.unwrap();

        assert_eq!(info_x.digest, info_y.digest);
        assert_ne!(info_x.blob_ref, info_y.blob_ref);
    }

    #[tokio::test]
    async fn different_content_produces_different_digest() {
        let (locator, _tmp) = make_store();

        let dir_a = locator.data_root().join("content_a");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::write(dir_a.join("data.txt"), b"alpha").unwrap();

        let dir_b = locator.data_root().join("content_b");
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(dir_b.join("data.txt"), b"beta").unwrap();

        let info_a = locator.locate_blob("content_a").await.unwrap();
        let info_b = locator.locate_blob("content_b").await.unwrap();

        assert_ne!(info_a.digest, info_b.digest);
    }
}
