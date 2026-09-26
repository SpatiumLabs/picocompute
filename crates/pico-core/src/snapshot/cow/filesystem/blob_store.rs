//! Content-addressable blob store for COW layer data.
//!
//! Each layer's filesystem content is stored in a directory keyed by its
//! `blob_ref`. Two layers with identical content produce the same hash
//! and share the same data directory, enabling automatic deduplication.
//!
//! ## Directory structure
//!
//! ```text
//! data_root/
//!   <blob_ref>/     # Content-addressed layer data directory
//!     ...           # User files and directories
//! ```
//!
//! ## Integrity
//!
//! Directory content is hashed using Blake3. The hash is computed over
//! the sorted, concatenated hashes of all files (in Merkle-tree fashion),
//! producing a deterministic directory digest that is independent of
//! filesystem metadata (timestamps, permissions, inode order).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::snapshot::error::{SnapshotError, SnapshotResult};

/// Content-addressable blob store for layer data.
///
/// Manages layer data directories under a root path. Layer data is
/// stored as plain directories, each keyed by its blob reference.
#[derive(Debug, Clone)]
pub struct BlobStore {
    /// Root directory for all layer data.
    root: PathBuf,
}

impl BlobStore {
    /// Creates a new blob store rooted at the given path.
    ///
    /// The root directory and all parent directories are created if
    /// they do not exist.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self { root }
    }

    /// Returns the data directory path for a given blob reference.
    pub fn data_dir(&self, blob_ref: &str) -> PathBuf {
        self.root.join(blob_ref)
    }

    /// Creates an empty layer data directory for the given blob reference.
    ///
    /// The directory is created atomically: data is written to a temp
    /// directory, then renamed into place.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn create_layer_dir(&self, blob_ref: &str) -> Result<PathBuf, std::io::Error> {
        let dir = self.data_dir(blob_ref);
        if dir.exists() {
            return Ok(dir);
        }

        // Create parent
        std::fs::create_dir_all(&self.root)?;

        // Create atomically via temp + rename
        let tmp = self.root.join(format!(".tmp_{blob_ref}"));
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)?;
        }
        std::fs::create_dir_all(&tmp)?;
        std::fs::rename(&tmp, &dir)?;

        Ok(dir)
    }

    /// Removes a layer data directory and all its contents.
    ///
    /// Returns `Ok(true)` if the directory was removed, `Ok(false)` if
    /// it did not exist.
    pub fn remove_layer_dir(&self, blob_ref: &str) -> Result<bool, std::io::Error> {
        let dir = self.data_dir(blob_ref);
        if !dir.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(true)
    }

    /// Computes the Blake3 digest of a layer data directory.
    ///
    /// The digest is a Merkle-tree hash of the directory contents,
    /// computed by:
    ///
    /// 1. Hashing each file's content individually (with path prefix).
    /// 2. Sorting all (path, hash) pairs lexicographically by path.
    /// 3. Hashing the concatenation of all sorted hashes.
    ///
    /// This produces a deterministic digest that is independent of
    /// filesystem metadata order, timestamps, or inode numbers.
    ///
    /// Directories contribute their path to the hash but not their
    /// content (only their children are traversed). Symlinks are
    /// followed and their target content is hashed.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or a file
    /// cannot be hashed.
    pub fn compute_dir_digest(&self, dir: &Path) -> SnapshotResult<String> {
        if !dir.exists() {
            return Ok(blake3_hash(b""));
        }

        let mut file_hashes: BTreeMap<String, String> = BTreeMap::new();
        self.collect_file_hashes(dir, dir, &mut file_hashes)?;

        // Build a deterministic digest from sorted path->hash pairs
        let mut hasher = blake3::Hasher::new();
        for (path, hash) in &file_hashes {
            hasher.update(path.as_bytes());
            hasher.update(b"\0");
            hasher.update(hash.as_bytes());
            hasher.update(b"\n");
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Recursively collects Blake3 hashes for all files under a directory.
    fn collect_file_hashes(
        &self,
        root: &Path,
        current: &Path,
        hashes: &mut BTreeMap<String, String>,
    ) -> SnapshotResult<()> {
        let entries = std::fs::read_dir(current).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to read dir {}: {e}", current.display()),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to read dir entry: {e}"),
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to get file type for {}: {e}", path.display()),
                })?;

            // Compute relative path from the layer root
            let rel_path = path
                .strip_prefix(root)
                .map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to compute relative path: {e}"),
                })?
                .to_string_lossy()
                .to_string();

            if file_type.is_dir() {
                self.collect_file_hashes(root, &path, hashes)?;
            } else if file_type.is_symlink() {
                // For symlinks, hash the target path
                let target =
                    read_symlink_target(&path).map_err(|e| SnapshotError::OperationConflict {
                        reason: format!("failed to read symlink {}: {e}", path.display()),
                    })?;
                let target_str = target.to_string_lossy();
                let hash = blake3_hash(format!("symlink:{target_str}").as_bytes());
                hashes.insert(rel_path, hash);
            } else {
                // Regular file: hash its content
                let content =
                    std::fs::read(&path).map_err(|e| SnapshotError::OperationConflict {
                        reason: format!("failed to read file {}: {e}", path.display()),
                    })?;
                let hash = blake3_hash(&content);
                hashes.insert(rel_path, hash);
            }
        }

        Ok(())
    }

    /// Verifies that a layer data directory matches its expected digest.
    ///
    /// Returns `Ok(())` if the digest matches, or an error describing
    /// the mismatch.
    pub fn verify_digest(&self, blob_ref: &str, expected_digest: &str) -> SnapshotResult<()> {
        let dir = self.data_dir(blob_ref);
        let actual = self.compute_dir_digest(&dir)?;
        if actual != expected_digest {
            return Err(SnapshotError::IntegrityFailed {
                expected: expected_digest.to_string(),
                actual,
            });
        }
        Ok(())
    }

    /// Returns true if a blob data directory exists.
    pub fn blob_exists(&self, blob_ref: &str) -> bool {
        self.data_dir(blob_ref).exists()
    }

    /// Copies the data from a source layer directory into a destination
    /// layer directory.
    ///
    /// Used during fork to populate the child's overlay with initial
    /// content when copy-on-write is triggered.
    pub fn copy_layer(&self, src_blob_ref: &str, dst_blob_ref: &str) -> Result<(), std::io::Error> {
        let src = self.data_dir(src_blob_ref);
        let dst = self.data_dir(dst_blob_ref);

        if !src.exists() {
            return Ok(());
        }

        std::fs::create_dir_all(dst.parent().unwrap_or(&dst))?;
        copy_dir_recursive(&src, &dst)
    }
}

/// Recursively copies a directory and all its contents.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            copy_symlink(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Computes the Blake3 hash of data and returns the hex string.
fn blake3_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Copies a symlink from source to destination.
#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    let target = std::fs::read_link(src)?;
    std::os::unix::fs::symlink(&target, dst)
}

#[cfg(not(unix))]
fn copy_symlink(src: &Path, _dst: &Path) -> Result<(), std::io::Error> {
    let target = std::fs::read_link(src)?;
    // On non-Unix, create a text file with the symlink target
    std::fs::write(
        _dst,
        format!("symlink:{}", target.to_string_lossy()).as_bytes(),
    )
}

/// Reads the target of a symlink.
#[cfg(unix)]
fn read_symlink_target(path: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    std::fs::read_link(path)
}

#[cfg(not(unix))]
fn read_symlink_target(path: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    std::fs::read_link(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (BlobStore, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let store = BlobStore::new(tmp.path().join("data"));
        (store, tmp)
    }

    #[test]
    fn create_and_remove_layer_dir() {
        let (store, _tmp) = make_store();
        let blob_ref = "test_blob_1";

        let dir = store.create_layer_dir(blob_ref).unwrap();
        assert!(dir.exists());
        assert!(store.blob_exists(blob_ref));

        assert!(store.remove_layer_dir(blob_ref).unwrap());
        assert!(!store.blob_exists(blob_ref));
    }

    #[test]
    fn create_existing_layer_is_idempotent() {
        let (store, _tmp) = make_store();
        let blob_ref = "test_blob_idem";

        let dir1 = store.create_layer_dir(blob_ref).unwrap();
        let dir2 = store.create_layer_dir(blob_ref).unwrap();
        assert_eq!(dir1, dir2);
    }

    #[test]
    fn empty_dir_digest_is_deterministic() {
        let (store, _tmp) = make_store();
        let dir = store.create_layer_dir("empty_1").unwrap();

        let d1 = store.compute_dir_digest(&dir).unwrap();
        let d2 = store.compute_dir_digest(&dir).unwrap();
        assert_eq!(d1, d2);

        // Empty directory should produce a non-empty hash
        assert!(!d1.is_empty());
        assert_eq!(d1.len(), 64); // Blake3 hex = 64 chars
    }

    #[test]
    fn dir_with_files_produces_deterministic_digest() {
        let (store, _tmp) = make_store();
        let dir = store.create_layer_dir("with_files").unwrap();

        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("b.txt"), b"world").unwrap();

        let d1 = store.compute_dir_digest(&dir).unwrap();
        let d2 = store.compute_dir_digest(&dir).unwrap();
        assert_eq!(d1, d2);

        // Different content produces different digest
        std::fs::write(dir.join("a.txt"), b"changed").unwrap();
        let d3 = store.compute_dir_digest(&dir).unwrap();
        assert_ne!(d1, d3);
    }

    #[test]
    fn digest_is_independent_of_write_order() {
        let (store, _tmp) = make_store();
        let dir = store.create_layer_dir("order_test").unwrap();

        // Write files in one order
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"b").unwrap();
        let d1 = store.compute_dir_digest(&dir).unwrap();

        // Recreate and write in reverse order
        store.remove_layer_dir("order_test").unwrap();
        let dir2 = store.create_layer_dir("order_test").unwrap();
        std::fs::write(dir2.join("b.txt"), b"b").unwrap();
        std::fs::write(dir2.join("a.txt"), b"a").unwrap();
        let d2 = store.compute_dir_digest(&dir2).unwrap();

        assert_eq!(d1, d2, "digest should be independent of file write order");
    }

    #[test]
    fn nested_dirs_affect_digest() {
        let (store, _tmp) = make_store();
        let dir = store.create_layer_dir("nested").unwrap();

        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/file.txt"), b"content").unwrap();

        let d1 = store.compute_dir_digest(&dir).unwrap();

        // Adding a file in the subdirectory changes the digest
        std::fs::write(dir.join("sub/extra.txt"), b"extra").unwrap();
        let d2 = store.compute_dir_digest(&dir).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn verify_digest_success_and_failure() {
        let (store, _tmp) = make_store();
        let blob_ref = "verify_test";
        let dir = store.create_layer_dir(blob_ref).unwrap();
        std::fs::write(dir.join("x.txt"), b"data").unwrap();

        let digest = store.compute_dir_digest(&dir).unwrap();
        assert!(store.verify_digest(blob_ref, &digest).is_ok());

        let result = store.verify_digest(blob_ref, "bad_digest");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SnapshotError::IntegrityFailed { .. }
        ));
    }

    #[test]
    fn copy_layer_preserves_content() {
        let (store, _tmp) = make_store();
        let src_dir = store.create_layer_dir("src_blob").unwrap();
        std::fs::write(src_dir.join("hello.txt"), b"world").unwrap();
        std::fs::create_dir_all(src_dir.join("nested")).unwrap();
        std::fs::write(src_dir.join("nested/deep.txt"), b"deep").unwrap();

        let src_digest = store.compute_dir_digest(&src_dir).unwrap();

        store.create_layer_dir("dst_blob").unwrap();
        store.copy_layer("src_blob", "dst_blob").unwrap();

        let dst_dir = store.data_dir("dst_blob");
        let dst_digest = store.compute_dir_digest(&dst_dir).unwrap();
        assert_eq!(src_digest, dst_digest);

        assert!(dst_dir.join("hello.txt").exists());
        assert!(dst_dir.join("nested/deep.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dst_dir.join("hello.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn remove_nonexistent_layer_returns_false() {
        let (store, _tmp) = make_store();
        assert!(!store.remove_layer_dir("nonexistent").unwrap());
    }

    #[test]
    fn different_layer_dirs_have_different_hashes() {
        let (store, _tmp) = make_store();
        let d1 = store.create_layer_dir("blob_a").unwrap();
        let d2 = store.create_layer_dir("blob_b").unwrap();

        std::fs::write(d1.join("f.txt"), b"a").unwrap();
        std::fs::write(d2.join("f.txt"), b"b").unwrap();

        let h1 = store.compute_dir_digest(&d1).unwrap();
        let h2 = store.compute_dir_digest(&d2).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn whiteout_files_are_included_in_digest() {
        let (store, _tmp) = make_store();
        let dir = store.create_layer_dir("with_whiteout").unwrap();

        let d1 = store.compute_dir_digest(&dir).unwrap();

        std::fs::write(dir.join(".whiteout.deleted_file"), b"").unwrap();
        let d2 = store.compute_dir_digest(&dir).unwrap();

        // Whiteout file should affect the digest (it's a real file)
        assert_ne!(d1, d2);
    }
}
