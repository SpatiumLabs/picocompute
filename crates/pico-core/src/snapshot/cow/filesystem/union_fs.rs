//! Union filesystem layer over COW workspace layer stacks.
//!
//! Performs filesystem I/O on a workspace's union view without coupling
//! to workspace lifecycle or metadata management. All methods operate on
//! a borrowed layer stack (`&[CowLayer]`) and a [`BlobStore`].
//!
//! ## Union semantics
//!
//! Reads search layers top-to-bottom (overlay first, then base layers
//! in reverse order). Writes go to the topmost writable overlay.
//! Deletes place `.whiteout.<name>` markers in the overlay to shadow
//! files in lower immutable layers.

use hashbrown::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::snapshot::cow::CowLayer;
use crate::snapshot::error::{SnapshotError, SnapshotResult};

use super::blob_store::BlobStore;

/// A whiteout marker indicating a deleted file.
const WHITEOUT_PREFIX: &str = ".whiteout.";

/// A file in the workspace union filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceFile {
    /// Relative path within the workspace.
    pub path: String,
    /// Whether this is a regular file, directory, or symlink.
    pub file_type: FileType,
    /// Size in bytes (0 for directories).
    pub size_bytes: u64,
    /// Blake3 digest of the file content (empty for directories).
    #[serde(default)]
    pub digest: Option<String>,
}

/// Type of a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

/// Result of a write operation on the union filesystem.
#[derive(Debug)]
pub struct WriteResult {
    /// The blob ref of the top layer where the write happened.
    pub top_blob_ref: String,
    /// The data directory of the top layer (for digest recomputation).
    pub data_dir: PathBuf,
}

/// Result of a delete operation on the union filesystem.
#[derive(Debug)]
pub struct DeleteResult {
    /// The blob ref of the top layer where the whiteout was placed.
    pub top_blob_ref: String,
    /// The data directory of the top layer (for digest recomputation).
    pub data_dir: PathBuf,
}

/// Stateless union filesystem over COW workspace layers.
///
/// All I/O methods take a `&[CowLayer]` directly so that callers
/// can resolve the layer stack from a workspace under their own
/// locking strategy.
#[derive(Debug)]
pub struct UnionFilesystem {
    /// Content-addressable blob store for layer data directories.
    blob_store: BlobStore,
}

impl UnionFilesystem {
    /// Creates a new union filesystem backed by the given blob store.
    pub fn new(blob_store: BlobStore) -> Self {
        Self { blob_store }
    }

    // ── Public API ──

    /// Resolves the filesystem path to the topmost (overlay) layer's data directory.
    pub fn workspace_root(&self, layers: &[CowLayer]) -> SnapshotResult<PathBuf> {
        let top = layers
            .last()
            .ok_or_else(|| SnapshotError::OperationConflict {
                reason: "workspace has no layers".into(),
            })?;
        Ok(self.blob_store.data_dir(&top.blob_ref))
    }

    /// Reads a file from the union filesystem by searching layers top-to-bottom.
    pub fn read_file(&self, layers: &[CowLayer], relative_path: &str) -> SnapshotResult<Vec<u8>> {
        self.read_file_from_layers(layers, relative_path)
    }

    /// Writes a file to the topmost (overlay) layer.
    ///
    /// Returns a [`WriteResult`] with the top layer's blob ref and data
    /// directory so the caller can recompute the integrity digest.
    pub fn write_file(
        &self,
        layers: &[CowLayer],
        relative_path: &str,
        content: &[u8],
    ) -> SnapshotResult<WriteResult> {
        let top = layers
            .last()
            .ok_or_else(|| SnapshotError::OperationConflict {
                reason: "workspace has no layers".into(),
            })?;
        let data_dir = self.blob_store.data_dir(&top.blob_ref);

        let file_path = data_dir.join(relative_path.trim_start_matches('/'));

        // Ensure parent directories exist
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to create parent dirs for {relative_path}: {e}"),
            })?;
        }

        // Remove any existing whiteout for this file
        if let Some(parent) = file_path.parent() {
            let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let whiteout_path = parent.join(format!("{WHITEOUT_PREFIX}{file_name}"));
            if whiteout_path.exists() {
                let _ = std::fs::remove_file(&whiteout_path);
            }
        }

        // Write atomically via temp file + rename
        let tmp = data_dir.join(format!(".tmp_{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, content).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to write temp file for {relative_path}: {e}"),
        })?;
        std::fs::rename(&tmp, &file_path).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to commit write for {relative_path}: {e}"),
        })?;

        Ok(WriteResult {
            top_blob_ref: top.blob_ref.clone(),
            data_dir,
        })
    }

    /// Deletes a file from the union filesystem by placing a whiteout
    /// marker in the topmost layer.
    ///
    /// Returns a [`DeleteResult`] with the top layer's blob ref and data
    /// directory so the caller can recompute the integrity digest.
    pub fn delete_file(
        &self,
        layers: &[CowLayer],
        relative_path: &str,
    ) -> SnapshotResult<DeleteResult> {
        let top = layers
            .last()
            .ok_or_else(|| SnapshotError::OperationConflict {
                reason: "workspace has no layers".into(),
            })?;
        let data_dir = self.blob_store.data_dir(&top.blob_ref);

        // Lower layers (all except the top)
        let lower: Vec<&CowLayer> = layers.iter().rev().skip(1).collect();

        let file_path = data_dir.join(relative_path.trim_start_matches('/'));

        // If the file exists in the top layer, remove it directly
        if file_path.exists() {
            if file_path.is_dir() {
                std::fs::remove_dir_all(&file_path).map_err(|e| {
                    SnapshotError::OperationConflict {
                        reason: format!("failed to remove directory {relative_path}: {e}"),
                    }
                })?;
            } else {
                std::fs::remove_file(&file_path).map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to remove file {relative_path}: {e}"),
                })?;
            }
        }

        // Check if the file exists in any lower layer
        if self.file_exists_in_layers(&lower, relative_path) {
            // Place a whiteout marker to shadow the lower-layer file
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to create whiteout parent for {relative_path}: {e}"),
                })?;
                let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let whiteout_path = parent.join(format!("{WHITEOUT_PREFIX}{file_name}"));
                std::fs::write(&whiteout_path, []).map_err(|e| {
                    SnapshotError::OperationConflict {
                        reason: format!("failed to write whiteout for {relative_path}: {e}"),
                    }
                })?;
            }
        }

        Ok(DeleteResult {
            top_blob_ref: top.blob_ref.clone(),
            data_dir,
        })
    }

    /// Lists the contents of a directory in the union view.
    ///
    /// Merges entries from all layers, with upper layers overriding
    /// lower layers. Whiteout entries are filtered out.
    pub fn list_directory(
        &self,
        layers: &[CowLayer],
        relative_path: &str,
    ) -> SnapshotResult<Vec<WorkspaceFile>> {
        let mut entries: HashMap<String, WorkspaceFile> = HashMap::new();
        let mut whiteouts: hashbrown::HashSet<String> = hashbrown::HashSet::new();

        // Process layers from bottom to top (upper layers override)
        for layer in layers {
            let data_dir = self.blob_store.data_dir(&layer.blob_ref);
            let dir_path = data_dir.join(relative_path.trim_start_matches('/'));
            if !dir_path.exists() || !dir_path.is_dir() {
                continue;
            }

            let dir_entries =
                std::fs::read_dir(&dir_path).map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to read directory {relative_path}: {e}"),
                })?;

            for entry in dir_entries {
                let entry = entry.map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to read dir entry: {e}"),
                })?;
                let name = entry.file_name().to_string_lossy().to_string();

                // Handle whiteout markers
                if let Some(stripped) = name.strip_prefix(WHITEOUT_PREFIX) {
                    whiteouts.insert(stripped.to_string());
                    continue;
                }

                // Skip entries that are whiteout markers
                if whiteouts.contains(&name) {
                    continue;
                }

                let file_type = if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                    FileType::Directory
                } else if entry.file_type().is_ok_and(|ft| ft.is_symlink()) {
                    FileType::Symlink
                } else {
                    FileType::File
                };

                let metadata = entry.metadata().ok();
                let size_bytes = metadata.map(|m| m.len()).unwrap_or(0);

                let rel_path = if relative_path == "/" || relative_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", relative_path.trim_end_matches('/'), name)
                };

                entries.insert(
                    name,
                    WorkspaceFile {
                        path: rel_path,
                        file_type,
                        size_bytes,
                        digest: None,
                    },
                );
            }
        }

        // Remove whiteout-shadowed entries
        for whiteout_name in &whiteouts {
            entries.remove(whiteout_name);
        }

        let mut result: Vec<WorkspaceFile> = entries.into_values().collect();
        result.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    /// Returns true if the file exists in the union view (not whiteouted).
    pub fn file_exists(&self, layers: &[CowLayer], relative_path: &str) -> bool {
        self.file_exists_in_all_layers(layers, relative_path)
    }

    // ── Internal helpers ──

    fn read_file_from_layers(
        &self,
        layers: &[CowLayer],
        relative_path: &str,
    ) -> SnapshotResult<Vec<u8>> {
        // Search top-to-bottom
        for layer in layers.iter().rev() {
            let data_dir = self.blob_store.data_dir(&layer.blob_ref);
            let file_path = data_dir.join(relative_path.trim_start_matches('/'));

            // Check for whiteout
            if let Some(parent) = file_path.parent()
                && let Some(name) = file_path.file_name().and_then(|n| n.to_str())
                && parent.join(format!("{WHITEOUT_PREFIX}{name}")).exists()
            {
                return Err(SnapshotError::SnapshotNotFound {
                    id: format!(
                        "file {relative_path} in workspace (whiteout in layer {})",
                        layer.blob_ref
                    ),
                });
            }

            if file_path.exists() && file_path.is_file() {
                return std::fs::read(&file_path).map_err(|e| SnapshotError::SnapshotNotFound {
                    id: format!("file {relative_path}: {e}"),
                });
            }
        }

        Err(SnapshotError::SnapshotNotFound {
            id: format!("file {relative_path} not found in any layer"),
        })
    }

    fn file_exists_in_layers(&self, layers: &[&CowLayer], relative_path: &str) -> bool {
        for layer in layers.iter().rev() {
            let data_dir = self.blob_store.data_dir(&layer.blob_ref);
            let file_path = data_dir.join(relative_path.trim_start_matches('/'));

            if let Some(parent) = file_path.parent()
                && let Some(name) = file_path.file_name().and_then(|n| n.to_str())
                && parent.join(format!("{WHITEOUT_PREFIX}{name}")).exists()
            {
                return false;
            }

            if file_path.exists() {
                return true;
            }
        }
        false
    }

    fn file_exists_in_all_layers(&self, layers: &[CowLayer], relative_path: &str) -> bool {
        for layer in layers.iter().rev() {
            let data_dir = self.blob_store.data_dir(&layer.blob_ref);
            let file_path = data_dir.join(relative_path.trim_start_matches('/'));

            if let Some(parent) = file_path.parent()
                && let Some(name) = file_path.file_name().and_then(|n| n.to_str())
                && parent.join(format!("{WHITEOUT_PREFIX}{name}")).exists()
            {
                return false;
            }

            if file_path.exists() {
                return true;
            }
        }
        false
    }
}
