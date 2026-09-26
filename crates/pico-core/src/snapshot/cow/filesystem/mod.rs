//! Filesystem-backed copy-on-write workspace engine.
//!
//! Provides a durable, content-addressable COW implementation that stores
//! workspace metadata, layer data, and lineage records on disk. Replaces
//! the in-memory [`CowEngine`](super::CowEngine) prototype.
//!
//! ## Architecture
//!
//! ```text
//! store_root/
//!   workspaces/<id>.json       CowWorkspace metadata (one file per workspace)
//!   lineages.json              All CowLineage records
//!   layers/<blob_ref>.json     CowLayer metadata (auxiliary; see below)
//!   data/<blob_ref>/           Content-addressed layer data directory
//!   gc.json                    Persistent reference counts for base layers
//!   layer_counter.json         Monotonic counter for unique layer IDs
//! ```
//!
//! ## Layer metadata files (`layers/<blob_ref>.json`)
//!
//! These files persist individual [`CowLayer`] metadata. They are
//! **auxiliary** to the workspace files: workspaces carry the
//! authoritative layer list in their `workspaces/<id>.json`. The
//! per-blob layer files are written for:
//!
//! 1. **External inspection**: tools and operators can query a layer's
//!    provenance, digest, and creation time without scanning all workspace
//!    manifests.
//! 2. **Future features**: cross-workspace layer sharing analysis,
//!    integrity audit trails, and blob-level restore orchestration.
//!
//! Layer metadata files are written by [`persist_layer_metadata`] during
//! workspace creation and fork. They are deleted when the corresponding
//! layer's ref count reaches zero and is swept by GC
//! ([`crate::snapshot::cow::filesystem::CowFilesystemEngine::delete_parent_workspace`]
//! and [`crate::snapshot::cow::filesystem::CowFilesystemEngine::sweep_released`]).
//! They are **not** loaded on [`CowFilesystemEngine::open`]; only workspace
//! files and lineages are loaded. This means orphaned layer metadata files
//! (with no corresponding workspace) are harmless dead data that the next
//! GC sweep will clean up.
//!
//! ## Key invariants
//!
//! 1. **Content addressing**: Layer data directories are keyed by Blake3 hash
//!    of their content. Two identical layers produce the same `blob_ref`,
//!    enabling automatic deduplication.
//!
//! 2. **Atomic layer commit**: Layer data is written to a temp directory first,
//!    then `rename(2)`d into place. The layer metadata is written *after* the
//!    data directory is committed. On crash, orphaned data directories have no
//!    corresponding metadata and are safely ignored.
//!
//! 3. **Integrity verification**: Each layer's data directory is hashed with
//!    Blake3 after commit. The resulting digest is stored in `CowLayer.digest`.
//!    On read, the digest is re-verified.
//!
//! 4. **Copy-on-write semantics**: A workspace resolves to a union view of its
//!    layers. Reads search layers top-to-bottom (overlay first, then base
//!    layers in reverse order). Writes go into the topmost overlay layer.
//!    Deletes create `.whiteout.<name>` marker files in the overlay.
//!
//! 5. **Garbage collection**: Reference counting tracks how many workspaces
//!    reference each base layer blob. A layer is eligible for deletion when
//!    its reference count reaches zero.

pub mod blob_locator;
pub mod blob_store;
pub mod gc;
#[cfg(test)]
mod tests;
pub mod union_fs;

use hashbrown::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::identity::{SandboxId, WorkspaceId};
use crate::snapshot::cow::{
    CowForkResult, CowLayer, CowLineage, CowWorkspace, CowWorkspaceManager, CowWorkspaceState,
    LayerKind, WorkspaceQuota,
};
use crate::snapshot::error::{SnapshotError, SnapshotResult};
use crate::types::now_iso;

use self::blob_store::BlobStore;
use self::gc::GcStore;
use self::union_fs::{UnionFilesystem, WorkspaceFile};

/// Filesystem-backed COW workspace engine.
///
/// Persists workspace metadata, layer data, and lineage records to disk.
/// Implements [`CowWorkspaceManager`] for drop-in compatibility with
/// [`ForkManager`](super::fork::ForkManager) and the cleanup module.
///
/// ## Thread safety
///
/// All public methods use internal synchronization (`parking_lot::RwLock`)
/// and are safe to call concurrently. Filesystem operations use atomic
/// `rename(2)` for crash safety.
///
/// ## Example
///
/// ```rust,ignore
/// use pico_core::snapshot::cow::filesystem::CowFilesystemEngine;
///
/// let engine = CowFilesystemEngine::open("/var/lib/pico/cow")?;
/// let root = engine.create_root_workspace(sandbox_id, 4096)?;
/// let child = engine.fork_workspace(&root.id, child_sandbox_id, 1024)?;
/// ```
#[derive(Debug)]
pub struct CowFilesystemEngine {
    /// Root directory for all storage.
    root: PathBuf,
    /// In-memory workspace cache, backed by disk.
    workspaces: RwLock<HashMap<WorkspaceId, CowWorkspace>>,
    /// Lineage records, backed by disk.
    lineages: RwLock<Vec<CowLineage>>,
    /// Monotonic counter for generating unique layer IDs.
    layer_counter: AtomicU64,
    /// Content-addressable blob store for layer data.
    blob_store: BlobStore,
    /// Persistent reference-count tracker for GC.
    gc: RwLock<GcStore>,
    /// Stateless union filesystem over workspace layer stacks.
    union_fs: UnionFilesystem,
}

impl CowFilesystemEngine {
    /// Opens or creates a COW filesystem store at the given root path.
    ///
    /// If the root directory does not exist, it is created along with
    /// all required subdirectories. Existing data is loaded from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the root path cannot be created, or if
    /// existing data on disk is corrupt.
    pub fn open(root: impl AsRef<Path>) -> SnapshotResult<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to create store root {}: {e}", root.display()),
        })?;

        let blob_store = BlobStore::new(root.join("data"));
        let gc = RwLock::new(GcStore::new(root.join("gc.json")));

        // Load existing workspaces from disk
        let workspaces_dir = root.join("workspaces");
        std::fs::create_dir_all(&workspaces_dir).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to create workspaces dir: {e}"),
        })?;

        let mut workspaces = HashMap::new();
        if workspaces_dir.exists() {
            for entry in std::fs::read_dir(&workspaces_dir).map_err(|e| {
                SnapshotError::OperationConflict {
                    reason: format!("failed to read workspaces dir: {e}"),
                }
            })? {
                let entry = entry.map_err(|e| SnapshotError::OperationConflict {
                    reason: format!("failed to read dir entry: {e}"),
                })?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json")
                    && let Ok(data) = std::fs::read_to_string(&path)
                    && let Ok(ws) = serde_json::from_str::<CowWorkspace>(&data)
                {
                    workspaces.insert(ws.id.clone(), ws);
                }
            }
        }

        // Load lineages from disk
        let lineages_path = root.join("lineages.json");
        let lineages: Vec<CowLineage> = if lineages_path.exists() {
            std::fs::read_to_string(&lineages_path)
                .ok()
                .and_then(|data| serde_json::from_str(&data).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Load layer counter
        let counter_path = root.join("layer_counter.json");
        let counter: u64 = if counter_path.exists() {
            std::fs::read_to_string(&counter_path)
                .ok()
                .and_then(|data| serde_json::from_str::<CounterFile>(&data).ok())
                .map(|c| c.counter)
                .unwrap_or(0)
        } else {
            // Seed from existing workspaces
            //
            // Robustness note: this parses `layer_id` suffixes assuming the
            // `layer_{wsp}_{num}` format. If the layer ID scheme evolves
            // (e.g., to Ulid-based or non-numeric suffixes), this fallback
            // path will return 0 and the counter will restart. This is safe
            // because the counter is only used for uniqueness within a
            // process lifetime; a restart from 0 won't collide with existing
            // layer IDs that use a different format. Still, prefer
            // `layer_counter.json` (which is persisted on every mutation)
            // as the authoritative source.
            workspaces
                .values()
                .flat_map(|ws| ws.layers.iter())
                .filter_map(|l| {
                    l.layer_id
                        .rsplit('_')
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                })
                .max()
                .map(|max| max + 1)
                .unwrap_or(0)
        };

        // Rebuild GC ref counts from existing workspaces only if GC file
        // is empty (crash recovery scenario). If gc.json has entries,
        // trust the persisted state.
        if gc.read().all_ref_counts().is_empty() {
            let mut gc_lock = gc.write();
            for ws in workspaces.values() {
                for layer in ws.layers_of_kind(LayerKind::Base) {
                    gc_lock.register_base_layer(layer);
                }
            }
        }

        // Load layer metadata from disk
        let layers_dir = root.join("layers");
        std::fs::create_dir_all(&layers_dir).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to create layers dir: {e}"),
        })?;

        let union_fs = UnionFilesystem::new(blob_store.clone());

        Ok(Self {
            root,
            workspaces: RwLock::new(workspaces),
            lineages: RwLock::new(lineages),
            layer_counter: AtomicU64::new(counter),
            blob_store,
            gc,
            union_fs,
        })
    }

    /// Returns the store root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persists workspace metadata to disk.
    fn persist_workspace(&self, ws: &CowWorkspace) -> SnapshotResult<()> {
        let dir = self.root.join("workspaces");
        std::fs::create_dir_all(&dir).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to create workspaces dir: {e}"),
        })?;
        let path = dir.join(format!("{}.json", ws.id.as_str()));
        let tmp = dir.join(format!("{}.tmp", ws.id.as_str()));
        let data =
            serde_json::to_string_pretty(ws).map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to serialize workspace: {e}"),
            })?;
        std::fs::write(&tmp, &data).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to write workspace temp: {e}"),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to commit workspace: {e}"),
        })?;
        Ok(())
    }

    /// Removes workspace metadata from disk.
    fn remove_workspace_file(&self, id: &WorkspaceId) -> SnapshotResult<()> {
        let path = self
            .root
            .join("workspaces")
            .join(format!("{}.json", id.as_str()));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to remove workspace file: {e}"),
            })?;
        }
        Ok(())
    }

    /// Persists lineage records to disk.
    fn persist_lineages(&self) -> SnapshotResult<()> {
        let path = self.root.join("lineages.json");
        let tmp = self.root.join("lineages.tmp");
        let lineages = self.lineages.read();
        let data = serde_json::to_string_pretty(&*lineages).map_err(|e| {
            SnapshotError::OperationConflict {
                reason: format!("failed to serialize lineages: {e}"),
            }
        })?;
        std::fs::write(&tmp, &data).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to write lineages temp: {e}"),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to commit lineages: {e}"),
        })?;
        Ok(())
    }

    /// Persists the layer counter to disk.
    fn persist_layer_counter(&self) -> SnapshotResult<()> {
        let path = self.root.join("layer_counter.json");
        let tmp = self.root.join("layer_counter.tmp");
        let counter = self.layer_counter.load(Ordering::Relaxed);
        let cf = CounterFile { counter };
        let data =
            serde_json::to_string_pretty(&cf).map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to serialize layer counter: {e}"),
            })?;
        std::fs::write(&tmp, &data).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to write counter temp: {e}"),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to commit counter: {e}"),
        })?;
        Ok(())
    }

    /// Persists a single layer's metadata to disk.
    fn persist_layer_metadata(&self, layer: &CowLayer) -> SnapshotResult<()> {
        let dir = self.root.join("layers");
        std::fs::create_dir_all(&dir).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to create layers dir: {e}"),
        })?;
        let path = dir.join(format!("{}.json", layer.blob_ref));
        let tmp = dir.join(format!("{}.tmp", layer.blob_ref));
        let data =
            serde_json::to_string_pretty(layer).map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to serialize layer: {e}"),
            })?;
        std::fs::write(&tmp, &data).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to write layer temp: {e}"),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| SnapshotError::OperationConflict {
            reason: format!("failed to commit layer metadata: {e}"),
        })?;
        Ok(())
    }

    /// Creates a new root workspace with a single base layer.
    ///
    /// The base layer's data directory is created empty. Writes to the
    /// workspace will populate the layer.
    pub fn create_root_workspace(
        &self,
        sandbox_id: SandboxId,
        base_layer_size_bytes: u64,
    ) -> SnapshotResult<CowWorkspace> {
        let id = WorkspaceId::generate();
        let blob_ref = format!("blob_root_{}", id.as_str());

        // Create the empty base layer data directory
        let data_dir = self.blob_store.data_dir(&blob_ref);
        self.blob_store.create_layer_dir(&blob_ref).map_err(|e| {
            SnapshotError::OperationConflict {
                reason: format!("failed to create base layer dir: {e}"),
            }
        })?;

        // Compute digest of the empty directory
        let digest = self.blob_store.compute_dir_digest(&data_dir)?;

        let now = now_iso();
        let base_layer = CowLayer {
            layer_id: format!("layer_{}_0", id.as_str()),
            kind: LayerKind::Base,
            blob_ref: blob_ref.clone(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: base_layer_size_bytes,
            digest: Some(digest),
            created_at: now.clone(),
        };

        let ws = CowWorkspace {
            id,
            sandbox_id,
            layers: vec![base_layer],
            parent_workspace_id: None,
            state: CowWorkspaceState::Active,
            created_at: now,
        };

        self.persist_workspace(&ws)?;

        // Register base layer in GC
        if let Some(base) = ws.layers.first() {
            self.gc.write().register_base_layer(base);
            self.persist_layer_metadata(base)?;
        }

        self.workspaces.write().insert(ws.id.clone(), ws.clone());
        self.persist_layer_counter()?;

        Ok(ws)
    }

    /// Forks an existing workspace, creating a child with shared base layers
    /// and a new independent writable overlay.
    ///
    /// The child inherits all parent base layers as shared immutable layers.
    /// A new empty writable overlay layer is appended for the child's
    /// exclusive writes.
    ///
    /// ## Atomicity
    ///
    /// The fork is atomic: if any step fails, no partial state is persisted.
    /// The child overlay layer data directory is created empty and committed
    /// via `rename(2)`.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::OperationConflict`] if the parent is not Active.
    /// Returns [`SnapshotError::SnapshotNotFound`] if the parent does not exist.
    pub fn fork_workspace(
        &self,
        parent_workspace_id: &WorkspaceId,
        child_sandbox_id: SandboxId,
        child_overlay_size_bytes: u64,
    ) -> SnapshotResult<CowForkResult> {
        let child_id = WorkspaceId::generate();
        let now = now_iso();

        // Phase 1: Read parent under read lock, release before I/O.
        let (base_layers, shared_layer_count, shared_bytes, overlay_index, top_base_blob) = {
            let guard = self.workspaces.read();
            let parent =
                guard
                    .get(parent_workspace_id)
                    .ok_or_else(|| SnapshotError::SnapshotNotFound {
                        id: parent_workspace_id.to_string(),
                    })?;

            if !parent.is_active() {
                return Err(SnapshotError::OperationConflict {
                    reason: format!(
                        "parent workspace {} is not active (state: {})",
                        parent.id.as_str(),
                        parent.state.as_str()
                    ),
                });
            }

            let base: Vec<CowLayer> = parent.layers_of_kind(LayerKind::Base).cloned().collect();
            let count = base.len();
            let bytes: u64 = base.iter().map(|l| l.size_bytes).sum();
            let index = count as u32;
            let top = base.last().map(|l| l.blob_ref.clone());
            (base, count, bytes, index, top)
        };

        // Phase 2: Clone base layers for GC registration, then build child.
        let base_for_gc = base_layers.clone();

        let overlay_blob_ref = format!("blob_overlay_{}", child_id.as_str());
        self.blob_store
            .create_layer_dir(&overlay_blob_ref)
            .map_err(|e| SnapshotError::OperationConflict {
                reason: format!("failed to create child overlay dir: {e}"),
            })?;

        let overlay_data_dir = self.blob_store.data_dir(&overlay_blob_ref);
        let overlay_digest = self.blob_store.compute_dir_digest(&overlay_data_dir)?;

        let layer_num = self.layer_counter.fetch_add(1, Ordering::Relaxed);
        let overlay = CowLayer {
            layer_id: format!("layer_{}_{}", child_id.as_str(), layer_num),
            kind: LayerKind::Overlay,
            blob_ref: overlay_blob_ref,
            layer_index: overlay_index,
            parent_blob_ref: top_base_blob,
            size_bytes: child_overlay_size_bytes,
            digest: Some(overlay_digest),
            created_at: now.clone(),
        };

        let mut child_layers = base_layers;
        child_layers.push(overlay);

        let child = CowWorkspace {
            id: child_id.clone(),
            sandbox_id: child_sandbox_id,
            layers: child_layers,
            parent_workspace_id: Some(parent_workspace_id.clone()),
            state: CowWorkspaceState::Active,
            created_at: now.clone(),
        };

        // Phase 3: Persist to disk (no workspace lock needed).
        self.persist_workspace(&child)?;
        if let Some(overlay) = child.layers.last() {
            self.persist_layer_metadata(overlay)?;
        }

        // Phase 4: Insert into in-memory map under write lock.
        {
            let mut guard = self.workspaces.write();
            // Re-validate parent still exists (frozen is harmless for an
            // existing child -- only new forks need the parent Active).
            if !guard.contains_key(parent_workspace_id) {
                return Err(SnapshotError::SnapshotNotFound {
                    id: parent_workspace_id.to_string(),
                });
            }
            guard.insert(child_id.clone(), child);
        }

        // Phase 5: Update GC ref counts and lineage records.
        {
            let mut gc_guard = self.gc.write();
            for layer in &base_for_gc {
                gc_guard.register_base_layer(layer);
            }
        }

        // Compute fork depth using the shared authoritative function.
        // Parent depth + 1 gives the child's depth in the fork chain.
        let fork_depth = super::workspace_fork_depth(self, parent_workspace_id) + 1;

        let lineage = CowLineage {
            parent_workspace_id: parent_workspace_id.clone(),
            child_workspace_id: child_id.clone(),
            shared_layer_count,
            fork_depth,
            created_at: now,
        };
        self.lineages.write().push(lineage);
        self.persist_lineages()?;
        self.persist_layer_counter()?;

        Ok(CowForkResult {
            parent_workspace_id: parent_workspace_id.clone(),
            child_workspace_id: child_id,
            shared_layer_count,
            shared_bytes,
        })
    }

    /// Gets a workspace by ID.
    pub fn get_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<CowWorkspace> {
        self.workspaces
            .read()
            .get(workspace_id)
            .cloned()
            .ok_or_else(|| SnapshotError::SnapshotNotFound {
                id: workspace_id.to_string(),
            })
    }

    /// Lists all workspaces for a sandbox.
    pub fn list_workspaces(&self, sandbox_id: &SandboxId) -> SnapshotResult<Vec<CowWorkspace>> {
        let guard = self.workspaces.read();
        Ok(guard
            .values()
            .filter(|ws| ws.sandbox_id == *sandbox_id)
            .cloned()
            .collect())
    }

    /// Lists all workspaces across all sandboxes.
    pub fn list_all_workspaces(&self) -> SnapshotResult<Vec<CowWorkspace>> {
        Ok(self.workspaces.read().values().cloned().collect())
    }

    /// Deletes a child workspace and its private overlay layers.
    ///
    /// Shared base layers are NOT removed; their reference counts are
    /// decremented in the GC tracker. The parent workspace is unaffected.
    pub fn delete_child_workspace(&self, child_workspace_id: &WorkspaceId) -> SnapshotResult<()> {
        let mut guard = self.workspaces.write();
        let child =
            guard
                .get(child_workspace_id)
                .ok_or_else(|| SnapshotError::SnapshotNotFound {
                    id: child_workspace_id.to_string(),
                })?;

        if child.is_root() {
            return Err(SnapshotError::OperationConflict {
                reason: format!(
                    "workspace {} is a root workspace, use delete_parent_workspace instead",
                    child_workspace_id.as_str()
                ),
            });
        }

        // Collect blob refs for overlay layers to delete
        let overlay_blobs: Vec<String> = child
            .layers_of_kind(LayerKind::Overlay)
            .map(|l| l.blob_ref.clone())
            .collect();

        // Deregister base layers from GC
        {
            let mut gc_guard = self.gc.write();
            for layer in child.layers_of_kind(LayerKind::Base) {
                gc_guard.deregister_base_layer(layer);
            }
        }

        // Delete overlay data directories
        for blob_ref in &overlay_blobs {
            let _ = self.blob_store.remove_layer_dir(blob_ref);
        }

        // Remove workspace from disk and memory
        self.remove_workspace_file(child_workspace_id)?;
        guard.remove(child_workspace_id);

        // Clean up lineage records
        self.lineages
            .write()
            .retain(|l| l.child_workspace_id != *child_workspace_id);
        self.persist_lineages()?;

        Ok(())
    }

    /// Deletes a parent workspace.
    ///
    /// Only succeeds if no active children reference this parent.
    /// Holds the workspace write lock from the start so the child
    /// check and deletion are atomic, preventing TOCTOU races with
    /// concurrent forks.
    pub fn delete_parent_workspace(&self, parent_workspace_id: &WorkspaceId) -> SnapshotResult<()> {
        let mut guard = self.workspaces.write();

        let parent =
            guard
                .get(parent_workspace_id)
                .ok_or_else(|| SnapshotError::SnapshotNotFound {
                    id: parent_workspace_id.to_string(),
                })?;

        // Check for active children while holding the write lock
        // to prevent TOCTOU races with concurrent forks.
        let lineage_guard = self.lineages.read();
        let active_children: Vec<WorkspaceId> = lineage_guard
            .iter()
            .filter(|l| l.parent_workspace_id == *parent_workspace_id)
            .filter_map(|l| {
                guard
                    .get(&l.child_workspace_id)
                    .map(|_| l.child_workspace_id.clone())
            })
            .collect();
        drop(lineage_guard);

        if !active_children.is_empty() {
            return Err(SnapshotError::OperationConflict {
                reason: format!(
                    "cannot delete parent workspace {}: {} active children exist (e.g., {})",
                    parent_workspace_id.as_str(),
                    active_children.len(),
                    active_children.first().map_or("unknown", |id| id.as_str())
                ),
            });
        }

        // Collect overlay blob refs
        let overlay_blobs: Vec<String> = parent
            .layers_of_kind(LayerKind::Overlay)
            .map(|l| l.blob_ref.clone())
            .collect();

        // Deregister base layers from GC
        {
            let mut gc_guard = self.gc.write();
            for layer in parent.layers_of_kind(LayerKind::Base) {
                gc_guard.deregister_base_layer(layer);
            }
        }

        // Delete overlay data directories
        for blob_ref in &overlay_blobs {
            let _ = self.blob_store.remove_layer_dir(blob_ref);
        }

        // Delete base layer data directories if ref count is zero
        {
            let gc_guard = self.gc.read();
            for layer in parent.layers_of_kind(LayerKind::Base) {
                if gc_guard
                    .get_ref_count(&layer.blob_ref)
                    .is_none_or(|c| c == 0)
                {
                    let _ = self.blob_store.remove_layer_dir(&layer.blob_ref);
                    let _ = std::fs::remove_file(
                        self.root
                            .join("layers")
                            .join(format!("{}.json", layer.blob_ref)),
                    );
                }
            }
        }

        self.remove_workspace_file(parent_workspace_id)?;
        guard.remove(parent_workspace_id);

        self.lineages
            .write()
            .retain(|l| l.parent_workspace_id != *parent_workspace_id);
        self.persist_lineages()?;

        Ok(())
    }

    /// Computes quota accounting for a workspace.
    pub fn compute_quota(&self, workspace_id: &WorkspaceId) -> SnapshotResult<WorkspaceQuota> {
        let ws = self.get_workspace(workspace_id)?;
        Ok(WorkspaceQuota::from_workspace(&ws))
    }

    /// Returns lineage records for all children of a parent workspace.
    pub fn get_children(&self, parent_id: &WorkspaceId) -> Vec<CowLineage> {
        self.lineages
            .read()
            .iter()
            .filter(|l| l.parent_workspace_id == *parent_id)
            .cloned()
            .collect()
    }

    /// Returns the parent workspace ID for a child, if it exists and is still present.
    pub fn get_parent(&self, child_id: &WorkspaceId) -> Option<WorkspaceId> {
        self.workspaces
            .read()
            .get(child_id)
            .and_then(|ws| ws.parent_workspace_id.clone())
    }

    /// Returns all lineage records.
    pub fn all_lineages(&self) -> Vec<CowLineage> {
        self.lineages.read().clone()
    }

    /// Returns the total number of workspaces stored.
    pub fn workspace_count(&self) -> usize {
        self.workspaces.read().len()
    }

    /// Returns the GC reference count for a blob reference.
    pub fn gc_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.gc.read().get_ref_count(blob_ref)
    }

    /// Returns the number of released layers (ref count = 0).
    pub fn released_layer_count(&self) -> usize {
        self.gc.read().released_layer_count()
    }

    /// Sweeps released layers from the GC tracker and deletes their data.
    ///
    /// Returns the blob references that were swept and removed from disk.
    pub fn sweep_released(&self) -> SnapshotResult<Vec<String>> {
        let swept = self.gc.write().sweep_released();
        for blob_ref in &swept {
            let _ = self.blob_store.remove_layer_dir(blob_ref);
            let _ =
                std::fs::remove_file(self.root.join("layers").join(format!("{}.json", blob_ref)));
        }
        Ok(swept)
    }

    // ── Workspace filesystem I/O ──
    //
    // These methods delegate to [`UnionFilesystem`] for the actual I/O
    // and handle workspace-level locking and metadata updates here.

    /// Resolves the filesystem path for a workspace's topmost layer.
    pub fn workspace_root(&self, workspace_id: &WorkspaceId) -> SnapshotResult<PathBuf> {
        let ws = self.get_workspace(workspace_id)?;
        self.union_fs.workspace_root(&ws.layers)
    }

    /// Reads a file from the workspace's union filesystem.
    pub fn read_file(
        &self,
        workspace_id: &WorkspaceId,
        relative_path: &str,
    ) -> SnapshotResult<Vec<u8>> {
        let ws = self.get_workspace(workspace_id)?;
        self.union_fs.read_file(&ws.layers, relative_path)
    }

    /// Writes a file to the workspace's topmost (overlay) layer.
    pub fn write_file(
        &self,
        workspace_id: &WorkspaceId,
        relative_path: &str,
        content: &[u8],
    ) -> SnapshotResult<()> {
        let layers = {
            let ws = self.get_workspace(workspace_id)?;
            ws.layers.clone()
        };
        let result = self.union_fs.write_file(&layers, relative_path, content)?;
        self.update_layer_digest(workspace_id, &result.top_blob_ref, &result.data_dir)?;
        Ok(())
    }

    /// Deletes a file from the workspace by placing a whiteout marker.
    pub fn delete_file(
        &self,
        workspace_id: &WorkspaceId,
        relative_path: &str,
    ) -> SnapshotResult<()> {
        let layers = {
            let ws = self.get_workspace(workspace_id)?;
            ws.layers.clone()
        };
        let result = self.union_fs.delete_file(&layers, relative_path)?;
        self.update_layer_digest(workspace_id, &result.top_blob_ref, &result.data_dir)?;
        Ok(())
    }

    /// Lists the contents of a directory in the workspace's union view.
    pub fn list_directory(
        &self,
        workspace_id: &WorkspaceId,
        relative_path: &str,
    ) -> SnapshotResult<Vec<WorkspaceFile>> {
        let ws = self.get_workspace(workspace_id)?;
        self.union_fs.list_directory(&ws.layers, relative_path)
    }

    /// Returns true if the file exists in the workspace (not whiteouted).
    pub fn file_exists(
        &self,
        workspace_id: &WorkspaceId,
        relative_path: &str,
    ) -> SnapshotResult<bool> {
        let ws = self.get_workspace(workspace_id)?;
        Ok(self.union_fs.file_exists(&ws.layers, relative_path))
    }

    /// Verifies the integrity of all layers in a workspace.
    pub fn verify_workspace_integrity(
        &self,
        workspace_id: &WorkspaceId,
    ) -> SnapshotResult<Vec<(String, String, String)>> {
        let ws = self.get_workspace(workspace_id)?;
        let mut mismatches = Vec::new();

        for layer in &ws.layers {
            let data_dir = self.blob_store.data_dir(&layer.blob_ref);
            let actual = self.blob_store.compute_dir_digest(&data_dir)?;
            if let Some(ref expected) = layer.digest
                && &actual != expected
            {
                mismatches.push((layer.blob_ref.clone(), expected.clone(), actual));
            }
        }

        Ok(mismatches)
    }

    /// Computes the layer digest and updates workspace metadata atomically.
    ///
    /// Holds the workspace write lock during digest computation to prevent
    /// TOCTOU races where concurrent writes could produce a stale digest
    /// that doesn't reflect all committed files on disk.
    ///
    /// The write lock duration is bounded by `compute_dir_digest`, which
    /// hashes all files in the layer directory. For typical overlay layers
    /// this is fast; for layers with many files, consider per-layer locking
    /// or incremental Merkle-tree digests.
    ///
    /// # Future optimization
    ///
    /// TODO: For large layers or write-heavy workloads, the full
    /// directory walk on every write can become a bottleneck. Options:
    /// - Content-only incremental hashing: maintain an `Accumulator` (e.g.,
    ///   `blake3::Hasher` or `BTreeMap<String, String>` of path→hash pairs)
    ///   per layer so writes only hash the new/modified file and recompute
    ///   the aggregate Merkle root in O(log n) instead of O(n).
    /// - Caching: store the per-file hash map alongside the layer metadata
    ///   (`layers/<blob_ref>.json` or a sibling `.hashes` file) and
    ///   invalidate only the changed paths.
    /// - Per-layer locking: replace the workspace-wide write lock with
    ///   finer-grained locks on individual layers so concurrent writes to
    ///   different layers don't contend.
    fn update_layer_digest(
        &self,
        workspace_id: &WorkspaceId,
        blob_ref: &str,
        data_dir: &Path,
    ) -> SnapshotResult<()> {
        let mut guard = self.workspaces.write();
        let new_digest = self.blob_store.compute_dir_digest(data_dir)?;
        let ws = guard
            .get_mut(workspace_id)
            .ok_or_else(|| SnapshotError::SnapshotNotFound {
                id: workspace_id.to_string(),
            })?;

        if let Some(layer) = ws.layers.iter_mut().find(|l| l.blob_ref == blob_ref) {
            layer.digest = Some(new_digest);
        }

        let ws_clone = ws.clone();
        drop(guard);
        self.persist_workspace(&ws_clone)?;
        Ok(())
    }
}

impl CowWorkspaceManager for CowFilesystemEngine {
    fn get_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<CowWorkspace> {
        self.get_workspace(workspace_id)
    }

    fn list_workspaces(&self, sandbox_id: &SandboxId) -> SnapshotResult<Vec<CowWorkspace>> {
        self.list_workspaces(sandbox_id)
    }

    fn list_all_workspaces(&self) -> SnapshotResult<Vec<CowWorkspace>> {
        self.list_all_workspaces()
    }

    fn store_workspace(&self, workspace: &CowWorkspace) -> SnapshotResult<()> {
        self.persist_workspace(workspace)?;
        self.workspaces
            .write()
            .insert(workspace.id.clone(), workspace.clone());
        Ok(())
    }

    fn delete_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<()> {
        let ws = self.get_workspace(workspace_id)?;
        if ws.is_root() {
            self.delete_parent_workspace(workspace_id)
        } else {
            self.delete_child_workspace(workspace_id)
        }
    }

    fn create_root_workspace(
        &self,
        sandbox_id: SandboxId,
        base_layer_size_bytes: u64,
    ) -> SnapshotResult<CowWorkspace> {
        self.create_root_workspace(sandbox_id, base_layer_size_bytes)
    }

    fn fork_workspace(
        &self,
        parent_workspace_id: &WorkspaceId,
        child_sandbox_id: SandboxId,
        child_overlay_size_bytes: u64,
    ) -> SnapshotResult<CowForkResult> {
        self.fork_workspace(
            parent_workspace_id,
            child_sandbox_id,
            child_overlay_size_bytes,
        )
    }

    fn get_children(&self, parent_id: &WorkspaceId) -> Vec<CowLineage> {
        self.get_children(parent_id)
    }

    fn get_parent(&self, child_id: &WorkspaceId) -> Option<WorkspaceId> {
        self.get_parent(child_id)
    }

    fn all_lineages(&self) -> Vec<CowLineage> {
        self.all_lineages()
    }

    fn workspace_count(&self) -> usize {
        self.workspace_count()
    }

    fn compute_quota(&self, workspace_id: &WorkspaceId) -> SnapshotResult<WorkspaceQuota> {
        self.compute_quota(workspace_id)
    }

    fn layer_data_dir(&self, blob_ref: &str) -> SnapshotResult<std::path::PathBuf> {
        Ok(self.blob_store.data_dir(blob_ref))
    }

    fn commit_layer_digest(
        &self,
        workspace_id: &WorkspaceId,
        blob_ref: &str,
    ) -> SnapshotResult<()> {
        let data_dir = self.blob_store.data_dir(blob_ref);
        self.update_layer_digest(workspace_id, blob_ref, &data_dir)
    }
}

/// Simple wrapper for persisting the layer counter.
#[derive(Debug, Serialize, Deserialize)]
struct CounterFile {
    counter: u64,
}
