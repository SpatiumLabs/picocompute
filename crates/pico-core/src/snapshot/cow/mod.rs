//! Copy-on-write workspace branching.
//!
//! Implements (prototype) and (production fork).
//! Parent and child workspaces share immutable base layers;
//! each receives an independent writable overlay after fork.
//! Quota accounting distinguishes shared (inherited) from private
//! (exclusive) data.
//!
//! ## Design
//!
//! A [`CowWorkspace`] is a stack of [`CowLayer`]s. Each layer is either
//! a `Base` (immutable, shared) or an `Overlay` (writable, private).
//! Forking a workspace creates a child that references the parent's
//! base layers and adds a new empty overlay.
//!
//! ## Backends
//!
//! Two engines implement [`CowWorkspaceManager`]:
//!
//! - [`CowEngine`] — In-memory engine for the prototype. Suitable
//!   for testing and single-process use.
//! - [`filesystem::CowFilesystemEngine`] — Durable, content-addressable
//!   engine backed by the local filesystem. Provides persistence, integrity
//!   verification, atomic layer commit, and garbage collection.
//!
//! ## Production fork
//!
//! The [`fork::ForkManager`] wraps a [`CowEngine`] to provide:
//! - Idempotent fork under retry (operation-keyed deduplication).
//! - Reference-counted GC-safe cleanup via [`cleanup::CowCleanupTracker`].
//! - Observability metrics via [`metrics::COW_FORK_METRICS`].
//! - Snapshot lineage integration.
//!
//! ## Async migration
//!
//! [`CowWorkspaceManager`] is intentionally synchronous in this prototype.
//! Sibling traits ([`super::repository::SnapshotRepository`],
//! [`super::blob::BlobLocator`]) use `#[async_trait]` for I/O-bound
//! backends. Production would need:
//! - Make `CowWorkspaceManager` async (`#[async_trait]` with `async fn`)
//! - Replace `parking_lot::RwLock` with `tokio::sync::RwLock` to avoid
//!   blocking the async runtime on lock acquisition
//! - Add `#[instrument]` tracing spans on lifecycle methods for
//!   distributed debugging
//!
//! ## Future work
//!
//! The filesystem engine (behind [`CowFilesystemEngine`]) provides:
//! - ✅ Content-addressable store (Blake3-hashed layer directories)
//! - ✅ Atomic layer commit (temp + rename)
//! - ✅ Integrity verification (digest on write, re-verify on read)
//! - ✅ Garbage collection (persistent ref-counted base layers, sweep)
//!
//! Remaining production requirements:
//! - Cross-host layer caching and lazy fetch
//! - Integration with overlayfs / btrfs snapshots for kernel-level COW
//! - Distributed garbage collection with cross-workspace reference counting

pub mod cleanup;
pub mod filesystem;
pub mod fork;
pub mod metrics;

use hashbrown::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::identity::{SandboxId, WorkspaceId};
use crate::types::now_iso;

use super::error::{SnapshotError, SnapshotResult};

/// Classification of a COW workspace layer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LayerKind {
    /// Immutable layer shared between parent and child workspaces.
    /// Base layers are never modified after creation.
    Base,
    /// Writable overlay layer private to a single workspace.
    /// All writes after fork go into the topmost overlay.
    Overlay,
}

impl LayerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Overlay => "overlay",
        }
    }
}

/// A single layer in a COW workspace stack.
///
/// Layers are ordered from bottom (index 0, oldest base) to top
/// (highest index, writable overlay).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CowLayer {
    /// Unique identifier for this layer.
    pub layer_id: String,
    /// Whether this is a base or overlay layer.
    pub kind: LayerKind,
    /// Blob reference for this layer's data.
    pub blob_ref: String,
    /// Position in the layer stack (0 = bottom).
    pub layer_index: u32,
    /// The layer below this one, if any.
    #[serde(default)]
    pub parent_blob_ref: Option<String>,
    /// Size of this layer in bytes.
    pub size_bytes: u64,
    /// Integrity digest for this layer.
    #[serde(default)]
    pub digest: Option<String>,
    /// When this layer was created (ISO 8601 UTC).
    pub created_at: String,
}

/// Lifecycle state of a COW workspace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CowWorkspaceState {
    /// Workspace is active and writable.
    Active,
    /// Workspace is frozen (no writes allowed; snapshot in progress).
    Frozen,
    /// Workspace is being deleted but layers may still be referenced.
    Deleting,
    /// Workspace and all its private layers have been deleted.
    Deleted,
}

impl CowWorkspaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        }
    }
}

/// A COW workspace representing the filesystem state of a sandbox.
///
/// A workspace is a stack of layers. Forks share base layers and
/// diverge via independent overlay layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowWorkspace {
    /// Unique workspace identifier.
    pub id: WorkspaceId,
    /// The sandbox this workspace belongs to.
    pub sandbox_id: SandboxId,
    /// Layers in this workspace, ordered bottom to top.
    pub layers: Vec<CowLayer>,
    /// Parent workspace ID (None for root workspaces).
    #[serde(default)]
    pub parent_workspace_id: Option<WorkspaceId>,
    /// Current lifecycle state.
    pub state: CowWorkspaceState,
    /// When this workspace was created (ISO 8601 UTC).
    pub created_at: String,
}

impl CowWorkspace {
    /// Creates a new root workspace with no parent.
    pub fn new_root(
        id: WorkspaceId,
        sandbox_id: SandboxId,
        base_layer_blob_ref: String,
        base_layer_size_bytes: u64,
    ) -> Self {
        let now = now_iso();
        let base_layer = CowLayer {
            layer_id: format!("layer_{}_0", id.as_str()),
            kind: LayerKind::Base,
            blob_ref: base_layer_blob_ref,
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: base_layer_size_bytes,
            digest: None,
            created_at: now.clone(),
        };
        Self {
            id,
            sandbox_id,
            layers: vec![base_layer],
            parent_workspace_id: None,
            state: CowWorkspaceState::Active,
            created_at: now,
        }
    }

    /// Returns an iterator over layers of the given [`LayerKind`].
    pub fn layers_of_kind(&self, kind: LayerKind) -> impl Iterator<Item = &CowLayer> + '_ {
        self.layers.iter().filter(move |l| l.kind == kind)
    }

    /// Returns the count of base (immutable) layers.
    pub fn base_layer_count(&self) -> usize {
        self.layers_of_kind(LayerKind::Base).count()
    }

    /// Returns the count of overlay (writable) layers.
    pub fn overlay_layer_count(&self) -> usize {
        self.layers_of_kind(LayerKind::Overlay).count()
    }

    /// Returns the total number of layers.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Returns true if this workspace is a root (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_workspace_id.is_none()
    }

    /// Returns true if this workspace is in Active state.
    pub fn is_active(&self) -> bool {
        self.state == CowWorkspaceState::Active
    }

    /// Returns the topmost layer (the writable overlay).
    pub fn top_layer(&self) -> Option<&CowLayer> {
        self.layers.last()
    }

    /// Total size of all layers in bytes.
    pub fn total_size_bytes(&self) -> u64 {
        self.layers.iter().map(|l| l.size_bytes).sum()
    }

    /// Size of shared (base) layers in bytes.
    pub fn shared_size_bytes(&self) -> u64 {
        self.layers_of_kind(LayerKind::Base)
            .map(|l| l.size_bytes)
            .sum()
    }

    /// Size of private (overlay) layers in bytes.
    pub fn private_size_bytes(&self) -> u64 {
        self.layers_of_kind(LayerKind::Overlay)
            .map(|l| l.size_bytes)
            .sum()
    }
}

/// Result of a workspace fork operation.
#[derive(Debug, Clone)]
pub struct CowForkResult {
    /// The parent workspace that was forked.
    pub parent_workspace_id: WorkspaceId,
    /// The newly created child workspace.
    pub child_workspace_id: WorkspaceId,
    /// Number of base layers shared between parent and child.
    pub shared_layer_count: usize,
    /// Size in bytes of the shared base layers.
    pub shared_bytes: u64,
}

/// Quota accounting for a workspace, separating shared from private data.
///
/// Shared bytes track immutable layers inherited from an ancestor.
/// Private bytes track overlay layers exclusive to this workspace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceQuota {
    /// Bytes in base layers shared with ancestors.
    pub shared_bytes: u64,
    /// Bytes in overlay layers private to this workspace.
    pub private_bytes: u64,
}

impl WorkspaceQuota {
    /// Total bytes consumed by this workspace.
    pub fn total_bytes(self) -> u64 {
        self.shared_bytes + self.private_bytes
    }

    /// Creates a new quota entry from a workspace.
    pub fn from_workspace(ws: &CowWorkspace) -> Self {
        Self {
            shared_bytes: ws.shared_size_bytes(),
            private_bytes: ws.private_size_bytes(),
        }
    }
}

/// A lineage relation describing how a child workspace descends from a parent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CowLineage {
    /// The parent workspace ID.
    pub parent_workspace_id: WorkspaceId,
    /// The child workspace ID.
    pub child_workspace_id: WorkspaceId,
    /// The number of base layers shared at fork time.
    pub shared_layer_count: usize,
    /// The fork depth of the child workspace (0 = root, 1 = first fork, etc.).
    ///
    /// Computed as `parent_fork_depth + 1`. Used to enforce `max_fork_depth`
    /// limits to prevent genealogical analysis of sandbox fleets.
    pub fork_depth: u32,
    /// When the fork occurred (ISO 8601 UTC).
    pub created_at: String,
}

/// Computes the fork depth of a workspace by walking the parent chain.
///
/// Root workspaces (no parent parent) return 0.
/// Children of root workspaces return 1, and so on.
///
/// This is the single authoritative depth computation used by both
/// the engine implementations and [`ForkManager`](fork::ForkManager).
/// All depth-sensitive code MUST use this function to ensure consistency.
///
/// # Safety limit
///
/// To guard against cycles in the parent chain, the walk stops after
/// [`MAX_COMPUTE_DEPTH`] iterations.
pub fn workspace_fork_depth(engine: &dyn CowWorkspaceManager, workspace_id: &WorkspaceId) -> u32 {
    const MAX_COMPUTE_DEPTH: u32 = 100;

    let mut depth = 0u32;
    let mut current = workspace_id.clone();

    while let Some(parent_id) = engine.get_parent(&current) {
        depth += 1;
        if depth > MAX_COMPUTE_DEPTH {
            // Cycle or excessively deep chain — return current depth.
            return depth;
        }
        current = parent_id;
    }

    depth
}

/// Manages COW workspace lifecycle operations.
///
/// Implementations may be in-memory (prototype) or backed by a
/// durable store (production).
///
/// ## Security note
///
/// The [`fork_workspace`](CowWorkspaceManager::fork_workspace) method does NOT
/// enforce fork depth limits. Depth is enforced only by
/// [`ForkManager`](fork::ForkManager). **All production fork paths MUST go
/// through `ForkManager`**. Callers using the engine directly bypass the
/// depth-limit security control.
///
/// This trait is intentionally **synchronous** for the prototype.
/// Production backends should use `#[async_trait]` with `async fn`
/// to support I/O-bound storage (see module-level async migration docs).
pub trait CowWorkspaceManager: Send + Sync {
    /// Gets a workspace by ID.
    ///
    /// # Errors
    ///
    /// Returns `SnapshotNotFound` if no workspace exists with the given ID.
    fn get_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<CowWorkspace>;

    /// Lists all workspaces for a sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store is unavailable.
    fn list_workspaces(&self, sandbox_id: &SandboxId) -> SnapshotResult<Vec<CowWorkspace>>;

    /// Lists all workspaces across all sandboxes.
    ///
    /// Used by cleanup to find children that may reside in
    /// different sandboxes than their parent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store is unavailable.
    fn list_all_workspaces(&self) -> SnapshotResult<Vec<CowWorkspace>>;

    /// Stores a workspace.
    ///
    /// # Errors
    ///
    /// Returns `SnapshotAlreadyExists` if a workspace with the same ID
    /// already exists. Returns an error if the underlying store is unavailable.
    fn store_workspace(&self, workspace: &CowWorkspace) -> SnapshotResult<()>;

    /// Deletes a workspace and its private layers.
    ///
    /// Shared base layers are not removed as long as other
    /// workspaces reference them.
    ///
    /// # Errors
    ///
    /// Returns `SnapshotNotFound` if the workspace does not exist.
    /// Returns `OperationConflict` if the workspace is a parent with
    /// active children (children must be deleted first).
    fn delete_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<()>;

    /// Creates a new root workspace with a single base layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store is unavailable.
    fn create_root_workspace(
        &self,
        sandbox_id: SandboxId,
        base_layer_size_bytes: u64,
    ) -> SnapshotResult<CowWorkspace>;

    /// Forks an existing workspace, creating a child with shared base layers
    /// and a new independent writable overlay.
    ///
    /// # Security
    ///
    /// This method does NOT enforce fork depth limits.
    /// Depth enforcement is the responsibility of
    /// [`ForkManager`](fork::ForkManager). Calling this method directly
    /// bypasses the depth-limit security control. **All production fork
    /// paths MUST go through `ForkManager`.**
    ///
    /// # Errors
    ///
    /// Returns `SnapshotNotFound` if the parent does not exist.
    /// Returns `OperationConflict` if the parent is not in Active state.
    fn fork_workspace(
        &self,
        parent_workspace_id: &WorkspaceId,
        child_sandbox_id: SandboxId,
        child_overlay_size_bytes: u64,
    ) -> SnapshotResult<CowForkResult>;

    /// Returns lineage records for all children of a parent workspace.
    fn get_children(&self, parent_id: &WorkspaceId) -> Vec<CowLineage>;

    /// Returns the parent workspace ID for a child, if it exists.
    fn get_parent(&self, child_id: &WorkspaceId) -> Option<WorkspaceId>;

    /// Returns all lineage records.
    fn all_lineages(&self) -> Vec<CowLineage>;

    /// Returns the total number of workspaces stored.
    fn workspace_count(&self) -> usize;

    /// Returns quota accounting (shared + private bytes) for a workspace.
    fn compute_quota(&self, workspace_id: &WorkspaceId) -> SnapshotResult<WorkspaceQuota>;

    /// Returns the filesystem path to a layer's data directory.
    ///
    /// Used by restore to populate layer data from resolved blobs.
    /// Implementations that are not filesystem-backed (e.g., in-memory
    /// engines) return [`SnapshotError::OperationConflict`].
    fn layer_data_dir(&self, _blob_ref: &str) -> SnapshotResult<PathBuf> {
        Err(SnapshotError::OperationConflict {
            reason: "layer_data_dir is not supported by this engine".into(),
        })
    }

    /// Recomputes and persists the integrity digest for a layer after
    /// its data has been modified externally (e.g., during restore).
    ///
    /// Implementations that are not filesystem-backed return
    /// [`SnapshotError::OperationConflict`].
    fn commit_layer_digest(
        &self,
        _workspace_id: &WorkspaceId,
        _blob_ref: &str,
    ) -> SnapshotResult<()> {
        Err(SnapshotError::OperationConflict {
            reason: "commit_layer_digest is not supported by this engine".into(),
        })
    }
}

/// In-memory COW workspace engine for the prototype.
///
/// Production would replace this with a durable store that supports
/// lazy layer resolution, content-addressable blob storage, and
/// cross-host garbage collection.
#[derive(Debug, Default)]
pub struct CowEngine {
    workspaces: RwLock<HashMap<WorkspaceId, CowWorkspace>>,
    lineages: RwLock<Vec<CowLineage>>,
    /// Counter for generating unique layer IDs.
    layer_counter: std::sync::atomic::AtomicU64,
}

impl CowEngine {
    /// Creates a new empty COW engine.
    pub fn new() -> Self {
        Self {
            workspaces: RwLock::new(HashMap::new()),
            lineages: RwLock::new(Vec::new()),
            layer_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Creates a new root workspace with a single base layer.
    pub fn create_root_workspace(
        &self,
        sandbox_id: SandboxId,
        base_layer_size_bytes: u64,
    ) -> SnapshotResult<CowWorkspace> {
        let id = WorkspaceId::generate();
        let blob_ref = format!("blob_root_{}", id.as_str());
        let ws = CowWorkspace::new_root(id.clone(), sandbox_id, blob_ref, base_layer_size_bytes);
        self.workspaces.write().insert(id, ws.clone());
        Ok(ws)
    }

    /// Forks an existing workspace, creating a child with shared base layers
    /// and a new independent writable overlay.
    ///
    /// # Behavior
    ///
    /// 1. The parent workspace must be in `Active` state.
    /// 2. All parent base layers become shared immutable layers in the child.
    /// 3. Parent overlay layers are NOT copied; the child gets its own empty overlay.
    /// 4. A [`CowLineage`] record is created linking parent and child.
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
        // Phase 1: Read parent under read lock, compute fork depth, and build
        // the child struct. The read lock is released before Phase 2 to avoid
        // write-lock reentrancy issues with parking_lot and to allow the depth
        // computation to use the shared `workspace_fork_depth` function.
        let (fork_depth, child_id, now, shared_layer_count, shared_bytes, child) = {
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

            let child_id = WorkspaceId::generate();
            let now = now_iso();

            let base_layers: Vec<CowLayer> =
                parent.layers_of_kind(LayerKind::Base).cloned().collect();
            let shared_layer_count = base_layers.len();
            let shared_bytes: u64 = base_layers.iter().map(|l| l.size_bytes).sum();

            let overlay_index = base_layers.len() as u32;
            let top_base_blob = base_layers.last().map(|l| l.blob_ref.clone());
            let mut child_layers = base_layers;
            child_layers.push(self.build_overlay_layer(
                &child_id,
                overlay_index,
                top_base_blob,
                child_overlay_size_bytes,
                &now,
            ));

            let child = CowWorkspace {
                id: child_id.clone(),
                sandbox_id: child_sandbox_id,
                layers: child_layers,
                parent_workspace_id: Some(parent_workspace_id.clone()),
                state: CowWorkspaceState::Active,
                created_at: now.clone(),
            };

            // Fork depth uses the shared authoritative function (no write lock
            // held, so no reentrancy issue).
            let fork_depth = workspace_fork_depth(self, parent_workspace_id) + 1;

            (
                fork_depth,
                child_id.clone(),
                now,
                shared_layer_count,
                shared_bytes,
                child,
            )
        };

        // Phase 2: Acquire write lock, re-validate parent, store child.
        {
            let mut guard = self.workspaces.write();
            // Re-validate parent still exists and is active (TOCTOU guard
            // against concurrent freeze/delete between Phase 1 and Phase 2).
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
            guard.insert(child_id.clone(), child);
        }

        // Phase 3: Record lineage (no workspace lock held).
        self.lineages.write().push(CowLineage {
            parent_workspace_id: parent_workspace_id.clone(),
            child_workspace_id: child_id.clone(),
            shared_layer_count,
            fork_depth,
            created_at: now,
        });

        Ok(CowForkResult {
            parent_workspace_id: parent_workspace_id.clone(),
            child_workspace_id: child_id,
            shared_layer_count,
            shared_bytes,
        })
    }

    /// Builds a writable overlay layer for a child workspace.
    fn build_overlay_layer(
        &self,
        child_id: &WorkspaceId,
        overlay_index: u32,
        parent_blob_ref: Option<String>,
        size_bytes: u64,
        now: &str,
    ) -> CowLayer {
        let layer_num = self
            .layer_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        CowLayer {
            layer_id: format!("layer_{}_{}", child_id.as_str(), layer_num),
            kind: LayerKind::Overlay,
            blob_ref: format!("blob_overlay_{}", child_id.as_str()),
            layer_index: overlay_index,
            parent_blob_ref,
            size_bytes,
            digest: None,
            created_at: now.to_string(),
        }
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
        let result: Vec<CowWorkspace> = guard
            .values()
            .filter(|ws| ws.sandbox_id == *sandbox_id)
            .cloned()
            .collect();
        Ok(result)
    }

    /// Lists all workspaces across all sandboxes.
    pub fn list_all_workspaces(&self) -> SnapshotResult<Vec<CowWorkspace>> {
        let guard = self.workspaces.read();
        Ok(guard.values().cloned().collect())
    }

    /// Deletes a child workspace without affecting the parent.
    ///
    /// Only removes the child's private (overlay) layers.
    /// Shared base layers persist because the parent still references them.
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
                    "workspace {} is a root workspace, use delete_workspace instead",
                    child_workspace_id.as_str()
                ),
            });
        }

        let parent_id = child.parent_workspace_id.clone();
        guard.remove(child_workspace_id);

        self.lineages
            .write()
            .retain(|l| l.child_workspace_id != *child_workspace_id);

        // Verify parent still exists and is healthy
        if let Some(ref pid) = parent_id
            && guard.get(pid).is_none()
        {
            // Parent already deleted -- that's acceptable
            tracing::warn!(
                child_id = %child_workspace_id,
                parent_id = %pid,
                "deleted child workspace whose parent was already removed"
            );
        }

        Ok(())
    }

    /// Deletes a parent workspace.
    ///
    /// Only succeeds if there are no active child workspaces.
    /// If children exist, they must be deleted first.
    pub fn delete_parent_workspace(&self, parent_workspace_id: &WorkspaceId) -> SnapshotResult<()> {
        let active_children: Vec<WorkspaceId> = {
            let guard = self.workspaces.read();
            let lineages = self.lineages.read();
            lineages
                .iter()
                .filter(|l| l.parent_workspace_id == *parent_workspace_id)
                .filter_map(|l| {
                    guard
                        .get(&l.child_workspace_id)
                        .map(|_| l.child_workspace_id.clone())
                })
                .collect()
        };

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

        self.lineages
            .write()
            .retain(|l| l.parent_workspace_id != *parent_workspace_id);

        self.workspaces.write().remove(parent_workspace_id);

        Ok(())
    }

    /// Returns the quota accounting for a workspace.
    pub fn compute_quota(&self, workspace_id: &WorkspaceId) -> SnapshotResult<WorkspaceQuota> {
        let ws = self.get_workspace(workspace_id)?;
        Ok(WorkspaceQuota::from_workspace(&ws))
    }

    /// Returns the lineage records for all forks from a parent workspace.
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
        let guard = self.workspaces.read();
        guard
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
}

impl CowWorkspaceManager for CowEngine {
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
}

#[cfg(test)]
mod tests;
