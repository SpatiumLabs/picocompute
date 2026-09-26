//! Garbage-collection-safe cleanup for COW workspace layers.
//!
//! Ensures that:
//! - Shared base layers are not deleted while any workspace references them.
//! - Children must be deleted before their parent.
//! - Deleted lineages are cleaned up atomically with workspace removal.
//!
//! ## Reference counting
//!
//! Each base layer tracks how many workspaces reference it via [`LayerRefCount`].
//! A base layer is only eligible for deletion when its `ref_count` drops to zero.
//! Overlay (private) layers are always deleted when their owning workspace is deleted.

use hashbrown::HashMap;

use crate::identity::WorkspaceId;

use super::CowLayer;
use super::CowWorkspaceManager;
use super::LayerKind;
use super::WorkspaceQuota;
use crate::snapshot::error::{SnapshotError, SnapshotResult};

/// Tracks the reference count for a shared base layer.
///
/// Implementations may be in-memory ([`CowCleanupTracker`]) or persistent
/// ([`super::filesystem::gc::GcStore`]).
pub trait LayerRefTracker {
    /// Registers a base layer, incrementing its reference count.
    fn register_base_layer(&mut self, layer: &CowLayer);

    /// Deregisters a base layer, decrementing its reference count.
    /// Returns `true` if the layer has no remaining references.
    fn deregister_base_layer(&mut self, layer: &CowLayer) -> bool;

    /// Returns the current reference count for a layer blob reference.
    fn get_ref_count(&self, blob_ref: &str) -> Option<u32>;

    /// Returns all tracked layer reference counts.
    fn all_ref_counts(&self) -> Vec<&LayerRefCount>;

    /// Returns the number of released layers (ref_count = 0).
    fn released_layer_count(&self) -> usize;

    /// Removes all released layers and returns their blob references.
    fn sweep_released(&mut self) -> Vec<String>;
}

/// Tracks the reference count for a shared base layer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayerRefCount {
    /// Blob reference for the layer being tracked.
    pub blob_ref: String,
    /// Number of workspaces currently referencing this layer.
    pub ref_count: u32,
    /// Layer size in bytes.
    pub size_bytes: u64,
}

impl LayerRefCount {
    /// Creates a new reference count entry starting at 1.
    pub fn new(blob_ref: &str, size_bytes: u64) -> Self {
        Self {
            blob_ref: blob_ref.to_string(),
            ref_count: 1,
            size_bytes,
        }
    }

    /// Increments the reference count.
    pub fn inc(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count. Returns the new count.
    pub fn dec(&mut self) -> u32 {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count
    }

    /// Returns true if no workspaces still reference this layer and
    /// it can be safely deleted.
    pub fn is_released(&self) -> bool {
        self.ref_count == 0
    }
}

/// Coordinates garbage-collection-safe cleanup of COW workspaces.
///
/// Tracks reference counts for base layers so that shared data
/// is never deleted while any live workspace references it.
#[derive(Debug, Default)]
pub struct CowCleanupTracker {
    /// Reference counts for base layers, keyed by blob_ref.
    ref_counts: HashMap<String, LayerRefCount>,
}

impl CowCleanupTracker {
    /// Creates a new empty cleanup tracker.
    pub fn new() -> Self {
        Self {
            ref_counts: HashMap::new(),
        }
    }

    /// Registers a base layer and increments its reference count.
    ///
    /// Called when a new workspace is created that shares this base layer.
    pub fn register_base_layer(&mut self, layer: &CowLayer) {
        debug_assert_eq!(
            layer.kind,
            LayerKind::Base,
            "register_base_layer called on non-base layer"
        );
        match self.ref_counts.get_mut(&layer.blob_ref) {
            Some(rc) => rc.inc(),
            None => {
                self.ref_counts.insert(
                    layer.blob_ref.clone(),
                    LayerRefCount::new(&layer.blob_ref, layer.size_bytes),
                );
            }
        }
    }

    /// Deregisters a base layer and decrements its reference count.
    ///
    /// Called when a workspace that shared this base layer is deleted.
    /// Returns `true` if the layer has no remaining references and can
    /// be safely removed from storage.
    pub fn deregister_base_layer(&mut self, layer: &CowLayer) -> bool {
        debug_assert_eq!(
            layer.kind,
            LayerKind::Base,
            "deregister_base_layer called on non-base layer"
        );
        if let Some(rc) = self.ref_counts.get_mut(&layer.blob_ref) {
            rc.dec();
            rc.is_released()
        } else {
            false
        }
    }

    /// Returns the current reference count for a layer blob reference.
    pub fn get_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.ref_counts.get(blob_ref).map(|rc| rc.ref_count)
    }

    /// Returns all layer reference counts.
    pub fn all_ref_counts(&self) -> Vec<&LayerRefCount> {
        self.ref_counts.values().collect()
    }

    /// Returns the total number of released layers (ref_count = 0)
    /// that are eligible for final deletion.
    pub fn released_layer_count(&self) -> usize {
        self.ref_counts
            .values()
            .filter(|rc| rc.is_released())
            .count()
    }

    /// Removes all released layers from the tracker.
    ///
    /// Returns the blob references that were fully released.
    pub fn sweep_released(&mut self) -> Vec<String> {
        let released: Vec<String> = self
            .ref_counts
            .iter()
            .filter(|(_, rc)| rc.is_released())
            .map(|(blob_ref, _)| blob_ref.clone())
            .collect();
        for blob_ref in &released {
            self.ref_counts.remove(blob_ref);
        }
        released
    }
}

impl LayerRefTracker for CowCleanupTracker {
    fn register_base_layer(&mut self, layer: &CowLayer) {
        self.register_base_layer(layer);
    }

    fn deregister_base_layer(&mut self, layer: &CowLayer) -> bool {
        self.deregister_base_layer(layer)
    }

    fn get_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.get_ref_count(blob_ref)
    }

    fn all_ref_counts(&self) -> Vec<&LayerRefCount> {
        self.all_ref_counts()
    }

    fn released_layer_count(&self) -> usize {
        self.released_layer_count()
    }

    fn sweep_released(&mut self) -> Vec<String> {
        self.sweep_released()
    }
}

/// Safe cleanup of a child workspace.
///
/// Removes the child workspace and its private overlay layers.
/// Deregisters the child's base layers from the cleanup tracker
/// (their reference counts are decremented). The parent workspace
/// is unaffected.
pub fn clean_child_workspace(
    child_id: &WorkspaceId,
    manager: &dyn CowWorkspaceManager,
    tracker: &mut dyn LayerRefTracker,
) -> SnapshotResult<()> {
    let child = manager.get_workspace(child_id)?;

    if child.is_root() {
        return Err(SnapshotError::OperationConflict {
            reason: format!(
                "workspace {} is a root workspace, cannot clean as child",
                child_id.as_str()
            ),
        });
    }

    // Deregister all base layers from the cleanup tracker
    for layer in child.layers_of_kind(LayerKind::Base) {
        tracker.deregister_base_layer(layer);
    }

    manager.delete_workspace(child_id)
}

/// Safe cleanup of a parent workspace.
///
/// Only succeeds if no active children reference this parent.
/// If children exist, they must be deleted first (via [`clean_child_workspace`]).
/// The parent's base layers are only deregistered after all children
/// have been cleaned.
///
/// Children may reside in different sandboxes than the parent.
/// To catch all children regardless of sandbox, this method scans
/// *all* stored workspaces, not just the parent's sandbox.
///
/// ## Performance note
///
/// This method calls [`CowWorkspaceManager::list_all_workspaces`],
/// which may be expensive in production backends with many workspaces.
/// Production implementations should prefer an indexed lookup by
/// `parent_workspace_id` rather than a full scan.
pub fn clean_parent_workspace(
    parent_id: &WorkspaceId,
    manager: &dyn CowWorkspaceManager,
    tracker: &mut dyn LayerRefTracker,
) -> SnapshotResult<()> {
    let parent = manager.get_workspace(parent_id)?;

    // Check for active children across ALL sandboxes.
    // Children can be created in different sandboxes than the parent
    // via ForkRequest::child_sandbox_id.
    let all_workspaces = manager.list_all_workspaces()?;
    let active_children: Vec<&WorkspaceId> = all_workspaces
        .iter()
        .filter(|ws| ws.parent_workspace_id.as_ref() == Some(parent_id))
        .map(|ws| &ws.id)
        .collect();

    if !active_children.is_empty() {
        return Err(SnapshotError::OperationConflict {
            reason: format!(
                "cannot delete parent workspace {}: {} active children exist (e.g., {})",
                parent_id.as_str(),
                active_children.len(),
                active_children.first().map_or("unknown", |id| id.as_str())
            ),
        });
    }

    // Deregister base layers
    for layer in parent.layers_of_kind(LayerKind::Base) {
        tracker.deregister_base_layer(layer);
    }

    manager.delete_workspace(parent_id)
}

/// Aggregated quota across all workspaces in a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AggregateQuota {
    /// Total shared bytes across all workspaces.
    pub total_shared_bytes: u64,
    /// Total private bytes across all workspaces.
    pub total_private_bytes: u64,
}

impl AggregateQuota {
    /// Creates an aggregate quota from a map of workspace quotas.
    pub fn from_quotas(quotas: &HashMap<WorkspaceId, WorkspaceQuota>) -> Self {
        let mut total_shared = 0u64;
        let mut total_private = 0u64;
        for q in quotas.values() {
            total_shared = total_shared.saturating_add(q.shared_bytes);
            total_private = total_private.saturating_add(q.private_bytes);
        }
        Self {
            total_shared_bytes: total_shared,
            total_private_bytes: total_private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_ref_count_new_starts_at_one() {
        let rc = LayerRefCount::new("blob_01", 1024);
        assert_eq!(rc.ref_count, 1);
        assert_eq!(rc.size_bytes, 1024);
        assert!(!rc.is_released());
    }

    #[test]
    fn layer_ref_count_inc_and_dec() {
        let mut rc = LayerRefCount::new("blob_01", 1024);
        rc.inc();
        assert_eq!(rc.ref_count, 2);
        assert!(!rc.is_released());

        rc.dec();
        assert_eq!(rc.ref_count, 1);
        assert!(!rc.is_released());

        rc.dec();
        assert_eq!(rc.ref_count, 0);
        assert!(rc.is_released());
    }

    #[test]
    fn layer_ref_count_never_underflows() {
        let mut rc = LayerRefCount::new("blob_01", 1024);
        rc.dec(); // 1 -> 0
        rc.dec(); // 0 -> 0 (saturating)
        assert_eq!(rc.ref_count, 0);
    }

    #[test]
    fn tracker_registers_and_deregisters_layers() {
        let mut tracker = CowCleanupTracker::new();
        let layer = CowLayer {
            layer_id: "l1".into(),
            kind: LayerKind::Base,
            blob_ref: "base_blob_1".into(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: 2048,
            digest: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };

        tracker.register_base_layer(&layer);
        assert_eq!(tracker.get_ref_count("base_blob_1"), Some(1));

        tracker.deregister_base_layer(&layer);
        assert_eq!(tracker.get_ref_count("base_blob_1"), Some(0));
        assert_eq!(tracker.released_layer_count(), 1);
    }

    #[test]
    fn tracker_multiple_registrations() {
        let mut tracker = CowCleanupTracker::new();
        let layer = CowLayer {
            layer_id: "l1".into(),
            kind: LayerKind::Base,
            blob_ref: "shared_blob".into(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: 1024,
            digest: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };

        tracker.register_base_layer(&layer);
        tracker.register_base_layer(&layer);
        tracker.register_base_layer(&layer);
        assert_eq!(tracker.get_ref_count("shared_blob"), Some(3));

        tracker.deregister_base_layer(&layer);
        assert_eq!(tracker.get_ref_count("shared_blob"), Some(2));
        assert!(!tracker.deregister_base_layer(&layer)); // still has refs
        assert!(tracker.deregister_base_layer(&layer)); // now released
        assert_eq!(tracker.released_layer_count(), 1);
    }

    #[test]
    fn sweep_removes_released_layers() {
        let mut tracker = CowCleanupTracker::new();
        let layer = CowLayer {
            layer_id: "l1".into(),
            kind: LayerKind::Base,
            blob_ref: "to_sweep".into(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: 512,
            digest: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };

        tracker.register_base_layer(&layer);
        tracker.deregister_base_layer(&layer);
        assert_eq!(tracker.released_layer_count(), 1);

        let swept = tracker.sweep_released();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], "to_sweep");
        assert_eq!(tracker.released_layer_count(), 0);
        assert_eq!(tracker.get_ref_count("to_sweep"), None);
    }

    #[test]
    fn aggregate_quota_defaults_to_zero() {
        let agg = AggregateQuota::default();
        assert_eq!(agg.total_shared_bytes, 0);
        assert_eq!(agg.total_private_bytes, 0);
    }

    #[test]
    fn aggregate_quota_from_quotas() {
        use crate::identity::WorkspaceId;

        let mut quotas = HashMap::new();
        quotas.insert(
            WorkspaceId::from_string("wsp_a"),
            WorkspaceQuota {
                shared_bytes: 1000,
                private_bytes: 500,
            },
        );
        quotas.insert(
            WorkspaceId::from_string("wsp_b"),
            WorkspaceQuota {
                shared_bytes: 2000,
                private_bytes: 750,
            },
        );

        let agg = AggregateQuota::from_quotas(&quotas);
        assert_eq!(agg.total_shared_bytes, 3000);
        assert_eq!(agg.total_private_bytes, 1250);
    }

    #[test]
    fn layer_ref_count_serde_roundtrip() {
        let rc = LayerRefCount::new("blob_x", 4096);
        let json = serde_json::to_string(&rc).unwrap();
        let back: LayerRefCount = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
    }
}
