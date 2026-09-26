//! Production filesystem COW fork.
//!
//! Implements: production filesystem fork for sandbox workspaces.
//! Builds on the prototype to provide:
//!
//! - Idempotent fork under retry (operation-keyed deduplication).
//! - Child workspace identity with quota accounting.
//! - Snapshot lineage integration via [`super::metadata::SnapshotMetadata`].
//! - Cleanup safety via reference-counted base layers.
//! - Observability via [`super::metrics::COW_FORK_METRICS`].
//!
//! ## Design
//!
//! [`ForkManager`] wraps a [`CowWorkspaceManager`] and a
//! [`crate::snapshot::repository::SnapshotRepository`] to coordinate
//! fork operations with snapshot metadata lineage recording.
//!
//! Fork idempotency is achieved through a [`ForkRequest`] with a
//! unique [`crate::identity::OperationId`] that serves as an
//! idempotency key. Retrying a fork with the same operation ID
//! returns the previously created child workspace (if any).

use hashbrown::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::identity::{OperationId, SandboxId, WorkspaceId};
use crate::snapshot::error::{SnapshotError, SnapshotResult};

use super::cleanup::CowCleanupTracker;
use pico_telemetry::metrics::{Labels, attr};

use super::metrics::COW_FORK_METRICS;
use super::{
    CowForkResult, CowLineage, CowWorkspace, CowWorkspaceManager, LayerKind, WorkspaceQuota,
};

/// Parameters for a workspace fork operation.
#[derive(Debug, Clone)]
pub struct ForkRequest {
    /// The parent workspace to fork from.
    pub parent_workspace_id: WorkspaceId,
    /// The sandbox that will own the child workspace.
    pub child_sandbox_id: SandboxId,
    /// Unique operation ID for idempotency.
    ///
    /// Retrying a fork with the same `operation_id` returns the
    /// previously created child workspace.
    pub operation_id: OperationId,
    /// Initial size in bytes for the child's writable overlay layer.
    /// The overlay grows as the child writes; this is the starting capacity.
    pub overlay_size_bytes: u64,
}

/// Outcome of a production fork operation.
///
/// Carries full workspace and lineage information so callers
/// can record the result in snapshot metadata.
#[derive(Debug, Clone)]
pub struct ForkOutcome {
    /// The result with parent/child workspace IDs and byte accounting.
    pub result: CowForkResult,
    /// The child workspace as it exists after fork.
    pub child_workspace: CowWorkspace,
    /// The parent workspace as it exists after fork (unchanged).
    pub parent_workspace: CowWorkspace,
    /// Lineage entry recording the fork relationship.
    pub lineage: CowLineage,
    /// Quota accounting for the child workspace.
    pub quota: WorkspaceQuota,
}

/// Manages production COW workspace fork operations.
///
/// Coordinates fork, cleanup, and quota accounting with:
/// - Idempotency via operation-keyed deduplication.
/// - Snapshot metadata lineage integration.
/// - Reference-counted GC-safe cleanup.
/// - Observability metrics.
///
/// The [`ForkManager`] is intentionally synchronous for in-process use.
/// Async backends (e.g., durable blob stores) should implement
/// [`CowWorkspaceManager`] with `#[async_trait]` and call this
/// manager from an async context.
///
/// ## Idempotency lifecycle
///
/// The idempotency registry is purely in-memory and covers retry
/// windows within a single [`ForkManager`] instance lifetime.
/// Process restart or multiple manager instances lose registered
/// keys. For cross-restart or distributed idempotency, persist
/// the mapping in the same backend as workspaces.
pub struct ForkManager {
    /// The underlying COW workspace engine (any [`CowWorkspaceManager`] impl).
    engine: Arc<dyn CowWorkspaceManager>,
    /// Tracks base layer reference counts for GC safety.
    cleanup_tracker: RwLock<CowCleanupTracker>,
    /// Maximum allowed fork depth (default: 10).
    ///
    /// Prevents genealogical analysis of sandbox fleets by limiting
    /// how deep a fork chain can grow. See SC-IMPL-08.
    max_fork_depth: u32,
    /// Maps idempotency keys (operation IDs) to child workspace IDs.
    ///
    /// `Some(id)` — the fork completed and the child workspace exists.
    /// `None` — the fork is in-progress; a concurrent caller holds
    ///   the reservation. Callers that encounter `None` should retry
    ///   after the in-progress fork completes, or treat it as a
    ///   transient conflict.
    ///
    /// The write lock is acquired before reading to avoid a TOCTOU
    /// race between the idempotency check and the reservation insert.
    idempotency_registry: RwLock<HashMap<OperationId, Option<WorkspaceId>>>,
}

impl ForkManager {
    /// Creates a new `ForkManager` backed by the given engine.
    ///
    /// `max_fork_depth` limits how deep a fork chain can grow.
    /// A value of 0 disables the check (use only in development).
    /// Default in production is 10 (see [`ForkManager::default_max_fork_depth`]).
    ///
    /// Accepts any [`CowWorkspaceManager`] implementation.
    pub fn new(engine: Arc<dyn CowWorkspaceManager>, max_fork_depth: u32) -> Self {
        Self {
            engine,
            cleanup_tracker: RwLock::new(CowCleanupTracker::new()),
            max_fork_depth,
            idempotency_registry: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the default maximum fork depth (10).
    pub const fn default_max_fork_depth() -> u32 {
        10
    }

    /// Creates a new `ForkManager` with the default maximum fork depth.
    ///
    /// Equivalent to `ForkManager::new(engine, ForkManager::default_max_fork_depth())`.
    /// Prefer this constructor in production code to avoid hard-coding the default
    /// in multiple places.
    pub fn new_with_default(engine: Arc<dyn CowWorkspaceManager>) -> Self {
        Self::new(engine, Self::default_max_fork_depth())
    }

    /// Creates a new root workspace with an initial base layer.
    ///
    /// Registers the base layer in the cleanup tracker for
    /// reference-counted GC safety.
    pub fn create_root_workspace(
        &self,
        sandbox_id: SandboxId,
        base_layer_size_bytes: u64,
    ) -> SnapshotResult<CowWorkspace> {
        let ws = self
            .engine
            .create_root_workspace(sandbox_id, base_layer_size_bytes)?;

        // Register base layers in the cleanup tracker
        let mut tracker = self.cleanup_tracker.write();
        for layer in ws.layers_of_kind(LayerKind::Base) {
            tracker.register_base_layer(layer);
        }

        Ok(ws)
    }

    /// Forks a workspace, creating a child with shared base layers
    /// and an independent writable overlay.
    ///
    /// # Idempotency
    ///
    /// If a fork with the same [`ForkRequest::operation_id`] has already
    /// succeeded, this method returns the existing child workspace
    /// instead of creating a new one. The operation is safe to retry.
    ///
    /// The idempotency check and reservation are performed atomically
    /// under a write lock to prevent concurrent callers with the same
    /// operation ID from both executing the fork (TOCTOU safety).
    ///
    /// Idempotency covers retry windows within a single [`ForkManager`]
    /// instance lifetime. Process restart or multiple manager instances
    /// lose registered keys.
    ///
    /// # Quota accounting
    ///
    /// The child's quota separates shared (inherited) bytes from
    /// private (overlay) bytes. Shared bytes track immutable base
    /// layers; private bytes track the child's writable overlay.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::OperationConflict`] if the parent is
    /// not in `Active` state, or if the parent workspace is frozen
    /// or deleted. Also returned if a concurrent call with the same
    /// operation ID is still in progress.
    ///
    /// Returns [`SnapshotError::SnapshotNotFound`] if the parent
    /// workspace does not exist.
    pub fn fork_workspace(&self, request: &ForkRequest) -> SnapshotResult<ForkOutcome> {
        COW_FORK_METRICS.fork_started.inc(&Labels::host());

        // ── Idempotency: atomically check-and-reserve ──
        // Acquire the write lock *before* the check to close the
        // TOCTOU window: two concurrent callers with the same
        // operation_id cannot both pass the check.
        {
            let mut registry = self.idempotency_registry.write();
            if let Some(entry) = registry.get(&request.operation_id) {
                match entry {
                    Some(existing_child_id) => {
                        // Fork already completed — return the existing child.
                        let child_id = existing_child_id.clone();
                        drop(registry);
                        return self.build_idempotent_outcome(request, &child_id);
                    }
                    None => {
                        // Fork is in-progress (reserved by another caller).
                        // The caller should retry after the in-progress
                        // fork completes.
                        return Err(SnapshotError::OperationConflict {
                            reason: format!(
                                "fork with operation_id {} is already in progress",
                                request.operation_id.as_str()
                            ),
                        });
                    }
                }
            }
            // Reserve the slot (None = in-progress) before releasing the lock.
            // This prevents any concurrent caller from also executing the fork.
            registry.insert(request.operation_id.clone(), None);
        }

        // ── Validate fork depth ──
        let parent_depth = self.compute_fork_depth(&request.parent_workspace_id)?;
        let child_depth = parent_depth + 1;

        if self.max_fork_depth > 0 && child_depth > self.max_fork_depth {
            // Remove the reservation since we're not executing the fork.
            self.idempotency_registry
                .write()
                .remove(&request.operation_id);

            COW_FORK_METRICS
                .fork_failed
                .inc(&Labels::host().with(attr::REASON, "fork_depth_exceeded"));
            return Err(SnapshotError::ForkDepthExceeded {
                max_depth: self.max_fork_depth,
                actual_depth: child_depth,
            });
        }

        // ── Execute the fork ──
        let engine_result = self.engine.fork_workspace(
            &request.parent_workspace_id,
            request.child_sandbox_id.clone(),
            request.overlay_size_bytes,
        );

        match engine_result {
            Ok(result) => {
                // Register child's base layers in the cleanup tracker
                let child = self.engine.get_workspace(&result.child_workspace_id)?;
                let mut tracker = self.cleanup_tracker.write();
                for layer in child.layers_of_kind(LayerKind::Base) {
                    tracker.register_base_layer(layer);
                }
                drop(tracker);

                let parent = self.engine.get_workspace(&request.parent_workspace_id)?;
                let lineage = self
                    .engine
                    .get_children(&request.parent_workspace_id)
                    .into_iter()
                    .find(|l| l.child_workspace_id == result.child_workspace_id)
                    .ok_or_else(|| SnapshotError::OperationConflict {
                        reason: "fork succeeded but lineage record not found".into(),
                    })?;
                let quota = WorkspaceQuota::from_workspace(&child);

                // Replace the reservation (None) with the real child ID
                self.idempotency_registry.write().insert(
                    request.operation_id.clone(),
                    Some(result.child_workspace_id.clone()),
                );

                // Emit shared/private byte metrics. Host-level gauges: the
                // result is a storage measurement, not a per-sandbox one.
                let labels = Labels::host();
                COW_FORK_METRICS
                    .shared_bytes
                    .set(result.shared_bytes as f64, &labels);
                COW_FORK_METRICS
                    .private_bytes
                    .set(child.private_size_bytes() as f64, &labels);
                COW_FORK_METRICS.fork_completed.inc(&labels);

                Ok(ForkOutcome {
                    result,
                    child_workspace: child,
                    parent_workspace: parent,
                    lineage,
                    quota,
                })
            }
            Err(e) => {
                // Remove the reservation so the caller can retry
                self.idempotency_registry
                    .write()
                    .remove(&request.operation_id);

                // Bounded by error variant rather than `Display`: the
                // rendered message embeds IDs and free-form reasons, which would
                // give the series unbounded cardinality.
                COW_FORK_METRICS
                    .fork_failed
                    .inc(&Labels::host().with(attr::REASON, SnapshotError::metric_reason(&e)));
                Err(e)
            }
        }
    }

    /// Builds a [`ForkOutcome`] for an already-completed fork (idempotent return path).
    fn build_idempotent_outcome(
        &self,
        request: &ForkRequest,
        child_id: &WorkspaceId,
    ) -> SnapshotResult<ForkOutcome> {
        let child = self.engine.get_workspace(child_id)?;
        let parent = self.engine.get_workspace(&request.parent_workspace_id)?;
        let shared_layer_count = child.base_layer_count();
        let shared_bytes = child.shared_size_bytes();
        let lineage = self
            .engine
            .get_children(&request.parent_workspace_id)
            .into_iter()
            .find(|l| l.child_workspace_id == *child_id)
            .ok_or_else(|| SnapshotError::OperationConflict {
                reason: format!(
                    "idempotent fork: child {} exists in registry but lineage record missing",
                    child_id.as_str()
                ),
            })?;

        let result = CowForkResult {
            parent_workspace_id: request.parent_workspace_id.clone(),
            child_workspace_id: child_id.clone(),
            shared_layer_count,
            shared_bytes,
        };
        let quota = WorkspaceQuota::from_workspace(&child);

        COW_FORK_METRICS.fork_completed.inc(&Labels::host());
        Ok(ForkOutcome {
            result,
            child_workspace: child,
            parent_workspace: parent,
            lineage,
            quota,
        })
    }

    /// Returns the quota accounting for a workspace.
    pub fn compute_quota(&self, workspace_id: &WorkspaceId) -> SnapshotResult<WorkspaceQuota> {
        self.engine.compute_quota(workspace_id)
    }

    /// Returns the aggregate quota for all workspaces in a sandbox.
    pub fn aggregate_quota(
        &self,
        sandbox_id: &SandboxId,
    ) -> SnapshotResult<super::cleanup::AggregateQuota> {
        let workspaces = self.engine.list_workspaces(sandbox_id)?;
        let mut total_shared = 0u64;
        let mut total_private = 0u64;
        for ws in &workspaces {
            let q = WorkspaceQuota::from_workspace(ws);
            total_shared = total_shared.saturating_add(q.shared_bytes);
            total_private = total_private.saturating_add(q.private_bytes);
        }
        Ok(super::cleanup::AggregateQuota {
            total_shared_bytes: total_shared,
            total_private_bytes: total_private,
        })
    }

    /// Safely cleans up a child workspace.
    ///
    /// Deregisters the child's base layers from the cleanup tracker.
    /// The child's private overlay layers are deleted.
    /// The parent workspace is unaffected.
    pub fn clean_child_workspace(&self, child_id: &WorkspaceId) -> SnapshotResult<()> {
        let mut tracker = self.cleanup_tracker.write();
        super::cleanup::clean_child_workspace(child_id, &*self.engine, &mut *tracker)
    }

    /// Safely cleans up a parent workspace.
    ///
    /// Only succeeds if no active children reference this parent.
    /// If children exist, they must be deleted first.
    pub fn clean_parent_workspace(&self, parent_id: &WorkspaceId) -> SnapshotResult<()> {
        let mut tracker = self.cleanup_tracker.write();
        super::cleanup::clean_parent_workspace(parent_id, &*self.engine, &mut *tracker)
    }

    /// Returns the lineage records for all forks from a parent workspace.
    pub fn get_children(&self, parent_id: &WorkspaceId) -> Vec<CowLineage> {
        self.engine.get_children(parent_id)
    }

    /// Returns the parent workspace ID for a child, if it exists.
    pub fn get_parent(&self, child_id: &WorkspaceId) -> Option<WorkspaceId> {
        self.engine.get_parent(child_id)
    }

    /// Returns all lineage records.
    pub fn all_lineages(&self) -> Vec<CowLineage> {
        self.engine.all_lineages()
    }

    /// Returns a workspace by ID.
    pub fn get_workspace(&self, workspace_id: &WorkspaceId) -> SnapshotResult<CowWorkspace> {
        self.engine.get_workspace(workspace_id)
    }

    /// Lists all workspaces for a sandbox.
    pub fn list_workspaces(&self, sandbox_id: &SandboxId) -> SnapshotResult<Vec<CowWorkspace>> {
        self.engine.list_workspaces(sandbox_id)
    }

    /// Returns the total number of workspaces stored.
    pub fn workspace_count(&self) -> usize {
        self.engine.workspace_count()
    }

    /// Returns the current cleanup tracker state (for testing).
    pub fn cleanup_tracker_ref_count(&self, blob_ref: &str) -> Option<u32> {
        self.cleanup_tracker.read().get_ref_count(blob_ref)
    }

    /// Returns the number of released layers (for testing).
    pub fn released_layer_count(&self) -> usize {
        self.cleanup_tracker.read().released_layer_count()
    }

    /// Sweeps released layers from the tracker (for testing).
    pub fn sweep_released(&self) -> Vec<String> {
        self.cleanup_tracker.write().sweep_released()
    }

    /// Returns the number of registered idempotency keys (including
    /// in-progress reservations).
    pub fn idempotency_key_count(&self) -> usize {
        self.idempotency_registry.read().len()
    }

    /// Removes an idempotency key (for testing scenarios).
    pub fn clear_idempotency_key(&self, operation_id: &OperationId) {
        self.idempotency_registry.write().remove(operation_id);
    }

    /// Returns true if a fork with the given operation ID is currently
    /// in progress (reserved but not yet completed).
    pub fn is_fork_in_progress(&self, operation_id: &OperationId) -> bool {
        self.idempotency_registry
            .read()
            .get(operation_id)
            .is_some_and(|entry| entry.is_none())
    }

    /// Returns the configured maximum fork depth.
    pub fn get_max_fork_depth(&self) -> u32 {
        self.max_fork_depth
    }

    /// Computes the fork depth of a workspace by walking the parent chain.
    ///
    /// Root workspaces (no parent) return 0.
    /// Children of root workspaces return 1, and so on.
    ///
    /// Delegates to the shared [`workspace_fork_depth`] function for
    /// a single consistent implementation across all call sites.
    fn compute_fork_depth(&self, workspace_id: &WorkspaceId) -> SnapshotResult<u32> {
        Ok(super::workspace_fork_depth(&*self.engine, workspace_id))
    }
}

#[cfg(test)]
mod tests;
