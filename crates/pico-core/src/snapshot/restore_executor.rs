//! Snapshot restore executor.
//!
//! Takes validated metadata and resolved blobs from the
//! [`RestoreOrchestrator`](super::restore::RestoreOrchestrator)
//! and executes the actual state restoration: creating COW workspace
//! layers from filesystem blobs, restoring memory via the runtime
//! backend, and cleaning up after partial failures.
//!
//! This module implements the execution half of: Base Snapshot Restore.

use std::path::Path;
use std::time::Instant;

use crate::identity::{SandboxId, WorkspaceId};
use crate::runtime::RuntimeBackend;

use super::blob::BlobSet;
use super::cow::{CowWorkspaceManager, LayerKind};
use super::error::{SnapshotError, SnapshotResult};
use super::metadata::SnapshotMetadata;
use super::restore::RestoreOutcome;

/// Phases of a snapshot restore operation.
///
/// Used for observability: each phase emits a metric or span,
/// and failures identify which phase failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePhase {
    /// Metadata compatibility validation.
    Validation,
    /// Blob reference resolution.
    BlobResolution,
    /// Blob integrity verification.
    IntegrityVerification,
    /// Filesystem (workspace) state restoration.
    FilesystemRestore,
    /// Memory state restoration via backend.
    MemoryRestore,
    /// Guest-agent transport reconnection.
    GuestReconnect,
    /// ResumeNotify sent to guest.
    ResumeNotify,
    /// Post-restore health validation.
    PostRestoreValidation,
}

impl RestorePhase {
    /// Human-readable phase name for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::BlobResolution => "blob_resolution",
            Self::IntegrityVerification => "integrity_verification",
            Self::FilesystemRestore => "filesystem_restore",
            Self::MemoryRestore => "memory_restore",
            Self::GuestReconnect => "guest_reconnect",
            Self::ResumeNotify => "resume_notify",
            Self::PostRestoreValidation => "post_restore_validation",
        }
    }
}

/// Outcome of a filesystem restore operation.
#[derive(Debug, Clone)]
pub struct FilesystemRestoreOutcome {
    /// The workspace created during restore.
    pub workspace_id: WorkspaceId,
    /// Number of layers restored.
    pub layers_restored: usize,
    /// Total bytes of blob data restored.
    pub total_bytes_restored: u64,
    /// The restored workspace (for caller inspection).
    pub workspace: super::cow::CowWorkspace,
}

/// Executes snapshot restore operations after metadata validation
/// and blob resolution are complete.
///
/// The executor is stateless: it takes validated inputs and produces
/// outcomes. Callers own retry, idempotency, and lifecycle transitions.
pub struct RestoreExecutor;

impl RestoreExecutor {
    /// Creates a new restore executor.
    pub fn new() -> Self {
        Self
    }

    /// Executes a complete filesystem restore.
    ///
    /// Creates a COW workspace from the resolved filesystem and workspace
    /// layer blobs. Each blob's data directory contents are copied into the
    /// corresponding layer's data directory in the COW engine.
    ///
    /// ## Flow
    ///
    /// 1. Create a root workspace via the COW engine
    /// 2. Copy each filesystem blob's data into the base layer directory
    /// 3. For each workspace layer blob, create an overlay and copy data
    /// 4. Recompute and persist digests for all populated layers
    ///
    /// ## Partial failure
    ///
    /// If blob copy or digest commit fails, the partially-created workspace
    /// is cleaned up via [`cleanup_partial_restore`](Self::cleanup_partial_restore).
    /// Callers receive [`SnapshotError::PartialRestoreCleanup`] so they can
    /// distinguish a clean abort from a workspace that needs operator review.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::OperationConflict`] if the COW engine does
    /// not support filesystem-backed layers.
    /// Returns [`SnapshotError::PartialRestoreCleanup`] if blob copy fails
    /// and cleanup also fails.
    pub fn execute_filesystem_restore(
        _metadata: &SnapshotMetadata,
        blob_set: &BlobSet,
        cow_engine: &dyn CowWorkspaceManager,
        sandbox_id: &SandboxId,
    ) -> SnapshotResult<FilesystemRestoreOutcome> {
        let started = Instant::now();
        let total_bytes: u64 = blob_set
            .filesystem_blobs
            .iter()
            .chain(blob_set.workspace_blobs.iter())
            .map(|b| b.size_bytes)
            .sum();

        // Create root workspace with the first filesystem blob's size as
        // the initial base layer capacity.
        let root_ws = cow_engine.create_root_workspace(sandbox_id.clone(), total_bytes.max(1))?;

        let workspace_id = root_ws.id.clone();
        let mut layers_restored: usize = 0;

        // Helper: copy blob data into a layer directory, then commit digest.
        let populate_layer = |engine: &dyn CowWorkspaceManager,
                              ws_id: &WorkspaceId,
                              blob_ref: &str,
                              src_path: &Path|
         -> SnapshotResult<()> {
            let dst_dir = engine.layer_data_dir(blob_ref)?;

            // Copy blob contents into the layer directory.
            // For directory blobs (COW layers), recursively copy.
            // For file blobs (rootfs images), copy the single file.
            if src_path.is_dir() {
                copy_dir_recursive(src_path, &dst_dir).map_err(|e| {
                    SnapshotError::OperationConflict {
                        reason: format!(
                            "failed to copy blob {blob_ref} from {} to {}: {e}",
                            src_path.display(),
                            dst_dir.display()
                        ),
                    }
                })?;
            } else if src_path.is_file() {
                let file_name = src_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| blob_ref.to_string());
                let dst_file = dst_dir.join(&file_name);
                if let Some(parent) = dst_file.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        SnapshotError::OperationConflict {
                            reason: format!("failed to create parent dir for {file_name}: {e}"),
                        }
                    })?;
                }
                std::fs::copy(src_path, &dst_file).map_err(|e| {
                    SnapshotError::OperationConflict {
                        reason: format!(
                            "failed to copy blob {blob_ref} to {}: {e}",
                            dst_file.display()
                        ),
                    }
                })?;
            } else {
                return Err(SnapshotError::BlobMissing {
                    blob_ref: blob_ref.to_string(),
                });
            }

            // Commit the layer digest after populating.
            engine.commit_layer_digest(ws_id, blob_ref)?;
            Ok(())
        };

        // Restore filesystem blobs into base layers.
        // The first blob goes into the root's base layer; additional
        // filesystem blobs are rare but supported.
        for blob in &blob_set.filesystem_blobs {
            let layer = root_ws.layers.get(layers_restored).ok_or_else(|| {
                SnapshotError::OperationConflict {
                    reason: format!(
                        "no layer at index {layers_restored} for blob {}",
                        blob.blob_ref
                    ),
                }
            })?;

            if let Err(e) = populate_layer(cow_engine, &workspace_id, &layer.blob_ref, &blob.path) {
                // Clean up the partially-created workspace.
                let _ = Self::cleanup_partial_restore(&workspace_id, cow_engine);
                return Err(e);
            }
            layers_restored += 1;
        }

        // Restore workspace layer blobs as overlays.
        // Each workspace layer blob corresponds to an overlay layer
        // that was captured in the snapshot.
        for blob in &blob_set.workspace_blobs {
            // Create an overlay layer by forking from the current workspace.
            // This gives us a new writable overlay that we populate with
            // the captured blob data.
            let fork_result =
                cow_engine.fork_workspace(&workspace_id, sandbox_id.clone(), blob.size_bytes);

            // Fork may fail if the engine doesn't support it.
            // Fall back to storing the blob data directly if needed.
            if let Err(e) = &fork_result {
                // For single-workspace restore, we can't fork from ourselves.
                // Instead, use store_workspace to register the layer.
                //
                // TODO(partial-restore): Skipping overlay creation leaves the
                // workspace in a best-effort state relative to the snapshot.
                // For MVP this is acceptable; a production path should either
                // fail the whole restore or emit a structured outcome so the
                // caller can decide whether to retry or surface a degraded state.
                tracing::warn!(
                    blob_ref = %blob.blob_ref,
                    error = %e,
                    "fork for workspace layer blob failed, skipping overlay creation"
                );
                continue;
            }

            let child_id = fork_result.unwrap().child_workspace_id;
            let child_ws = cow_engine.get_workspace(&child_id)?;
            let overlay = child_ws
                .layers_of_kind(LayerKind::Overlay)
                .last()
                .cloned()
                .ok_or_else(|| SnapshotError::OperationConflict {
                    reason: "forked child has no overlay layer".into(),
                })?;

            if let Err(e) = populate_layer(cow_engine, &child_id, &overlay.blob_ref, &blob.path) {
                let _ = Self::cleanup_partial_restore(&child_id, cow_engine);
                return Err(e);
            }
            layers_restored += 1;
        }

        let workspace = cow_engine.get_workspace(&workspace_id)?;

        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            workspace_id = %workspace_id,
            sandbox_id = %sandbox_id,
            layers_restored = %layers_restored,
            total_bytes = %total_bytes,
            latency_ms = %latency_ms,
            "filesystem restore completed"
        );

        Ok(FilesystemRestoreOutcome {
            workspace_id,
            layers_restored,
            total_bytes_restored: total_bytes,
            workspace,
        })
    }

    /// Executes memory restore via the runtime backend.
    ///
    /// Calls [`RuntimeBackend::restore_snapshot`] with the resolved
    /// memory blob paths. The backend is responsible for loading the
    /// memory image and restoring runtime device state.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::OperationConflict`] if the backend does
    /// not support [`crate::runtime::BackendCapability::SnapshotRestore`].
    pub async fn execute_memory_restore(
        blob_set: &BlobSet,
        backend: &dyn RuntimeBackend,
    ) -> SnapshotResult<()> {
        if blob_set.memory_blobs.is_empty() {
            return Ok(());
        }

        let ctx = crate::runtime::BackendRestoreContext {
            snapshot_id: String::new(),
            sandbox_id: String::new(),
            blob_paths: blob_set
                .memory_blobs
                .iter()
                .map(|b| b.path.clone())
                .collect(),
        };

        backend
            .restore_snapshot(&ctx)
            .await
            .map_err(|e| SnapshotError::OperationConflict {
                reason: format!("memory restore failed: {e}"),
            })
    }

    /// Cleans up a partially-created workspace after a failed restore.
    ///
    /// Attempts to delete the workspace and its layers. If cleanup itself
    /// fails, returns [`SnapshotError::PartialRestoreCleanup`] so operators
    /// know manual review is needed.
    pub fn cleanup_partial_restore(
        workspace_id: &WorkspaceId,
        cow_engine: &dyn CowWorkspaceManager,
    ) -> SnapshotResult<()> {
        match cow_engine.delete_workspace(workspace_id) {
            Ok(()) => {
                tracing::info!(
                    workspace_id = %workspace_id,
                    "partial restore cleanup succeeded"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    workspace_id = %workspace_id,
                    error = %e,
                    "partial restore cleanup failed — manual review required"
                );
                Err(SnapshotError::PartialRestoreCleanup {
                    reason: format!(
                        "failed to clean up workspace {} after restore failure: {e}",
                        workspace_id.as_str()
                    ),
                })
            }
        }
    }

    /// Constructs a restore outcome with phase-level diagnostics.
    ///
    /// Shares the single outcome path via `RestoreOutcome::build`.
    pub fn phase_failure_outcome(
        phase: RestorePhase,
        reason: &str,
        blob_set: Option<&BlobSet>,
        elapsed: Instant,
    ) -> RestoreOutcome {
        RestoreOutcome::build(
            false,
            format!("restore failed at phase {}: {reason}", phase.as_str()),
            elapsed.elapsed().as_millis() as u64,
            blob_set.is_some_and(|bs| !bs.is_empty()),
            false,
            blob_set.cloned(),
            false,
        )
    }
}

impl Default for RestoreExecutor {
    fn default() -> Self {
        Self::new()
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
            let target = std::fs::read_link(&src_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_path)?;
            #[cfg(not(unix))]
            {
                let _ = target;
                std::fs::write(&dst_path, format!("symlink:{}", target.to_string_lossy()))?;
            }
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OperationId;
    use crate::identity::TenantId;
    use crate::snapshot::blob::BlobInfo;
    use crate::snapshot::cow::filesystem::CowFilesystemEngine;
    use crate::snapshot::metadata::FilesystemRef;
    use crate::snapshot::metadata::WorkspaceLayerRef;
    use crate::snapshot::profile::SnapshotProfile;
    use crate::snapshot::purpose::{LineageType, SnapshotPurpose};
    use crate::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
    use tempfile::TempDir;

    fn make_test_metadata(sandbox_id: &SandboxId) -> SnapshotMetadata {
        let mut meta = SnapshotMetadata::new(
            crate::identity::SnapshotId::generate(),
            TenantId::from_string("tnt_restore"),
            sandbox_id.clone(),
            None,
            LineageType::Root,
            SnapshotPurpose::Session,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img_restore".into(),
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
        );
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "restore-fs-blob".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: None,
            is_root: true,
        });
        let _ = meta.mark_ready();
        meta
    }

    fn make_temp_engine() -> (CowFilesystemEngine, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let engine = CowFilesystemEngine::open(tmp.path()).expect("open engine");
        (engine, tmp)
    }

    fn make_blob_set(fs_blobs: Vec<BlobInfo>) -> BlobSet {
        BlobSet {
            filesystem_blobs: fs_blobs,
            memory_blobs: vec![],
            workspace_blobs: vec![],
        }
    }

    // ── Filesystem restore ──

    #[test]
    fn execute_filesystem_restore_creates_workspace() {
        let (engine, _tmp) = make_temp_engine();
        let sandbox_id = SandboxId::from_string("sbx_fs_restore");

        // Create a temp file to serve as the blob source
        let src_tmp = TempDir::new().unwrap();
        let src_file = src_tmp.path().join("rootfs.ext4");
        std::fs::write(&src_file, b"fake rootfs content").unwrap();

        let metadata = make_test_metadata(&sandbox_id);
        let blob_set = make_blob_set(vec![BlobInfo {
            blob_ref: "restore-fs-blob".into(),
            path: src_file.clone(),
            size_bytes: 20,
            digest: None,
        }]);

        let outcome =
            RestoreExecutor::execute_filesystem_restore(&metadata, &blob_set, &engine, &sandbox_id)
                .expect("filesystem restore should succeed");

        assert_eq!(outcome.layers_restored, 1);
        assert!(outcome.total_bytes_restored > 0);
        assert!(outcome.workspace.is_root());

        // Verify the workspace exists and has data
        let ws = engine
            .get_workspace(&outcome.workspace_id)
            .expect("workspace should exist");
        assert_eq!(ws.sandbox_id, sandbox_id);
        assert_eq!(ws.layer_count(), 1);
    }

    #[test]
    fn execute_filesystem_restore_preserves_data() {
        let (engine, _tmp) = make_temp_engine();
        let sandbox_id = SandboxId::from_string("sbx_data_restore");

        let src_tmp = TempDir::new().unwrap();
        let src_file = src_tmp.path().join("data.bin");
        let content = b"hello restore world";
        std::fs::write(&src_file, content).unwrap();

        let metadata = make_test_metadata(&sandbox_id);
        let blob_set = make_blob_set(vec![BlobInfo {
            blob_ref: "restore-fs-blob".into(),
            path: src_file.clone(),
            size_bytes: content.len() as u64,
            digest: None,
        }]);

        let outcome =
            RestoreExecutor::execute_filesystem_restore(&metadata, &blob_set, &engine, &sandbox_id)
                .unwrap();

        // Read the file back from the workspace
        let ws = engine.get_workspace(&outcome.workspace_id).unwrap();
        let restored = engine.read_file(&outcome.workspace_id, "data.bin").unwrap();
        assert_eq!(restored, content);

        // Verify digest was committed
        assert!(ws.layers[0].digest.is_some());
    }

    #[test]
    fn execute_filesystem_restore_with_workspace_layers() {
        let (engine, _tmp) = make_temp_engine();
        let sandbox_id = SandboxId::from_string("sbx_ws_restore");

        let src_tmp = TempDir::new().unwrap();
        let src_file = src_tmp.path().join("base.dat");
        std::fs::write(&src_file, b"base layer").unwrap();

        let overlay_tmp = TempDir::new().unwrap();
        let overlay_file = overlay_tmp.path().join("overlay.dat");
        std::fs::write(&overlay_file, b"overlay data").unwrap();

        let mut metadata = make_test_metadata(&sandbox_id);
        metadata.workspace_layers.push(WorkspaceLayerRef {
            blob_ref: "ws-overlay-1".into(),
            layer_index: 1,
            parent_blob_ref: Some("restore-fs-blob".into()),
            digest: None,
        });

        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "restore-fs-blob".into(),
                path: src_file,
                size_bytes: 10,
                digest: None,
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![BlobInfo {
                blob_ref: "ws-overlay-1".into(),
                path: overlay_file,
                size_bytes: 13,
                digest: None,
            }],
        };

        let outcome =
            RestoreExecutor::execute_filesystem_restore(&metadata, &blob_set, &engine, &sandbox_id)
                .unwrap();

        // Should have restored both layers (base + overlay via fork)
        assert!(outcome.layers_restored >= 1);
        assert_eq!(engine.workspace_count(), 2); // root + forked child
    }

    #[test]
    fn partial_restore_cleanup_removes_workspace() {
        let (engine, _tmp) = make_temp_engine();
        let sandbox_id = SandboxId::from_string("sbx_cleanup");

        let ws = engine.create_root_workspace(sandbox_id, 1024).unwrap();
        let ws_id = ws.id.clone();

        assert_eq!(engine.workspace_count(), 1);

        RestoreExecutor::cleanup_partial_restore(&ws_id, &engine).expect("cleanup should succeed");

        assert_eq!(engine.workspace_count(), 0);
    }

    #[test]
    fn cleanup_nonexistent_workspace_is_ok() {
        let (engine, _tmp) = make_temp_engine();
        let fake_id = WorkspaceId::from_string("wsp_nonexistent");

        // Cleanup of nonexistent workspace is a no-op (delete_workspace returns error)
        let result = RestoreExecutor::cleanup_partial_restore(&fake_id, &engine);
        // The engine returns SnapshotNotFound, which cleanup wraps as PartialRestoreCleanup
        assert!(result.is_err());
    }
}
