//! Snapshot restore and fork execution for the supervisor.
//!
//! Implements the sandboxd-owned restore path sketched in
//! `docs/design/snapshot-restore-sandboxd-rpc.md`: ledger-fenced validation
//! from trusted metadata via `RestoreOrchestrator`, blob integrity plus
//! decryption, COW filesystem staging, backend memory restore when the
//! caller requires it, stale guest-session invalidation, and durable
//! outcome persistence.
//!
//! Phase 2 stages data and invalidates stale authority. Fresh authority
//! (guest handshake, DNS and network attach, lease and credential reissue,
//! `ResumeNotify`) is issued by the subsequent boot or resume through the
//! existing paths, which own those managers. Inline notify waits on guest
//! `resume-notify` support in the sandboxd guest client.

use std::sync::Arc;

use pico_core::{
    BackendRecord, BackendRestoreContext, BlobLocator, CowWorkspaceManager, CpuShape, DeviceModel,
    KeyResolver, MemoryShape, OperationId, RestoreContext, RestoreIntent, RestoreOrchestrator,
    RuntimeType, SandboxId, SandboxState, SnapshotId, SnapshotRepository, TenantId,
};

use super::{
    Execution, OperationKind, OutcomeReason, OutcomeStatus, SandboxSupervisor, SupervisorError,
    base_outcome, run_until_deadline,
};
use crate::CommandContext;
use crate::ledger::BeginOperation;

/// Snapshot restore stores injected into the supervisor.
///
/// `None` until installed; restore and fork fail closed while unconfigured.
/// Tests install in-memory doubles. Production wiring follows once the
/// snapshot store location decision in the design doc lands.
#[derive(Clone)]
pub struct SnapshotRestoreStores {
    /// Durable snapshot metadata.
    pub repository: Arc<dyn SnapshotRepository>,
    /// Blob reference resolution.
    pub blob_locator: Arc<dyn BlobLocator>,
    /// COW workspace engine for filesystem staging.
    pub cow_engine: Arc<dyn CowWorkspaceManager>,
    /// KMS key resolution for encrypted blobs. `None` means plaintext only.
    pub key_resolver: Option<Arc<dyn KeyResolver>>,
}

/// Validated restore command (built by `grpc::convert` from the wire).
///
/// Host evidence is the shared [`HostShape`] so `disk_mb` is added once.
#[derive(Debug, Clone)]
pub struct RestoreCommand {
    /// Snapshot to restore from.
    pub snapshot_id: String,
    /// Tenant requesting restore.
    pub request_tenant_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: RuntimeType,
    /// Shared host capability evidence.
    pub host: pico_sandboxd_proto::v1::HostShape,
}

/// Validated fork command (built by `grpc::convert` from the wire).
#[derive(Debug, Clone)]
pub struct ForkCommand {
    /// Parent snapshot to branch from. Must have fork purpose.
    pub parent_snapshot_id: String,
    /// Tenant requesting fork.
    pub request_tenant_id: String,
    /// Child sandbox identity. Receives an independent workspace.
    pub child_sandbox_id: String,
    /// True when caller needs memory profile.
    pub requires_memory: bool,
    /// Runtime family the host selected.
    pub runtime: RuntimeType,
    /// Shared host capability evidence, same shape as restore.
    pub host: pico_sandboxd_proto::v1::HostShape,
}

impl RestoreCommand {
    /// Builds a core `RestoreContext` from RPC fields plus ledger identity.
    fn to_restore_context(
        &self,
        sandbox_id: &SandboxId,
        operation_id: &OperationId,
        policy_epoch: u64,
    ) -> RestoreContext {
        build_restore_context(
            &self.snapshot_id,
            sandbox_id,
            operation_id,
            policy_epoch,
            &self.request_tenant_id,
            self.requires_memory,
            self.runtime,
            &self.host,
        )
    }
}

impl ForkCommand {
    /// Builds a core `RestoreContext` targeting the child sandbox.
    fn to_restore_context(
        &self,
        child_id: &SandboxId,
        operation_id: &OperationId,
        policy_epoch: u64,
    ) -> RestoreContext {
        build_restore_context(
            &self.parent_snapshot_id,
            child_id,
            operation_id,
            policy_epoch,
            &self.request_tenant_id,
            self.requires_memory,
            self.runtime,
            &self.host,
        )
    }
}

/// Single context builder shared by restore and fork.
///
/// Centralizes `RestoreContext` construction so staging does not rebuild
/// it from separate args and drift from core validation. Takes the shared
/// `HostShape` directly so new host fields propagate without touching
/// restore and fork call sites separately.
#[expect(
    clippy::too_many_arguments,
    reason = "context threads every restore dimension once; callers pass command structs plus identity"
)]
fn build_restore_context(
    snapshot_id: &str,
    sandbox_id: &SandboxId,
    operation_id: &OperationId,
    policy_epoch: u64,
    request_tenant_id: &str,
    requires_memory: bool,
    runtime: RuntimeType,
    host: &pico_sandboxd_proto::v1::HostShape,
) -> RestoreContext {
    RestoreContext {
        snapshot_id: SnapshotId::from_string(snapshot_id),
        sandbox_id: sandbox_id.clone(),
        operation_id: operation_id.clone(),
        host_backend: BackendRecord {
            backend_type: host.backend_type.clone(),
            backend_version: host.backend_version.clone(),
            protocol_version: host.protocol_version.clone(),
            guest_agent_version: None,
        },
        host_cpu: CpuShape::new(host.cpu_arch.clone()),
        host_memory: MemoryShape {
            memory_mb: u64::from(host.memory_mb),
            vcpus: host.vcpus,
        },
        host_device: DeviceModel::new(host.machine_type.clone()),
        host_runtime: runtime,
        requires_memory,
        request_tenant: TenantId::from_string(request_tenant_id),
        current_policy_epoch: policy_epoch,
        production_mode: true,
    }
}

/// Staged restore output shared by the restore and fork paths.
struct StagedRestore {
    /// Whether backend memory state was restored.
    memory_restored: bool,
    /// Number of filesystem layers staged.
    layers_staged: usize,
}

impl SandboxSupervisor {
    /// Installs snapshot restore stores (repository, locator, COW, KMS).
    #[must_use]
    pub fn with_snapshot_stores(self, stores: SnapshotRestoreStores) -> Self {
        *self.snapshot_stores.write() = Some(stores);
        self
    }

    /// Restores sandbox state from a snapshot and persists the outcome.
    ///
    /// The target must be prepared (a runtime handle attached). Filesystem
    /// staging leaves the sandbox in `Preparing` for a subsequent boot,
    /// which issues fresh authority. Memory restore leaves it `Suspended`
    /// for a subsequent resume. Validation failures are `Failed` outcomes
    /// with `RestoreRejected`, not RPC errors.
    ///
    /// # Errors
    ///
    /// Returns an error for missing stores, missing runtime handle, stale
    /// fencing or policy epoch, ledger access, or deadline handling. Data
    /// plane rejections are outcomes.
    pub async fn restore(
        &self,
        context: CommandContext,
        cmd: RestoreCommand,
    ) -> Result<super::OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let stores = self.snapshot_stores.read().clone().ok_or_else(|| {
            SupervisorError::SnapshotRestore("snapshot restore stores not configured".into())
        })?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Restore,
                &metadata,
                SandboxState::Resuming,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let backend = Arc::clone(&handle.backend);
        let restore_ctx = cmd.to_restore_context(
            &context.sandbox_id,
            &context.operation_id,
            context.policy_epoch,
        );
        let execution = run_until_deadline(&token, context.deadline_unix_ms, async move {
            stage_restore(&stores, &*backend, &restore_ctx, RestoreIntent::Restore).await
        })
        .await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, state) = match execution {
            Execution::Completed(Ok(staged)) => {
                invalidate_guest_session(&handle).await;
                let message = if staged.memory_restored {
                    format!(
                        "restore staged from snapshot; memory restored, resume required (layers={})",
                        staged.layers_staged
                    )
                } else {
                    format!(
                        "restore staged from snapshot; boot required (layers={})",
                        staged.layers_staged
                    )
                };
                let outcome = super::OperationOutcome {
                    status: OutcomeStatus::Succeeded,
                    reason: OutcomeReason::Completed,
                    message: Some(message),
                    ..base_outcome(&context, OperationKind::Restore)
                };
                let state = if staged.memory_restored {
                    SandboxState::Suspended
                } else {
                    SandboxState::Preparing
                };
                (outcome, state)
            }
            Execution::Completed(Err(message)) => (
                restore_rejected_outcome(&context, OperationKind::Restore, message),
                SandboxState::Failed,
            ),
            Execution::Canceled => (
                super::canceled_outcome(&context, OperationKind::Restore),
                SandboxState::Failed,
            ),
            Execution::TimedOut => (
                super::timed_out_outcome(&context, OperationKind::Restore),
                SandboxState::Failed,
            ),
        };
        self.persist_outcome(&outcome, state, &[]).await?;
        Ok(outcome)
    }

    /// Forks a child sandbox from a fork snapshot point.
    ///
    /// The child must be prepared. The parent snapshot must have fork
    /// purpose. The child receives an independent workspace; no leases,
    /// credentials, DNS cache, flows, or port exposure are inherited.
    /// Lineage binding is preserved through the parent snapshot id in the
    /// outcome message and audit trail.
    ///
    /// The parent envelope keeps its pre-operation ledger state on every
    /// path: fork stages into the child, so a fork failure must never wedge
    /// the parent into `Failed` and a success must never regress a live
    /// parent back to `Preparing`. Only the outcome row records the result.
    ///
    /// Staging mints an independent root workspace rather than a
    /// `ForkManager` shared-base child, so fork depth does not accumulate
    /// here and shared-base lineage stays a follow-up. Depth limits apply
    /// at the workspace COW level.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::restore`].
    pub async fn fork(
        &self,
        context: CommandContext,
        cmd: ForkCommand,
    ) -> Result<super::OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let stores = self.snapshot_stores.read().clone().ok_or_else(|| {
            SupervisorError::SnapshotRestore("snapshot restore stores not configured".into())
        })?;
        let child_id = SandboxId::from_string(cmd.child_sandbox_id.clone());
        if child_id.as_str() == context.sandbox_id.as_str() {
            return Err(SupervisorError::SandboxMismatch {
                command: context.sandbox_id.to_string(),
                config: cmd.child_sandbox_id.clone(),
            });
        }
        let handle = self.runtime_handle(child_id.as_str(), None).await?;
        // Capture the parent envelope state before `begin` moves it to
        // `Resuming`: staging targets the child, so completion re-persists
        // the parent's prior state instead of overwriting it.
        let parent_state = self
            .observation(&context.sandbox_id)
            .await?
            .map(|snapshot| snapshot.status.observed_state)
            .unwrap_or(SandboxState::Preparing);
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Fork,
                &metadata,
                SandboxState::Resuming,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let backend = Arc::clone(&handle.backend);
        let restore_ctx =
            cmd.to_restore_context(&child_id, &context.operation_id, context.policy_epoch);
        let execution = run_until_deadline(&token, context.deadline_unix_ms, async move {
            stage_restore(&stores, &*backend, &restore_ctx, RestoreIntent::Fork).await
        })
        .await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, state) = match execution {
            Execution::Completed(Ok(staged)) => {
                invalidate_guest_session(&handle).await;
                let outcome = super::OperationOutcome {
                    status: OutcomeStatus::Succeeded,
                    reason: OutcomeReason::Completed,
                    message: Some(format!(
                        "fork staged from parent snapshot; boot required (layers={})",
                        staged.layers_staged
                    )),
                    ..base_outcome(&context, OperationKind::Fork)
                };
                (outcome, parent_state)
            }
            Execution::Completed(Err(message)) => (
                restore_rejected_outcome(&context, OperationKind::Fork, message),
                parent_state,
            ),
            Execution::Canceled => (
                super::canceled_outcome(&context, OperationKind::Fork),
                parent_state,
            ),
            Execution::TimedOut => (
                super::timed_out_outcome(&context, OperationKind::Fork),
                parent_state,
            ),
        };
        self.persist_outcome(&outcome, state, &[]).await?;
        Ok(outcome)
    }
}

/// Clears stale guest authority so a restored sandbox cannot reuse a
/// pre-snapshot session, boot id, or connection.
async fn invalidate_guest_session(handle: &super::RuntimeHandle) {
    *handle.guest_session.lock().await = None;
    handle.guest_boot_id.write().clear();
}

/// Failed restore outcome with the typed rejection reason.
fn restore_rejected_outcome(
    context: &CommandContext,
    kind: OperationKind,
    message: String,
) -> super::OperationOutcome {
    super::OperationOutcome {
        status: OutcomeStatus::Failed,
        reason: OutcomeReason::RestoreRejected,
        message: Some(message),
        ..base_outcome(context, kind)
    }
}

/// Stages restore from validated context with explicit intent.
///
/// Single purpose gate lives in core via `prepare_*_with_intent`;
/// supervisor passes `Restore` or `Fork` intent instead of re-checking
/// purpose after validation. Memory requires route through
/// `prepare_memory_restore_with_intent` for the memory-profile gate plus
/// shared pre-KMS integrity; filesystem uses `prepare_restore_with_intent`.
/// Guards are held for the full staging duration: single ownership, no
/// hidden orchestrator store.
async fn stage_restore(
    stores: &SnapshotRestoreStores,
    backend: &dyn pico_core::RuntimeBackend,
    restore_ctx: &RestoreContext,
    intent: RestoreIntent,
) -> Result<StagedRestore, String> {
    let mut orchestrator = RestoreOrchestrator::new(
        Arc::clone(&stores.repository),
        Arc::clone(&stores.blob_locator),
    );
    if let Some(ref resolver) = stores.key_resolver {
        orchestrator = orchestrator.with_key_resolver(Arc::clone(resolver));
    }
    let prepared = if restore_ctx.requires_memory {
        orchestrator
            .prepare_memory_restore_with_intent(restore_ctx, intent)
            .await
            .map_err(|e| e.to_string())?
    } else {
        orchestrator
            .prepare_restore_with_intent(restore_ctx, intent)
            .await
            .map_err(|e| e.to_string())?
    };
    let (metadata, blob_set, _guards) = prepared.into_parts();

    let memory_restored = if restore_ctx.requires_memory {
        if blob_set.memory_blobs.is_empty() {
            return Err("memory profile requires memory blobs".into());
        }
        let backend_ctx = BackendRestoreContext {
            snapshot_id: restore_ctx.snapshot_id.to_string(),
            sandbox_id: restore_ctx.sandbox_id.to_string(),
            blob_paths: blob_set
                .memory_blobs
                .iter()
                .map(|b| b.path.clone())
                .collect(),
        };
        backend
            .restore_snapshot(&backend_ctx)
            .await
            .map_err(|e| e.to_string())?;
        true
    } else {
        false
    };

    let fs_outcome = pico_core::RestoreExecutor::execute_filesystem_restore(
        &metadata,
        &blob_set,
        &*stores.cow_engine,
        &restore_ctx.sandbox_id,
    )
    .map_err(|e| e.to_string())?;

    Ok(StagedRestore {
        memory_restored,
        layers_staged: fs_outcome.layers_restored,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use parking_lot::Mutex;
    use pico_core::{
        BackendRecord, BlobInfo, BlobLocator, CpuShape, DeviceModel, FencingToken, MemoryShape,
        OperationId, SandboxConfig, SandboxId, SandboxState, SnapshotId, SnapshotListPage,
        SnapshotMetadata, SnapshotPurpose, SnapshotRepository, SnapshotResult, SnapshotState,
        TenantId,
    };
    use pico_core::{FilesystemRef, LineageType, SnapshotProfile};

    use super::*;
    use crate::HostResourceSpec as SupervisorHostSpec;
    use crate::{CommandContext, SandboxSupervisor};

    struct MemRepo {
        inner: Mutex<Vec<SnapshotMetadata>>,
    }

    impl MemRepo {
        fn new() -> Self {
            Self {
                inner: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SnapshotRepository for MemRepo {
        async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
            self.inner
                .lock()
                .iter()
                .find(|m| m.id == *id)
                .cloned()
                .ok_or_else(|| pico_core::SnapshotError::SnapshotNotFound { id: id.to_string() })
        }

        async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
            self.inner.lock().push(metadata.clone());
            Ok(())
        }

        async fn update_snapshot(
            &self,
            metadata: &SnapshotMetadata,
            _expected_version: u64,
        ) -> SnapshotResult<()> {
            let mut guard = self.inner.lock();
            if let Some(existing) = guard.iter_mut().find(|m| m.id == metadata.id) {
                *existing = metadata.clone();
                Ok(())
            } else {
                Err(pico_core::SnapshotError::SnapshotNotFound {
                    id: metadata.id.to_string(),
                })
            }
        }

        async fn list_snapshots(
            &self,
            _tenant_id: &TenantId,
            _purpose: Option<SnapshotPurpose>,
            _state: Option<SnapshotState>,
            _limit: usize,
            _cursor: Option<String>,
        ) -> SnapshotResult<SnapshotListPage> {
            Ok(SnapshotListPage {
                snapshots: self.inner.lock().clone(),
                next_cursor: None,
            })
        }

        async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
            self.inner.lock().retain(|m| m.id != *id);
            Ok(())
        }
    }

    struct FileLocator {
        files: Mutex<HashMap<String, std::path::PathBuf>>,
    }

    impl FileLocator {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
            }
        }

        fn insert(&self, blob_ref: &str, path: std::path::PathBuf) {
            self.files.lock().insert(blob_ref.to_string(), path);
        }
    }

    #[async_trait]
    impl BlobLocator for FileLocator {
        async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo> {
            let path = self.files.lock().get(blob_ref).cloned().ok_or_else(|| {
                pico_core::SnapshotError::BlobMissing {
                    blob_ref: blob_ref.to_string(),
                }
            })?;
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            Ok(BlobInfo {
                blob_ref: blob_ref.to_string(),
                path,
                size_bytes: len,
                digest: None,
            })
        }
    }

    fn v1_snapshot(
        snapshot_id: SnapshotId,
        tenant: &str,
        purpose: SnapshotPurpose,
        profile: SnapshotProfile,
        blob_ref: &str,
        digest: &str,
    ) -> SnapshotMetadata {
        let mut meta = SnapshotMetadata::new(
            snapshot_id,
            TenantId::from_string(tenant),
            SandboxId::generate(),
            None,
            LineageType::Root,
            purpose,
            profile,
            OperationId::generate(),
            "img_base".into(),
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
        meta.schema_version = 1;
        meta.policy_epoch = Some(1);
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: blob_ref.to_string(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some(format!("blake3:{digest}")),
            is_root: true,
        });
        let _ = meta.mark_ready();
        meta
    }

    fn sample_host_shape() -> pico_sandboxd_proto::v1::HostShape {
        pico_sandboxd_proto::v1::HostShape {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            cpu_arch: "x86_64".into(),
            memory_mb: 4096,
            vcpus: 4,
            machine_type: "q35".into(),
            disk_mb: 0,
        }
    }

    fn restore_cmd(snapshot_id: &str) -> RestoreCommand {
        RestoreCommand {
            snapshot_id: snapshot_id.to_string(),
            request_tenant_id: "tnt_test".into(),
            requires_memory: false,
            runtime: RuntimeType::Firecracker,
            host: sample_host_shape(),
        }
    }

    fn ctx(sandbox_id: &str, sequence: u64) -> CommandContext {
        CommandContext::with_timeout(
            SandboxId::from_string(sandbox_id),
            OperationId::generate(),
            FencingToken { epoch: 1, sequence },
            1,
            Duration::from_secs(30),
        )
    }

    async fn prepared_supervisor(
        sandbox_id: &str,
        repo: Arc<MemRepo>,
        locator: Arc<FileLocator>,
        cow_dir: &tempfile::TempDir,
    ) -> SandboxSupervisor {
        use pico_runtime::mock::MockBackend;

        let cow = Arc::new(
            pico_core::snapshot::cow::filesystem::CowFilesystemEngine::open(cow_dir.path())
                .expect("open cow engine"),
        );
        let supervisor = SandboxSupervisor::in_memory()
            .with_guest_session(false)
            .with_snapshot_stores(SnapshotRestoreStores {
                repository: repo,
                blob_locator: locator,
                cow_engine: cow,
                key_resolver: None,
            });
        let backend: Arc<dyn pico_core::RuntimeBackend> = Arc::new(MockBackend::default());
        supervisor
            .prepare(
                ctx(sandbox_id, 1),
                backend,
                &SandboxConfig {
                    id: sandbox_id.into(),
                    ..SandboxConfig::default()
                },
                &SupervisorHostSpec::default(),
            )
            .await
            .expect("prepare");
        supervisor
    }

    fn write_blob(
        dir: &tempfile::TempDir,
        name: &str,
        data: &[u8],
    ) -> (std::path::PathBuf, String) {
        let path = dir.path().join(name);
        std::fs::write(&path, data).expect("write blob");
        let digest = pico_core::compute_blob_digest(data);
        (path, digest)
    }

    #[tokio::test]
    async fn restore_filesystem_succeeds_and_stays_preparing() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"filesystem bytes");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_restore_ok", repo, locator, &cow_dir).await;
        let outcome = supervisor
            .restore(
                ctx("sbx_restore_ok", 2),
                restore_cmd(&snapshot_id.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Succeeded);
        assert_eq!(outcome.kind, OperationKind::Restore);
        let observation = supervisor
            .observation(&SandboxId::from_string("sbx_restore_ok"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observation.status.observed_state, SandboxState::Preparing);
    }

    #[tokio::test]
    async fn restore_rejects_wrong_tenant() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"data");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_a",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_restore_tenant", repo, locator, &cow_dir).await;
        let outcome = supervisor
            .restore(
                ctx("sbx_restore_tenant", 2),
                restore_cmd(&snapshot_id.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.reason, OutcomeReason::RestoreRejected);
    }

    #[tokio::test]
    async fn restore_rejects_tampered_blob() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        // Record digest of original bytes but store tampered bytes.
        let expected = pico_core::compute_blob_digest(b"original");
        let (path, _) = write_blob(&blob_dir, "rootfs.ext4", b"tampered");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &expected,
        ));

        let supervisor = prepared_supervisor("sbx_restore_tamper", repo, locator, &cow_dir).await;
        let outcome = supervisor
            .restore(
                ctx("sbx_restore_tamper", 2),
                restore_cmd(&snapshot_id.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.reason, OutcomeReason::RestoreRejected);
    }

    #[tokio::test]
    async fn restore_rejects_stale_policy_epoch() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"data");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_restore_epoch", repo, locator, &cow_dir).await;
        // Context epoch 2 vs snapshot epoch 1.
        let context = CommandContext::with_timeout(
            SandboxId::from_string("sbx_restore_epoch"),
            OperationId::generate(),
            FencingToken {
                epoch: 1,
                sequence: 2,
            },
            2,
            Duration::from_secs(30),
        );
        let outcome = supervisor
            .restore(context, restore_cmd(&snapshot_id.to_string()))
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.reason, OutcomeReason::RestoreRejected);
    }

    #[tokio::test]
    async fn restore_rejects_memory_require_without_blobs() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        // Memory-profile snapshot with no memory segments: validation
        // passes, so the missing-blobs guard is what rejects the restore.
        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"data");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Memory,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_restore_mem", repo, locator, &cow_dir).await;
        let mut cmd = restore_cmd(&snapshot_id.to_string());
        cmd.requires_memory = true;
        let outcome = supervisor
            .restore(ctx("sbx_restore_mem", 2), cmd)
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.reason, OutcomeReason::RestoreRejected);
    }

    #[tokio::test]
    async fn restore_fails_closed_without_stores() {
        let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
        let err = supervisor
            .restore(ctx("sbx_nostore", 1), restore_cmd("snp_x"))
            .await
            .unwrap_err();
        assert!(matches!(err, SupervisorError::SnapshotRestore(_)));
    }

    #[tokio::test]
    async fn restore_rejects_unprepared_sandbox() {
        let cow_dir = tempfile::TempDir::new().unwrap();
        let supervisor = SandboxSupervisor::in_memory()
            .with_guest_session(false)
            .with_snapshot_stores(SnapshotRestoreStores {
                repository: Arc::new(MemRepo::new()),
                blob_locator: Arc::new(FileLocator::new()),
                cow_engine: Arc::new(
                    pico_core::snapshot::cow::filesystem::CowFilesystemEngine::open(cow_dir.path())
                        .unwrap(),
                ),
                key_resolver: None,
            });
        let err = supervisor
            .restore(ctx("sbx_missing", 1), restore_cmd("snp_x"))
            .await
            .unwrap_err();
        assert!(matches!(err, SupervisorError::RuntimeNotAttached(_)));
    }

    #[tokio::test]
    async fn restore_is_idempotent_on_operation_id() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"bytes");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_restore_idem", repo, locator, &cow_dir).await;
        let context = ctx("sbx_restore_idem", 2);
        let first = supervisor
            .restore(context.clone(), restore_cmd(&snapshot_id.to_string()))
            .await
            .unwrap();
        let second = supervisor
            .restore(context, restore_cmd(&snapshot_id.to_string()))
            .await
            .unwrap();
        assert_eq!(first.status, OutcomeStatus::Succeeded);
        assert_eq!(second.status, OutcomeStatus::Succeeded);
        assert_eq!(first.operation_id, second.operation_id);
    }

    fn fork_cmd(parent: &str, child: &str) -> ForkCommand {
        ForkCommand {
            parent_snapshot_id: parent.to_string(),
            request_tenant_id: "tnt_test".into(),
            child_sandbox_id: child.to_string(),
            requires_memory: false,
            runtime: RuntimeType::Firecracker,
            host: sample_host_shape(),
        }
    }

    #[tokio::test]
    async fn fork_succeeds_with_fork_purpose_snapshot() {
        use pico_runtime::mock::MockBackend;

        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"fork bytes");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Fork,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let cow = Arc::new(
            pico_core::snapshot::cow::filesystem::CowFilesystemEngine::open(cow_dir.path())
                .expect("open cow engine"),
        );
        let supervisor = SandboxSupervisor::in_memory()
            .with_guest_session(false)
            .with_snapshot_stores(SnapshotRestoreStores {
                repository: Arc::clone(&repo) as _,
                blob_locator: Arc::clone(&locator) as _,
                cow_engine: cow,
                key_resolver: None,
            });
        // The fork envelope targets the parent id; the child must also be
        // prepared so it has a runtime handle and workspace.
        for (id, seq) in [("sbx_fork_parent", 1), ("sbx_fork_child", 1)] {
            let backend: Arc<dyn pico_core::RuntimeBackend> = Arc::new(MockBackend::default());
            supervisor
                .prepare(
                    ctx(id, seq),
                    backend,
                    &SandboxConfig {
                        id: id.into(),
                        ..SandboxConfig::default()
                    },
                    &SupervisorHostSpec::default(),
                )
                .await
                .expect("prepare");
        }
        let outcome = supervisor
            .fork(
                ctx("sbx_fork_parent", 2),
                fork_cmd(&snapshot_id.to_string(), "sbx_fork_child"),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Succeeded);
        assert_eq!(outcome.kind, OperationKind::Fork);
        let observation = supervisor
            .observation(&SandboxId::from_string("sbx_fork_parent"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observation.status.observed_state, SandboxState::Preparing);
    }

    #[tokio::test]
    async fn fork_rejects_non_fork_purpose() {
        let blob_dir = tempfile::TempDir::new().unwrap();
        let cow_dir = tempfile::TempDir::new().unwrap();
        let repo = Arc::new(MemRepo::new());
        let locator = Arc::new(FileLocator::new());
        let snapshot_id = SnapshotId::generate();

        let (path, digest) = write_blob(&blob_dir, "rootfs.ext4", b"bytes");
        locator.insert("rootfs.ext4", path);
        repo.inner.lock().push(v1_snapshot(
            snapshot_id.clone(),
            "tnt_test",
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            "rootfs.ext4",
            &digest,
        ));

        let supervisor = prepared_supervisor("sbx_fork_base", repo, locator, &cow_dir).await;
        {
            use pico_runtime::mock::MockBackend;
            let backend: Arc<dyn pico_core::RuntimeBackend> = Arc::new(MockBackend::default());
            supervisor
                .prepare(
                    ctx("sbx_fork_kid", 1),
                    backend,
                    &SandboxConfig {
                        id: "sbx_fork_kid".into(),
                        ..SandboxConfig::default()
                    },
                    &SupervisorHostSpec::default(),
                )
                .await
                .expect("prepare child");
        }
        let outcome = supervisor
            .fork(
                ctx("sbx_fork_base", 2),
                fork_cmd(&snapshot_id.to_string(), "sbx_fork_kid"),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.reason, OutcomeReason::RestoreRejected);
        // A failed fork must not wedge the parent envelope: the parent keeps
        // its pre-operation ledger state.
        let parent = supervisor
            .observation(&SandboxId::from_string("sbx_fork_base"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parent.status.observed_state, SandboxState::Preparing);
    }
}
