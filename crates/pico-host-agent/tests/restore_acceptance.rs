//! End-to-end restore acceptance for the sandboxd-owned path.
//!
//! Spins up a live sandboxd supervisor with snapshot stores installed,
//! connects a real `HostAgent`, and drives
//! `HostAgent::restore_from_snapshot` through the `Restore` RPC with a
//! MockBackend. No VMM, TAP device, or cgroup hierarchy is required.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use pico_core::snapshot::cow::filesystem::CowFilesystemEngine;
use pico_core::{
    BackendRecord, BlobInfo, BlobLocator, FilesystemRef, LineageType, MemoryShape, OperationId,
    RuntimeType, SandboxId, SandboxSpec, SnapshotId, SnapshotListPage, SnapshotMetadata,
    SnapshotProfile, SnapshotPurpose, SnapshotRepository, SnapshotResult, SnapshotState, TenantId,
};
use pico_host_agent::HostAgent;
use pico_host_agent::restore::RestoreHostParams;
use pico_host_agent::sandboxd_client::{SandboxdConnect, SandboxdHandle};
use pico_runtime::mock::MockBackend;
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor, SnapshotRestoreStores};
use tempfile::TempDir;

const TOKEN: &str = "restore-acceptance-token";
const TIMEOUT: Duration = Duration::from_secs(5);

struct MemRepo {
    inner: Mutex<Vec<SnapshotMetadata>>,
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

struct Fixture {
    _dir: TempDir,
    socket: std::path::PathBuf,
    ledger: std::path::PathBuf,
    workspace: std::path::PathBuf,
    repo: Arc<MemRepo>,
    locator: Arc<FileLocator>,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let workspace = dir.path().join("workspaces");
        std::fs::create_dir_all(&workspace).unwrap();
        Self {
            socket: dir.path().join("sandboxd.sock"),
            ledger: dir.path().join("state.db"),
            workspace,
            repo: Arc::new(MemRepo {
                inner: Mutex::new(Vec::new()),
            }),
            locator: Arc::new(FileLocator {
                files: Mutex::new(HashMap::new()),
            }),
            _dir: dir,
        }
    }

    /// Stores a v1 base snapshot with one real blob file. The host
    /// capabilities mirror `RestoreHostParams::for_firecracker` so the
    /// compat check passes on any architecture.
    fn store_snapshot(&self, tenant: &str) -> SnapshotId {
        let snapshot_id = SnapshotId::generate();
        let params = RestoreHostParams::for_firecracker(64, 1, "1.10.0", "2.0", "0.5.0");
        let blob_path = self._dir.path().join("rootfs.ext4");
        std::fs::write(&blob_path, b"acceptance rootfs bytes").unwrap();
        let digest = pico_core::compute_blob_digest(b"acceptance rootfs bytes");
        self.locator
            .files
            .lock()
            .insert("rootfs.ext4".into(), blob_path);

        let mut meta = SnapshotMetadata::new(
            snapshot_id.clone(),
            TenantId::from_string(tenant),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img_base".into(),
            BackendRecord {
                backend_type: params.backend.backend_type.clone(),
                backend_version: params.backend.backend_version.clone(),
                protocol_version: params.backend.protocol_version.clone(),
                guest_agent_version: Some("0.5.0".into()),
            },
            params.cpu.clone(),
            MemoryShape {
                memory_mb: 64,
                vcpus: 1,
            },
            params.device.clone(),
        );
        meta.schema_version = 1;
        meta.policy_epoch = Some(1);
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "rootfs.ext4".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some(format!("blake3:{digest}")),
            is_root: true,
        });
        meta.mark_ready().unwrap();
        self.repo.inner.lock().push(meta);
        snapshot_id
    }

    fn supervisor(&self) -> SandboxSupervisor {
        let cow = Arc::new(
            CowFilesystemEngine::open(self.workspace.join("cow")).expect("open cow engine"),
        );
        SandboxSupervisor::open(
            &self.ledger,
            HostResourceConfig::new(self.workspace.clone()),
        )
        .unwrap()
        .with_guest_session(false)
        .with_snapshot_stores(SnapshotRestoreStores {
            repository: Arc::clone(&self.repo) as _,
            blob_locator: Arc::clone(&self.locator) as _,
            cow_engine: cow,
            key_resolver: None,
        })
    }

    async fn serve(
        &self,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let mut registry = AdapterRegistry::new();
        registry.register(
            RuntimeType::Firecracker,
            || Arc::new(MockBackend::default()),
        );
        let config = SandboxdConfig {
            socket_path: self.socket.clone(),
            auth_token: TOKEN.into(),
            ledger_path: self.ledger.clone(),
            workspace_root: self.workspace.clone(),
            cpu_isolation_policy: Default::default(),
            cross_tenant_host: false,
            allowed_peer_uids: Vec::new(),
            log_format: Default::default(),
            dns_proxy_listen_addr: None,
            network_enabled: false,
        };
        let listener = bind_uds(&self.socket).await.unwrap();
        let supervisor = self.supervisor();
        supervisor.reconcile().await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let serve = serve_uds(listener, supervisor, registry, &config, async move {
                let _ = shutdown_rx.await;
            });
            let _ = serve.await;
        });
        (task, shutdown_tx)
    }

    async fn connect_agent(&self) -> HostAgent {
        let sandboxd = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: self.socket.clone(),
                auth_token: TOKEN.into(),
            },
            TIMEOUT,
        )
        .await
        .expect("connect sandboxd");
        HostAgent::with_sandboxd(
            self.workspace.clone(),
            300,
            RuntimeType::Firecracker,
            sandboxd,
        )
        .expect("host agent")
    }
}

fn spec(id: &str) -> SandboxSpec {
    SandboxSpec {
        runtime: None,
        id: Some(id.into()),
        ports: None,
        env: None,
        memory_mb: Some(64),
        vcpus: Some(1),
        idle_timeout_secs: None,
        ssh_public_key: None,
        ssh_key_type: None,
        image_id: None,
        image_digest: None,
        credential_request: None,
    }
}

#[tokio::test]
async fn restore_from_snapshot_succeeds_end_to_end() {
    let fixture = Fixture::new();
    // No credential request means the default tenant owns the sandbox.
    let snapshot_id = fixture.store_snapshot("default");
    let (_task, _shutdown) = fixture.serve().await;
    let agent = fixture.connect_agent().await;

    let params = RestoreHostParams::for_firecracker(64, 1, "1.10.0", "2.0", "0.5.0");
    let outcome = agent
        .restore_from_snapshot(snapshot_id, spec("sbx_restore_e2e"), params, false)
        .await
        .expect("restore RPC");
    assert!(outcome.success, "expected success: {}", outcome.reason);
    assert!(outcome.blobs_resolved);

    let state = agent.get_status("sbx_restore_e2e").await.unwrap();
    assert_eq!(state, pico_core::SandboxState::Preparing);
}

#[tokio::test]
async fn restore_from_snapshot_rejects_cross_tenant_artifact() {
    let fixture = Fixture::new();
    let snapshot_id = fixture.store_snapshot("tnt_other");
    let (_task, _shutdown) = fixture.serve().await;
    let agent = fixture.connect_agent().await;

    let params = RestoreHostParams::for_firecracker(64, 1, "1.10.0", "2.0", "0.5.0");
    let outcome = agent
        .restore_from_snapshot(snapshot_id, spec("sbx_restore_xtenant"), params, false)
        .await
        .expect("restore RPC carries rejection in the outcome");
    assert!(
        !outcome.success,
        "cross-tenant restore must not succeed: {}",
        outcome.reason
    );
}
