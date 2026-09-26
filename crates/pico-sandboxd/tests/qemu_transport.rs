//! Integration: QEMU-class guest transport without TCP.
//!
//! A backend returning `GuestTransport::Unix` (the QEMU virtio-serial
//! fallback shape) must boot through production sandboxd with
//! `allow_tcp_guest_transport = false`. This pins acceptance:
//! sandboxd can handshake a QEMU guest without the TCP development flag.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pico_core::{
    BackendCapabilities, BackendCapability, BackendError, BackendHealth, BackendMetadata,
    BackendOperation, BackendResult, BackendStats, CleanupReport, DiagnosticBundle, ExecRequest,
    ExecResponse, FencingToken, ForkResult, GuestTransport, OperationId, PreparedSandbox,
    ResourceReceipt, RuntimeBackend, RuntimeType, SandboxConfig, SandboxId, SandboxState,
};
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
use pico_sandboxd_proto::METADATA_TOKEN_KEY;
use pico_sandboxd_proto::v1::sandboxd_client::SandboxdClient;
use pico_sandboxd_proto::v1::{
    BootRequest, CommandMeta, DestroyRequest, ExecRequest as ProtoExecRequest, FileReadRequest,
    FileWriteRequest, GetSandboxRequest, OutcomeStatus, PrepareRequest,
    RuntimeType as ProtoRuntime, SandboxConfig as ProtoSandboxConfig, SandboxState as ProtoState,
    exec_event,
};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

mod common;
use common::mock_guest;

const TOKEN: &str = "test-sandboxd-token";

/// Minimal QEMU-shaped backend: Unix transport, no TCP anywhere.
#[derive(Debug, Clone)]
struct UnixTransportBackend {
    socket_path: PathBuf,
    state: Arc<Mutex<SandboxState>>,
    sandbox: Arc<Mutex<Option<SandboxConfig>>>,
}

impl UnixTransportBackend {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            state: Arc::new(Mutex::new(SandboxState::Pending)),
            sandbox: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl RuntimeBackend for UnixTransportBackend {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: RuntimeType::Qemu,
            version: "qemu-transport-test-1".into(),
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::GuestReadiness,
                BackendCapability::Exec,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
            ]),
        }
    }

    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        *self.sandbox.lock().await = Some(config.clone());
        *self.state.lock().await = SandboxState::Preparing;
        Ok(PreparedSandbox {
            resources: vec![ResourceReceipt {
                class: "qemu-serial-socket".into(),
                name: self.socket_path.display().to_string(),
                external_id: None,
            }],
        })
    }

    async fn boot(&self) -> BackendResult<()> {
        let state = *self.state.lock().await;
        if state != SandboxState::Preparing {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::Boot,
                expected: vec![SandboxState::Preparing],
                actual: state,
            });
        }
        *self.state.lock().await = SandboxState::Booting;
        Ok(())
    }

    async fn attach_transport(&self) -> BackendResult<GuestTransport> {
        let state = *self.state.lock().await;
        if !matches!(state, SandboxState::Booting | SandboxState::Running) {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::AttachTransport,
                expected: vec![SandboxState::Booting, SandboxState::Running],
                actual: state,
            });
        }
        *self.state.lock().await = SandboxState::Running;
        Ok(GuestTransport::Unix {
            path: self.socket_path.display().to_string(),
        })
    }

    async fn wait_ready(&self, _transport: &GuestTransport) -> BackendResult<()> {
        *self.state.lock().await = SandboxState::Running;
        Ok(())
    }

    async fn exec(&self, request: ExecRequest) -> BackendResult<ExecResponse> {
        Ok(ExecResponse {
            exit_code: 0,
            stdout: request.command,
            stderr: String::new(),
            duration_ms: 0,
        })
    }

    async fn fork(&self, _target: &SandboxConfig) -> BackendResult<ForkResult> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Fork,
        })
    }

    async fn destroy(&self) -> BackendResult<CleanupReport> {
        *self.state.lock().await = SandboxState::Destroyed;
        Ok(CleanupReport::default())
    }

    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.destroy().await
    }

    async fn state(&self) -> BackendResult<SandboxState> {
        Ok(*self.state.lock().await)
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        Ok(BackendStats {
            memory_bytes: Some(1024),
            cpu_time_ms: Some(1),
            details: serde_json::json!({"backend": "qemu-transport-test"}),
        })
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        Ok(BackendHealth::ready())
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        Ok(DiagnosticBundle {
            captured_at: pico_core::now_iso(),
            summary: "qemu transport test diagnostics".into(),
            artifacts: Vec::new(),
        })
    }
}

fn deadline_ms(timeout: Duration) -> i64 {
    let deadline = SystemTime::now()
        .checked_add(timeout)
        .unwrap_or(SystemTime::now());
    deadline
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn meta(sandbox_id: &str, sequence: u64) -> CommandMeta {
    CommandMeta {
        sandbox_id: sandbox_id.into(),
        operation_id: OperationId::generate().to_string(),
        assignment_fencing_token: FencingToken { epoch: 1, sequence }.to_string(),
        policy_epoch: 1,
        deadline_unix_ms: deadline_ms(Duration::from_secs(10)),
    }
}

fn authed<T>(inner: T) -> Request<T> {
    let mut request = Request::new(inner);
    request
        .metadata_mut()
        .insert(METADATA_TOKEN_KEY, MetadataValue::from_static(TOKEN));
    request
}

async fn connect_with_retry(socket: &std::path::Path) -> SandboxdClient<Channel> {
    let uri = format!("unix://{}", socket.display());
    let endpoint = Endpoint::from_shared(uri).expect("unix uri");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match endpoint.connect().await {
            Ok(channel) => return SandboxdClient::new(channel),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("connect uds after retry: {e}"),
        }
    }
}

#[tokio::test]
async fn qemu_unix_guest_boots_without_tcp_transport_flag() {
    let sandbox_id = SandboxId::from_string("sbx_qemu_unix_transport");
    let dir = TempDir::new().unwrap();
    let guest_socket = dir.path().join("pico-agent0.sock");
    mock_guest::spawn_mock_guest_session_unix(sandbox_id.as_str(), &guest_socket).await;

    let socket = dir.path().join("sandboxd.sock");
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    // Production posture: vsock/Unix only.
    let supervisor =
        SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone())).unwrap();
    supervisor.reconcile().await.unwrap();

    let backend = UnixTransportBackend::new(guest_socket);
    let mut registry = AdapterRegistry::new();
    registry.register(RuntimeType::Qemu, move || Arc::new(backend.clone()));

    let config = SandboxdConfig {
        socket_path: socket.clone(),
        auth_token: TOKEN.into(),
        ledger_path: ledger,
        workspace_root: workspace,
        cpu_isolation_policy: Default::default(),
        cross_tenant_host: false,
        allowed_peer_uids: Vec::new(),
        log_format: Default::default(),
        dns_proxy_listen_addr: None,
        network_enabled: false,
    };

    let listener = bind_uds(&socket).await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let _server = tokio::spawn(async move {
        let serve = serve_uds(listener, supervisor, registry, &config, async move {
            let _ = shutdown_rx.await;
        });
        let _guard = shutdown_tx;
        serve.await.unwrap();
    });
    let mut client = connect_with_retry(&socket).await;

    let prepare = client
        .prepare(authed(PrepareRequest {
            meta: Some(meta(sandbox_id.as_str(), 1)),
            config: Some(ProtoSandboxConfig {
                id: sandbox_id.as_str().into(),
                memory_limit_bytes: 64 * 1024 * 1024,
                cpu_shares: 100,
                memory_soft_limit_bytes: None,
                max_pids: None,
                network_isolated: true,
                ssh_port: None,
                cpu_set: Vec::new(),
            }),
            runtime_type: ProtoRuntime::Qemu as i32,
            host: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded as i32);

    // The fail-closed handshake must succeed over Unix with TCP disabled.
    let boot = client
        .boot(authed(BootRequest {
            meta: Some(meta(sandbox_id.as_str(), 2)),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(boot.status, OutcomeStatus::Succeeded as i32);
    assert_eq!(boot.observed_state, ProtoState::Running as i32);

    let mut stream = client
        .exec(authed(ProtoExecRequest {
            meta: Some(meta(sandbox_id.as_str(), 3)),
            command: "echo".into(),
            args: vec!["hi".into()],
            env: Default::default(),
            working_dir: "/".into(),
            timeout_ms: Some(2_000),
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        }))
        .await
        .unwrap()
        .into_inner();

    let mut saw_stdout = false;
    let mut saw_exited = false;
    while let Some(event) = stream.next().await {
        match event.unwrap().body {
            Some(exec_event::Body::Stdout(chunk)) => {
                saw_stdout = true;
                assert!(String::from_utf8_lossy(&chunk.data).contains("ran:echo"));
            }
            Some(exec_event::Body::Exited(exited)) => {
                saw_exited = true;
                assert_eq!(exited.exit_code, 0);
            }
            Some(exec_event::Body::Failed(failed)) => {
                panic!("unexpected failed event: {failed:?}");
            }
            _ => {}
        }
    }
    assert!(saw_stdout && saw_exited);

    let got = client
        .get_sandbox(authed(GetSandboxRequest {
            sandbox_id: sandbox_id.as_str().into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.observed_state, ProtoState::Running as i32);

    let write = client
        .file_write(authed(FileWriteRequest {
            meta: Some(meta(sandbox_id.as_str(), 4)),
            path: "/tmp/hello".into(),
            content: b"hello".to_vec(),
            mode: Some(0o644),
            create_parents: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(write.size_bytes, 5);

    let read = client
        .file_read(authed(FileReadRequest {
            meta: Some(meta(sandbox_id.as_str(), 5)),
            path: "/tmp/hello".into(),
            max_bytes: 1024,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.content, b"hello");

    let destroy = client
        .destroy(authed(DestroyRequest {
            meta: Some(meta(sandbox_id.as_str(), 6)),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded as i32);
}
