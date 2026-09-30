//! Integration: mock guest + sandboxd Exec stream end-to-end.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pico_core::{FencingToken, OperationId, RuntimeType, SandboxId};
use pico_runtime::mock::{MockBackend, MockBackendConfig};
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
use pico_sandboxd_proto::METADATA_TOKEN_KEY;
use pico_sandboxd_proto::v1::sandboxd_client::SandboxdClient;
use pico_sandboxd_proto::v1::{
    BootRequest, CommandMeta, DestroyRequest, ExecRequest, FileReadRequest, FileWriteRequest,
    GetSandboxRequest, OutcomeStatus, PrepareRequest, RuntimeType as ProtoRuntime, SandboxConfig,
    SandboxState as ProtoState, ServiceClass as ProtoServiceClass, exec_event,
};
use tempfile::TempDir;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

mod common;
use common::mock_guest;

const TOKEN: &str = "test-sandboxd-token";

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
        deadline_unix_ms: deadline_ms(Duration::from_secs(5)),
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

async fn start_pair_with_guest(
    sandbox_id: &str,
) -> (
    TempDir,
    SandboxdClient<Channel>,
    tokio::task::JoinHandle<()>,
) {
    let dir = TempDir::new().unwrap();
    let guest_socket = dir.path().join("pico-agent0.sock");
    mock_guest::spawn_mock_guest_session_unix(sandbox_id, &guest_socket).await;
    let socket = dir.path().join("sandboxd.sock");
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    let supervisor =
        SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone())).unwrap();
    supervisor.reconcile().await.unwrap();

    let backend = MockBackend::new(MockBackendConfig {
        guest_transport_path: guest_socket.display().to_string(),
        ..MockBackendConfig::default()
    });
    let mut registry = AdapterRegistry::new();
    registry.register(RuntimeType::Firecracker, move || Arc::new(backend.clone()));

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
    let server = tokio::spawn(async move {
        let serve = serve_uds(listener, supervisor, registry, &config, async move {
            let _ = shutdown_rx.await;
        });
        let _guard = shutdown_tx;
        serve.await.unwrap();
    });

    let client = connect_with_retry(&socket).await;
    (dir, client, server)
}

#[tokio::test]
async fn boot_running_only_with_guest_session_and_exec_stream() {
    let sandbox_id = SandboxId::from_string("sbx_guest_session_e2e");
    let (_dir, mut client, _server) = start_pair_with_guest(sandbox_id.as_str()).await;

    let prepare = client
        .prepare(authed(PrepareRequest {
            meta: Some(meta(sandbox_id.as_str(), 1)),
            config: Some(SandboxConfig {
                id: sandbox_id.as_str().into(),
                memory_limit_bytes: 64 * 1024 * 1024,
                cpu_shares: 100,
                memory_soft_limit_bytes: None,
                max_pids: None,
                network_isolated: true,
                ssh_port: None,
                cpu_set: Vec::new(),
                service_class: ProtoServiceClass::LatencySensitive as i32,
            }),
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded as i32);

    let boot = client
        .boot(authed(BootRequest {
            meta: Some(meta(sandbox_id.as_str(), 2)),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(boot.status, OutcomeStatus::Succeeded as i32);
    assert_eq!(boot.observed_state, ProtoState::Running as i32);

    let got = client
        .get_sandbox(authed(GetSandboxRequest {
            sandbox_id: sandbox_id.as_str().into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.observed_state, ProtoState::Running as i32);

    let mut stream = client
        .exec(authed(ExecRequest {
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

    let mut saw_started = false;
    let mut saw_stdout = false;
    let mut saw_exited = false;
    while let Some(event) = stream.next().await {
        let event = event.unwrap();
        match event.body {
            Some(exec_event::Body::Started(_)) => saw_started = true,
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
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(saw_started && saw_stdout && saw_exited);

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

#[tokio::test]
async fn boot_fails_closed_without_guest_session() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("sandboxd.sock");
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    let supervisor =
        SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone())).unwrap();
    supervisor.reconcile().await.unwrap();
    let mut registry = AdapterRegistry::new();
    registry.register(
        RuntimeType::Firecracker,
        || Arc::new(MockBackend::default()),
    );
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
    let sandbox_id = SandboxId::from_string("sbx_fail_closed");

    client
        .prepare(authed(PrepareRequest {
            meta: Some(meta(sandbox_id.as_str(), 1)),
            config: Some(SandboxConfig {
                id: sandbox_id.as_str().into(),
                memory_limit_bytes: 64 * 1024 * 1024,
                cpu_shares: 100,
                memory_soft_limit_bytes: None,
                max_pids: None,
                network_isolated: true,
                ssh_port: None,
                cpu_set: Vec::new(),
                service_class: ProtoServiceClass::LatencySensitive as i32,
            }),
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: None,
        }))
        .await
        .unwrap();

    let mut boot_meta = meta(sandbox_id.as_str(), 2);
    boot_meta.deadline_unix_ms = deadline_ms(Duration::from_millis(200));
    let boot = client
        .boot(authed(BootRequest {
            meta: Some(boot_meta),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(boot.status, OutcomeStatus::Succeeded as i32);
    assert_ne!(boot.observed_state, ProtoState::Running as i32);
}
