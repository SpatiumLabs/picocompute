//! Integration: Prepare + Destroy over UDS with MockBackend.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pico_core::{FencingToken, OperationId, RuntimeType, SandboxId};
use pico_runtime::mock::MockBackend;
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
use pico_sandboxd_proto::METADATA_TOKEN_KEY;
use pico_sandboxd_proto::v1::sandboxd_client::SandboxdClient;
use pico_sandboxd_proto::v1::{
    CommandMeta, DestroyRequest, GetPortTargetRequest, GetSandboxRequest, HealthRequest,
    HostResourceSpec, ListSandboxesRequest, OutcomeStatus, PrepareRequest,
    RuntimeType as ProtoRuntime, SandboxConfig, SandboxState as ProtoState, WatchRequest,
    port_target, watch_event,
};
use tempfile::TempDir;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

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

async fn start_pair() -> (
    TempDir,
    SandboxdClient<Channel>,
    tokio::task::JoinHandle<()>,
) {
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
async fn prepare_and_destroy_over_uds() {
    let (_dir, mut client, server) = start_pair().await;
    let sandbox_id = SandboxId::from_string("sbx_grpc_uds_test");

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
            }),
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(prepare.status, OutcomeStatus::Succeeded as i32);
    assert_ne!(prepare.observed_state, ProtoState::Unspecified as i32);

    let listed = client
        .list_sandboxes(authed(ListSandboxesRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.sandboxes.len(), 1);

    let got = client
        .get_sandbox(authed(GetSandboxRequest {
            sandbox_id: sandbox_id.as_str().into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.sandbox_id, sandbox_id.as_str());

    let health = client
        .health(authed(HealthRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(health.ready_for_work);
    assert!(health.reconcile_complete);

    let destroy = client
        .destroy(authed(DestroyRequest {
            meta: Some(meta(sandbox_id.as_str(), 2)),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded as i32);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn rejects_missing_auth_token() {
    let (_dir, mut client, server) = start_pair().await;

    let err = client
        .health(Request::new(HealthRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn rejects_wrong_auth_token() {
    let (_dir, mut client, server) = start_pair().await;

    let mut request = Request::new(HealthRequest {});
    request.metadata_mut().insert(
        METADATA_TOKEN_KEY,
        MetadataValue::from_static("wrong-token"),
    );
    let err = client.health(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn get_port_target_and_watch_over_uds() {
    use tokio::time::timeout;
    use tokio_stream::StreamExt;

    let (_dir, mut client, server) = start_pair().await;
    let sandbox_id = SandboxId::from_string("sbx_grpc_port_watch");

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
            }),
            runtime_type: ProtoRuntime::Firecracker as i32,
            host: Some(HostResourceSpec {
                vcpus: 1,
                memory_mb: 128,
                requested_ports: vec![8080],
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded as i32);

    let port = client
        .get_port_target(authed(GetPortTargetRequest {
            sandbox_id: sandbox_id.as_str().into(),
            guest_port: 8080,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(port.generation >= 1);
    assert!(matches!(
        port.target.unwrap().target,
        Some(port_target::Target::TcpAddr(addr)) if addr == "127.0.0.1:8080"
    ));

    let mut watch = client
        .watch(authed(WatchRequest {
            sandbox_ids: vec![sandbox_id.as_str().into()],
        }))
        .await
        .unwrap()
        .into_inner();
    let upsert = timeout(Duration::from_secs(2), watch.next())
        .await
        .expect("watch upsert timeout")
        .expect("stream ended")
        .unwrap();
    match upsert.body {
        Some(watch_event::Body::Upsert(obs)) => {
            assert_eq!(obs.sandbox_id, sandbox_id.as_str());
            assert_eq!(obs.ports.len(), 1);
        }
        other => panic!("expected upsert, got {other:?}"),
    }
    let reconcile = timeout(Duration::from_secs(2), watch.next())
        .await
        .expect("watch reconcile timeout")
        .expect("stream ended")
        .unwrap();
    assert!(matches!(
        reconcile.body,
        Some(watch_event::Body::Reconcile(_))
    ));

    let destroy = client
        .destroy(authed(DestroyRequest {
            meta: Some(meta(sandbox_id.as_str(), 2)),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded as i32);

    let removed = timeout(Duration::from_secs(2), async {
        loop {
            let event = watch.next().await.expect("stream ended").unwrap();
            if matches!(
                event.body,
                Some(watch_event::Body::RemovedSandboxId(ref id)) if id == sandbox_id.as_str()
            ) {
                return event;
            }
        }
    })
    .await
    .expect("removed timeout");
    assert!(matches!(
        removed.body,
        Some(watch_event::Body::RemovedSandboxId(id)) if id == sandbox_id.as_str()
    ));

    let missing = client
        .get_port_target(authed(GetPortTargetRequest {
            sandbox_id: sandbox_id.as_str().into(),
            guest_port: 8080,
        }))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    server.abort();
    let _ = server.await;
}
