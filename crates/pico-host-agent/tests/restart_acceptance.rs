//! Restart-resilience acceptance tests for the host-agent/sandboxd process
//! split (ADR-0011, PR8).
//!
//! These tests run an in-process sandboxd gRPC server over a Unix domain
//! socket and exercise the real `SandboxdHandle` client inside `HostAgent`.
//! A daemon "kill" is simulated by shutting the server task down and dropping
//! the supervisor; a host-agent "kill" is simulated by constructing a brand
//! new `HostAgent` against the surviving daemon. Everything runs unprivileged
//! on Linux (CI) and macOS (local dev): the MockBackend stands in for runtime
//! mechanics and a minimal framed mock guest answers the exec protocol, so no
//! Firecracker binary, TAP device, or cgroup hierarchy is required.
//!
//! Covered acceptance scenarios:
//!
//! 1. A Running sandbox survives a host-agent restart: the new agent
//!    rehydrates it from sandboxd `ListSandboxes` and exec still works.
//! 2. Killing sandboxd marks the host not ready; after a daemon restart the
//!    ledger still shows exactly one sandbox and the host never silently
//!    re-creates the runtime (no silent dual create).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use pico_core::crypto;
use pico_core::{ExecRequest, RuntimeType, SandboxSpec, SandboxState};
use pico_guest_protocol::bootstrap_v1::*;
use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::ExecRequest as GuestExecRequest;
use pico_guest_protocol::operational_v1::*;
use pico_host_agent::HostAgent;
use pico_host_agent::health::HealthStatus;
use pico_host_agent::sandboxd_client::{SandboxdConnect, SandboxdHandle};
use pico_runtime::mock::{MockBackend, MockBackendConfig};
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
use pico_sandboxd_proto::v1::SandboxState as ProtoState;
use prost::Message;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;

const TOKEN: &str = "restart-acceptance-token";
const TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Mock guest: bootstrap handshake + exec responses, nothing else.
// ---------------------------------------------------------------------------

/// Spawns a minimal framed guest on a Unix socket that completes the
/// bootstrap handshake and echoes every exec request back with exit code 0.
async fn spawn_mock_guest(sandbox_id: &str) -> PathBuf {
    // Keep the socket path short: overlong Unix socket paths exceed SUN_LEN
    // and fail bind. A process-scoped atomic counter keeps names unique
    // across parallel tests without long identifiers.
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let socket_path = std::env::temp_dir().join(format!("cr-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let sandbox_id = sandbox_id.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_handshake(&mut stream, &sandbox_id).await.unwrap();
        while let Ok((tag, bytes)) = framed::read_tagged_raw(&mut stream, TIMEOUT).await {
            if tag != framed::TAG_EXEC_REQUEST {
                continue;
            }
            let request = GuestExecRequest::decode(bytes.as_slice()).unwrap_or_default();
            let stdout = ExecResponse {
                frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                    frame: Some(StreamFrame {
                        sequence: 1,
                        payload: format!("ran:{}\n", request.command).into_bytes(),
                        end_of_stream: true,
                    }),
                })),
            };
            if framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &stdout, TIMEOUT)
                .await
                .is_err()
            {
                return;
            }
            // Wire format: exit_code (i32 BE) + duration_ms (u64 BE).
            let mut payload = Vec::new();
            payload.extend_from_slice(&0i32.to_be_bytes());
            payload.extend_from_slice(&7u64.to_be_bytes());
            let outcome = ExecResponse {
                frame: Some(exec_response::Frame::Outcome(OperationOutcome {
                    status: Some(operation_outcome::Status::Success(
                        operation_outcome::Success {
                            result_payload: payload,
                        },
                    )),
                })),
            };
            if framed::send_tagged(&mut stream, framed::TAG_EXEC_RESPONSE, &outcome, TIMEOUT)
                .await
                .is_err()
            {
                return;
            }
        }
    });
    socket_path
}

async fn serve_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    sandbox_id: &str,
) -> std::io::Result<()> {
    let shared = crypto::derive_handshake_shared_secret(sandbox_id);
    let host_hello = framed::read_message::<HostHello>(stream, TIMEOUT)
        .await
        .map_err(io_err)?;
    let host_nonce = host_hello
        .host_nonce
        .as_ref()
        .map(|n| n.value.as_slice())
        .unwrap_or(&[]);
    let guest_nonce = crypto::generate_nonce();
    let identity_version = "restart-acceptance-guest";
    let boot_id = "boot-restart-acceptance";
    let image_id = host_hello.image_id.clone();
    let image_digest = host_hello.image_digest.clone();

    let mut transcript: heapless::Vec<u8, 512> = heapless::Vec::new();
    let _ = transcript.extend_from_slice(b"pico.guest.bootstrap.v1|guest");
    let _ = transcript.extend_from_slice(host_nonce);
    let _ = transcript.extend_from_slice(&guest_nonce);
    let _ = transcript.extend_from_slice(identity_version.as_bytes());
    let _ = transcript.extend_from_slice(boot_id.as_bytes());
    let _ = transcript.extend_from_slice(image_id.as_bytes());
    let _ = transcript.extend_from_slice(image_digest.as_bytes());
    let proof = crypto::blake3_mac(&shared, &transcript);

    let guest_hello = GuestHello {
        supported_versions: vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }],
        guest_capabilities: Some(CapabilitySet {
            identifiers: vec![
                "exec".into(),
                "file".into(),
                "mount".into(),
                "stats".into(),
                "health".into(),
                "shutdown".into(),
            ],
        }),
        guest_nonce: Some(Nonce {
            value: guest_nonce.to_vec(),
        }),
        agent_version: identity_version.into(),
        boot_id: boot_id.into(),
        image_id,
        image_digest,
        proof: Some(Proof {
            value: proof.to_vec(),
        }),
    };
    framed::send_message(stream, &guest_hello, TIMEOUT)
        .await
        .map_err(io_err)?;
    let _host_reply = framed::read_message::<HostReply>(stream, TIMEOUT)
        .await
        .map_err(io_err)?;
    let result = HandshakeResult {
        outcome: Some(handshake_result::Outcome::Established(true)),
    };
    framed::send_message(stream, &result, TIMEOUT)
        .await
        .map_err(io_err)?;
    Ok(())
}

fn io_err(err: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

// ---------------------------------------------------------------------------
// sandboxd server harness over a temp Unix socket.
// ---------------------------------------------------------------------------

struct SandboxdServer {
    _dir: TempDir,
    socket: PathBuf,
    ledger: PathBuf,
    workspace: PathBuf,
}

impl SandboxdServer {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let workspace = dir.path().join("workspaces");
        std::fs::create_dir_all(&workspace).unwrap();
        Self {
            socket: dir.path().join("sandboxd.sock"),
            ledger: dir.path().join("state.db"),
            workspace,
            _dir: dir,
        }
    }

    fn config(&self) -> SandboxdConfig {
        SandboxdConfig {
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
        }
    }

    fn supervisor(&self, require_guest_session: bool) -> SandboxSupervisor {
        SandboxSupervisor::open(
            &self.ledger,
            HostResourceConfig::new(self.workspace.clone()),
        )
        .unwrap()
        .with_guest_session(require_guest_session)
    }

    async fn serve(
        &self,
        supervisor: SandboxSupervisor,
        registry: AdapterRegistry,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let config = self.config();
        let listener = bind_uds(&self.socket).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let serve = serve_uds(listener, supervisor, registry, &config, async move {
                let _ = shutdown_rx.await;
            });
            let _ = serve.await;
        });
        (task, shutdown_tx)
    }

    async fn connect_client(&self) -> SandboxdHandle {
        SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: self.socket.clone(),
                auth_token: TOKEN.into(),
            },
            TIMEOUT,
        )
        .await
        .expect("connect sandboxd")
    }

    async fn connect_agent(&self) -> HostAgent {
        let sandboxd = self.connect_client().await;
        HostAgent::with_sandboxd(
            self.workspace.clone(),
            300,
            RuntimeType::Firecracker,
            sandboxd,
        )
        .expect("host agent")
    }
}

fn registry_with_backends<F>(make: F) -> AdapterRegistry
where
    F: Fn() -> Arc<MockBackend> + Send + Sync + 'static,
{
    let mut registry = AdapterRegistry::new();
    registry.register(RuntimeType::Firecracker, move || make());
    registry
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
        service_class: None,
    }
}

fn exec_request(command: &str) -> ExecRequest {
    ExecRequest {
        command: command.into(),
        args: vec![],
        env: None,
        working_dir: None,
        timeout_secs: Some(5),
    }
}

// ---------------------------------------------------------------------------
// Acceptance scenario 1: Running sandbox survives a host-agent restart.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn running_sandbox_survives_host_agent_restart_and_still_execs() {
    let sandbox_id = "sbx_host_restart";
    let guest = spawn_mock_guest(sandbox_id).await;

    let server = SandboxdServer::new();
    let supervisor = server.supervisor(true);
    supervisor.reconcile().await.unwrap();
    let registry = registry_with_backends(move || {
        Arc::new(MockBackend::new(MockBackendConfig {
            guest_transport_path: guest.display().to_string(),
            ..MockBackendConfig::default()
        }))
    });
    let (_task, _shutdown) = server.serve(supervisor, registry).await;

    let agent_a = server.connect_agent().await;
    let info = agent_a.create_sandbox(spec(sandbox_id)).await.unwrap();
    assert_eq!(info.state, SandboxState::Running);
    let response = agent_a
        .exec(sandbox_id, exec_request("true"))
        .await
        .unwrap();
    assert_eq!(response.exit_code, 0);

    // The host-agent "dies" and a brand new agent connects to the surviving
    // sandboxd. Its sandbox map starts empty...
    let agent_b = server.connect_agent().await;
    let (before, _) = agent_b.list_sandboxes_paginated(10, None).await.unwrap();
    assert!(
        before.is_empty(),
        "fresh host-agent must not invent entries"
    );

    // ...until it rehydrates from sandboxd observations.
    let rehydrated = agent_b.rehydrate_from_sandboxd().await.unwrap();
    assert_eq!(rehydrated, 1);
    let (items, _) = agent_b.list_sandboxes_paginated(10, None).await.unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec![sandbox_id],
        "rehydrated host-agent sees exactly the surviving sandbox"
    );
    assert_eq!(
        agent_b.get_status(sandbox_id).await.unwrap(),
        SandboxState::Running
    );

    // Exec still works through the surviving sandboxd, routed via the
    // rehydrated entry's persisted fencing and policy context.
    let response = agent_b
        .exec(sandbox_id, exec_request("echo hello"))
        .await
        .unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("ran:echo hello"));

    // Rehydration is insert-only: a second pass must not duplicate.
    let again = agent_b.rehydrate_from_sandboxd().await.unwrap();
    assert_eq!(again, 0);
    let (items, _) = agent_b.list_sandboxes_paginated(10, None).await.unwrap();
    assert_eq!(items.len(), 1);
}

// ---------------------------------------------------------------------------
// Acceptance scenario 2: killing sandboxd marks the host not ready, and a
// daemon restart never silently creates a second runtime.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sandboxd_outage_marks_host_not_ready_and_restart_never_dual_creates() {
    let sandbox_id = "sbx_daemon_restart";
    let server = SandboxdServer::new();

    let supervisor = server.supervisor(false);
    supervisor.reconcile().await.unwrap();
    let (task, shutdown) = server
        .serve(
            supervisor,
            registry_with_backends(|| Arc::new(MockBackend::default())),
        )
        .await;

    let agent = server.connect_agent().await;
    let info = agent.create_sandbox(spec(sandbox_id)).await.unwrap();
    assert_eq!(info.state, SandboxState::Running);

    // Kill sandboxd: no listener, no supervisor, no runtime ownership.
    let _ = shutdown.send(());
    task.abort();
    let _ = task.await;

    let health = tokio::time::timeout(TIMEOUT, agent.health_with_gc())
        .await
        .expect("health check against dead sandboxd must not hang");
    assert!(
        matches!(health.status, HealthStatus::Degraded),
        "host must not report ready while sandboxd is down: {health:?}"
    );

    // Restart sandboxd on the same durable ledger and workspace. The registry
    // counts backend instantiations: creating one for an existing sandbox
    // would be a silent dual create.
    let backend_creations = Arc::new(AtomicUsize::new(0));
    let restarted = server.supervisor(false);
    restarted.reconcile().await.unwrap();
    let counter = Arc::clone(&backend_creations);
    let registry = registry_with_backends(move || {
        counter.fetch_add(1, AtomicOrdering::SeqCst);
        Arc::new(MockBackend::default())
    });
    let (_task, _shutdown) = server.serve(restarted, registry).await;

    let client = server.connect_client().await;
    let observations = client.list_sandboxes().await.unwrap();
    assert_eq!(
        observations.len(),
        1,
        "ledger must show exactly one sandbox after restart"
    );
    assert_eq!(observations[0].sandbox_id, sandbox_id);
    assert_eq!(observations[0].observed_state, ProtoState::Running as i32);

    // Let the host's own observation loop (watch + periodic list) settle,
    // then prove it never asked for a new runtime for the existing sandbox.
    agent.rehydrate_from_sandboxd().await.unwrap();
    assert_eq!(
        backend_creations.load(AtomicOrdering::SeqCst),
        0,
        "host silently re-created a runtime for an existing sandbox"
    );
    let (items, _) = agent.list_sandboxes_paginated(10, None).await.unwrap();
    assert_eq!(items.len(), 1, "host still tracks exactly one sandbox");
    assert_eq!(
        agent.get_status(sandbox_id).await.unwrap(),
        SandboxState::Running
    );

    // sandboxd reconciled before serving (matching the binary entrypoint), so
    // host health recovers once the daemon is reachable again.
    let health = tokio::time::timeout(TIMEOUT, agent.health_with_gc())
        .await
        .expect("health check against restarted sandboxd must not hang");
    assert!(
        matches!(health.status, HealthStatus::Ready),
        "host must recover readiness once sandboxd reconciles: {health:?}"
    );
}

// ---------------------------------------------------------------------------
// Guest-session path (production-required for real backends): a sandboxd
// restart drops the session with the supervisor, and exec must fail closed
// until a fresh prepare re-attaches a runtime handle.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_fails_closed_until_runtime_reattaches_after_sandboxd_restart() {
    let sandbox_id = "sbx_session_restart";
    let guest = spawn_mock_guest(sandbox_id).await;
    let guest_path = guest.display().to_string();
    let server = SandboxdServer::new();

    let supervisor = server.supervisor(true);
    supervisor.reconcile().await.unwrap();
    let first_path = guest_path.clone();
    let registry = registry_with_backends(move || {
        Arc::new(MockBackend::new(MockBackendConfig {
            guest_transport_path: first_path.clone(),
            ..MockBackendConfig::default()
        }))
    });
    let (task, shutdown) = server.serve(supervisor, registry).await;

    let agent = server.connect_agent().await;
    let info = agent.create_sandbox(spec(sandbox_id)).await.unwrap();
    assert_eq!(info.state, SandboxState::Running);
    let response = agent.exec(sandbox_id, exec_request("true")).await.unwrap();
    assert_eq!(response.exit_code, 0);

    // Kill sandboxd: the framed guest session dies with the supervisor even
    // though the mock guest listener outlives it.
    let _ = shutdown.send(());
    task.abort();
    let _ = task.await;

    // Restart with guest sessions required, as in production. Runtime handles
    // and guest sessions are process-local and never re-adopted.
    let restarted = server.supervisor(true);
    restarted.reconcile().await.unwrap();
    let guest_path = guest.display().to_string();
    let registry = registry_with_backends(move || {
        Arc::new(MockBackend::new(MockBackendConfig {
            guest_transport_path: guest_path.clone(),
            ..MockBackendConfig::default()
        }))
    });
    let (_task, _shutdown) = server.serve(restarted, registry).await;

    // The agent channel lazily reconnects after the daemon restart; the first
    // RPC can race the transport teardown, so gate on health until the channel
    // is proven live (matching how the background observation loop recovers).
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let health = agent.health_with_gc().await;
        if matches!(health.status, HealthStatus::Ready) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent channel never reconnected to restarted sandboxd"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The surviving agent already tracks the sandbox: rehydration must be a
    // no-op here (insert-only), which is also the no-dual-create invariant.
    let rehydrated = agent.rehydrate_from_sandboxd().await.unwrap();
    assert_eq!(rehydrated, 0);
    // `SandboxNotFound` is the supervisor's RuntimeNotAttached crossing the
    // wire: the sandbox is known, but its runtime ownership is unrecoverable
    // after restart, so exec must fail closed rather than fabricate output.
    let err = agent
        .exec(sandbox_id, exec_request("true"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, pico_core::SandboxError::SandboxNotFound(_)),
        "exec must fail closed after sandboxd restart, got {err:?}"
    );
}
