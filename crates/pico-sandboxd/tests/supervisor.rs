use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pico_core::{
    BackendOperation, ExecRequest, FencingToken, OperationId, RuntimeBackend, SandboxConfig,
    SandboxId, SandboxState,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::{
    CommandContext, HostResourceConfig, HostResourceSpec, OutcomeReason, OutcomeStatus,
    ProcessRequest, SandboxSupervisor, SupervisorError,
};

mod common;
use common::mock_guest;

fn sandbox_id() -> SandboxId {
    SandboxId::from_string("sbx_supervisor_test")
}

fn config() -> SandboxConfig {
    SandboxConfig {
        id: sandbox_id().into_inner().to_string(),
        network_isolated: true,
        ..Default::default()
    }
}

fn command(sequence: u64, timeout: Duration) -> CommandContext {
    CommandContext::with_timeout(
        sandbox_id(),
        OperationId::generate(),
        FencingToken { epoch: 1, sequence },
        1,
        timeout,
    )
}

async fn running_supervisor() -> (SandboxSupervisor, MockBackend) {
    let supervisor = SandboxSupervisor::in_memory();
    // Keep the socket path short: overlong Unix socket paths exceed SUN_LEN
    // and fail bind.
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let socket_path = std::env::temp_dir().join(format!("cs-{}-{n}.sock", std::process::id()));
    mock_guest::spawn_mock_guest_session_unix(sandbox_id().as_str(), &socket_path).await;
    let backend = MockBackend::new(MockBackendConfig {
        guest_transport_path: socket_path.display().to_string(),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());
    let prepare = supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded);
    let boot = supervisor
        .boot(command(2, Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);
    assert!(supervisor.has_guest_session(&sandbox_id()).await);
    (supervisor, backend)
}

struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "pico-sandboxd-{}.db",
                OperationId::generate().as_str()
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-shm", "-wal"] {
            let mut value = self.path.as_os_str().to_os_string();
            value.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(value));
        }
    }
}

#[tokio::test]
async fn supervisor_runs_mock_runtime_from_prepare_to_destroy() {
    let (supervisor, backend) = running_supervisor().await;
    let exec = ExecRequest {
        command: "true".into(),
        args: Vec::new(),
        env: None,
        working_dir: None,
        timeout_secs: Some(1),
    };

    let (exec_outcome, response) = supervisor
        .exec(command(3, Duration::from_secs(1)), exec)
        .await
        .unwrap();
    assert_eq!(exec_outcome.status, OutcomeStatus::Succeeded);
    assert_eq!(response.unwrap().exit_code, 0);

    let destroy = supervisor
        .destroy(command(4, Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded);
    let status = supervisor.status(&sandbox_id()).await.unwrap().unwrap();
    assert_eq!(status.observed_state, SandboxState::Destroyed);
    assert_eq!(
        backend.operations().await,
        vec![
            BackendOperation::Prepare,
            BackendOperation::Boot,
            BackendOperation::AttachTransport,
            BackendOperation::Exec,
            BackendOperation::Destroy,
            BackendOperation::Cleanup,
        ]
    );
}

#[tokio::test]
async fn terminal_operation_replay_returns_persisted_outcome() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::default();
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());
    let context = command(1, Duration::from_secs(1));

    let first = supervisor
        .prepare(
            context.clone(),
            Arc::clone(&runtime),
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let replay = supervisor
        .prepare(context, runtime, &config(), &HostResourceSpec::default())
        .await
        .unwrap();

    assert_eq!(replay, first);
    assert_eq!(backend.operations().await, vec![BackendOperation::Prepare]);
}

#[tokio::test]
async fn stale_fencing_token_is_rejected_before_runtime_side_effects() {
    let (supervisor, backend) = running_supervisor().await;
    let stale = CommandContext::with_timeout(
        sandbox_id(),
        OperationId::generate(),
        FencingToken {
            epoch: 1,
            sequence: 1,
        },
        1,
        Duration::from_secs(1),
    );
    let request = ExecRequest {
        command: "true".into(),
        args: Vec::new(),
        env: None,
        working_dir: None,
        timeout_secs: Some(1),
    };

    let error = supervisor.exec(stale, request).await.unwrap_err();

    assert!(matches!(error, SupervisorError::StaleFencingToken { .. }));
    assert_eq!(
        backend.operations().await,
        vec![
            BackendOperation::Prepare,
            BackendOperation::Boot,
            BackendOperation::AttachTransport,
        ]
    );
}

#[tokio::test]
async fn stale_policy_epoch_is_rejected_before_side_effects() {
    let (supervisor, backend) = running_supervisor().await;
    let stale = CommandContext::with_timeout(
        sandbox_id(),
        OperationId::generate(),
        FencingToken {
            epoch: 1,
            sequence: 3,
        },
        0,
        Duration::from_secs(1),
    );
    let request = ExecRequest {
        command: "true".into(),
        args: Vec::new(),
        env: None,
        working_dir: None,
        timeout_secs: Some(1),
    };

    let error = supervisor.exec(stale, request).await.unwrap_err();

    assert!(matches!(error, SupervisorError::StalePolicyEpoch { .. }));
    assert_eq!(
        backend.operations().await,
        vec![
            BackendOperation::Prepare,
            BackendOperation::Boot,
            BackendOperation::AttachTransport,
        ]
    );
}

#[tokio::test]
async fn runtime_operation_can_be_canceled_explicitly() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Delay {
            operation: BackendOperation::Boot,
            duration: Duration::from_secs(5),
        }),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());
    supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let context = command(2, Duration::from_secs(10));
    let operation_id = context.operation_id.clone();
    let daemon = supervisor.clone();
    let task = tokio::spawn(async move { daemon.boot(context).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert!(supervisor.cancel(&operation_id).await);
    let outcome = task.await.unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Canceled);
    assert_eq!(outcome.reason, OutcomeReason::CanceledByHost);
}

#[tokio::test]
async fn runtime_operation_enforces_absolute_deadline() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Delay {
            operation: BackendOperation::Boot,
            duration: Duration::from_secs(1),
        }),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend);
    supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();

    let outcome = supervisor
        .boot(command(2, Duration::from_millis(10)))
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::TimedOut);
    assert_eq!(outcome.reason, OutcomeReason::DeadlineExceeded);
    assert_eq!(
        outcome.non_ready_reason,
        Some(pico_core::NonReadyReason::Timeout)
    );
}

#[tokio::test]
async fn readiness_failure_is_typed_cleaned_up_and_replayed() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::NotReady {
            operation: BackendOperation::AttachTransport,
            reason: pico_core::NonReadyReason::Protocol,
        }),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());
    supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let context = command(2, Duration::from_secs(1));

    let first = supervisor.boot(context.clone()).await.unwrap();
    let replay = supervisor.boot(context).await.unwrap();

    assert_eq!(first.status, OutcomeStatus::Failed);
    assert_eq!(
        first.non_ready_reason,
        Some(pico_core::NonReadyReason::Protocol)
    );
    assert_eq!(replay, first);
    assert!(!supervisor.has_guest_session(&sandbox_id()).await);
    assert_eq!(
        backend.operations().await,
        vec![
            BackendOperation::Prepare,
            BackendOperation::Boot,
            BackendOperation::AttachTransport,
            BackendOperation::Cleanup,
        ]
    );
}

#[tokio::test]
async fn boot_fail_closed_without_guest_does_not_mark_running() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::default();
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());
    supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();

    let outcome = supervisor
        .boot(command(2, Duration::from_millis(200)))
        .await
        .unwrap();
    let status = supervisor.status(&sandbox_id()).await.unwrap().unwrap();

    assert_ne!(outcome.status, OutcomeStatus::Succeeded);
    assert_ne!(status.observed_state, SandboxState::Running);
    assert!(!supervisor.has_guest_session(&sandbox_id()).await);
    assert!(
        !backend
            .operations()
            .await
            .contains(&BackendOperation::WaitReady)
    );
}

#[tokio::test]
async fn incomplete_runtime_setup_is_cleaned_without_degrading_health() {
    let supervisor = SandboxSupervisor::in_memory();
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::IncompleteSetup {
            operation: BackendOperation::Prepare,
        }),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend.clone());

    let outcome = supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let health = supervisor.health().await;

    assert_eq!(outcome.status, OutcomeStatus::Failed);
    assert_eq!(health.review_required, 0);
    assert_eq!(
        backend.operations().await,
        vec![BackendOperation::Prepare, BackendOperation::Cleanup]
    );
}

#[tokio::test]
async fn runtime_handle_survives_host_agent_client_restart() {
    let (daemon, _) = running_supervisor().await;
    let host_agent_client = daemon.clone();
    drop(host_agent_client);
    let restarted_host_agent_client = daemon.clone();
    let request = ExecRequest {
        command: "status".into(),
        args: Vec::new(),
        env: None,
        working_dir: None,
        timeout_secs: Some(1),
    };

    let (outcome, response) = restarted_host_agent_client
        .exec(command(3, Duration::from_secs(1)), request)
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    assert_eq!(response.unwrap().stdout, "status");
}

#[tokio::test]
async fn daemon_restart_marks_interrupted_operation_for_review() {
    let database = TempDatabase::new();
    let supervisor = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(database.path().with_extension("workspaces")),
    )
    .unwrap();
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Delay {
            operation: BackendOperation::Boot,
            duration: Duration::from_secs(5),
        }),
        ..MockBackendConfig::default()
    });
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(backend);
    supervisor
        .prepare(
            command(1, Duration::from_secs(1)),
            runtime,
            &config(),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let daemon = supervisor.clone();
    let task = tokio::spawn(async move { daemon.boot(command(2, Duration::from_secs(10))).await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    task.abort();
    let _ = task.await;
    drop(supervisor);

    let restarted = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(database.path().with_extension("workspaces")),
    )
    .unwrap();
    let status = restarted.status(&sandbox_id()).await.unwrap().unwrap();
    let health = restarted.health().await;

    assert_eq!(status.observed_state, SandboxState::Booting);
    assert_eq!(health.review_required, 1);
}

#[tokio::test]
#[cfg_attr(not(unix), ignore)]
async fn process_exit_captures_bounded_streams_and_releases_handles() {
    let (supervisor, _) = running_supervisor().await;
    let mut request = ProcessRequest::new("/bin/cat");
    request.stdin = b"hello sandboxd".to_vec();

    let output = supervisor
        .run_process(command(3, Duration::from_secs(1)), request)
        .await
        .unwrap();
    let health = supervisor.health().await;

    assert_eq!(output.outcome.status, OutcomeStatus::Succeeded);
    assert_eq!(output.stdout, b"hello sandboxd");
    assert_eq!(health.process_handles, 0);
    assert_eq!(health.stream_handles, 0);
    assert_eq!(health.pidfd_handles, 0);
}

#[tokio::test]
#[cfg_attr(not(unix), ignore)]
async fn process_cancellation_kills_process_tree_and_releases_handles() {
    let (supervisor, _) = running_supervisor().await;
    let context = command(3, Duration::from_secs(10));
    let operation_id = context.operation_id.clone();
    let daemon = supervisor.clone();
    let task = tokio::spawn(async move {
        daemon
            .run_process(context, ProcessRequest::new("/bin/sleep").with_arg("5"))
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert!(supervisor.cancel(&operation_id).await);
    let output = task.await.unwrap();
    let health = supervisor.health().await;

    assert_eq!(output.outcome.status, OutcomeStatus::Canceled);
    assert_eq!(health.process_handles, 0);
    assert_eq!(health.stream_handles, 0);
}

#[tokio::test]
#[cfg_attr(not(unix), ignore)]
async fn process_timeout_kills_process_and_releases_handles() {
    let (supervisor, _) = running_supervisor().await;
    let request = ProcessRequest::new("/bin/sleep").with_arg("5");

    let output = supervisor
        .run_process(command(3, Duration::from_millis(10)), request)
        .await
        .unwrap();
    let health = supervisor.health().await;

    assert_eq!(output.outcome.status, OutcomeStatus::TimedOut);
    assert_eq!(health.process_handles, 0);
    assert_eq!(health.stream_handles, 0);
}

trait ProcessRequestTestExt {
    fn with_arg(self, arg: &str) -> Self;
}

impl ProcessRequestTestExt for ProcessRequest {
    fn with_arg(mut self, arg: &str) -> Self {
        self.args.push(arg.into());
        self
    }
}

#[tokio::test]
async fn observation_includes_requested_ports_and_generation() {
    use pico_sandboxd::{ObservationWatchEvent, ResolvedPortTarget};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration as TokioDuration, timeout};

    let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
    let id = SandboxId::from_string("sbx_obs_ports");
    let mut rx = supervisor.subscribe_watch();
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::default());
    let config = SandboxConfig {
        id: id.as_str().into(),
        ..Default::default()
    };
    let host = HostResourceSpec {
        requested_ports: vec![8080, 8443],
        ..HostResourceSpec::default()
    };
    let prepare = supervisor
        .prepare(
            CommandContext::with_timeout(
                id.clone(),
                OperationId::generate(),
                FencingToken {
                    epoch: 1,
                    sequence: 1,
                },
                1,
                Duration::from_secs(1),
            ),
            runtime,
            &config,
            &host,
        )
        .await
        .unwrap();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded);

    let snapshot = supervisor.observation(&id).await.unwrap().unwrap();
    assert!(snapshot.generation >= 1);
    assert_eq!(snapshot.ports.len(), 2);
    assert_eq!(
        snapshot.ports[0].target,
        ResolvedPortTarget::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)))
    );

    let (port, generation) = supervisor.port_target(&id, 8080).await.unwrap().unwrap();
    assert_eq!(port.guest_port, 8080);
    assert_eq!(generation, snapshot.generation);
    assert!(
        supervisor.port_target(&id, 9).await.unwrap().is_none(),
        "unrequested port must fail closed"
    );

    let event = timeout(TokioDuration::from_secs(1), rx.recv())
        .await
        .expect("watch upsert timeout")
        .unwrap();
    match event {
        ObservationWatchEvent::Upsert(obs) => {
            assert_eq!(obs.status.sandbox_id, id);
            assert_eq!(obs.ports.len(), 2);
        }
        other => panic!("expected upsert, got {other:?}"),
    }

    let before = snapshot.generation;
    let boot = supervisor
        .boot(CommandContext::with_timeout(
            id.clone(),
            OperationId::generate(),
            FencingToken {
                epoch: 1,
                sequence: 2,
            },
            1,
            Duration::from_secs(1),
        ))
        .await
        .unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);
    let after_boot = supervisor.observation(&id).await.unwrap().unwrap();
    assert!(after_boot.generation > before);

    let destroy = supervisor
        .destroy(CommandContext::with_timeout(
            id.clone(),
            OperationId::generate(),
            FencingToken {
                epoch: 1,
                sequence: 3,
            },
            1,
            Duration::from_secs(1),
        ))
        .await
        .unwrap();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded);
    // Ledger may retain a Destroyed row; live handle (ports/generation) is gone.
    if let Some(after_destroy) = supervisor.observation(&id).await.unwrap() {
        assert_eq!(after_destroy.status.observed_state, SandboxState::Destroyed);
        assert!(after_destroy.ports.is_empty());
        assert_eq!(after_destroy.generation, 0);
    }
    assert!(supervisor.port_target(&id, 8080).await.unwrap().is_none());

    // Drain intermediate upserts until Removed. A successful destroy must
    // not publish an upsert that still carries live port targets.
    let mut saw_removed = false;
    for _ in 0..8 {
        let event = timeout(TokioDuration::from_secs(1), rx.recv())
            .await
            .expect("watch event timeout")
            .unwrap();
        match event {
            ObservationWatchEvent::Removed(ref gone) if gone == &id => {
                saw_removed = true;
                break;
            }
            ObservationWatchEvent::Upsert(ref obs)
                if obs.status.observed_state == SandboxState::Destroyed
                    && !obs.ports.is_empty() =>
            {
                panic!("destroy must not upsert live ports");
            }
            _ => {}
        }
    }
    assert!(saw_removed, "destroy must publish Removed watch event");
}

#[tokio::test]
async fn empty_requested_ports_fail_closed_on_get_port_target() {
    let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
    let id = SandboxId::from_string("sbx_no_ports");
    let runtime: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::default());
    let config = SandboxConfig {
        id: id.as_str().into(),
        ..Default::default()
    };
    let prepare = supervisor
        .prepare(
            CommandContext::with_timeout(
                id.clone(),
                OperationId::generate(),
                FencingToken {
                    epoch: 1,
                    sequence: 1,
                },
                1,
                Duration::from_secs(1),
            ),
            runtime,
            &config,
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded);
    assert!(
        supervisor.port_target(&id, 8080).await.unwrap().is_none(),
        "empty requested_ports must not resolve any guest port"
    );
    let snapshot = supervisor.observation(&id).await.unwrap().unwrap();
    assert!(snapshot.ports.is_empty());
}

#[tokio::test]
async fn resume_bumps_generation_on_observation() {
    let (supervisor, _) = running_supervisor().await;
    let id = sandbox_id();
    let before = supervisor
        .observation(&id)
        .await
        .unwrap()
        .unwrap()
        .generation;

    let suspend = supervisor
        .suspend(command(3, Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(suspend.status, OutcomeStatus::Succeeded);
    let resume = supervisor
        .resume(command(4, Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(resume.status, OutcomeStatus::Succeeded);

    let after = supervisor
        .observation(&id)
        .await
        .unwrap()
        .unwrap()
        .generation;
    assert!(
        after > before,
        "resume must bump generation (before={before}, after={after})"
    );
}
