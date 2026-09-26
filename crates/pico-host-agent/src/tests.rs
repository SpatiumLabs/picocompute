use std::sync::Arc;
use std::time::Duration;

use pico_core::{
    ExecRequest, FencingToken, OperationId, RuntimeType, SandboxSpec, SandboxState, TaskEvent,
    TaskRequest, TaskState,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::config::SandboxdConfig;
use pico_sandboxd::grpc::server::{bind_uds, serve_uds};
use pico_sandboxd::registry::AdapterRegistry;
use pico_sandboxd::{HostResourceConfig, SandboxSupervisor};
use tempfile::TempDir;

use super::*;
use crate::boot::{BootCommand, BootStatus};
use crate::sandboxd_client::{SandboxdConnect, SandboxdHandle};
use crate::util::port_bind_error;

const TOKEN: &str = "test-host-sandboxd-token";

fn assert_lifecycle_facade<T: pico_core::SandboxFacade>() {}

#[test]
fn host_agent_implements_narrow_facade() {
    assert_lifecycle_facade::<HostAgent>();
}

struct TestHarness {
    _dir: TempDir,
    agent: HostAgent,
    server: tokio::task::JoinHandle<()>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Signal the in-process sandboxd server to stop serving, then abort
        // the task as a backstop so a hanging server cannot leak into the
        // next test's runtime.
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(());
        }
        self.server.abort();
    }
}

impl TestHarness {
    async fn new() -> Self {
        Self::with_idle_timeout(Duration::from_secs(300)).await
    }

    async fn with_idle_timeout(idle: Duration) -> Self {
        Self::with_backends(idle, |_| {}).await
    }

    async fn with_backends<F>(idle: Duration, configure: F) -> Self
    where
        F: FnOnce(&mut AdapterRegistry),
    {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("sandboxd.sock");
        let ledger = dir.path().join("state.db");
        let workspace = dir.path().join("workspaces");
        std::fs::create_dir_all(&workspace).unwrap();

        let supervisor =
            SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
                .unwrap()
                .with_guest_session(false);
        supervisor.reconcile().await.unwrap();

        let mut registry = AdapterRegistry::new();
        registry.register(
            RuntimeType::Firecracker,
            || Arc::new(MockBackend::default()),
        );
        registry.register(RuntimeType::Qemu, || Arc::new(MockBackend::default()));
        configure(&mut registry);

        let config = SandboxdConfig {
            socket_path: socket.clone(),
            auth_token: TOKEN.into(),
            ledger_path: ledger,
            workspace_root: workspace.clone(),
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
            let _ = serve.await;
        });

        let sandboxd = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: socket,
                auth_token: TOKEN.into(),
            },
            Duration::from_secs(5),
        )
        .await
        .expect("connect sandboxd");

        let agent = HostAgent::with_sandboxd(
            workspace,
            idle.as_secs().max(1),
            RuntimeType::Firecracker,
            sandboxd,
        )
        .expect("host agent");

        Self {
            _dir: dir,
            agent,
            server,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Builds a boot command that matches this agent's identity so admission
    /// checks pass (and every negative test can override a single field).
    fn boot_command(&self, id: &str) -> BootCommand {
        BootCommand {
            sandbox_id: id.to_string(),
            operation_id: OperationId::generate(),
            assigned_host_id: self.agent.identity.host_id.clone(),
            assigned_cell_id: self.agent.identity.cell_id.clone(),
            assignment_fencing_token: FencingToken {
                epoch: 1,
                sequence: 1,
            },
            policy_epoch: 1,
            timeout_secs: 30,
        }
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
async fn prepare_keeps_sandbox_preparing_until_boot() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .prepare_sandbox(spec("sbx_prepare"))
        .await
        .unwrap();
    assert_eq!(info.state, SandboxState::Preparing);
}

#[tokio::test]
async fn boot_transitions_prepared_sandbox_to_running() {
    let harness = TestHarness::new().await;
    let prepared = harness
        .agent
        .prepare_sandbox(spec("sbx_boot"))
        .await
        .unwrap();
    let info = harness
        .agent
        .boot_prepared_sandbox(&prepared.id)
        .await
        .unwrap();
    assert_eq!(info.state, SandboxState::Running);
}

#[tokio::test]
async fn create_sandbox_prepare_and_boot() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_create"))
        .await
        .unwrap();
    assert_eq!(info.state, SandboxState::Running);
}

#[tokio::test]
async fn destroy_removes_sandbox() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_destroy"))
        .await
        .unwrap();
    harness.agent.destroy(&info.id).await.unwrap();
    let err = harness.agent.get_sandbox(&info.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn destroy_revokes_all_known_credential_leases() {
    use pico_core::event_bus::InMemoryAuditSink;
    use pico_core::secrets::mock::MockSecretsBroker;
    use pico_core::{
        AuditEventKind, LeaseAction, LeaseManager, LeaseScope, LeaseValidationError,
        PolicyDecision, PolicyDecisionId, PolicyOutcome, PrincipalId, SandboxId, TenantId,
    };

    let sink = Arc::new(InMemoryAuditSink::new());
    let lease_sink: Arc<dyn pico_core::event_bus::AuditEventSink> =
        Arc::<InMemoryAuditSink>::clone(&sink);
    let hlc = Arc::new(pico_core::Hlc::new());
    let lease_mgr = Arc::new(LeaseManager::with_audit_sink(lease_sink, Arc::clone(&hlc)));
    let decision = PolicyDecision {
        decision_id: PolicyDecisionId::generate(),
        outcome: PolicyOutcome::Allow,
        policy_epoch: 1,
    };
    let tenant = TenantId::from_string("tnt_destroy_revoke");
    let sbx = SandboxId::from_string("sbx_destroy_revoke");
    let subject = PrincipalId::new("user:alice");
    let a = lease_mgr.issue(
        tenant.clone(),
        subject.clone(),
        sbx.clone(),
        pico_core::LeaseAction::CredentialAccess,
        LeaseScope::unbounded(),
        &decision,
        3600,
    );
    let b = lease_mgr.issue(
        tenant.clone(),
        subject,
        sbx.clone(),
        LeaseAction::Exec,
        LeaseScope::unbounded(),
        &decision,
        3600,
    );

    let broker = Arc::new(MockSecretsBroker::new());
    let coordinator = Arc::new(crate::secrets::SecretsCoordinator::new(
        broker as Arc<dyn pico_core::secrets::SecretsBroker>,
        Arc::clone(&lease_mgr),
        Arc::<InMemoryAuditSink>::clone(&sink) as Arc<dyn pico_core::event_bus::AuditEventSink>,
        Arc::clone(&hlc),
    ));

    let harness = TestHarness::new().await;
    let agent = harness.agent.clone().with_secrets(Arc::clone(&coordinator));
    let mut create_spec = spec("sbx_destroy_revoke");
    create_spec.credential_request = Some(pico_core::CredentialRequestSpec {
        tenant_id: tenant.clone(),
        lease_id: a.lease_id.clone(),
        policy_decision_id: None,
        credential_types: vec![],
        lease: None,
    });
    // Use prepare (not create/boot) so no guest session is needed; destroy
    // still runs the credential revoke path.
    let info = harness.agent.prepare_sandbox(create_spec).await.unwrap();
    agent.destroy(&info.id).await.unwrap();

    for (id, action) in [
        (&a.lease_id, LeaseAction::CredentialAccess),
        (&b.lease_id, LeaseAction::Exec),
    ] {
        assert!(matches!(
            lease_mgr.validate(id, &sbx, &tenant, action, 1),
            Err(LeaseValidationError::Revoked { .. })
        ));
    }
    let lease_revokes = sink.events_by_kind(AuditEventKind::LeaseRevoked);
    let cred_revokes = sink.events_by_kind(AuditEventKind::CredentialRevoked);
    assert_eq!(lease_revokes.len(), 2);
    assert_eq!(cred_revokes.len(), 2);
    let op = lease_revokes[0].operation_id.clone();
    assert!(op.is_some());
    for e in lease_revokes.iter().chain(cred_revokes.iter()) {
        assert_eq!(e.operation_id, op);
    }
}

#[tokio::test]
async fn stop_then_purge_cleans_up_stopped_sandbox() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_stop"))
        .await
        .unwrap();
    harness.agent.stop(&info.id).await.unwrap();
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Stopped
    );
    // stop() is idempotent: a second stop must not re-issue Destroy against
    // the already-destroyed sandboxd runtime.
    harness.agent.stop(&info.id).await.unwrap();
    harness.agent.purge(&info.id).await.unwrap();
    let err = harness.agent.get_sandbox(&info.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn repeated_stop_disarms_idle_timer_after_keepalive() {
    let harness = TestHarness::with_idle_timeout(Duration::from_millis(25)).await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_stop_rearm"))
        .await
        .unwrap();
    harness.agent.stop(&info.id).await.unwrap();
    harness.agent.keepalive(&info.id).await.unwrap();
    harness.agent.stop(&info.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Stopped
    );
}

#[tokio::test]
async fn purge_rejects_running_sandbox() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_purge_running"))
        .await
        .unwrap();
    let err = harness.agent.purge(&info.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::InvalidStateTransition(_)));
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Running
    );
}

#[tokio::test]
async fn destroy_after_stop_completes_host_teardown() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_stop_destroy"))
        .await
        .unwrap();
    harness.agent.stop(&info.id).await.unwrap();
    // stop() already issued Destroy, so the sandboxd runtime handle is gone;
    // destroy() must tolerate that and still finish host-side cleanup.
    harness.agent.destroy(&info.id).await.unwrap();
    let err = harness.agent.get_sandbox(&info.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn stop_on_prepared_sandbox_is_rejected() {
    let harness = TestHarness::new().await;
    let prepared = harness
        .agent
        .prepare_sandbox(spec("sbx_stop_preparing"))
        .await
        .unwrap();
    let err = harness.agent.stop(&prepared.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::InvalidStateTransition(_)));
    assert_eq!(
        harness.agent.get_status(&prepared.id).await.unwrap(),
        SandboxState::Preparing
    );
    // Rejected stop must not bump the admit token; the original boot
    // command must still pass fencing admission.
    let report = harness
        .agent
        .boot_sandbox(harness.boot_command(&prepared.id))
        .await
        .unwrap();
    assert_eq!(report.status, BootStatus::Ready);
}

#[tokio::test]
async fn stop_on_suspended_sandbox_is_rejected() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_stop_suspended"))
        .await
        .unwrap();
    harness.agent.suspend(&info.id).await.unwrap();
    let err = harness.agent.stop(&info.id).await.unwrap_err();
    assert!(matches!(err, SandboxError::InvalidStateTransition(_)));
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Suspended
    );
    harness.agent.resume(&info.id).await.unwrap();
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Running
    );
}

#[tokio::test]
async fn rehydrate_promotes_legacy_pending_observation_to_preparing() {
    use pico_sandboxd_proto::v1::{RuntimeType as ProtoRuntime, SandboxState as ProtoState};
    let harness = TestHarness::new().await;
    let observation = pico_sandboxd_proto::v1::SandboxObservation {
        sandbox_id: "sbx_legacy_pending".into(),
        observed_state: ProtoState::Pending as i32,
        generation: 1,
        host_boot_id: "boot-1".into(),
        guest_boot_id: String::new(),
        backend: ProtoRuntime::Firecracker as i32,
        ports: Vec::new(),
        ssh: None,
        policy_epoch: 1,
        assignment_fencing_token: "1.0".into(),
        updated_at: String::new(),
    };
    let entry = harness.agent.entry_from_observation(&observation).unwrap();
    assert_eq!(entry.desired_state(), SandboxState::Preparing);
}

#[tokio::test]
async fn rehydrate_skips_unknown_backend() {
    use pico_sandboxd_proto::v1::{RuntimeType as ProtoRuntime, SandboxState as ProtoState};
    let harness = TestHarness::new().await;
    let observation = pico_sandboxd_proto::v1::SandboxObservation {
        sandbox_id: "sbx_unknown_backend".into(),
        observed_state: ProtoState::Running as i32,
        generation: 1,
        host_boot_id: "boot-1".into(),
        guest_boot_id: String::new(),
        backend: 9999,
        ports: Vec::new(),
        ssh: None,
        policy_epoch: 1,
        assignment_fencing_token: "1.0".into(),
        updated_at: String::new(),
    };
    assert!(harness.agent.entry_from_observation(&observation).is_none());
    // Unspecified is also unknown: fail closed instead of defaulting.
    let mut unspecified = observation.clone();
    unspecified.sandbox_id = "sbx_unspecified_backend".into();
    unspecified.backend = ProtoRuntime::Unspecified as i32;
    assert!(harness.agent.entry_from_observation(&unspecified).is_none());
}

#[tokio::test]
async fn rehydrate_derives_gvisor_ssh_username() {
    use pico_sandboxd_proto::v1::{RuntimeType as ProtoRuntime, SandboxState as ProtoState};
    let harness = TestHarness::new().await;
    let observation = pico_sandboxd_proto::v1::SandboxObservation {
        sandbox_id: "sbx_gvisor_rehydrate".into(),
        observed_state: ProtoState::Running as i32,
        generation: 1,
        host_boot_id: "boot-1".into(),
        guest_boot_id: String::new(),
        backend: ProtoRuntime::Gvisor as i32,
        ports: Vec::new(),
        ssh: None,
        policy_epoch: 1,
        assignment_fencing_token: "1.0".into(),
        updated_at: String::new(),
    };
    let entry = harness.agent.entry_from_observation(&observation).unwrap();
    assert_eq!(entry.test_ssh_username(), "user");
}

#[tokio::test]
async fn exec_missing_sandbox_returns_not_found() {
    let harness = TestHarness::new().await;
    let err = harness
        .agent
        .exec(
            "missing",
            ExecRequest {
                command: "true".into(),
                args: vec![],
                env: None,
                working_dir: None,
                timeout_secs: Some(1),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn exec_rejects_non_running_state() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .prepare_sandbox(spec("sbx_pending_exec"))
        .await
        .unwrap();
    let err = harness
        .agent
        .exec(
            &info.id,
            ExecRequest {
                command: "true".into(),
                args: vec![],
                env: None,
                working_dir: None,
                timeout_secs: Some(1),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::InvalidStateTransition(_)));
}

#[tokio::test]
async fn exec_via_sandboxd_rpc_fails_closed_without_guest_session() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_exec"))
        .await
        .unwrap();
    // The MockBackend guest session is disabled, so sandboxd rejects the exec
    // as unavailable; the host must surface the typed NotReady instead of
    // fabricating a success. This still proves the call went through the
    // sandboxd Exec RPC (there is no host-side adapter path anymore).
    let err = harness
        .agent
        .exec(
            &info.id,
            ExecRequest {
                command: "true".into(),
                args: vec![],
                env: None,
                working_dir: None,
                timeout_secs: Some(2),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, SandboxError::NotReady(_)),
        "expected NotReady from sandboxd without a guest session, got {err:?}"
    );
}

#[tokio::test]
async fn suspend_and_resume_roundtrip() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(spec("sbx_suspend"))
        .await
        .unwrap();
    harness.agent.suspend(&info.id).await.unwrap();
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Suspended
    );
    harness.agent.resume(&info.id).await.unwrap();
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Running
    );
}

#[tokio::test]
async fn suspend_missing_sandbox_returns_not_found() {
    let harness = TestHarness::new().await;
    let err = harness.agent.suspend("missing").await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn resume_missing_sandbox_returns_not_found() {
    let harness = TestHarness::new().await;
    let err = harness.agent.resume("missing").await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn destroy_missing_sandbox_returns_not_found() {
    let harness = TestHarness::new().await;
    let err = harness.agent.destroy("missing").await.unwrap_err();
    assert!(matches!(err, SandboxError::SandboxNotFound(_)));
}

#[tokio::test]
async fn boot_report_ready_and_replay() {
    let harness = TestHarness::new().await;
    let prepared = harness
        .agent
        .prepare_sandbox(spec("sbx_boot_report"))
        .await
        .unwrap();
    let command = harness.boot_command(&prepared.id);
    let report = harness.agent.boot_sandbox(command.clone()).await.unwrap();
    assert_eq!(report.status, BootStatus::Ready);
    let replay = harness.agent.boot_sandbox(command).await.unwrap();
    assert_eq!(replay.status, BootStatus::Ready);
}

#[tokio::test]
async fn boot_rejects_assignment_mismatches() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_vbc"))
        .await
        .unwrap();

    let mut wrong_host = harness.boot_command("sbx_vbc");
    wrong_host.assigned_host_id = "other-host".into();
    let err = harness.agent.boot_sandbox(wrong_host).await.unwrap_err();
    assert!(matches!(err, SandboxError::Conflict(_)));

    let mut wrong_cell = harness.boot_command("sbx_vbc");
    wrong_cell.assigned_cell_id = "other-cell".into();
    let err = harness.agent.boot_sandbox(wrong_cell).await.unwrap_err();
    assert!(matches!(err, SandboxError::Conflict(_)));

    // Rejected commands must not consume the sandbox: it stays Preparing.
    assert_eq!(
        harness.agent.get_status("sbx_vbc").await.unwrap(),
        SandboxState::Preparing
    );
}

#[tokio::test]
async fn boot_rejects_invalid_epoch_and_timeout() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_vbc_epoch"))
        .await
        .unwrap();

    let mut zero_epoch = harness.boot_command("sbx_vbc_epoch");
    zero_epoch.policy_epoch = 0;
    let err = harness.agent.boot_sandbox(zero_epoch).await.unwrap_err();
    assert!(matches!(err, SandboxError::BadRequest(_)));

    let mut zero_timeout = harness.boot_command("sbx_vbc_epoch");
    zero_timeout.timeout_secs = 0;
    let err = harness.agent.boot_sandbox(zero_timeout).await.unwrap_err();
    assert!(matches!(err, SandboxError::BadRequest(_)));

    let mut too_long = harness.boot_command("sbx_vbc_epoch");
    too_long.timeout_secs = 301;
    let err = harness.agent.boot_sandbox(too_long).await.unwrap_err();
    assert!(matches!(err, SandboxError::BadRequest(_)));

    assert_eq!(
        harness.agent.get_status("sbx_vbc_epoch").await.unwrap(),
        SandboxState::Preparing
    );
}

#[tokio::test]
async fn boot_rejects_stale_fencing_token() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_vbc_fence"))
        .await
        .unwrap();
    harness
        .agent
        .boot_sandbox(harness.boot_command("sbx_vbc_fence"))
        .await
        .unwrap();

    let mut stale = harness.boot_command("sbx_vbc_fence");
    stale.assignment_fencing_token = FencingToken {
        epoch: 1,
        sequence: 0,
    };
    let err = harness.agent.boot_sandbox(stale).await.unwrap_err();
    assert!(matches!(err, SandboxError::OperationStale(_)));
}

#[tokio::test]
async fn boot_rejects_quota_exceeded_before_rpc() {
    let mut harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_vbc_quota"))
        .await
        .unwrap();
    harness.agent.capacity.memory_mb_total = 32;
    let err = harness
        .agent
        .boot_sandbox(harness.boot_command("sbx_vbc_quota"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SandboxError::QuotaExceeded { .. }),
        "expected QuotaExceeded for a 64 MiB sandbox on a 32 MiB host, got {err:?}"
    );
    assert_eq!(
        harness.agent.get_status("sbx_vbc_quota").await.unwrap(),
        SandboxState::Preparing
    );
}

#[tokio::test]
async fn destroy_failure_with_partial_cleanup_keeps_sandbox_registered() {
    let harness = TestHarness::with_backends(Duration::from_secs(300), |registry| {
        registry.register(RuntimeType::Qemu, || {
            Arc::new(MockBackend::new(MockBackendConfig {
                failure: Some(MockFailure::PartialCleanup {
                    remaining: vec!["mock-tap".into()],
                }),
                ..MockBackendConfig::default()
            }))
        });
    })
    .await;

    let info = harness
        .agent
        .create_sandbox(SandboxSpec {
            runtime: Some(RuntimeType::Qemu),
            ..spec("sbx_partial_cleanup")
        })
        .await
        .unwrap();
    let err = harness.agent.destroy(&info.id).await.unwrap_err();
    // A destroy that leaves resources behind surfaces as a Conflict (cleanup
    // reason); the sandbox must remain registered for operator retry.
    assert!(
        matches!(err, SandboxError::Conflict(_)),
        "expected a typed destroy failure, got {err:?}"
    );
    assert!(
        harness.agent.get_sandbox(&info.id).await.is_ok(),
        "destroy failure must leave the sandbox registered for retry"
    );
    assert_eq!(
        harness.agent.get_status(&info.id).await.unwrap(),
        SandboxState::Failed
    );
}

#[tokio::test]
async fn draining_rejects_new_prepare() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .draining
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let err = harness
        .agent
        .prepare_sandbox(spec("sbx_drain"))
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::Conflict(_)));
}

#[tokio::test]
async fn health_reports_ready_when_sandboxd_up() {
    let harness = TestHarness::new().await;
    let health = harness.agent.health_with_gc().await;
    assert!(health.status.is_serviceable());
}

#[tokio::test]
async fn health_advertises_sandboxd_registered_backends() {
    let harness = TestHarness::with_backends(Duration::from_secs(300), |_registry| {}).await;
    let health = harness.agent.health_with_gc().await;
    // The harness registry registers exactly Firecracker and Qemu, so the host
    // advertisement must mirror that set (sorted) instead of the builtin
    // defaults, which also include RemoteFirecracker and GVisor.
    assert_eq!(
        health.supported_backends,
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        "advertisement must mirror the sandboxd registry"
    );
    let inventory = harness.agent.inventory().await;
    assert_eq!(inventory.supported_backends, health.supported_backends);
}

#[tokio::test]
async fn file_write_then_read_returns_content() {
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .prepare_sandbox(spec("sbx_files"))
        .await
        .unwrap();
    // Workspace is owned by sandboxd under the shared workspace root.
    let written = harness
        .agent
        .file_write(
            &info.id,
            FileWriteRequest {
                path: "hello.txt".into(),
                content: "hi".into(),
                append: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(written.path, "hello.txt");
    let read = harness
        .agent
        .file_read(&info.id, "hello.txt")
        .await
        .unwrap();
    assert_eq!(read.content, "hi");
}

#[tokio::test]
async fn file_list_sorts_and_recurses() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_list"))
        .await
        .unwrap();
    for path in ["b.txt", "dir/a.txt"] {
        harness
            .agent
            .file_write(
                "sbx_list",
                FileWriteRequest {
                    path: path.into(),
                    content: String::new(),
                    append: false,
                },
            )
            .await
            .unwrap();
    }

    let files = harness
        .agent
        .file_list("sbx_list", ".", true)
        .await
        .unwrap();
    let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(paths, vec!["b.txt", "dir", "dir/a.txt"]);
}

#[cfg(unix)]
#[tokio::test]
async fn file_read_rejects_symlink_target() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_symlink_read"))
        .await
        .unwrap();
    let workspace = harness
        .agent
        .workspaces
        .sandbox_dir("sbx_symlink_read")
        .unwrap();
    std::os::unix::fs::symlink("/etc/passwd", workspace.join("link.txt")).unwrap();

    let err = harness
        .agent
        .file_read("sbx_symlink_read", "link.txt")
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::PathEscape(_)));
}

#[cfg(unix)]
#[tokio::test]
async fn file_write_rejects_symlink_target() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_symlink_write"))
        .await
        .unwrap();
    let workspace = harness
        .agent
        .workspaces
        .sandbox_dir("sbx_symlink_write")
        .unwrap();
    let outside = std::env::temp_dir().join(pico_core::new_ulid("pico_outside"));
    std::fs::write(&outside, "outside").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("link.txt")).unwrap();

    let err = harness
        .agent
        .file_write(
            "sbx_symlink_write",
            FileWriteRequest {
                path: "link.txt".into(),
                content: "inside".into(),
                append: false,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::PathEscape(_)));
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside");
}

#[cfg(unix)]
#[tokio::test]
async fn file_write_rejects_symlink_parent() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_symlink_parent"))
        .await
        .unwrap();
    let workspace = harness
        .agent
        .workspaces
        .sandbox_dir("sbx_symlink_parent")
        .unwrap();
    let outside_dir = std::env::temp_dir().join(pico_core::new_ulid("pico_outside"));
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::os::unix::fs::symlink(&outside_dir, workspace.join("dir_link")).unwrap();

    let err = harness
        .agent
        .file_write(
            "sbx_symlink_parent",
            FileWriteRequest {
                path: "dir_link/a.txt".into(),
                content: "inside".into(),
                append: false,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SandboxError::PathEscape(_)));
}

#[tokio::test]
async fn reaper_destroys_idle_sandbox_via_rpc() {
    // The harness truncates sub-second idle timeouts (as_secs().max(1)), so the
    // reaper fires solely from the explicit arm_with_timeout below.
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(SandboxSpec {
            idle_timeout_secs: Some(0),
            ..spec("sbx_reaper")
        })
        .await
        .unwrap();
    harness
        .agent
        .reaper
        .arm_with_timeout(&info.id, Duration::from_millis(10))
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        // The destroyer must have issued the sandboxd Destroy RPC and removed
        // the host entry; anything else means the idle-reaper path regressed.
        // Poll instead of sleeping once so the assertion holds on loaded CI.
        if harness.agent.get_sandbox(&info.id).await.is_err() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "idle sandbox was not destroyed by the reaper within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn keepalive_missing_returns_not_found() {
    let harness = TestHarness::new().await;
    assert!(matches!(
        harness.agent.keepalive("sbx_nope").await.unwrap_err(),
        SandboxError::SandboxNotFound(_)
    ));
}

#[tokio::test]
async fn keepalive_preserves_sandbox_idle_timeout_override() {
    // Global default is 300s; the per-sandbox override is 1s. keepalive must
    // re-arm the reaper with the entry's override, not the global default:
    // if it used the default the sandbox would survive far beyond the
    // deadline below, and the test would fail with a clear timeout message.
    let harness = TestHarness::new().await;
    let info = harness
        .agent
        .create_sandbox(SandboxSpec {
            idle_timeout_secs: Some(1),
            ..spec("sbx_keepalive_override")
        })
        .await
        .unwrap();
    harness.agent.keepalive(&info.id).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        // The reaper must fire at the per-sandbox override (1s), not the
        // default; a dead host entry after keepalive proves the override was
        // preserved through the activity bump.
        if harness.agent.get_sandbox(&info.id).await.is_err() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "keepalive must re-arm with the per-sandbox idle timeout override"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn stop_preserves_bound_ports_until_destroy() {
    let harness = TestHarness::new().await;
    let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let info = harness
        .agent
        .create_sandbox(SandboxSpec {
            ports: Some(vec![port]),
            ..spec("sbx_stop_ports")
        })
        .await
        .unwrap();
    assert!(
        harness
            .agent
            .port_proxy
            .bound_ports(&info.id)
            .await
            .contains(&port),
        "boot must bind the requested port"
    );
    harness.agent.stop(&info.id).await.unwrap();
    assert!(
        harness
            .agent
            .port_proxy
            .bound_ports(&info.id)
            .await
            .contains(&port),
        "stop must preserve bound ports"
    );
    harness.agent.destroy(&info.id).await.unwrap();
    assert!(
        !harness
            .agent
            .port_proxy
            .bound_ports(&info.id)
            .await
            .contains(&port),
        "destroy must release bound ports"
    );
}

// ═══════════════════════════════════════════════════════════════
// Task lifecycle
// ═══════════════════════════════════════════════════════════════

#[cfg(unix)]
fn write_task_script(
    agent: &HostAgent,
    sandbox_id: &str,
    name: &str,
    content: &str,
) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let workspace = agent.workspaces.sandbox_dir(sandbox_id).unwrap();
    let script = workspace.join(name);
    std::fs::write(&script, content).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
async fn wait_for_task_state(
    agent: &HostAgent,
    sandbox_id: &str,
    task_id: &str,
    expected: TaskState,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let info = agent.task_get(sandbox_id, task_id).await.unwrap();
        if info.state == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("task did not reach {expected:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn task_runs_to_completion_and_streams_events() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .create_sandbox(spec("sbx_task_done"))
        .await
        .unwrap();
    let script = write_task_script(
        &harness.agent,
        "sbx_task_done",
        "task_echo.sh",
        "#!/bin/sh\nsleep 0.1\necho \"$1\"\n",
    );

    let started = harness
        .agent
        .task_start(
            "sbx_task_done",
            TaskRequest {
                prompt: "hello".into(),
                agent: script.to_string_lossy().to_string(),
                model: None,
                timeout_secs: Some(5),
            },
        )
        .await
        .unwrap();
    assert_eq!(started.state, TaskState::Pending);

    let mut rx = harness.agent.task_registry.subscribe(&started.id).unwrap();
    let mut saw_stdout = false;
    let mut saw_result = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
            Ok(Ok(TaskEvent::Stdout { data, .. })) if data == "hello" => {
                saw_stdout = true;
            }
            Ok(Ok(TaskEvent::Result { exit_code: 0, .. })) => {
                saw_result = true;
                break;
            }
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
        }
    }

    assert!(saw_stdout, "expected stdout event");
    assert!(saw_result, "expected result event");
    let final_info = harness
        .agent
        .task_get("sbx_task_done", &started.id)
        .await
        .unwrap();
    assert_eq!(final_info.state, TaskState::Completed);
    assert_eq!(final_info.exit_code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn task_cancel_moves_running_task_to_cancelled() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .create_sandbox(spec("sbx_task_cancel"))
        .await
        .unwrap();
    let script = write_task_script(
        &harness.agent,
        "sbx_task_cancel",
        "task_sleep.sh",
        "#!/bin/sh\nexec sleep 5\n",
    );

    let started = harness
        .agent
        .task_start(
            "sbx_task_cancel",
            TaskRequest {
                prompt: "ignored".into(),
                agent: script.to_string_lossy().to_string(),
                model: None,
                timeout_secs: Some(30),
            },
        )
        .await
        .unwrap();

    wait_for_task_state(
        &harness.agent,
        "sbx_task_cancel",
        &started.id,
        TaskState::Running,
    )
    .await;

    harness
        .agent
        .task_cancel("sbx_task_cancel", &started.id)
        .await
        .unwrap();

    wait_for_task_state(
        &harness.agent,
        "sbx_task_cancel",
        &started.id,
        TaskState::Cancelled,
    )
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn destroy_cancels_running_tasks_for_sandbox() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .create_sandbox(spec("sbx_task_destroy"))
        .await
        .unwrap();
    let script = write_task_script(
        &harness.agent,
        "sbx_task_destroy",
        "task_destroy_sleep.sh",
        "#!/bin/sh\nexec sleep 5\n",
    );

    let started = harness
        .agent
        .task_start(
            "sbx_task_destroy",
            TaskRequest {
                prompt: "ignored".into(),
                agent: script.to_string_lossy().to_string(),
                model: None,
                timeout_secs: Some(30),
            },
        )
        .await
        .unwrap();
    wait_for_task_state(
        &harness.agent,
        "sbx_task_destroy",
        &started.id,
        TaskState::Running,
    )
    .await;

    harness.agent.destroy("sbx_task_destroy").await.unwrap();

    let final_info = harness
        .agent
        .task_get("sbx_task_destroy", &started.id)
        .await
        .unwrap();
    assert_eq!(final_info.state, TaskState::Cancelled);
}

#[test]
fn addr_in_use_maps_to_port_in_use() {
    let err = std::io::Error::from(std::io::ErrorKind::AddrInUse);
    assert!(matches!(
        port_bind_error(3000, err),
        SandboxError::PortInUse(3000)
    ));
}

#[tokio::test]
async fn list_empty_paginates() {
    let harness = TestHarness::new().await;
    let (items, next) = harness
        .agent
        .list_sandboxes_paginated(10, None)
        .await
        .unwrap();
    assert!(items.is_empty());
    assert!(next.is_none());
}

#[tokio::test]
async fn list_paginates_with_cursor() {
    let harness = TestHarness::new().await;
    for i in 0..3 {
        harness
            .agent
            .prepare_sandbox(spec(&format!("sbx_{i:02}")))
            .await
            .unwrap();
    }
    let (page1, next1) = harness
        .agent
        .list_sandboxes_paginated(2, None)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(next1.as_deref(), Some("sbx_01"));

    let (page2, next2) = harness
        .agent
        .list_sandboxes_paginated(2, next1)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, "sbx_02");
    assert!(next2.is_none());
}

fn write_cgroup_files(
    dir: &std::path::Path,
    pressure_some_avg10: &str,
    oom_kill: u64,
    high: u64,
    nr_throttled: u64,
) {
    std::fs::write(
        dir.join("memory.pressure"),
        format!(
            "some avg10={pressure_some_avg10} avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("memory.events"),
        format!("low 0\nhigh {high}\nmax 0\noom 0\noom_kill {oom_kill}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("cpu.stat"),
        format!(
            "usage_usec 100\nuser_usec 50\nsystem_usec 50\nnr_periods 10\nnr_throttled {nr_throttled}\nthrottled_usec 5000\n"
        ),
    )
    .unwrap();
}

#[test]
fn cgroup_poller_baselines_first_poll_then_emits_deltas() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("sbx_a");
    let b = tmp.path().join("sbx_b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    write_cgroup_files(&a, "10.00", 1, 2, 3);
    write_cgroup_files(&b, "20.00", 0, 5, 1);

    let mut baselines = HashMap::new();
    let paths = vec![a.clone(), b.clone()];
    let first = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(first.max_pressure, 20.0);
    assert_eq!(first.pressure_read_errors, 0);
    assert_eq!(first.oom_delta, 0);
    assert_eq!(first.high_delta, 0);
    assert_eq!(first.throttled_delta, 0);

    write_cgroup_files(&a, "12.00", 3, 2, 5);
    write_cgroup_files(&b, "5.00", 1, 9, 1);
    let second = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(second.max_pressure, 12.0);
    assert_eq!(second.oom_delta, 3);
    assert_eq!(second.high_delta, 4);
    assert_eq!(second.throttled_delta, 2);
}

#[test]
fn cgroup_poller_treats_counter_reset_as_new_epoch() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("sbx_a");
    std::fs::create_dir_all(&a).unwrap();
    write_cgroup_files(&a, "1.00", 50, 50, 50);

    let mut baselines = HashMap::new();
    let paths = vec![a.clone()];
    let first = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(first.oom_delta, 0);

    // Simulated cgroup recreation restarts kernel counters at zero.
    write_cgroup_files(&a, "1.00", 2, 1, 4);
    let second = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(second.oom_delta, 2);
    assert_eq!(second.high_delta, 1);
    assert_eq!(second.throttled_delta, 4);
}

#[test]
fn cgroup_poller_skips_unreadable_events_without_delta() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("sbx_a");
    std::fs::create_dir_all(&a).unwrap();
    write_cgroup_files(&a, "1.00", 1, 1, 1);

    let mut baselines = HashMap::new();
    let paths = vec![a.clone()];
    let first = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(first.oom_delta, 0);

    std::fs::remove_file(a.join("memory.events")).unwrap();
    std::fs::remove_file(a.join("cpu.stat")).unwrap();
    std::fs::remove_file(a.join("memory.pressure")).unwrap();
    let second = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(second.oom_delta, 0);
    assert_eq!(second.high_delta, 0);
    assert_eq!(second.throttled_delta, 0);
    assert_eq!(second.pressure_read_errors, 1);
    assert_eq!(second.max_pressure, 0.0);

    // Next good poll diffs against the last good baseline, not the gap.
    write_cgroup_files(&a, "1.00", 3, 4, 2);
    let third = super::poll_cgroup_dirs(&paths, &mut baselines);
    assert_eq!(third.oom_delta, 2);
    assert_eq!(third.high_delta, 3);
    assert_eq!(third.throttled_delta, 1);
}

#[test]
fn cgroup_poller_prunes_disappeared_dirs() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("sbx_a");
    let b = tmp.path().join("sbx_b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    write_cgroup_files(&a, "1.00", 0, 0, 0);
    write_cgroup_files(&b, "1.00", 0, 0, 0);

    let mut baselines = HashMap::new();
    super::poll_cgroup_dirs(&[a.clone(), b.clone()], &mut baselines);
    assert_eq!(baselines.len(), 2);
    super::poll_cgroup_dirs(std::slice::from_ref(&a), &mut baselines);
    assert_eq!(baselines.len(), 1);
    assert!(baselines.contains_key(&a));
}

#[tokio::test]
async fn inventory_reports_live_scheduler_capacity() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_live_a"))
        .await
        .unwrap();
    harness
        .agent
        .prepare_sandbox(spec("sbx_live_b"))
        .await
        .unwrap();

    let inventory = harness.agent.inventory().await;
    let scheduler = inventory.scheduler_capacity.expect("live snapshot");
    // spec() requests 1 vCPU and 64 MB per sandbox.
    assert_eq!(scheduler.allocated_vcpus, 2);
    assert_eq!(scheduler.allocated_memory_mb, 128);
    assert_eq!(scheduler.used_process_slots, 2);
    assert_eq!(
        scheduler.used_disk_mb,
        2 * crate::scheduler_capacity::DEFAULT_DISK_MB_PER_SANDBOX
    );
    assert_eq!(inventory.current_sandboxes, 2);
    let pressure = inventory.pressure.expect("pressure snapshot");
    assert_eq!(pressure.in_flight_creates, 0);
    assert_eq!(pressure.in_flight_restores, 0);
}

#[tokio::test]
async fn stats_reports_capacity_pressure_and_utilization() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_stats_a"))
        .await
        .unwrap();

    let stats = harness.agent.stats().await;
    assert_eq!(stats["sandbox_count"], 1);
    assert_eq!(stats["capacity"]["allocated_vcpus"], 1);
    assert_eq!(stats["capacity"]["allocated_memory_mb"], 64);
    assert_eq!(stats["pressure"]["in_flight_creates"], 0);
    assert_eq!(stats["pressure"]["in_flight_restores"], 0);
    assert!(stats.get("utilization").is_some());
    assert!(stats["utilization"]["cpu"].as_f64().unwrap() >= 0.0);
}

#[tokio::test]
async fn in_flight_guards_track_create_and_restore_pressure() {
    let harness = TestHarness::new().await;
    assert_eq!(harness.agent.scheduler_pressure().in_flight_creates, 0);
    {
        let _create = harness.agent.track_create();
        assert_eq!(harness.agent.scheduler_pressure().in_flight_creates, 1);
        {
            let _restore = harness.agent.track_restore();
            assert_eq!(harness.agent.scheduler_pressure().in_flight_restores, 1);
        }
        assert_eq!(harness.agent.scheduler_pressure().in_flight_restores, 0);
    }
    assert_eq!(harness.agent.scheduler_pressure().in_flight_creates, 0);
}

#[tokio::test]
async fn boot_rejects_when_live_allocation_exhausts_vcpus() {
    let mut harness = TestHarness::new().await;
    harness.agent.capacity.cpu_count = 1;
    harness
        .agent
        .prepare_sandbox(spec("sbx_live_first"))
        .await
        .unwrap();
    harness
        .agent
        .boot_sandbox(harness.boot_command("sbx_live_first"))
        .await
        .unwrap();

    // A second 1-vCPU sandbox no longer fits the 1-vCPU total even though
    // each request alone fits; the live sum must fail closed.
    harness
        .agent
        .prepare_sandbox(spec("sbx_live_second"))
        .await
        .unwrap();
    let err = harness
        .agent
        .boot_sandbox(harness.boot_command("sbx_live_second"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SandboxError::QuotaExceeded { .. }),
        "expected live QuotaExceeded, got {err:?}"
    );
}

#[tokio::test]
async fn scheduler_host_info_maps_health_and_capacity() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_info_a"))
        .await
        .unwrap();
    let health = harness.agent.health_with_gc().await;
    let info = harness.agent.scheduler_host_info(&health).await;
    assert_eq!(info.host_id.as_str(), harness.agent.identity.host_id);
    assert_eq!(info.current_sandboxes, 1);
    assert_eq!(info.capacity.allocated_vcpus, 1);
    assert!(info.health.can_admit());
}

#[tokio::test]
async fn live_allocation_skips_failed_and_releases_stopped_cpu_memory() {
    let harness = TestHarness::new().await;
    harness
        .agent
        .prepare_sandbox(spec("sbx_res_a"))
        .await
        .unwrap();
    harness
        .agent
        .prepare_sandbox(spec("sbx_res_b"))
        .await
        .unwrap();

    // Force residency states directly: A is retained for review but holds
    // no resources; B is stopped and keeps disk/slot only.
    {
        let guard = harness.agent.sandboxes.lock().await;
        guard.get("sbx_res_a").unwrap().desired.lock().state = SandboxState::Failed;
        guard.get("sbx_res_b").unwrap().desired.lock().state = SandboxState::Stopped;
    }

    let inventory = harness.agent.inventory().await;
    let scheduler = inventory.scheduler_capacity.expect("live snapshot");
    assert_eq!(scheduler.allocated_vcpus, 0);
    assert_eq!(scheduler.allocated_memory_mb, 0);
    assert_eq!(inventory.current_sandboxes, 1);
    assert_eq!(scheduler.used_process_slots, 1);
    assert_eq!(
        scheduler.used_disk_mb,
        crate::scheduler_capacity::DEFAULT_DISK_MB_PER_SANDBOX
    );
}
