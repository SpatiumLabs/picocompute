//! Restart-resilience acceptance tests for sandboxd (ADR-0011, PR8).
//!
//! These tests simulate a sandboxd process kill by dropping the supervisor
//! mid-operation and re-opening it against the same durable ledger and
//! workspace root. They run unprivileged on Linux (CI) and macOS (local dev):
//! no Firecracker binary, TAP device, or cgroup hierarchy is required because
//! the MockBackend stands in for runtime mechanics.
//!
//! Covered acceptance scenarios:
//!
//! 1. Destroy resumes cleanup from the ledger after a sandboxd restart
//!    mid-destroy, ending in a fully released `Destroyed` sandbox.
//! 2. The resume path refuses sandboxes whose observed state does not prove
//!    destroy intent, keeping possibly-live runtimes for operator review.
//! 3. Supervisor health reports not-ready until startup reconciliation has
//!    run (the gRPC server entrypoint binds the socket only after reconcile).

use std::sync::Arc;
use std::time::Duration;

use pico_core::{
    BackendOperation, FencingToken, OperationId, SandboxConfig, SandboxId, SandboxState,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::{
    CommandContext, HostResourceConfig, OutcomeStatus, SandboxSupervisor, SupervisorError,
};
use tempfile::TempDir;

fn ctx(sandbox_id: &SandboxId, sequence: u64) -> CommandContext {
    CommandContext::with_timeout(
        sandbox_id.clone(),
        OperationId::generate(),
        FencingToken { epoch: 1, sequence },
        1,
        Duration::from_secs(60),
    )
}

fn spec(sandbox_id: &str) -> SandboxConfig {
    SandboxConfig {
        id: sandbox_id.into(),
        ..SandboxConfig::default()
    }
}

/// Boots a sandbox to Running with a mock backend whose `destroy` blocks for
/// `destroy_delay`, giving the test a window to kill the supervisor while the
/// destroy operation is durably in flight.
async fn boot_running(
    supervisor: &SandboxSupervisor,
    sandbox_id: &SandboxId,
    destroy_delay: Option<Duration>,
) -> Arc<MockBackend> {
    let backend = Arc::new(MockBackend::new(MockBackendConfig {
        failure: destroy_delay.map(|duration| MockFailure::Delay {
            operation: BackendOperation::Destroy,
            duration,
        }),
        ..MockBackendConfig::default()
    }));
    let prepare = supervisor
        .prepare(
            ctx(sandbox_id, 1),
            Arc::<MockBackend>::clone(&backend) as Arc<dyn pico_core::RuntimeBackend>,
            &spec(sandbox_id.as_str()),
            &pico_sandboxd::HostResourceSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(prepare.status, OutcomeStatus::Succeeded);
    let boot = supervisor.boot(ctx(sandbox_id, 2)).await.unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);
    backend
}

#[tokio::test]
async fn destroy_resumes_cleanup_from_ledger_after_mid_destroy_restart() {
    let dir = TempDir::new().unwrap();
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    let sandbox_id = SandboxId::from_string("sbx_mid_destroy");
    {
        let supervisor =
            SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
                .unwrap()
                .with_guest_session(false);
        supervisor.reconcile().await.unwrap();
        boot_running(&supervisor, &sandbox_id, Some(Duration::from_secs(600))).await;

        // Start destroy in the background; the backend destroy blocks for ten
        // minutes, so the operation stays durably in flight when we "kill" the
        // supervisor below.
        let destroy_supervisor = supervisor.clone();
        let destroy_ctx = ctx(&sandbox_id, 3);
        let destroy_task =
            tokio::spawn(async move { destroy_supervisor.destroy(destroy_ctx).await });

        // Wait until the ledger durably records the destroy intent.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = supervisor.status(&sandbox_id).await.unwrap().unwrap();
            if status.observed_state == SandboxState::Destroying {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "destroy never reached the ledger"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Simulated SIGKILL: the in-flight destroy future and every
        // process-local runtime handle vanish with the supervisor.
        destroy_task.abort();
        drop(supervisor);
    }

    // Restart the daemon on the same ledger and workspace: reconcile must
    // classify the interrupted destroy instead of forgetting it.
    let restarted = SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
        .unwrap()
        .with_guest_session(false);
    let review = restarted.reconcile().await.unwrap();
    assert_eq!(review, 1, "interrupted destroy must require review");
    let status = restarted.status(&sandbox_id).await.unwrap().unwrap();
    assert_eq!(status.observed_state, SandboxState::Destroying);
    assert!(
        restarted
            .resource_receipts(&sandbox_id)
            .await
            .unwrap()
            .iter()
            .any(|receipt| receipt.cleanup_state == "present"),
        "host resource receipts survive the restart as present"
    );

    // A retried destroy (fresh operation id, next fencing sequence) resumes
    // the recorded intent from ledger receipts even though the backend handle
    // is gone for good.
    let outcome = restarted.destroy(ctx(&sandbox_id, 4)).await.unwrap();
    assert_eq!(
        outcome.status,
        OutcomeStatus::Succeeded,
        "destroy resume failed: {:?}",
        outcome.message
    );
    let status = restarted.status(&sandbox_id).await.unwrap().unwrap();
    assert_eq!(status.observed_state, SandboxState::Destroyed);
    assert!(
        !workspace.join(sandbox_id.as_str()).exists(),
        "resume must remove the workspace directory"
    );
    let receipts = restarted.resource_receipts(&sandbox_id).await.unwrap();
    let workspace_receipt = receipts
        .iter()
        .find(|receipt| receipt.class == "workspace")
        .expect("workspace receipt recorded");
    assert_eq!(workspace_receipt.cleanup_state, "released");
}

#[tokio::test]
async fn destroy_resume_with_leftover_host_resources_escalates_to_review() {
    let dir = TempDir::new().unwrap();
    let ledger = dir.path().join("state.db");
    let workspace_root = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace_root).unwrap();

    let sandbox_id = SandboxId::from_string("sbx_mid_destroy_leftover");
    {
        let supervisor =
            SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace_root.clone()))
                .unwrap()
                .with_guest_session(false);
        supervisor.reconcile().await.unwrap();
        boot_running(&supervisor, &sandbox_id, Some(Duration::from_secs(600))).await;

        let destroy_supervisor = supervisor.clone();
        let destroy_ctx = ctx(&sandbox_id, 3);
        let destroy_task =
            tokio::spawn(async move { destroy_supervisor.destroy(destroy_ctx).await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = supervisor.status(&sandbox_id).await.unwrap().unwrap();
            if status.observed_state == SandboxState::Destroying {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        destroy_task.abort();
        drop(supervisor);
    }

    // Break host-resource teardown deterministically and unprivileged: the
    // restarted supervisor opens its workspace manager lazily, and a regular
    // file at the root path is not a directory.
    std::fs::remove_dir_all(&workspace_root).unwrap();
    std::fs::write(&workspace_root, b"not a directory").unwrap();

    let restarted =
        SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace_root.clone()))
            .unwrap()
            .with_guest_session(false);
    let review = restarted.reconcile().await.unwrap();
    assert_eq!(review, 1);

    // The resumed destroy cannot remove anything: it must escalate instead of
    // fabricating success, keeping receipts present for a later retry.
    let outcome = restarted.destroy(ctx(&sandbox_id, 4)).await.unwrap();
    assert_eq!(outcome.status, OutcomeStatus::RequiresReview);
    assert_eq!(
        restarted
            .status(&sandbox_id)
            .await
            .unwrap()
            .unwrap()
            .observed_state,
        SandboxState::Failed,
    );
    // Review surfacing: the interrupted op plus the partial-cleanup outcome.
    assert_eq!(restarted.health().await.review_required, 2);
    assert!(
        restarted
            .resource_receipts(&sandbox_id)
            .await
            .unwrap()
            .iter()
            .any(|receipt| receipt.cleanup_state == "present"),
        "leftover receipts must stay present for GC and operator review"
    );

    // Restore the workspace root: the next retry converges without manual
    // ledger surgery.
    std::fs::remove_file(&workspace_root).unwrap();
    std::fs::create_dir_all(&workspace_root).unwrap();
    let outcome = restarted.destroy(ctx(&sandbox_id, 5)).await.unwrap();
    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    assert_eq!(
        restarted
            .status(&sandbox_id)
            .await
            .unwrap()
            .unwrap()
            .observed_state,
        SandboxState::Destroyed,
    );
}

#[tokio::test]
async fn destroy_after_restart_refuses_sandboxes_without_destroy_intent() {
    let dir = TempDir::new().unwrap();
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    let sandbox_id = SandboxId::from_string("sbx_live_after_restart");
    {
        let supervisor =
            SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
                .unwrap()
                .with_guest_session(false);
        supervisor.reconcile().await.unwrap();
        boot_running(&supervisor, &sandbox_id, None).await;
        // No in-flight operation: a clean-looking crash while Running.
        drop(supervisor);
    }

    let restarted = SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
        .unwrap()
        .with_guest_session(false);
    restarted.reconcile().await.unwrap();

    // The runtime may still be live on the host (reparented, unreachable), so
    // the resume path must refuse rather than tear host resources down under
    // a running workload.
    let err = restarted.destroy(ctx(&sandbox_id, 3)).await.unwrap_err();
    assert!(
        matches!(err, SupervisorError::RuntimeNotAttached(_)),
        "expected RuntimeNotAttached, got {err:?}"
    );
    let status = restarted.status(&sandbox_id).await.unwrap().unwrap();
    assert_eq!(status.observed_state, SandboxState::Running);
    assert!(
        workspace.join(sandbox_id.as_str()).exists(),
        "refused destroy must leave host resources in place"
    );
}

#[tokio::test]
async fn supervisor_health_is_not_ready_before_reconcile() {
    let dir = TempDir::new().unwrap();
    let ledger = dir.path().join("state.db");
    let workspace = dir.path().join("workspaces");
    std::fs::create_dir_all(&workspace).unwrap();

    let supervisor = SandboxSupervisor::open(&ledger, HostResourceConfig::new(workspace.clone()))
        .unwrap()
        .with_guest_session(false);
    // Before any operation runs, initialization has not happened: readiness
    // must fail closed so the production entrypoint (which binds the socket
    // only after `reconcile`) is the sole healthy serving window.
    assert!(!supervisor.health().await.ready);

    supervisor.reconcile().await.unwrap();
    assert!(supervisor.health().await.ready);
}
