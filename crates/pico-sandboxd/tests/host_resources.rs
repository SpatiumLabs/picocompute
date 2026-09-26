//! Integration: host resource materialization (workspace, cgroup, CPU pinning)
//! inside sandboxd prepare/destroy, including ledger receipts and rollback.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pico_core::cpu_isolation::{CpuIsolationPolicy, CpuTopology};
use pico_core::{
    BackendOperation, FencingToken, NonReadyReason, OperationId, RuntimeBackend, SandboxConfig,
    SandboxId, SandboxState,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::{
    CommandContext, HostResourceConfig, HostResourceSpec, OutcomeStatus, SandboxSupervisor,
};
use tempfile::TempDir;

fn sandbox_id(name: &str) -> SandboxId {
    SandboxId::from_string(format!("sbx_{name}"))
}

fn config(id: &SandboxId) -> SandboxConfig {
    SandboxConfig {
        id: id.as_str().into(),
        network_isolated: true,
        ..Default::default()
    }
}

fn command(id: &SandboxId, timeout: Duration) -> CommandContext {
    CommandContext::with_timeout(
        id.clone(),
        OperationId::generate(),
        FencingToken::default(),
        1,
        timeout,
    )
}

fn supervisor(workspace_root: &Path) -> SandboxSupervisor {
    SandboxSupervisor::in_memory()
        .with_host_resources(HostResourceConfig::new(workspace_root.to_path_buf()))
}

fn supervisor_with_policy(workspace_root: &Path, policy: CpuIsolationPolicy) -> SandboxSupervisor {
    SandboxSupervisor::in_memory().with_host_resources(
        HostResourceConfig::new(workspace_root.to_path_buf()).with_cpu_isolation_policy(policy),
    )
}

fn mock_backend() -> Arc<dyn RuntimeBackend> {
    Arc::new(MockBackend::default())
}

async fn prepare(
    supervisor: &SandboxSupervisor,
    id: &SandboxId,
) -> pico_sandboxd::OperationOutcome {
    supervisor
        .prepare(
            command(id, Duration::from_secs(5)),
            mock_backend(),
            &config(id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap()
}

async fn destroy(
    supervisor: &SandboxSupervisor,
    id: &SandboxId,
) -> pico_sandboxd::OperationOutcome {
    supervisor
        .destroy(command(id, Duration::from_secs(5)))
        .await
        .unwrap()
}

async fn present_receipt_classes(supervisor: &SandboxSupervisor, id: &SandboxId) -> Vec<String> {
    supervisor
        .resource_receipts(id)
        .await
        .unwrap()
        .into_iter()
        .filter(|receipt| receipt.cleanup_state == "present")
        .map(|receipt| receipt.class)
        .collect()
}

fn workspace_dir(root: &Path, id: &SandboxId) -> PathBuf {
    root.join(id.as_str())
}

/// File-backed ledger database in the system temp directory so a supervisor
/// can be dropped and reopened with the same durable state, mirroring a
/// daemon restart.
struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "pico-sandboxd-host-resources-{}.db",
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
async fn prepare_materializes_workspace_and_writes_host_receipts() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor_with_policy(&root, CpuIsolationPolicy::DedicatedCores);
    let id = sandbox_id("materialize");

    let outcome = prepare(&supervisor, &id).await;

    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    assert!(workspace_dir(&root, &id).is_dir());
    let receipts = supervisor.resource_receipts(&id).await.unwrap();
    let classes: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.class.as_str())
        .collect();
    assert!(classes.contains(&"workspace"), "receipts: {receipts:?}");
    assert!(classes.contains(&"cgroup"), "receipts: {receipts:?}");
    assert!(
        classes.contains(&"cpu"),
        "CPU allocation must be durably receipted: {receipts:?}"
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.cleanup_state == "present"),
        "receipts: {receipts:?}"
    );
}

#[tokio::test]
async fn destroy_releases_host_receipts_and_removes_workspace() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor(&root);
    let id = sandbox_id("release");
    assert_eq!(
        prepare(&supervisor, &id).await.status,
        OutcomeStatus::Succeeded
    );

    let outcome = destroy(&supervisor, &id).await;

    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    assert!(!workspace_dir(&root, &id).exists());
    let receipts = supervisor.resource_receipts(&id).await.unwrap();
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.cleanup_state == "released"),
        "receipts: {receipts:?}"
    );
    let classes: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.class.as_str())
        .collect();
    assert!(classes.contains(&"workspace"), "receipts: {receipts:?}");
    assert!(classes.contains(&"cgroup"), "receipts: {receipts:?}");
    assert_eq!(
        supervisor
            .status(&id)
            .await
            .unwrap()
            .unwrap()
            .observed_state,
        SandboxState::Destroyed
    );
}

#[tokio::test]
async fn failed_backend_prepare_rolls_back_host_resources() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor(&root);
    let id = sandbox_id("rollback");
    let backend: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::NotReady {
            operation: BackendOperation::Prepare,
            reason: NonReadyReason::Backend,
        }),
        ..MockBackendConfig::default()
    }));
    let context = command(&id, Duration::from_secs(5));

    let outcome = supervisor
        .prepare(
            context.clone(),
            backend,
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Failed);
    assert!(
        !workspace_dir(&root, &id).exists(),
        "workspace must be rolled back"
    );
    let receipts = supervisor.resource_receipts(&id).await.unwrap();
    assert_eq!(
        present_receipt_classes(&supervisor, &id).await.len(),
        0,
        "no resource may survive a fully rolled back prepare: {receipts:?}"
    );
    // The host receipts remain as released rows so the ledger proves the
    // resources existed and were cleaned.
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.cleanup_state == "released"),
        "receipts: {receipts:?}"
    );

    // Replaying the same failed operation must not re-materialize anything:
    // the persisted outcome comes back without running prepare again.
    let replay = supervisor
        .prepare(
            context,
            mock_backend(),
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(replay, outcome);
    assert!(
        !workspace_dir(&root, &id).exists(),
        "replayed failure must not recreate the workspace"
    );
    assert!(present_receipt_classes(&supervisor, &id).await.is_empty());
}

#[tokio::test]
async fn failed_materialization_rolls_back_partial_resources() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor(&root);
    let id = SandboxId::from_string("../escape");

    let outcome = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Failed);
    assert_eq!(outcome.non_ready_reason, Some(NonReadyReason::Resource));
    assert!(!workspace_dir(&root, &id).exists());
    assert!(supervisor.resource_receipts(&id).await.unwrap().is_empty());
}

#[tokio::test]
async fn prepare_replay_does_not_repeat_materialization() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor(&root);
    let id = sandbox_id("replay");
    let backend = mock_backend();
    let context = command(&id, Duration::from_secs(5));

    let first = supervisor
        .prepare(
            context.clone(),
            Arc::clone(&backend),
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    let replay = supervisor
        .prepare(
            context,
            Arc::clone(&backend),
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();

    assert_eq!(replay, first);
    let host_receipts = supervisor
        .resource_receipts(&id)
        .await
        .unwrap()
        .into_iter()
        .filter(|receipt| matches!(receipt.class.as_str(), "workspace" | "cgroup"))
        .count();
    assert_eq!(host_receipts, 2);
}

#[tokio::test]
async fn cross_tenant_host_fails_prepare_when_cpu_allocation_exhausted() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor_with_policy(&root, CpuIsolationPolicy::DedicatedCores);
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;

    let first_id = sandbox_id("tenant_one");
    let first = supervisor
        .prepare(
            command(&first_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&first_id),
            &HostResourceSpec {
                vcpus: total_cpus,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-a".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(first.status, OutcomeStatus::Succeeded);

    let second_id = sandbox_id("tenant_two");
    let second = supervisor
        .prepare(
            command(&second_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&second_id),
            &HostResourceSpec {
                vcpus: 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-b".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(second.status, OutcomeStatus::Failed);
    assert_eq!(second.non_ready_reason, Some(NonReadyReason::Resource));
    assert!(!workspace_dir(&root, &second_id).exists());
    // The workspace receipt stays in the ledger as proof of the rollback:
    // it was created before allocation failed and released during rollback.
    let receipts = supervisor.resource_receipts(&second_id).await.unwrap();
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.cleanup_state == "released"),
        "receipts: {receipts:?}"
    );
    assert!(
        present_receipt_classes(&supervisor, &second_id)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn daemon_cross_tenant_flag_cannot_be_weakened_by_request() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = SandboxSupervisor::in_memory().with_host_resources(
        HostResourceConfig::new(root.clone())
            .with_cpu_isolation_policy(CpuIsolationPolicy::DedicatedCores)
            .with_cross_tenant_host(true),
    );
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;

    let first_id = sandbox_id("daemon_occupant");
    let first = supervisor
        .prepare(
            command(&first_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&first_id),
            &HostResourceSpec {
                vcpus: total_cpus,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-a".to_string()),
                cross_tenant_host: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(first.status, OutcomeStatus::Succeeded);

    // The request claims a non-cross-tenant host, but the daemon flag wins.
    let second_id = sandbox_id("daemon_overflow");
    let second = supervisor
        .prepare(
            command(&second_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&second_id),
            &HostResourceSpec {
                vcpus: 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-b".to_string()),
                cross_tenant_host: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(second.status, OutcomeStatus::Failed);
    assert_eq!(second.non_ready_reason, Some(NonReadyReason::Resource));
    assert!(!workspace_dir(&root, &second_id).exists());
}

#[tokio::test]
async fn shared_host_proceeds_without_pinning_when_cpu_allocation_exhausted() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor_with_policy(&root, CpuIsolationPolicy::DedicatedCores);
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;

    let first_id = sandbox_id("occupant");
    let first = supervisor
        .prepare(
            command(&first_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&first_id),
            &HostResourceSpec {
                vcpus: total_cpus,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-a".to_string()),
                cross_tenant_host: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(first.status, OutcomeStatus::Succeeded);

    let second_id = sandbox_id("overflow");
    let second = supervisor
        .prepare(
            command(&second_id, Duration::from_secs(5)),
            mock_backend(),
            &config(&second_id),
            &HostResourceSpec {
                vcpus: 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-b".to_string()),
                cross_tenant_host: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // On non-cross-tenant hosts allocation failure degrades to unpinned
    // instead of failing the prepare.
    assert_eq!(second.status, OutcomeStatus::Succeeded);
    assert!(workspace_dir(&root, &second_id).is_dir());
}

#[tokio::test]
async fn concurrent_strict_policy_prepares_yield_exactly_one_winner() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor_with_policy(&root, CpuIsolationPolicy::DedicatedCores);
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;

    // Both racers demand every logical CPU on a cross-tenant host, so the
    // shared allocator can only grant one of them: exactly one prepare
    // succeeds and the other fails with a resource reason.
    let first_id = sandbox_id("racer_one");
    let second_id = sandbox_id("racer_two");
    let first = {
        let supervisor = supervisor.clone();
        let id = first_id.clone();
        tokio::spawn(async move {
            supervisor
                .prepare(
                    command(&id, Duration::from_secs(5)),
                    mock_backend(),
                    &config(&id),
                    &HostResourceSpec {
                        vcpus: total_cpus,
                        memory_mb: 512,
                        requested_ports: Vec::new(),
                        tenant_id: Some("tenant-a".to_string()),
                        cross_tenant_host: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
        })
    };
    let second = {
        let supervisor = supervisor.clone();
        let id = second_id.clone();
        tokio::spawn(async move {
            supervisor
                .prepare(
                    command(&id, Duration::from_secs(5)),
                    mock_backend(),
                    &config(&id),
                    &HostResourceSpec {
                        vcpus: total_cpus,
                        memory_mb: 512,
                        requested_ports: Vec::new(),
                        tenant_id: Some("tenant-b".to_string()),
                        cross_tenant_host: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
        })
    };

    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    let statuses = [first.status, second.status];
    let succeeded = statuses
        .iter()
        .filter(|status| **status == OutcomeStatus::Succeeded)
        .count();
    let failed = statuses
        .iter()
        .filter(|status| **status == OutcomeStatus::Failed)
        .count();
    assert_eq!(succeeded, 1, "exactly one racer must win: {statuses:?}");
    assert_eq!(failed, 1, "exactly one racer must lose: {statuses:?}");

    let loser = if first.status == OutcomeStatus::Failed {
        &first
    } else {
        &second
    };
    let winner_id = if first.status == OutcomeStatus::Succeeded {
        &first_id
    } else {
        &second_id
    };
    let loser_id = &loser.sandbox_id;
    assert_eq!(loser.non_ready_reason, Some(NonReadyReason::Resource));
    assert!(
        !workspace_dir(&root, loser_id).exists(),
        "loser workspace must be rolled back"
    );
    assert!(workspace_dir(&root, winner_id).is_dir());
    assert!(
        present_receipt_classes(&supervisor, loser_id)
            .await
            .is_empty(),
        "loser must not keep present receipts"
    );
}

#[tokio::test]
async fn prepare_after_crash_recovers_workspace_and_receipts() {
    let database = TempDatabase::new();
    let root = database.path().with_extension("workspaces");
    let supervisor =
        SandboxSupervisor::open(database.path(), HostResourceConfig::new(root.clone())).unwrap();
    let id = sandbox_id("crash_retry");
    let backend: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Delay {
            operation: BackendOperation::Prepare,
            duration: Duration::from_secs(30),
        }),
        ..MockBackendConfig::default()
    }));

    // Crash mid-prepare: materialization completed (workspace dir exists)
    // but the backend prepare never returned and nothing was persisted.
    let daemon = supervisor.clone();
    let task_id = id.clone();
    let task = tokio::spawn(async move {
        daemon
            .prepare(
                command(&task_id, Duration::from_secs(60)),
                backend,
                &config(&task_id),
                &HostResourceSpec::default(),
            )
            .await
    });
    // Wait until the workspace exists so the abort provably lands after
    // materialization instead of during the ledger begin.
    for _ in 0..200 {
        if workspace_dir(&root, &id).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        workspace_dir(&root, &id).is_dir(),
        "materialization must complete before the crash"
    );
    task.abort();
    let _ = task.await;
    drop(supervisor);

    // The restarted supervisor flags the interrupted operation and a fresh
    // prepare re-materializes the same workspace and persists receipts.
    let restarted =
        SandboxSupervisor::open(database.path(), HostResourceConfig::new(root.clone())).unwrap();
    let _ = restarted.status(&id).await.unwrap();
    assert_eq!(restarted.health().await.review_required, 1);

    let retry = restarted
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &HostResourceSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status, OutcomeStatus::Succeeded);
    assert!(workspace_dir(&root, &id).is_dir());
    let present = present_receipt_classes(&restarted, &id).await;
    assert!(
        present.contains(&"workspace".to_string()),
        "receipts: {present:?}"
    );
    assert!(
        present.contains(&"cgroup".to_string()),
        "receipts: {present:?}"
    );
}

#[tokio::test]
async fn restarted_supervisor_refuses_cpu_overcommit() {
    let database = TempDatabase::new();
    let root = database.path().with_extension("workspaces");
    let policy = CpuIsolationPolicy::DedicatedCores;
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;

    let first = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(root.clone()).with_cpu_isolation_policy(policy),
    )
    .unwrap();
    let occupant = sandbox_id("restart_occupant");
    let outcome = first
        .prepare(
            command(&occupant, Duration::from_secs(5)),
            mock_backend(),
            &config(&occupant),
            &HostResourceSpec {
                vcpus: total_cpus,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-a".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    drop(first);

    // The restarted supervisor rebuilds its allocator from the durable cpu
    // receipts, so every core stays owned by the pre-restart occupant.
    let restarted = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(root.clone()).with_cpu_isolation_policy(policy),
    )
    .unwrap();
    let _ = restarted.status(&occupant).await.unwrap();

    let overflow = sandbox_id("restart_overflow");
    let outcome = restarted
        .prepare(
            command(&overflow, Duration::from_secs(5)),
            mock_backend(),
            &config(&overflow),
            &HostResourceSpec {
                vcpus: 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-b".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Failed);
    assert_eq!(outcome.non_ready_reason, Some(NonReadyReason::Resource));
    assert!(!workspace_dir(&root, &overflow).exists());
}

#[tokio::test]
async fn restarted_supervisor_restores_partial_allocation_and_serves_remaining() {
    let database = TempDatabase::new();
    let root = database.path().with_extension("workspaces");
    let policy = CpuIsolationPolicy::DedicatedCores;
    let total_cpus = CpuTopology::detect().total_logical_cpus as u32;
    assert!(total_cpus > 1, "test needs at least 2 logical CPUs");

    let first = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(root.clone()).with_cpu_isolation_policy(policy),
    )
    .unwrap();
    let occupant = sandbox_id("restart_partial");
    let outcome = first
        .prepare(
            command(&occupant, Duration::from_secs(5)),
            mock_backend(),
            &config(&occupant),
            &HostResourceSpec {
                vcpus: total_cpus - 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-a".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    drop(first);

    // The rebuilt allocator keeps every core the pre-restart occupant held,
    // so the one remaining free core stays allocatable for a new tenant.
    let restarted = SandboxSupervisor::open(
        database.path(),
        HostResourceConfig::new(root.clone()).with_cpu_isolation_policy(policy),
    )
    .unwrap();
    let _ = restarted.status(&occupant).await.unwrap();

    let newcomer = sandbox_id("restart_newcomer");
    let outcome = restarted
        .prepare(
            command(&newcomer, Duration::from_secs(5)),
            mock_backend(),
            &config(&newcomer),
            &HostResourceSpec {
                vcpus: 1,
                memory_mb: 512,
                requested_ports: Vec::new(),
                tenant_id: Some("tenant-b".to_string()),
                cross_tenant_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(outcome.status, OutcomeStatus::Succeeded);
    assert!(workspace_dir(&root, &newcomer).is_dir());
}

#[tokio::test]
async fn destroyed_sandbox_leaves_no_present_host_receipts() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("workspaces");
    let supervisor = supervisor(&root);
    let id = sandbox_id("gc_ready");
    assert_eq!(
        prepare(&supervisor, &id).await.status,
        OutcomeStatus::Succeeded
    );
    assert_eq!(
        destroy(&supervisor, &id).await.status,
        OutcomeStatus::Succeeded
    );

    assert!(present_receipt_classes(&supervisor, &id).await.is_empty());
}
