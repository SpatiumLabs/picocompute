//! Public `sandboxd` supervision boundary used by `host-agent`.
//!
//! This module defines the durable command envelope, observable outcomes,
//! supervisor health surface, and the orchestration entry points that own
//! runtime and process lifecycles on one host.

use hashbrown::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock as ParkingLotRwLock;
use pico_core::{
    BackendCapabilities, BackendError, BackendMetadata, ExecRequest, ExecResponse, FencingToken,
    GuestTransport, NonReadyReason, OperationId, RuntimeBackend, SandboxConfig, SandboxId,
    SandboxState,
};
use tokio::sync::{Mutex, OnceCell, RwLock};
use tokio_util::sync::CancellationToken;

use crate::gc::GarbageCollector;
use crate::guest::{
    ExecStreamEvent, GetFileResult, GuestClientError, GuestConnection, HandshakeConfig,
    HandshakeError,
};
use crate::ledger::{BeginOperation, BeginOperationRequest, Ledger};
use crate::process::{ProcessOutput, ProcessRegistry, ProcessRequest};
use crate::resources::{
    HostResourceConfig, HostResourceManager, HostResourceSpec, cgroup_receipt_name,
    cpu_receipt_name, workspace_receipt_name,
};
use crate::secrets::SecretsCoordinator;
use crate::{DnsAttachConfig, DnsAttachManager, NetworkAttachManager};

mod types;
pub use types::*;

pub(crate) mod restore;
pub use restore::{ForkCommand, RestoreCommand, SnapshotRestoreStores};

impl OutcomeStatus {
    pub(crate) fn is_terminal(self) -> bool {
        self != Self::Running
    }
}

impl CommandContext {
    /// Creates a command context with a deadline relative to the current time.
    ///
    /// The resulting deadline is persisted as an absolute Unix timestamp so a
    /// restarted supervisor can keep enforcing the original timeout instead of
    /// silently granting the operation more time.
    #[must_use]
    pub fn with_timeout(
        sandbox_id: SandboxId,
        operation_id: OperationId,
        assignment_fencing_token: FencingToken,
        policy_epoch: u64,
        timeout: Duration,
    ) -> Self {
        let deadline = SystemTime::now()
            .checked_add(timeout)
            .unwrap_or(SystemTime::now());
        Self {
            sandbox_id,
            operation_id,
            assignment_fencing_token,
            policy_epoch,
            deadline_unix_ms: system_time_to_unix_ms(deadline),
        }
    }
}

struct RuntimeHandle {
    backend: Arc<dyn RuntimeBackend>,
    operation_gate: Mutex<()>,
    guest_session: Mutex<Option<GuestConnection>>,
    /// Monotonic observation generation; bumped on lifecycle transitions.
    generation: AtomicU64,
    /// Guest ports requested at prepare for GetPortTarget / observation ports.
    requested_ports: ParkingLotRwLock<Vec<u16>>,
    /// Cached guest boot id so observation enrich never needs `guest_session`.
    guest_boot_id: ParkingLotRwLock<String>,
    /// Tenant identity from prepare host resources (for DNS/secrets audit).
    tenant_id: ParkingLotRwLock<String>,
    /// Backend runtime selected at prepare (for DNS network identity).
    runtime: ParkingLotRwLock<Option<pico_core::RuntimeType>>,
    /// SSH host port from prepare config for observation wiring.
    ssh_host_port: ParkingLotRwLock<Option<u16>>,
    /// SSH public key from prepare host resources for observation wiring.
    ssh_public_key: ParkingLotRwLock<Option<String>>,
    /// Image id for guest handshake validation (empty means skip check for
    /// older clients that did not send image evidence).
    image_id: ParkingLotRwLock<String>,
    /// Image digest for future handshake binding (retained, not yet enforced).
    image_digest: ParkingLotRwLock<String>,
}

impl SandboxSupervisor {
    /// Opens a durable supervisor backed by a SQLite WAL database.
    ///
    /// Guest session ownership defaults on so the sandboxd binary fail-closes
    /// Boot without a framed handshake. Host resources (workspace, cgroup,
    /// CPU pinning) are materialized under the supplied configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the database parent directory cannot be created.
    pub fn open(path: impl AsRef<Path>, host: HostResourceConfig) -> Result<Self, SupervisorError> {
        Ok(Self::new(
            Ledger::open(path.as_ref())?,
            true,
            HostResourceManager::new(host),
        ))
    }

    /// Creates an in-memory supervisor for tests and local composition.
    ///
    /// Guest session ownership defaults on. A unique temporary workspace root
    /// is used; override it with [`SandboxSupervisor::with_host_resources`].
    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(
            Ledger::in_memory(),
            true,
            HostResourceManager::new(HostResourceConfig::new(default_test_workspace_root())),
        )
    }

    /// Controls whether Boot requires a fail-closed guest handshake.
    #[must_use]
    pub fn with_guest_session(mut self, require: bool) -> Self {
        self.require_guest_session = require;
        self
    }

    /// Overrides the host resource configuration (workspace root and CPU
    /// isolation policy) used by prepare and destroy.
    #[must_use]
    pub fn with_host_resources(mut self, config: HostResourceConfig) -> Self {
        let host_resources = HostResourceManager::new(config);
        self.process_registry = ProcessRegistry::new(host_resources.clone());
        self.host_resources = host_resources;
        self
    }

    fn new(
        ledger: Ledger,
        require_guest_session: bool,
        host_resources: HostResourceManager,
    ) -> Self {
        let (watch_tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            ledger,
            runtimes: Arc::new(RwLock::new(HashMap::new())),
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            process_registry: ProcessRegistry::new(host_resources.clone()),
            initialized: Arc::new(OnceCell::new()),
            reconcile_complete: Arc::new(AtomicBool::new(false)),
            host_boot_id: Arc::new(read_host_boot_id()),
            review_required: Arc::new(AtomicU64::new(0)),
            require_guest_session,
            host_resources,
            watch_tx,
            secrets: Arc::new(default_secrets_coordinator()),
            dns: Arc::new(DnsAttachManager::disabled()),
            network: Arc::new(NetworkAttachManager::disabled()),
            snapshot_stores: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Overrides secrets coordination (broker, lease manager, audit sink).
    #[must_use]
    pub fn with_secrets(mut self, coordinator: Arc<SecretsCoordinator>) -> Self {
        self.secrets = coordinator;
        self
    }

    /// Overrides DNS attach ownership (proxy process + attach receipts).
    #[must_use]
    pub fn with_dns(mut self, dns: Arc<DnsAttachManager>) -> Self {
        self.dns = dns;
        self
    }

    /// Convenience builder for DNS attach from a listen address.
    #[must_use]
    pub fn with_dns_listen_addr(self, addr: Option<std::net::SocketAddr>) -> Self {
        self.with_dns(Arc::new(DnsAttachManager::new(DnsAttachConfig {
            listen_addr: addr,
        })))
    }

    /// Overrides TAP/veth/route pipeline ownership.
    #[must_use]
    pub fn with_network(mut self, network: Arc<NetworkAttachManager>) -> Self {
        self.network = network;
        self
    }

    /// Reconciles interrupted operations and returns the number of items
    /// that require operator review.
    ///
    /// This is called once at startup to detect operations that were active
    /// when the supervisor last shut down. Use [`SandboxSupervisor::gc_stats`]
    /// for periodic garbage collection results.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable ledger cannot be initialized or updated.
    pub async fn reconcile(&self) -> Result<u64, SupervisorError> {
        self.ensure_initialized().await?;
        Ok(self.review_required.load(Ordering::Relaxed))
    }

    /// Returns persisted reconciliation findings that require operator review.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn review_findings_count(&self) -> Result<u64, SupervisorError> {
        self.ensure_initialized().await?;
        self.ledger.review_required_count().await
    }

    /// Supervises runtime preparation and persists returned resource receipts.
    ///
    /// Host resources (workspace, cgroup, CPU pinning) are materialized before
    /// the backend runs, and their receipts are persisted together with the
    /// backend receipts on success. A failed prepare rolls back every host
    /// resource created during the attempt.
    ///
    /// Successful prepare records deterministic receipts and leaves the
    /// sandbox observed as `Preparing` so a later boot can be retried or
    /// replayed safely after restart. Observed state does not invent a
    /// `Pending` shortcut; that transition is not in the ADR-0001 table.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing, mismatched sandbox identity, or ledger access.
    pub async fn prepare(
        &self,
        context: CommandContext,
        backend: Arc<dyn RuntimeBackend>,
        config: &SandboxConfig,
        host: &HostResourceSpec,
    ) -> Result<OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        if context.sandbox_id.as_str() != config.id {
            return Err(SupervisorError::SandboxMismatch {
                command: context.sandbox_id.to_string(),
                config: config.id.clone(),
            });
        }
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), Some(backend))
            .await?;
        let _gate = handle.operation_gate.lock().await;
        {
            let mut ports = handle.requested_ports.write();
            *ports = host.requested_ports.clone();
            ports.sort_unstable();
            ports.dedup();
        }
        {
            *handle.tenant_id.write() = host.tenant_id.clone().unwrap_or_default();
            *handle.runtime.write() = Some(handle.backend.metadata().runtime);
            *handle.ssh_host_port.write() = config.ssh_port;
            *handle.ssh_public_key.write() = host.ssh_public_key.clone();
            *handle.image_id.write() = host.image_id.clone().unwrap_or_default();
            *handle.image_digest.write() = host.image_digest.clone().unwrap_or_default();
        }
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Prepare,
                &metadata,
                SandboxState::Preparing,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }

        let mut effective_config = config.clone();
        let workspaces = match self.host_resources.workspaces().await {
            Ok(workspaces) => workspaces,
            Err(message) => {
                let outcome = host_resource_outcome(&context, message);
                self.persist_outcome(&outcome, SandboxState::Failed, &[])
                    .await?;
                return Ok(outcome);
            }
        };
        let host_receipts =
            match self
                .host_resources
                .materialize(workspaces, &mut effective_config, host)
            {
                Ok(receipts) => receipts,
                Err(error) => {
                    let outcome = host_resource_outcome(&context, error.message);
                    let (outcome, state, released) = outcome_with_cleanup(
                        outcome,
                        SandboxState::Failed,
                        Some(Ok(error.rollback)),
                        "host resource materialization failed",
                    );
                    // Persist receipts for resources that were actually created
                    // so partially rolled back leftovers stay visible to
                    // review and garbage collection.
                    self.persist_outcome(&outcome, state, &error.created)
                        .await?;
                    self.ledger
                        .mark_resources_released(&context.sandbox_id, &released)
                        .await?;
                    return Ok(outcome);
                }
            };

        let backend_class = runtime_to_backend_class(
            handle
                .runtime
                .read()
                .unwrap_or(handle.backend.metadata().runtime),
        );
        let network_receipts = match self
            .network
            .provision(context.sandbox_id.as_str(), backend_class)
            .await
        {
            Ok(receipts) => receipts,
            Err(err) => {
                let teardown = self
                    .host_resources
                    .teardown_async(workspaces, context.sandbox_id.as_str())
                    .await;
                let outcome =
                    host_resource_outcome(&context, format!("network provision failed: {err}"));
                let (outcome, state, released) = outcome_with_cleanup(
                    outcome,
                    SandboxState::Failed,
                    Some(Ok(teardown)),
                    "network provision failed",
                );
                self.persist_outcome(&outcome, state, &host_receipts)
                    .await?;
                self.ledger
                    .mark_resources_released(&context.sandbox_id, &released)
                    .await?;
                return Ok(outcome);
            }
        };

        let token = self.register_active(&context.operation_id).await;
        let execution = run_until_deadline(
            &token,
            context.deadline_unix_ms,
            handle.backend.prepare(&effective_config),
        )
        .await;
        self.unregister_active(&context.operation_id).await;

        let network_released = if matches!(execution, Execution::Completed(Ok(_))) {
            Vec::new()
        } else {
            self.network
                .deprovision(context.sandbox_id.as_str(), backend_class)
                .await
        };
        let cleanup = if matches!(execution, Execution::Completed(Ok(_))) {
            None
        } else {
            let backend_cleanup = cleanup_failed_setup(&*handle.backend).await;
            Some(match backend_cleanup {
                Ok(mut report) => {
                    let mut teardown = self
                        .host_resources
                        .teardown_async(workspaces, context.sandbox_id.as_str())
                        .await;
                    teardown.released.append(&mut report.released);
                    teardown.remaining.append(&mut report.remaining);
                    Ok(teardown)
                }
                Err(error) => {
                    // Host resources are still released best-effort so the GC
                    // does not re-collect resources that are already gone.
                    self.host_resources
                        .teardown_async(workspaces, context.sandbox_id.as_str())
                        .await;
                    Err(error)
                }
            })
        };
        let (outcome, state, resources, mut released) = match execution {
            Execution::Completed(Ok(prepared)) => {
                let mut resources = host_receipts;
                resources.extend(network_receipts);
                resources.extend(prepared.resources);
                (
                    successful_outcome(&context, OperationKind::Prepare, OutcomeReason::Completed),
                    SandboxState::Preparing,
                    resources,
                    Vec::new(),
                )
            }
            Execution::Completed(Err(error)) => {
                let outcome = backend_error_outcome(&context, OperationKind::Prepare, &error);
                let (outcome, state, released) = outcome_with_cleanup(
                    outcome,
                    SandboxState::Failed,
                    cleanup,
                    "runtime preparation failed",
                );
                let mut created = host_receipts;
                created.extend(network_receipts);
                (outcome, state, created, released)
            }
            Execution::Canceled => {
                let outcome = canceled_outcome(&context, OperationKind::Prepare);
                let (outcome, state, released) = outcome_with_cleanup(
                    outcome,
                    SandboxState::Failed,
                    cleanup,
                    "runtime preparation was canceled",
                );
                let mut created = host_receipts;
                created.extend(network_receipts);
                (outcome, state, created, released)
            }
            Execution::TimedOut => {
                let outcome = timed_out_outcome(&context, OperationKind::Prepare);
                let (outcome, state, released) = outcome_with_cleanup(
                    outcome,
                    SandboxState::Failed,
                    cleanup,
                    "runtime preparation timed out",
                );
                let mut created = host_receipts;
                created.extend(network_receipts);
                (outcome, state, created, released)
            }
        };
        // Deprovision ran even when backend cleanup failed; keep TAP/veth
        // receipts from staying present after the devices were torn down.
        released.extend(network_released);
        self.persist_outcome(&outcome, state, &resources).await?;
        self.ledger
            .mark_resources_released(&context.sandbox_id, &released)
            .await?;
        Ok(outcome)
    }

    /// Boots a prepared runtime and establishes a fail-closed guest session.
    ///
    /// `sandboxd` treats backend start, transport attachment, and framed guest
    /// handshake as one supervised unit. Observed state becomes Running only
    /// after the guest session is stored. JSON-RPC readiness probes are not
    /// used on this path.
    ///
    /// # Errors
    ///
    /// Returns an error when no runtime is attached or the ledger cannot be updated.
    pub async fn boot(&self, context: CommandContext) -> Result<OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Boot,
                &metadata,
                SandboxState::Booting,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let backend = Arc::clone(&handle.backend);
        let backend_for_cleanup = Arc::clone(&backend);
        let require_guest = self.require_guest_session;
        let sandbox_id = context.sandbox_id.to_string();
        let policy_epoch = context.policy_epoch;
        let image_id = handle.image_id.read().clone();
        let image_digest = handle.image_digest.read().clone();
        let execution = run_until_deadline(&token, context.deadline_unix_ms, async move {
            backend.boot().await?;
            let transport = backend.attach_transport().await?;
            if require_guest {
                let session = establish_guest_session(
                    &sandbox_id,
                    policy_epoch,
                    &transport,
                    &image_id,
                    &image_digest,
                )
                .await?;
                Ok::<Option<GuestConnection>, BackendError>(Some(session))
            } else {
                // Legacy path: JSON-RPC readiness, no session ownership.
                backend.wait_ready(&transport).await?;
                Ok(None)
            }
        })
        .await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, state, released, boot_resources) = match execution {
            Execution::Completed(Ok(session)) => {
                if let Some(session) = session {
                    *handle.guest_boot_id.write() = session.guest_boot_id().to_string();
                    *handle.guest_session.lock().await = Some(session);
                }
                let tenant_id = handle.tenant_id.read().clone();
                let backend_class = runtime_to_backend_class(
                    handle
                        .runtime
                        .read()
                        .unwrap_or(handle.backend.metadata().runtime),
                );
                match self
                    .dns
                    .attach(
                        context.sandbox_id.as_str(),
                        &tenant_id,
                        backend_class,
                        context.policy_epoch,
                    )
                    .await
                {
                    Ok(dns_receipts) => (
                        successful_outcome(&context, OperationKind::Boot, OutcomeReason::Completed),
                        SandboxState::Running,
                        Vec::new(),
                        dns_receipts,
                    ),
                    Err(err) => {
                        // Boot succeeded but DNS attach failed: fail closed by
                        // tearing down the guest session and reporting failure.
                        // The cleanup report flows through the shared tail so
                        // released resources are marked in the ledger and
                        // partial cleanup surfaces as RequiresReview.
                        *handle.guest_session.lock().await = None;
                        handle.guest_boot_id.write().clear();
                        let _ = handle.backend.destroy().await;
                        let cleanup = cleanup_failed_setup(&*backend_for_cleanup).await;
                        let mut outcome = successful_outcome(
                            &context,
                            OperationKind::Boot,
                            OutcomeReason::BackendFailure,
                        );
                        outcome.status = OutcomeStatus::Failed;
                        outcome.message = Some(format!("DNS attachment failed during boot: {err}"));
                        let (outcome, state, released) = outcome_with_cleanup(
                            outcome,
                            SandboxState::Failed,
                            Some(cleanup),
                            "DNS attachment failed during boot",
                        );
                        (outcome, state, released, Vec::new())
                    }
                }
            }
            other => {
                let cleanup = cleanup_failed_setup(&*backend_for_cleanup).await;
                let outcome = match other {
                    Execution::Completed(Err(ref error)) => {
                        backend_error_outcome(&context, OperationKind::Boot, error)
                    }
                    Execution::Canceled => canceled_outcome(&context, OperationKind::Boot),
                    Execution::TimedOut => timed_out_outcome(&context, OperationKind::Boot),
                    Execution::Completed(Ok(_)) => unreachable!(),
                };
                let (outcome, state, released) = outcome_with_cleanup(
                    outcome,
                    SandboxState::Failed,
                    Some(cleanup),
                    "sandbox boot did not become ready",
                );
                (outcome, state, released, Vec::new())
            }
        };
        self.persist_outcome(&outcome, state, &boot_resources)
            .await?;
        self.ledger
            .mark_resources_released(&context.sandbox_id, &released)
            .await?;
        Ok(outcome)
    }

    /// Streams guest exec frames for a sandbox with an established session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sandbox has no guest session or the guest RPC fails.
    pub async fn exec_guest_stream(
        &self,
        context: CommandContext,
        command: String,
        args: Vec<String>,
        env: hashbrown::HashMap<String, String>,
        working_dir: String,
        timeout: Option<std::time::Duration>,
    ) -> Result<
        tokio::sync::mpsc::Receiver<Result<ExecStreamEvent, GuestClientError>>,
        SupervisorError,
    > {
        self.ensure_initialized().await?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        // A missing session means the exec was never admitted: refuse before
        // registering the operation so a sandboxd restart does not report a
        // dangling 'running' row as an interrupted operation.
        let mut session_guard = handle.guest_session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            SupervisorError::GuestSession(GuestSessionError::NoSession {
                sandbox_id: context.sandbox_id.to_string(),
            })
        })?;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Exec,
                &metadata,
                SandboxState::Running,
            )
            .await?
        {
            BeginOperation::Replay(_) => {
                return Err(SupervisorError::GuestSession(
                    GuestSessionError::ReplayNotSupported,
                ));
            }
            BeginOperation::Execute => {}
        }

        let token = self.register_active(&context.operation_id).await;
        let operation_id = context.operation_id.to_string();
        let rx = run_until_deadline(&token, context.deadline_unix_ms, async {
            session
                .exec_stream(&command, &args, &env, &working_dir, &operation_id, timeout)
                .await
        })
        .await;

        self.unregister_active(&context.operation_id).await;

        match rx {
            Execution::Completed(Ok(mut receiver)) => {
                let mut events = Vec::new();
                let mut terminal_ok = false;
                while let Some(item) = receiver.recv().await {
                    match &item {
                        Ok(ExecStreamEvent::Exited { .. }) => terminal_ok = true,
                        Ok(ExecStreamEvent::Failed { .. }) => terminal_ok = false,
                        Err(_) => terminal_ok = false,
                        _ => {}
                    }
                    events.push(item);
                }
                let outcome = if terminal_ok {
                    successful_outcome(&context, OperationKind::Exec, OutcomeReason::Completed)
                } else {
                    OperationOutcome {
                        status: OutcomeStatus::Failed,
                        reason: OutcomeReason::BackendFailure,
                        message: Some("guest exec did not complete successfully".into()),
                        ..base_outcome(&context, OperationKind::Exec)
                    }
                };
                self.persist_outcome(&outcome, SandboxState::Running, &[])
                    .await?;
                let (tx, rx) = tokio::sync::mpsc::channel(events.len().max(1));
                for event in events {
                    let _ = tx.send(event).await;
                }
                Ok(rx)
            }
            Execution::Completed(Err(err)) => {
                let outcome = OperationOutcome {
                    status: OutcomeStatus::Failed,
                    reason: OutcomeReason::BackendFailure,
                    message: Some(err.to_string()),
                    ..base_outcome(&context, OperationKind::Exec)
                };
                self.persist_outcome(&outcome, SandboxState::Running, &[])
                    .await?;
                Err(SupervisorError::GuestSession(
                    GuestSessionError::RpcFailed {
                        detail: err.to_string(),
                    },
                ))
            }
            Execution::Canceled => {
                let outcome = canceled_outcome(&context, OperationKind::Exec);
                self.persist_outcome(&outcome, SandboxState::Running, &[])
                    .await?;
                Err(SupervisorError::GuestSession(
                    GuestSessionError::ExecCanceled,
                ))
            }
            Execution::TimedOut => {
                let outcome = timed_out_outcome(&context, OperationKind::Exec);
                self.persist_outcome(&outcome, SandboxState::Running, &[])
                    .await?;
                Err(SupervisorError::GuestSession(
                    GuestSessionError::ExecTimedOut,
                ))
            }
        }
    }

    /// Reads a guest file through the established session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sandbox has no guest session or the guest RPC fails.
    pub async fn guest_file_read(
        &self,
        sandbox_id: &SandboxId,
        path: &str,
        operation_id: &str,
        max_bytes: u64,
    ) -> Result<GetFileResult, SupervisorError> {
        let handle = self.runtime_handle(sandbox_id.as_str(), None).await?;
        let _gate = handle.operation_gate.lock().await;
        let mut session_guard = handle.guest_session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            SupervisorError::GuestSession(GuestSessionError::NoSession {
                sandbox_id: sandbox_id.to_string(),
            })
        })?;
        let result = session.get_file(path, operation_id).await.map_err(|e| {
            SupervisorError::GuestSession(GuestSessionError::RpcFailed {
                detail: e.to_string(),
            })
        })?;
        // Server-side cap: prevent unbounded memory from oversized guest file responses.
        const DEFAULT_READ_CAP: u64 = 16 * 1024 * 1024;
        let cap = if max_bytes == 0 {
            DEFAULT_READ_CAP
        } else {
            max_bytes
        };
        if result.data.len() as u64 > cap {
            return Err(SupervisorError::GuestSession(
                GuestSessionError::OutputLimit {
                    path: path.to_string(),
                    cap,
                },
            ));
        }
        Ok(result)
    }

    /// Writes a guest file through the established session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sandbox has no guest session or the guest RPC fails.
    pub async fn guest_file_write(
        &self,
        sandbox_id: &SandboxId,
        path: &str,
        content: &[u8],
        mode: u32,
        operation_id: &str,
    ) -> Result<u64, SupervisorError> {
        let handle = self.runtime_handle(sandbox_id.as_str(), None).await?;
        let _gate = handle.operation_gate.lock().await;
        let mut session_guard = handle.guest_session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            SupervisorError::GuestSession(GuestSessionError::NoSession {
                sandbox_id: sandbox_id.to_string(),
            })
        })?;
        let response = session
            .put_file(path, content, mode, true, operation_id)
            .await
            .map_err(|e| {
                SupervisorError::GuestSession(GuestSessionError::RpcFailed {
                    detail: e.to_string(),
                })
            })?;
        match response.result {
            Some(pico_guest_protocol::operational_v1::put_file_response::Result::BytesWritten(
                n,
            )) => Ok(n),
            Some(pico_guest_protocol::operational_v1::put_file_response::Result::Error(err)) => {
                Err(SupervisorError::GuestSession(
                    GuestSessionError::RpcFailed {
                        detail: format!("put file failed: {err:?}"),
                    },
                ))
            }
            None => Err(SupervisorError::GuestSession(
                GuestSessionError::RpcFailed {
                    detail: "put file returned empty result".into(),
                },
            )),
        }
    }

    /// Injects secrets into the guest through the established session.
    ///
    /// Host passes a lease-backed credential request (optionally with inline
    /// material for tests). sandboxd validates the lease when configured,
    /// fetches the broker when material is absent, and injects via the framed
    /// guest session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sandbox has no guest session, the request is
    /// invalid, lease validation fails, the broker fails, or guest inject fails.
    pub async fn inject_secrets(
        &self,
        sandbox_id: &SandboxId,
        operation_id: &str,
        policy_epoch: u64,
        spec: &pico_sandboxd_proto::v1::CredentialInjectSpec,
    ) -> Result<(), SupervisorError> {
        self.ensure_initialized().await?;
        let handle = self.runtime_handle(sandbox_id.as_str(), None).await?;
        let _gate = handle.operation_gate.lock().await;
        let mut session_guard = handle.guest_session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            SupervisorError::GuestSession(GuestSessionError::NoSession {
                sandbox_id: sandbox_id.to_string(),
            })
        })?;
        self.secrets
            .inject(sandbox_id, operation_id, policy_epoch, spec, session)
            .await?;
        Ok(())
    }

    /// Lists a guest directory by running a constrained `find` via the guest session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sandbox has no guest session or the guest RPC fails.
    pub async fn guest_file_list(
        &self,
        sandbox_id: &SandboxId,
        dir: &str,
        recursive: bool,
        operation_id: &str,
    ) -> Result<Vec<(String, bool, u64)>, SupervisorError> {
        let handle = self.runtime_handle(sandbox_id.as_str(), None).await?;
        let _gate = handle.operation_gate.lock().await;
        let mut session_guard = handle.guest_session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            SupervisorError::GuestSession(GuestSessionError::NoSession {
                sandbox_id: sandbox_id.to_string(),
            })
        })?;
        let maxdepth = if recursive {
            Vec::new()
        } else {
            vec!["-maxdepth".into(), "1".into()]
        };
        let mut args = vec![dir.into()];
        args.extend(maxdepth);
        args.extend([
            "-mindepth".into(),
            "1".into(),
            "-printf".into(),
            "%y %s %p\\n".into(),
        ]);
        let result = session
            .exec(
                "find",
                &args,
                &hashbrown::HashMap::default(),
                "/",
                operation_id,
                Some(std::time::Duration::from_secs(30)),
            )
            .await
            .map_err(|e| {
                SupervisorError::GuestSession(GuestSessionError::RpcFailed {
                    detail: e.to_string(),
                })
            })?;
        if result.status != "success" {
            return Err(SupervisorError::GuestSession(
                GuestSessionError::RpcFailed {
                    detail: format!("guest file list failed: {}", result.status),
                },
            ));
        }
        let stdout = String::from_utf8_lossy(&result.stdout);
        let mut entries = Vec::new();
        for line in stdout.lines() {
            let mut parts = line.splitn(3, ' ');
            let kind = parts.next().unwrap_or("");
            let size: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let path = parts.next().unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            entries.push((path, kind == "d", size));
        }
        Ok(entries)
    }

    /// Cancels a supervised operation and best-effort cancels the guest op.
    ///
    /// Returns whether a local active operation token was canceled.
    pub async fn cancel_with_guest(
        &self,
        operation_id: &OperationId,
        sandbox_id: &SandboxId,
    ) -> bool {
        let local = self.cancel(operation_id).await;
        if let Ok(handle) = self.runtime_handle(sandbox_id.as_str(), None).await {
            let mut session_guard = handle.guest_session.lock().await;
            if let Some(session) = session_guard.as_mut() {
                let _ = session.cancel(operation_id.as_str()).await;
            }
        }
        local
    }

    /// Returns whether a guest session is established for the sandbox.
    pub async fn has_guest_session(&self, sandbox_id: &SandboxId) -> bool {
        let Ok(handle) = self.runtime_handle(sandbox_id.as_str(), None).await else {
            return false;
        };
        handle.guest_session.lock().await.is_some()
    }

    /// Executes a guest command under per-sandbox serialization and deadline control.
    ///
    /// The operation outcome is durable, but stdout and stderr are intentionally
    /// returned only to the caller and are never written to the local ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when no runtime is attached or the ledger cannot be updated.
    pub async fn exec(
        &self,
        context: CommandContext,
        request: ExecRequest,
    ) -> Result<(OperationOutcome, Option<ExecResponse>), SupervisorError> {
        self.ensure_initialized().await?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Exec,
                &metadata,
                SandboxState::Running,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok((*outcome, None)),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let execution = run_until_deadline(
            &token,
            context.deadline_unix_ms,
            handle.backend.exec(request),
        )
        .await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, response) = match execution {
            Execution::Completed(Ok(response)) => (
                successful_outcome(&context, OperationKind::Exec, OutcomeReason::Completed),
                Some(response),
            ),
            Execution::Completed(Err(error)) => (
                backend_error_outcome(&context, OperationKind::Exec, &error),
                None,
            ),
            Execution::Canceled => (canceled_outcome(&context, OperationKind::Exec), None),
            Execution::TimedOut => (timed_out_outcome(&context, OperationKind::Exec), None),
        };
        self.persist_outcome(&outcome, SandboxState::Running, &[])
            .await?;
        Ok((outcome, response))
    }

    /// Suspends a running sandbox and persists the operation outcome.
    ///
    /// The backend is asked to suspend and the resulting state transition to
    /// `Suspended` is recorded durably. The runtime handle is retained so later
    /// resume can pick up where suspend left off.
    ///
    /// # Errors
    ///
    /// Returns an error when no runtime is attached or the ledger cannot be updated.
    pub async fn suspend(
        &self,
        context: CommandContext,
    ) -> Result<OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Suspend,
                &metadata,
                SandboxState::Suspending,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let execution =
            run_until_deadline(&token, context.deadline_unix_ms, handle.backend.suspend()).await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, state) = suspend_outcome_from_execution(&context, execution);
        self.persist_outcome(&outcome, state, &[]).await?;
        Ok(outcome)
    }

    /// Resumes a suspended sandbox and persists the operation outcome.
    ///
    /// The backend is asked to resume and the resulting state transition to
    /// `Running` is recorded durably. The runtime handle is retained throughout
    /// the suspend/resume cycle.
    ///
    /// # Errors
    ///
    /// Returns an error when no runtime is attached or the ledger cannot be updated.
    pub async fn resume(
        &self,
        context: CommandContext,
    ) -> Result<OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Resume,
                &metadata,
                SandboxState::Resuming,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let execution =
            run_until_deadline(&token, context.deadline_unix_ms, handle.backend.resume()).await;
        self.unregister_active(&context.operation_id).await;

        let (outcome, state) = resume_outcome_from_execution(&context, execution);
        self.persist_outcome(&outcome, state, &[]).await?;
        Ok(outcome)
    }

    /// Destroys the runtime, completes backend cleanup, and releases its live handle.
    ///
    /// Host resources (cgroup, workspace, CPU allocation) are torn down after
    /// the backend finishes cleanup, and the released names mark the matching
    /// ledger receipts. Successful destroy removes the in-memory runtime
    /// handle only after the backend proves cleanup completion, which keeps
    /// repeated destroy calls and restart reconciliation honest about
    /// remaining ownership.
    ///
    /// When no runtime handle is attached (a sandboxd restart dropped all
    /// process-local handles), the command falls through to
    /// [`SandboxSupervisor::resume_destroy_from_ledger`].
    ///
    /// # Errors
    ///
    /// Returns an error when no runtime is attached or the ledger cannot be updated.
    pub async fn destroy(
        &self,
        context: CommandContext,
    ) -> Result<OperationOutcome, SupervisorError> {
        self.ensure_initialized().await?;
        let handle = match self.runtime_handle(context.sandbox_id.as_str(), None).await {
            Ok(handle) => handle,
            Err(SupervisorError::RuntimeNotAttached(_)) => {
                return self.resume_destroy_from_ledger(context).await;
            }
            Err(err) => return Err(err),
        };
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Destroy,
                &metadata,
                SandboxState::Destroying,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let backend = Arc::clone(&handle.backend);
        let execution = run_until_deadline(&token, context.deadline_unix_ms, async move {
            let mut report = backend.destroy().await?;
            let cleanup = backend.cleanup().await?;
            report.released.extend(cleanup.released);
            report.remaining.extend(cleanup.remaining);
            Ok::<_, BackendError>(report)
        })
        .await;
        self.unregister_active(&context.operation_id).await;

        // DNS attach and TAP/veth are owned by sandboxd; tear down before host
        // resource teardown. Adapters do not delete host network objects.
        let dns_released = self.dns.detach(context.sandbox_id.as_str()).await;
        let network_released = self
            .network
            .deprovision(
                context.sandbox_id.as_str(),
                runtime_to_backend_class(handle.backend.metadata().runtime),
            )
            .await;

        let (outcome, state, mut released) = match execution {
            Execution::Completed(Ok(report)) => {
                let mut released = report.released;
                let mut remaining = report.remaining;
                match self.host_resources.workspaces().await {
                    Ok(workspaces) => {
                        let mut teardown = self
                            .host_resources
                            .teardown_async(workspaces, context.sandbox_id.as_str())
                            .await;
                        released.append(&mut teardown.released);
                        remaining.append(&mut teardown.remaining);
                    }
                    Err(_) => {
                        remaining.push(cgroup_receipt_name(context.sandbox_id.as_str()));
                        if self
                            .host_resources
                            .cpu_isolation_policy()
                            .requires_pinning()
                        {
                            remaining.push(cpu_receipt_name(context.sandbox_id.as_str()));
                        }
                        remaining.push(workspace_receipt_name(context.sandbox_id.as_str()));
                    }
                }
                if remaining.is_empty() {
                    (
                        successful_outcome(
                            &context,
                            OperationKind::Destroy,
                            OutcomeReason::Completed,
                        ),
                        SandboxState::Destroyed,
                        released,
                    )
                } else {
                    (
                        partial_cleanup_outcome(&context, &remaining),
                        SandboxState::Failed,
                        released,
                    )
                }
            }
            Execution::Completed(Err(error)) => {
                // The backend could not prove cleanup, so runtime ownership is
                // ambiguous: host resources stay in place for operator review
                // instead of risking teardown under a live runtime.
                (
                    backend_error_outcome(&context, OperationKind::Destroy, &error),
                    SandboxState::Failed,
                    Vec::new(),
                )
            }
            Execution::Canceled => (
                canceled_outcome(&context, OperationKind::Destroy),
                SandboxState::Failed,
                Vec::new(),
            ),
            Execution::TimedOut => (
                timed_out_outcome(&context, OperationKind::Destroy),
                SandboxState::Failed,
                Vec::new(),
            ),
        };
        // Detach ran unconditionally above, so its releases apply to every
        // terminal arm. Otherwise receipts recorded at boot stay "present"
        // after a failed or retried destroy even though detach succeeded.
        released.extend(dns_released);
        released.extend(network_released);
        self.persist_outcome(&outcome, state, &[]).await?;
        self.ledger
            .mark_resources_released(&context.sandbox_id, &released)
            .await?;
        if outcome.status == OutcomeStatus::Succeeded {
            if let Some(handle) = self.runtimes.read().await.get(context.sandbox_id.as_str()) {
                *handle.guest_session.lock().await = None;
                handle.guest_boot_id.write().clear();
            }
            self.runtimes
                .write()
                .await
                .remove(context.sandbox_id.as_str());
            // Prefer Removed over the upsert already emitted by persist_outcome
            // so hosts drop port routes instead of caching a destroyed snapshot.
            self.publish_watch(ObservationWatchEvent::Removed(context.sandbox_id.clone()));
        }
        Ok(outcome)
    }

    /// Resumes an interrupted destroy from durable ledger state alone.
    ///
    /// Runtime handles are process-local, so a sandboxd restart detaches the
    /// supervisor from every backend. A destroy with durable destroy intent is
    /// safe to finish from receipts: DNS detach and host resource teardown are
    /// deterministic, idempotent, and were fenced before the restart. Sandboxes
    /// without destroy intent keep failing with `RuntimeNotAttached`: their
    /// runtime may still be live on the host (reparented, unreachable), so
    /// host resources stay put for operator review instead of risking teardown
    /// under a running workload.
    ///
    /// Destroy intent is durable evidence, not just the observed state:
    /// `Destroying` and `Destroyed` prove it directly, while `Failed` proves it
    /// only when the ledger's latest operation is destroy (the destroy reached
    /// teardown and ended in partial cleanup or was restarted away). A `Failed`
    /// sandbox whose latest operation is anything else never finished its
    /// backend teardown, so its resources stay for review.
    ///
    /// The path races no deadline: teardown already bounds its own transient
    /// retries, so a restarted supervisor converges even when the original
    /// command deadline lapsed during the restart.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeNotAttached` for unknown sandboxes and for sandboxes
    /// without durable destroy intent, or a ledger error.
    async fn resume_destroy_from_ledger(
        &self,
        context: CommandContext,
    ) -> Result<OperationOutcome, SupervisorError> {
        let Some(status) = self.ledger.sandbox_status(&context.sandbox_id).await? else {
            return Err(SupervisorError::RuntimeNotAttached(
                context.sandbox_id.to_string(),
            ));
        };
        let destroy_intent = match status.observed_state {
            SandboxState::Destroying | SandboxState::Destroyed => true,
            SandboxState::Failed => self
                .ledger
                .latest_operation_kind(&context.sandbox_id)
                .await?
                .is_some_and(|kind| kind == OperationKind::Destroy),
            _ => false,
        };
        if !destroy_intent {
            return Err(SupervisorError::RuntimeNotAttached(
                context.sandbox_id.to_string(),
            ));
        }
        // The persisted runtime identity replaces handle metadata so fencing
        // and monotonicity checks run against exactly what the ledger recorded.
        let metadata = BackendMetadata {
            runtime: status.runtime,
            version: status.backend_version.clone(),
            // Capabilities are not consulted on the destroy path; the ledger
            // only persists runtime family and backend version.
            capabilities: BackendCapabilities::default(),
        };
        match self
            .begin(
                &context,
                OperationKind::Destroy,
                &metadata,
                SandboxState::Destroying,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => return Ok(*outcome),
            BeginOperation::Execute => {}
        }

        // Same host-resource leg as the supervised destroy path, minus backend
        // mechanics: no backend exists after a restart, and process identities
        // were already marked unrecoverable during startup reconciliation.
        let dns_released = self.dns.detach(context.sandbox_id.as_str()).await;
        let network_released = self
            .network
            .deprovision(
                context.sandbox_id.as_str(),
                runtime_to_backend_class(status.runtime),
            )
            .await;
        let (outcome, state, mut released) = match self.host_resources.workspaces().await {
            Ok(workspaces) => {
                let teardown = self
                    .host_resources
                    .teardown_async(workspaces, context.sandbox_id.as_str())
                    .await;
                if teardown.remaining.is_empty() {
                    (
                        successful_outcome(
                            &context,
                            OperationKind::Destroy,
                            OutcomeReason::Completed,
                        ),
                        SandboxState::Destroyed,
                        teardown.released,
                    )
                } else {
                    (
                        partial_cleanup_outcome(&context, &teardown.remaining),
                        SandboxState::Failed,
                        teardown.released,
                    )
                }
            }
            Err(_) => {
                let mut remaining = vec![cgroup_receipt_name(context.sandbox_id.as_str())];
                if self
                    .host_resources
                    .cpu_isolation_policy()
                    .requires_pinning()
                {
                    remaining.push(cpu_receipt_name(context.sandbox_id.as_str()));
                }
                remaining.push(workspace_receipt_name(context.sandbox_id.as_str()));
                (
                    partial_cleanup_outcome(&context, &remaining),
                    SandboxState::Failed,
                    Vec::new(),
                )
            }
        };
        released.extend(dns_released);
        released.extend(network_released);
        self.persist_outcome(&outcome, state, &[]).await?;
        self.ledger
            .mark_resources_released(&context.sandbox_id, &released)
            .await?;
        if outcome.status == OutcomeStatus::Succeeded {
            // Same watch contract as the supervised path: hosts drop port
            // routes for the removed sandbox.
            self.publish_watch(ObservationWatchEvent::Removed(context.sandbox_id.clone()));
        }
        Ok(outcome)
    }

    /// Runs a host process with pidfd tracking where supported.
    ///
    /// The supervisor records durable process identity and bounded stream
    /// capture while keeping stdin, stdout, and stderr out of the SQLite
    /// ledger.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid process requests, missing runtime state, or ledger access.
    pub async fn run_process(
        &self,
        context: CommandContext,
        request: ProcessRequest,
    ) -> Result<ProcessOutput, SupervisorError> {
        self.ensure_initialized().await?;
        request.validate()?;
        let handle = self
            .runtime_handle(context.sandbox_id.as_str(), None)
            .await?;
        let _gate = handle.operation_gate.lock().await;
        let metadata = handle.backend.metadata();
        match self
            .begin(
                &context,
                OperationKind::Process,
                &metadata,
                SandboxState::Running,
            )
            .await?
        {
            BeginOperation::Replay(outcome) => {
                return Ok(ProcessOutput {
                    outcome: *outcome,
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
            }
            BeginOperation::Execute => {}
        }
        let token = self.register_active(&context.operation_id).await;
        let result = self
            .process_registry
            .run(
                &self.ledger,
                &context,
                self.host_boot_id.as_str(),
                request,
                token,
            )
            .await;
        self.unregister_active(&context.operation_id).await;
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                let outcome = OperationOutcome {
                    status: OutcomeStatus::Failed,
                    reason: OutcomeReason::ProcessFailure,
                    message: Some(error.to_string()),
                    ..base_outcome(&context, OperationKind::Process)
                };
                self.persist_outcome(&outcome, SandboxState::Running, &[])
                    .await?;
                return Err(error);
            }
        };
        self.persist_outcome(&output.outcome, SandboxState::Running, &[])
            .await?;
        Ok(output)
    }

    /// Requests cancellation of an active runtime or process operation.
    ///
    /// Returns `true` when an active operation was found.
    pub async fn cancel(&self, operation_id: &OperationId) -> bool {
        let token = self
            .active_operations
            .lock()
            .await
            .get(operation_id.as_str())
            .cloned();
        if let Some(token) = token {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Returns the persisted host-local status for one sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn status(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<SandboxStatus>, SupervisorError> {
        self.ensure_initialized().await?;
        self.ledger.sandbox_status(sandbox_id).await
    }

    /// Returns all persisted host-local sandbox observations.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn statuses(&self) -> Result<Vec<SandboxStatus>, SupervisorError> {
        self.ensure_initialized().await?;
        self.ledger.list_sandbox_statuses().await
    }

    /// Returns the persisted resource receipts recorded for one sandbox,
    /// including their cleanup state.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn resource_receipts(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Vec<ResourceReceiptStatus>, SupervisorError> {
        self.ensure_initialized().await?;
        self.ledger.list_receipts(sandbox_id).await
    }

    /// Returns aggregate local supervision health for host reporting.
    ///
    /// The returned counts are derived from in-memory handles, while
    /// `review_required` is sourced from the durable ledger so health remains
    /// meaningful across supervisor restarts.
    pub async fn health(&self) -> SupervisorHealth {
        SupervisorHealth {
            ready: self.initialized.get().is_some(),
            reconcile_complete: self.reconcile_complete.load(Ordering::Acquire),
            review_required: self.review_required.load(Ordering::Relaxed),
            runtime_handles: self.runtimes.read().await.len(),
            process_handles: self.process_registry.active_count().await,
            stream_handles: self.process_registry.active_stream_count().await,
            pidfd_handles: self.process_registry.active_pidfd_count().await,
        }
    }

    /// Host boot identity associated with this supervisor process.
    #[must_use]
    pub fn host_boot_id(&self) -> &str {
        self.host_boot_id.as_str()
    }

    /// Creates a garbage collector that shares this supervisor's durable ledger
    /// and [`HostResourceManager`].
    ///
    /// The returned collector runs as a periodic background task. Callers should
    /// spawn [`GarbageCollector::run`] in a background tokio task. Orphan
    /// workspace/cgroup removal goes through the shared manager so GC is not a
    /// second writer of host resource trees.
    #[must_use]
    pub fn create_gc(&self) -> GarbageCollector {
        GarbageCollector::new(
            self.ledger.clone(),
            self.host_resources.clone(),
            crate::gc::DEFAULT_GC_INTERVAL,
        )
    }

    async fn ensure_initialized(&self) -> Result<(), SupervisorError> {
        self.initialized
            .get_or_try_init(|| async {
                self.ledger.initialize().await?;
                let interrupted = self.ledger.reconcile_interrupted_operations().await?;
                self.review_required.store(interrupted, Ordering::Relaxed);
                // Rebuild the CPU allocator from proven present receipts so a
                // restarted daemon cannot overcommit dedicated cores that were
                // allocated before the restart. Receipts of destroyed sandboxes
                // are excluded here (their cleanup is owned by the GC pass);
                // the "present and not destroyed" query is the single source of
                // truth for the rebuild, and fencing keeps concurrent destroys
                // single-writer so this snapshot is consistent.
                let cpu_receipts = self.ledger.list_present_cpu_receipts().await?;
                self.host_resources.restore_cpu_allocations(&cpu_receipts);
                self.reconcile_complete.store(true, Ordering::Release);
                Ok::<(), SupervisorError>(())
            })
            .await?;
        Ok(())
    }

    async fn runtime_handle(
        &self,
        sandbox_id: &str,
        backend: Option<Arc<dyn RuntimeBackend>>,
    ) -> Result<Arc<RuntimeHandle>, SupervisorError> {
        if let Some(handle) = self.runtimes.read().await.get(sandbox_id).cloned() {
            return Ok(handle);
        }
        let Some(backend) = backend else {
            return Err(SupervisorError::RuntimeNotAttached(sandbox_id.to_string()));
        };
        let mut runtimes = self.runtimes.write().await;
        Ok(Arc::clone(
            runtimes.entry(sandbox_id.to_string()).or_insert_with(|| {
                Arc::new(RuntimeHandle {
                    backend,
                    operation_gate: Mutex::new(()),
                    guest_session: Mutex::new(None),
                    generation: AtomicU64::new(0),
                    requested_ports: ParkingLotRwLock::new(Vec::new()),
                    guest_boot_id: ParkingLotRwLock::new(String::new()),
                    tenant_id: ParkingLotRwLock::new(String::new()),
                    runtime: ParkingLotRwLock::new(None),
                    ssh_host_port: ParkingLotRwLock::new(None),
                    ssh_public_key: ParkingLotRwLock::new(None),
                    image_id: ParkingLotRwLock::new(String::new()),
                    image_digest: ParkingLotRwLock::new(String::new()),
                })
            }),
        ))
    }

    async fn begin(
        &self,
        context: &CommandContext,
        kind: OperationKind,
        metadata: &BackendMetadata,
        state: SandboxState,
    ) -> Result<BeginOperation, SupervisorError> {
        self.ledger
            .begin_operation(BeginOperationRequest {
                context,
                kind,
                metadata,
                state,
                host_boot_id: self.host_boot_id.as_str(),
            })
            .await
    }

    async fn register_active(&self, operation_id: &OperationId) -> CancellationToken {
        let token = CancellationToken::new();
        self.active_operations
            .lock()
            .await
            .insert(operation_id.as_str().to_string(), token.clone());
        token
    }

    async fn unregister_active(&self, operation_id: &OperationId) {
        self.active_operations
            .lock()
            .await
            .remove(operation_id.as_str());
    }

    // Persisting outcomes in one helper keeps review accounting aligned with
    // the durable operation record instead of relying on callers to remember
    // both steps.
    async fn persist_outcome(
        &self,
        outcome: &OperationOutcome,
        state: SandboxState,
        resources: &[pico_core::ResourceReceipt],
    ) -> Result<(), SupervisorError> {
        self.ledger
            .complete_operation(outcome, state, resources)
            .await?;
        if outcome.status == OutcomeStatus::RequiresReview {
            self.review_required.fetch_add(1, Ordering::Relaxed);
        }
        self.bump_generation(outcome.sandbox_id.as_str()).await;
        // Successful destroy publishes Removed after the handle is dropped.
        // An upsert here would still include live ports and can win if Removed
        // is lost to Watch lag.
        if state != SandboxState::Destroyed {
            self.publish_observation_upsert(&outcome.sandbox_id).await;
        }
        Ok(())
    }

    async fn bump_generation(&self, sandbox_id: &str) {
        if let Some(handle) = self.runtimes.read().await.get(sandbox_id) {
            handle.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn publish_watch(&self, event: ObservationWatchEvent) {
        let _ = self.watch_tx.send(event);
    }

    async fn publish_observation_upsert(&self, sandbox_id: &SandboxId) {
        if let Ok(Some(snapshot)) = self.observation(sandbox_id).await {
            self.publish_watch(ObservationWatchEvent::Upsert(snapshot));
        }
    }

    /// Returns an enriched observation for one sandbox, or `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn observation(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<SandboxObservationSnapshot>, SupervisorError> {
        self.ensure_initialized().await?;
        let Some(status) = self.ledger.sandbox_status(sandbox_id).await? else {
            return Ok(None);
        };
        Ok(Some(self.enrich_status(status).await))
    }

    /// Returns enriched observations for every ledger sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn observations(&self) -> Result<Vec<SandboxObservationSnapshot>, SupervisorError> {
        self.ensure_initialized().await?;
        let statuses = self.ledger.list_sandbox_statuses().await?;
        let mut out = Vec::with_capacity(statuses.len());
        for status in statuses {
            out.push(self.enrich_status(status).await);
        }
        Ok(out)
    }

    /// Resolves one guest port target for host proxying.
    ///
    /// Returns `None` when the sandbox is unknown, the port was not requested,
    /// or the backend cannot yet publish a reachable target (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be read.
    pub async fn port_target(
        &self,
        sandbox_id: &SandboxId,
        guest_port: u16,
    ) -> Result<Option<(PortTargetObservation, u64)>, SupervisorError> {
        self.ensure_initialized().await?;
        if self.ledger.sandbox_status(sandbox_id).await?.is_none() {
            return Ok(None);
        }
        let Some(handle) = self.runtimes.read().await.get(sandbox_id.as_str()).cloned() else {
            return Ok(None);
        };
        let requested = handle.requested_ports.read().clone();
        if !requested.contains(&guest_port) {
            return Ok(None);
        }
        let generation = handle.generation.load(Ordering::Acquire);
        let Some(target) = resolve_port_target(&handle.backend, guest_port).await else {
            return Ok(None);
        };
        Ok(Some((
            PortTargetObservation { guest_port, target },
            generation,
        )))
    }

    /// Subscribes to observation Watch events.
    ///
    /// The returned receiver is lagging-safe; slow consumers drop intermediate
    /// events and must reconcile via [`Self::observations`].
    #[must_use]
    pub fn subscribe_watch(&self) -> tokio::sync::broadcast::Receiver<ObservationWatchEvent> {
        self.watch_tx.subscribe()
    }

    async fn enrich_status(&self, status: SandboxStatus) -> SandboxObservationSnapshot {
        let handle = self
            .runtimes
            .read()
            .await
            .get(status.sandbox_id.as_str())
            .cloned();
        let (generation, guest_boot_id, ports, ssh_host_port, ssh_public_key) = match handle {
            Some(handle) => {
                let generation = handle.generation.load(Ordering::Acquire);
                // Never lock guest_session here: lifecycle ops may hold it while
                // calling persist_outcome (e.g. exec stream), and tokio Mutex is
                // not reentrant.
                let guest_boot_id = handle.guest_boot_id.read().clone();
                let requested = handle.requested_ports.read().clone();
                let mut ports = Vec::with_capacity(requested.len());
                for guest_port in requested {
                    if let Some(target) = resolve_port_target(&handle.backend, guest_port).await {
                        ports.push(PortTargetObservation { guest_port, target });
                    }
                }
                let ssh_host_port = *handle.ssh_host_port.read();
                let ssh_public_key = handle.ssh_public_key.read().clone();
                (
                    generation,
                    guest_boot_id,
                    ports,
                    ssh_host_port,
                    ssh_public_key,
                )
            }
            None => (0, String::new(), Vec::new(), None, None),
        };
        SandboxObservationSnapshot {
            status,
            generation,
            guest_boot_id,
            ports,
            ssh_host_port,
            ssh_public_key,
        }
    }
}

async fn resolve_port_target(
    backend: &Arc<dyn RuntimeBackend>,
    guest_port: u16,
) -> Option<ResolvedPortTarget> {
    use pico_core::runtime::PortExposure;
    match backend.port_exposure(guest_port) {
        PortExposure::BackendManaged => Some(ResolvedPortTarget::BackendManaged),
        PortExposure::Unsupported => Some(ResolvedPortTarget::Unsupported),
        PortExposure::HostProxy => match backend.port_addr(guest_port).await {
            Ok(Some(addr)) => Some(ResolvedPortTarget::Tcp(addr)),
            Ok(None) | Err(_) => None,
        },
    }
}

fn handshake_config(
    sandbox_id: &str,
    policy_epoch: u64,
    transport_addr: std::net::SocketAddr,
    image_id: &str,
    image_digest: &str,
) -> HandshakeConfig {
    HandshakeConfig {
        sandbox_id: sandbox_id.into(),
        image_id: image_id.into(),
        image_digest: image_digest.into(),
        host_agent_version: env!("CARGO_PKG_VERSION").into(),
        host_capabilities: vec![
            "exec".into(),
            "file".into(),
            "mount".into(),
            "stats".into(),
            "health".into(),
            "shutdown".into(),
        ],
        transport_addr,
        timeout: std::time::Duration::from_secs(30),
        policy_epoch,
    }
}

async fn establish_guest_session(
    sandbox_id: &str,
    policy_epoch: u64,
    transport: &GuestTransport,
    image_id: &str,
    image_digest: &str,
) -> Result<GuestConnection, BackendError> {
    let dummy_addr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
    let result = match transport {
        GuestTransport::Unix { path } => {
            let config =
                handshake_config(sandbox_id, policy_epoch, dummy_addr, image_id, image_digest);
            GuestConnection::connect_unix(path, &config).await
        }
        GuestTransport::Vsock {
            port,
            uds_path: Some(uds_path),
            ..
        } => {
            let config =
                handshake_config(sandbox_id, policy_epoch, dummy_addr, image_id, image_digest);
            GuestConnection::connect_firecracker_vsock(uds_path, *port, &config).await
        }
        GuestTransport::Vsock {
            cid,
            port,
            uds_path: None,
        } => {
            let config =
                handshake_config(sandbox_id, policy_epoch, dummy_addr, image_id, image_digest);
            GuestConnection::connect_vsock(*cid, *port, &config).await
        }
    };
    match result {
        Ok(conn) => {
            if conn.capabilities().is_empty() {
                return Err(BackendError::NotReady {
                    operation: pico_core::BackendOperation::WaitReady,
                    reason: NonReadyReason::Protocol,
                    message: "guest handshake produced empty capabilities".into(),
                });
            }
            Ok(conn)
        }
        Err(err) => Err(handshake_to_backend_error(err)),
    }
}

fn handshake_to_backend_error(err: HandshakeError) -> BackendError {
    let reason = match &err {
        HandshakeError::Timeout(_) | HandshakeError::ConnectionRefused(_) => {
            NonReadyReason::Timeout
        }
        _ => NonReadyReason::Protocol,
    };
    BackendError::NotReady {
        operation: pico_core::BackendOperation::WaitReady,
        reason,
        message: err.to_string(),
    }
}

fn suspend_outcome_from_execution(
    context: &CommandContext,
    execution: Execution<Result<(), BackendError>>,
) -> (OperationOutcome, SandboxState) {
    match execution {
        Execution::Completed(Ok(())) => (
            successful_outcome(context, OperationKind::Suspend, OutcomeReason::Completed),
            SandboxState::Suspended,
        ),
        Execution::Completed(Err(error)) => (
            backend_error_outcome(context, OperationKind::Suspend, &error),
            SandboxState::Failed,
        ),
        Execution::Canceled => (
            canceled_outcome(context, OperationKind::Suspend),
            SandboxState::Failed,
        ),
        Execution::TimedOut => (
            timed_out_outcome(context, OperationKind::Suspend),
            SandboxState::Failed,
        ),
    }
}

fn resume_outcome_from_execution(
    context: &CommandContext,
    execution: Execution<Result<(), BackendError>>,
) -> (OperationOutcome, SandboxState) {
    match execution {
        Execution::Completed(Ok(())) => (
            successful_outcome(context, OperationKind::Resume, OutcomeReason::Completed),
            SandboxState::Running,
        ),
        Execution::Completed(Err(error)) => (
            backend_error_outcome(context, OperationKind::Resume, &error),
            SandboxState::Failed,
        ),
        Execution::Canceled => (
            canceled_outcome(context, OperationKind::Resume),
            SandboxState::Failed,
        ),
        Execution::TimedOut => (
            timed_out_outcome(context, OperationKind::Resume),
            SandboxState::Failed,
        ),
    }
}

fn outcome_with_cleanup(
    mut outcome: OperationOutcome,
    state: SandboxState,
    cleanup: Option<Result<pico_core::CleanupReport, BackendError>>,
    fallback_message: &str,
) -> (OperationOutcome, SandboxState, Vec<String>) {
    let Some(cleanup) = cleanup else {
        return (outcome, state, Vec::new());
    };
    match cleanup {
        Ok(report) if report.remaining.is_empty() => {
            if outcome.status == OutcomeStatus::RequiresReview {
                outcome.status = OutcomeStatus::Failed;
                outcome.reason = OutcomeReason::BackendFailure;
            }
            (outcome, state, report.released)
        }
        Ok(report) => {
            outcome.status = OutcomeStatus::RequiresReview;
            outcome.reason = OutcomeReason::PartialCleanup;
            outcome.non_ready_reason = Some(NonReadyReason::Cleanup);
            outcome.message = Some(format!(
                "{}; cleanup remains for resources: {}",
                outcome.message.as_deref().unwrap_or(fallback_message),
                report.remaining.join(", ")
            ));
            (outcome, SandboxState::Failed, report.released)
        }
        Err(error) => {
            outcome.status = OutcomeStatus::RequiresReview;
            outcome.reason = OutcomeReason::PartialCleanup;
            outcome.non_ready_reason = Some(NonReadyReason::Cleanup);
            outcome.message = Some(format!(
                "{}; cleanup failed: {error}",
                outcome.message.as_deref().unwrap_or(fallback_message)
            ));
            (outcome, SandboxState::Failed, Vec::new())
        }
    }
}

async fn cleanup_failed_setup(
    backend: &dyn RuntimeBackend,
) -> Result<pico_core::CleanupReport, BackendError> {
    let timeout = Duration::from_secs(30);
    tokio::time::timeout(timeout, backend.cleanup())
        .await
        .map_err(|_| BackendError::NotReady {
            operation: pico_core::BackendOperation::Cleanup,
            reason: NonReadyReason::Timeout,
            message: format!(
                "failed setup cleanup did not complete within {}s",
                timeout.as_secs()
            ),
        })?
}

fn successful_outcome(
    context: &CommandContext,
    kind: OperationKind,
    reason: OutcomeReason,
) -> OperationOutcome {
    OperationOutcome {
        status: OutcomeStatus::Succeeded,
        reason,
        message: None,
        ..base_outcome(context, kind)
    }
}

fn backend_error_outcome(
    context: &CommandContext,
    kind: OperationKind,
    error: &BackendError,
) -> OperationOutcome {
    let (status, reason) = match error {
        BackendError::NotReady {
            reason: NonReadyReason::Timeout,
            ..
        }
        | BackendError::Timeout { .. } => {
            (OutcomeStatus::TimedOut, OutcomeReason::DeadlineExceeded)
        }
        BackendError::PartialCleanup { .. } => {
            (OutcomeStatus::RequiresReview, OutcomeReason::PartialCleanup)
        }
        BackendError::IncompleteSetup { .. } => {
            (OutcomeStatus::RequiresReview, OutcomeReason::BackendFailure)
        }
        BackendError::NotReady { .. }
        | BackendError::StaleState { .. }
        | BackendError::Unsupported { .. }
        | BackendError::InvalidState { .. }
        | BackendError::Failed { .. }
        | BackendError::Backend { .. } => (OutcomeStatus::Failed, OutcomeReason::BackendFailure),
    };
    OperationOutcome {
        status,
        reason,
        non_ready_reason: Some(error.non_ready_reason()),
        message: Some(error.to_string()),
        ..base_outcome(context, kind)
    }
}

fn canceled_outcome(context: &CommandContext, kind: OperationKind) -> OperationOutcome {
    OperationOutcome {
        status: OutcomeStatus::Canceled,
        reason: OutcomeReason::CanceledByHost,
        message: Some("operation canceled by host-agent".into()),
        ..base_outcome(context, kind)
    }
}

fn timed_out_outcome(context: &CommandContext, kind: OperationKind) -> OperationOutcome {
    OperationOutcome {
        status: OutcomeStatus::TimedOut,
        reason: OutcomeReason::DeadlineExceeded,
        non_ready_reason: Some(NonReadyReason::Timeout),
        message: Some("persisted operation deadline elapsed".into()),
        ..base_outcome(context, kind)
    }
}

/// Outcome used when host resource materialization or workspace initialization
/// fails before the backend is invoked.
fn host_resource_outcome(context: &CommandContext, message: String) -> OperationOutcome {
    OperationOutcome {
        status: OutcomeStatus::Failed,
        reason: OutcomeReason::BackendFailure,
        non_ready_reason: Some(NonReadyReason::Resource),
        message: Some(message),
        ..base_outcome(context, OperationKind::Prepare)
    }
}

/// Outcome used when destroy or cleanup left known resources behind.
///
/// Host cgroup/workspace teardown already exhausted bounded transient retries
/// before contributing names here. `RequiresReview` is intentional for those
/// leftovers and for backend resources without a safe auto-remove path.
fn partial_cleanup_outcome(context: &CommandContext, remaining: &[String]) -> OperationOutcome {
    OperationOutcome {
        status: OutcomeStatus::RequiresReview,
        reason: OutcomeReason::PartialCleanup,
        message: Some(format!(
            "cleanup remains for resources: {}",
            remaining.join(", ")
        )),
        ..base_outcome(context, OperationKind::Destroy)
    }
}

pub(crate) fn base_outcome(context: &CommandContext, kind: OperationKind) -> OperationOutcome {
    OperationOutcome {
        operation_id: context.operation_id.clone(),
        sandbox_id: context.sandbox_id.clone(),
        kind,
        status: OutcomeStatus::Running,
        reason: OutcomeReason::InProgress,
        non_ready_reason: None,
        message: None,
        completed_at: pico_core::now_iso(),
    }
}

pub(crate) fn duration_until(deadline_unix_ms: i64) -> Duration {
    let now = system_time_to_unix_ms(SystemTime::now());
    let remaining = deadline_unix_ms.saturating_sub(now);
    Duration::from_millis(u64::try_from(remaining).unwrap_or(0))
}

fn system_time_to_unix_ms(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

/// Unique temporary workspace root for in-memory supervisors so concurrent
/// test supervisors do not share a workspace directory.
fn default_test_workspace_root() -> PathBuf {
    std::env::temp_dir().join(pico_core::new_ulid("sandboxd-ws"))
}

fn default_secrets_coordinator() -> SecretsCoordinator {
    use pico_core::Hlc;
    use pico_core::event_bus::InMemoryAuditSink;
    SecretsCoordinator::new(
        None,
        None,
        Arc::new(InMemoryAuditSink::new()),
        Arc::new(Hlc::new()),
    )
}

fn runtime_to_backend_class(
    runtime: pico_core::RuntimeType,
) -> pico_network_agent::identity::BackendClass {
    use pico_core::RuntimeType;
    use pico_network_agent::identity::BackendClass;
    match runtime {
        RuntimeType::GVisor => BackendClass::Container,
        _ => BackendClass::MicroVm,
    }
}

/// Returns the observation epoch identity for this supervisor process.
///
/// The kernel boot UUID identifies the host, but sandboxd generations are
/// process-local and reset when only the daemon restarts. Add a per-process
/// incarnation so the host-agent can distinguish that reset from a host reboot.
fn read_host_boot_id() -> String {
    #[cfg(target_os = "linux")]
    let host_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("process-{}", std::process::id()));

    #[cfg(not(target_os = "linux"))]
    let host_boot_id = format!("process-{}", std::process::id());

    format!("{host_boot_id}:{}", ulid::Ulid::generate())
}

#[cfg(test)]
mod tests;
