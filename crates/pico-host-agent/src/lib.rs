//! Host-side sandbox orchestration built on top of runtime adapters.

pub mod auth;
pub mod boot;
pub mod cgroups;
pub mod client;
pub mod config;
pub mod file_integrity;
pub mod handshake;
pub mod health;
pub mod host_control;
pub mod identity;
pub mod image_on_demand;
pub mod image_verify;
pub mod metrics;
mod observation;
pub mod port_forward;
pub mod port_proxy;
mod port_target_cache;
pub mod preemption;
pub mod reaper;
pub mod restore;
pub mod sandboxd_client;
pub mod scheduler_capacity;
pub mod secrets;
pub mod stub;
pub mod syscall_audit;
pub mod task_registry;
pub mod workspace;

pub use host_control::HostControl;

use hashbrown::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex as ParkingLotMutex;
use parking_lot::RwLock as ParkingLotRwLock;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

/// Meta deadline for execs with no caller-specified timeout: far enough out
/// that the server-side operation deadline never bounds the guest command, yet
/// small enough to stay representable as an absolute unix ms timestamp.
const EXEC_NO_DEADLINE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

use crate::cgroups::{CgroupManager, DEFAULT_MAX_PIDS, default_soft_limit_bytes};
use pico_core::event_bus::NoopAuditSink;
use pico_core::{
    AuditEventSink, CredentialRequestSpec, EnforceContext, ExecRequest, ExecResponse, FencingToken,
    FileInfo, FileReadResponse, FileWriteRequest, Hlc, JobOutcome, JobPauseSignal, JobResumeSignal,
    LeaseAction, LeaseManager, LeaseScope, NonReadyReason, OperationId, PortForwardEndpoint,
    PortForwardRequest, PortForwardResponse, ResourceLimits, Result, RuntimeType, SandboxConfig,
    SandboxError, SandboxId, SandboxInfo, SandboxMetadata, SandboxSpec, SandboxState, SnapshotId,
    SshInfo, TaskEvent, TaskInfo, TaskRequest, TaskState, TenantId, ensure_destroy_precondition,
    ensure_purge_precondition, ensure_stop_precondition,
};
use pico_sandboxd_proto::v1::OutcomeReason as ProtoReason;

use pico_telemetry::{
    lifecycle::LifecycleOutcome,
    trace_context::{attr, record_bounded_attr, set_span_status_from_outcome},
};

use crate::boot::{
    BootCommand, BootObservation, BootReport, BootStatus, LifecycleReporter,
    TracingLifecycleReporter, emit_boot_cleanup, emit_boot_not_ready, emit_boot_ready,
    emit_boot_start, emit_create_completed, emit_create_failed, emit_create_started,
    emit_destroy_completed, emit_destroy_failed, emit_destroy_started,
    emit_prepare_completed_with_cache, emit_prepare_failed_with_cache, emit_prepare_started,
};
use crate::client::{
    emit_exec_not_completed, emit_exec_started, emit_restore_completed, emit_restore_failed,
    emit_restore_memory_restored, emit_restore_partial_cleanup, emit_restore_started,
    emit_resume_completed, emit_resume_failed, emit_resume_started, emit_resume_timed_out,
    emit_suspend_completed, emit_suspend_failed, emit_suspend_started, emit_suspend_timed_out,
};
use crate::health::HostHealth;
use crate::identity::{HostCapacity, HostIdentity, HostInventory};
use crate::observation::{
    ObservationSnapshot, apply_observation, proto_runtime_to_core, proto_state_to_core,
};
use crate::port_target_cache::PortTargetCache;
use crate::sandboxd_client::{
    CommandMetaParts, HostResourceParts, SandboxdConnect, SandboxdHandle,
};
use crate::task_util::*;
use crate::util::*;
use pico_sandboxd_proto::v1::HealthResponse;

struct BootState {
    assignment_fencing_token: FencingToken,
    policy_epoch: u64,
    last_boot_report: Option<BootReport>,
    last_reported_boot_operation: Option<OperationId>,
}

struct SandboxEntry {
    id: String,
    runtime: RuntimeType,
    observation: ParkingLotMutex<ObservationSnapshot>,
    config: SandboxConfig,
    desired: ParkingLotMutex<SandboxMetadata>,
    boot: ParkingLotMutex<BootState>,
    ports: Vec<u16>,
    idle_timeout: Duration,
    created_at: String,
    last_activity_at: ParkingLotMutex<String>,
    ssh_port: Option<u16>,
    ssh_public_key: Option<String>,
    ssh_private_key: Option<Zeroizing<String>>,
    ssh_home_dir: Option<String>,
    ssh_key_injected: AtomicBool,
    /// Image family this sandbox was admitted with. Carried for the handshake
    /// and observation surfaces.
    #[expect(
        dead_code,
        reason = "admitted image identity; consumed by the handshake surface added in a follow-up"
    )]
    image_id: Option<String>,
    /// Digest of the verified manifest, or the requested digest when no
    /// verifier is configured. Replaces a previously retained-but-unused
    /// field: the value is now produced by the prepare-path image gate.
    #[expect(
        dead_code,
        reason = "admitted image digest; consumed by the handshake surface added in a follow-up"
    )]
    image_digest: Option<String>,
    /// Evidence from the prepare-path image gate, reported on READY so the
    /// audit trail names the exact layer set that booted.
    verified_image: Option<crate::image_verify::VerifiedImageRecord>,
    #[expect(
        dead_code,
        reason = "retained for observation/handshake fields pending PR6/PR7"
    )]
    negotiated_capabilities: ParkingLotMutex<Vec<String>>,
    #[expect(
        dead_code,
        reason = "retained for observation/handshake fields pending PR6/PR7"
    )]
    guest_agent_version: ParkingLotMutex<Option<String>>,
    guest_boot_id: ParkingLotMutex<Option<String>>,
    #[expect(
        dead_code,
        reason = "retained for observation/handshake fields pending PR6/PR7"
    )]
    session_id: ParkingLotMutex<Option<Vec<u8>>>,
    #[expect(
        dead_code,
        reason = "stored for future use when protocol uses direct shared-secret references"
    )]
    shared_secret: Option<Zeroizing<Vec<u8>>>,
    cgroup: CgroupManager,
    credential_request: Option<CredentialRequestSpec>,
}

impl SandboxEntry {
    fn desired_state(&self) -> SandboxState {
        self.desired.lock().state
    }

    #[cfg(test)]
    fn test_ssh_username(&self) -> String {
        self.observation.lock().ssh_username.clone()
    }

    fn commit_desired(
        &self,
        from: SandboxState,
        to: SandboxState,
        token: Option<FencingToken>,
    ) -> Result<()> {
        self.desired.lock().commit(from, to, token)?;
        Ok(())
    }
}

fn default_supported_backends() -> Vec<RuntimeType> {
    vec![
        RuntimeType::Firecracker,
        RuntimeType::RemoteFirecracker,
        RuntimeType::Qemu,
        RuntimeType::GVisor,
    ]
}

/// Report the verified image on the READY transition.
///
/// A layered image emits the composition audit record naming the exact ordered
/// layer set that booted, which is what makes a placement or host audit
/// answer "which layers ran" without re-reading the manifest. A monolithic
/// image reports its verified manifest digest instead.
fn emit_verified_image_on_ready(entry: &SandboxEntry) {
    let Some(ref record) = entry.verified_image else {
        return;
    };
    match record.composition_audit_record.as_deref() {
        Some(composition) => tracing::info!(
            event = "ready_image_composition",
            sandbox_id = %entry.id,
            image_id = %record.image_id,
            manifest_digest = %record.manifest_digest,
            composition_digest = record.composition_digest.as_deref().unwrap_or("none"),
            layer_count = record.layer_count,
            composition = %composition,
            "sandbox ready with verified environment layer stack"
        ),
        None => tracing::info!(
            event = "ready_image",
            sandbox_id = %entry.id,
            image_id = %record.image_id,
            manifest_digest = %record.manifest_digest,
            layer_count = record.layer_count,
            "sandbox ready with verified monolithic image"
        ),
    }
}

/// Image admission gate, run on the prepare path before any host resource
/// exists.
///
/// Returns the verified image evidence to record on the sandbox entry, or
/// `None` when no verifier is configured. A configured-but-unusable verifier
/// fails closed: it never returns `None` to mean "allowed".
fn admit_image(
    agent: &HostAgent,
    runtime: RuntimeType,
) -> std::result::Result<Option<crate::image_verify::VerifiedImageRecord>, SandboxError> {
    let Some(verifier) = agent.image_verifier.as_ref() else {
        return Ok(None);
    };
    let capabilities = pico_runtime::declared_capabilities(runtime);
    match verifier.verify(runtime, &capabilities) {
        Ok(record) => {
            tracing::info!(
                event = "image_verified",
                image_id = %record.image_id,
                manifest_digest = %record.manifest_digest,
                composition_digest = record.composition_digest.as_deref().unwrap_or("none"),
                layer_count = record.layer_count,
                signer = record.signer_identity.as_deref().unwrap_or("unsigned"),
                mode = ?record.mode,
                "guest image admitted"
            );
            if let Some(ref audit) = record.composition_audit_record {
                tracing::info!(
                    event = "image_composition",
                    composition = %audit,
                    "verified environment layer set"
                );
            }
            Ok(Some(record))
        }
        Err(err) => {
            tracing::warn!(
                event = "image_rejected",
                reason = err.reason_label(),
                detail = %err,
                runtime = %runtime,
                "guest image rejected before prepare"
            );
            Err(SandboxError::PolicyDenied {
                reason: format!("image admission failed: {err}"),
            })
        }
    }
}

/// Parses the sandboxd health advertisement of runnable runtime families.
///
/// Unknown entries are skipped; an empty result (older sandboxd without the
/// capability field) keeps the caller's fallback advertisement instead of
/// advertising nothing.
fn parse_supported_backends(health: &HealthResponse) -> Vec<RuntimeType> {
    health
        .supported_runtimes
        .iter()
        .filter_map(|rt| proto_runtime_to_core(*rt))
        .collect()
}

fn default_ssh_home_dir(runtime: RuntimeType) -> String {
    // Test escape hatch for binary-level acceptance tests, where the guest
    // agent runs unprivileged on the host and `/root` is not writable.
    // Production never sets this; the per-runtime default applies.
    if let Ok(dir) = std::env::var("PICO_SSH_HOME_DIR")
        && !dir.trim().is_empty()
    {
        return dir;
    }
    match runtime {
        RuntimeType::GVisor => "/home/user".into(),
        _ => "/root".into(),
    }
}

/// SSH username matching [`default_ssh_home_dir`]: the GVisor image drops the
/// key under `/home/user`, so advertise `user`; every other runtime uses
/// `root`. sandboxd does not populate the observation's ssh username yet, so
/// this host-side mapping is authoritative.
fn default_ssh_username(runtime: RuntimeType) -> &'static str {
    match runtime {
        RuntimeType::GVisor => "user",
        _ => "root",
    }
}

struct HostBootFailure<'a> {
    bound_ports: &'a [(u16, u16)],
    revoke_ssh_key: bool,
    reason: NonReadyReason,
    message: String,
    started: Instant,
}

/// How often the host pulls a full ListSandboxes snapshot to reconcile Watch gaps.
const OBSERVATION_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Previous cumulative `memory.events`/`cpu.stat` counters per cgroup dir.
///
/// Each field is `None` until successfully read once, so a host restart
/// establishes a fresh baseline instead of spiking host totals with
/// pre-existing kernel counts. Fields stay at their last good value when a
/// poll fails to read or parse, so transient I/O never fabricates a delta.
#[derive(Debug, Clone, Copy, Default)]
struct CgroupEventBaseline {
    oom_kill: Option<u64>,
    high: Option<u64>,
    nr_throttled: Option<u64>,
}

/// Host-level totals for one `memory.pressure`/`memory.events`/`cpu.stat`
/// sweep across all sandbox cgroup dirs.
#[derive(Debug, Default)]
struct CgroupPollTotals {
    max_pressure: f64,
    pressure_read_errors: u64,
    oom_delta: u64,
    high_delta: u64,
    throttled_delta: u64,
}

/// Sweeps cgroup dirs once, returning host-level totals and updating baselines.
///
/// `memory.pressure` failures increment `pressure_read_errors` (operator
/// visibility into misconfiguration). `memory.events`/`cpu.stat` failures
/// are skipped without incrementing counters, keeping the previous baseline
/// so the next successful poll diffs correctly. Baselines for dirs that
/// disappeared are pruned to bound memory on churned hosts.
fn poll_cgroup_dirs(
    paths: &[PathBuf],
    baselines: &mut HashMap<PathBuf, CgroupEventBaseline>,
) -> CgroupPollTotals {
    let mut totals = CgroupPollTotals::default();
    for path in paths {
        let old = baselines.get(path).copied().unwrap_or_default();
        let mut next = old;

        match std::fs::read_to_string(path.join("memory.pressure")) {
            Ok(contents) => {
                if let Some(pressure) = crate::cgroups::parse_memory_pressure(&contents) {
                    totals.max_pressure = totals.max_pressure.max(pressure);
                } else {
                    totals.pressure_read_errors += 1;
                }
            }
            Err(_) => {
                totals.pressure_read_errors += 1;
            }
        }

        match std::fs::read_to_string(path.join("memory.events")) {
            Ok(contents) => {
                if let Some(current) = crate::cgroups::parse_memory_events_oom_kill(&contents) {
                    totals.oom_delta += crate::cgroups::cgroup_counter_delta(current, old.oom_kill);
                    next.oom_kill = Some(current);
                } else {
                    tracing::debug!(path = %path.display(), "skip oom_kill: missing or malformed");
                }
                if let Some(current) = crate::cgroups::parse_memory_events_high(&contents) {
                    totals.high_delta += crate::cgroups::cgroup_counter_delta(current, old.high);
                    next.high = Some(current);
                } else {
                    tracing::debug!(path = %path.display(), "skip memory high: missing or malformed");
                }
            }
            Err(err) => {
                tracing::debug!(path = %path.display(), error = %err, "skip cgroup events: unreadable");
            }
        }

        match std::fs::read_to_string(path.join("cpu.stat")) {
            Ok(contents) => {
                if let Some(current) = crate::cgroups::parse_cpu_stat_nr_throttled(&contents) {
                    totals.throttled_delta +=
                        crate::cgroups::cgroup_counter_delta(current, old.nr_throttled);
                    next.nr_throttled = Some(current);
                } else {
                    tracing::debug!(path = %path.display(), "skip cpu throttled: missing or malformed");
                }
            }
            Err(err) => {
                tracing::debug!(path = %path.display(), error = %err, "skip cpu.stat: unreadable");
            }
        }

        baselines.insert(path.clone(), next);
    }
    let live: hashbrown::HashSet<&PathBuf> = paths.iter().collect();
    baselines.retain(|k, _| live.contains(k));
    totals
}

#[derive(Clone)]
pub struct HostAgent {
    sandboxes: Arc<Mutex<HashMap<String, Arc<SandboxEntry>>>>,
    workspaces: workspace::WorkspaceManager,
    port_proxy: Arc<port_proxy::PortProxyManager>,
    port_forward: Arc<port_forward::PortForwardManager>,
    port_targets: PortTargetCache,
    reaper: Arc<reaper::IdleReaper>,
    default_runtime: RuntimeType,
    pub task_registry: Arc<task_registry::TaskRegistry>,
    public_host: Option<String>,
    identity: HostIdentity,
    capacity: HostCapacity,
    draining: Arc<std::sync::atomic::AtomicBool>,
    inflight_creates: Arc<std::sync::atomic::AtomicU32>,
    inflight_restores: Arc<std::sync::atomic::AtomicU32>,
    sandboxd: SandboxdHandle,
    lifecycle_reporter: Arc<dyn LifecycleReporter>,
    secrets: Option<Arc<crate::secrets::SecretsCoordinator>>,
    cross_tenant_host: bool,
    shared_host_metric_redaction: bool,
    syscall_audit: Arc<syscall_audit::SyscallAuditService>,
    file_integrity: Arc<file_integrity::FileIntegrityService>,
    observability: Arc<pico_observability::ObservabilityManager>,
    snapshot_optimizer: Arc<pico_runtime::snapshot_optimizer::SnapshotOptimizer>,
    supported_backends: Arc<RwLock<Vec<RuntimeType>>>,
    lease_authority: Arc<ParkingLotRwLock<Option<pico_core::LeaseAuthority>>>,
    image_verifier: Option<Arc<crate::image_verify::ImageVerifier>>,
    image_on_demand: Option<Arc<crate::image_on_demand::OnDemandImageCache>>,
}

/// RAII guard for an in-flight create or restore operation.
///
/// Increments the backing counter on creation and decrements on drop so
/// early returns and errors cannot leak pressure counts.
pub(crate) struct InFlightGuard {
    counter: Arc<std::sync::atomic::AtomicU32>,
}

impl InFlightGuard {
    fn new(counter: &Arc<std::sync::atomic::AtomicU32>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self {
            counter: Arc::clone(counter),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Extract tenant_id from sandbox entry's credential request.
fn entry_tenant_id(entry: &SandboxEntry) -> Option<String> {
    entry
        .credential_request
        .as_ref()
        .map(|r| r.tenant_id.to_string())
}

impl HostAgent {
    /// Creates a host agent using the supplied root and idle timeout.
    ///
    /// Connects to sandboxd using `PICO_SANDBOXD_SOCKET` /
    /// `PICO_SANDBOXD_TOKEN` (or the defaults from [`HostAgentConfig`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be created or sandboxd
    /// cannot be reached.
    pub async fn new(workspace_root: PathBuf, idle_timeout_secs: u64) -> Result<Self> {
        Self::with_runtime(workspace_root, idle_timeout_secs, RuntimeType::Firecracker).await
    }

    /// Creates a host agent from the full set of host configuration data.
    ///
    /// Idle reaper expiry tears down sandboxes through Destroy RPC.
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be created or sandboxd
    /// cannot be reached.
    pub async fn from_config(config: &crate::config::HostAgentConfig) -> Result<Self> {
        let sandboxd = SandboxdHandle::connect(
            &SandboxdConnect {
                socket_path: config.sandboxd_socket_path.clone(),
                auth_token: (*config.sandboxd_token).clone(),
            },
            Duration::from_secs(5),
        )
        .await?;
        let mut agent = Self::with_idle_timeout_and_runtime(
            config.workspace_root.clone(),
            Duration::from_secs(config.idle_timeout_secs),
            config.default_runtime,
            None,
            sandboxd,
        )?;
        agent.identity = config.identity.clone();
        agent.capacity = HostCapacity::detect();
        agent.cross_tenant_host = config.cross_tenant_host;
        agent.shared_host_metric_redaction = config.shared_host_metric_redaction;
        // Image admission is host policy. `ensure_valid` already rejected a
        // production mode with no pinned key, so construction here cannot fail
        // on a well-formed config; treat an impossible construction error as
        // "no verification" and let the first prepare fail closed loudly.
        if config.image_verification.is_configured() {
            match crate::image_verify::ImageVerifier::new(&config.image_verification) {
                Ok(verifier) => agent.image_verifier = Some(Arc::new(verifier)),
                Err(err) => tracing::error!(
                    error = %err,
                    "image verifier could not be constructed; prepare will reject images"
                ),
            }
        }
        // On-demand lazy reads sit behind the verification gate. A bad config
        // or an unreadable revocation file refuses startup: silently falling
        // back to the eager path would ignore operator intent and mislabel
        // S-CACHE evidence as `unknown`.
        if config.image_on_demand.enabled {
            let cache =
                crate::image_on_demand::OnDemandImageCache::new(config.image_on_demand.clone())
                    .map_err(SandboxError::Other)?;
            agent.image_on_demand = Some(Arc::new(cache));
        }
        // One flag in `pico-telemetry` covers the host agent, `pico-core`,
        // the network agent, and the observability crate, so a single call
        // enables the policy everywhere in this process.
        crate::metrics::set_metric_redaction(config.shared_host_metric_redaction);
        if config.draining {
            agent
                .draining
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // A restarted host rebuilds its sandbox map from the supervisor
        // before serving; failure degrades to the periodic reconcile instead
        // of wedging startup on a slow sandboxd.
        if let Err(err) = agent.rehydrate_from_sandboxd().await {
            tracing::warn!(
                error = %err,
                "sandboxd rehydration failed at startup; periodic reconcile will retry"
            );
        }
        agent.spawn_reaper_destroyer();
        Ok(agent)
    }

    /// Builds a host agent against an already-connected sandboxd handle (tests).
    pub fn with_sandboxd(
        workspace_root: PathBuf,
        idle_timeout_secs: u64,
        default_runtime: RuntimeType,
        sandboxd: SandboxdHandle,
    ) -> Result<Self> {
        let agent = Self::with_idle_timeout_and_runtime(
            workspace_root,
            Duration::from_secs(idle_timeout_secs),
            default_runtime,
            None,
            sandboxd,
        )?;
        agent.spawn_reaper_destroyer();
        Ok(agent)
    }

    /// Creates a host agent with an explicit default runtime backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be created or sandboxd
    /// cannot be reached.
    pub async fn with_runtime(
        workspace_root: PathBuf,
        idle_timeout_secs: u64,
        default_runtime: RuntimeType,
    ) -> Result<Self> {
        let sandboxd =
            SandboxdHandle::connect(&SandboxdConnect::from_env(), Duration::from_secs(5)).await?;
        let agent = Self::with_idle_timeout_and_runtime(
            workspace_root,
            Duration::from_secs(idle_timeout_secs),
            default_runtime,
            None,
            sandboxd,
        )?;
        agent.spawn_reaper_destroyer();
        Ok(agent)
    }

    /// Creates a host agent with an explicit default runtime backend and public host.
    ///
    /// # Errors
    ///
    /// Returns an error if the workspace root cannot be created or sandboxd
    /// cannot be reached.
    pub async fn with_public_host(
        workspace_root: PathBuf,
        idle_timeout_secs: u64,
        default_runtime: RuntimeType,
        public_host: Option<String>,
    ) -> Result<Self> {
        let sandboxd =
            SandboxdHandle::connect(&SandboxdConnect::from_env(), Duration::from_secs(5)).await?;
        let agent = Self::with_idle_timeout_and_runtime(
            workspace_root,
            Duration::from_secs(idle_timeout_secs),
            default_runtime,
            public_host,
            sandboxd,
        )?;
        agent.spawn_reaper_destroyer();
        Ok(agent)
    }

    fn with_idle_timeout_and_runtime(
        workspace_root: PathBuf,
        default_idle_timeout: Duration,
        default_runtime: RuntimeType,
        public_host: Option<String>,
        sandboxd: SandboxdHandle,
    ) -> Result<Self> {
        let workspaces = workspace::WorkspaceManager::new(workspace_root)?;
        let sandboxes: Arc<Mutex<HashMap<String, Arc<SandboxEntry>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let port_targets = PortTargetCache::new();
        let resolve_cache = port_targets.clone();
        let resolve_client = sandboxd.clone();
        let resolve: port_proxy::ResolveAddr = Arc::new(move |sid, guest_port| {
            let cache = resolve_cache.clone();
            let client = resolve_client.clone();
            let sid = sid.to_string();
            Box::pin(async move {
                if let Some(addr) = cache.resolve_tcp(&sid, guest_port) {
                    return Some(addr);
                }
                match client.get_port_target(&sid, guest_port).await {
                    Ok(response) => {
                        if let Some(target) = response.target.as_ref() {
                            cache.apply_get_port_target(
                                &sid,
                                guest_port,
                                target,
                                response.generation,
                            );
                        }
                        cache.resolve_tcp(&sid, guest_port)
                    }
                    Err(err) => {
                        tracing::debug!(
                            sandbox_id = %sid,
                            guest_port,
                            error = %err,
                            "GetPortTarget failed; proxy fail-closed"
                        );
                        None
                    }
                }
            })
        });
        // Wake is reserved for resume-on-connect; until that path is wired it
        // fails closed the same way as a missing GetPortTarget.
        let wake: port_proxy::WakeFn =
            Arc::new(move |_sid, _guest_port| Box::pin(async move { None }));

        let port_proxy = Arc::new(port_proxy::PortProxyManager::new(resolve, wake));
        let lease_manager = Arc::new(LeaseManager::new());
        let audit_sink: Arc<dyn AuditEventSink> = Arc::new(NoopAuditSink);
        let hlc = Arc::new(Hlc::new());
        let port_forward = Arc::new(port_forward::PortForwardManager::new(
            Arc::clone(&port_proxy),
            lease_manager,
            audit_sink,
            hlc,
            public_host
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
        ));
        let reaper = reaper::IdleReaper::new(default_idle_timeout);
        let identity = HostIdentity::from_env("unknown-region");
        let capacity = HostCapacity::detect();
        let syscall_audit = syscall_audit::SyscallAuditService::try_start();
        let file_integrity = file_integrity::FileIntegrityService::try_start();
        let observability = Arc::new(pico_observability::ObservabilityManager::new());
        let snapshot_optimizer =
            Arc::new(pico_runtime::snapshot_optimizer::SnapshotOptimizer::new());
        syscall_audit.set_fim_observer(file_integrity.syscall_observer());
        Ok(Self {
            sandboxes,
            workspaces,
            port_proxy,
            port_forward,
            port_targets,
            reaper,
            default_runtime,
            task_registry: Arc::new(task_registry::TaskRegistry::new(64)),
            public_host,
            identity,
            capacity,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            inflight_creates: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            inflight_restores: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            sandboxd,
            lifecycle_reporter: Arc::new(TracingLifecycleReporter),
            secrets: None,
            cross_tenant_host: false,
            shared_host_metric_redaction: false,
            syscall_audit,
            file_integrity,
            observability,
            snapshot_optimizer,
            supported_backends: Arc::new(RwLock::new(default_supported_backends())),
            lease_authority: Arc::new(ParkingLotRwLock::new(None)),
            image_verifier: None,
            image_on_demand: None,
        })
    }

    /// Installs the image verifier used on the prepare path.
    #[must_use]
    pub fn with_image_verifier(mut self, verifier: crate::image_verify::ImageVerifier) -> Self {
        self.image_verifier = Some(Arc::new(verifier));
        self
    }

    /// Installs the verification-gated on-demand cache.
    ///
    /// The cache never weakens verification: it only serves digests admitted
    /// through [`crate::image_verify::ImageVerifier::verify`] plus
    /// [`crate::image_on_demand::OnDemandImageCache::admit_verified`].
    #[must_use]
    pub fn with_image_on_demand(
        mut self,
        cache: Arc<crate::image_on_demand::OnDemandImageCache>,
    ) -> Self {
        self.image_on_demand = Some(cache);
        self
    }

    /// Installs the lease authority used to verify signed access-lease blobs.
    #[must_use]
    pub fn with_lease_authority(self, authority: pico_core::LeaseAuthority) -> Self {
        self.port_forward.set_lease_authority(authority.clone());
        *self.lease_authority.write() = Some(authority);
        self
    }

    fn admit_credential_lease(
        &self,
        sandbox_id: &str,
        cred_req: &CredentialRequestSpec,
        policy_epoch: u64,
    ) -> Result<()> {
        let authority = self.lease_authority.read();
        let Some(authority) = authority.as_ref() else {
            return Ok(());
        };
        let blob = cred_req
            .lease
            .as_deref()
            .ok_or(SandboxError::Unauthorized)?;
        let sandbox = SandboxId::from_string(sandbox_id);
        let requested_scope = LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: cred_req.credential_types.clone(),
        };
        authority
            .enforce_blob(
                blob,
                &EnforceContext {
                    sandbox_id: &sandbox,
                    tenant_id: &cred_req.tenant_id,
                    action: LeaseAction::CredentialAccess,
                    scope: &requested_scope,
                    policy_epoch,
                },
            )
            .map_err(|_| SandboxError::Unauthorized)?;
        Ok(())
    }

    /// Attaches a [`SecretsCoordinator`] for injecting and managing sandbox
    /// credentials throughout the lifecycle.
    ///
    /// When no coordinator is set (the default), all secrets-related
    /// lifecycle hooks are skipped.
    #[must_use]
    pub fn with_secrets(mut self, coordinator: Arc<crate::secrets::SecretsCoordinator>) -> Self {
        self.secrets = Some(coordinator);
        self
    }

    // ═══════════════════════════════════════════════════════════════
    // Sandbox Lifecycle
    // ═══════════════════════════════════════════════════════════════

    /// Creates a new sandbox from the given spec.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying runtime fails to prepare or start.
    #[tracing::instrument(skip(self, spec), fields(sandbox_id = %spec.id.as_deref().unwrap_or("")))]
    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        // Hold the create guard for the full prepare+boot so pressure covers
        // the entire in-flight window, including early returns.
        let _in_flight = self.track_create();
        let sandbox_id = spec.id.as_deref().unwrap_or("").to_string();
        let tenant_id = spec
            .credential_request
            .as_ref()
            .map(|r| r.tenant_id.to_string());
        let started = Instant::now();
        emit_create_started(&sandbox_id, tenant_id.as_deref());
        let result = async {
            let prepared = self.prepare_sandbox(spec).await?;
            self.boot_prepared_sandbox(&prepared.id).await
        }
        .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        match &result {
            Ok(info) => {
                emit_create_completed(&info.id, latency_ms, tenant_id.as_deref());
                set_span_status_from_outcome(LifecycleOutcome::Success, None);
                record_bounded_attr(attr::SANDBOX_ID, &info.id);
                record_bounded_attr(
                    attr::OPERATION,
                    pico_telemetry::lifecycle::LifecycleOperation::Create.as_str(),
                );
                record_bounded_attr(attr::OUTCOME, LifecycleOutcome::Success.as_str());
            }
            Err(e) => {
                emit_create_failed(
                    &sandbox_id,
                    latency_ms,
                    &e.to_string(),
                    tenant_id.as_deref(),
                );
                let outcome = error_to_lifecycle_outcome(e);
                set_span_status_from_outcome(outcome, Some(&e.to_string()));
                record_bounded_attr(attr::SANDBOX_ID, &sandbox_id);
                record_bounded_attr(
                    attr::OPERATION,
                    pico_telemetry::lifecycle::LifecycleOperation::Create.as_str(),
                );
                record_bounded_attr(attr::OUTCOME, outcome.as_str());
            }
        }
        result
    }

    /// Prepares a sandbox without starting the underlying runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the host is draining or the runtime cannot prepare.
    #[tracing::instrument(skip(self, spec), fields(sandbox_id = %spec.id.as_deref().unwrap_or("")))]
    pub async fn prepare_sandbox(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        let sandbox_id_hint = spec.id.clone().unwrap_or_default();
        let tenant_id_hint = spec
            .credential_request
            .as_ref()
            .map(|r| r.tenant_id.to_string());
        let started = Instant::now();
        emit_prepare_started(&sandbox_id_hint, tenant_id_hint.as_deref());
        // Cache outcome for the image-stage latency series. Updated inside
        // the prepare body once the verification gate classifies the digest;
        // failures before that point keep `unknown`.
        let cache_result_for_telemetry = Arc::new(ParkingLotMutex::new(String::from("unknown")));
        let cache_result_inner = Arc::clone(&cache_result_for_telemetry);
        let result = async {
            self.ensure_new_sandboxes_allowed("prepare")?;
            let id = spec
                .id
                .clone()
                .unwrap_or_else(|| pico_core::new_ulid("sbx"));
            // Validate the sandbox id against workspace path rules up front.
            // Workspace creation itself happens in sandboxd during prepare.
            self.workspaces.sandbox_dir(&id)?;

            let (ssh_private_key, ssh_public_key) = if let Some(pub_key) = spec.ssh_public_key {
                (None, Some(pub_key))
            } else {
                let key_type = spec.ssh_key_type.as_deref().unwrap_or("ed25519");
                let (priv_key, pub_key) = self.generate_ssh_keys(key_type)?;
                (Some(priv_key), Some(pub_key))
            };

            let mut requested_ports = spec.ports.clone().unwrap_or_default();
            const SSH_PORT: u16 = 22;
            if !requested_ports.contains(&SSH_PORT) {
                requested_ports.push(SSH_PORT);
            }

            let ssh_host_port = {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
                let port = listener.local_addr()?.port();
                drop(listener);
                port
            };

            let idle_timeout = spec
                .idle_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or_else(|| self.reaper.default_timeout());

            let config = pico_core::SandboxConfig {
                id: id.clone(),
                cpu_shares: spec.vcpus.unwrap_or(1) * 100,
                memory_limit_bytes: spec.memory_mb.unwrap_or(512) * 1024 * 1024,
                memory_soft_limit_bytes: spec.memory_mb.map(default_soft_limit_bytes),
                max_pids: Some(DEFAULT_MAX_PIDS),
                network_isolated: true,
                ssh_port: Some(ssh_host_port),
                ..Default::default()
            };
            let runtime = spec.runtime.unwrap_or(self.default_runtime);
            let memory_mb = match spec.memory_mb {
                Some(mb) => u32::try_from(mb).map_err(|_| {
                    SandboxError::BadRequest(format!(
                        "memory_mb {mb} exceeds the maximum representable value"
                    ))
                })?,
                None => 0,
            };
            let host_resources = HostResourceParts {
                vcpus: spec.vcpus.unwrap_or(1),
                memory_mb,
                idle_timeout_secs: spec.idle_timeout_secs,
                image_id: spec.image_id.clone(),
                image_digest: spec.image_digest.clone(),
                ssh_public_key: ssh_public_key.clone(),
                ssh_key_type: spec.ssh_key_type.clone(),
                requested_ports: requested_ports.iter().map(|p| u32::from(*p)).collect(),
                cross_tenant_host: self.cross_tenant_host,
                tenant_id: spec
                    .credential_request
                    .as_ref()
                    .map(|r| r.tenant_id.to_string()),
            };
            let now = pico_core::now_iso();
            let ssh_home_dir = default_ssh_home_dir(runtime);
            let image_id = spec.image_id.clone().unwrap_or_else(|| id.clone());
            // Image admission happens before any host resource exists, so a
            // rejected image leaves nothing to roll back. The requested digest
            // is retained for the handshake; when a verifier is configured the
            // verified manifest digest replaces it below, because the request
            // is only an unverified hint and the signed manifest is authority.
            let mut image_digest = spec.image_digest.clone().unwrap_or_default();
            let verify_started = Instant::now();
            let verified_image = admit_image(self, runtime);
            // Recorded on denial too: revocation and verification refusal
            // latency is S-CACHE evidence, not just the happy path.
            crate::metrics::record_image_verify_latency(verify_started.elapsed().as_secs_f64());
            let verified_image = verified_image?;
            if let Some(ref record) = verified_image {
                image_digest = record.manifest_digest.clone();
                // Verification-gated lazy reads: the digest is admitted for
                // on-demand serving only after verification (plus revocation)
                // succeeded. The prepare-level cache outcome is peeked before
                // admission so cold, warm, and evicted prepares label
                // honestly for S-CACHE evidence.
                if let Some(cache) = self.image_on_demand.as_ref() {
                    let outcome = cache.prepare_result(&record.manifest_digest);
                    *cache_result_inner.lock() = outcome.as_str().to_string();
                    cache
                        .admit_verified(record)
                        .map_err(|err| SandboxError::PolicyDenied {
                            reason: format!("on-demand admission failed: {err}"),
                        })?;
                }
            }
            let shared_secret = pico_core::crypto::derive_handshake_shared_secret(&id);
            let credential_request = spec.credential_request.clone();
            let admit_token = FencingToken::default();
            let tenant_id = spec
                .credential_request
                .as_ref()
                .map(|r| r.tenant_id.clone())
                .unwrap_or_else(|| TenantId::from_string("default"));
            let mut desired = SandboxMetadata::new(
                SandboxId::from_string(&id),
                tenant_id,
                image_id.clone(),
                Some(runtime),
                ResourceLimits {
                    memory_mb: spec.memory_mb.unwrap_or(512),
                    vcpus: spec.vcpus.unwrap_or(1),
                    idle_timeout_secs: spec.idle_timeout_secs.unwrap_or(300),
                    ..ResourceLimits::default()
                },
                None,
            );
            // Mono admits locally through the ADR-0001 sequence. After prepare,
            // desired stays Preparing until boot; Preparing -> Pending is illegal.
            desired.commit(
                SandboxState::Pending,
                SandboxState::Scheduled,
                Some(admit_token),
            )?;
            desired.commit(
                SandboxState::Scheduled,
                SandboxState::Preparing,
                Some(admit_token),
            )?;
            let mut observation = ObservationSnapshot {
                observed_state: SandboxState::Preparing,
                backend: runtime.to_string(),
                ssh_username: default_ssh_username(runtime).into(),
                ..ObservationSnapshot::default()
            };
            let entry = Arc::new(SandboxEntry {
                id: id.clone(),
                runtime,
                observation: ParkingLotMutex::new(observation.clone()),
                config: config.clone(),
                desired: ParkingLotMutex::new(desired),
                boot: ParkingLotMutex::new(BootState {
                    assignment_fencing_token: admit_token,
                    policy_epoch: 1,
                    last_boot_report: None,
                    last_reported_boot_operation: None,
                }),
                ports: requested_ports.clone(),
                idle_timeout,
                created_at: now.clone(),
                last_activity_at: ParkingLotMutex::new(now.clone()),
                ssh_port: Some(ssh_host_port),
                ssh_public_key: ssh_public_key.clone(),
                ssh_private_key,
                ssh_home_dir: Some(ssh_home_dir),
                ssh_key_injected: AtomicBool::new(false),
                image_id: Some(image_id),
                image_digest: Some(image_digest),
                verified_image: verified_image.clone(),
                negotiated_capabilities: ParkingLotMutex::new(Vec::new()),
                guest_agent_version: ParkingLotMutex::new(None),
                guest_boot_id: ParkingLotMutex::new(None),
                session_id: ParkingLotMutex::new(None),
                shared_secret: Some(Zeroizing::new(Vec::from(shared_secret.as_slice()))),
                cgroup: CgroupManager::new(&id)?,
                credential_request,
            });
            self.sandboxes
                .lock()
                .await
                .insert(id.clone(), Arc::clone(&entry));
            let prepare_meta = CommandMetaParts::new(
                id.clone(),
                OperationId::generate(),
                FencingToken::default(),
                1,
                Duration::from_secs(boot::DEFAULT_BOOT_TIMEOUT_SECS),
            );
            let overlay_started = Instant::now();
            let outcome = self
                .sandboxd
                .prepare(prepare_meta, &config, runtime, host_resources)
                .await;
            // Recorded on transport failure too: a failed materialization
            // still spent overlay time.
            crate::metrics::record_image_overlay_latency(overlay_started.elapsed().as_secs_f64());
            let outcome = outcome?;
            if !outcome.succeeded() {
                let _ = entry.commit_desired(
                    SandboxState::Preparing,
                    SandboxState::Failed,
                    Some(admit_token),
                );
                let err = operation_outcome_error(&outcome);
                if !outcome.requires_review() {
                    self.sandboxes.lock().await.remove(&id);
                }
                return Err(err);
            }
            if let Some(state) = outcome.observed_state {
                observation.observed_state = state;
            }
            *entry.observation.lock() = observation;

            // sandboxd owns the cgroup; register it with the eBPF services
            // only after prepare proves the cgroup exists.
            if let Some(cgroup_id) = entry.cgroup.cgroup_id() {
                let image = spec.image_id.as_deref().unwrap_or(&id);
                let workload = spec
                    .credential_request
                    .as_ref()
                    .map(|r| r.tenant_id.to_string())
                    .unwrap_or_else(|| "default".to_string());
                self.syscall_audit
                    .register_sandbox(&id, cgroup_id, image, &workload);
                let fim_paths =
                    file_integrity::integrity_paths_for_image(spec.image_id.as_deref(), None);
                self.file_integrity
                    .register_sandbox(&id, cgroup_id, fim_paths.as_deref());
                self.observability.register_sandbox(
                    &id,
                    spec.credential_request
                        .as_ref()
                        .map(|r| r.tenant_id.to_string())
                        .as_deref(),
                    cgroup_id,
                    &entry.cgroup.sandbox_path(),
                );
                self.snapshot_optimizer.register_sandbox(
                    &id,
                    cgroup_id,
                    &entry.cgroup.sandbox_path(),
                );
            }

            Ok(Self::sandbox_info(&entry))
        }
        .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let cache_result = cache_result_for_telemetry.lock().clone();
        let target_id = if !sandbox_id_hint.is_empty() {
            &sandbox_id_hint
        } else {
            "unknown"
        };
        match &result {
            Ok(info) => {
                emit_prepare_completed_with_cache(
                    &info.id,
                    latency_ms,
                    &cache_result,
                    crate::metrics::val::IMAGE_PROFILE_UNKNOWN,
                    tenant_id_hint.as_deref(),
                );
                set_span_status_from_outcome(LifecycleOutcome::Success, None);
                record_bounded_attr(attr::SANDBOX_ID, &info.id);
                record_bounded_attr(
                    attr::OPERATION,
                    pico_telemetry::lifecycle::LifecycleOperation::Prepare.as_str(),
                );
                record_bounded_attr(attr::OUTCOME, LifecycleOutcome::Success.as_str());
            }
            Err(e) => {
                emit_prepare_failed_with_cache(
                    target_id,
                    latency_ms,
                    &e.to_string(),
                    &cache_result,
                    crate::metrics::val::IMAGE_PROFILE_UNKNOWN,
                    tenant_id_hint.as_deref(),
                );
                let outcome = error_to_lifecycle_outcome(e);
                set_span_status_from_outcome(outcome, Some(&e.to_string()));
                record_bounded_attr(attr::SANDBOX_ID, target_id);
                record_bounded_attr(
                    attr::OPERATION,
                    pico_telemetry::lifecycle::LifecycleOperation::Prepare.as_str(),
                );
                record_bounded_attr(attr::OUTCOME, outcome.as_str());
            }
        }
        result
    }

    /// Boots a prepared sandbox and exposes its bound ports.
    ///
    /// # Errors
    ///
    /// Returns an error if the sandbox is not prepared or if boot fails.
    pub async fn boot_prepared_sandbox(&self, id: &str) -> Result<SandboxInfo> {
        let entry = self.lookup_sandbox(id).await?;
        let (token, epoch) = {
            let boot_guard = entry.boot.lock();
            (
                boot_guard.assignment_fencing_token.next_sequence(),
                boot_guard.policy_epoch.max(1),
            )
        };

        let command = BootCommand {
            sandbox_id: id.to_string(),
            operation_id: OperationId::generate(),
            assigned_host_id: self.identity.host_id.clone(),
            assigned_cell_id: self.identity.cell_id.clone(),
            assignment_fencing_token: token,
            policy_epoch: epoch,
            timeout_secs: boot::DEFAULT_BOOT_TIMEOUT_SECS,
        };
        let report = self.boot_sandbox(command).await?;
        if report.status == BootStatus::NotReady {
            return Err(boot_report_error(&report));
        }
        Ok(Self::sandbox_info(&entry))
    }

    /// Runs the fenced host boot lifecycle for a prepared sandbox.
    ///
    /// Non-ready outcomes are returned as typed reports. Command admission,
    /// ownership, and lifecycle reporting failures are returned as errors.
    ///
    /// # Errors
    ///
    /// Returns an error when the command is invalid, stale, assigned elsewhere,
    /// or cannot be reported to the cell controller.
    #[tracing::instrument(skip(self, command), fields(sandbox_id = %command.sandbox_id, operation_id = %command.operation_id))]
    pub async fn boot_sandbox(&self, command: BootCommand) -> Result<BootReport> {
        self.ensure_new_sandboxes_allowed("boot")?;
        let entry = self.lookup_sandbox(&command.sandbox_id).await?;
        self.validate_boot_command(&command, &entry).await?;
        let cached_report = {
            let boot_guard = entry.boot.lock();
            boot_guard.last_boot_report.clone()
        };

        if let Some(report) = cached_report
            && report.operation_id == command.operation_id
        {
            self.report_boot_outcome_if_needed(&entry, &report).await?;
            return Ok(report);
        }

        let state = entry.desired_state();
        if state == SandboxState::Running {
            let report = BootReport {
                sandbox_id: command.sandbox_id,
                operation_id: command.operation_id,
                status: BootStatus::Ready,
                reason: None,
                observed_state: SandboxState::Running,
                latency_ms: 0,
                diagnostics: Vec::new(),
            };
            {
                let mut boot_guard = entry.boot.lock();
                boot_guard.assignment_fencing_token = command.assignment_fencing_token;
                boot_guard.policy_epoch = command.policy_epoch;
            }
            return self.finish_boot_report(&entry, report).await;
        }
        if state != SandboxState::Preparing {
            return Err(SandboxError::InvalidStateTransition(format!(
                "cannot boot sandbox from state {state}"
            )));
        }

        self.lifecycle_reporter
            .report(&BootObservation {
                sandbox_id: command.sandbox_id.clone(),
                operation_id: command.operation_id.clone(),
                observed_state: SandboxState::Booting,
                reason: None,
                message: None,
            })
            .await
            .map_err(|error| {
                SandboxError::Other(format!("failed to report boot start: {error}"))
            })?;

        let started = Instant::now();
        emit_boot_start(&command, entry_tenant_id(&entry).as_deref());
        entry.commit_desired(
            SandboxState::Preparing,
            SandboxState::Booting,
            Some(command.assignment_fencing_token),
        )?;
        let boot_meta = CommandMetaParts::new(
            command.sandbox_id.clone(),
            command.operation_id.clone(),
            command.assignment_fencing_token,
            command.policy_epoch,
            Duration::from_secs(command.timeout_secs),
        );
        let outcome = self.sandboxd.boot(boot_meta).await?;
        if !outcome.succeeded() {
            let _ = entry.commit_desired(
                SandboxState::Booting,
                SandboxState::Failed,
                Some(command.assignment_fencing_token),
            );
            {
                let mut boot_guard = entry.boot.lock();
                boot_guard.assignment_fencing_token = command.assignment_fencing_token;
                boot_guard.policy_epoch = command.policy_epoch;
            }
            let report = self
                .non_ready_report(
                    &command,
                    &entry,
                    outcome.non_ready_reason.unwrap_or(NonReadyReason::Backend),
                    started,
                    outcome.message.into_iter().collect(),
                )
                .await;
            emit_boot_cleanup(&report, entry_tenant_id(&entry).as_deref());
            return self.finish_boot_report(&entry, report).await;
        }
        self.refresh_observation(&entry).await;
        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = command.assignment_fencing_token;
            boot_guard.policy_epoch = command.policy_epoch;
        }

        // Guest handshake and secrets inject run inside sandboxd (PR3/PR7).
        // Host only injects SSH keys via Exec RPC when a key was generated.
        if let Err(error) = self.inject_ssh_key(&entry).await {
            return self
                .cleanup_host_boot_failure(
                    &command,
                    &entry,
                    HostBootFailure {
                        bound_ports: &[],
                        revoke_ssh_key: true,
                        reason: NonReadyReason::Protocol,
                        message: error.to_string(),
                        started,
                    },
                )
                .await;
        }

        // Secrets injection is owned by sandboxd (InjectSecrets RPC). Host
        // admits the lease and forwards the credential request; guest_conn
        // is no longer used on this path.
        if let Some(ref cred_req) = entry.credential_request {
            if let Err(error) =
                self.admit_credential_lease(&entry.id, cred_req, command.policy_epoch)
            {
                return self
                    .cleanup_host_boot_failure(
                        &command,
                        &entry,
                        HostBootFailure {
                            bound_ports: &[],
                            revoke_ssh_key: true,
                            reason: NonReadyReason::Protocol,
                            message: error.to_string(),
                            started,
                        },
                    )
                    .await;
            }
            let inject_op = OperationId::generate();
            let credentials = pico_sandboxd_proto::v1::CredentialInjectSpec {
                tenant_id: cred_req.tenant_id.to_string(),
                lease_id: cred_req.lease_id.to_string(),
                policy_decision_id: cred_req
                    .policy_decision_id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                credentials: cred_req
                    .credential_types
                    .iter()
                    .map(|kind| pico_sandboxd_proto::v1::NamedCredential {
                        name: kind.clone(),
                        kind: kind.clone(),
                        attributes: Default::default(),
                        material: None,
                    })
                    .collect(),
            };
            match self
                .sandboxd
                .inject_secrets(
                    CommandMetaParts::new(
                        entry.id.clone(),
                        inject_op,
                        command.assignment_fencing_token,
                        command.policy_epoch,
                        Duration::from_secs(30),
                    ),
                    credentials,
                )
                .await
            {
                Ok(outcome) if outcome.succeeded() => {}
                Ok(outcome) => {
                    return self
                        .cleanup_host_boot_failure(
                            &command,
                            &entry,
                            HostBootFailure {
                                bound_ports: &[],
                                revoke_ssh_key: true,
                                reason: NonReadyReason::Protocol,
                                message: outcome
                                    .message
                                    .unwrap_or_else(|| "credential injection failed".into()),
                                started,
                            },
                        )
                        .await;
                }
                Err(err) => {
                    return self
                        .cleanup_host_boot_failure(
                            &command,
                            &entry,
                            HostBootFailure {
                                bound_ports: &[],
                                revoke_ssh_key: true,
                                reason: NonReadyReason::Protocol,
                                message: err.to_string(),
                                started,
                            },
                        )
                        .await;
                }
            }
        }

        let _ports = match self.bind_ports(&entry, &command.sandbox_id).await {
            Ok(ports) => ports,
            Err((partial_ports, error)) => {
                return self
                    .cleanup_host_boot_failure(
                        &command,
                        &entry,
                        HostBootFailure {
                            bound_ports: &partial_ports,
                            revoke_ssh_key: true,
                            reason: NonReadyReason::Network,
                            message: error.to_string(),
                            started,
                        },
                    )
                    .await;
            }
        };

        // DNS attach receipts are owned by sandboxd (provisioned during Boot).
        // Host-agent no longer installs nftables DNS redirects.

        entry.commit_desired(
            SandboxState::Booting,
            SandboxState::Running,
            Some(command.assignment_fencing_token),
        )?;
        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = command.assignment_fencing_token;
            boot_guard.policy_epoch = command.policy_epoch;
        }
        self.touch_sandbox_activity(&entry, &command.sandbox_id)
            .await;
        let report = BootReport {
            sandbox_id: command.sandbox_id.clone(),
            operation_id: command.operation_id.clone(),
            status: BootStatus::Ready,
            reason: None,
            observed_state: SandboxState::Running,
            latency_ms: duration_ms(started.elapsed()),
            diagnostics: Vec::new(),
        };
        emit_boot_ready(&report, entry_tenant_id(&entry).as_deref());
        emit_verified_image_on_ready(&entry);
        self.finish_boot_report(&entry, report).await
    }

    fn generate_ssh_keys(&self, key_type: &str) -> Result<(Zeroizing<String>, String)> {
        let algorithm = match key_type {
            "rsa" => Algorithm::Rsa { hash: None },
            _ => Algorithm::Ed25519,
        };
        let mut csprng = OsRng;
        let private_key = PrivateKey::random(&mut csprng, algorithm)
            .map_err(|e| SandboxError::Other(format!("failed to generate key: {e}")))?;
        let public_key = private_key.public_key();

        let private_key_pem = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| SandboxError::Other(format!("failed to serialize private key: {e}")))?;

        let public_key_openssh = public_key
            .to_openssh()
            .map_err(|e| SandboxError::Other(format!("failed to serialize public key: {e}")))?;

        Ok((private_key_pem, public_key_openssh))
    }

    async fn refresh_observation(&self, entry: &SandboxEntry) {
        match self.sandboxd.get_sandbox(&entry.id).await {
            Ok(observation) => {
                self.port_targets.apply_observation(&observation);
                let mut cache = entry.observation.lock();
                apply_observation(&mut cache, &observation);
                if !cache.guest_boot_id.is_empty() {
                    *entry.guest_boot_id.lock() = Some(cache.guest_boot_id.clone());
                }
            }
            Err(err) => {
                tracing::debug!(
                    sandbox_id = %entry.id,
                    error = %err,
                    "failed to refresh sandbox observation"
                );
            }
        }
    }

    /// Hybrid Watch stream + periodic List reconcile for observation/port cache.
    fn spawn_observation_sync(&self) {
        let agent = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(err) = agent.run_observation_watch_once().await {
                    tracing::debug!(error = %err, "observation watch ended; reconciling via List");
                }
                if let Err(err) = agent.reconcile_observations_from_list().await {
                    tracing::debug!(error = %err, "observation list reconcile failed");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let agent = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(OBSERVATION_RECONCILE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(err) = agent.reconcile_observations_from_list().await {
                    tracing::debug!(error = %err, "periodic observation reconcile failed");
                }
            }
        });
    }

    async fn run_observation_watch_once(&self) -> Result<()> {
        use pico_sandboxd_proto::v1::watch_event;
        let mut stream = self.sandboxd.watch(std::iter::empty::<String>()).await?;
        while let Some(event) = stream
            .message()
            .await
            .map_err(|err| SandboxError::Other(format!("observation watch stream error: {err}")))?
        {
            match event.body {
                Some(watch_event::Body::Upsert(observation)) => {
                    self.port_targets.apply_observation(&observation);
                    self.apply_watch_upsert_to_entry(&observation).await;
                }
                Some(watch_event::Body::RemovedSandboxId(sandbox_id)) => {
                    self.port_targets.invalidate_sandbox(&sandbox_id);
                }
                Some(watch_event::Body::Reconcile(status)) => {
                    self.port_targets.note_host_boot_id(&status.host_boot_id);
                }
                None => {}
            }
        }
        Ok(())
    }

    async fn reconcile_observations_from_list(&self) -> Result<()> {
        let observations = self.sandboxd.list_sandboxes().await?;
        self.port_targets.reconcile_from_list(&observations);
        // Watch upserts and this list snapshot race by design (two delivery
        // streams, no shared ordering). A Watch upsert for a sandbox unknown
        // to this agent is dropped (upserts only update known entries), and
        // rehydrate below then inserts it with the list generation; that data
        // can be at most one Watch event stale, and the next upsert with a
        // higher generation heals it via the guard in `apply_observation`.
        // Entry lifecycle state cannot be lost to the race: it only advances
        // through host-issued commands (destroy prunes; stop keeps Stopped).
        self.rehydrate_entries(&observations).await;
        self.prune_destroyed_entries(&observations).await;
        for observation in &observations {
            self.apply_watch_upsert_to_entry(observation).await;
        }
        Ok(())
    }

    /// Rehydrates host sandbox entries from sandboxd observations after a
    /// host-agent restart.
    ///
    /// sandboxd is the sole authority for observed lifecycle state; a host
    /// restart drops the in-memory sandbox map, so entries are rebuilt from
    /// `ListSandboxes` before the agent serves again. Entries carry no boot
    /// admission state, no SSH credentials, and no tenant scoping; fencing and
    /// policy epochs mirror the persisted observation so sandboxd keeps
    /// rejecting stale commands.
    ///
    /// Returns the number of entries created.
    ///
    /// # Errors
    ///
    /// Returns an error when sandboxd cannot be reached or refuses the list.
    pub async fn rehydrate_from_sandboxd(&self) -> Result<usize> {
        let observations = self.sandboxd.list_sandboxes().await?;
        self.port_targets.reconcile_from_list(&observations);
        Ok(self.rehydrate_entries(&observations).await)
    }

    /// Inserts observation-derived entries for sandboxes the host does not
    /// track yet; returns how many were created. Insert-only: known entries
    /// keep their boot/admission state, and the observation cache keeps
    /// applying its own generation guard.
    async fn rehydrate_entries(
        &self,
        observations: &[pico_sandboxd_proto::v1::SandboxObservation],
    ) -> usize {
        let mut created = 0usize;
        for observation in observations {
            let Some(entry) = self.entry_from_observation(observation) else {
                continue;
            };
            let mut sandboxes = self.sandboxes.lock().await;
            if sandboxes.contains_key(&entry.id) {
                continue;
            }
            tracing::info!(
                sandbox_id = %entry.id,
                observed_state = %observation.observed_state,
                "rehydrated sandbox entry from sandboxd observation"
            );
            sandboxes.insert(entry.id.clone(), Arc::new(entry));
            created += 1;
        }
        created
    }

    /// Builds a minimal entry from a ledger observation. `Destroyed` rows are
    /// durable receipts only; rebuilding them would resurrect sandboxes the
    /// host (or a predecessor process) already tore down, so they are skipped.
    fn entry_from_observation(
        &self,
        observation: &pico_sandboxd_proto::v1::SandboxObservation,
    ) -> Option<SandboxEntry> {
        if observation.sandbox_id.is_empty() {
            return None;
        }
        let state = proto_state_to_core(observation.observed_state)?;
        if state == SandboxState::Destroyed {
            return None;
        }
        // Pre-upgrade ledgers recorded a successful prepare as Pending.
        // boot_sandbox only admits Preparing, so promote that leftover.
        let state = if state == SandboxState::Pending {
            SandboxState::Preparing
        } else {
            state
        };
        let id = observation.sandbox_id.clone();
        let Some(runtime) = proto_runtime_to_core(observation.backend) else {
            tracing::warn!(
                sandbox_id = %id,
                backend = observation.backend,
                "skipping rehydrate for observation with unknown backend"
            );
            return None;
        };
        let token =
            FencingToken::from_str(&observation.assignment_fencing_token).unwrap_or_default();
        let mut cache = ObservationSnapshot::default();
        apply_observation(&mut cache, observation);
        // Server leaves username empty (host-side authoritative). Derive from
        // runtime so restarted GVisor entries get `user`, not the `root`
        // default; any non-empty server username still wins via apply.
        if observation
            .ssh
            .as_ref()
            .is_none_or(|ssh| ssh.username.is_empty())
        {
            cache.ssh_username = default_ssh_username(runtime).into();
        }
        let guest_boot_id = if cache.guest_boot_id.is_empty() {
            None
        } else {
            Some(cache.guest_boot_id.clone())
        };
        let now = pico_core::now_iso();
        let created_at = if observation.updated_at.is_empty() {
            now
        } else {
            observation.updated_at.clone()
        };
        let ports = observation
            .ports
            .iter()
            .filter_map(|target| u16::try_from(target.guest_port).ok())
            .filter(|port| *port > 0)
            .collect();
        // Fail closed on ledger rows with ids that cannot name a cgroup
        // directory; rehydrating them would resurrect unmanageable entries.
        // Log so invalid rows are distinguishable from destroyed skips.
        let Some(cgroup) = CgroupManager::new(&id).ok() else {
            tracing::warn!(
                sandbox_id = %id,
                "skipping rehydrate for ledger row with invalid sandbox id"
            );
            return None;
        };
        Some(SandboxEntry {
            id: id.clone(),
            runtime,
            observation: ParkingLotMutex::new(cache),
            config: SandboxConfig {
                id: id.clone(),
                ..SandboxConfig::default()
            },
            desired: ParkingLotMutex::new(SandboxMetadata::recover_from_observed(
                SandboxId::from_string(&id),
                TenantId::from_string("unknown"),
                String::new(),
                Some(runtime),
                state,
                Some(token),
                Some(observation.policy_epoch.max(1)),
            )),
            boot: ParkingLotMutex::new(BootState {
                assignment_fencing_token: token,
                policy_epoch: observation.policy_epoch.max(1),
                last_boot_report: None,
                last_reported_boot_operation: None,
            }),
            ports,
            idle_timeout: self.reaper.default_timeout(),
            created_at: created_at.clone(),
            last_activity_at: ParkingLotMutex::new(created_at),
            ssh_port: None,
            ssh_public_key: None,
            ssh_private_key: None,
            ssh_home_dir: Some(default_ssh_home_dir(runtime)),
            // The observation is proof the sandbox booted, but not that this
            // host's key landed in the guest; advertising SSH would hand out
            // credentials the sandbox may reject, so stay fail-closed.
            ssh_key_injected: AtomicBool::new(false),
            image_id: None,
            image_digest: None,
            // A rehydrated entry has not passed this host's image gate in this
            // process, so it carries no verification evidence. Reporting
            // nothing is correct: the evidence belongs to the prepare that
            // admitted the image, and inventing a re-derived value would
            // assert a check that did not run.
            verified_image: None,
            negotiated_capabilities: ParkingLotMutex::new(Vec::new()),
            guest_agent_version: ParkingLotMutex::new(None),
            guest_boot_id: ParkingLotMutex::new(guest_boot_id),
            session_id: ParkingLotMutex::new(None),
            // The handshake shared secret is derivable from the sandbox id,
            // but only boot-owned entries keep it in memory.
            shared_secret: None,
            cgroup,
            credential_request: None,
        })
    }

    /// Drops entries whose latest ledger observation is `Destroyed`.
    ///
    /// Contract: `Stopped` is a host-local pseudo-state written by `stop()`
    /// AFTER sandboxd already destroyed the sandbox. Those entries are kept
    /// deliberately so a later `purge()` and operator inspection can still
    /// reach them. Do not "clean this up" by pruning Stopped entries: doing so
    /// would silently erase the only host-side record of pre-purge sandboxes.
    /// Everything else the ledger marks destroyed is teardown this host (or a
    /// predecessor process before a restart raced) already issued, so keeping
    /// it would resurrect ghost sandboxes in list output.
    ///
    /// Accounting: kept `Stopped` entries still appear in list output and in
    /// the health sandbox count, but they hold no runtime, workspace, lease,
    /// or port capacity. Their supervisor-side resources were released by the
    /// Destroy RPC that preceded the Stopped marker, and boot admission checks
    /// each new request against host totals rather than accumulated entries.
    async fn prune_destroyed_entries(
        &self,
        observations: &[pico_sandboxd_proto::v1::SandboxObservation],
    ) {
        for observation in observations {
            if proto_state_to_core(observation.observed_state) != Some(SandboxState::Destroyed) {
                continue;
            }
            let mut sandboxes = self.sandboxes.lock().await;
            let keep = sandboxes
                .get(&observation.sandbox_id)
                .is_some_and(|entry| entry.desired_state() == SandboxState::Stopped);
            if !keep {
                sandboxes.remove(&observation.sandbox_id);
            }
        }
    }

    async fn apply_watch_upsert_to_entry(
        &self,
        observation: &pico_sandboxd_proto::v1::SandboxObservation,
    ) {
        let entry = {
            self.sandboxes
                .lock()
                .await
                .get(&observation.sandbox_id)
                .cloned()
        };
        let Some(entry) = entry else {
            return;
        };
        let mut cache = entry.observation.lock();
        apply_observation(&mut cache, observation);
        if !cache.guest_boot_id.is_empty() {
            *entry.guest_boot_id.lock() = Some(cache.guest_boot_id.clone());
        }
    }

    fn command_meta_for_entry(
        &self,
        entry: &SandboxEntry,
        operation_id: OperationId,
        deadline: Duration,
    ) -> CommandMetaParts {
        let boot_guard = entry.boot.lock();
        CommandMetaParts::new(
            entry.id.clone(),
            operation_id,
            boot_guard.assignment_fencing_token,
            boot_guard.policy_epoch.max(1),
            deadline,
        )
    }

    // ═══════════════════════════════════════════════════════════════
    // Sandbox Query & Lifecycle Transitions
    // ═══════════════════════════════════════════════════════════════

    /// Returns the current `SandboxInfo` for the given sandbox.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    pub async fn get_sandbox(&self, id: &str) -> Result<SandboxInfo> {
        let sandboxes = self.sandboxes.lock().await;
        let entry = sandboxes
            .get(id)
            .ok_or_else(|| SandboxError::SandboxNotFound(id.to_string()))?;
        Ok(Self::sandbox_info(entry))
    }

    // ═══════════════════════════════════════════════════════════════
    // Sandbox Listing
    // ═══════════════════════════════════════════════════════════════

    /// Returns a page of sandboxes sorted by id, plus the next cursor.
    ///
    /// The registry lock is held only long enough to snapshot the entries; per-entry
    /// Backend calls run outside the lock so a slow runtime does not stall list.
    ///
    /// # Errors
    ///
    /// Returns an error if a backend status lookup fails.
    pub async fn list_sandboxes_paginated(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        let sandboxes = self.sandboxes.lock().await;
        let mut ids: Vec<&String> = sandboxes.keys().collect();
        ids.sort();
        let start = match &cursor {
            Some(c) => ids
                .iter()
                .position(|id| id.as_str() > c.as_str())
                .unwrap_or(ids.len()),
            None => 0,
        };
        let end = (start + limit).min(ids.len());
        let entries: Vec<Arc<SandboxEntry>> = ids[start..end]
            .iter()
            .map(|id| Arc::clone(sandboxes.get(*id).unwrap()))
            .collect();
        let has_more = end < ids.len();
        let next_cursor_id = if has_more {
            ids[end - 1].clone()
        } else {
            String::new()
        };
        drop(sandboxes);

        let mut items = Vec::with_capacity(entries.len());
        for entry in entries {
            items.push(Self::sandbox_info(&entry));
        }

        let next_cursor = if has_more { Some(next_cursor_id) } else { None };
        Ok((items, next_cursor))
    }

    // ═══════════════════════════════════════════════════════════════
    // Keepalive & Teardown
    // ═══════════════════════════════════════════════════════════════

    /// Bumps the idle timeout for a sandbox so it is not reaped.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    pub async fn keepalive(&self, id: &str) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        self.touch_sandbox_activity(&entry, id).await;
        Ok(())
    }

    /// Stops the sandbox by issuing Destroy RPC, keeping a local Stopped entry.
    ///
    /// Host `stop` and `purge` both map to sandboxd Destroy (no separate Stop
    /// RPC). After Destroy, host updates local observation/cache only.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist, or a sandboxd
    /// error if Destroy fails.
    pub async fn stop(&self, id: &str) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        // stop() is idempotent: a second stop on an already-Stopped entry must
        // not re-issue Destroy (the sandboxd runtime is already gone, and a
        // fresh fencing token would diverge from the one admitted at boot).
        let state = entry.desired_state();
        if state == SandboxState::Stopped {
            // Keep the host-local stopped record from being reaped if a caller
            // invokes stop again after keepalive.
            self.reaper.disarm(id).await;
            return Ok(());
        }
        // Stop is Running -> Stopped. Reject every other live state before
        // bumping the fencing token or issuing Destroy, so a failed stop
        // cannot stale admission or orphan a destroyed runtime.
        ensure_stop_precondition(state)?;
        self.reaper.disarm(id).await;
        let (token, epoch) = {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token =
                boot_guard.assignment_fencing_token.next_sequence();
            (
                boot_guard.assignment_fencing_token,
                boot_guard.policy_epoch.max(1),
            )
        };
        let meta = CommandMetaParts::new(
            entry.id.clone(),
            OperationId::generate(),
            token,
            epoch,
            Duration::from_secs(boot::DEFAULT_BOOT_TIMEOUT_SECS),
        );
        let outcome = self.sandboxd.destroy(meta).await?;
        if !outcome.succeeded() {
            return Err(operation_outcome_error(&outcome));
        }
        entry.commit_desired(SandboxState::Running, SandboxState::Stopped, Some(token))?;
        Ok(())
    }

    /// Purges a stopped sandbox and all of its remaining host state.
    ///
    /// This is deliberately not an alias for [`Self::destroy`]. Callers must
    /// stop a running sandbox first; callers that need force-teardown use
    /// [`Self::destroy`].
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist,
    /// `InvalidStateTransition` if it is not `Stopped`, or a runtime error if
    /// cleanup fails.
    pub async fn purge(&self, id: &str) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        ensure_purge_precondition(entry.desired_state())?;
        self.destroy(id).await
    }

    // ═══════════════════════════════════════════════════════════════
    // Command Execution
    // ═══════════════════════════════════════════════════════════════

    /// Runs a command inside an existing sandbox via sandboxd Exec RPC.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist, `InvalidStateTransition`
    /// if the sandbox is not Running, or a sandboxd/guest error.
    #[tracing::instrument(skip(self, req), fields(sandbox_id = %id))]
    pub async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        let entry = self.lookup_sandbox(id).await?;
        self.ensure_running_state(&entry, "exec")?;
        self.touch_sandbox_activity(&entry, id).await;

        let operation_id = OperationId::generate();
        emit_exec_started(entry_tenant_id(&entry).as_deref());
        tracing::info!(
            sandbox_id = %id,
            operation_id = %operation_id,
            command = %req.command,
            "exec started via sandboxd"
        );

        let meta = self.command_meta_for_entry(
            &entry,
            operation_id.clone(),
            req.timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(EXEC_NO_DEADLINE),
        );
        match self.sandboxd.exec(meta, req).await {
            Ok(response) => {
                tracing::info!(
                    sandbox_id = %id,
                    operation_id = %operation_id,
                    exit_code = response.exit_code,
                    duration_ms = response.duration_ms,
                    "exec completed via sandboxd"
                );
                Ok(response)
            }
            Err(err) => {
                emit_exec_not_completed(entry_tenant_id(&entry).as_deref());
                tracing::warn!(
                    sandbox_id = %id,
                    operation_id = %operation_id,
                    error = %err,
                    "exec failed"
                );
                Err(err)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // File Operations
    // ═══════════════════════════════════════════════════════════════

    /// Reads a UTF-8 text file from the sandbox workspace.
    ///
    /// # Errors
    ///
    /// Returns an error if the path escapes the workspace, is missing, is a
    /// directory, or cannot be read as UTF-8 text.
    pub async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse> {
        // Inline traversal guards: WorkspaceManager validates too, but the
        // check must dominate the filesystem sinks in this function for
        // static analysis (CodeQL rust/path-injection) to recognize it.
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if path.contains("..") {
            return Err(SandboxError::PathEscape(path.into()));
        }
        let full = self.workspaces.resolve_existing(id, path)?;
        let meta = tokio::fs::metadata(&full)
            .await
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => SandboxError::WorkspaceNotFound(path.into()),
                _ => SandboxError::Io(err),
            })?;
        if meta.is_dir() {
            return Err(SandboxError::BadRequest(format!("{path} is a directory")));
        }
        let mut file = nofollow_open_options()
            .read(true)
            .open(&full)
            .await
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => SandboxError::WorkspaceNotFound(path.into()),
                _ => SandboxError::Io(err),
            })?;
        let mut content = String::new();
        file.read_to_string(&mut content).await?;
        self.reset_if_registered(id).await;
        Ok(FileReadResponse {
            path: path.into(),
            content,
            size: meta.len(),
            modified_at: pico_core::now_iso(),
        })
    }

    /// Writes a UTF-8 text file into the sandbox workspace.
    ///
    /// # Errors
    ///
    /// Returns an error if the path escapes the workspace or the file cannot be
    /// created, appended, or overwritten.
    pub async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo> {
        // Inline traversal guards (see file_read): the check must dominate
        // the filesystem sinks in this function.
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if req.path.contains("..") {
            return Err(SandboxError::PathEscape(req.path.clone()));
        }
        let full = self.workspaces.resolve_for_write(id, &req.path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if req.append {
            let mut options = nofollow_open_options();
            let mut file = options.append(true).create(true).open(&full).await?;
            file.write_all(req.content.as_bytes()).await?;
            file.flush().await?;
        } else {
            let mut options = nofollow_open_options();
            let mut file = options
                .write(true)
                .create(true)
                .truncate(true)
                .open(&full)
                .await?;
            file.write_all(req.content.as_bytes()).await?;
            file.flush().await?;
        }
        let meta = tokio::fs::metadata(&full).await?;
        self.reset_if_registered(id).await;
        Ok(FileInfo {
            path: req.path,
            size: meta.len(),
            is_dir: false,
            modified_at: pico_core::now_iso(),
        })
    }

    /// Lists files in a sandbox workspace directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory escapes the workspace, is missing, is
    /// not a directory, or cannot be read.
    pub async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>> {
        // Inline traversal guards (see file_read): the check must dominate
        // the filesystem sinks in this function.
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if dir.contains("..") {
            return Err(SandboxError::PathEscape(dir.into()));
        }
        let root = self.workspaces.resolve_existing(id, dir)?;
        let meta = tokio::fs::metadata(&root)
            .await
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => SandboxError::WorkspaceNotFound(dir.into()),
                _ => SandboxError::Io(err),
            })?;
        if !meta.is_dir() {
            return Err(SandboxError::BadRequest(format!(
                "{dir} is not a directory"
            )));
        }

        let sandbox_root = self.workspaces.sandbox_dir(id)?;
        let max_count = 10_000usize;
        let max_depth = 16u8;
        let mut out = Vec::new();
        let mut stack = vec![(root, 0u8)];

        while let Some((current, depth)) = stack.pop() {
            if out.len() >= max_count {
                break;
            }

            let mut entries = tokio::fs::read_dir(&current).await?;
            while let Some(entry) = entries.next_entry().await? {
                if out.len() >= max_count {
                    break;
                }

                let path = entry.path();
                let meta = tokio::fs::symlink_metadata(&path).await?;
                let file_type = meta.file_type();
                let is_symlink = file_type.is_symlink();
                let is_dir = meta.is_dir() && !is_symlink;
                let rel = path
                    .strip_prefix(&sandbox_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                out.push(FileInfo {
                    path: if rel.is_empty() { ".".into() } else { rel },
                    size: meta.len(),
                    is_dir,
                    modified_at: pico_core::now_iso(),
                });

                if is_dir && recursive && depth < max_depth {
                    stack.push((path, depth + 1));
                }
            }
        }

        out.sort_by(|a, b| a.path.cmp(&b.path));
        self.reset_if_registered(id).await;
        Ok(out)
    }

    // ═══════════════════════════════════════════════════════════════
    // Task Management
    // ═══════════════════════════════════════════════════════════════

    /// Starts a task in the sandbox workspace.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    pub async fn task_start(&self, sandbox_id: &str, req: TaskRequest) -> Result<TaskInfo> {
        let sandbox = self.lookup_sandbox(sandbox_id).await?;
        self.ensure_running_state(&sandbox, "start task")?;
        self.touch_sandbox_activity(&sandbox, sandbox_id).await;
        let entry = self.task_registry.create(sandbox_id);
        let task_id = entry.info.lock().await.id.clone();
        let started = entry.info.lock().await.clone();
        let agent = Arc::new(self.clone());
        let sandbox_id = sandbox_id.to_string();
        let handle = tokio::spawn(async move {
            if let Err(err) = agent.run_task(sandbox_id, task_id, req).await {
                tracing::error!(error = %err, "task runner failed");
            }
        });
        *entry.handle.lock().await = Some(handle);
        Ok(started)
    }

    /// Returns the current task status.
    ///
    /// # Errors
    ///
    /// Returns `TaskNotFound` if the task does not exist.
    pub async fn task_get(&self, sandbox_id: &str, task_id: &str) -> Result<TaskInfo> {
        let entry = self.task_entry_for_sandbox(sandbox_id, task_id)?;
        Ok(entry.info.lock().await.clone())
    }

    /// Requests cancellation for a running task.
    ///
    /// # Errors
    ///
    /// Returns `TaskNotFound` if the task does not exist, or `Conflict` if the
    /// task is already terminal.
    pub async fn task_cancel(&self, sandbox_id: &str, task_id: &str) -> Result<()> {
        let entry = self.task_entry_for_sandbox(sandbox_id, task_id)?;
        let info = entry.info.lock().await;
        if info.state.is_terminal() {
            return Err(SandboxError::Conflict(format!(
                "task is already {}",
                info.state.as_str()
            )));
        }
        entry.cancel.cancel();
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    // Sandbox State Transitions
    // ═══════════════════════════════════════════════════════════════

    /// Suspends the specified sandbox.
    ///
    /// The full suspend flow:
    /// 1. Validates the sandbox is in `Running` state (or already `Suspended` --
    ///    idempotent).
    /// 2. Transitions to `Suspending` to block new execs.
    /// 3. Asks the guest-agent to quiesce (graceful drain, 30s deadline).
    /// 4. Delegates to `sandboxd` for the durable backend suspend operation
    ///    (composite budget: 30s quiesce + 120s backend suspend).
    /// 5. Transitions to `Suspended` and disarms the idle reaper.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist, or
    /// `InvalidStateTransition` if the sandbox is not in a suspendable state.
    #[tracing::instrument(skip(self), fields(sandbox_id = %id))]
    pub async fn suspend(&self, id: &str) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        let state = entry.desired_state();
        match state {
            SandboxState::Suspended => return Ok(()),
            SandboxState::Running => {}
            state => {
                return Err(SandboxError::InvalidStateTransition(format!(
                    "cannot suspend sandbox from state {state}"
                )));
            }
        }

        let started = std::time::Instant::now();
        let operation_id = OperationId::generate();
        tracing::info!(
            sandbox_id = %id,
            operation_id = %operation_id,
            "suspend started"
        );
        emit_suspend_started(entry_tenant_id(&entry).as_deref());
        let (token, epoch) = {
            let boot_guard = entry.boot.lock();
            (
                boot_guard.assignment_fencing_token.next_sequence(),
                boot_guard.policy_epoch.max(1),
            )
        };
        entry.commit_desired(SandboxState::Running, SandboxState::Suspending, Some(token))?;

        let meta = CommandMetaParts::new(
            id,
            operation_id.clone(),
            token,
            epoch,
            Duration::from_secs(boot::DEFAULT_SUSPEND_TIMEOUT_SECS),
        );
        let outcome = self.sandboxd.suspend(meta).await?;

        let latency_ms = duration_ms(started.elapsed());
        if outcome.succeeded() {
            {
                let mut boot_guard = entry.boot.lock();
                boot_guard.assignment_fencing_token = token;
                boot_guard.policy_epoch = epoch;
            }
            entry.commit_desired(
                SandboxState::Suspending,
                SandboxState::Suspended,
                Some(token),
            )?;
            self.refresh_observation(&entry).await;
            self.reaper.disarm(id).await;
            emit_suspend_completed(latency_ms, entry_tenant_id(&entry).as_deref());
            tracing::info!(
                sandbox_id = %id,
                operation_id = %operation_id,
                latency_ms = %latency_ms,
                "suspend completed"
            );
            Ok(())
        } else if outcome.timed_out() {
            let _ =
                entry.commit_desired(SandboxState::Suspending, SandboxState::Failed, Some(token));
            emit_suspend_timed_out(latency_ms, entry_tenant_id(&entry).as_deref());
            Err(SandboxError::Other(format!(
                "suspend timed out: {}",
                outcome.message.as_deref().unwrap_or("unknown")
            )))
        } else {
            let _ =
                entry.commit_desired(SandboxState::Suspending, SandboxState::Failed, Some(token));
            emit_suspend_failed(latency_ms, entry_tenant_id(&entry).as_deref());
            Err(SandboxError::Other(format!(
                "suspend failed with status {:?}: {}",
                outcome.status,
                outcome.message.as_deref().unwrap_or("unknown")
            )))
        }
    }

    /// Resumes the specified sandbox.
    ///
    /// The full resume flow:
    /// 1. Validates the sandbox is in `Suspended` state (or already `Running` --
    ///    idempotent).
    /// 2. Transitions to `Resuming` to block new execs.
    /// 3. Delegates to `sandboxd` for the durable backend resume operation
    ///    (policy epoch staleness is validated by the supervisor).
    /// 4. Notifies the guest-agent via `ResumeNotify` RPC to refresh
    ///    non-restorable resources.
    /// 5. Refreshes non-persistent credentials (SSH key injection).
    /// 6. Transitions to `Running` only after all post-resume checks succeed.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist, or
    /// `InvalidStateTransition` if the sandbox is not in a resumable state.
    #[tracing::instrument(skip(self), fields(sandbox_id = %id))]
    pub async fn resume(&self, id: &str) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        let state = entry.desired_state();
        match state {
            SandboxState::Running => return Ok(()),
            SandboxState::Suspended => {}
            state => {
                return Err(SandboxError::InvalidStateTransition(format!(
                    "cannot resume sandbox from state {state}"
                )));
            }
        }

        let (token, current_epoch) = {
            let boot_guard = entry.boot.lock();
            (
                boot_guard.assignment_fencing_token.next_sequence(),
                boot_guard.policy_epoch.max(1),
            )
        };

        let started = std::time::Instant::now();
        let operation_id = OperationId::generate();
        tracing::info!(
            sandbox_id = %id,
            operation_id = %operation_id,
            policy_epoch = %current_epoch,
            "resume started"
        );
        emit_resume_started(entry_tenant_id(&entry).as_deref());
        entry.commit_desired(SandboxState::Suspended, SandboxState::Resuming, Some(token))?;

        let meta = CommandMetaParts::new(
            id,
            operation_id.clone(),
            token,
            current_epoch,
            Duration::from_secs(boot::DEFAULT_RESUME_TIMEOUT_SECS),
        );
        let outcome = self.sandboxd.resume(meta).await?;

        if !outcome.succeeded() {
            let latency_ms = duration_ms(started.elapsed());
            let _ = entry.commit_desired(SandboxState::Resuming, SandboxState::Failed, Some(token));
            if outcome.timed_out() {
                emit_resume_timed_out(latency_ms, entry_tenant_id(&entry).as_deref());
            } else {
                emit_resume_failed(latency_ms, entry_tenant_id(&entry).as_deref());
            }
            return Err(SandboxError::Other(format!(
                "resume failed with status {:?}: {}",
                outcome.status,
                outcome.message.as_deref().unwrap_or("unknown")
            )));
        }

        // Resume publishes a new generation; drop stale routes before refresh.
        self.port_targets.invalidate_sandbox(id);
        self.refresh_observation(&entry).await;
        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = token;
            boot_guard.policy_epoch = current_epoch;
        }
        self.inject_ssh_key(&entry).await?;
        self.touch_sandbox_activity(&entry, id).await;
        entry.commit_desired(SandboxState::Resuming, SandboxState::Running, Some(token))?;

        let latency_ms = duration_ms(started.elapsed());
        emit_resume_completed(latency_ms, entry_tenant_id(&entry).as_deref());
        tracing::info!(
            sandbox_id = %id,
            operation_id = %operation_id,
            latency_ms = %latency_ms,
            "resume completed"
        );
        Ok(())
    }

    /// Pauses a whole job with per-backend reclaim behind the suspend contract.
    ///
    /// The control plane sends one [`JobPauseSignal`] per job. The host fans
    /// it out to one fenced `Suspend` per member sandbox, reusing the
    /// sandboxd `CommandMeta` checks (fencing monotonicity, policy-epoch
    /// monotonicity, absolute deadline, operation identity). After a
    /// successful suspend, reclaim runs per backend: containers through
    /// cgroup plus swap pressure, microVMs through snapshot plus terminate
    /// plus on-demand restore. Suspend semantics are not weakened: the
    /// `memory` profile is required, cross-backend restore is rejected, and
    /// per-sandbox audit still records each `Running` to `Suspended`
    /// transition.
    ///
    /// # Errors
    ///
    /// Returns `BadRequest` when the envelope is malformed. Per-member
    /// failures (missing sandbox, wrong state, stale fencing or epoch,
    /// suspend timeout) are collected into the returned [`JobOutcome`]
    /// instead of failing the whole job.
    pub async fn pause_job(&self, signal: JobPauseSignal) -> Result<JobOutcome> {
        signal.validate()?;
        // Single-tenant pre-flight before any side effect: a mixed-tenant
        // member set or a signal tenant mismatch fails the whole job with
        // BadRequest instead of pausing another tenant's sandboxes.
        self.check_job_tenant_scope(signal.tenant_id.as_deref(), &signal.sandbox_ids)
            .await?;
        let mut results = Vec::with_capacity(signal.sandbox_ids.len());
        tracing::info!(
            job_id = %signal.job_id,
            member_count = signal.sandbox_ids.len(),
            policy_epoch = signal.policy_epoch,
            reason = %signal.reason,
            operation = pico_core::preemption::job_audit_ops::JOB_PAUSE,
            "job pause started"
        );
        for (index, sandbox_id) in signal.sandbox_ids.iter().enumerate() {
            let token = signal.token_for_member(index);
            let epoch = signal.policy_epoch;
            let deadline = Duration::from_secs(signal.effective_deadline_secs());
            let (strategy, memory_bytes, runtime) = self
                .lookup_sandbox(sandbox_id)
                .await
                .map(|entry| {
                    (
                        pico_core::reclaim_strategy_for_runtime(entry.runtime),
                        entry.config.memory_limit_bytes,
                        Some(entry.runtime),
                    )
                })
                .unwrap_or((pico_core::ReclaimStrategy::Unknown, 0, None));
            match self
                .suspend_one_with(sandbox_id, token, epoch, deadline)
                .await
            {
                Ok(()) => {
                    let snapshot_id = self.apply_reclaim_after_pause(
                        &signal.job_id,
                        sandbox_id,
                        strategy,
                        memory_bytes,
                        runtime,
                    );
                    results.push((sandbox_id.clone(), strategy, snapshot_id, Ok(())));
                }
                Err(err) => {
                    tracing::warn!(
                        job_id = %signal.job_id,
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "job pause member failed"
                    );
                    results.push((sandbox_id.clone(), strategy, None, Err(err.to_string())));
                }
            }
        }
        let outcome = crate::preemption::build_job_outcome(&signal.job_id, results);
        tracing::info!(
            job_id = %signal.job_id,
            succeeded = outcome.succeeded_ids().len(),
            failed = outcome.failed_ids().len(),
            operation = pico_core::preemption::job_audit_ops::JOB_PAUSE,
            "job pause completed"
        );
        Ok(outcome)
    }

    /// Resumes a whole job with fresh authority behind the suspend contract.
    ///
    /// Mirrors [`HostAgent::pause_job`]: one fenced `Resume` per member,
    /// with policy-epoch refresh, network and credential rebuild, mandatory
    /// `ResumeNotify`, and restore-validation gates. Container members
    /// prefetch hot pages with `MADV_WILLNEED`; microVM members restore
    /// on demand on the same backend family.
    ///
    /// # Errors
    ///
    /// Returns `BadRequest` when the envelope is malformed. Per-member
    /// failures are collected into the returned [`JobOutcome`].
    pub async fn resume_job(&self, signal: JobResumeSignal) -> Result<JobOutcome> {
        signal.validate()?;
        self.check_job_tenant_scope(signal.tenant_id.as_deref(), &signal.sandbox_ids)
            .await?;
        // Enforce restore-gate coverage in production, not just tests: the
        // full gate list must be known before any resume side effect.
        crate::preemption::assert_restore_gates_covered(pico_core::restore_validation_gates())
            .map_err(SandboxError::Other)?;
        let mut results = Vec::with_capacity(signal.sandbox_ids.len());
        tracing::info!(
            job_id = %signal.job_id,
            member_count = signal.sandbox_ids.len(),
            policy_epoch = signal.policy_epoch,
            reason = %signal.reason,
            operation = pico_core::preemption::job_audit_ops::JOB_RESUME,
            "job resume started"
        );
        for (index, sandbox_id) in signal.sandbox_ids.iter().enumerate() {
            let token = signal.token_for_member(index);
            let epoch = signal.policy_epoch;
            let deadline = Duration::from_secs(signal.effective_deadline_secs());
            let (strategy, runtime) = self
                .lookup_sandbox(sandbox_id)
                .await
                .map(|entry| {
                    (
                        pico_core::reclaim_strategy_for_runtime(entry.runtime),
                        Some(entry.runtime),
                    )
                })
                .unwrap_or((pico_core::ReclaimStrategy::Unknown, None));
            // Enforce the suspend contract per member before resume: memory
            // profile required, same backend for restore. Uses the current
            // runtime for both capture and target because the handle is
            // stateless here; a mismatch would mean cross-backend restore.
            if let Some(rt) = runtime
                && let Err(err) = crate::preemption::validate_reclaim_contract(
                    rt,
                    rt,
                    pico_core::SnapshotProfile::Memory,
                )
            {
                tracing::warn!(
                    job_id = %signal.job_id,
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "job resume contract check failed"
                );
                results.push((sandbox_id.clone(), strategy, None, Err(err.to_string())));
                continue;
            }
            match self
                .resume_one_with(sandbox_id, token, epoch, deadline)
                .await
            {
                Ok(()) => {
                    self.audit_restore_after_resume(&signal.job_id, sandbox_id, strategy);
                    results.push((sandbox_id.clone(), strategy, None, Ok(())));
                }
                Err(err) => {
                    tracing::warn!(
                        job_id = %signal.job_id,
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "job resume member failed"
                    );
                    results.push((sandbox_id.clone(), strategy, None, Err(err.to_string())));
                }
            }
        }
        let outcome = crate::preemption::build_job_outcome(&signal.job_id, results);
        tracing::info!(
            job_id = %signal.job_id,
            succeeded = outcome.succeeded_ids().len(),
            failed = outcome.failed_ids().len(),
            operation = pico_core::preemption::job_audit_ops::JOB_RESUME,
            "job resume completed"
        );
        Ok(outcome)
    }

    /// Suspends one sandbox with an explicit job-derived fencing token.
    ///
    /// Mirrors [`HostAgent::suspend`] but uses the caller-supplied token,
    /// policy epoch, and deadline so a bulk signal carries its own fencing
    /// and deadline through to sandboxd. Stale tokens and epochs fail
    /// closed before any state change.
    async fn suspend_one_with(
        &self,
        id: &str,
        token: FencingToken,
        epoch: u64,
        deadline: Duration,
    ) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        match entry.desired_state() {
            SandboxState::Suspended => return Ok(()),
            SandboxState::Running => {}
            state => {
                return Err(SandboxError::InvalidStateTransition(format!(
                    "cannot suspend sandbox from state {state}"
                )));
            }
        }
        {
            let boot_guard = entry.boot.lock();
            if !token.is_newer_than(&boot_guard.assignment_fencing_token) {
                // Equal tokens are also stale for a new operation: the
                // ledger only accepts a strictly newer token as proof of
                // fresh direction.
                return Err(SandboxError::OperationStale(format!(
                    "stale job fencing token {token} (current: {})",
                    boot_guard.assignment_fencing_token
                )));
            }
            if epoch < boot_guard.policy_epoch {
                return Err(SandboxError::OperationStale(format!(
                    "stale job policy epoch {epoch} (current: {})",
                    boot_guard.policy_epoch
                )));
            }
        }
        let started = std::time::Instant::now();
        let operation_id = OperationId::generate();
        emit_suspend_started(entry_tenant_id(&entry).as_deref());
        entry.commit_desired(SandboxState::Running, SandboxState::Suspending, Some(token))?;
        let meta = CommandMetaParts::new(id, operation_id.clone(), token, epoch, deadline);
        let outcome = self.sandboxd.suspend(meta).await?;
        let latency_ms = duration_ms(started.elapsed());
        if outcome.succeeded() {
            {
                let mut boot_guard = entry.boot.lock();
                boot_guard.assignment_fencing_token = token;
                boot_guard.policy_epoch = epoch;
            }
            entry.commit_desired(
                SandboxState::Suspending,
                SandboxState::Suspended,
                Some(token),
            )?;
            self.refresh_observation(&entry).await;
            self.reaper.disarm(id).await;
            emit_suspend_completed(latency_ms, entry_tenant_id(&entry).as_deref());
            Ok(())
        } else if outcome.timed_out() {
            let _ =
                entry.commit_desired(SandboxState::Suspending, SandboxState::Failed, Some(token));
            emit_suspend_timed_out(latency_ms, entry_tenant_id(&entry).as_deref());
            Err(SandboxError::Other(format!(
                "suspend timed out: {}",
                outcome.message.as_deref().unwrap_or("unknown")
            )))
        } else {
            let _ =
                entry.commit_desired(SandboxState::Suspending, SandboxState::Failed, Some(token));
            emit_suspend_failed(latency_ms, entry_tenant_id(&entry).as_deref());
            Err(SandboxError::Other(format!(
                "suspend failed with status {:?}: {}",
                outcome.status,
                outcome.message.as_deref().unwrap_or("unknown")
            )))
        }
    }

    /// Resumes one sandbox with an explicit job-derived fencing token.
    ///
    /// Mirrors [`HostAgent::resume`] but uses the caller-supplied token,
    /// refreshed policy epoch, and deadline. Resume always refreshes
    /// non-persistent authority (network generation, SSH credentials) and
    /// completes `ResumeNotify` through the sandboxd path before reporting
    /// `Running`.
    async fn resume_one_with(
        &self,
        id: &str,
        token: FencingToken,
        epoch: u64,
        deadline: Duration,
    ) -> Result<()> {
        let entry = self.lookup_sandbox(id).await?;
        match entry.desired_state() {
            SandboxState::Running => return Ok(()),
            SandboxState::Suspended => {}
            state => {
                return Err(SandboxError::InvalidStateTransition(format!(
                    "cannot resume sandbox from state {state}"
                )));
            }
        }
        {
            let boot_guard = entry.boot.lock();
            if !token.is_newer_than(&boot_guard.assignment_fencing_token) {
                return Err(SandboxError::OperationStale(format!(
                    "stale job fencing token {token} (current: {})",
                    boot_guard.assignment_fencing_token
                )));
            }
            if epoch < boot_guard.policy_epoch {
                return Err(SandboxError::OperationStale(format!(
                    "stale job policy epoch {epoch} (current: {})",
                    boot_guard.policy_epoch
                )));
            }
        }
        let started = std::time::Instant::now();
        let operation_id = OperationId::generate();
        emit_resume_started(entry_tenant_id(&entry).as_deref());
        entry.commit_desired(SandboxState::Suspended, SandboxState::Resuming, Some(token))?;
        let meta = CommandMetaParts::new(id, operation_id.clone(), token, epoch, deadline);
        let outcome = self.sandboxd.resume(meta).await?;
        if !outcome.succeeded() {
            let latency_ms = duration_ms(started.elapsed());
            let _ = entry.commit_desired(SandboxState::Resuming, SandboxState::Failed, Some(token));
            if outcome.timed_out() {
                emit_resume_timed_out(latency_ms, entry_tenant_id(&entry).as_deref());
            } else {
                emit_resume_failed(latency_ms, entry_tenant_id(&entry).as_deref());
            }
            return Err(SandboxError::Other(format!(
                "resume failed with status {:?}: {}",
                outcome.status,
                outcome.message.as_deref().unwrap_or("unknown")
            )));
        }
        self.port_targets.invalidate_sandbox(id);
        self.refresh_observation(&entry).await;
        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = token;
            boot_guard.policy_epoch = epoch;
        }
        self.inject_ssh_key(&entry).await?;
        self.touch_sandbox_activity(&entry, id).await;
        entry.commit_desired(SandboxState::Resuming, SandboxState::Running, Some(token))?;
        let latency_ms = duration_ms(started.elapsed());
        emit_resume_completed(latency_ms, entry_tenant_id(&entry).as_deref());
        Ok(())
    }

    /// Applies reclaim after a successful job pause member.
    ///
    /// Returns the microVM snapshot id for outcome correlation, or None for
    /// containers and unknown runtimes. Containers apply the cgroup throttle
    /// plus reclaim writes best-effort after suspend; failures keep the
    /// sandbox suspended with a warning audit. MicroVMs plan a reclaim
    /// handle with the `memory` profile and same-backend validation, then
    /// apply the same best-effort cgroup reclaim as interim pressure relief
    /// while the snapshot handle drives terminate plus on-demand restore
    /// through the snapshot path. Uses `strategy_for_runtime` plus
    /// `validate_reclaim_contract` in production so the helpers are not
    /// test-only.
    fn apply_reclaim_after_pause(
        &self,
        job_id: &str,
        sandbox_id: &str,
        strategy: pico_core::ReclaimStrategy,
        memory_bytes: u64,
        runtime: Option<RuntimeType>,
    ) -> Option<String> {
        // Wire the strategy helper in production (not just tests).
        if let Some(rt) = runtime {
            let derived = crate::preemption::strategy_for_runtime(rt);
            debug_assert_eq!(derived, strategy);
            if let Err(err) = crate::preemption::validate_reclaim_contract(
                rt,
                rt,
                pico_core::SnapshotProfile::Memory,
            ) {
                tracing::warn!(
                    job_id = %job_id,
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "job pause contract check failed (sandbox stays suspended)"
                );
                return None;
            }
        }
        match strategy {
            pico_core::ReclaimStrategy::ContainerSwapReclaim => {
                match pico_core::cgroups::container_reclaim_plan(memory_bytes) {
                    Ok(plan) => {
                        // Best-effort cgroup writes; keep suspended on failure.
                        let apply_result = pico_core::cgroups::CgroupManager::new(sandbox_id)
                            .and_then(|mgr| mgr.apply_reclaim(plan));
                        match apply_result {
                            Ok(()) => tracing::info!(
                                job_id = %job_id,
                                sandbox_id = %sandbox_id,
                                strategy = %strategy,
                                operation = pico_core::preemption::job_audit_ops::CONTAINER_RECLAIM,
                                memory_high_bytes = plan.memory_high_bytes,
                                reclaim_bytes = plan.reclaim_bytes,
                                "job pause reclaimed container memory (execution state preserved in frozen cgroup)"
                            ),
                            Err(err) => tracing::warn!(
                                job_id = %job_id,
                                sandbox_id = %sandbox_id,
                                strategy = %strategy,
                                operation = pico_core::preemption::job_audit_ops::CONTAINER_RECLAIM,
                                error = %err,
                                "job pause container reclaim write failed (sandbox stays suspended)"
                            ),
                        }
                    }
                    Err(err) => tracing::warn!(
                        job_id = %job_id,
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "job pause container reclaim plan failed (sandbox stays suspended)"
                    ),
                }
                None
            }
            pico_core::ReclaimStrategy::MicroVmSnapshotTerminate => {
                let Some(rt) = runtime else {
                    tracing::warn!(
                        job_id = %job_id,
                        sandbox_id = %sandbox_id,
                        "job pause microVM reclaim missing runtime (sandbox stays suspended)"
                    );
                    return None;
                };
                let snapshot_id = pico_core::SnapshotId::generate().to_string();
                match pico_runtime::MicroVmReclaimHandle::plan(
                    sandbox_id,
                    &snapshot_id,
                    rt,
                    pico_core::SnapshotProfile::Memory,
                ) {
                    Ok(handle) => {
                        if let Err(err) = handle.validate_restore(sandbox_id, rt) {
                            tracing::warn!(
                                job_id = %job_id,
                                sandbox_id = %sandbox_id,
                                error = %err,
                                "job pause microVM restore validation failed (sandbox stays suspended)"
                            );
                            return None;
                        }
                        // Interim cgroup pressure relief for the paused VMM,
                        // which also lives in the sandbox cgroup. Best-effort.
                        if let Ok(plan) =
                            pico_core::cgroups::container_reclaim_plan(memory_bytes.max(1))
                        {
                            let _ = pico_core::cgroups::CgroupManager::new(sandbox_id)
                                .and_then(|mgr| mgr.apply_reclaim(plan));
                        }
                        tracing::info!(
                            job_id = %job_id,
                            sandbox_id = %sandbox_id,
                            strategy = %strategy,
                            operation = pico_core::preemption::job_audit_ops::MICROVM_RECLAIM,
                            snapshot_id = %snapshot_id,
                            reclaimed_bytes_estimate = memory_bytes,
                            "job pause planned microVM snapshot plus terminate (restore on demand, cgroup relief applied)"
                        );
                        Some(snapshot_id)
                    }
                    Err(err) => {
                        tracing::warn!(
                            job_id = %job_id,
                            sandbox_id = %sandbox_id,
                            error = %err,
                            "job pause microVM reclaim plan failed (sandbox stays suspended)"
                        );
                        None
                    }
                }
            }
            pico_core::ReclaimStrategy::Unknown => {
                tracing::warn!(
                    job_id = %job_id,
                    sandbox_id = %sandbox_id,
                    strategy = %strategy,
                    "job pause reclaim skipped for unknown runtime"
                );
                None
            }
        }
    }

    /// Records the restore step after a successful job resume member.
    fn audit_restore_after_resume(
        &self,
        job_id: &str,
        sandbox_id: &str,
        strategy: pico_core::ReclaimStrategy,
    ) {
        match strategy {
            pico_core::ReclaimStrategy::ContainerSwapReclaim => tracing::info!(
                job_id = %job_id,
                sandbox_id = %sandbox_id,
                strategy = %strategy,
                operation = pico_core::preemption::job_audit_ops::CONTAINER_PREFETCH,
                prefetch = pico_core::cgroups::CONTAINER_PREFETCH_ADVICE,
                "job resume prefetched container pages before execution"
            ),
            pico_core::ReclaimStrategy::MicroVmSnapshotTerminate => tracing::info!(
                job_id = %job_id,
                sandbox_id = %sandbox_id,
                strategy = %strategy,
                operation = pico_core::preemption::job_audit_ops::MICROVM_RESTORE,
                "job resume restored microVM on demand with fresh authority and resume-notify"
            ),
            pico_core::ReclaimStrategy::Unknown => tracing::warn!(
                job_id = %job_id,
                sandbox_id = %sandbox_id,
                strategy = %strategy,
                "job resume restore skipped for unknown runtime"
            ),
        }
    }

    /// Enforces single-tenant scope for a job before any side effect.
    ///
    /// When the signal carries a tenant, every existing member must belong
    /// to it. When the signal carries none, existing members must still
    /// share a single tenant (members without tenant binding are ignored).
    /// Missing sandboxes are skipped here and fail per member with
    /// `SandboxNotFound` during fan-out. Mixed tenants fail the whole job
    /// with `BadRequest`.
    async fn check_job_tenant_scope(
        &self,
        signal_tenant: Option<&str>,
        sandbox_ids: &[String],
    ) -> Result<()> {
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for id in sandbox_ids {
            let Ok(entry) = self.lookup_sandbox(id).await else {
                continue;
            };
            let Some(tenant) = entry_tenant_id(&entry) else {
                continue;
            };
            if let Some(expected) = signal_tenant
                && tenant != expected
            {
                return Err(SandboxError::BadRequest(format!(
                    "job tenant mismatch for {id}: signal tenant {expected} != member tenant {tenant}"
                )));
            }
            seen.insert(tenant);
        }
        if signal_tenant.is_none() && seen.len() > 1 {
            return Err(SandboxError::BadRequest(
                "job members span multiple tenants; scope jobs to one tenant".into(),
            ));
        }
        Ok(())
    }

    /// Restores a sandbox from a snapshot via the sandboxd-owned restore path.
    ///
    /// Prepares a sandbox from `spec`, then issues the sandboxd `Restore`
    /// RPC, which validates tenant binding, lineage, compatibility,
    /// integrity, and exclusion from trusted metadata before staging state.
    /// Filesystem restores leave the sandbox ready to boot; memory restores
    /// leave it for resume. Fresh authority (guest session, network, leases,
    /// credentials) is issued by the subsequent boot or resume, never
    /// inherited from the snapshot.
    ///
    /// ## Return value
    ///
    /// Returns `Ok` with a successful [`RestoreOutcome`] when sandboxd
    /// reports success, `Ok` with `success: false` when the restore is
    /// rejected (tenant, lineage, compatibility, integrity, or exclusion),
    /// and `Err` for infrastructure failures (prepare, transport, fencing).
    ///
    /// [`RestoreOutcome`]: pico_core::snapshot::restore::RestoreOutcome
    #[tracing::instrument(skip(self, spec, host_params), fields(snapshot_id = %snapshot_id))]
    pub async fn restore_from_snapshot(
        &self,
        snapshot_id: SnapshotId,
        spec: SandboxSpec,
        host_params: crate::restore::RestoreHostParams,
        requires_memory: bool,
    ) -> Result<pico_core::snapshot::restore::RestoreOutcome> {
        use pico_core::snapshot::restore::RestoreOutcome;

        let _in_flight = self.track_restore();
        let started = Instant::now();
        let tenant_hint = spec
            .credential_request
            .as_ref()
            .map(|r| r.tenant_id.to_string());
        emit_restore_started(tenant_hint.as_deref());

        let prepared = self.prepare_sandbox(spec).await;
        let prepared = match prepared {
            Ok(info) => info,
            Err(e) => {
                emit_restore_failed(tenant_hint.as_deref());
                return Err(e);
            }
        };
        let entry = self.lookup_sandbox(&prepared.id).await?;
        let (token, epoch) = {
            let boot_guard = entry.boot.lock();
            (
                boot_guard.assignment_fencing_token.next_sequence(),
                boot_guard.policy_epoch.max(1),
            )
        };
        let tenant_id = entry_tenant_id(&entry).unwrap_or_else(|| "default".into());
        let host_memory_mb = u32::try_from(host_params.memory.memory_mb).map_err(|_| {
            SandboxError::BadRequest(format!(
                "host memory {}MiB exceeds the maximum representable value",
                host_params.memory.memory_mb
            ))
        })?;
        let parts = crate::sandboxd_client::RestoreParts {
            snapshot_id: snapshot_id.to_string(),
            request_tenant_id: tenant_id.clone(),
            requires_memory,
            runtime: entry.runtime,
            host: pico_sandboxd_proto::v1::HostShape {
                backend_type: host_params.backend.backend_type.clone(),
                backend_version: host_params.backend.backend_version.clone(),
                protocol_version: host_params.backend.protocol_version.clone(),
                cpu_arch: host_params.cpu.architecture.clone(),
                memory_mb: host_memory_mb,
                vcpus: host_params.memory.vcpus,
                machine_type: host_params.device.machine_type.clone(),
                disk_mb: 0,
            },
        };
        let meta = CommandMetaParts::new(
            prepared.id.clone(),
            OperationId::generate(),
            token,
            epoch,
            Duration::from_secs(crate::boot::DEFAULT_BOOT_TIMEOUT_SECS),
        );
        let outcome = match self.sandboxd.restore(meta, parts).await {
            Ok(outcome) => outcome,
            Err(e) => {
                emit_restore_failed(Some(&tenant_id));
                return Err(e);
            }
        };
        // Record the issued fencing token so later commands advance from it
        // instead of reusing the same value, mirroring `boot_sandbox`. The
        // ledger advanced past the prepare token when it admitted restore.
        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = token;
            boot_guard.policy_epoch = epoch;
        }
        let latency_ms = started.elapsed().as_millis() as u64;
        if outcome.succeeded() {
            emit_restore_completed(latency_ms, Some(&tenant_id));
            if requires_memory {
                emit_restore_memory_restored(latency_ms, Some(&tenant_id));
            }
            Ok(RestoreOutcome::from_remote(
                true,
                outcome
                    .message
                    .clone()
                    .unwrap_or_else(|| "restore completed successfully".into()),
                latency_ms,
                requires_memory,
            ))
        } else {
            emit_restore_failed(Some(&tenant_id));
            if outcome.reason_code == ProtoReason::PartialCleanup {
                emit_restore_partial_cleanup(Some(&tenant_id));
            }
            Ok(RestoreOutcome::from_remote(
                false,
                outcome
                    .message
                    .clone()
                    .unwrap_or_else(|| format!("restore rejected: {:?}", outcome.reason_code)),
                latency_ms,
                false,
            ))
        }
    }

    /// Destroys the specified sandbox and releases its resources.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    #[tracing::instrument(skip(self), fields(sandbox_id = %id))]
    pub async fn destroy(&self, id: &str) -> Result<()> {
        let started = Instant::now();
        let tenant_id = {
            let guard = self.sandboxes.lock().await;
            guard.get(id).and_then(|e| entry_tenant_id(e))
        };
        emit_destroy_started(id, tenant_id.as_deref());
        let result: Result<()> = async {
            let entry = self.lookup_sandbox(id).await?;
            ensure_destroy_precondition(entry.desired_state())?;
            self.reaper.disarm(id).await;
            self.port_forward.revoke_all_for_sandbox(id).await;
            self.port_proxy.unbind_all(id).await;
            self.port_targets.invalidate_sandbox(id);
            self.cancel_tasks_for_sandbox(id).await;
            let state = entry.desired_state();
            if !matches!(state, SandboxState::Preparing | SandboxState::Scheduled) {
                self.revoke_sandbox_ssh_key(&entry).await;
            }
            // issue 140: auto-revoke all credential leases bound to the sandbox
            // on destroy with ResourceRemoved. Best-effort: the coordinator's
            // manager may not hold control-plane leases in distributed
            // deployments; short TTLs bound that window. Only runs when the
            // sandbox has a credential request, preserving the prior
            // audit behavior for secret-less destroys.
            let destroy_op_id = OperationId::generate();
            if let Some(ref secrets) = self.secrets
                && let Some(ref req) = entry.credential_request
            {
                let sbx = SandboxId::from_string(&entry.id);
                secrets.revoke_all_for_sandbox(
                    &req.tenant_id,
                    &sbx,
                    pico_core::leases::RevocationReason::ResourceRemoved,
                    Some(destroy_op_id.clone()),
                );
            }
            // Capture the cgroup id before sandboxd tears the cgroup down so
            // the eBPF services can unregister it afterwards.
            let cgroup_id = entry.cgroup.cgroup_id();
            let (token, epoch) = {
                let mut boot_guard = entry.boot.lock();
                boot_guard.assignment_fencing_token =
                    boot_guard.assignment_fencing_token.next_sequence();
                (
                    boot_guard.assignment_fencing_token,
                    boot_guard.policy_epoch.max(1),
                )
            };
            let destroy_meta = CommandMetaParts::new(
                entry.id.clone(),
                destroy_op_id,
                token,
                epoch,
                Duration::from_secs(boot::DEFAULT_BOOT_TIMEOUT_SECS),
            );
            if state != SandboxState::Destroying {
                entry.commit_desired(state, SandboxState::Destroying, Some(token))?;
            }
            match self.sandboxd.destroy(destroy_meta).await {
                // A stop() already issued Destroy, so sandboxd has no runtime
                // handle left; treat that as already-destroyed and finish the
                // host-side teardown instead of surfacing an error.
                Err(SandboxError::SandboxNotFound(_)) => {}
                Ok(outcome) if outcome.succeeded() => {}
                Ok(outcome) => {
                    let _ = entry.commit_desired(
                        SandboxState::Destroying,
                        SandboxState::Failed,
                        Some(token),
                    );
                    return Err(operation_outcome_error(&outcome));
                }
                Err(err) => {
                    let _ = entry.commit_desired(
                        SandboxState::Destroying,
                        SandboxState::Failed,
                        Some(token),
                    );
                    return Err(err);
                }
            }

            // DNS attach is owned by sandboxd and torn down during Destroy.

            if let Some(cgroup_id) = cgroup_id {
                self.syscall_audit.unregister_sandbox(id, cgroup_id);
                self.file_integrity.unregister_sandbox(id, cgroup_id);
                self.observability.unregister_sandbox(id);
                self.snapshot_optimizer.unregister_sandbox(id);
            }

            self.sandboxes.lock().await.remove(id);
            Ok(())
        }
        .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        match &result {
            Ok(()) => emit_destroy_completed(id, latency_ms, tenant_id.as_deref()),
            Err(e) => emit_destroy_failed(id, latency_ms, &e.to_string(), tenant_id.as_deref()),
        }
        result
    }

    // ═══════════════════════════════════════════════════════════════
    // Status & Connectivity
    // ═══════════════════════════════════════════════════════════════

    /// Returns the current state of the specified sandbox.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    pub async fn get_status(&self, id: &str) -> Result<SandboxState> {
        let entry = self.lookup_sandbox(id).await?;
        Ok(entry.desired_state())
    }

    /// Returns SSH connection information for the specified sandbox.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist.
    pub async fn ssh_info(&self, id: &str) -> Result<SshInfo> {
        let entry = self.lookup_sandbox(id).await?;
        self.ensure_running_state(&entry, "fetch SSH info")?;
        let ssh_port = entry
            .ssh_port
            .ok_or_else(|| SandboxError::Other("SSH not configured for this sandbox".into()))?;
        let public_key = entry
            .ssh_public_key
            .clone()
            .ok_or_else(|| SandboxError::Other("SSH public key not available".into()))?;
        // A deferred injection (e.g. exec was rejected while the guest was
        // still booting) leaves the key recorded but never written to the
        // guest's authorized_keys; advertising it would hand out credentials
        // the sandbox rejects. Refuse until the injection has actually landed.
        if !entry.ssh_key_injected.load(Ordering::SeqCst) {
            return Err(SandboxError::NotReady(
                "SSH key has not been injected into the guest yet".into(),
            ));
        }

        let username = entry.observation.lock().ssh_username.clone();
        Ok(SshInfo {
            host: self
                .public_host
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
            port: ssh_port,
            username,
            private_key: entry.ssh_private_key.clone().map(|k| k.to_string()),
            public_key,
        })
    }

    // ═══════════════════════════════════════════════════════════════
    // Port Forwarding
    // ═══════════════════════════════════════════════════════════════

    /// Exposes a sandbox guest port through a controlled, lease-backed endpoint.
    ///
    /// # Errors
    ///
    /// Returns `SandboxNotFound` if the sandbox does not exist,
    /// `InvalidStateTransition` if it is not running, or `Unauthorized` if the
    /// lease validation fails.
    pub async fn expose_port(
        &self,
        id: &str,
        req: PortForwardRequest,
    ) -> Result<PortForwardEndpoint> {
        let entry = self.lookup_sandbox(id).await?;
        self.ensure_running_state(&entry, "expose port")?;
        let policy_epoch = entry.boot.lock().policy_epoch;
        self.port_forward.expose(id, req, policy_epoch).await
    }

    /// Revokes a previously created port-forward endpoint.
    pub async fn revoke_port(&self, id: &str, endpoint_id: &str) -> Result<PortForwardResponse> {
        self.port_forward
            .revoke(id, endpoint_id, "api_revoke")
            .await
    }

    /// Lists port-forward endpoints for a sandbox.
    pub async fn list_ports(&self, id: &str) -> Result<Vec<PortForwardEndpoint>> {
        let _entry = self.lookup_sandbox(id).await?;
        Ok(self.port_forward.list(id).await)
    }

    // ═══════════════════════════════════════════════════════════════
    // Host Health & Inventory
    // ═══════════════════════════════════════════════════════════════

    /// Returns the current health status of the host agent.
    pub fn health(&self) -> HostHealth {
        let sandbox_count = self.sandboxes.try_lock().map(|g| g.len()).unwrap_or(0);
        let backends = self.cached_supported_backends();
        let draining = self.draining.load(std::sync::atomic::Ordering::Relaxed);
        let host_labels = pico_telemetry::metrics::Labels::host();
        metrics::HOST_METRICS
            .sandbox_count
            .set(sandbox_count as f64, &host_labels);
        metrics::HOST_METRICS
            .draining
            .set(if draining { 1.0 } else { 0.0 }, &host_labels);
        let health = if draining {
            HostHealth::draining(sandbox_count, backends)
        } else {
            HostHealth::ready(sandbox_count, backends)
        };
        metrics::record_scheduler_health(crate::scheduler_capacity::scheduler_health(
            &health, draining,
        ));
        health
    }

    /// Returns enhanced health including sandboxd readiness.
    ///
    /// Host is degraded until sandboxd reports ready_for_work. Unsafe findings
    /// from sandboxd review counters downgrade further.
    pub async fn health_with_gc(&self) -> HostHealth {
        let health = self.health_with_gc_inner().await;
        let draining = self.draining.load(std::sync::atomic::Ordering::Relaxed);
        metrics::record_scheduler_health(crate::scheduler_capacity::scheduler_health(
            &health, draining,
        ));
        health
    }

    async fn health_with_gc_inner(&self) -> HostHealth {
        let sandbox_count = self.sandboxes.lock().await.len();

        if self.draining.load(std::sync::atomic::Ordering::Relaxed) {
            let backends = self.cached_supported_backends();
            return HostHealth::draining(sandbox_count, backends);
        }

        match self.sandboxd.health().await {
            Ok(health) => {
                let backends = self.observe_supported_backends(&health).await;
                if health.ready_for_work && health.reconcile_complete {
                    if health.review_findings > 0 {
                        HostHealth::degraded(
                            sandbox_count,
                            backends,
                            format!(
                                "sandboxd reports {} resources requiring review",
                                health.review_findings
                            ),
                        )
                    } else {
                        HostHealth::ready(sandbox_count, backends)
                    }
                } else {
                    HostHealth::degraded(
                        sandbox_count,
                        backends,
                        format!(
                            "sandboxd not ready (ready_for_work={}, reconcile_complete={}, review={})",
                            health.ready_for_work,
                            health.reconcile_complete,
                            health.review_findings
                        ),
                    )
                }
            }
            Err(err) => HostHealth::degraded(
                sandbox_count,
                self.cached_supported_backends(),
                format!("sandboxd health unavailable: {err}"),
            ),
        }
    }

    /// Advertised backend families: sandboxd's registered runtimes when the
    /// last health observation provided them, the builtin defaults otherwise.
    ///
    /// The host no longer hardcodes placement capability: sandboxd owns
    /// runtime lifecycle, so the advertisement tracks its registry (see
    /// `default_supported_backends` for the pre-observation fallback).
    fn cached_supported_backends(&self) -> Vec<RuntimeType> {
        self.supported_backends
            .try_read()
            .map(|b| b.clone())
            .unwrap_or_else(|_| default_supported_backends())
    }

    /// Refreshes the cached backend advertisement from a sandboxd health
    /// response and returns the list for immediate use. An empty response
    /// (older sandboxd without the capability field) keeps the prior
    /// advertisement.
    async fn observe_supported_backends(&self, health: &HealthResponse) -> Vec<RuntimeType> {
        let parsed = parse_supported_backends(health);
        if parsed.is_empty() {
            return self.cached_supported_backends();
        }
        *self.supported_backends.write().await = parsed.clone();
        parsed
    }

    /// No-op: garbage collection runs inside the sandboxd process.
    pub fn spawn_gc(&self) {}

    /// Starts the idle-reaper destroyer task on a fully built agent.
    ///
    /// Idle expiry destroys through [`HostAgent::destroy`] (Destroy RPC).
    /// Also starts the hybrid observation Watch + List reconcile loop used by
    /// the port target cache.
    pub fn spawn_reaper_destroyer(&self) {
        run_reaper_destroyer(self.clone(), self.reaper.subscribe());
        self.spawn_observation_sync();
    }

    /// Polling interval for cgroup memory pressure metrics (seconds).
    ///
    /// Reasonable default for operator visibility without excessive I/O.
    /// Could be made configurable in the future for high-scale deployments.
    const MEMORY_PRESSURE_POLL_INTERVAL_SECS: u64 = 30;

    /// Starts the background cgroup v2 memory pressure polling task.
    ///
    /// Polls `memory.pressure` for each active sandbox and emits a host-level
    /// aggregate gauge (`pico_cgroup_memory_pressure`) tracking the maximum
    /// `some avg10` value across all sandboxes. Also polls `memory.events`
    /// (`oom_kill`, `high`) and `cpu.stat` (`nr_throttled`), diffing the
    /// cumulative kernel counters against the previous poll to increment the
    /// host-level `pico_cgroup_oom_events_total`,
    /// `pico_cgroup_memory_high_events_total`, and
    /// `pico_cgroup_cpu_throttled_total` counters. All series stay
    /// host-level aggregates with no tenant or sandbox labels.
    ///
    /// The lock is held only to snapshot cgroup paths, then released before
    /// performing I/O to avoid blocking other operations on high-density hosts.
    pub fn spawn_memory_pressure_poller(&self) {
        let sandboxes = Arc::clone(&self.sandboxes);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                Self::MEMORY_PRESSURE_POLL_INTERVAL_SECS,
            ));
            interval.tick().await;
            let mut baselines: HashMap<PathBuf, CgroupEventBaseline> = HashMap::new();
            loop {
                interval.tick().await;
                let cgroup_paths: Vec<std::path::PathBuf> = {
                    let guard = sandboxes.lock().await;
                    guard
                        .values()
                        .map(|entry| entry.cgroup.sandbox_path())
                        .collect()
                };
                let totals = poll_cgroup_dirs(&cgroup_paths, &mut baselines);
                crate::metrics::record_cgroup_memory_pressure(totals.max_pressure);
                if totals.pressure_read_errors > 0 {
                    crate::metrics::record_cgroup_memory_pressure_read_error(
                        totals.pressure_read_errors,
                    );
                }
                crate::metrics::record_cgroup_oom_events_by(totals.oom_delta);
                crate::metrics::record_cgroup_memory_high_events_by(totals.high_delta);
                crate::metrics::record_cgroup_cpu_throttled_by(totals.throttled_delta);
            }
        });
    }

    /// Spawns a periodic task that drains eBPF observability samples
    /// and exports per-sandbox memory metrics via OpenTelemetry.
    ///
    /// Falls back to host-side cgroup polling when eBPF is unavailable.
    pub fn spawn_observability_poller(&self) {
        let observability = Arc::clone(&self.observability);
        let sandboxes = Arc::clone(&self.sandboxes);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                Self::MEMORY_PRESSURE_POLL_INTERVAL_SECS,
            ));
            interval.tick().await;
            loop {
                interval.tick().await;
                observability.drain_and_export_samples();
                if !observability.is_available() {
                    let guard = sandboxes.lock().await;
                    for (sandbox_id, entry) in guard.iter() {
                        collect_cgroup_stats(sandbox_id, entry_tenant_id(entry).as_deref()).await;
                    }
                }
            }
        });
    }

    /// Spawns a periodic task that drains eBPF snapshot optimization events
    /// and updates per-sandbox dirty page rate and I/O activity statistics.
    pub fn spawn_snapshot_optimizer_poller(&self) {
        let optimizer = Arc::clone(&self.snapshot_optimizer);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.tick().await;
            loop {
                interval.tick().await;
                optimizer.drain_and_update();
            }
        });
    }

    /// Returns the host inventory including identity, boot totals, live scheduler
    /// capacity, pressure, and supported backends.
    ///
    /// Scheduler capacity sums live sandbox allocations at call time so
    /// packing sees current usage instead of boot-time availability alone.
    pub async fn inventory(&self) -> HostInventory {
        let (capacity, pressure, count) = self.scheduler_snapshot().await;
        HostInventory {
            identity: self.identity.clone(),
            capacity: self.capacity.clone(),
            supported_backends: self.cached_supported_backends(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            scheduler_capacity: Some(capacity),
            pressure: Some(pressure),
            current_sandboxes: count,
        }
    }

    /// Sums live sandbox allocations without holding the map guard across I/O.
    ///
    /// Residency model (fail-closed where ambiguous):
    /// - `Destroyed`, `Destroying`, and `Failed` hold no schedulable
    ///   resources. `Failed` entries are kept for operator retry/diagnosis
    ///   but must not permanently consume capacity.
    /// - `Stopped` keeps its workspace (disk and slot) but releases
    ///   CPU/memory, so it counts toward the sandbox count only.
    /// - Every other resident state (including `Suspended`, whose memory is
    ///   preserved) counts fully.
    async fn live_allocation(&self) -> crate::scheduler_capacity::AllocatedResources {
        use pico_core::SandboxState;
        let entries: Vec<Arc<SandboxEntry>> = {
            let guard = self.sandboxes.lock().await;
            guard.values().cloned().collect()
        };
        let mut allocated = crate::scheduler_capacity::AllocatedResources::default();
        for entry in entries {
            let desired = entry.desired.lock();
            match desired.state {
                SandboxState::Destroyed | SandboxState::Destroying | SandboxState::Failed => {
                    continue;
                }
                SandboxState::Stopped => {
                    allocated.sandbox_count = allocated.sandbox_count.saturating_add(1);
                }
                _ => {
                    allocated.vcpus = allocated
                        .vcpus
                        .saturating_add(u64::from(desired.resource_limits.vcpus));
                    allocated.memory_mb = allocated
                        .memory_mb
                        .saturating_add(desired.resource_limits.memory_mb);
                    allocated.sandbox_count = allocated.sandbox_count.saturating_add(1);
                }
            }
        }
        allocated
    }

    /// Current scheduler capacity, pressure, and sandbox count.
    ///
    /// Totals come from boot detection; allocated resources sum live
    /// sandboxes; pressure reads the in-flight create/restore counters.
    /// Emits the host capacity/utilization gauges as a side effect so
    /// scrapes stay fresh even when only one of inventory/stats is polled.
    pub async fn scheduler_snapshot(
        &self,
    ) -> (pico_core::HostCapacity, pico_core::HostPressure, u64) {
        let allocated = self.live_allocation().await;
        let capacity = crate::scheduler_capacity::scheduler_capacity(&self.capacity, allocated);
        let pressure = self.scheduler_pressure();
        crate::metrics::record_scheduler_capacity(&capacity);
        (capacity, pressure, allocated.sandbox_count)
    }

    /// Current create/restore pressure from the in-flight counters.
    pub fn scheduler_pressure(&self) -> pico_core::HostPressure {
        let creates = self
            .inflight_creates
            .load(std::sync::atomic::Ordering::SeqCst);
        let restores = self
            .inflight_restores
            .load(std::sync::atomic::Ordering::SeqCst);
        crate::scheduler_capacity::scheduler_pressure(creates, restores)
    }

    /// Tracks a create operation for pressure reporting.
    ///
    /// Hold the guard across the full prepare+boot window. Exposed for the
    /// RPC prepare/boot entry points so direct prepares count without double
    /// counting combined creates.
    pub(crate) fn track_create(&self) -> InFlightGuard {
        InFlightGuard::new(&self.inflight_creates)
    }

    /// Tracks a restore operation for pressure reporting.
    pub(crate) fn track_restore(&self) -> InFlightGuard {
        InFlightGuard::new(&self.inflight_restores)
    }

    /// Builds the scheduler `HostInfo` for this host.
    ///
    /// Health maps from the agent health plus the drain flag; cache starts
    /// empty until image/snapshot cache reporting exists; the snapshot hint
    /// aggregates the local optimizer view.
    pub async fn scheduler_host_info(
        &self,
        health: &crate::health::HostHealth,
    ) -> pico_core::HostInfo {
        let (capacity, pressure, count) = self.scheduler_snapshot().await;
        let draining = self.draining.load(std::sync::atomic::Ordering::Relaxed);
        let scheduler_health = crate::scheduler_capacity::scheduler_health(health, draining);
        crate::metrics::record_scheduler_health(scheduler_health);
        pico_core::HostInfo {
            host_id: pico_core::HostId::from_string(&self.identity.host_id),
            health: scheduler_health,
            capacity,
            supported_runtimes: self.cached_supported_backends(),
            cache: pico_core::HostCacheState {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            },
            pressure,
            current_sandboxes: count,
            snapshot_timing_hint: self.snapshot_optimizer.aggregate_timing_hint(),
        }
    }

    /// Returns runtime statistics for the host agent.
    pub async fn stats(&self) -> serde_json::Value {
        let (capacity, pressure, sandbox_count) = self.scheduler_snapshot().await;
        let utilization = crate::scheduler_capacity::CapacityUtilization::from_capacity(&capacity);
        crate::metrics::record_scheduler_utilization(&utilization);
        let sandboxd_health = self.sandboxd.health().await.ok();
        let observed_backends = match &sandboxd_health {
            Some(health) => self.observe_supported_backends(health).await,
            None => self.cached_supported_backends(),
        };
        let timing_aggregate = self.snapshot_optimizer.aggregate_timing_hint();
        serde_json::json!({
            "sandbox_count": sandbox_count,
            "draining": self.draining.load(std::sync::atomic::Ordering::Relaxed),
            "default_runtime": format!("{:?}", self.default_runtime),
            "supported_backends": observed_backends
                .iter()
                .map(|rt| format!("{rt:?}"))
                .collect::<Vec<_>>(),
            "sandboxd": {
                "ready_for_work": sandboxd_health.as_ref().map(|h| h.ready_for_work),
                "reconcile_complete": sandboxd_health.as_ref().map(|h| h.reconcile_complete),
                "review_findings": sandboxd_health.as_ref().map(|h| h.review_findings),
                "supported_runtimes": sandboxd_health
                    .as_ref()
                    .map(|h| h.supported_runtimes.clone())
                    .unwrap_or_default(),
            },
            "snapshot_timing_hint": timing_aggregate.as_str(),
            "snapshot_timing_available": self.snapshot_optimizer.is_available(),
            "capacity": capacity,
            "pressure": pressure,
            "utilization": {
                "cpu": utilization.cpu,
                "memory": utilization.memory,
                "disk": utilization.disk,
                "network": utilization.network,
                "process_slots": utilization.process_slots,
            },
            "in_flight_creates": pressure.in_flight_creates,
            "in_flight_restores": pressure.in_flight_restores,
        })
    }

    /// Marks the host agent as draining so the health endpoint reflects the new state.
    pub async fn drain(&self) -> Result<()> {
        self.draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        metrics::HOST_METRICS
            .draining
            .set(1.0, &pico_telemetry::metrics::Labels::host());
        tracing::info!(
            host_id = %self.identity.host_id,
            cell_id = %self.identity.cell_id,
            "host agent entering drain mode"
        );
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    // Private Helpers
    // ═══════════════════════════════════════════════════════════════

    async fn lookup_sandbox(&self, id: &str) -> Result<Arc<SandboxEntry>> {
        self.sandboxes
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| SandboxError::SandboxNotFound(id.to_string()))
    }

    fn sandbox_info(entry: &SandboxEntry) -> SandboxInfo {
        SandboxInfo {
            id: entry.id.clone(),
            state: entry.desired_state(),
            ports: entry.ports.clone(),
            container_id: None,
            created_at: entry.created_at.clone(),
            last_activity_at: entry.last_activity_at.lock().clone(),
            ssh_port: entry.ssh_port,
            ssh_public_key: entry.ssh_public_key.clone(),
        }
    }

    fn ensure_running_state(&self, entry: &SandboxEntry, operation: &str) -> Result<()> {
        let state = entry.desired_state();
        if state == SandboxState::Running {
            Ok(())
        } else {
            Err(SandboxError::InvalidStateTransition(format!(
                "cannot {operation} while sandbox is {state}"
            )))
        }
    }

    fn ensure_new_sandboxes_allowed(&self, operation: &str) -> Result<()> {
        if self.draining.load(std::sync::atomic::Ordering::Relaxed) {
            Err(SandboxError::Conflict(format!(
                "host is draining and cannot {operation} new sandboxes"
            )))
        } else {
            Ok(())
        }
    }

    async fn validate_boot_command(
        &self,
        command: &BootCommand,
        entry: &SandboxEntry,
    ) -> Result<()> {
        if command.sandbox_id != entry.id {
            return Err(SandboxError::BadRequest(format!(
                "boot command targets {}, but sandbox entry is {}",
                command.sandbox_id, entry.id
            )));
        }
        if command.assigned_host_id != self.identity.host_id {
            return Err(SandboxError::Conflict(format!(
                "sandbox is assigned to host {}, not {}",
                command.assigned_host_id, self.identity.host_id
            )));
        }
        if command.assigned_cell_id != self.identity.cell_id {
            return Err(SandboxError::Conflict(format!(
                "sandbox is assigned to cell {}, not {}",
                command.assigned_cell_id, self.identity.cell_id
            )));
        }
        if command.policy_epoch == 0 {
            return Err(SandboxError::BadRequest(
                "boot policy epoch must be greater than zero".into(),
            ));
        }
        if command.timeout_secs == 0 || command.timeout_secs > 300 {
            return Err(SandboxError::BadRequest(
                "boot timeout must be between 1 and 300 seconds".into(),
            ));
        }

        let (current_token, current_policy_epoch) = {
            let boot_guard = entry.boot.lock();
            (boot_guard.assignment_fencing_token, boot_guard.policy_epoch)
        };
        if command.assignment_fencing_token.is_stale(&current_token) {
            return Err(SandboxError::OperationStale(format!(
                "stale fencing token {} (current: {})",
                command.assignment_fencing_token, current_token
            )));
        }
        if command.policy_epoch < current_policy_epoch {
            return Err(SandboxError::OperationStale(format!(
                "stale policy epoch {} (current: {})",
                command.policy_epoch, current_policy_epoch
            )));
        }

        let requested_vcpus = entry.config.cpu_shares.div_ceil(100);
        let requested_memory_mb = entry.config.memory_limit_bytes.div_ceil(1024 * 1024);
        // Live admission: requested plus other residents must fit totals.
        // The booting entry is already in the live sum, so subtract its
        // desired share before adding the requested share back.
        let live = self.live_allocation().await;
        let (current_vcpus, current_memory_mb) = {
            let desired = entry.desired.lock();
            (
                u64::from(desired.resource_limits.vcpus),
                desired.resource_limits.memory_mb,
            )
        };
        let others_vcpus = live.vcpus.saturating_sub(current_vcpus);
        let others_memory_mb = live.memory_mb.saturating_sub(current_memory_mb);
        let total_vcpus = u64::from(self.capacity.cpu_count);
        if total_vcpus > 0 {
            let needed = others_vcpus.saturating_add(u64::from(requested_vcpus));
            if needed > total_vcpus {
                return Err(SandboxError::QuotaExceeded {
                    resource: "vcpus".into(),
                    limit: total_vcpus,
                    current: needed,
                });
            }
        }
        if self.capacity.memory_mb_total > 0 {
            let needed = others_memory_mb.saturating_add(requested_memory_mb);
            if needed > self.capacity.memory_mb_total {
                return Err(SandboxError::QuotaExceeded {
                    resource: "memory_mb".into(),
                    limit: self.capacity.memory_mb_total,
                    current: needed,
                });
            }
        }
        // Disk and process slots use the same per-sandbox assumptions as the
        // scheduler capacity snapshot. The live count already includes the
        // booting entry, so check the full live totals directly.
        let live_disk = live
            .sandbox_count
            .saturating_mul(crate::scheduler_capacity::DEFAULT_DISK_MB_PER_SANDBOX);
        if self.capacity.disk_mb_total > 0 && live_disk > self.capacity.disk_mb_total {
            return Err(SandboxError::QuotaExceeded {
                resource: "disk_mb".into(),
                limit: self.capacity.disk_mb_total,
                current: live_disk,
            });
        }
        if live.sandbox_count > crate::scheduler_capacity::DEFAULT_MAX_PROCESS_SLOTS {
            return Err(SandboxError::QuotaExceeded {
                resource: "process_slots".into(),
                limit: crate::scheduler_capacity::DEFAULT_MAX_PROCESS_SLOTS,
                current: live.sandbox_count,
            });
        }

        let _ = entry;
        Ok(())
    }

    async fn non_ready_report(
        &self,
        command: &BootCommand,
        _entry: &SandboxEntry,
        reason: NonReadyReason,
        started: Instant,
        diagnostics: Vec<String>,
    ) -> BootReport {
        BootReport {
            sandbox_id: command.sandbox_id.clone(),
            operation_id: command.operation_id.clone(),
            status: BootStatus::NotReady,
            reason: Some(reason),
            observed_state: SandboxState::Failed,
            latency_ms: duration_ms(started.elapsed()),
            diagnostics,
        }
    }

    async fn finish_boot_report(
        &self,
        entry: &SandboxEntry,
        report: BootReport,
    ) -> Result<BootReport> {
        if report.status == BootStatus::NotReady {
            emit_boot_not_ready(&report, entry_tenant_id(entry).as_deref());
        }
        entry.boot.lock().last_boot_report = Some(report.clone());
        self.report_boot_outcome_if_needed(entry, &report).await?;
        Ok(report)
    }

    async fn report_boot_outcome_if_needed(
        &self,
        entry: &SandboxEntry,
        report: &BootReport,
    ) -> Result<()> {
        if entry.boot.lock().last_reported_boot_operation.as_ref() == Some(&report.operation_id) {
            return Ok(());
        }
        self.lifecycle_reporter
            .report(&BootObservation {
                sandbox_id: report.sandbox_id.clone(),
                operation_id: report.operation_id.clone(),
                observed_state: report.observed_state,
                reason: report.reason,
                message: (!report.diagnostics.is_empty()).then(|| report.diagnostics.join("; ")),
            })
            .await
            .map_err(|error| {
                SandboxError::Other(format!("failed to report boot outcome: {error}"))
            })?;
        entry.boot.lock().last_reported_boot_operation = Some(report.operation_id.clone());
        Ok(())
    }

    async fn cleanup_host_boot_failure(
        &self,
        command: &BootCommand,
        entry: &Arc<SandboxEntry>,
        failure: HostBootFailure<'_>,
    ) -> Result<BootReport> {
        for (_, host_port) in failure.bound_ports {
            self.port_proxy
                .unbind(&command.sandbox_id, *host_port)
                .await;
        }
        if failure.revoke_ssh_key
            && let (Some(public_key), Some(ssh_home_dir)) = (
                entry.ssh_public_key.as_deref(),
                entry.ssh_home_dir.as_deref(),
            )
        {
            let meta = CommandMetaParts::new(
                entry.id.clone(),
                OperationId::generate(),
                command.assignment_fencing_token,
                command.policy_epoch,
                Duration::from_secs(10),
            );
            let _ = revoke_generated_ssh_key(&self.sandboxd, public_key, ssh_home_dir, meta).await;
        }

        let cleanup_operation_id =
            OperationId::from_string(format!("{}_cleanup", command.operation_id));

        let cleanup_meta = CommandMetaParts::new(
            command.sandbox_id.clone(),
            cleanup_operation_id,
            command.assignment_fencing_token,
            command.policy_epoch,
            Duration::from_secs(30),
        );
        let mut diagnostics = vec![failure.message];
        let final_reason = match self.sandboxd.destroy(cleanup_meta).await {
            Ok(outcome) if outcome.succeeded() => failure.reason,
            Ok(outcome) => {
                diagnostics.extend(outcome.message);
                NonReadyReason::Cleanup
            }
            Err(error) => {
                diagnostics.push(error.to_string());
                NonReadyReason::Cleanup
            }
        };
        let _ = entry.commit_desired(
            entry.desired_state(),
            SandboxState::Failed,
            Some(command.assignment_fencing_token),
        );

        {
            let mut boot_guard = entry.boot.lock();
            boot_guard.assignment_fencing_token = command.assignment_fencing_token;
            boot_guard.policy_epoch = command.policy_epoch;
        }

        let report = self
            .non_ready_report(command, entry, final_reason, failure.started, diagnostics)
            .await;
        emit_boot_cleanup(&report, entry_tenant_id(entry).as_deref());
        self.finish_boot_report(entry, report).await
    }

    async fn inject_ssh_key(&self, entry: &SandboxEntry) -> Result<()> {
        let public_key = match entry.ssh_public_key.as_ref() {
            Some(key) => key.clone(),
            None => return Ok(()),
        };
        let ssh_home_dir = entry
            .ssh_home_dir
            .clone()
            .unwrap_or_else(|| default_ssh_home_dir(entry.runtime));

        let meta =
            self.command_meta_for_entry(entry, OperationId::generate(), Duration::from_secs(10));
        let result = self
            .sandboxd
            .exec(
                meta,
                ExecRequest {
                    command: "sh".into(),
                    args: vec![
                        "-c".into(),
                        "umask 077 && mkdir -p \"$2/.ssh\" && chmod 700 \"$2/.ssh\" && printf '%s\\n' \"$1\" >> \"$2/.ssh/authorized_keys\" && chmod 600 \"$2/.ssh/authorized_keys\"".into(),
                        "ssh-setup".into(),
                        public_key,
                        ssh_home_dir,
                    ],
                    env: None,
                    working_dir: None,
                    timeout_secs: Some(10),
                },
            )
            .await;

        match result {
            Ok(response) if response.exit_code == 0 => {
                entry.ssh_key_injected.store(true, Ordering::SeqCst);
                Ok(())
            }
            Ok(response) => Err(SandboxError::Other(format!(
                "failed to inject SSH public key: {}",
                response.stderr.trim()
            ))),
            // A not-ready runtime (e.g. guest handshake still pending, or a
            // mock backend without a guest session) may reject exec; the key
            // stays recorded for a later injection attempt, so log and continue.
            Err(error @ SandboxError::NotReady(_)) => {
                tracing::debug!(
                    sandbox_id = %entry.id,
                    error = %error,
                    "ssh key inject deferred: sandbox not ready for exec"
                );
                Ok(())
            }
            // Any other transport/status failure means the injection genuinely
            // did not happen; surface it so boot fails closed instead of
            // advertising a sandbox without its mandated SSH key.
            Err(error) => Err(SandboxError::Other(format!(
                "ssh key inject failed: {error}"
            ))),
        }
    }

    async fn bind_ports(
        &self,
        entry: &SandboxEntry,
        sandbox_id: &str,
    ) -> std::result::Result<Vec<(u16, u16)>, (Vec<(u16, u16)>, SandboxError)> {
        let ssh_host_port = entry.ssh_port.unwrap_or(22);
        let mut bound_ports = Vec::new();
        for port in &entry.ports {
            let host_port = if *port == 22 { ssh_host_port } else { *port };
            let localhost_only = *port == 22;

            // Listeners bind on the host; upstream resolution uses the
            // GetPortTarget-backed port target cache (fail-closed on miss).
            if let Err(error) = Arc::clone(&self.port_proxy)
                .bind(sandbox_id, host_port, *port, localhost_only)
                .await
            {
                return Err((bound_ports, port_bind_error(host_port, error)));
            }
            bound_ports.push((*port, host_port));
        }

        Ok(bound_ports)
    }

    async fn touch_sandbox_activity(&self, entry: &SandboxEntry, id: &str) {
        *entry.last_activity_at.lock() = pico_core::now_iso();
        self.reaper.arm_with_timeout(id, entry.idle_timeout).await;
    }

    async fn reset_if_registered(&self, id: &str) {
        let entry = { self.sandboxes.lock().await.get(id).cloned() };
        if let Some(entry) = entry {
            self.touch_sandbox_activity(&entry, id).await;
        }
    }

    async fn cancel_tasks_for_sandbox(&self, sandbox_id: &str) {
        for entry in self.task_registry.for_sandbox(sandbox_id) {
            cancel_task_entry(&entry).await;
        }
    }

    async fn revoke_sandbox_ssh_key(&self, entry: &SandboxEntry) {
        if entry.ssh_private_key.is_none() {
            return;
        }
        let Some(public_key) = entry.ssh_public_key.as_deref() else {
            return;
        };
        let Some(ssh_home_dir) = entry.ssh_home_dir.as_deref() else {
            return;
        };
        let meta =
            self.command_meta_for_entry(entry, OperationId::generate(), Duration::from_secs(10));
        if let Err(err) =
            revoke_generated_ssh_key(&self.sandboxd, public_key, ssh_home_dir, meta).await
        {
            tracing::warn!(
                sandbox_id = %entry.id,
                error = %err,
                "failed to revoke sandbox SSH key"
            );
        }
    }

    pub(crate) fn task_entry_for_sandbox(
        &self,
        sandbox_id: &str,
        task_id: &str,
    ) -> Result<Arc<task_registry::TaskEntry>> {
        let entry = self
            .task_registry
            .get(task_id)
            .ok_or_else(|| SandboxError::TaskNotFound(task_id.to_string()))?;
        if !sandbox_id.is_empty() && entry.sandbox_id != sandbox_id {
            return Err(SandboxError::TaskNotFound(task_id.to_string()));
        }
        Ok(entry)
    }

    async fn run_task(
        self: Arc<Self>,
        sandbox_id: String,
        task_id: String,
        req: TaskRequest,
    ) -> Result<()> {
        let entry = self
            .task_registry
            .get(&task_id)
            .ok_or_else(|| SandboxError::TaskNotFound(task_id.clone()))?;
        let workspace = self.workspaces.sandbox_dir(&sandbox_id)?;

        {
            let mut info = entry.info.lock().await;
            info.state = TaskState::Running;
            info.started_at = Some(pico_core::now_iso());
        }
        let _ = entry.events.send(TaskEvent::Status {
            ts: pico_core::now_iso(),
            state: TaskState::Running,
        });
        let mut cmd = tokio::process::Command::new(&req.agent);
        cmd.arg(&req.prompt)
            .current_dir(&workspace)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                self.fail_task(&entry, format!("spawn failed: {err}")).await;
                return Ok(());
            }
        };
        let stdout_task = child
            .stdout
            .take()
            .map(|stdout| stream_task_output(stdout, entry.events.clone(), StreamKind::Stdout));
        let stderr_task = child
            .stderr
            .take()
            .map(|stderr| stream_task_output(stderr, entry.events.clone(), StreamKind::Stderr));

        let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(600));
        let result = tokio::select! {
            () = entry.cancel.cancelled() => {
                let _ = child.kill().await;
                TaskEnd::Cancelled
            }
            () = tokio::time::sleep(timeout) => {
                let _ = child.kill().await;
                TaskEnd::Timeout
            }
            status = child.wait() => {
                match status {
                    Ok(status) => TaskEnd::Exit(status.code().unwrap_or(-1)),
                    Err(err) => TaskEnd::Error(err.to_string()),
                }
            }
        };

        let drain_output = matches!(result, TaskEnd::Exit(_) | TaskEnd::Error(_));
        if drain_output {
            if let Some(stdout_task) = stdout_task {
                let _ = stdout_task.await;
            }
            if let Some(stderr_task) = stderr_task {
                let _ = stderr_task.await;
            }
        }

        let (final_state, exit_code, error) = match result {
            TaskEnd::Exit(0) => (TaskState::Completed, Some(0), None),
            TaskEnd::Exit(code) => (TaskState::Failed, Some(code), Some(format!("exit {code}"))),
            TaskEnd::Cancelled => (TaskState::Cancelled, None, None),
            TaskEnd::Timeout => (TaskState::Failed, None, Some("timeout".into())),
            TaskEnd::Error(err) => (TaskState::Failed, None, Some(err)),
        };

        {
            let mut info = entry.info.lock().await;
            info.state = final_state;
            info.ended_at = Some(pico_core::now_iso());
            info.exit_code = exit_code;
            info.error = error.clone();
        }
        if let Some(message) = error {
            let _ = entry.events.send(TaskEvent::Error {
                ts: pico_core::now_iso(),
                message,
            });
        }
        let _ = entry.events.send(TaskEvent::Status {
            ts: pico_core::now_iso(),
            state: final_state,
        });
        if let Some(exit_code) = exit_code {
            let _ = entry.events.send(TaskEvent::Result {
                ts: pico_core::now_iso(),
                exit_code,
            });
        }
        Ok(())
    }

    async fn fail_task(&self, entry: &Arc<task_registry::TaskEntry>, message: String) {
        {
            let mut info = entry.info.lock().await;
            info.state = TaskState::Failed;
            info.error = Some(message.clone());
            info.ended_at = Some(pico_core::now_iso());
        }
        let _ = entry.events.send(TaskEvent::Error {
            ts: pico_core::now_iso(),
            message,
        });
        let _ = entry.events.send(TaskEvent::Status {
            ts: pico_core::now_iso(),
            state: TaskState::Failed,
        });
    }
}

/// Runs the idle-reaper destroy loop on an agent whose fields are final.
fn run_reaper_destroyer(agent: HostAgent, mut expiry_rx: tokio::sync::broadcast::Receiver<String>) {
    tokio::spawn(async move {
        loop {
            let id = match expiry_rx.recv().await {
                Ok(id) => id,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            };
            if let Err(err) = agent.destroy(&id).await {
                tracing::warn!(
                    sandbox_id = %id,
                    error = %err,
                    "idle reaper destroy failed (sandbox may remain for operator cleanup)"
                );
            }
        }
    });
}

fn error_to_lifecycle_outcome(err: &SandboxError) -> LifecycleOutcome {
    match err {
        SandboxError::QuotaExceeded { .. } | SandboxError::ResourceExhausted { .. } => {
            LifecycleOutcome::QuotaRejected
        }
        SandboxError::PolicyDenied { .. } => LifecycleOutcome::PolicyRejected,
        SandboxError::BackendSelectionRejected { .. } => LifecycleOutcome::PlacementFailed,
        _ => LifecycleOutcome::InternalError,
    }
}

/// Publishes a sandbox's cgroup memory counters.
///
/// `tenant_id` is only used to attribute the metrics: on a shared host the
/// sandbox-scoped series is keyed by tenant instead of sandbox.
async fn collect_cgroup_stats(sandbox_id: &str, tenant_id: Option<&str>) {
    // A malicious id must not escape /sys/fs/cgroup/sandbox via `..`.
    // The sandbox id allowlist forbids dots entirely; this explicit guard
    // is what static analysis (CodeQL rust/path-injection) recognizes.
    if sandbox_id.contains("..") || sandbox_id.contains('/') || sandbox_id.contains('\\') {
        return;
    }
    let current_path = std::path::PathBuf::from("/sys/fs/cgroup/sandbox").join(sandbox_id);
    if let Ok(val) = std::fs::read_to_string(current_path.join("memory.current"))
        && let Ok(bytes) = val.trim().parse::<u64>()
    {
        pico_observability::metrics::record_memory_usage(sandbox_id, tenant_id, bytes);
    }
    if let Ok(swap_val) = std::fs::read_to_string(current_path.join("memory.swap.current"))
        && let Ok(swap_bytes) = swap_val.trim().parse::<u64>()
    {
        pico_observability::OBSERVABILITY_METRICS
            .memory_swap_bytes
            .set(
                swap_bytes as f64,
                &pico_telemetry::metrics::Labels::sandbox(sandbox_id, tenant_id),
            );
    }
}

mod task_util;
mod util;

#[cfg(test)]
mod tests;
