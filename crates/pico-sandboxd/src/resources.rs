//! Host resource materialization owned by `sandboxd`.
//!
//! Workspace directories, cgroup v2 hierarchies, and CPU pinning allocations
//! are created during [`SandboxSupervisor::prepare`] and torn down during
//! [`SandboxSupervisor::destroy`]. Each materialized resource produces a
//! durable ledger receipt so the garbage collector can reconcile resources
//! after crashes or missed cleanup.
//!
//! # Ownership boundary
//!
//! [`HostResourceManager`] is the **sole writer** of host workspace lifecycle
//! (`ensure`/`delete`), cgroup hierarchy lifecycle (`setup`/`setup_cpuset`/
//! `cleanup`/`add_process`), and CPU pinning allocation (`allocate`/`release`/
//! `restore`). Callers inside `sandboxd` (supervisor prepare/destroy, process
//! attach, garbage collector orphan cleanup) must go through this type rather
//! than constructing `WorkspaceManager`/`CgroupManager`/`CpuAllocator` for
//! mutation.
//!
//! Read-only access is intentionally outside this path:
//! - cgroup identity (`cgroup_id`, path) and pressure/stats file reads
//! - host-agent path resolution for file/task I/O against an already
//!   materialized workspace (no `ensure`/`delete` on production paths)
//! - runtime adapters applying `sched_setaffinity` from a `cpu_set` that was
//!   allocated here (affinity only; never allocation)
//!
//! CPU allocations are durably recorded as `cpu` class receipts alongside the
//! workspace and cgroup receipts. During supervisor init the allocator is
//! rebuilt from the present `cpu` receipts, so a restarted daemon cannot
//! overcommit dedicated cores that were allocated before the restart.
//!
//! Concurrency: the manager clones cheaply and shares one in-memory CPU
//! allocator behind a `parking_lot::Mutex`; allocation is a short synchronous
//! computation, so the lock is never held across an `.await`. The workspace
//! manager initializes lazily behind a `tokio::sync::OnceCell`.
//!
//! [`SandboxSupervisor::prepare`]: crate::SandboxSupervisor::prepare
//! [`SandboxSupervisor::destroy`]: crate::SandboxSupervisor::destroy

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use pico_core::cgroups::{CgroupManager, DEFAULT_MAX_PIDS, default_soft_limit_bytes};
use pico_core::cpu_isolation::{CpuAllocator, CpuIsolationPolicy, CpuSet, CpuTopology};
use pico_core::workspace::WorkspaceManager;
use pico_core::{CORE_METRICS, CleanupReport, ResourceReceipt, SandboxConfig};
use pico_telemetry::metrics::Labels;
use serde::{Deserialize, Serialize};

use crate::gc::ResourceClass;
use crate::ledger::CpuReceiptRow;

/// Default memory size in MiB used when neither the runtime config nor the
/// host resource spec carries a value.
const DEFAULT_MEMORY_MB: u64 = 512;

/// Per-prepare host resource inputs coordinated by `sandboxd`.
///
/// Zero-valued numeric fields derive from the runtime [`SandboxConfig`], so
/// callers that already computed a full config can pass
/// [`HostResourceSpec::default`].
///
/// Image, SSH, and idle fields are retained for handshake validation and
/// observation (image/SSH/idle evidence wired through prepare); CPU/memory/ports drive allocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostResourceSpec {
    /// Virtual CPUs to allocate (0 derives from the config CPU shares).
    pub vcpus: u32,
    /// Memory size in MiB requested for the sandbox (0 derives the memory
    /// limit and soft limit from the config values only).
    pub memory_mb: u64,
    /// Guest ports the host intends to proxy or query via GetPortTarget.
    pub requested_ports: Vec<u16>,
    /// Owning tenant for cross-tenant CPU allocation checks.
    pub tenant_id: Option<String>,
    /// Whether the host mixes tenants. CPU allocation failures become fatal
    /// on cross-tenant hosts that require pinning. The daemon-level
    /// [`HostResourceConfig`] flag always wins over this per-request input.
    pub cross_tenant_host: bool,
    /// Optional idle timeout hint (seconds). Enforced by host-agent reaper;
    /// retained here for audit and future sandboxd enforcement.
    pub idle_timeout_secs: Option<u64>,
    /// Optional image id for guest handshake validation.
    pub image_id: Option<String>,
    /// Optional image digest. Retained for audit; not yet enforced by
    /// handshake validation (only image id is compared).
    pub image_digest: Option<String>,
    /// Optional SSH public key for observation and audit.
    pub ssh_public_key: Option<String>,
    /// Optional SSH key type (e.g. ed25519).
    pub ssh_key_type: Option<String>,
}

/// Static host resource configuration selected at `sandboxd` start.
#[derive(Debug, Clone)]
pub struct HostResourceConfig {
    /// Root directory under which per-sandbox workspaces are created.
    pub workspace_root: PathBuf,
    /// CPU isolation policy enforced for every prepare.
    pub cpu_isolation_policy: CpuIsolationPolicy,
    /// Whether this host mixes tenants. When true, CPU allocation failures
    /// hard-fail prepares regardless of the per-request flag.
    pub cross_tenant_host: bool,
}

impl HostResourceConfig {
    /// Creates a host resource configuration with the given workspace root.
    #[must_use]
    pub fn new(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            cpu_isolation_policy: CpuIsolationPolicy::None,
            cross_tenant_host: false,
        }
    }

    /// Sets the CPU isolation policy enforced at prepare time.
    #[must_use]
    pub fn with_cpu_isolation_policy(mut self, policy: CpuIsolationPolicy) -> Self {
        self.cpu_isolation_policy = policy;
        self
    }

    /// Marks this host as tenant-shared so pinning allocation failures
    /// hard-fail every prepare.
    #[must_use]
    pub fn with_cross_tenant_host(mut self, cross_tenant_host: bool) -> Self {
        self.cross_tenant_host = cross_tenant_host;
        self
    }
}

/// Failure of host materialization after best-effort rollback.
pub(crate) struct HostResourceError {
    /// Redacted failure detail suitable for outcome messages.
    pub message: String,
    /// Cleanup evidence produced by rolling back partially created resources.
    pub rollback: CleanupReport,
    /// Receipts for resources that were actually created before the failure,
    /// so leftovers remain visible in the ledger.
    pub created: Vec<ResourceReceipt>,
}

struct HostResourceInner {
    workspaces: tokio::sync::OnceCell<WorkspaceManager>,
    workspace_root: PathBuf,
    cpu_allocator: Mutex<CpuAllocator>,
    cross_tenant_host: bool,
}

/// Owns workspace, cgroup, and CPU allocation resources across prepares.
#[derive(Clone)]
pub(crate) struct HostResourceManager {
    inner: Arc<HostResourceInner>,
}

impl HostResourceManager {
    pub(crate) fn new(config: HostResourceConfig) -> Self {
        let topology = CpuTopology::detect();
        if config.cpu_isolation_policy.requires_pinning() {
            let physical_cores = topology.physical_cores.len();
            if physical_cores < 4 {
                tracing::warn!(
                    policy = ?config.cpu_isolation_policy,
                    physical_cores = physical_cores,
                    total_cpus = topology.total_logical_cpus,
                    "strict CPU isolation enabled on a host with fewer than 4 physical cores; \
                     cross-tenant isolation may be weak"
                );
            }
            if config.cpu_isolation_policy.requires_smt_exclusion()
                && topology.physical_cores.iter().all(|c| !c.has_smt())
                && topology.total_logical_cpus > 1
            {
                tracing::info!(
                    "SMT exclusion enabled but no SMT siblings detected; \
                     dedicated-core isolation is still enforced"
                );
            }
        }
        Self {
            inner: Arc::new(HostResourceInner {
                workspaces: tokio::sync::OnceCell::new(),
                workspace_root: config.workspace_root,
                cpu_allocator: Mutex::new(CpuAllocator::new(topology, config.cpu_isolation_policy)),
                cross_tenant_host: config.cross_tenant_host,
            }),
        }
    }

    /// Workspace root shared with the garbage collector.
    pub(crate) fn workspace_root(&self) -> &PathBuf {
        &self.inner.workspace_root
    }

    /// Lazily initializes the workspace manager so opening a supervisor does
    /// not create directories until the first lifecycle operation.
    pub(crate) async fn workspaces(&self) -> Result<&WorkspaceManager, String> {
        self.inner
            .workspaces
            .get_or_try_init(|| async {
                WorkspaceManager::new(self.inner.workspace_root.clone()).map_err(|err| {
                    format!(
                        "failed to initialize workspace root {}: {err}",
                        self.inner.workspace_root.display()
                    )
                })
            })
            .await
    }

    /// Materializes workspace, CPU allocation, and cgroup for one sandbox and
    /// fills any unset resource fields of `config` in place.
    ///
    /// On success the returned receipts prove every created host resource. On
    /// failure all partially created resources are rolled back and the error
    /// carries both the rollback evidence and the receipts for resources that
    /// were actually created, so leftovers stay visible in the ledger.
    pub(crate) fn materialize(
        &self,
        workspaces: &WorkspaceManager,
        config: &mut SandboxConfig,
        host: &HostResourceSpec,
    ) -> Result<Vec<ResourceReceipt>, HostResourceError> {
        let sandbox_id = config.id.clone();

        let workspace_dir = match workspaces.ensure(&sandbox_id) {
            Ok(dir) => dir,
            Err(err) => {
                return Err(HostResourceError {
                    message: format!("workspace ensure failed for {sandbox_id}: {err}"),
                    rollback: CleanupReport::default(),
                    created: Vec::new(),
                });
            }
        };
        let mut created = vec![ResourceReceipt {
            class: ResourceClass::Workspace.as_str().to_string(),
            name: workspace_receipt_name(&sandbox_id),
            external_id: Some(workspace_dir.display().to_string()),
        }];

        fill_config_gaps(config, host);

        let tenant_id = host
            .tenant_id
            .clone()
            .unwrap_or_else(|| format!("default-{sandbox_id}"));
        let vcpu_count = if host.vcpus > 0 {
            host.vcpus
        } else {
            (config.cpu_shares / 100).max(1)
        };
        let (policy, allocation) = {
            let mut allocator = self.inner.cpu_allocator.lock();
            let policy = allocator.policy();
            let allocation = allocator.allocate(&sandbox_id, &tenant_id, None, vcpu_count);
            (policy, allocation)
        };
        match allocation {
            Ok(set) => {
                config.cpu_set = Some(set.as_slice().to_vec());
                if policy.requires_pinning() {
                    // Only strict hosts need durable overcommit protection:
                    // without pinning there is no cross-tenant isolation
                    // contract to preserve across a restart.
                    let external_id = match encode_cpu_receipt(&tenant_id, &set) {
                        Ok(external_id) => external_id,
                        Err(message) => {
                            // A missing receipt silently defeats the durability
                            // contract of strict hosts, so fail and roll back
                            // instead of proceeding without it.
                            return Err(HostResourceError {
                                message: format!(
                                    "failed to encode cpu receipt for {sandbox_id}: {message}"
                                ),
                                rollback: self.teardown(workspaces, &sandbox_id),
                                created,
                            });
                        }
                    };
                    created.push(ResourceReceipt {
                        class: ResourceClass::Cpu.as_str().to_string(),
                        name: cpu_receipt_name(&sandbox_id),
                        external_id: Some(external_id),
                    });
                }
            }
            Err(err) => {
                let cross_tenant = self.inner.cross_tenant_host || host.cross_tenant_host;
                if cross_tenant && policy.requires_pinning() {
                    return Err(HostResourceError {
                        message: format!(
                            "CPU pinning required for cross-tenant host (policy {policy:?}) \
                             but allocation failed for sandbox {sandbox_id}: {err}"
                        ),
                        rollback: self.teardown(workspaces, &sandbox_id),
                        created,
                    });
                }
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "failed to allocate CPU set; proceeding without CPU pinning"
                );
            }
        }

        let cgroup = match CgroupManager::new(&sandbox_id) {
            Ok(cgroup) => cgroup,
            Err(err) => {
                return Err(HostResourceError {
                    message: format!("invalid cgroup id for {sandbox_id}: {err}"),
                    rollback: self.teardown(workspaces, &sandbox_id),
                    created,
                });
            }
        };
        if let Err(err) = cgroup.setup(
            config.memory_limit_bytes,
            config.memory_soft_limit_bytes,
            config.cpu_shares,
            config.cpu_bandwidth,
            config.max_pids,
            &config.io_limits,
        ) {
            return Err(HostResourceError {
                message: format!("cgroup setup failed for {sandbox_id}: {err}"),
                rollback: self.teardown(workspaces, &sandbox_id),
                created,
            });
        }
        created.push(ResourceReceipt {
            class: ResourceClass::Cgroup.as_str().to_string(),
            name: cgroup_receipt_name(&sandbox_id),
            external_id: cgroup.cgroup_id().map(|id| id.to_string()),
        });

        if let Some(ref cpus) = config.cpu_set
            && let Err(err) = cgroup.setup_cpuset(cpus)
        {
            if policy.requires_pinning() {
                // A missing cpuset silently weakens the isolation contract on
                // strict hosts, so fail and roll back instead of proceeding.
                return Err(HostResourceError {
                    message: format!(
                        "cpuset setup failed for {sandbox_id} while policy {policy:?} \
                         requires pinning: {err}"
                    ),
                    rollback: self.teardown(workspaces, &sandbox_id),
                    created,
                });
            }
            tracing::warn!(
                sandbox_id = %sandbox_id,
                error = %err,
                "failed to set CPU pinning via cgroup cpuset"
            );
        }

        Ok(created)
    }

    /// Tears down every host resource owned by one sandbox.
    ///
    /// CPU allocations are released in memory without a receipt; cgroup and
    /// workspace removals produce deterministic names in the report so the
    /// supervisor can mark the matching ledger receipts released or flag the
    /// leftovers for review.
    ///
    /// Cgroup and workspace deletion already apply a bounded transient retry
    /// (EBUSY/ENOTEMPTY while processes drain). Only leftovers that still
    /// remain after that budget are reported as `remaining` and escalate to
    /// `requires_review`.
    pub(crate) fn teardown(
        &self,
        workspaces: &WorkspaceManager,
        sandbox_id: &str,
    ) -> CleanupReport {
        let mut report = CleanupReport::default();
        match self.cleanup_cgroup(sandbox_id) {
            Ok(()) => report.released.push(cgroup_receipt_name(sandbox_id)),
            Err(err) => {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "cgroup cleanup failed after transient retries; \
                     receipt stays present for GC or operator review"
                );
                report.remaining.push(cgroup_receipt_name(sandbox_id));
            }
        }
        // Prefer the caller-provided manager (already initialized during
        // prepare) so teardown does not re-open the workspace root.
        match workspaces.delete(sandbox_id) {
            Ok(()) => report.released.push(workspace_receipt_name(sandbox_id)),
            Err(err) => {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "workspace cleanup failed after transient retries; \
                     receipt stays present for GC or operator review"
                );
                report.remaining.push(workspace_receipt_name(sandbox_id));
            }
        }
        {
            let mut allocator = self.inner.cpu_allocator.lock();
            let policy = allocator.policy();
            allocator.release(sandbox_id);
            // Only strict hosts write durable cpu receipts, so only they
            // have a receipt name worth reporting for release.
            if policy.requires_pinning() {
                report.released.push(cpu_receipt_name(sandbox_id));
            }
        }
        report
    }

    /// Async variant of [`HostResourceManager::teardown`] for supervisor and
    /// GC call sites: transient retries sleep between attempts, so the work
    /// runs on the blocking pool instead of stalling an async worker.
    ///
    /// If the blocking task itself fails (panic or shutdown), every host
    /// resource is reported as `remaining` so the caller escalates to
    /// review instead of dropping receipts for unknown state.
    pub(crate) async fn teardown_async(
        &self,
        workspaces: &WorkspaceManager,
        sandbox_id: &str,
    ) -> CleanupReport {
        let policy = self.cpu_isolation_policy();
        let this = self.clone();
        let workspaces = workspaces.clone();
        let sandbox_id = sandbox_id.to_string();
        let task_id = sandbox_id.clone();
        match tokio::task::spawn_blocking(move || this.teardown(&workspaces, &task_id)).await {
            Ok(report) => report,
            Err(err) => {
                tracing::error!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "teardown worker failed; flagging host resources as remaining for review"
                );
                let mut report = CleanupReport::default();
                report.remaining.push(cgroup_receipt_name(&sandbox_id));
                report.remaining.push(workspace_receipt_name(&sandbox_id));
                if policy.requires_pinning() {
                    report.remaining.push(cpu_receipt_name(&sandbox_id));
                }
                report
            }
        }
    }

    /// Rebuilds CPU allocation state from durable receipts after a restart.
    ///
    /// Present `cpu` receipts are trusted as proven allocations: each sandbox
    /// gets its tenant and CPU set restored without revalidation, so a fresh
    /// daemon refuses to overcommit the cores it allocated before restarting.
    /// Receipts that fail to parse or reference CPUs outside the host topology
    /// fail closed: nothing is restored for them, the operator is alerted, and
    /// the receipt stays in the ledger so the garbage collector routes it to
    /// review instead of deleting the evidence.
    ///
    /// The host topology is assumed stable across restarts of one daemon.
    /// SMT sibling relationships are not revalidated per restored set, but
    /// cross-tenant SMT violations introduced by a topology change (BIOS
    /// toggle, CPU hot-unplug, failover) are detected after the rebuild and
    /// reported as a warning instead of failing the restore.
    pub(crate) fn restore_cpu_allocations(&self, receipts: &[CpuReceiptRow]) {
        let mut allocator = self.inner.cpu_allocator.lock();
        let mut restored = 0u32;
        let mut skipped = 0u32;
        for row in receipts {
            let record = match parse_cpu_receipt(row) {
                Ok(record) => record,
                Err(message) => {
                    skipped += 1;
                    tracing::error!(
                        sandbox_id = %row.sandbox_id,
                        error = %message,
                        "skipping unparsable CPU receipt during allocator rebuild; \
                         receipt kept in ledger for operator review"
                    );
                    continue;
                }
            };
            match allocator.restore(&record.sandbox_id, &record.tenant_id, record.cpu_set) {
                Ok(()) => restored += 1,
                Err(message) => {
                    skipped += 1;
                    tracing::error!(
                        sandbox_id = %record.sandbox_id,
                        error = %message,
                        "rejecting CPU receipt during allocator rebuild; \
                         receipt kept in ledger for operator review"
                    );
                }
            }
        }
        if restored > 0 {
            tracing::info!(
                restored_allocations = restored,
                "rebuilt CPU allocator from durable receipts"
            );
        }
        let violations = allocator.validate_cross_tenant_smt();
        if !violations.is_empty() {
            let detail: Vec<String> = violations.iter().map(ToString::to_string).collect();
            tracing::warn!(
                count = violations.len(),
                violations = %detail.join("; "),
                "restored CPU allocations violate SMT exclusion under the current topology; \
                 host topology likely changed since these allocations were made"
            );
        }
        let labels = Labels::host();
        CORE_METRICS
            .cpu_receipts_restored
            .inc_by(u64::from(restored), &labels);
        CORE_METRICS
            .cpu_receipts_skipped
            .inc_by(u64::from(skipped), &labels);
    }

    /// Returns the CPU isolation policy enforced on this host.
    pub(crate) fn cpu_isolation_policy(&self) -> CpuIsolationPolicy {
        self.inner.cpu_allocator.lock().policy()
    }

    /// Attaches a running process to the sandbox cgroup v2 hierarchy.
    ///
    /// Best-effort: failures are logged and not propagated. Attachment is a
    /// hardening measure; the process still runs if the write fails (for
    /// example when the cgroup was already torn down).
    pub(crate) fn attach_process(&self, sandbox_id: &str, pid: u32) {
        let cgroup = match CgroupManager::new(sandbox_id) {
            Ok(cgroup) => cgroup,
            Err(err) => {
                tracing::warn!(
                    pid = pid,
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "invalid cgroup id, skipping process attachment"
                );
                return;
            }
        };
        // Skip silently when the hierarchy is already gone (teardown raced
        // exec); avoid string-matching io errors to classify NotFound.
        if !cgroup.exists() {
            tracing::debug!(
                pid = pid,
                sandbox_id = %sandbox_id,
                "cgroup absent, skipping process attachment"
            );
            return;
        }
        if let Err(err) = cgroup.add_process(pid) {
            tracing::warn!(
                pid = pid,
                sandbox_id = %sandbox_id,
                error = %err,
                "failed to attach process to cgroup"
            );
        }
    }

    /// Removes a sandbox workspace directory (destroy teardown and orphan GC).
    ///
    /// Absent directories are treated as success so retries stay idempotent.
    /// Prefer the cached manager when prepare has already initialized it;
    /// otherwise open a one-shot handle on the shared root (GC cold path).
    /// The cold path creates the workspace root if missing as a side effect
    /// of `WorkspaceManager::new`; acceptable because prepare ensures the
    /// root on any host that has run a sandbox.
    pub(crate) fn delete_workspace_dir(&self, sandbox_id: &str) -> Result<(), String> {
        if let Some(workspaces) = self.inner.workspaces.get() {
            return workspaces
                .delete(sandbox_id)
                .map_err(|err| format!("failed to remove workspace {sandbox_id}: {err}"));
        }
        let workspaces =
            WorkspaceManager::new(self.inner.workspace_root.clone()).map_err(|err| {
                format!(
                    "failed to open workspace root {}: {err}",
                    self.inner.workspace_root.display()
                )
            })?;
        workspaces
            .delete(sandbox_id)
            .map_err(|err| format!("failed to remove workspace {sandbox_id}: {err}"))
    }

    /// Removes a sandbox cgroup v2 tree (destroy teardown and orphan GC).
    ///
    /// Uses the full tree walk from [`CgroupManager::cleanup`] so nested
    /// controller directories are removed, not only the leaf directory.
    pub(crate) fn cleanup_cgroup(&self, sandbox_id: &str) -> Result<(), String> {
        CgroupManager::new(sandbox_id)
            .map_err(|err| format!("invalid cgroup id {sandbox_id}: {err}"))?
            .cleanup()
            .map_err(|err| format!("failed to remove cgroup {sandbox_id}: {err}"))
    }
}

/// Deterministic receipt name for the workspace resource of one sandbox.
///
/// Names are class-prefixed so ledger release statements keyed by name never
/// confuse the workspace and cgroup receipts of the same sandbox.
pub(crate) fn workspace_receipt_name(sandbox_id: &str) -> String {
    format!("workspace/{sandbox_id}")
}

/// Deterministic receipt name for the cgroup resource of one sandbox.
pub(crate) fn cgroup_receipt_name(sandbox_id: &str) -> String {
    format!("cgroup/{sandbox_id}")
}

/// Deterministic receipt name for the CPU allocation of one sandbox.
pub(crate) fn cpu_receipt_name(sandbox_id: &str) -> String {
    format!("cpu/{sandbox_id}")
}

/// Current version of the CPU receipt payload schema.
///
/// Bump on breaking shape changes; parsers reject unknown versions so the
/// receipt fails closed into operator review instead of mis-restoring.
const CPU_RECEIPT_VERSION: u32 = 1;

/// Durable payload of a CPU allocation receipt.
///
/// Stored in the receipt's `external_id` so a restarted daemon can rebuild
/// the allocator with the exact tenant ownership and CPU set that were
/// allocated before the restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CpuAllocationRecord {
    /// Payload schema version; must equal [`CPU_RECEIPT_VERSION`].
    version: u32,
    /// Tenant that owns the allocation.
    tenant_id: String,
    /// Logical CPU indices allocated to the sandbox.
    cpus: Vec<u32>,
}

/// A CPU allocation parsed from a durable receipt row.
pub(crate) struct ParsedCpuReceipt {
    sandbox_id: String,
    tenant_id: String,
    cpu_set: CpuSet,
}

/// Serializes a CPU allocation for storage on a receipt.
fn encode_cpu_receipt(tenant_id: &str, cpu_set: &CpuSet) -> Result<String, String> {
    serde_json::to_string(&CpuAllocationRecord {
        version: CPU_RECEIPT_VERSION,
        tenant_id: tenant_id.to_string(),
        cpus: cpu_set.as_slice().to_vec(),
    })
    .map_err(|err| format!("cannot serialize cpu receipt payload: {err}"))
}

/// Parses a CPU allocation back from a durable receipt row.
///
/// Used by the allocator rebuild and by the garbage collector to decide
/// whether a cpu receipt can be auto-removed or needs operator review.
pub(crate) fn parse_cpu_receipt(row: &CpuReceiptRow) -> Result<ParsedCpuReceipt, String> {
    let external_id = row
        .external_id
        .as_deref()
        .ok_or_else(|| "cpu receipt has no external id".to_string())?;
    let record: CpuAllocationRecord = serde_json::from_str(external_id)
        .map_err(|err| format!("cannot parse cpu receipt payload: {err}"))?;
    if record.version != CPU_RECEIPT_VERSION {
        return Err(format!(
            "unsupported cpu receipt payload version {} (expected {CPU_RECEIPT_VERSION})",
            record.version
        ));
    }
    let cpu_set = CpuSet::new(record.cpus)
        .ok_or_else(|| "cpu receipt encodes an empty CPU set".to_string())?;
    Ok(ParsedCpuReceipt {
        sandbox_id: row.sandbox_id.clone(),
        tenant_id: record.tenant_id,
        cpu_set,
    })
}

/// Fills unset resource fields of `config` from the host resource spec while
/// preferring explicit config values. The memory soft limit is only derived
/// when the caller requested an explicit memory size.
fn fill_config_gaps(config: &mut SandboxConfig, host: &HostResourceSpec) {
    if config.memory_limit_bytes == 0 {
        let memory_mb = if host.memory_mb > 0 {
            host.memory_mb
        } else {
            DEFAULT_MEMORY_MB
        };
        config.memory_limit_bytes = memory_mb.saturating_mul(1024 * 1024);
    }
    if config.cpu_shares == 0 {
        config.cpu_shares = host.vcpus.max(1).saturating_mul(100);
    }
    if config.memory_soft_limit_bytes.is_none() && host.memory_mb > 0 {
        config.memory_soft_limit_bytes = Some(default_soft_limit_bytes(host.memory_mb));
    }
    if config.max_pids.is_none() {
        config.max_pids = Some(DEFAULT_MAX_PIDS);
    }
}
