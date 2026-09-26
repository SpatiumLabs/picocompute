//! Host-level garbage collection for orphaned and leaked runtime resources.
//!
//! The garbage collector runs as a periodic background worker. It scans the
//! durable sandboxd ledger for sandboxes with remaining resources, detects
//! orphaned host-level artifacts (workspace directories, cgroups, etc.), and
//! attempts safe cleanup or flags findings for operator review.
//!
//! Cleanup decisions are idempotent and restart-safe. Findings are persisted
//! in the reconciliation_findings table so operator review is available across
//! host-agent restarts.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::ledger::{CpuReceiptRow, GcScanRow, Ledger};
use crate::resources::{HostResourceManager, parse_cpu_receipt};
use crate::supervisor::SupervisorError;
use pico_core::{CORE_METRICS, validate_sandbox_id};
use pico_telemetry::metrics::Labels;

/// Default interval between garbage collection scans.
pub(crate) const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(300);

/// Default scan deadline before the pass is abandoned.
const GC_SCAN_DEADLINE: Duration = Duration::from_secs(120);

/// Base path for sandbox cgroup v2 hierarchies.
pub(crate) const DEFAULT_CGROUP_SANDBOX_BASE: &str = "/sys/fs/cgroup/sandbox";

/// Stable resource classes tracked by the garbage collector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Workspace directories under the agent root.
    Workspace,
    /// Linux cgroup v2 hierarchies.
    Cgroup,
    /// CPU pinning allocations tracked in memory by `sandboxd`.
    Cpu,
    /// Host processes or process trees owned by a sandbox.
    Process,
    /// Mount points, overlays, or bind mounts.
    Mount,
    /// TAP/veth network devices.
    NetworkDevice,
    /// Unix domain sockets.
    Uds,
    /// Vsock sockets.
    Vsock,
    /// Temporary snapshot or image files.
    TempFile,
    /// A resource class not predefined here.
    Other,
}

impl ResourceClass {
    /// Returns the class as a stable string for persistence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Cgroup => "cgroup",
            Self::Cpu => "cpu",
            Self::Process => "process",
            Self::Mount => "mount",
            Self::NetworkDevice => "network_device",
            Self::Uds => "uds",
            Self::Vsock => "vsock",
            Self::TempFile => "temp_file",
            Self::Other => "other",
        }
    }

    /// Parses a resource class from its stable string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "workspace" => Self::Workspace,
            "cgroup" => Self::Cgroup,
            "cpu" => Self::Cpu,
            "process" => Self::Process,
            "mount" => Self::Mount,
            "network_device" => Self::NetworkDevice,
            "uds" => Self::Uds,
            "vsock" => Self::Vsock,
            "temp_file" => Self::TempFile,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// A single resource finding produced during a garbage collection scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrphanFinding {
    /// Sandbox identity, if known.
    pub sandbox_id: Option<String>,
    /// Resource class.
    pub resource_class: ResourceClass,
    /// Deterministic resource name or path.
    pub resource_name: String,
    /// Evidence describing why this resource appears orphaned.
    pub evidence: String,
    /// Whether the resource can be safely removed.
    pub safe_to_remove: bool,
}

/// Classification of a GC action taken or recommended.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GcAction {
    /// Resource was successfully removed.
    Removed,
    /// Resource could not be removed safely and requires operator review.
    RequiresReview,
    /// Resource appeared during a previous scan and still exists.
    Confirmed,
    /// Resource was already absent.
    AlreadyAbsent,
}

impl GcAction {
    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::RequiresReview => "requires_review",
            Self::Confirmed => "confirmed",
            Self::AlreadyAbsent => "already_absent",
        }
    }

    #[cfg(test)]
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "removed" => Self::Removed,
            "requires_review" => Self::RequiresReview,
            "confirmed" => Self::Confirmed,
            "already_absent" => Self::AlreadyAbsent,
            _ => return None,
        })
    }
}

/// Summary statistics for one garbage collection pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcStats {
    /// Number of resource receipts scanned.
    pub receipts_scanned: u64,
    /// Resources confirmed present but already tracked.
    pub confirmed: u64,
    /// Resources removed during this pass.
    pub removed: u64,
    /// Resources that require operator review.
    pub review_required: u64,
    /// Resources whose cleanup failed for transient reasons.
    pub cleanup_failed: u64,
    /// Duration of the scan pass in milliseconds.
    pub scan_duration_ms: u64,
    /// Timestamp when the pass completed.
    pub completed_at: String,
}

/// Outcome of a single cleanup attempt.
#[derive(Debug, Clone)]
struct CleanupOutcome {
    pub finding: OrphanFinding,
    pub action: GcAction,
    pub error: Option<String>,
}

/// Host-level background garbage collector.
///
/// Cloning shares the same inner state, enabling safe concurrent health
/// queries while the background worker owns the scan loop.
///
/// Orphan workspace and cgroup removal is delegated to
/// [`HostResourceManager`] so GC is not a second mutator of those trees.
/// CPU allocator rebuild remains init-time only; GC only marks
/// durable `cpu` receipts absent after a destroyed sandbox is proven gone.
#[derive(Clone)]
pub struct GarbageCollector {
    ledger: Ledger,
    host_resources: HostResourceManager,
    workspace_root: Arc<PathBuf>,
    cgroup_base_path: Arc<PathBuf>,
    scan_interval: Duration,
    enabled: Arc<AtomicBool>,
    last_stats: Arc<tokio::sync::RwLock<GcStats>>,
}

impl GarbageCollector {
    /// Creates a new garbage collector.
    ///
    /// The collector does not start scanning until [`GarbageCollector::run`]
    /// is called. Workspace root for orphan scans is taken from
    /// `host_resources`.
    #[must_use]
    pub(crate) fn new(
        ledger: Ledger,
        host_resources: HostResourceManager,
        scan_interval: Duration,
    ) -> Self {
        let workspace_root = host_resources.workspace_root().clone();
        Self {
            ledger,
            host_resources,
            workspace_root: Arc::new(workspace_root),
            cgroup_base_path: Arc::new(PathBuf::from(DEFAULT_CGROUP_SANDBOX_BASE)),
            scan_interval,
            enabled: Arc::new(AtomicBool::new(true)),
            last_stats: Arc::new(tokio::sync::RwLock::new(GcStats::default())),
        }
    }

    /// Disables future garbage collection scans.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Returns the most recent scan statistics.
    pub async fn stats(&self) -> GcStats {
        self.last_stats.read().await.clone()
    }

    /// Runs the garbage collection loop until disabled.
    ///
    /// This method never returns unless all scans fail or the collector is
    /// disabled. Callers should spawn it in a background task.
    pub async fn run(&self) {
        info!(
            interval_secs = self.scan_interval.as_secs(),
            "starting host garbage collector"
        );
        let mut interval = tokio::time::interval(self.scan_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if !self.enabled.load(Ordering::Relaxed) {
                info!("garbage collector disabled, stopping scan loop");
                break;
            }
            let started = Instant::now();
            match tokio::time::timeout(GC_SCAN_DEADLINE, self.scan_pass()).await {
                Ok(Ok(stats)) => {
                    let elapsed = started.elapsed();
                    info!(
                        receipts_scanned = stats.receipts_scanned,
                        removed = stats.removed,
                        review_required = stats.review_required,
                        cleanup_failed = stats.cleanup_failed,
                        duration_ms = elapsed.as_millis(),
                        "garbage collection pass completed"
                    );
                    *self.last_stats.write().await = stats;
                }
                Ok(Err(error)) => {
                    error!(
                        error = %error,
                        "garbage collection scan failed, retrying on next interval"
                    );
                }
                Err(_elapsed) => {
                    warn!(
                        "garbage collection scan timed out after {:?}",
                        GC_SCAN_DEADLINE
                    );
                }
            }
        }
    }

    /// Runs one complete garbage collection scan pass.
    async fn scan_pass(&self) -> Result<GcStats, SupervisorError> {
        let mut stats = GcStats::default();
        let started = Instant::now();

        // Resolve known sandbox IDs once so Phase 2 and Phase 3 can share
        // the same result without redundant ledger queries.
        let known_ids = self.ledger.list_known_sandbox_ids().await?;
        let known_ids = Arc::new(known_ids);

        // Phase 1: Scan durable resource receipts for sandboxes that have
        // outstanding resources.
        let rows = self.ledger.list_gc_scan_rows().await?;
        stats.receipts_scanned = rows.len() as u64;

        for row in &rows {
            if !self.enabled.load(Ordering::Relaxed) {
                break;
            }
            let outcomes = self.inspect_row(row).await;
            for outcome in outcomes {
                match outcome.action {
                    GcAction::Removed => {
                        self.ledger
                            .mark_resource_removed(&row.sandbox_id, &row.resource_name)
                            .await?;
                        stats.removed += 1;
                    }
                    GcAction::Confirmed => stats.confirmed += 1,
                    GcAction::RequiresReview => {
                        self.ledger
                            .record_finding(
                                Some(&row.sandbox_id),
                                None,
                                row.resource_class.as_str(),
                                &outcome.finding.evidence,
                                "requires_review",
                                outcome.error.as_deref(),
                            )
                            .await?;
                        stats.review_required += 1;
                    }
                    GcAction::AlreadyAbsent => {
                        self.ledger
                            .mark_resource_removed(&row.sandbox_id, &row.resource_name)
                            .await?;
                        stats.removed += 1;
                    }
                }
            }
        }

        // Phase 2: Scan workspace root for orphaned directories that have no
        // corresponding sandbox entry in the ledger.
        let workspace_findings = self.scan_orphan_workspaces(Arc::clone(&known_ids)).await;
        for finding in workspace_findings {
            if finding.safe_to_remove {
                if let Some(ref sandbox_id) = finding.sandbox_id {
                    match self.remove_workspace_blocking(sandbox_id).await {
                        Ok(()) => {
                            stats.removed += 1;
                            self.ledger
                                .record_finding(
                                    Some(sandbox_id),
                                    None,
                                    finding.resource_class.as_str(),
                                    &finding.evidence,
                                    "removed",
                                    None,
                                )
                                .await?;
                        }
                        Err(error) => {
                            stats.cleanup_failed += 1;
                            warn!(
                                sandbox_id = %sandbox_id,
                                error = %error,
                                "failed to remove orphaned workspace"
                            );
                            self.ledger
                                .record_finding(
                                    Some(sandbox_id),
                                    None,
                                    finding.resource_class.as_str(),
                                    &finding.evidence,
                                    "requires_review",
                                    Some(&error),
                                )
                                .await?;
                        }
                    }
                }
            } else {
                if let Some(ref sandbox_id) = finding.sandbox_id {
                    self.ledger
                        .record_finding(
                            Some(sandbox_id),
                            None,
                            finding.resource_class.as_str(),
                            &finding.evidence,
                            "requires_review",
                            None,
                        )
                        .await?;
                }
                stats.review_required += 1;
            }
        }

        // Phase 3: Scan for orphaned cgroups.
        let cgroup_findings = self
            .scan_orphan_cgroups(&rows, Arc::clone(&known_ids))
            .await;
        for finding in cgroup_findings {
            if finding.safe_to_remove {
                if let Some(ref sandbox_id) = finding.sandbox_id {
                    match self.remove_cgroup_blocking(sandbox_id).await {
                        Ok(()) => {
                            stats.removed += 1;
                            self.ledger
                                .record_finding(
                                    Some(sandbox_id),
                                    None,
                                    finding.resource_class.as_str(),
                                    &finding.evidence,
                                    "removed",
                                    None,
                                )
                                .await?;
                        }
                        Err(error) => {
                            stats.cleanup_failed += 1;
                            debug!(
                                sandbox_id = %sandbox_id,
                                error = %error,
                                "failed to remove orphaned cgroup"
                            );
                            self.ledger
                                .record_finding(
                                    Some(sandbox_id),
                                    None,
                                    finding.resource_class.as_str(),
                                    &finding.evidence,
                                    "requires_review",
                                    Some(&error),
                                )
                                .await?;
                        }
                    }
                }
            } else {
                if let Some(ref sandbox_id) = finding.sandbox_id {
                    self.ledger
                        .record_finding(
                            Some(sandbox_id),
                            None,
                            finding.resource_class.as_str(),
                            &finding.evidence,
                            "requires_review",
                            None,
                        )
                        .await?;
                }
                stats.review_required += 1;
            }
        }

        stats.scan_duration_ms = started.elapsed().as_millis() as u64;
        stats.completed_at = pico_core::now_iso();
        emit_gc_metrics(&stats);
        Ok(stats)
    }

    /// Inspects a single resource receipt row for cleanup opportunities.
    ///
    /// Receipts stay `present` for the whole lifetime of a sandbox, so
    /// removal must only happen once the sandbox is proven `Destroyed`.
    /// Auto-removing resources for live or failed sandboxes could delete
    /// workspaces under a running VMM; failed sandboxes are left for
    /// operator review instead.
    async fn inspect_row(&self, row: &GcScanRow) -> Vec<CleanupOutcome> {
        let mut outcomes = Vec::new();
        let class = resource_class_from_row(row);

        // Ledger encodes states lowercase ("destroyed"); SandboxState::as_str
        // is PascalCase for display, so compare against the ledger encoding.
        if row.observed_state != "destroyed" {
            outcomes.push(CleanupOutcome {
                finding: OrphanFinding {
                    sandbox_id: Some(row.sandbox_id.clone()),
                    resource_class: class.unwrap_or(ResourceClass::Other),
                    resource_name: row.resource_name.clone(),
                    evidence: format!(
                        "resource {}:{} is still owned by a sandbox in state {}",
                        row.resource_class, row.resource_name, row.observed_state
                    ),
                    safe_to_remove: false,
                },
                action: GcAction::Confirmed,
                error: None,
            });

            return outcomes;
        }

        match class {
            Some(ResourceClass::Workspace) => {
                let finding = self.inspect_workspace(&row.sandbox_id);
                let outcome = self
                    .decide_workspace_outcome(&row.sandbox_id, &finding)
                    .await;
                outcomes.push(CleanupOutcome {
                    finding,
                    action: outcome.0,
                    error: outcome.1,
                });
            }
            Some(ResourceClass::Cgroup) => {
                let finding = self.inspect_cgroup(&row.sandbox_id);
                let outcome = self.decide_cgroup_outcome(&row.sandbox_id, &finding).await;
                outcomes.push(CleanupOutcome {
                    finding,
                    action: outcome.0,
                    error: outcome.1,
                });
            }
            Some(ResourceClass::Cpu) => {
                // CPU allocations live only in the daemon's memory and are
                // released during destroy teardown; once the owning sandbox
                // is destroyed there is no host artifact left to clean up.
                // Unparsable payloads stay requires_review on purpose: the
                // allocator rebuild skipped them at startup, and auto-delete
                // would discard the only evidence of a possible overcommit.
                // This is not a transient leftover; do not auto-retry away.
                let receipt = CpuReceiptRow {
                    sandbox_id: row.sandbox_id.clone(),
                    external_id: row.external_id.clone(),
                };
                let (action, evidence, safe_to_remove) = match parse_cpu_receipt(&receipt) {
                    Ok(_) => (
                        GcAction::AlreadyAbsent,
                        "CPU allocation has no host artifact to clean up".to_string(),
                        true,
                    ),
                    Err(message) => (
                        GcAction::RequiresReview,
                        format!("CPU receipt payload cannot be parsed: {message}"),
                        false,
                    ),
                };
                outcomes.push(CleanupOutcome {
                    finding: OrphanFinding {
                        sandbox_id: Some(row.sandbox_id.clone()),
                        resource_class: ResourceClass::Cpu,
                        resource_name: row.resource_name.clone(),
                        evidence,
                        safe_to_remove,
                    },
                    action,
                    error: None,
                });
            }
            _ => {
                // Unknown/unhandled classes (mount, network device, etc.) lack
                // safe auto-remove heuristics. Keep requires_review rather than
                // guessing; this is never a transient cgroup/workspace drain.
                outcomes.push(CleanupOutcome {
                    finding: OrphanFinding {
                        sandbox_id: Some(row.sandbox_id.clone()),
                        resource_class: class.unwrap_or(ResourceClass::Other),
                        resource_name: row.resource_name.clone(),
                        evidence: format!(
                            "unhandled resource {}:{}, requires operator review",
                            row.resource_class, row.resource_name
                        ),
                        safe_to_remove: false,
                    },
                    action: GcAction::RequiresReview,
                    error: None,
                });
            }
        }

        outcomes
    }

    // ── Workspace helpers ──

    fn inspect_workspace(&self, sandbox_id: &str) -> OrphanFinding {
        // Explicit traversal guard so a hostile ledger row can never turn
        // the join/metadata below into a path escape. The `contains` check
        // is what static analysis recognizes; the allowlist rejects the
        // rest (`/`, `\`, absolute paths, wrong prefix). Invalid ids stay
        // requires_review instead of being auto-removed.
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Workspace,
                resource_name: sandbox_id.to_string(),
                evidence: format!("invalid sandbox id: {sandbox_id}"),
                safe_to_remove: false,
            };
        }
        let path = self.workspace_root.join(sandbox_id);
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Workspace,
                resource_name: sandbox_id.to_string(),
                evidence: format!("workspace directory exists at {}", path.display()),
                safe_to_remove: true,
            },
            Ok(_) => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Workspace,
                resource_name: sandbox_id.to_string(),
                evidence: format!(
                    "workspace path exists but is not a directory: {}",
                    path.display()
                ),
                safe_to_remove: false,
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Workspace,
                resource_name: sandbox_id.to_string(),
                evidence: format!("workspace directory absent at {}", path.display()),
                safe_to_remove: false,
            },
            Err(err) => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Workspace,
                resource_name: sandbox_id.to_string(),
                evidence: format!("cannot stat workspace path {}: {err}", path.display()),
                safe_to_remove: false,
            },
        }
    }

    async fn decide_workspace_outcome(
        &self,
        sandbox_id: &str,
        finding: &OrphanFinding,
    ) -> (GcAction, Option<String>) {
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return (
                GcAction::RequiresReview,
                Some(format!("invalid sandbox id: {sandbox_id}")),
            );
        }
        if !finding.safe_to_remove {
            return self
                .unsafe_path_outcome(&self.workspace_root.join(sandbox_id), &finding.evidence);
        }
        match self.remove_workspace_blocking(sandbox_id).await {
            Ok(()) => (GcAction::Removed, None),
            // Removal already exhausted transient retries in core; remaining
            // failures need a human (or a later pass after the host changes).
            Err(error) => (GcAction::RequiresReview, Some(error)),
        }
    }

    /// Runs workspace removal on the blocking pool: deletion retries
    /// transient errors with sleeps, so it must not run on an async worker.
    /// A failed join means the removal state is unknown; surfacing an error
    /// keeps the receipt present for review instead of assuming success.
    async fn remove_workspace_blocking(&self, sandbox_id: &str) -> Result<(), String> {
        let this = self.clone();
        let sandbox_id = sandbox_id.to_string();
        tokio::task::spawn_blocking(move || this.remove_workspace(&sandbox_id))
            .await
            .unwrap_or_else(|err| Err(format!("cleanup worker failed: {err}")))
    }

    fn remove_workspace(&self, sandbox_id: &str) -> Result<(), String> {
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return Err(format!("invalid sandbox id: {sandbox_id}"));
        }
        let existed = self.workspace_root.join(sandbox_id).exists();
        self.host_resources
            .delete_workspace_dir(sandbox_id)
            .map(|()| {
                if existed {
                    info!(sandbox_id = %sandbox_id, "removed orphaned workspace directory");
                }
            })
    }

    // ── Cgroup helpers ──

    fn inspect_cgroup(&self, sandbox_id: &str) -> OrphanFinding {
        // Explicit traversal guard (see inspect_workspace).
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Cgroup,
                resource_name: sandbox_id.to_string(),
                evidence: format!("invalid sandbox id: {sandbox_id}"),
                safe_to_remove: false,
            };
        }
        let path = self.cgroup_base_path.join(sandbox_id);
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Cgroup,
                resource_name: sandbox_id.to_string(),
                evidence: format!("cgroup directory exists at {}", path.display()),
                safe_to_remove: true,
            },
            Ok(_) => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Cgroup,
                resource_name: sandbox_id.to_string(),
                evidence: format!(
                    "cgroup path exists but is not a directory: {}",
                    path.display()
                ),
                safe_to_remove: false,
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Cgroup,
                resource_name: sandbox_id.to_string(),
                evidence: format!("cgroup directory absent at {}", path.display()),
                safe_to_remove: false,
            },
            Err(err) => OrphanFinding {
                sandbox_id: Some(sandbox_id.to_string()),
                resource_class: ResourceClass::Cgroup,
                resource_name: sandbox_id.to_string(),
                evidence: format!("cannot stat cgroup path {}: {err}", path.display()),
                safe_to_remove: false,
            },
        }
    }

    async fn decide_cgroup_outcome(
        &self,
        sandbox_id: &str,
        finding: &OrphanFinding,
    ) -> (GcAction, Option<String>) {
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return (
                GcAction::RequiresReview,
                Some(format!("invalid sandbox id: {sandbox_id}")),
            );
        }
        if !finding.safe_to_remove {
            return self
                .unsafe_path_outcome(&self.cgroup_base_path.join(sandbox_id), &finding.evidence);
        }
        match self.remove_cgroup_blocking(sandbox_id).await {
            Ok(()) => (GcAction::Removed, None),
            // Same as workspace: core already retried EBUSY/ENOTEMPTY.
            Err(error) => (GcAction::RequiresReview, Some(error)),
        }
    }

    /// Blocking-pool variant of [`GarbageCollector::remove_cgroup`]; see
    /// [`GarbageCollector::remove_workspace_blocking`] for the rationale.
    async fn remove_cgroup_blocking(&self, sandbox_id: &str) -> Result<(), String> {
        let this = self.clone();
        let sandbox_id = sandbox_id.to_string();
        tokio::task::spawn_blocking(move || this.remove_cgroup(&sandbox_id))
            .await
            .unwrap_or_else(|err| Err(format!("cleanup worker failed: {err}")))
    }

    /// Classifies a path that inspect marked unsafe to auto-remove.
    ///
    /// Proven absence converges to a released receipt without operator
    /// action. Non-directory paths and stat failures stay `requires_review`
    /// because automatic deletion could remove the wrong object.
    fn unsafe_path_outcome(
        &self,
        path: &std::path::Path,
        evidence: &str,
    ) -> (GcAction, Option<String>) {
        match std::fs::symlink_metadata(path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                (GcAction::AlreadyAbsent, None)
            }
            // Unknown resource shape, permission to inspect, or non-dir path:
            // keep requires_review so an operator decides.
            _ => (GcAction::RequiresReview, Some(evidence.to_string())),
        }
    }

    fn remove_cgroup(&self, sandbox_id: &str) -> Result<(), String> {
        if sandbox_id.contains("..") || validate_sandbox_id(sandbox_id).is_err() {
            return Err(format!("invalid sandbox id: {sandbox_id}"));
        }
        let existed = self.cgroup_base_path.join(sandbox_id).exists();
        self.host_resources.cleanup_cgroup(sandbox_id).map(|()| {
            if existed {
                info!(sandbox_id = %sandbox_id, "removed orphaned cgroup directory");
            }
        })
    }

    // ── Phase 2: Orphan workspace scan ──

    /// Scans the workspace root for directories that do not correspond to
    /// any sandbox known to the ledger.
    async fn scan_orphan_workspaces(&self, known_ids: Arc<Vec<String>>) -> Vec<OrphanFinding> {
        let mut findings = Vec::new();

        let entries = match std::fs::read_dir(self.workspace_root.as_ref()) {
            Ok(entries) => entries,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    error!(
                        error = %error,
                        workspace_root = %self.workspace_root.display(),
                        "failed to read workspace root for orphan scan"
                    );
                }
                return findings;
            }
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !known_ids.iter().any(|id| id == name) {
                let file_type = entry.file_type().ok();
                let is_dir = file_type.is_some_and(|ft| ft.is_dir());
                findings.push(OrphanFinding {
                    sandbox_id: Some(name.to_string()),
                    resource_class: ResourceClass::Workspace,
                    resource_name: name.to_string(),
                    evidence: format!(
                        "orphaned workspace {:?} (sandbox unknown to ledger)",
                        entry.path()
                    ),
                    safe_to_remove: is_dir,
                });
            }
        }

        findings
    }

    // ── Phase 3: Orphan cgroup scan ──

    /// Scans the cgroup sandbox hierarchy for directories that do not
    /// correspond to any sandbox known to the ledger.
    async fn scan_orphan_cgroups(
        &self,
        _rows: &[GcScanRow],
        known_ids: Arc<Vec<String>>,
    ) -> Vec<OrphanFinding> {
        let mut findings = Vec::new();
        let cgroup_root = self.cgroup_base_path.as_ref();

        let entries = match std::fs::read_dir(cgroup_root) {
            Ok(entries) => entries,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    error!(
                        error = %error,
                        cgroup_root = %cgroup_root.display(),
                        "failed to read cgroup root for orphan scan"
                    );
                }
                return findings;
            }
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !known_ids.iter().any(|id| id == name) {
                findings.push(OrphanFinding {
                    sandbox_id: Some(name.to_string()),
                    resource_class: ResourceClass::Cgroup,
                    resource_name: name.to_string(),
                    evidence: format!(
                        "orphaned cgroup {:?} (sandbox unknown to ledger)",
                        entry.path()
                    ),
                    safe_to_remove: true,
                });
            }
        }

        findings
    }
}

/// Maps a GC scan row's resource class to a typed `ResourceClass`.
fn resource_class_from_row(row: &GcScanRow) -> Option<ResourceClass> {
    ResourceClass::parse(&row.resource_class)
}

/// Returns true when a GC pass found resources that could not be cleaned up
/// safely, indicating the host may be in an unsafe state.
#[must_use]
pub fn has_unsafe_findings(stats: &GcStats) -> bool {
    stats.cleanup_failed > 0
}

/// Emits OTLP metrics for one garbage collection pass.
pub(crate) fn emit_gc_metrics(stats: &GcStats) {
    // Host-level aggregate: the GC pass spans every sandbox on the host.
    let labels = Labels::host();
    CORE_METRICS
        .gc_pass_duration
        .record(stats.scan_duration_ms as f64 / 1000.0, &labels);
    // Zero-valued outcomes are skipped so a clean pass creates no empty points.
    for (counter, count) in [
        (&CORE_METRICS.gc_orphans_detected, stats.receipts_scanned),
        (&CORE_METRICS.gc_resources_removed, stats.removed),
        (&CORE_METRICS.gc_review_required, stats.review_required),
        (&CORE_METRICS.gc_cleanup_failed, stats.cleanup_failed),
    ] {
        if count > 0 {
            counter.inc_by(count, &labels);
        }
    }
}
#[cfg(test)]
mod tests;
