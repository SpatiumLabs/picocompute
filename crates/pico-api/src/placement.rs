//! Scheduler-backed placement admission for the create path.
//!
//! Wires `RegionalScheduler` then `CellScheduler` into API create admission
//! so production admits use the same packing math calibrated by active
//! capacity measurements.
//!
//! ## Design
//!
//! - `PlacementRegistry` is a multi-host registry fed by host-agent capacity
//!   reports. Each cell owns a `HostInventory` with a 60s stale TTL; the
//!   admit path expires stale hosts before snapshotting.
//! - `PlacementGate` runs two-stage placement: regional cell selection, then
//!   cell host selection. `InsufficientCapacity` and `PressureSaturated`
//!   fail closed as retryable `PlacementThrottled` (422 + `Retry-After`).
//! - Silent backend fallback is forbidden: the requested runtime is resolved
//!   explicitly once (defaulting to Firecracker) before scheduling, and the
//!   selected host must support it. No second attempt with a different
//!   backend is made under pressure.

use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::RwLock;
use pico_core::{
    CacheLocality, CellCapacity, CellHealth, CellId, CellInfo, CellScheduler, CellSchedulerError,
    CellSchedulerRequest, HostCacheState, HostCapacity, HostHealth, HostId, HostInfo,
    HostInventory, HostPressure, RegionId, RegionalScheduler, RuntimeType, SandboxError,
    SchedulerError, SchedulerRequest, SnapshotTimingHint, TenantId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Stale-host TTL in seconds for host-agent capacity reports.
pub const HOST_STALE_TTL_SECS: i64 = 60;

/// Default disk request in MB.
///
/// `SandboxSpec` carries no disk field, so placement assumes 1 GiB per
/// sandbox. Hosts with less than 1 GiB disk headroom fail closed at the
/// cell stage. Override per gate with [`PlacementGate::with_disk_mb`].
pub const DEFAULT_DISK_MB: u64 = 1024;

/// Default `Retry-After` hint in seconds for throttled placement.
///
/// Aliases the core constant so the gate default and the core scheduler
/// conversions disagree on nothing by construction.
pub const DEFAULT_RETRY_AFTER_SECS: u64 = pico_core::PLACEMENT_RETRY_AFTER_SECS;

/// Capacity report pushed by a host-agent.
///
/// This is the control-plane view of `HostAgent::inventory` plus live
/// pressure and health. Reports refresh `HostInventory` entries and their
/// last-seen timestamps; entries older than [`HOST_STALE_TTL_SECS`]
/// expire before placement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostCapacityReport {
    /// Host identifier.
    pub host_id: String,
    /// Cell this host belongs to.
    pub cell_id: String,
    /// Region this host belongs to (used to seed cell region on first report).
    #[serde(default)]
    pub region: Option<String>,
    /// Current health status.
    pub health: HostHealth,
    /// Resource capacity and allocation.
    pub capacity: HostCapacity,
    /// Create/restore pressure.
    pub pressure: HostPressure,
    /// Runtime backends supported by this host.
    pub supported_runtimes: Vec<RuntimeType>,
    /// Local image/snapshot cache state.
    #[serde(default)]
    pub cache: Option<HostCacheState>,
    /// Sandboxes currently running on this host.
    #[serde(default)]
    pub current_sandboxes: u64,
    /// Snapshot timing hint aggregate.
    #[serde(default)]
    pub snapshot_timing_hint: SnapshotTimingHint,
}

impl HostCapacityReport {
    /// Converts the report into scheduler `HostInfo`.
    pub fn to_host_info(&self) -> HostInfo {
        HostInfo {
            host_id: HostId::from_string(&self.host_id),
            health: self.health,
            capacity: self.capacity,
            supported_runtimes: self.supported_runtimes.clone(),
            cache: self.cache.clone().unwrap_or(HostCacheState {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            }),
            pressure: self.pressure,
            current_sandboxes: self.current_sandboxes,
            snapshot_timing_hint: self.snapshot_timing_hint,
        }
    }
}

/// Maps host-agent health status to scheduler host health.
pub fn map_agent_health(status: pico_host_agent::health::HealthStatus) -> HostHealth {
    use pico_host_agent::health::HealthStatus as AgentHealthStatus;
    match status {
        AgentHealthStatus::Ready => HostHealth::Healthy,
        AgentHealthStatus::Degraded => HostHealth::Degraded,
        AgentHealthStatus::Draining => HostHealth::Draining,
        AgentHealthStatus::Unsafe => HostHealth::Unavailable,
    }
}

/// Builds a capacity report from live host-agent observations.
///
/// Prefers the scheduler capacity and pressure already computed by the
/// host-agent from live sandbox allocations and in-flight counters. Falls
/// back to boot-total-derived estimates for reports from older agents that
/// predate live snapshots.
///
/// The three inputs are observed sequentially, not atomically: inventory,
/// health, and stats each reflect a slightly different instant. Under churn
/// the resulting report can mix timestamps (e.g. capacity from before a
/// create with health from after). The 30s re-report loop bounds the skew;
/// do not treat one report as a single-instant snapshot.
pub fn host_report_from_observations(
    inventory: &pico_host_agent::identity::HostInventory,
    health: &pico_host_agent::health::HostHealth,
    stats: &serde_json::Value,
) -> HostCapacityReport {
    let live = inventory.scheduler_capacity.is_some();
    let sandbox_count = if live {
        inventory.current_sandboxes
    } else {
        health.sandbox_count as u64
    };
    let timing = pico_core::HostSnapshotTimingStats::from_stats_value(stats).as_hint();
    let capacity = inventory
        .scheduler_capacity
        .unwrap_or_else(|| HostCapacity {
            total_vcpus: u64::from(inventory.capacity.cpu_count),
            allocated_vcpus: 0,
            total_memory_mb: inventory.capacity.memory_mb_total,
            allocated_memory_mb: inventory
                .capacity
                .memory_mb_total
                .saturating_sub(inventory.capacity.memory_mb_available),
            total_disk_mb: inventory.capacity.disk_mb_total,
            used_disk_mb: inventory
                .capacity
                .disk_mb_total
                .saturating_sub(inventory.capacity.disk_mb_available),
            total_network_mbps: 10_000,
            allocated_network_mbps: 0,
            max_process_slots: 1000,
            used_process_slots: sandbox_count,
        });
    let pressure = inventory
        .pressure
        .or_else(|| serde_json::from_value::<HostPressure>(stats.get("pressure")?.clone()).ok())
        .unwrap_or(HostPressure {
            in_flight_creates: 0,
            in_flight_restores: 0,
            max_concurrent_creates: 8,
            max_concurrent_restores: 8,
        });
    HostCapacityReport {
        host_id: inventory.identity.host_id.clone(),
        cell_id: inventory.identity.cell_id.clone(),
        region: Some(inventory.identity.region.clone()),
        health: map_agent_health(health.status),
        capacity,
        pressure,
        supported_runtimes: inventory.supported_backends.clone(),
        cache: Some(HostCacheState {
            cached_images: Vec::new(),
            cached_snapshots: Vec::new(),
        }),
        current_sandboxes: sandbox_count,
        snapshot_timing_hint: timing,
    }
}

/// Multi-host placement registry.
///
/// Cells are provisioned explicitly via [`Self::upsert_cell`]. Hosts report
/// per cell via [`Self::report_host`] into a per-cell [`HostInventory`].
/// Stale hosts expire after [`HOST_STALE_TTL_SECS`] and are excluded from
/// placement snapshots.
pub struct PlacementRegistry {
    cells: RwLock<HashMap<String, CellInfo>>,
    hosts: RwLock<HashMap<String, Arc<HostInventory>>>,
    stale_ttl_secs: i64,
}

impl PlacementRegistry {
    /// Creates an empty registry with the default 60s stale TTL.
    pub fn new() -> Self {
        Self::with_stale_ttl(HOST_STALE_TTL_SECS)
    }

    /// Creates an empty registry with a custom stale TTL.
    ///
    /// Production uses the default 60s TTL via [`Self::new`]; custom values
    /// exist for tests and capacity tuning.
    pub fn with_stale_ttl(stale_ttl_secs: i64) -> Self {
        Self {
            cells: RwLock::new(HashMap::new()),
            hosts: RwLock::new(HashMap::new()),
            stale_ttl_secs,
        }
    }

    /// Provisions or updates a cell.
    pub fn upsert_cell(&self, cell: CellInfo) {
        let key = cell.cell_id.as_str().to_string();
        self.cells.write().insert(key.clone(), cell);
        self.hosts
            .write()
            .entry(key)
            .or_insert_with(|| Arc::new(HostInventory::with_stale_ttl(self.stale_ttl_secs)));
    }

    /// Ingests a host-agent capacity report.
    ///
    /// Upserts the host into its cell inventory with `now` as last-seen,
    /// then refreshes the cell aggregate from live hosts so regional
    /// scheduling tracks reported totals instead of drifting from static
    /// provisioning. If the cell is unknown, it is seeded from the
    /// reporting host (region, runtimes, and capacity derived from the
    /// host) so ad-hoc single-cell deployments place without explicit
    /// provisioning.
    pub fn report_host(&self, report: &HostCapacityReport, now: OffsetDateTime) {
        let cell_key = report.cell_id.clone();
        {
            let mut cells = self.cells.write();
            if !cells.contains_key(&cell_key) {
                cells.insert(cell_key.clone(), Self::seed_cell_from_report(report));
            }
        }
        let inventory = {
            let mut hosts = self.hosts.write();
            hosts
                .entry(cell_key.clone())
                .or_insert_with(|| Arc::new(HostInventory::with_stale_ttl(self.stale_ttl_secs)))
                .clone()
        };
        inventory.upsert(report.to_host_info(), now);
        self.refresh_cell_from_hosts(&cell_key, now);
    }

    /// Seeds a cell entry from the first host report for an unknown cell.
    ///
    /// Capacity is derived from the reporting host (not zeros) so the cell
    /// passes regional `can_fit` once its first host reports. Totals are
    /// corrected on every subsequent report by
    /// [`Self::refresh_cell_from_hosts`].
    fn seed_cell_from_report(report: &HostCapacityReport) -> CellInfo {
        let info = report.to_host_info();
        CellInfo {
            cell_id: CellId::from_string(&report.cell_id),
            region_id: RegionId::from_string(report.region.as_deref().unwrap_or("default-region")),
            health: CellHealth::Healthy,
            capacity: CellCapacity {
                total_vcpus: info.capacity.total_vcpus,
                allocated_vcpus: info.capacity.allocated_vcpus,
                total_memory_mb: info.capacity.total_memory_mb,
                allocated_memory_mb: info.capacity.allocated_memory_mb,
                max_sandboxes: info.capacity.max_process_slots.max(1),
                current_sandboxes: info.current_sandboxes,
            },
            supported_runtimes: report.supported_runtimes.clone(),
            failure_domain: format!("fd-{}", report.cell_id),
            cache: CacheLocality {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            },
            admission_pressure: info.pressure.combined_pressure(),
            snapshot_timing_hint: info.snapshot_timing_hint,
        }
    }

    /// Recomputes a cell aggregate from its live (non-stale) hosts.
    ///
    /// Host reports are the source of truth for totals: regional capacity,
    /// runtime union, mean admission pressure, and the most conservative
    /// snapshot timing hint all follow live hosts. Region and failure
    /// domain stay as provisioned. Empty (all stale) cells keep their last
    /// provisioned values so expiry alone never fabricates capacity.
    fn refresh_cell_from_hosts(&self, cell_key: &str, now: OffsetDateTime) {
        let hosts: Vec<HostInfo> = {
            let hosts = self.hosts.read();
            match hosts.get(cell_key) {
                Some(inventory) => {
                    inventory.expire_stale(now);
                    inventory.snapshot()
                }
                None => Vec::new(),
            }
        };
        if hosts.is_empty() {
            return;
        }
        let mut cells = self.cells.write();
        let Some(cell) = cells.get_mut(cell_key) else {
            return;
        };
        cell.capacity.total_vcpus = hosts.iter().map(|h| h.capacity.total_vcpus).sum();
        cell.capacity.allocated_vcpus = hosts.iter().map(|h| h.capacity.allocated_vcpus).sum();
        cell.capacity.total_memory_mb = hosts.iter().map(|h| h.capacity.total_memory_mb).sum();
        cell.capacity.allocated_memory_mb =
            hosts.iter().map(|h| h.capacity.allocated_memory_mb).sum();
        cell.capacity.max_sandboxes = hosts
            .iter()
            .map(|h| h.capacity.max_process_slots)
            .sum::<u64>()
            .max(1);
        cell.capacity.current_sandboxes = hosts.iter().map(|h| h.current_sandboxes).sum();
        let mut runtimes: Vec<RuntimeType> = hosts
            .iter()
            .flat_map(|h| h.supported_runtimes.iter().copied())
            .collect();
        runtimes.sort_by_key(|r| format!("{r:?}"));
        runtimes.dedup();
        cell.supported_runtimes = runtimes;
        let pressures: Vec<f64> = hosts
            .iter()
            .map(|h| h.pressure.combined_pressure())
            .collect();
        cell.admission_pressure = pressures.iter().sum::<f64>() / pressures.len().max(1) as f64;
        cell.snapshot_timing_hint =
            SnapshotTimingHint::aggregate(hosts.iter().map(|h| h.snapshot_timing_hint));
        cell.health = Self::aggregate_cell_health(&hosts);
    }

    /// Aggregates host health into one cell health.
    ///
    /// Any admittable host keeps the cell admittable (healthy when all
    /// admittable hosts are healthy, degraded otherwise). Fully
    /// non-admittable cells report draining when any host is draining or
    /// administratively disabled, else unavailable.
    fn aggregate_cell_health(hosts: &[HostInfo]) -> CellHealth {
        let mut any_healthy = false;
        let mut any_degraded = false;
        let mut any_draining = false;
        for host in hosts {
            match host.health {
                HostHealth::Healthy => any_healthy = true,
                HostHealth::Degraded => any_degraded = true,
                HostHealth::Draining | HostHealth::DisabledForPlacement => any_draining = true,
                HostHealth::Unavailable | HostHealth::Quarantined => {}
            }
        }
        if any_healthy && !any_degraded {
            CellHealth::Healthy
        } else if any_healthy || any_degraded {
            CellHealth::Degraded
        } else if any_draining {
            CellHealth::Draining
        } else {
            CellHealth::Unavailable
        }
    }

    /// Expires stale hosts across all cells. Returns expired host IDs.
    pub fn expire_stale(&self, now: OffsetDateTime) -> Vec<HostId> {
        let hosts = self.hosts.read();
        let mut expired = Vec::new();
        for inventory in hosts.values() {
            expired.extend(inventory.expire_stale(now));
        }
        expired
    }

    /// Snapshots provisioned cells after expiring stale hosts.
    pub fn snapshot_cells(&self, now: OffsetDateTime) -> Vec<CellInfo> {
        self.expire_stale(now);
        self.cells_snapshot()
    }

    /// Snapshots live hosts for a cell after expiring stale entries.
    pub fn snapshot_hosts(&self, cell_id: &CellId, now: OffsetDateTime) -> Vec<HostInfo> {
        let hosts = self.hosts.read();
        match hosts.get(cell_id.as_str()) {
            Some(inventory) => {
                inventory.expire_stale(now);
                inventory.snapshot()
            }
            None => Vec::new(),
        }
    }

    /// Cells snapshot without expiry (admit path expires once up front).
    fn cells_snapshot(&self) -> Vec<CellInfo> {
        self.cells.read().values().cloned().collect()
    }

    /// Hosts snapshot without expiry (admit path expires once up front).
    fn hosts_snapshot(&self, cell_id: &CellId) -> Vec<HostInfo> {
        let hosts = self.hosts.read();
        match hosts.get(cell_id.as_str()) {
            Some(inventory) => inventory.snapshot(),
            None => Vec::new(),
        }
    }

    /// Returns the number of provisioned cells.
    pub fn cell_count(&self) -> usize {
        self.cells.read().len()
    }

    /// Returns the number of live hosts for a cell (excludes stale after expiry).
    pub fn host_count(&self, cell_id: &CellId, now: OffsetDateTime) -> usize {
        self.snapshot_hosts(cell_id, now).len()
    }
}

impl Default for PlacementRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Placement decision from two-stage scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDecision {
    /// Selected cell.
    pub cell_id: CellId,
    /// Selected host.
    pub host_id: HostId,
    /// Regional placement reason for traces and audit.
    pub regional_reason: String,
    /// Cell placement reason for traces and audit.
    pub cell_reason: String,
}

/// Typed placement failures.
///
/// `Throttled` is fail-closed and retryable: quota must release and the API
/// must not fall back to another backend or host silently.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PlacementError {
    /// No cells or hosts are available (registry empty or all stale).
    #[error("no placement capacity: {reason} (retry after {retry_after_secs}s)")]
    NoCapacity {
        reason: String,
        retry_after_secs: u64,
    },
    /// Capacity or pressure shed load; retry after the hint.
    #[error("placement throttled: {reason} (retry after {retry_after_secs}s)")]
    Throttled {
        reason: String,
        retry_after_secs: u64,
    },
    /// Hard rejection (unsupported runtime, draining, constraints).
    #[error("placement rejected: {reason}")]
    Rejected { reason: String },
}

impl From<PlacementError> for SandboxError {
    fn from(err: PlacementError) -> Self {
        match err {
            PlacementError::NoCapacity {
                reason,
                retry_after_secs,
            }
            | PlacementError::Throttled {
                reason,
                retry_after_secs,
            } => SandboxError::PlacementThrottled {
                reason,
                retry_after_secs,
            },
            PlacementError::Rejected { reason } => SandboxError::Unprocessable(reason),
        }
    }
}

/// Scheduler-backed admission gate for the create path.
///
/// Holds the regional and cell schedulers plus the shared registry. The gate
/// is synchronous and holds no async guards across scheduling.
pub struct PlacementGate {
    regional: RegionalScheduler,
    cell: CellScheduler,
    registry: Arc<PlacementRegistry>,
    default_runtime: RuntimeType,
    retry_after_secs: u64,
    disk_mb: u64,
}

impl PlacementGate {
    /// Creates a gate sharing the given registry.
    pub fn new(registry: Arc<PlacementRegistry>) -> Self {
        Self {
            regional: RegionalScheduler::new(),
            cell: CellScheduler::new(),
            registry,
            default_runtime: RuntimeType::Firecracker,
            retry_after_secs: DEFAULT_RETRY_AFTER_SECS,
            disk_mb: DEFAULT_DISK_MB,
        }
    }

    /// Creates a gate with explicit schedulers (tests and custom weights).
    pub fn with_schedulers(
        registry: Arc<PlacementRegistry>,
        regional: RegionalScheduler,
        cell: CellScheduler,
    ) -> Self {
        Self {
            regional,
            cell,
            registry,
            default_runtime: RuntimeType::Firecracker,
            retry_after_secs: DEFAULT_RETRY_AFTER_SECS,
            disk_mb: DEFAULT_DISK_MB,
        }
    }

    /// Overrides the explicit default runtime used when `spec.runtime` is `None`.
    ///
    /// The default is Firecracker (production microVM floor). Resolving once
    /// before scheduling keeps backend choice explicit and auditable; the
    /// gate never retries with a different backend under pressure.
    pub fn with_default_runtime(mut self, runtime: RuntimeType) -> Self {
        self.default_runtime = runtime;
        self
    }

    /// Overrides the `Retry-After` hint for throttled placement.
    pub fn with_retry_after_secs(mut self, secs: u64) -> Self {
        self.retry_after_secs = secs;
        self
    }

    /// Overrides the assumed disk request in MB.
    ///
    /// `SandboxSpec` carries no disk field; the default assumes 1 GiB per
    /// sandbox. Lower it for disk-light workloads or raise it where images
    /// need more headroom. Hosts with less free disk than this fail closed.
    pub fn with_disk_mb(mut self, disk_mb: u64) -> Self {
        self.disk_mb = disk_mb;
        self
    }

    /// Returns the shared registry for capacity report ingestion.
    pub fn registry(&self) -> &Arc<PlacementRegistry> {
        &self.registry
    }

    /// Returns the explicit default runtime used when `spec.runtime` is `None`.
    pub fn default_runtime(&self) -> RuntimeType {
        self.default_runtime
    }

    /// Admits a create request through regional then cell scheduling.
    ///
    /// Resolves the runtime explicitly, expires stale hosts once (TTL 60s),
    /// snapshots cells and hosts, and fails closed on
    /// `InsufficientCapacity` and `PressureSaturated` without backend
    /// fallback. Draining and unsupported runtimes reject without a
    /// `Retry-After` hint; capacity and pressure throttle with one.
    pub fn admit(
        &self,
        sandbox_id: &str,
        tenant_id: &TenantId,
        vcpus: u32,
        memory_mb: u64,
        runtime: Option<RuntimeType>,
        image: &str,
    ) -> Result<PlacementDecision, PlacementError> {
        // Resolve backend once, explicitly, before any scheduling. A `None`
        // request means the production default, not "try anything and fall
        // back silently under pressure".
        let resolved_runtime = runtime.unwrap_or(self.default_runtime);
        let now = OffsetDateTime::now_utc();
        self.registry.expire_stale(now);
        let cells = self.registry.cells_snapshot();
        if cells.is_empty() {
            return Err(PlacementError::NoCapacity {
                reason: "no cells provisioned or all host reports stale".into(),
                retry_after_secs: self.retry_after_secs,
            });
        }

        let sched_req = SchedulerRequest {
            tenant_id: tenant_id.clone(),
            vcpus,
            memory_mb,
            runtime: Some(resolved_runtime),
            image: image.to_string(),
            snapshot_id: None,
            preferred_region: None,
            avoid_failure_domains: Vec::new(),
            sandbox_id: sandbox_id.to_string(),
        };
        let regional_resp = self
            .regional
            .schedule(&sched_req, &cells)
            .map_err(|err| self.classify_regional_error(&err))?;
        let cell_id = regional_resp
            .cell_id
            .clone()
            .ok_or(PlacementError::Rejected {
                reason: "regional placement returned no cell".into(),
            })?;
        let regional_reason = format!("{:?}", regional_resp.reason);

        let hosts = self.registry.hosts_snapshot(&cell_id);
        if hosts.is_empty() {
            return Err(PlacementError::NoCapacity {
                reason: format!(
                    "cell {} has no live hosts (all reports stale)",
                    cell_id.as_str()
                ),
                retry_after_secs: self.retry_after_secs,
            });
        }

        let cell_req = CellSchedulerRequest {
            sandbox_id: sandbox_id.to_string(),
            vcpus,
            memory_mb,
            disk_mb: self.disk_mb,
            runtime: Some(resolved_runtime),
            image: image.to_string(),
            snapshot_id: None,
            is_restore: false,
        };
        let cell_resp = self
            .cell
            .schedule(&cell_req, &hosts)
            .map_err(|err| self.classify_cell_error(&err))?;
        let host_id = cell_resp.host_id.clone().ok_or(PlacementError::Rejected {
            reason: "cell placement returned no host".into(),
        })?;

        // Fail closed: the selected host must support the resolved backend.
        // The scheduler already enforces this as a hard constraint; recheck
        // here so a future scheduler change cannot reintroduce silent
        // fallback.
        if let Some(selected) = hosts.iter().find(|h| h.host_id == host_id)
            && !selected.supported_runtimes.contains(&resolved_runtime)
        {
            return Err(PlacementError::Rejected {
                reason: format!(
                    "selected host {} does not support {resolved_runtime:?}; refusing silent fallback",
                    host_id.as_str()
                ),
            });
        }

        Ok(PlacementDecision {
            cell_id,
            host_id,
            regional_reason,
            cell_reason: format!("{:?}", cell_resp.reason),
        })
    }

    fn classify_regional_error(&self, err: &SchedulerError) -> PlacementError {
        // Typed mapping only: throttled variants carry Retry-After, hard
        // rejections do not. Schedulers must return PressureSaturated /
        // InsufficientCapacity for capacity/pressure blockers instead of a
        // generic NoCellSatisfiesConstraints string so the hint survives.
        if err.is_throttled() {
            return PlacementError::Throttled {
                reason: err.to_string(),
                retry_after_secs: self.retry_after_secs,
            };
        }
        PlacementError::Rejected {
            reason: err.to_string(),
        }
    }

    fn classify_cell_error(&self, err: &CellSchedulerError) -> PlacementError {
        // Typed mapping only. Draining/disabled and unsupported runtimes
        // reject without a retry hint; capacity/pressure throttle.
        if err.is_throttled() {
            return PlacementError::Throttled {
                reason: err.to_string(),
                retry_after_secs: self.retry_after_secs,
            };
        }
        PlacementError::Rejected {
            reason: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::{CellHealth, RegionId};

    fn test_cell(id: &str) -> CellInfo {
        CellInfo {
            cell_id: CellId::from_string(id),
            region_id: RegionId::from_string("rgn_1"),
            health: CellHealth::Healthy,
            capacity: CellCapacity {
                total_vcpus: 64,
                allocated_vcpus: 0,
                total_memory_mb: 262_144,
                allocated_memory_mb: 0,
                max_sandboxes: 100,
                current_sandboxes: 0,
            },
            supported_runtimes: vec![RuntimeType::Firecracker],
            failure_domain: format!("fd-{id}"),
            cache: CacheLocality {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            },
            admission_pressure: 0.0,
            snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
        }
    }

    fn test_report(host: &str, cell: &str) -> HostCapacityReport {
        HostCapacityReport {
            host_id: host.into(),
            cell_id: cell.into(),
            region: Some("rgn_1".into()),
            health: HostHealth::Healthy,
            capacity: HostCapacity {
                total_vcpus: 32,
                allocated_vcpus: 0,
                total_memory_mb: 131_072,
                allocated_memory_mb: 0,
                total_disk_mb: 1_000_000,
                used_disk_mb: 0,
                total_network_mbps: 10_000,
                allocated_network_mbps: 0,
                max_process_slots: 1000,
                used_process_slots: 0,
            },
            pressure: HostPressure {
                in_flight_creates: 0,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
            supported_runtimes: vec![RuntimeType::Firecracker],
            cache: None,
            current_sandboxes: 0,
            snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
        }
    }

    #[test]
    fn registry_refresh_and_expire_with_60s_ttl() {
        let registry = PlacementRegistry::new();
        assert_eq!(HOST_STALE_TTL_SECS, 60);
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        assert_eq!(registry.cell_count(), 1);
        assert_eq!(registry.host_count(&CellId::from_string("cel_1"), now), 1);

        let stale = now + time::Duration::seconds(HOST_STALE_TTL_SECS + 1);
        assert_eq!(
            registry.host_count(&CellId::from_string("cel_1"), stale),
            0,
            "stale host reports must expire after TTL 60s"
        );
    }

    #[test]
    fn gate_places_regional_then_cell() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let decision = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .expect("healthy capacity must place");
        assert_eq!(decision.cell_id.as_str(), "cel_1");
        assert_eq!(decision.host_id.as_str(), "hst_1");
        assert!(!decision.regional_reason.is_empty());
        assert!(!decision.cell_reason.is_empty());
    }

    #[test]
    fn gate_resolves_default_runtime_explicitly() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        // `None` resolves to Firecracker, which the host supports.
        let decision = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                None,
                "img:1",
            )
            .expect("default runtime must place explicitly");
        assert_eq!(decision.host_id.as_str(), "hst_1");
    }

    #[test]
    fn gate_fails_closed_on_insufficient_capacity() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let err = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                10_000,
                10_000_000,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .unwrap_err();
        assert!(
            matches!(err, PlacementError::Throttled { .. }),
            "oversized request must throttle, got {err}"
        );
        let sandbox_err: SandboxError = err.into();
        assert!(
            matches!(sandbox_err, SandboxError::PlacementThrottled { .. }),
            "throttle must map to PlacementThrottled, got {sandbox_err}"
        );
    }

    #[test]
    fn gate_fails_closed_on_pressure_saturated() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        let mut report = test_report("hst_1", "cel_1");
        report.pressure.in_flight_creates = 8;
        report.pressure.max_concurrent_creates = 8;
        registry.report_host(&report, now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let err = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .unwrap_err();
        assert!(
            matches!(err, PlacementError::Throttled { .. }),
            "saturated pressure must throttle without fallback, got {err}"
        );
    }

    #[test]
    fn gate_rejects_unsupported_runtime_without_fallback() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let err = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::GVisor),
                "img:1",
            )
            .unwrap_err();
        assert!(
            matches!(err, PlacementError::Rejected { .. }),
            "unsupported runtime must reject, not silently fall back, got {err}"
        );
    }

    #[test]
    fn gate_no_capacity_when_registry_empty() {
        let registry = Arc::new(PlacementRegistry::new());
        let gate = PlacementGate::new(registry);
        let err = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoCapacity { .. }));
    }

    #[test]
    fn report_to_unknown_cell_seeds_placeable_capacity() {
        // Ad-hoc deployments that never provisioned a cell must still place
        // once the first host reports; the seeded cell derives capacity
        // from the host instead of zeros.
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.report_host(&test_report("hst_9", "cel_new"), now);
        assert_eq!(registry.cell_count(), 1);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let decision = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .expect("auto-seeded cell must place");
        assert_eq!(decision.cell_id.as_str(), "cel_new");
        assert_eq!(decision.host_id.as_str(), "hst_9");
    }

    #[test]
    fn cell_aggregate_tracks_host_reports() {
        let registry = PlacementRegistry::new();
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        registry.report_host(&test_report("hst_1", "cel_1"), now);
        let mut second = test_report("hst_2", "cel_1");
        second.capacity.total_vcpus = 64;
        second.capacity.total_memory_mb = 262_144;
        registry.report_host(&second, now);
        let cells = registry.snapshot_cells(now);
        let cell = cells
            .iter()
            .find(|c| c.cell_id.as_str() == "cel_1")
            .expect("cell must exist");
        assert_eq!(cell.capacity.total_vcpus, 32 + 64);
        assert_eq!(cell.capacity.total_memory_mb, 131_072 + 262_144);
        assert_eq!(cell.capacity.current_sandboxes, 0);
        assert_eq!(cell.health, CellHealth::Healthy);
    }

    #[test]
    fn gate_rejects_draining_without_retry_hint() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        let mut report = test_report("hst_1", "cel_1");
        report.health = HostHealth::Draining;
        registry.report_host(&report, now);
        let gate = PlacementGate::new(Arc::clone(&registry));
        let err = gate
            .admit(
                "sbx_1",
                &TenantId::from_string("tnt_1"),
                2,
                512,
                Some(RuntimeType::Firecracker),
                "img:1",
            )
            .unwrap_err();
        assert!(
            matches!(err, PlacementError::Rejected { .. }),
            "draining must reject without Retry-After, got {err}"
        );
        let sandbox_err: SandboxError = err.into();
        assert!(
            matches!(sandbox_err, SandboxError::Unprocessable(_)),
            "draining must map to Unprocessable, got {sandbox_err}"
        );
    }

    #[test]
    fn gate_honors_custom_disk_mb() {
        let registry = Arc::new(PlacementRegistry::new());
        let now = OffsetDateTime::now_utc();
        registry.upsert_cell(test_cell("cel_1"));
        let mut report = test_report("hst_1", "cel_1");
        report.capacity.total_disk_mb = 512;
        report.capacity.used_disk_mb = 0;
        registry.report_host(&report, now);
        let gate = PlacementGate::new(Arc::clone(&registry)).with_disk_mb(256);
        gate.admit(
            "sbx_1",
            &TenantId::from_string("tnt_1"),
            2,
            512,
            Some(RuntimeType::Firecracker),
            "img:1",
        )
        .expect("256 MB request must fit 512 MB disk");
    }
}

#[cfg(test)]
mod host_observation_tests {
    use super::*;
    use pico_host_agent::health::HostHealth as AgentHostHealth;
    use pico_host_agent::identity::{
        HostCapacity as BootHostCapacity, HostIdentity, HostInventory as AgentHostInventory,
    };

    fn boot_inventory() -> AgentHostInventory {
        AgentHostInventory {
            identity: HostIdentity::new("hst_1".into(), "cel_1".into(), "rgn_1".into()),
            capacity: BootHostCapacity {
                cpu_count: 32,
                memory_mb_total: 131_072,
                memory_mb_available: 65_536,
                disk_mb_total: 1_000_000,
                disk_mb_available: 900_000,
            },
            supported_backends: vec![RuntimeType::Firecracker],
            agent_version: "test".into(),
            scheduler_capacity: None,
            pressure: None,
            current_sandboxes: 0,
        }
    }

    #[test]
    fn prefers_live_scheduler_snapshot() {
        let mut inventory = boot_inventory();
        inventory.scheduler_capacity = Some(HostCapacity {
            total_vcpus: 32,
            allocated_vcpus: 4,
            total_memory_mb: 131_072,
            allocated_memory_mb: 1024,
            total_disk_mb: 1_000_000,
            used_disk_mb: 2048,
            total_network_mbps: 10_000,
            allocated_network_mbps: 0,
            max_process_slots: 1000,
            used_process_slots: 2,
        });
        inventory.pressure = Some(HostPressure {
            in_flight_creates: 2,
            in_flight_restores: 1,
            max_concurrent_creates: 8,
            max_concurrent_restores: 8,
        });
        inventory.current_sandboxes = 2;
        let health = AgentHostHealth::ready(99, vec![]);
        let report = host_report_from_observations(&inventory, &health, &serde_json::json!({}));
        assert_eq!(report.capacity.allocated_vcpus, 4);
        assert_eq!(report.capacity.allocated_memory_mb, 1024);
        assert_eq!(report.pressure.in_flight_creates, 2);
        assert_eq!(report.pressure.in_flight_restores, 1);
        // Live count wins over the stale health count.
        assert_eq!(report.current_sandboxes, 2);
    }

    #[test]
    fn falls_back_to_boot_derived_estimates() {
        let inventory = boot_inventory();
        let health = AgentHostHealth::ready(3, vec![]);
        let report = host_report_from_observations(&inventory, &health, &serde_json::json!({}));
        assert_eq!(report.capacity.total_vcpus, 32);
        assert_eq!(report.capacity.allocated_vcpus, 0);
        assert_eq!(
            report.capacity.allocated_memory_mb,
            131_072 - 65_536,
            "fallback memory derives from total minus available"
        );
        assert_eq!(
            report.capacity.used_disk_mb,
            1_000_000 - 900_000,
            "fallback disk derives from total minus available"
        );
        assert_eq!(report.current_sandboxes, 3);
        assert_eq!(report.pressure.in_flight_creates, 0);
    }

    #[test]
    fn parses_pressure_from_stats_when_inventory_predates_it() {
        let inventory = boot_inventory();
        let health = AgentHostHealth::ready(0, vec![]);
        let stats = serde_json::json!({
            "pressure": {
                "in_flight_creates": 3,
                "in_flight_restores": 1,
                "max_concurrent_creates": 8,
                "max_concurrent_restores": 8
            }
        });
        let report = host_report_from_observations(&inventory, &health, &stats);
        assert_eq!(report.pressure.in_flight_creates, 3);
        assert_eq!(report.pressure.in_flight_restores, 1);
    }

    #[test]
    fn maps_agent_health_statuses() {
        use pico_host_agent::health::HealthStatus as AgentHealthStatus;
        assert_eq!(
            map_agent_health(AgentHealthStatus::Ready),
            HostHealth::Healthy
        );
        assert_eq!(
            map_agent_health(AgentHealthStatus::Degraded),
            HostHealth::Degraded
        );
        assert_eq!(
            map_agent_health(AgentHealthStatus::Draining),
            HostHealth::Draining
        );
        assert_eq!(
            map_agent_health(AgentHealthStatus::Unsafe),
            HostHealth::Unavailable
        );
    }
}
