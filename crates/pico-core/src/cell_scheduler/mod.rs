//! Cell scheduler for host-level sandbox placement.
//!
//! Within a selected cell, the cell scheduler places each sandbox on a
//! specific host without overcommitting CPU, memory, disk, network, or
//! local cache capacity. It produces deterministic, traceable placement
//! decisions with weighted scoring and exposes capacity-pressure metrics
//! for observability.
//!
//! ## Design
//!
//! The scheduler operates in three phases:
//!
//! 1. **Hard constraint filtering** - hosts that cannot satisfy the request
//!    are eliminated (health, capacity, runtime support, draining/disabled
//!    state, process slots).
//! 2. **Weighted scoring** - surviving hosts are scored across multiple
//!    dimensions (capacity headroom, cache locality, create/restore pressure,
//!    sandbox spread, disk availability).
//! 3. **Selection** - the highest-scoring host is chosen; ties are broken
//!    deterministically by host ID for reproducibility.
//!
//! The [`HostInventory`] provides host registry management with automatic
//! stale-host expiry, ensuring that hosts which stop reporting capacity
//! are removed from scheduling consideration.

use hashbrown::HashMap;
use pico_telemetry::metrics::Labels;

use parking_lot::RwLock;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::identity::HostId;
use crate::in_flight::InFlightOverlay;
use crate::overcommit::{
    OvercommitPolicy, ServiceClass, effective_capacity_for_class, effective_memory_request,
};
use crate::placement_engine::{SelectionDetail, SelectionMode};
use crate::runtime::RuntimeType;
use crate::scheduler::SnapshotTimingHint;

// ---- Host Model ----

/// Health status of a host within a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHealth {
    /// Host is fully operational and can accept new workloads.
    Healthy,
    /// Host is operational but reporting degraded performance or partial failures.
    Degraded,
    /// Host is draining existing workloads and must not accept new placements.
    Draining,
    /// Host has been explicitly disabled for new placement by an operator.
    DisabledForPlacement,
    /// Host is unreachable or has failed.
    Unavailable,
    /// Host is quarantined due to active alerts from the host quarantine system.
    ///
    /// Quarantined hosts have triggered alert conditions (e.g., repeated runtime
    /// failures, stale resources, capacity reporting staleness) and must not
    /// receive new sandbox placements until the alerts are resolved.
    Quarantined,
}

impl HostHealth {
    /// Whether this host can accept new sandbox placements.
    pub fn can_admit(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::DisabledForPlacement => "disabled_for_placement",
            Self::Unavailable => "unavailable",
            Self::Quarantined => "quarantined",
        }
    }

    /// Overlay quarantine onto a placement snapshot.
    ///
    /// Already non-admitting states (drain, disable, unavailable, quarantined)
    /// are left unchanged so an operator drain is not rewritten.
    pub fn with_quarantine(self, quarantined: bool) -> Self {
        if quarantined && self.can_admit() {
            Self::Quarantined
        } else {
            self
        }
    }
}

/// Resource capacity of a host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCapacity {
    /// Total vCPUs on the host.
    pub total_vcpus: u64,
    /// vCPUs currently allocated to sandboxes.
    pub allocated_vcpus: u64,
    /// Total memory in MB.
    pub total_memory_mb: u64,
    /// Memory in MB currently allocated.
    pub allocated_memory_mb: u64,
    /// Total disk space in MB.
    pub total_disk_mb: u64,
    /// Disk space in MB currently used.
    pub used_disk_mb: u64,
    /// Total network bandwidth in Mbps.
    pub total_network_mbps: u64,
    /// Network bandwidth in Mbps currently allocated.
    pub allocated_network_mbps: u64,
    /// Maximum number of sandbox process slots.
    pub max_process_slots: u64,
    /// Process slots currently in use.
    pub used_process_slots: u64,
}

impl HostCapacity {
    fn headroom_ratio(used: u64, total: u64) -> f64 {
        if total == 0 {
            return 0.0;
        }
        let available = total.saturating_sub(used);
        available as f64 / total as f64
    }

    /// Fraction of vCPUs still available (0.0 to 1.0).
    pub fn vcpu_headroom(&self) -> f64 {
        Self::headroom_ratio(self.allocated_vcpus, self.total_vcpus)
    }

    /// Fraction of memory still available (0.0 to 1.0).
    pub fn memory_headroom(&self) -> f64 {
        Self::headroom_ratio(self.allocated_memory_mb, self.total_memory_mb)
    }

    /// Fraction of disk still available (0.0 to 1.0).
    pub fn disk_headroom(&self) -> f64 {
        Self::headroom_ratio(self.used_disk_mb, self.total_disk_mb)
    }

    /// Fraction of network bandwidth still available (0.0 to 1.0).
    pub fn network_headroom(&self) -> f64 {
        Self::headroom_ratio(self.allocated_network_mbps, self.total_network_mbps)
    }

    /// Fraction of process slots still available (0.0 to 1.0).
    pub fn process_slot_headroom(&self) -> f64 {
        Self::headroom_ratio(self.used_process_slots, self.max_process_slots)
    }

    /// Whether the host can accommodate the requested resources.
    pub fn can_fit(&self, vcpus: u32, memory_mb: u64, disk_mb: u64) -> bool {
        self.remaining_fit_count(vcpus, memory_mb, disk_mb) > 0
    }

    /// Whether disk and process slots fit, ignoring vCPU and memory.
    ///
    /// Attributes best-effort rejections: disk bytes are real and slots
    /// bound fd/process accounting, so neither is ever overcommitted. When
    /// these fixed resources reject, the failure is not about overcommit
    /// budget and the scheduler reports plain insufficient capacity
    /// instead of budget exhaustion.
    pub fn fits_fixed_resources(&self, disk_mb: u64) -> bool {
        self.total_disk_mb.saturating_sub(self.used_disk_mb) >= disk_mb
            && self
                .max_process_slots
                .saturating_sub(self.used_process_slots)
                >= 1
    }

    /// How many additional sandboxes of this shape fit without overcommit.
    ///
    /// Packing is the minimum of remaining vCPU, memory, disk, and process
    /// slots. A zero request in a dimension is treated as unbounded for that
    /// dimension so callers can probe a single resource.
    pub fn remaining_fit_count(&self, vcpus: u32, memory_mb: u64, disk_mb: u64) -> u64 {
        let vcpu = self
            .total_vcpus
            .saturating_sub(self.allocated_vcpus)
            .checked_div(u64::from(vcpus))
            .unwrap_or(u64::MAX);
        let memory = self
            .total_memory_mb
            .saturating_sub(self.allocated_memory_mb)
            .checked_div(memory_mb)
            .unwrap_or(u64::MAX);
        let disk = self
            .total_disk_mb
            .saturating_sub(self.used_disk_mb)
            .checked_div(disk_mb)
            .unwrap_or(u64::MAX);
        let slots = self
            .max_process_slots
            .saturating_sub(self.used_process_slots);
        vcpu.min(memory).min(disk).min(slots)
    }
}

/// Local image and snapshot cache state on a host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCacheState {
    /// Image IDs currently cached on this host.
    pub cached_images: Vec<String>,
    /// Snapshot IDs currently cached on this host.
    pub cached_snapshots: Vec<String>,
}

impl HostCacheState {
    /// Whether the requested image is cached locally.
    pub fn has_image(&self, image: &str) -> bool {
        self.cached_images.iter().any(|id| id == image)
    }

    /// Whether the requested snapshot is cached locally.
    pub fn has_snapshot(&self, snapshot: &str) -> bool {
        self.cached_snapshots.iter().any(|id| id == snapshot)
    }
}

/// Current create and restore pressure on a host.
///
/// Tracks the rate of in-flight operations to avoid overloading a single
/// host with concurrent create or restore operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct HostPressure {
    /// Number of sandbox create operations currently in progress.
    pub in_flight_creates: u32,
    /// Number of snapshot restore operations currently in progress.
    pub in_flight_restores: u32,
    /// Maximum concurrent create operations the host can handle.
    pub max_concurrent_creates: u32,
    /// Maximum concurrent restore operations the host can handle.
    pub max_concurrent_restores: u32,
}

impl HostPressure {
    /// Create pressure as a fraction (0.0 = idle, 1.0 = saturated).
    pub fn create_pressure(&self) -> f64 {
        if self.max_concurrent_creates == 0 {
            return 1.0;
        }
        self.in_flight_creates as f64 / self.max_concurrent_creates as f64
    }

    /// Restore pressure as a fraction (0.0 = idle, 1.0 = saturated).
    pub fn restore_pressure(&self) -> f64 {
        if self.max_concurrent_restores == 0 {
            return 1.0;
        }
        self.in_flight_restores as f64 / self.max_concurrent_restores as f64
    }

    /// Combined pressure as the maximum of create and restore pressure.
    pub fn combined_pressure(&self) -> f64 {
        self.create_pressure().max(self.restore_pressure())
    }

    /// Whether the host can accept a new create operation.
    pub fn can_accept_create(&self) -> bool {
        self.in_flight_creates < self.max_concurrent_creates
    }

    /// Whether the host can accept a new restore operation.
    pub fn can_accept_restore(&self) -> bool {
        self.in_flight_restores < self.max_concurrent_restores
    }
}

/// Complete information about a host available to the cell scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Host identifier.
    pub host_id: HostId,
    /// Current health status.
    pub health: HostHealth,
    /// Resource capacity and allocation.
    pub capacity: HostCapacity,
    /// Runtime backends supported by this host.
    pub supported_runtimes: Vec<RuntimeType>,
    /// Local image and snapshot cache state.
    pub cache: HostCacheState,
    /// Current create and restore pressure.
    pub pressure: HostPressure,
    /// Number of sandboxes currently running on this host.
    pub current_sandboxes: u64,
    /// Host-level snapshot timing hint (aggregate across sandboxes).
    ///
    /// Serde-defaults to [`SnapshotTimingHint::InsufficientData`] when absent.
    #[serde(default)]
    pub snapshot_timing_hint: SnapshotTimingHint,
}

// ---- Cell Scheduler Request ----

/// Input to the cell scheduler for a host placement decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellSchedulerRequest {
    /// Sandbox being scheduled.
    pub sandbox_id: String,
    /// Requested vCPUs.
    pub vcpus: u32,
    /// Requested memory in MB.
    pub memory_mb: u64,
    /// Requested disk space in MB.
    pub disk_mb: u64,
    /// Requested runtime backend (if any).
    pub runtime: Option<RuntimeType>,
    /// Container image or rootfs identifier.
    pub image: String,
    /// Snapshot to restore from (if any).
    pub snapshot_id: Option<String>,
    /// Whether this is a restore operation (affects pressure check).
    pub is_restore: bool,
    /// Scheduling service class for this sandbox.
    ///
    /// Serde-defaults to [`ServiceClass::LatencySensitive`] so payloads
    /// written before the CAP-168 track keep strict no-overcommit packing.
    /// Best-effort requests pack against overcommitted effective capacity
    /// only when the scheduler's [`OvercommitPolicy`] is enabled; the
    /// policy stays disabled unless a config explicitly enables it.
    #[serde(default)]
    pub service_class: ServiceClass,
}

// ---- Scoring ----

/// Scoring dimension identifiers for host-level placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostScoreDimension {
    /// Average headroom across CPU, memory, network, and process slots.
    CapacityHeadroom,
    /// Image and snapshot cache locality.
    CacheLocality,
    /// Create and restore operation pressure.
    Pressure,
    /// Prefer hosts with fewer sandboxes for even distribution.
    SandboxSpread,
    /// Disk space availability.
    DiskAvailability,
}

impl HostScoreDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapacityHeadroom => "capacity_headroom",
            Self::CacheLocality => "cache_locality",
            Self::Pressure => "pressure",
            Self::SandboxSpread => "sandbox_spread",
            Self::DiskAvailability => "disk_availability",
        }
    }

    pub const ALL: &[Self] = &[
        Self::CapacityHeadroom,
        Self::CacheLocality,
        Self::Pressure,
        Self::SandboxSpread,
        Self::DiskAvailability,
    ];
}

/// Individual scoring component for host placement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostScoreComponent {
    /// Name of the scoring dimension.
    pub name: HostScoreDimension,
    /// Weight of this component (0.0 to 1.0).
    pub weight: f64,
    /// Normalized score for this component (0.0 to 1.0).
    pub score: f64,
    /// Weighted contribution (weight * score).
    pub contribution: f64,
}

/// Complete scoring breakdown for a candidate host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostScoreBreakdown {
    /// Host that was scored.
    pub host_id: HostId,
    /// Individual scoring components.
    pub components: Vec<HostScoreComponent>,
    /// Total weighted score.
    pub total_score: f64,
}

/// Default scoring weights for the cell scheduler.
#[derive(Debug, Clone, Copy)]
pub struct CellScoringWeights {
    /// Weight for capacity headroom (higher = more headroom preferred).
    pub capacity_headroom: f64,
    /// Weight for cache locality (1.0 if cached, 0.0 if not).
    pub cache_locality: f64,
    /// Weight for low create/restore pressure (1.0 - pressure).
    pub pressure: f64,
    /// Weight for sandbox spread (fewer sandboxes = higher score).
    pub sandbox_spread: f64,
    /// Weight for disk availability.
    pub disk_availability: f64,
}

impl CellScoringWeights {
    /// Get the weight for a scoring dimension.
    pub fn weight_for(&self, dim: HostScoreDimension) -> f64 {
        match dim {
            HostScoreDimension::CapacityHeadroom => self.capacity_headroom,
            HostScoreDimension::CacheLocality => self.cache_locality,
            HostScoreDimension::Pressure => self.pressure,
            HostScoreDimension::SandboxSpread => self.sandbox_spread,
            HostScoreDimension::DiskAvailability => self.disk_availability,
        }
    }
}

impl Default for CellScoringWeights {
    fn default() -> Self {
        Self {
            capacity_headroom: 0.30,
            cache_locality: 0.25,
            pressure: 0.20,
            sandbox_spread: 0.10,
            disk_availability: 0.15,
        }
    }
}

// ---- Cell Scheduler Response ----

/// Why a host was chosen or why placement failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostPlacementReason {
    /// Host scored highest across weighted dimensions.
    BestScore,
    /// Host was the only one that passed hard constraints.
    OnlyCandidate,
    /// Host was chosen because it has the requested image or snapshot cached.
    CacheHit,
    /// No host could satisfy the request.
    NoHostAvailable { reason: String },
}

/// Rejection detail for a single host that was filtered out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRejection {
    /// Host that was rejected.
    pub host_id: HostId,
    /// Human-readable reason for rejection.
    pub reason: String,
}

/// Result of a cell-level host placement decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellSchedulerResponse {
    /// Whether placement succeeded.
    pub placed: bool,
    /// Selected host (if placement succeeded).
    pub host_id: Option<HostId>,
    /// Why this host was chosen or why placement failed.
    pub reason: HostPlacementReason,
    /// Score breakdown for the selected host (for observability).
    pub score_breakdown: Option<HostScoreBreakdown>,
    /// All candidate scores (for debugging and capacity modelling).
    pub candidate_scores: Vec<HostScoreBreakdown>,
    /// Hosts that were rejected and why (for observability).
    pub rejections: Vec<HostRejection>,
    /// Backpressure signal for the cell admission path.
    pub backpressure: CellBackpressureSignal,
    /// Placement metrics for observability.
    pub metrics: PlacementMetrics,
    /// How the winner was chosen (full best or power-of-k sample).
    pub selection: SelectionDetail,
    /// Whether any candidate capacity was adjusted by the in-flight overlay.
    pub overlay_adjusted: bool,
    /// Service class of the admitted request (echoed for observability).
    ///
    /// Serde-defaults to [`ServiceClass::LatencySensitive`].
    #[serde(default)]
    pub service_class: ServiceClass,
    /// True when a best-effort request was admitted beyond strict
    /// no-overcommit capacity via the [`OvercommitPolicy`] gate.
    ///
    /// S-NOISY evidence uses this bit to separate strict admits from
    /// overcommit admits. Serde-defaults to false.
    #[serde(default)]
    pub overcommit_applied: bool,
}

/// Backpressure signal from the cell scheduler.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct CellBackpressureSignal {
    /// Fraction of hosts that passed hard constraints (0.0 to 1.0).
    pub host_admission_rate: f64,
    /// Average headroom across surviving hosts.
    pub avg_headroom: f64,
    /// Whether the cell scheduler recommends rejecting new requests.
    pub should_throttle: bool,
    /// Number of hosts evaluated.
    pub total_hosts: usize,
    /// Number of hosts that passed hard constraints.
    pub eligible_hosts: usize,
}

impl CellBackpressureSignal {
    /// Threshold below which the scheduler recommends throttling.
    pub const THROTTLE_THRESHOLD: f64 = 0.15;

    /// Threshold below which headroom triggers throttle.
    pub const HEADROOM_THRESHOLD: f64 = 0.10;
}

// ---- Placement Errors ----

/// Actionable placement failure reasons returned by the cell scheduler.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum CellSchedulerError {
    /// No hosts are registered in the inventory.
    #[error("no hosts available in cell")]
    NoHostsAvailable,

    /// All hosts were filtered out by hard constraints.
    #[error("no host can satisfy constraints: {reason}")]
    NoHostSatisfiesConstraints { reason: String },

    /// The requested runtime backend is not supported by any host.
    #[error("no host supports runtime backend: {runtime}")]
    UnsupportedRuntime { runtime: String },

    /// All hosts have insufficient capacity for the requested resources.
    #[error("insufficient capacity: need {vcpus} vCPUs, {memory_mb} MB memory, {disk_mb} MB disk")]
    InsufficientCapacity {
        vcpus: u32,
        memory_mb: u64,
        disk_mb: u64,
    },

    /// All eligible hosts are draining or disabled.
    #[error("all hosts are draining or disabled for placement")]
    AllHostsDraining,

    /// All eligible hosts have saturated create/restore pressure.
    #[error("all hosts have saturated create/restore pressure")]
    PressureSaturated,

    /// The configured overcommit policy is invalid.
    #[error("invalid overcommit policy: {reason}")]
    InvalidOvercommitPolicy { reason: String },
}

impl CellSchedulerError {
    /// Whether this error is throttled (retryable) and must carry `Retry-After`.
    pub fn is_throttled(&self) -> bool {
        matches!(
            self,
            Self::InsufficientCapacity { .. } | Self::PressureSaturated | Self::NoHostsAvailable
        )
    }
}

// ---- Observability ----

/// Placement metrics collected during a scheduling decision.
///
/// Returned on successful placement. [`CellScheduler::schedule`] also
/// records evaluated/passed histograms on success and on reject so
/// `PicoComputeCellCannotPlace` can fire when hosts are considered but none
/// pass. Empty snapshots are not recorded (evaluated ~ 0 is inventory loss).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlacementMetrics {
    /// Wall-clock placement decision latency in microseconds.
    pub placement_latency_us: u64,
    /// Score of the selected host (or 0.0 if placement failed).
    pub selected_host_score: f64,
    /// Number of hosts evaluated.
    pub hosts_evaluated: usize,
    /// Number of hosts that passed hard constraints.
    pub hosts_passed_constraints: usize,
    /// Rejection counts grouped by reason category.
    pub rejection_counts: Vec<RejectionCount>,
    /// Average capacity pressure across evaluated hosts.
    pub avg_capacity_pressure: f64,
}

impl PlacementMetrics {
    /// Record placement metrics to the observability backend.
    ///
    /// Host-level aggregates: placement spans the whole cell, so these carry no
    /// identity attribute.
    pub fn record(&self) {
        let m = &crate::metrics::CORE_METRICS;
        let labels = Labels::host();
        m.placement_latency
            .record(self.placement_latency_us as f64 / 1_000_000.0, &labels);
        m.hosts_evaluated
            .record(self.hosts_evaluated as f64, &labels);
        m.hosts_passed
            .record(self.hosts_passed_constraints as f64, &labels);
    }
}

/// Count of rejections for a specific reason category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectionCount {
    /// Reason category.
    pub reason: String,
    /// Number of hosts rejected for this reason.
    pub count: usize,
}

// ---- Host Inventory ----

/// Internal entry tracking a host and its last-seen timestamp.
#[derive(Debug, Clone)]
struct HostEntry {
    info: HostInfo,
    last_seen: OffsetDateTime,
}

/// Host inventory with automatic stale-host expiry.
///
/// Tracks hosts within a cell, their capacity reports, and last-seen
/// timestamps. Hosts that have not reported within the configured TTL
/// are automatically expired during refresh operations.
pub struct HostInventory {
    entries: RwLock<HashMap<String, HostEntry>>,
    stale_ttl_secs: i64,
}

impl HostInventory {
    /// Creates a new empty host inventory.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            stale_ttl_secs: 60,
        }
    }

    /// Creates a new host inventory with a custom stale-host TTL.
    pub fn with_stale_ttl(stale_ttl_secs: i64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            stale_ttl_secs,
        }
    }

    /// Registers or updates a host in the inventory.
    pub fn upsert(&self, host: HostInfo, now: OffsetDateTime) {
        let key = host.host_id.as_str().to_string();
        let mut entries = self.entries.write();
        entries.insert(
            key,
            HostEntry {
                info: host,
                last_seen: now,
            },
        );
    }

    /// Removes a host from the inventory.
    pub fn remove(&self, host_id: &HostId) -> Option<HostInfo> {
        let mut entries = self.entries.write();
        entries.remove(host_id.as_str()).map(|e| e.info)
    }

    /// Returns a snapshot of all hosts currently in the inventory.
    pub fn snapshot(&self) -> Vec<HostInfo> {
        let entries = self.entries.read();
        entries.values().map(|e| e.info.clone()).collect()
    }

    /// Returns the number of hosts in the inventory.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns true if the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Expires hosts that have not reported within the TTL.
    ///
    /// Returns the host IDs that were expired.
    pub fn expire_stale(&self, now: OffsetDateTime) -> Vec<HostId> {
        let ttl = time::Duration::seconds(self.stale_ttl_secs);
        let mut entries = self.entries.write();
        let stale_keys: Vec<String> = entries
            .iter()
            .filter(|(_, entry)| now - entry.last_seen > ttl)
            .map(|(key, _)| key.clone())
            .collect();

        let expired_ids: Vec<HostId> = stale_keys
            .iter()
            .filter_map(|key| entries.get(key).map(|e| e.info.host_id.clone()))
            .collect();

        for key in &stale_keys {
            entries.remove(key);
        }

        expired_ids
    }

    /// Refreshes a host's capacity report and last-seen timestamp.
    ///
    /// If the host is not in the inventory, this is a no-op.
    pub fn refresh_capacity(&self, host_id: &HostId, capacity: HostCapacity, now: OffsetDateTime) {
        self.update_host(host_id, now, |entry| entry.info.capacity = capacity);
    }

    /// Refreshes a host's pressure report and last-seen timestamp.
    pub fn refresh_pressure(&self, host_id: &HostId, pressure: HostPressure, now: OffsetDateTime) {
        self.update_host(host_id, now, |entry| entry.info.pressure = pressure);
    }

    /// Updates a host's health status and last-seen timestamp.
    pub fn update_health(&self, host_id: &HostId, health: HostHealth, now: OffsetDateTime) {
        self.update_host(host_id, now, |entry| entry.info.health = health);
    }

    /// Refreshes a host's snapshot timing hint from stats/heartbeat.
    ///
    /// No-op if the host is not in the inventory.
    pub fn refresh_snapshot_timing(
        &self,
        host_id: &HostId,
        hint: SnapshotTimingHint,
        now: OffsetDateTime,
    ) {
        self.update_host(host_id, now, |entry| {
            entry.info.snapshot_timing_hint = hint;
        });
    }

    /// Most conservative snapshot timing hint across registered hosts.
    ///
    /// Intended for populating [`crate::scheduler::CellInfo`]. Call sites must
    /// use a per-cell [`HostInventory`] instance (this type tracks hosts within
    /// one cell); do not aggregate a multi-cell registry into a single cell.
    pub fn aggregate_snapshot_timing(&self) -> SnapshotTimingHint {
        let entries = self.entries.read();
        SnapshotTimingHint::aggregate(entries.values().map(|e| e.info.snapshot_timing_hint))
    }

    fn update_host(
        &self,
        host_id: &HostId,
        now: OffsetDateTime,
        update: impl FnOnce(&mut HostEntry),
    ) {
        let key = host_id.as_str().to_string();
        let mut entries = self.entries.write();
        if let Some(entry) = entries.get_mut(&key) {
            update(entry);
            entry.last_seen = now;
        }
    }
}

impl Default for HostInventory {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Cell Scheduler ----

/// Cell scheduler that selects hosts for sandbox placement within a cell.
///
/// The scheduler is stateless with respect to host state: it receives
/// a snapshot of host information at scheduling time and produces a
/// placement decision. Host state is managed by [`HostInventory`] and
/// passed in on each scheduling call.
///
/// Burst hardening is local to each instance: the winner policy
/// ([`SelectionMode`], default full best) and an [`InFlightOverlay`] of this
/// instance's recent placements fold unreported load back into the snapshot
/// before filtering and scoring. Instances never coordinate with each other;
/// the host keeps final admission authority over stale estimates.
pub struct CellScheduler {
    weights: CellScoringWeights,
    max_pressure: f64,
    audit_sink: Option<std::sync::Arc<dyn crate::event_bus::AuditEventSink>>,
    hlc: std::sync::Arc<crate::identity::Hlc>,
    /// How the winning host is chosen from scored survivors.
    selection: SelectionMode,
    /// This instance's recent placements, folded into snapshots.
    overlay: parking_lot::Mutex<InFlightOverlay>,
    /// Instance RNG for power-of-k sampling (OS-seeded; tests override).
    rng: parking_lot::Mutex<rand::rngs::SmallRng>,
    /// Gated best-effort overcommit policy (disabled by default).
    ///
    /// While disabled, every request packs strict no-overcommit regardless
    /// of [`CellSchedulerRequest::service_class`].
    overcommit: OvercommitPolicy,
}

impl CellScheduler {
    /// Creates a new cell scheduler with default weights.
    pub fn new() -> Self {
        Self {
            weights: CellScoringWeights::default(),
            max_pressure: 0.90,
            audit_sink: None,
            hlc: std::sync::Arc::new(crate::identity::Hlc::new()),
            selection: SelectionMode::Best,
            overlay: parking_lot::Mutex::new(InFlightOverlay::new()),
            rng: parking_lot::Mutex::new(rand::make_rng()),
            overcommit: OvercommitPolicy::default(),
        }
    }

    /// Creates a new cell scheduler with custom weights.
    pub fn with_weights(weights: CellScoringWeights) -> Self {
        Self {
            weights,
            max_pressure: 0.90,
            audit_sink: None,
            hlc: std::sync::Arc::new(crate::identity::Hlc::new()),
            selection: SelectionMode::Best,
            overlay: parking_lot::Mutex::new(InFlightOverlay::new()),
            rng: parking_lot::Mutex::new(rand::make_rng()),
            overcommit: OvercommitPolicy::default(),
        }
    }

    /// Sets the maximum create/restore pressure threshold.
    pub fn with_max_pressure(mut self, threshold: f64) -> Self {
        self.max_pressure = threshold;
        self
    }

    /// Sets how the winning host is chosen from scored survivors.
    ///
    /// [`SelectionMode::Best`] keeps full scoring with deterministic
    /// tie-break. [`SelectionMode::PowerOfK`] samples `k` eligible hosts
    /// and picks the best of the sample to spread bursty placements.
    pub fn with_selection(mut self, selection: SelectionMode) -> Self {
        self.selection = selection;
        self
    }

    /// Sets the gated best-effort overcommit policy.
    ///
    /// The default policy is disabled, which keeps strict no-overcommit
    /// packing for every request class. The policy is validated when
    /// scheduling starts; an invalid policy fails placement closed with
    /// [`CellSchedulerError::InvalidOvercommitPolicy`].
    pub fn with_overcommit_policy(mut self, policy: OvercommitPolicy) -> Self {
        self.overcommit = policy;
        self
    }

    /// Returns the configured overcommit policy.
    pub fn overcommit_policy(&self) -> OvercommitPolicy {
        self.overcommit
    }

    /// Seeds the sampling RNG deterministically (tests).
    ///
    /// Production instances keep the OS seed from construction so
    /// concurrent schedulers diverge instead of herding.
    pub fn with_sampling_seed(mut self, seed: u64) -> Self {
        *self.rng.get_mut() = rand::rngs::SmallRng::seed_from_u64(seed);
        self
    }

    /// Overrides the in-flight overlay entry lifetime and bound.
    ///
    /// A zero bound disables overlay recording, which restores the old
    /// stale-snapshot herding behavior; prefer the default outside tests
    /// that pin the pre-overlay baseline.
    pub fn with_overlay_limits(mut self, ttl_secs: i64, max_entries: usize) -> Self {
        *self.overlay.get_mut() = InFlightOverlay::with_limits(ttl_secs, max_entries);
        self
    }

    /// Drops the in-flight entry for a host whose assignment settled.
    ///
    /// Call when the downstream placement is accepted and reflected in a
    /// fresh snapshot, or finally rejected, so later decisions stop
    /// double-counting it ahead of the overlay TTL. Returns true when an
    /// entry existed.
    pub fn acknowledge_placement(&self, host_id: &str) -> bool {
        self.overlay.lock().release(host_id)
    }

    /// Folds this instance's unreported placements into a host snapshot.
    fn apply_overlay(
        host: &HostInfo,
        overlay: &InFlightOverlay,
        now: OffsetDateTime,
    ) -> (HostInfo, bool) {
        let Some(reserved) = overlay.reserved_for(host.host_id.as_str(), now) else {
            return (host.clone(), false);
        };
        let mut adjusted = host.clone();
        adjusted.capacity.allocated_vcpus = adjusted
            .capacity
            .allocated_vcpus
            .saturating_add(reserved.vcpus);
        adjusted.capacity.allocated_memory_mb = adjusted
            .capacity
            .allocated_memory_mb
            .saturating_add(reserved.memory_mb);
        adjusted.capacity.used_disk_mb = adjusted
            .capacity
            .used_disk_mb
            .saturating_add(reserved.disk_mb);
        adjusted.capacity.used_process_slots = adjusted
            .capacity
            .used_process_slots
            .saturating_add(reserved.count);
        adjusted.current_sandboxes = adjusted.current_sandboxes.saturating_add(reserved.count);
        // Create/restore pressure is intentionally left to the reported
        // snapshot: it measures ops in progress, while the overlay reserves
        // capacity for placements whose reports have not arrived yet. Folding
        // reservations into pressure would shed on hosts that already
        // finished booting but whose reports are still in flight.
        (adjusted, true)
    }

    /// Set an audit event sink for emitting placement outcome events.
    pub fn with_audit_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::event_bus::AuditEventSink>,
        hlc: std::sync::Arc<crate::identity::Hlc>,
    ) -> Self {
        self.audit_sink = Some(sink);
        self.hlc = hlc;
        self
    }

    /// Schedule a sandbox placement across the given hosts.
    ///
    /// Evaluates all hosts against hard constraints, scores survivors,
    /// and returns a placement decision with full traceability.
    pub fn schedule(
        &self,
        request: &CellSchedulerRequest,
        hosts: &[HostInfo],
    ) -> Result<CellSchedulerResponse, CellSchedulerError> {
        self.schedule_with_context(request, hosts, None)
    }

    /// Schedule with create-path trace correlation.
    ///
    /// Carries trace, operation, and idempotency identity into placement
    /// audit events. Rejection reasons stay typed in the error; the audit
    /// event carries the same reason. Emission is best-effort and never
    /// fails placement. Before evaluation, this instance's in-flight
    /// overlay folds unreported placements into the snapshot; the winner
    /// policy then applies.
    #[tracing::instrument(skip(self, request, hosts, context), fields(sandbox_id = %request.sandbox_id, sampled_k = tracing::field::Empty, overlay_adjusted = tracing::field::Empty))]
    pub fn schedule_with_context(
        &self,
        request: &CellSchedulerRequest,
        hosts: &[HostInfo],
        context: Option<&crate::scheduler::ScheduleTraceContext>,
    ) -> Result<CellSchedulerResponse, CellSchedulerError> {
        let start = OffsetDateTime::now_utc();
        if let Err(err) = self.overcommit.validate() {
            return Err(CellSchedulerError::InvalidOvercommitPolicy {
                reason: err.to_string(),
            });
        }
        let sampled_k = match self.selection {
            SelectionMode::Best => None,
            SelectionMode::PowerOfK { k } => Some(k),
        };

        if hosts.is_empty() {
            tracing::Span::current().record("sampled_k", sampled_k);
            tracing::Span::current().record("overlay_adjusted", false);
            self.emit_outcome_with_context(
                request,
                None,
                "no_host_available",
                None,
                0,
                SelectionDetail {
                    sampled: false,
                    sample_size: 0,
                    eligible: 0,
                },
                false,
                context,
            );
            return Err(CellSchedulerError::NoHostsAvailable);
        }

        // Fold this instance's recent placements into the snapshot so a
        // burst spreads across consecutive decisions even when the snapshot
        // does not move. Adjusted rows are scheduler-local; the input slice
        // is never mutated.
        let overlay = self.overlay.lock();
        let mut overlay_adjusted = false;
        let adjusted: Vec<HostInfo> = hosts
            .iter()
            .map(|host| {
                let (row, hit) = Self::apply_overlay(host, &overlay, start);
                overlay_adjusted |= hit;
                row
            })
            .collect();
        drop(overlay);

        // Compute max_sandboxes for spread scoring
        let max_sandboxes = adjusted
            .iter()
            .map(|h| h.current_sandboxes)
            .max()
            .unwrap_or(0);

        // Single evaluation point: one constraint check and one scoring pass
        // per candidate. Headroom derives from the stored breakdown.
        let outcome = crate::placement_engine::place_sampled_with_breakdown(
            &adjusted,
            |host| match self.check_hard_constraints(host, request) {
                Ok(()) => crate::placement_engine::ConstraintResult::Pass,
                Err(reason) => crate::placement_engine::ConstraintResult::Fail(reason),
            },
            |host| self.score_host(host, request, max_sandboxes),
            Self::headroom_from_breakdown,
            |host| host.host_id.as_str(),
            |breakdown| breakdown.total_score,
            self.selection,
            &mut *self.rng.lock(),
        );
        tracing::Span::current().record("sampled_k", sampled_k);
        tracing::Span::current().record("overlay_adjusted", overlay_adjusted);

        if outcome.selected.is_none() {
            let rejections: Vec<HostRejection> = outcome
                .rejections
                .iter()
                .map(|(h, reason)| HostRejection {
                    host_id: h.host_id.clone(),
                    reason: reason.clone(),
                })
                .collect();
            let elapsed = OffsetDateTime::now_utc() - start;
            PlacementMetrics {
                placement_latency_us: elapsed.whole_microseconds() as u64,
                selected_host_score: 0.0,
                hosts_evaluated: outcome.backpressure.total_candidates,
                hosts_passed_constraints: 0,
                rejection_counts: Self::aggregate_rejections(&rejections),
                avg_capacity_pressure: Self::compute_avg_pressure(hosts),
            }
            .record();
            let err = self.classify_rejection(request, &outcome.rejections);
            tracing::warn!(reason = %err, "cell placement rejected");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                outcome.selection,
                overlay_adjusted,
                context,
            );
            return Err(err);
        }

        let Some(selected_host) = outcome.selected else {
            let err = CellSchedulerError::NoHostSatisfiesConstraints {
                reason: "placement invariant violated: selected missing".into(),
            };
            tracing::warn!(reason = %err, "cell placement invariant violated");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                outcome.selection,
                overlay_adjusted,
                context,
            );
            return Err(err);
        };
        let Some(best_idx) = outcome
            .scored
            .iter()
            .position(|s| s.candidate.host_id == selected_host.host_id)
        else {
            let err = CellSchedulerError::NoHostSatisfiesConstraints {
                reason: "placement invariant violated: selected host not scored".into(),
            };
            tracing::warn!(reason = %err, "cell placement invariant violated");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                outcome.selection,
                overlay_adjusted,
                context,
            );
            return Err(err);
        };

        // Scores already computed once; reuse breakdowns directly.
        let best_score = outcome.scored[best_idx].total_score;
        let reason =
            self.determine_reason_from_outcome(&outcome, &outcome.scored[best_idx].breakdown);
        let backpressure_cached = outcome.backpressure;
        let scores: Vec<HostScoreBreakdown> =
            outcome.scored.into_iter().map(|s| s.breakdown).collect();
        let best = &scores[best_idx];

        let backpressure = CellBackpressureSignal {
            host_admission_rate: backpressure_cached.admission_rate,
            avg_headroom: backpressure_cached.avg_headroom,
            should_throttle: backpressure_cached.should_throttle,
            total_hosts: backpressure_cached.total_candidates,
            eligible_hosts: backpressure_cached.eligible_candidates,
        };

        let elapsed = OffsetDateTime::now_utc() - start;
        let latency_us = elapsed.whole_microseconds() as u64;

        let host_rejections: Vec<HostRejection> = outcome
            .rejections
            .iter()
            .map(|(h, reason)| HostRejection {
                host_id: h.host_id.clone(),
                reason: reason.clone(),
            })
            .collect();

        let rejection_counts = Self::aggregate_rejections(&host_rejections);
        let avg_pressure = Self::compute_avg_pressure(hosts);

        let metrics = PlacementMetrics {
            placement_latency_us: latency_us,
            selected_host_score: best_score,
            hosts_evaluated: backpressure_cached.total_candidates,
            hosts_passed_constraints: backpressure_cached.eligible_candidates,
            rejection_counts,
            avg_capacity_pressure: avg_pressure,
        };
        let selection = outcome.selection;

        // Record this decision locally so the next decision from this
        // instance sees the load even when the snapshot has not refreshed.
        // The host keeps final admission authority; a stale estimate that
        // slips through fails closed at boot with a typed reason.
        self.overlay.lock().record(
            selected_host.host_id.as_str(),
            u64::from(request.vcpus),
            request.memory_mb,
            request.disk_mb,
            start,
        );

        let response = CellSchedulerResponse {
            placed: true,
            host_id: Some(selected_host.host_id.clone()),
            reason: reason.clone(),
            score_breakdown: Some(best.clone()),
            candidate_scores: scores,
            rejections: host_rejections,
            backpressure,
            metrics,
            selection,
            overlay_adjusted,
            service_class: request.service_class,
            // True only when the winner could not have fit this request
            // strict: the admit consumed overcommit budget.
            overcommit_applied: request.service_class.is_best_effort()
                && self.overcommit.enabled
                && !selected_host.capacity.can_fit(
                    request.vcpus,
                    request.memory_mb,
                    request.disk_mb,
                ),
        };

        response.metrics.record();
        tracing::info!(
            host_id = ?response.host_id,
            reason = ?reason,
            score = best_score,
            sampled = selection.sampled,
            sample_size = selection.sample_size,
            overlay_adjusted = overlay_adjusted,
            service_class = ?response.service_class,
            overcommit_applied = response.overcommit_applied,
            "cell placement admitted"
        );
        self.emit_outcome_with_context(
            request,
            response.host_id.as_ref().map(|h| h.as_str().to_string()),
            format!("{reason:?}"),
            Some(best_score),
            backpressure_cached.eligible_candidates,
            selection,
            overlay_adjusted,
            context,
        );

        Ok(response)
    }

    /// Emits the placement outcome audit event when a sink is attached.
    ///
    /// Carries the winner policy and overlay state so sampled placements
    /// stay reconstructible from audit alone.
    #[expect(
        clippy::too_many_arguments,
        reason = "private audit-emission sink; every argument maps to one audit field and bundling would hide the event contract"
    )]
    fn emit_outcome_with_context(
        &self,
        request: &CellSchedulerRequest,
        host_id: Option<String>,
        reason: impl Into<String>,
        score: Option<f64>,
        candidates_evaluated: usize,
        selection: SelectionDetail,
        overlay_adjusted: bool,
        context: Option<&crate::scheduler::ScheduleTraceContext>,
    ) {
        if let Some(ref sink) = self.audit_sink {
            crate::event_bus::emit_placement_outcome(
                sink.as_ref(),
                &self.hlc,
                crate::event_bus::PlacementOutcomeParams {
                    sandbox_id: request.sandbox_id.clone(),
                    tenant_id: None,
                    cell_id: None,
                    host_id,
                    reason: reason.into(),
                    score,
                    candidates_evaluated,
                    sampled: selection.sampled,
                    sample_size: selection.sample_size,
                    eligible: selection.eligible,
                    overlay_adjusted,
                    trace_id: context.and_then(|c| c.trace_id.clone()),
                    operation_id: context.and_then(|c| c.operation_id.clone()),
                    idempotency_key: context.and_then(|c| c.idempotency_key.clone()),
                },
            );
        }
    }

    /// Headroom derived from the stored breakdown (no candidate recompute).
    ///
    /// The candidate argument exists for the shared engine signature and is ignored.
    fn headroom_from_breakdown(_host: &HostInfo, breakdown: &HostScoreBreakdown) -> f64 {
        breakdown
            .components
            .iter()
            .find(|c| c.name == HostScoreDimension::CapacityHeadroom)
            .map(|c| c.score)
            .unwrap_or(0.0)
    }

    /// Determines the placement reason from the outcome.
    fn determine_reason_from_outcome(
        &self,
        outcome: &crate::placement_engine::PlacementOutcomeWithBreakdown<
            '_,
            HostInfo,
            HostScoreBreakdown,
        >,
        best: &HostScoreBreakdown,
    ) -> HostPlacementReason {
        if outcome.scored.len() == 1 {
            return HostPlacementReason::OnlyCandidate;
        }

        let cache_component = best
            .components
            .iter()
            .find(|c| c.name == HostScoreDimension::CacheLocality);
        if let Some(comp) = cache_component
            && (comp.score - 1.0).abs() < f64::EPSILON
            && comp.contribution > 0.2
        {
            return HostPlacementReason::CacheHit;
        }

        HostPlacementReason::BestScore
    }

    /// Single constraint evaluation point for cell placement.
    ///
    /// All hard-constraint logic lives here so a fix lands once. The
    /// placement-engine filter calls this exactly once per candidate, and
    /// [`Self::classify_rejection`] derives typed errors from the returned
    /// rejection strings instead of re-implementing these checks.
    ///
    /// Best-effort requests pack against overcommitted effective capacity
    /// (scaled vCPU/memory totals plus the shared-base discount) only when
    /// the overcommit policy is enabled; every other combination packs
    /// strict. The budget-exhausted rejection names overcommit only when
    /// the fixed resources (disk, slots) fit, so a disk- or slot-bound
    /// failure is never misattributed to budget. Both rejection strings
    /// keep the `capacity` keyword so [`Self::categorize_rejection`]
    /// still maps them to `insufficient_capacity`.
    ///
    /// Returns `Ok(())` if the host passes, or `Err(reason)` with a
    /// human-readable rejection reason.
    fn check_hard_constraints(
        &self,
        host: &HostInfo,
        request: &CellSchedulerRequest,
    ) -> Result<(), String> {
        if !host.health.can_admit() {
            return Err(format!("host is {}", host.health.as_str()));
        }

        let memory_req =
            effective_memory_request(request.memory_mb, request.service_class, &self.overcommit);
        let effective =
            effective_capacity_for_class(&host.capacity, request.service_class, &self.overcommit);
        if !effective.can_fit(request.vcpus, memory_req, request.disk_mb) {
            if request.service_class.is_best_effort()
                && self.overcommit.enabled
                && host.capacity.fits_fixed_resources(request.disk_mb)
            {
                return Err(
                    "insufficient capacity (best-effort overcommit budget exhausted)".into(),
                );
            }
            return Err("insufficient capacity".into());
        }

        if let Some(ref runtime) = request.runtime
            && !host.supported_runtimes.contains(runtime)
        {
            return Err(format!("unsupported runtime: {runtime:?}"));
        }

        if request.is_restore && !host.pressure.can_accept_restore() {
            return Err("restore pressure saturated".into());
        }

        if !request.is_restore && !host.pressure.can_accept_create() {
            return Err("create pressure saturated".into());
        }

        let combined = host.pressure.combined_pressure();
        if combined > self.max_pressure {
            return Err(format!(
                "pressure {combined:.2} exceeds threshold {:.2}",
                self.max_pressure
            ));
        }

        Ok(())
    }

    /// Scores a single host across all weighted dimensions.
    fn score_host(
        &self,
        host: &HostInfo,
        request: &CellSchedulerRequest,
        max_sandboxes: u64,
    ) -> HostScoreBreakdown {
        let mut components = Vec::with_capacity(5);

        let headroom = (host.capacity.vcpu_headroom()
            + host.capacity.memory_headroom()
            + host.capacity.network_headroom()
            + host.capacity.process_slot_headroom())
            / 4.0;
        components.push(self.make_component(
            HostScoreDimension::CapacityHeadroom,
            self.weights.capacity_headroom,
            headroom,
        ));

        let cache_score = self.compute_cache_score(host, request);
        components.push(self.make_component(
            HostScoreDimension::CacheLocality,
            self.weights.cache_locality,
            cache_score,
        ));

        let pressure_score = 1.0 - host.pressure.combined_pressure();
        components.push(self.make_component(
            HostScoreDimension::Pressure,
            self.weights.pressure,
            pressure_score,
        ));

        let spread_score = if max_sandboxes > 0 {
            1.0 - (host.current_sandboxes as f64 / max_sandboxes as f64)
        } else {
            1.0
        };
        components.push(self.make_component(
            HostScoreDimension::SandboxSpread,
            self.weights.sandbox_spread,
            spread_score,
        ));

        let disk_score = host.capacity.disk_headroom();
        components.push(self.make_component(
            HostScoreDimension::DiskAvailability,
            self.weights.disk_availability,
            disk_score,
        ));

        let total_score: f64 = components.iter().map(|c| c.contribution).sum();

        HostScoreBreakdown {
            host_id: host.host_id.clone(),
            components,
            total_score,
        }
    }

    fn compute_cache_score(&self, host: &HostInfo, request: &CellSchedulerRequest) -> f64 {
        let image_hit = if host.cache.has_image(&request.image) {
            1.0
        } else {
            0.0
        };

        let snapshot_hit = match &request.snapshot_id {
            Some(snap) if host.cache.has_snapshot(snap) => 1.0,
            Some(_) => 0.0,
            None => 0.5,
        };

        match &request.snapshot_id {
            Some(_) => image_hit * 0.4 + snapshot_hit * 0.6,
            None => image_hit,
        }
    }

    fn make_component(
        &self,
        name: HostScoreDimension,
        weight: f64,
        score: f64,
    ) -> HostScoreComponent {
        HostScoreComponent {
            name,
            weight,
            score,
            contribution: weight * score,
        }
    }

    /// Classifies why all hosts were rejected from single-evaluation rejections.
    ///
    /// Derives the typed error from `rejections` categories (produced by
    /// [`Self::check_hard_constraints`]) instead of re-evaluating host fields,
    /// so constraint fixes land once. Throttled causes (`capacity`,
    /// `pressure`) map to retryable variants preserving the `Retry-After`
    /// hint; draining/disabled and unsupported runtimes stay hard rejections.
    ///
    /// Priority mirrors the regional scheduler: health, then runtime-only,
    /// then capacity, then pressure. Capacity implies a runtime supporter
    /// exists, so mixed runtime+capacity still throttles on the capacity bound;
    /// per-host rejection strings retain the runtime detail.
    fn classify_rejection(
        &self,
        request: &CellSchedulerRequest,
        rejections: &[(&HostInfo, String)],
    ) -> CellSchedulerError {
        if rejections.is_empty() {
            return CellSchedulerError::NoHostSatisfiesConstraints {
                reason: "all hosts filtered by constraints".into(),
            };
        }

        let categories: Vec<&'static str> = rejections
            .iter()
            .map(|(_, reason)| Self::categorize_rejection(reason))
            .collect();

        let is_health = |c: &&'static str| {
            matches!(
                *c,
                "unavailable" | "draining" | "disabled_for_placement" | "quarantined"
            )
        };
        let all_health = categories.iter().all(is_health);
        if all_health {
            let all_draining = categories
                .iter()
                .all(|c| matches!(*c, "draining" | "disabled_for_placement"));
            if all_draining {
                return CellSchedulerError::AllHostsDraining;
            }
            return CellSchedulerError::NoHostSatisfiesConstraints {
                reason: "all hosts are unavailable".into(),
            };
        }

        let admittable: Vec<&'static str> = categories
            .iter()
            .copied()
            .filter(|c| {
                !matches!(
                    *c,
                    "unavailable" | "draining" | "disabled_for_placement" | "quarantined"
                )
            })
            .collect();

        if let Some(ref runtime) = request.runtime
            && !admittable.is_empty()
            && admittable.iter().all(|c| *c == "unsupported_runtime")
        {
            return CellSchedulerError::UnsupportedRuntime {
                runtime: format!("{runtime:?}"),
            };
        }

        if admittable.contains(&"insufficient_capacity") {
            return CellSchedulerError::InsufficientCapacity {
                vcpus: request.vcpus,
                memory_mb: request.memory_mb,
                disk_mb: request.disk_mb,
            };
        }

        if admittable.contains(&"pressure_saturated") {
            return CellSchedulerError::PressureSaturated;
        }

        if categories.contains(&"insufficient_capacity") {
            return CellSchedulerError::InsufficientCapacity {
                vcpus: request.vcpus,
                memory_mb: request.memory_mb,
                disk_mb: request.disk_mb,
            };
        }
        if categories.contains(&"pressure_saturated") {
            return CellSchedulerError::PressureSaturated;
        }

        if let Some(ref runtime) = request.runtime
            && categories.contains(&"unsupported_runtime")
        {
            return CellSchedulerError::UnsupportedRuntime {
                runtime: format!("{runtime:?}"),
            };
        }

        let reasons: Vec<&str> = rejections.iter().map(|(_, r)| r.as_str()).collect();
        CellSchedulerError::NoHostSatisfiesConstraints {
            reason: reasons.join("; "),
        }
    }

    /// Aggregates rejection reasons into counts.
    fn aggregate_rejections(rejections: &[HostRejection]) -> Vec<RejectionCount> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in rejections {
            let category = Self::categorize_rejection(&r.reason);
            *counts.entry(category.to_string()).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(reason, count)| RejectionCount { reason, count })
            .collect()
    }

    fn categorize_rejection(reason: &str) -> &'static str {
        const CATEGORIES: &[(&str, &str)] = &[
            ("unavailable", "unavailable"),
            ("draining", "draining"),
            ("disabled", "disabled_for_placement"),
            ("quarantined", "quarantined"),
            ("capacity", "insufficient_capacity"),
            ("runtime", "unsupported_runtime"),
            ("pressure", "pressure_saturated"),
        ];
        CATEGORIES
            .iter()
            .find(|(keyword, _)| reason.contains(keyword))
            .map(|(_, category)| *category)
            .unwrap_or("other")
    }

    /// Computes average capacity pressure across all hosts.
    fn compute_avg_pressure(hosts: &[HostInfo]) -> f64 {
        if hosts.is_empty() {
            return 0.0;
        }
        let total: f64 = hosts.iter().map(|h| h.pressure.combined_pressure()).sum();
        total / hosts.len() as f64
    }
}

impl Default for CellScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
