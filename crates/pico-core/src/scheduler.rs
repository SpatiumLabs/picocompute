//! Regional scheduler for sandbox placement.
//!
//! Selects a healthy cell for each sandbox while honoring tenant policy,
//! capacity, locality, image/snapshot cache availability, and failure
//! domains. The scheduler produces deterministic, traceable placement
//! decisions with weighted scoring and exposes backpressure signals to
//! the API admission path.
//!
//! ## Design
//!
//! The scheduler operates in three phases:
//!
//! 1. **Hard constraint filtering** - cells that cannot satisfy the request
//!    are eliminated (capacity, runtime support, health, failure domain).
//! 2. **Weighted scoring** - surviving cells are scored across multiple
//!    dimensions (capacity headroom, cache locality, admission pressure,
//!    failure domain spread).
//! 3. **Selection** - the highest-scoring cell is chosen; ties are broken
//!    deterministically by cell ID for reproducibility.

use serde::{Deserialize, Serialize};

use crate::identity::{CellId, RegionId, TenantId};
use crate::metadata::PlacementInfo;
use crate::runtime::RuntimeType;

// ---- Cell Model ----

/// Health status of a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellHealth {
    /// Cell is fully operational.
    Healthy,
    /// Cell is degraded but still accepting workloads with reduced capacity.
    Degraded,
    /// Cell is draining and should not accept new workloads.
    Draining,
    /// Cell is unreachable or has failed.
    Unavailable,
}

impl CellHealth {
    /// Whether this cell can accept new workloads.
    pub fn can_admit(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Resource capacity of a cell.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CellCapacity {
    /// Total vCPUs available in the cell.
    pub total_vcpus: u64,
    /// vCPUs currently allocated.
    pub allocated_vcpus: u64,
    /// Total memory in MB available in the cell.
    pub total_memory_mb: u64,
    /// Memory in MB currently allocated.
    pub allocated_memory_mb: u64,
    /// Maximum number of sandboxes the cell can host.
    pub max_sandboxes: u64,
    /// Number of sandboxes currently running.
    pub current_sandboxes: u64,
}

impl CellCapacity {
    /// Fraction of vCPUs still available (0.0 to 1.0).
    pub fn vcpu_headroom(&self) -> f64 {
        if self.total_vcpus == 0 {
            return 0.0;
        }
        let available = self.total_vcpus.saturating_sub(self.allocated_vcpus);
        available as f64 / self.total_vcpus as f64
    }

    /// Fraction of memory still available (0.0 to 1.0).
    pub fn memory_headroom(&self) -> f64 {
        if self.total_memory_mb == 0 {
            return 0.0;
        }
        let available = self
            .total_memory_mb
            .saturating_sub(self.allocated_memory_mb);
        available as f64 / self.total_memory_mb as f64
    }

    /// Fraction of sandbox slots still available (0.0 to 1.0).
    pub fn sandbox_headroom(&self) -> f64 {
        if self.max_sandboxes == 0 {
            return 0.0;
        }
        let available = self.max_sandboxes.saturating_sub(self.current_sandboxes);
        available as f64 / self.max_sandboxes as f64
    }

    /// Whether the cell can accommodate the requested resources.
    pub fn can_fit(&self, vcpus: u32, memory_mb: u64) -> bool {
        self.remaining_fit_count(vcpus, memory_mb) > 0
    }

    /// How many additional sandboxes of this shape fit without overcommit.
    ///
    /// Packing is the minimum of remaining vCPU, memory, and sandbox slots.
    /// A zero request in a dimension is treated as unbounded for that
    /// dimension so callers can probe a single resource.
    pub fn remaining_fit_count(&self, vcpus: u32, memory_mb: u64) -> u64 {
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
        let slots = self.max_sandboxes.saturating_sub(self.current_sandboxes);
        vcpu.min(memory).min(slots)
    }
}

/// Hint from the snapshot optimizer about whether a sandbox is
/// a good candidate for quiesce, based on dirty page rate and I/O activity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotTimingHint {
    /// Dirty rate is low and I/O is idle; quiesce is recommended.
    QuiesceRecommended,
    /// Sandbox is under active I/O; defer quiesce.
    DeferActiveIo,
    /// Dirty rate is moderate; quiesce is acceptable.
    QuiesceAcceptable,
    /// Insufficient data to make a recommendation.
    #[default]
    InsufficientData,
    /// Optimization backend is unavailable.
    Unavailable,
}

impl SnapshotTimingHint {
    /// Convert to a 0.0-1.0 score where higher is better for quiesce.
    ///
    /// | Variant | Score |
    /// |---|---|
    /// | [`Self::QuiesceRecommended`] | 1.0 |
    /// | [`Self::QuiesceAcceptable`] | 0.6 |
    /// | [`Self::InsufficientData`] | 0.5 (neutral) |
    /// | [`Self::Unavailable`] | 0.5 (neutral) |
    /// | [`Self::DeferActiveIo`] | 0.0 |
    pub fn as_score(self) -> f64 {
        match self {
            Self::QuiesceRecommended => 1.0,
            Self::QuiesceAcceptable => 0.6,
            Self::InsufficientData => 0.5,
            Self::Unavailable => 0.5,
            Self::DeferActiveIo => 0.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuiesceRecommended => "quiesce_recommended",
            Self::DeferActiveIo => "defer_active_io",
            Self::QuiesceAcceptable => "quiesce_acceptable",
            Self::InsufficientData => "insufficient_data",
            Self::Unavailable => "unavailable",
        }
    }

    /// Parse a host-reported snake_case hint string.
    ///
    /// Returns `None` for unknown values so callers can apply fallback policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use pico_core::SnapshotTimingHint;
    ///
    /// assert_eq!(
    ///     SnapshotTimingHint::parse("quiesce_recommended"),
    ///     Some(SnapshotTimingHint::QuiesceRecommended)
    /// );
    /// assert_eq!(SnapshotTimingHint::parse("not_a_hint"), None);
    /// ```
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "quiesce_recommended" => Some(Self::QuiesceRecommended),
            "defer_active_io" => Some(Self::DeferActiveIo),
            "quiesce_acceptable" => Some(Self::QuiesceAcceptable),
            "insufficient_data" => Some(Self::InsufficientData),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    /// Map host agent stats fields into a scheduler-ready hint.
    ///
    /// When `available` is false (optimizer offline or host missing the
    /// feature), returns [`Self::Unavailable`] (neutral score 0.5). Missing or
    /// unknown hint strings map to [`Self::InsufficientData`].
    ///
    /// Prefer [`HostSnapshotTimingStats::as_hint`] when deserializing a typed
    /// host-stats payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use pico_core::SnapshotTimingHint;
    ///
    /// let live = SnapshotTimingHint::from_host_stats(true, Some("quiesce_recommended"));
    /// assert_eq!(live, SnapshotTimingHint::QuiesceRecommended);
    ///
    /// let offline = SnapshotTimingHint::from_host_stats(false, Some("quiesce_recommended"));
    /// assert_eq!(offline, SnapshotTimingHint::Unavailable);
    /// assert!((offline.as_score() - 0.5).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    pub fn from_host_stats(available: bool, hint: Option<&str>) -> Self {
        if !available {
            return Self::Unavailable;
        }
        hint.and_then(Self::parse).unwrap_or(Self::InsufficientData)
    }

    /// Extract timing fields from a host agent `stats` JSON object.
    ///
    /// Absent fields produce [`Self::Unavailable`] for backward compatibility.
    /// Prefer deserializing into [`HostSnapshotTimingStats`] at control-plane
    /// boundaries, then calling [`HostSnapshotTimingStats::as_hint`].
    ///
    /// # Examples
    ///
    /// ```
    /// use pico_core::SnapshotTimingHint;
    ///
    /// let stats = serde_json::json!({
    ///     "snapshot_timing_hint": "defer_active_io",
    ///     "snapshot_timing_available": true,
    /// });
    /// assert_eq!(
    ///     SnapshotTimingHint::from_host_stats_json(&stats),
    ///     SnapshotTimingHint::DeferActiveIo
    /// );
    /// ```
    #[must_use]
    pub fn from_host_stats_json(stats: &serde_json::Value) -> Self {
        HostSnapshotTimingStats::from_stats_value(stats).as_hint()
    }

    /// More conservative (worse-for-quiesce) of two hints.
    ///
    /// Aggregates sandbox→host and host→cell signals by lowest score so
    /// placement stays conservative under active I/O. Equal scores keep
    /// `self` (`<=`) for stable left-hand selection.
    #[must_use]
    pub fn worse(self, other: Self) -> Self {
        if self.as_score() <= other.as_score() {
            self
        } else {
            other
        }
    }

    /// Aggregate host-level hints into one cell-level signal via [`Self::worse`].
    ///
    /// An empty set yields [`Self::InsufficientData`] (neutral score).
    #[must_use]
    pub fn aggregate(hints: impl IntoIterator<Item = Self>) -> Self {
        let mut iter = hints.into_iter();
        let Some(first) = iter.next() else {
            return Self::InsufficientData;
        };
        iter.fold(first, Self::worse)
    }
}

/// Error returned when parsing an unknown snapshot timing hint string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSnapshotTimingHint;

impl std::fmt::Display for InvalidSnapshotTimingHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid snapshot timing hint")
    }
}

impl std::error::Error for InvalidSnapshotTimingHint {}

impl std::str::FromStr for SnapshotTimingHint {
    type Err = InvalidSnapshotTimingHint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidSnapshotTimingHint)
    }
}

/// Snapshot timing subset of host agent `GET /rpc/v1/stats`.
///
/// Typed boundary for the control plane: deserialize host stats (or a subset)
/// into this struct, then convert with [`Self::as_hint`] for
/// [`CellInfo::apply_host_snapshot_timing`].
///
/// Unknown JSON fields are ignored so this can be deserialized from a full
/// host-agent stats payload.
///
/// ## Expected host-agent JSON shape
///
/// Emitted by `HostAgent::stats()` (alongside other host metrics):
///
/// ```json
/// {
///   "snapshot_timing_available": true,
///   "snapshot_timing_hint": "quiesce_recommended"
/// }
/// ```
///
/// `snapshot_timing_hint` is one of:
/// `quiesce_recommended`, `defer_active_io`, `quiesce_acceptable`,
/// `insufficient_data`, `unavailable` (see [`SnapshotTimingHint::as_str`]).
/// When `snapshot_timing_available` is `false` or either field is absent,
/// scoring stays neutral (0.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSnapshotTimingStats {
    /// Whether the eBPF optimizer backend is available on the host.
    #[serde(default)]
    pub snapshot_timing_available: bool,
    /// Aggregate host-level hint as reported by the host agent (`as_str` form).
    #[serde(default)]
    pub snapshot_timing_hint: Option<String>,
}

impl HostSnapshotTimingStats {
    /// Build from a full (or partial) host-agent stats JSON object.
    ///
    /// Only the timing fields are read; other keys are ignored.
    #[must_use]
    pub fn from_stats_value(stats: &serde_json::Value) -> Self {
        Self {
            snapshot_timing_available: stats
                .get("snapshot_timing_available")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            snapshot_timing_hint: stats
                .get("snapshot_timing_hint")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        }
    }

    /// Convert to a scheduler-ready hint with fallback semantics.
    ///
    /// # Examples
    ///
    /// ```
    /// use pico_core::{HostSnapshotTimingStats, SnapshotTimingHint};
    ///
    /// let stats = HostSnapshotTimingStats {
    ///     snapshot_timing_available: true,
    ///     snapshot_timing_hint: Some("quiesce_recommended".into()),
    /// };
    /// assert_eq!(stats.as_hint(), SnapshotTimingHint::QuiesceRecommended);
    /// ```
    #[must_use]
    pub fn as_hint(&self) -> SnapshotTimingHint {
        SnapshotTimingHint::from_host_stats(
            self.snapshot_timing_available,
            self.snapshot_timing_hint.as_deref(),
        )
    }
}

impl From<&HostSnapshotTimingStats> for SnapshotTimingHint {
    fn from(stats: &HostSnapshotTimingStats) -> Self {
        stats.as_hint()
    }
}

impl From<HostSnapshotTimingStats> for SnapshotTimingHint {
    fn from(stats: HostSnapshotTimingStats) -> Self {
        stats.as_hint()
    }
}

/// Image and snapshot cache locality information for a cell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheLocality {
    /// Image IDs currently cached on the cell.
    pub cached_images: Vec<String>,
    /// Snapshot IDs currently cached on the cell.
    pub cached_snapshots: Vec<String>,
}

impl CacheLocality {
    /// Whether the requested image is cached.
    pub fn has_image(&self, image: &str) -> bool {
        self.cached_images.iter().any(|id| id == image)
    }

    /// Whether the requested snapshot is cached.
    pub fn has_snapshot(&self, snapshot: &str) -> bool {
        self.cached_snapshots.iter().any(|id| id == snapshot)
    }
}

/// Information about a cell available to the regional scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellInfo {
    /// Cell identifier.
    pub cell_id: CellId,
    /// Region this cell belongs to.
    pub region_id: RegionId,
    /// Current health status.
    pub health: CellHealth,
    /// Resource capacity.
    pub capacity: CellCapacity,
    /// Runtime backends supported by this cell.
    pub supported_runtimes: Vec<RuntimeType>,
    /// Failure domain identifier (cells in the same failure domain
    /// should not both be selected for HA workloads).
    pub failure_domain: String,
    /// Cache locality information.
    pub cache: CacheLocality,
    /// Current admission pressure (0.0 = idle, 1.0 = saturated).
    /// Values above a threshold trigger backpressure.
    pub admission_pressure: f64,
    /// Snapshot timing hint from the eBPF optimizer (cell-level aggregate).
    ///
    /// Set via [`Self::apply_host_snapshot_timing`] from host inventory/stats.
    /// Serde-defaults to [`SnapshotTimingHint::InsufficientData`] (neutral).
    #[serde(default)]
    pub snapshot_timing_hint: SnapshotTimingHint,
}

impl CellInfo {
    /// Set [`Self::snapshot_timing_hint`] from host-level hints.
    ///
    /// Aggregates with [`SnapshotTimingHint::aggregate`] (most conservative).
    ///
    /// # Examples
    ///
    /// ```
    /// use pico_core::{
    ///     CacheLocality, CellCapacity, CellHealth, CellId, CellInfo, RegionId, RuntimeType,
    ///     SnapshotTimingHint,
    /// };
    ///
    /// let mut cell = CellInfo {
    ///     cell_id: CellId::from_string("cel_1"),
    ///     region_id: RegionId::from_string("rgn_us-east-1"),
    ///     health: CellHealth::Healthy,
    ///     capacity: CellCapacity {
    ///         total_vcpus: 10,
    ///         allocated_vcpus: 0,
    ///         total_memory_mb: 1024,
    ///         allocated_memory_mb: 0,
    ///         max_sandboxes: 5,
    ///         current_sandboxes: 0,
    ///     },
    ///     supported_runtimes: vec![RuntimeType::Firecracker],
    ///     failure_domain: "fd-1".into(),
    ///     cache: CacheLocality {
    ///         cached_images: vec![],
    ///         cached_snapshots: vec![],
    ///     },
    ///     admission_pressure: 0.0,
    ///     snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    /// };
    ///
    /// cell.apply_host_snapshot_timing([
    ///     SnapshotTimingHint::QuiesceRecommended,
    ///     SnapshotTimingHint::DeferActiveIo,
    /// ]);
    /// assert_eq!(cell.snapshot_timing_hint, SnapshotTimingHint::DeferActiveIo);
    /// ```
    pub fn apply_host_snapshot_timing(
        &mut self,
        host_hints: impl IntoIterator<Item = SnapshotTimingHint>,
    ) {
        self.snapshot_timing_hint = SnapshotTimingHint::aggregate(host_hints);
    }
}

// ---- Scheduler Request ----

/// Trace correlation carried on the create path.
///
/// Standalone scheduler calls use an empty context, which preserves the
/// existing `trace_id=None` audit contract. The create orchestrator
/// supplies trace, operation, and idempotency identity so placement
/// decisions and rejections are visible in traces and audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleTraceContext {
    /// Request trace for cross-component correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Operation identity for retry convergence and audit correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<crate::identity::OperationId>,
    /// Client idempotency key when placement is on the create path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Input to the regional scheduler for a placement decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerRequest {
    /// Tenant requesting the sandbox.
    pub tenant_id: TenantId,
    /// Requested vCPUs.
    pub vcpus: u32,
    /// Requested memory in MB.
    pub memory_mb: u64,
    /// Requested runtime backend (if any).
    pub runtime: Option<RuntimeType>,
    /// Container image or rootfs identifier.
    pub image: String,
    /// Snapshot to restore from (if any).
    pub snapshot_id: Option<String>,
    /// Preferred region (if any).
    pub preferred_region: Option<RegionId>,
    /// Failure domains to avoid (for HA spread).
    pub avoid_failure_domains: Vec<String>,
    /// Sandbox ID being scheduled (for deterministic tie-breaking).
    pub sandbox_id: String,
}

// ---- Scoring ----

/// Scoring dimension identifiers to avoid magic strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreDimension {
    CapacityHeadroom,
    ImageCache,
    SnapshotCache,
    AdmissionPressure,
    RegionPreference,
    SnapshotTiming,
}

impl ScoreDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapacityHeadroom => "capacity_headroom",
            Self::ImageCache => "image_cache",
            Self::SnapshotCache => "snapshot_cache",
            Self::AdmissionPressure => "admission_pressure",
            Self::RegionPreference => "region_preference",
            Self::SnapshotTiming => "snapshot_timing",
        }
    }

    pub const ALL: &[Self] = &[
        Self::CapacityHeadroom,
        Self::ImageCache,
        Self::SnapshotCache,
        Self::AdmissionPressure,
        Self::RegionPreference,
        Self::SnapshotTiming,
    ];
}

/// Individual scoring component with weight and normalized score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreComponent {
    /// Name of the scoring dimension.
    pub name: ScoreDimension,
    /// Weight of this component (0.0 to 1.0).
    pub weight: f64,
    /// Normalized score for this component (0.0 to 1.0).
    pub score: f64,
    /// Weighted contribution (weight * score).
    pub contribution: f64,
}

/// Complete scoring breakdown for a candidate cell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreBreakdown {
    /// Cell that was scored.
    pub cell_id: CellId,
    /// Individual scoring components.
    pub components: Vec<ScoreComponent>,
    /// Total weighted score.
    pub total_score: f64,
}

/// Default scoring weights for the scheduler.
#[derive(Debug, Clone, Copy)]
pub struct ScoringWeights {
    /// Weight for capacity headroom (higher = more headroom preferred).
    pub capacity_headroom: f64,
    /// Weight for image cache locality (1.0 if cached, 0.0 if not).
    pub image_cache: f64,
    /// Weight for snapshot cache locality (1.0 if cached, 0.0 if not).
    pub snapshot_cache: f64,
    /// Weight for low admission pressure (1.0 - pressure).
    pub admission_pressure: f64,
    /// Weight for region preference (1.0 if preferred, 0.5 if not).
    pub region_preference: f64,
    /// Weight for snapshot timing hint (based on dirty page rate and I/O activity).
    ///
    /// Default is intentionally low (0.05) until live host data is validated
    /// in production; raise once the dimension moves off the neutral 0.5 score.
    ///
    /// Justification: the hint travels host stats -> `HostInfo` ->
    /// `CellInfo` aggregate (most conservative via `worse`) -> regional score.
    /// Four hops are required because placement must stay conservative under
    /// active I/O (a single busy host defers the whole cell). Weight stays
    /// near-zero so neutral `InsufficientData`/`Unavailable` (0.5) cannot move
    /// placement; only a validated live signal with a raised weight should.
    /// `HostInfo.snapshot_timing_hint` exists only as the aggregation source;
    /// cell scoring never scores hosts directly on timing.
    pub snapshot_timing: f64,
}

impl ScoringWeights {
    /// Get the weight for a scoring dimension.
    pub fn weight_for(&self, dim: ScoreDimension) -> f64 {
        match dim {
            ScoreDimension::CapacityHeadroom => self.capacity_headroom,
            ScoreDimension::ImageCache => self.image_cache,
            ScoreDimension::SnapshotCache => self.snapshot_cache,
            ScoreDimension::AdmissionPressure => self.admission_pressure,
            ScoreDimension::RegionPreference => self.region_preference,
            ScoreDimension::SnapshotTiming => self.snapshot_timing,
        }
    }
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            capacity_headroom: 0.35,
            image_cache: 0.25,
            snapshot_cache: 0.15,
            admission_pressure: 0.10,
            region_preference: 0.10,
            snapshot_timing: 0.05,
        }
    }
}

// ---- Scheduler Response ----

/// Why a cell was chosen or why scheduling failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlacementReason {
    /// Cell scored highest across weighted dimensions.
    BestScore,
    /// Cell was the only one that passed hard constraints.
    OnlyCandidate,
    /// Cell was chosen because it has the requested image cached.
    CacheHit,
    /// Cell was chosen to spread across failure domains.
    FailureDomainSpread,
    /// No cell could satisfy the request.
    NoCellAvailable { reason: String },
}

/// Result of a scheduling decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerResponse {
    /// Whether scheduling succeeded.
    pub scheduled: bool,
    /// Selected cell (if scheduling succeeded).
    pub cell_id: Option<CellId>,
    /// Placement info for the metadata record.
    pub placement: Option<PlacementInfo>,
    /// Why this cell was chosen or why scheduling failed.
    pub reason: PlacementReason,
    /// Score breakdown for the selected cell (for observability).
    pub score_breakdown: Option<ScoreBreakdown>,
    /// All candidate scores (for debugging and capacity modelling).
    pub candidate_scores: Vec<ScoreBreakdown>,
    /// Backpressure signal for the API admission path.
    pub backpressure: BackpressureSignal,
}

/// Backpressure signal from the scheduler to the API admission path.
///
/// Indicates how constrained the scheduling environment is, allowing the
/// API to shed load or warn operators before hard capacity is reached.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BackpressureSignal {
    /// Fraction of cells that passed hard constraints (0.0 to 1.0).
    pub cell_admission_rate: f64,
    /// Average headroom across surviving cells.
    pub avg_headroom: f64,
    /// Whether the scheduler recommends rejecting new requests.
    pub should_throttle: bool,
    /// Number of cells evaluated.
    pub total_cells: usize,
    /// Number of cells that passed hard constraints.
    pub eligible_cells: usize,
}

impl BackpressureSignal {
    /// Threshold below which the scheduler recommends throttling.
    pub const THROTTLE_THRESHOLD: f64 = 0.15;

    /// Threshold below which headroom triggers throttle.
    pub const HEADROOM_THRESHOLD: f64 = 0.10;
}

// ---- Scheduler Errors ----

/// Errors returned by the regional scheduler.
///
/// `InsufficientCapacity` and `PressureSaturated` are throttled (retryable)
/// and must map to `PlacementThrottled` with a `Retry-After` hint through
/// `CreateError` and the API gate. Hard rejections (`UnsupportedRuntime`,
/// draining/unavailable `NoCellSatisfiesConstraints`) stay `Unprocessable`
/// without a retry hint.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// No cells are registered in the scheduler.
    #[error("no cells available in region")]
    NoCellsAvailable,

    /// All cells were filtered out by hard constraints.
    #[error("no cell can satisfy constraints: {reason}")]
    NoCellSatisfiesConstraints { reason: String },

    /// The requested runtime backend is not supported by any cell.
    #[error("no cell supports runtime backend: {runtime}")]
    UnsupportedRuntime { runtime: String },

    /// All cells have insufficient capacity for the requested resources.
    #[error("insufficient capacity: need {vcpus} vCPUs and {memory_mb} MB memory")]
    InsufficientCapacity { vcpus: u32, memory_mb: u64 },

    /// All eligible cells are saturated on admission pressure.
    ///
    /// Returned instead of generic `NoCellSatisfiesConstraints` when pressure
    /// is the blocker so the create path preserves the retry hint instead of
    /// collapsing to `Unprocessable`.
    #[error("admission pressure saturated")]
    PressureSaturated,

    /// All eligible cells are in failure domains that should be avoided.
    #[error("all eligible cells are in avoided failure domains")]
    FailureDomainExhausted,
}

impl SchedulerError {
    /// Whether this error is throttled (retryable) and must carry `Retry-After`.
    pub fn is_throttled(&self) -> bool {
        matches!(
            self,
            Self::InsufficientCapacity { .. }
                | Self::PressureSaturated
                | Self::NoCellsAvailable
                | Self::FailureDomainExhausted
        )
    }
}

// ---- Regional Scheduler ----

/// Regional scheduler that selects cells for sandbox placement.
///
/// The scheduler is stateless with respect to cell state: it receives
/// a snapshot of cell information at scheduling time and produces a
/// placement decision. Cell state is managed externally and passed
/// in on each scheduling call.
pub struct RegionalScheduler {
    /// Scoring weights.
    weights: ScoringWeights,
    /// Maximum admission pressure before a cell is considered saturated.
    max_admission_pressure: f64,
    /// Optional audit sink for emitting placement outcome events.
    audit_sink: Option<std::sync::Arc<dyn crate::event_bus::AuditEventSink>>,
    /// HLC generator for event timestamps.
    hlc: std::sync::Arc<crate::identity::Hlc>,
}

impl RegionalScheduler {
    /// Creates a new regional scheduler with default weights.
    pub fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
            max_admission_pressure: 0.85,
            audit_sink: None,
            hlc: std::sync::Arc::new(crate::identity::Hlc::new()),
        }
    }

    /// Creates a new regional scheduler with custom weights.
    pub fn with_weights(weights: ScoringWeights) -> Self {
        Self {
            weights,
            max_admission_pressure: 0.85,
            audit_sink: None,
            hlc: std::sync::Arc::new(crate::identity::Hlc::new()),
        }
    }

    /// Sets the maximum admission pressure threshold.
    pub fn with_max_admission_pressure(mut self, threshold: f64) -> Self {
        self.max_admission_pressure = threshold;
        self
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

    /// Schedule a sandbox placement across the given cells.
    ///
    /// Evaluates all cells against hard constraints, scores survivors,
    /// and returns a placement decision with full traceability.
    pub fn schedule(
        &self,
        request: &SchedulerRequest,
        cells: &[CellInfo],
    ) -> Result<SchedulerResponse, SchedulerError> {
        self.schedule_with_context(request, cells, None)
    }

    /// Schedule with create-path trace correlation.
    ///
    /// The context carries trace, operation, and idempotency identity into
    /// placement audit events and tracing spans. Rejection reasons remain
    /// typed in the returned error; the audit event carries the same reason
    /// for operators. Audit emission stays best-effort and never fails
    /// placement.
    ///
    /// Constraints are evaluated once per candidate via
    /// [`Self::check_constraints`]; scores are computed once per survivor via
    /// [`Self::score_cell`] through `place_with_breakdown` (no second pass to
    /// rebuild breakdowns, no separate headroom recompute).
    #[tracing::instrument(skip(self, request, cells, context), fields(sandbox_id = %request.sandbox_id, trace_id = tracing::field::Empty))]
    pub fn schedule_with_context(
        &self,
        request: &SchedulerRequest,
        cells: &[CellInfo],
        context: Option<&ScheduleTraceContext>,
    ) -> Result<SchedulerResponse, SchedulerError> {
        if let Some(ctx) = context
            && let Some(trace_id) = &ctx.trace_id
        {
            tracing::Span::current().record("trace_id", trace_id.as_str());
        }
        if cells.is_empty() {
            self.emit_outcome_with_context(request, None, "no_cell_available", None, 0, context);
            return Err(SchedulerError::NoCellsAvailable);
        }

        // Single evaluation point: one constraint check and one scoring pass
        // per candidate. Headroom derives from the stored breakdown.
        let outcome = crate::placement_engine::place_with_breakdown(
            cells,
            |cell| self.check_constraints(cell, request),
            |cell| self.score_cell(cell, request),
            Self::headroom_from_breakdown,
            |cell| cell.cell_id.as_str(),
            |breakdown| breakdown.total_score,
        );

        if outcome.selected.is_none() {
            let err = self.classify_rejection(request, &outcome.rejections);
            tracing::warn!(reason = %err, "regional placement rejected");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                context,
            );
            return Err(err);
        }

        // Fail closed without panic: the early return above covers selected
        // None, and the index lookup covers a scored-invariant violation.
        let Some(selected_cell) = outcome.selected else {
            let err = SchedulerError::NoCellSatisfiesConstraints {
                reason: "placement invariant violated: selected missing".into(),
            };
            tracing::warn!(reason = %err, "regional placement invariant violated");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                context,
            );
            return Err(err);
        };
        let Some(best_idx) = outcome
            .scored
            .iter()
            .position(|s| s.candidate.cell_id == selected_cell.cell_id)
        else {
            let err = SchedulerError::NoCellSatisfiesConstraints {
                reason: "placement invariant violated: selected cell not scored".into(),
            };
            tracing::warn!(reason = %err, "regional placement invariant violated");
            self.emit_outcome_with_context(
                request,
                None,
                format!("{err:?}"),
                None,
                outcome.backpressure.total_candidates,
                context,
            );
            return Err(err);
        };

        // Scores already computed once; reuse breakdowns directly. Compute the
        // reason before moving the breakdowns out of the outcome.
        let best_score = outcome.scored[best_idx].total_score;
        let reason = self.determine_reason_from_outcome(
            &outcome,
            &outcome.scored[best_idx].breakdown,
            request,
        );
        let backpressure_cached = outcome.backpressure;
        let scores: Vec<ScoreBreakdown> = outcome.scored.into_iter().map(|s| s.breakdown).collect();
        let best = &scores[best_idx];

        let placement = PlacementInfo {
            region: Some(selected_cell.region_id.as_str().to_string()),
            cell: Some(selected_cell.cell_id.as_str().to_string()),
            host: None,
            runtime_backend: request.runtime,
            network_identity: None,
        };

        let backpressure = BackpressureSignal {
            cell_admission_rate: backpressure_cached.admission_rate,
            avg_headroom: backpressure_cached.avg_headroom,
            should_throttle: backpressure_cached.should_throttle,
            total_cells: backpressure_cached.total_candidates,
            eligible_cells: backpressure_cached.eligible_candidates,
        };

        let response = SchedulerResponse {
            scheduled: true,
            cell_id: Some(selected_cell.cell_id.clone()),
            placement: Some(placement),
            reason: reason.clone(),
            score_breakdown: Some(best.clone()),
            candidate_scores: scores,
            backpressure,
        };

        tracing::info!(
            cell_id = ?response.cell_id,
            reason = ?reason,
            score = best_score,
            "regional placement admitted"
        );
        self.emit_outcome_with_context(
            request,
            response.cell_id.as_ref().map(|c| c.as_str().to_string()),
            format!("{reason:?}"),
            Some(best_score),
            backpressure_cached.eligible_candidates,
            context,
        );

        Ok(response)
    }

    fn emit_outcome_with_context(
        &self,
        request: &SchedulerRequest,
        cell_id: Option<String>,
        reason: impl Into<String>,
        score: Option<f64>,
        candidates_evaluated: usize,
        context: Option<&ScheduleTraceContext>,
    ) {
        if let Some(ref sink) = self.audit_sink {
            crate::event_bus::emit_placement_outcome(
                sink.as_ref(),
                &self.hlc,
                crate::event_bus::PlacementOutcomeParams {
                    sandbox_id: request.sandbox_id.clone(),
                    tenant_id: Some(request.tenant_id.clone()),
                    cell_id,
                    host_id: None,
                    reason: reason.into(),
                    score,
                    candidates_evaluated,
                    trace_id: context.and_then(|c| c.trace_id.clone()),
                    operation_id: context.and_then(|c| c.operation_id.clone()),
                    idempotency_key: context.and_then(|c| c.idempotency_key.clone()),
                },
            );
        }
    }

    /// Single constraint evaluation point for regional placement.
    ///
    /// All hard-constraint logic lives here so a fix lands once. The
    /// placement-engine filter calls this exactly once per candidate, and
    /// [`Self::classify_rejection`] derives typed errors from the returned
    /// rejection strings (via `categorize_rejection`) instead of
    /// re-implementing these checks.
    fn check_constraints(
        &self,
        cell: &CellInfo,
        request: &SchedulerRequest,
    ) -> crate::placement_engine::ConstraintResult {
        use crate::placement_engine::ConstraintResult;
        if !cell.health.can_admit() {
            return ConstraintResult::Fail(format!("cell is {}", cell.health.as_str()));
        }
        if !cell.capacity.can_fit(request.vcpus, request.memory_mb) {
            return ConstraintResult::Fail("insufficient capacity".into());
        }
        if let Some(ref runtime) = request.runtime
            && !cell.supported_runtimes.contains(runtime)
        {
            return ConstraintResult::Fail(format!("unsupported runtime: {runtime:?}"));
        }
        if cell.admission_pressure > self.max_admission_pressure {
            return ConstraintResult::Fail(format!(
                "admission pressure {} exceeds threshold",
                cell.admission_pressure
            ));
        }
        ConstraintResult::Pass
    }

    /// Headroom derived from the stored breakdown (no candidate recompute).
    ///
    /// Reads the `CapacityHeadroom` component score so backpressure uses the
    /// same headroom value scored once in [`Self::score_cell`]. The candidate
    /// argument exists for the shared engine signature and is ignored.
    fn headroom_from_breakdown(_cell: &CellInfo, breakdown: &ScoreBreakdown) -> f64 {
        breakdown
            .components
            .iter()
            .find(|c| c.name == ScoreDimension::CapacityHeadroom)
            .map(|c| c.score)
            .unwrap_or(0.0)
    }

    /// Determines the placement reason from the outcome.
    fn determine_reason_from_outcome(
        &self,
        outcome: &crate::placement_engine::PlacementOutcomeWithBreakdown<
            '_,
            CellInfo,
            ScoreBreakdown,
        >,
        best: &ScoreBreakdown,
        request: &SchedulerRequest,
    ) -> PlacementReason {
        if outcome.scored.len() == 1 {
            return PlacementReason::OnlyCandidate;
        }

        let image_cache_component = best
            .components
            .iter()
            .find(|c| c.name == ScoreDimension::ImageCache);
        if let Some(comp) = image_cache_component
            && (comp.score - 1.0).abs() < f64::EPSILON
            && comp.contribution > 0.2
        {
            return PlacementReason::CacheHit;
        }

        if !request.avoid_failure_domains.is_empty() {
            let dominated_by_spread = outcome.scored.iter().any(|s| {
                request
                    .avoid_failure_domains
                    .contains(&s.candidate.failure_domain)
                    && s.candidate.cell_id != best.cell_id
            });
            if dominated_by_spread {
                return PlacementReason::FailureDomainSpread;
            }
        }

        PlacementReason::BestScore
    }

    /// Scores a single cell across all weighted dimensions.
    fn score_cell(&self, cell: &CellInfo, request: &SchedulerRequest) -> ScoreBreakdown {
        let mut components = Vec::with_capacity(6);

        // Capacity headroom: average of vCPU, memory, and sandbox headroom
        let headroom = (cell.capacity.vcpu_headroom()
            + cell.capacity.memory_headroom()
            + cell.capacity.sandbox_headroom())
            / 3.0;
        components.push(self.make_component(
            ScoreDimension::CapacityHeadroom,
            self.weights.capacity_headroom,
            headroom,
        ));

        // Image cache locality
        let image_score = if cell.cache.has_image(&request.image) {
            1.0
        } else {
            0.0
        };
        components.push(self.make_component(
            ScoreDimension::ImageCache,
            self.weights.image_cache,
            image_score,
        ));

        // Snapshot cache locality
        let snapshot_score = match &request.snapshot_id {
            Some(snap) if cell.cache.has_snapshot(snap) => 1.0,
            Some(_) => 0.0,
            None => 0.5, // neutral if no snapshot requested
        };
        components.push(self.make_component(
            ScoreDimension::SnapshotCache,
            self.weights.snapshot_cache,
            snapshot_score,
        ));

        // Admission pressure (lower is better)
        let pressure_score = 1.0 - cell.admission_pressure;
        components.push(self.make_component(
            ScoreDimension::AdmissionPressure,
            self.weights.admission_pressure,
            pressure_score,
        ));

        // Region preference
        let region_score = match &request.preferred_region {
            Some(preferred) if cell.region_id == *preferred => 1.0,
            Some(_) => 0.5,
            None => 0.75, // neutral if no preference
        };
        components.push(self.make_component(
            ScoreDimension::RegionPreference,
            self.weights.region_preference,
            region_score,
        ));

        // Snapshot timing hint from eBPF optimizer
        let timing_score = cell.snapshot_timing_hint.as_score();
        components.push(self.make_component(
            ScoreDimension::SnapshotTiming,
            self.weights.snapshot_timing,
            timing_score,
        ));

        // Failure domain avoidance bonus: penalize cells in avoided domains
        if request.avoid_failure_domains.contains(&cell.failure_domain) {
            let penalty_component = self.make_component(ScoreDimension::RegionPreference, 0.0, 0.0);
            components.push(penalty_component);
        }

        let total_score: f64 = components.iter().map(|c| c.contribution).sum();

        // Apply failure domain penalty
        let total_score = if request.avoid_failure_domains.contains(&cell.failure_domain) {
            total_score * 0.5
        } else {
            total_score
        };

        ScoreBreakdown {
            cell_id: cell.cell_id.clone(),
            components,
            total_score,
        }
    }

    fn make_component(&self, name: ScoreDimension, weight: f64, score: f64) -> ScoreComponent {
        ScoreComponent {
            name,
            weight,
            score,
            contribution: weight * score,
        }
    }

    /// Classifies why all cells were rejected from single-evaluation rejections.
    ///
    /// Derives the typed error from `rejections` categories (produced by
    /// [`Self::check_constraints`]) instead of re-evaluating candidate fields,
    /// so constraint fixes land once. Throttled causes (`capacity`,
    /// `pressure`) map to retryable variants preserving the `Retry-After`
    /// hint through `CreateError`; draining/unavailable and unsupported
    /// runtimes stay hard rejections.
    ///
    /// Priority: health, then runtime-only (no supporter), then capacity,
    /// then pressure. Capacity implies a runtime supporter exists because the
    /// capacity check runs after the runtime check, so any admittable capacity
    /// failure throttles even in mixed runtime+capacity fleets (heterogeneous
    /// runtimes). In that mixed case the message names the capacity bound;
    /// the runtime mismatch is visible in per-candidate rejection strings and
    /// audit events.
    fn classify_rejection(
        &self,
        request: &SchedulerRequest,
        rejections: &[(&CellInfo, String)],
    ) -> SchedulerError {
        use crate::placement_engine::categorize_rejection;

        if rejections.is_empty() {
            return SchedulerError::NoCellSatisfiesConstraints {
                reason: "all eligible cells filtered by admission pressure or constraints".into(),
            };
        }

        let categories: Vec<&'static str> = rejections
            .iter()
            .map(|(_, reason)| categorize_rejection(reason))
            .collect();

        let all_health = categories
            .iter()
            .copied()
            .all(|c| matches!(c, "unavailable" | "draining" | "disabled_for_placement"));
        if all_health {
            return SchedulerError::NoCellSatisfiesConstraints {
                reason: "all cells are unavailable or draining".into(),
            };
        }

        let admittable: Vec<&'static str> = categories
            .iter()
            .copied()
            .filter(|c| !matches!(*c, "unavailable" | "draining" | "disabled_for_placement"))
            .collect();

        if let Some(ref runtime) = request.runtime
            && !admittable.is_empty()
            && admittable.iter().all(|c| *c == "unsupported_runtime")
        {
            return SchedulerError::UnsupportedRuntime {
                runtime: format!("{runtime:?}"),
            };
        }

        if admittable.contains(&"insufficient_capacity") {
            return SchedulerError::InsufficientCapacity {
                vcpus: request.vcpus,
                memory_mb: request.memory_mb,
            };
        }

        if admittable.contains(&"pressure_saturated") {
            return SchedulerError::PressureSaturated;
        }

        if categories.contains(&"insufficient_capacity") {
            return SchedulerError::InsufficientCapacity {
                vcpus: request.vcpus,
                memory_mb: request.memory_mb,
            };
        }
        if categories.contains(&"pressure_saturated") {
            return SchedulerError::PressureSaturated;
        }

        if let Some(ref runtime) = request.runtime
            && categories.contains(&"unsupported_runtime")
        {
            return SchedulerError::UnsupportedRuntime {
                runtime: format!("{runtime:?}"),
            };
        }

        SchedulerError::NoCellSatisfiesConstraints {
            reason: "all eligible cells filtered by admission pressure or constraints".into(),
        }
    }
}

impl Default for RegionalScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CellId, RegionId, TenantId};

    fn make_cell(id: &str, region: &str, health: CellHealth) -> CellInfo {
        CellInfo {
            cell_id: CellId::from_string(id),
            region_id: RegionId::from_string(region),
            health,
            capacity: CellCapacity {
                total_vcpus: 100,
                allocated_vcpus: 20,
                total_memory_mb: 10240,
                allocated_memory_mb: 2048,
                max_sandboxes: 50,
                current_sandboxes: 10,
            },
            supported_runtimes: vec![RuntimeType::Firecracker, RuntimeType::Qemu],
            failure_domain: format!("fd-{id}"),
            cache: CacheLocality {
                cached_images: vec!["alpine-3.18".into()],
                cached_snapshots: vec![],
            },
            admission_pressure: 0.2,
            snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
        }
    }

    fn make_request() -> SchedulerRequest {
        SchedulerRequest {
            tenant_id: TenantId::from_string("tnt_test"),
            vcpus: 2,
            memory_mb: 512,
            runtime: Some(RuntimeType::Firecracker),
            image: "alpine-3.18".into(),
            snapshot_id: None,
            preferred_region: None,
            avoid_failure_domains: vec![],
            sandbox_id: "sbx_test".into(),
        }
    }

    // ================================================================
    // Hard constraint tests
    // ================================================================

    #[test]
    fn schedule_with_no_cells_returns_error() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let result = scheduler.schedule(&request, &[]);
        assert!(matches!(result, Err(SchedulerError::NoCellsAvailable)));
    }

    #[test]
    fn schedule_rejects_unhealthy_cells() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![
            make_cell("cel_1", "rgn_us-east-1", CellHealth::Draining),
            make_cell("cel_2", "rgn_us-east-1", CellHealth::Unavailable),
        ];
        let result = scheduler.schedule(&request, &cells);
        assert!(matches!(
            result,
            Err(SchedulerError::NoCellSatisfiesConstraints { .. })
        ));
    }

    #[test]
    fn schedule_rejects_insufficient_capacity() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.vcpus = 200;
        request.memory_mb = 50000;
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];
        let result = scheduler.schedule(&request, &cells);
        assert!(matches!(
            result,
            Err(SchedulerError::InsufficientCapacity { .. })
        ));
    }

    #[test]
    fn schedule_rejects_unsupported_runtime() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.runtime = Some(RuntimeType::RemoteFirecracker);
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];
        let result = scheduler.schedule(&request, &cells);
        assert!(matches!(
            result,
            Err(SchedulerError::UnsupportedRuntime { .. })
        ));
    }

    #[test]
    fn schedule_rejects_high_admission_pressure() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let mut cell = make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy);
        cell.admission_pressure = 0.95;
        let result = scheduler.schedule(&request, &[cell]);
        // Pressure is throttled (retryable), not generic Unprocessable, so the
        // create path preserves Retry-After.
        assert!(matches!(result, Err(SchedulerError::PressureSaturated)));
        let err: crate::error::SandboxError = result.unwrap_err().into();
        assert!(matches!(
            err,
            crate::error::SandboxError::PlacementThrottled { .. }
        ));
    }

    #[test]
    fn schedule_accepts_degraded_cell() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Degraded)];
        let result = scheduler.schedule(&request, &cells);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.scheduled);
        assert_eq!(response.reason, PlacementReason::OnlyCandidate);
    }

    // ================================================================
    // Scoring tests
    // ================================================================

    #[test]
    fn schedule_prefers_cell_with_more_headroom() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let mut cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        cell_a.capacity.allocated_vcpus = 80;
        cell_a.capacity.allocated_memory_mb = 8192;

        let cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn schedule_prefers_cell_with_cached_image() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.image = "ubuntu-22.04".into();

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.cache.cached_images.push("ubuntu-22.04".into());

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn schedule_prefers_cell_with_cached_snapshot() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.snapshot_id = Some("snp_123".into());

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.cache.cached_snapshots.push("snp_123".into());

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn schedule_prefers_cell_in_preferred_region() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.preferred_region = Some(RegionId::from_string("rgn_eu-west-1"));

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        let cell_b = make_cell("cel_b", "rgn_eu-west-1", CellHealth::Healthy);

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn schedule_penalizes_avoided_failure_domains() {
        let scheduler = RegionalScheduler::new();
        let mut request = make_request();
        request.avoid_failure_domains = vec!["fd-cel_a".into()];

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        let cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn schedule_prefers_lower_admission_pressure() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let mut cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        cell_a.admission_pressure = 0.7;

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.admission_pressure = 0.1;

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    // ================================================================
    // Tie-breaking tests
    // ================================================================

    #[test]
    fn schedule_breaks_ties_deterministically_by_cell_id() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        let cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);

        let result1 = scheduler
            .schedule(&request, &[cell_a.clone(), cell_b.clone()])
            .unwrap();
        let result2 = scheduler.schedule(&request, &[cell_b, cell_a]).unwrap();

        assert_eq!(result1.cell_id, result2.cell_id);
    }

    // ================================================================
    // Placement reason tests
    // ================================================================

    #[test]
    fn schedule_returns_only_candidate_when_single_cell() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert_eq!(result.reason, PlacementReason::OnlyCandidate);
    }

    #[test]
    fn schedule_returns_best_score_for_multiple_cells() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![
            make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy),
            make_cell("cel_2", "rgn_us-east-1", CellHealth::Healthy),
        ];

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(matches!(
            result.reason,
            PlacementReason::BestScore | PlacementReason::CacheHit
        ));
    }

    // ================================================================
    // Backpressure tests
    // ================================================================

    #[test]
    fn backpressure_signals_no_throttle_when_healthy() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![
            make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy),
            make_cell("cel_2", "rgn_us-east-1", CellHealth::Healthy),
        ];

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(!result.backpressure.should_throttle);
        assert_eq!(result.backpressure.total_cells, 2);
        assert_eq!(result.backpressure.eligible_cells, 2);
    }

    #[test]
    fn backpressure_signals_throttle_when_few_eligible() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let mut cells: Vec<CellInfo> = (0..10)
            .map(|i| make_cell(&format!("cel_{i}"), "rgn_us-east-1", CellHealth::Healthy))
            .collect();

        for cell in cells.iter_mut().take(9) {
            cell.health = CellHealth::Unavailable;
        }

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(result.backpressure.should_throttle);
        assert_eq!(result.backpressure.eligible_cells, 1);
        assert_eq!(result.backpressure.total_cells, 10);
    }

    // ================================================================
    // Score breakdown tests
    // ================================================================

    #[test]
    fn score_breakdown_contains_all_components() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];

        let result = scheduler.schedule(&request, &cells).unwrap();
        let breakdown = result.score_breakdown.unwrap();

        let component_dims: Vec<ScoreDimension> =
            breakdown.components.iter().map(|c| c.name).collect();
        assert!(component_dims.contains(&ScoreDimension::CapacityHeadroom));
        assert!(component_dims.contains(&ScoreDimension::ImageCache));
        assert!(component_dims.contains(&ScoreDimension::SnapshotCache));
        assert!(component_dims.contains(&ScoreDimension::AdmissionPressure));
        assert!(component_dims.contains(&ScoreDimension::RegionPreference));
        assert!(component_dims.contains(&ScoreDimension::SnapshotTiming));
    }

    #[test]
    fn score_breakdown_total_matches_sum_of_contributions() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];

        let result = scheduler.schedule(&request, &cells).unwrap();
        let breakdown = result.score_breakdown.unwrap();

        let sum: f64 = breakdown.components.iter().map(|c| c.contribution).sum();
        assert!((breakdown.total_score - sum).abs() < f64::EPSILON);
    }

    #[test]
    fn candidate_scores_include_all_eligible_cells() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![
            make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy),
            make_cell("cel_2", "rgn_us-east-1", CellHealth::Healthy),
            make_cell("cel_3", "rgn_us-east-1", CellHealth::Unavailable),
        ];

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert_eq!(result.candidate_scores.len(), 2);
    }

    // ================================================================
    // Placement info tests
    // ================================================================

    #[test]
    fn placement_info_contains_region_and_cell() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();
        let cells = vec![make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy)];

        let result = scheduler.schedule(&request, &cells).unwrap();
        let placement = result.placement.unwrap();

        assert_eq!(placement.region.as_deref(), Some("rgn_us-east-1"));
        assert_eq!(placement.cell.as_deref(), Some("cel_1"));
        assert_eq!(placement.runtime_backend, Some(RuntimeType::Firecracker));
    }

    // ================================================================
    // Simulation tests
    // ================================================================

    #[test]
    fn simulation_overloaded_region_still_schedules() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let mut cells: Vec<CellInfo> = (0..5)
            .map(|i| make_cell(&format!("cel_{i}"), "rgn_us-east-1", CellHealth::Healthy))
            .collect();

        for cell in cells.iter_mut().take(4) {
            cell.capacity.allocated_vcpus = 98;
            cell.capacity.allocated_memory_mb = 10000;
            cell.capacity.current_sandboxes = 49;
        }

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(result.scheduled);
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_4");
    }

    #[test]
    fn simulation_partially_unavailable_cells() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let cells = vec![
            make_cell("cel_1", "rgn_us-east-1", CellHealth::Unavailable),
            make_cell("cel_2", "rgn_us-east-1", CellHealth::Healthy),
            make_cell("cel_3", "rgn_us-east-1", CellHealth::Draining),
            make_cell("cel_4", "rgn_us-east-1", CellHealth::Degraded),
        ];

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(result.scheduled);
        let cell_id = result.cell_id.as_ref().unwrap().as_str();
        assert!(cell_id == "cel_2" || cell_id == "cel_4");
    }

    #[test]
    fn simulation_all_cells_saturated_triggers_throttle() {
        let scheduler = RegionalScheduler::new();
        let request = make_request();

        let mut cells: Vec<CellInfo> = (0..10)
            .map(|i| make_cell(&format!("cel_{i}"), "rgn_us-east-1", CellHealth::Healthy))
            .collect();

        for cell in cells.iter_mut() {
            // Leave just enough capacity for the request (2 vCPUs, 512 MB)
            // but keep headroom very low
            cell.capacity.allocated_vcpus = 98;
            cell.capacity.allocated_memory_mb = 9728;
            cell.capacity.current_sandboxes = 49;
        }

        let result = scheduler.schedule(&request, &cells).unwrap();
        assert!(result.backpressure.should_throttle);
        assert!(result.backpressure.avg_headroom < BackpressureSignal::HEADROOM_THRESHOLD);
    }

    // ================================================================
    // Cell capacity tests
    // ================================================================

    #[test]
    fn cell_capacity_headroom_calculations() {
        let cap = CellCapacity {
            total_vcpus: 100,
            allocated_vcpus: 25,
            total_memory_mb: 10240,
            allocated_memory_mb: 2560,
            max_sandboxes: 50,
            current_sandboxes: 10,
        };

        assert!((cap.vcpu_headroom() - 0.75).abs() < f64::EPSILON);
        assert!((cap.memory_headroom() - 0.75).abs() < f64::EPSILON);
        assert!((cap.sandbox_headroom() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn cell_capacity_zero_total_returns_zero_headroom() {
        let cap = CellCapacity {
            total_vcpus: 0,
            allocated_vcpus: 0,
            total_memory_mb: 0,
            allocated_memory_mb: 0,
            max_sandboxes: 0,
            current_sandboxes: 0,
        };

        assert_eq!(cap.vcpu_headroom(), 0.0);
        assert_eq!(cap.memory_headroom(), 0.0);
        assert_eq!(cap.sandbox_headroom(), 0.0);
    }

    #[test]
    fn cell_capacity_can_fit_checks_all_dimensions() {
        let cap = CellCapacity {
            total_vcpus: 10,
            allocated_vcpus: 8,
            total_memory_mb: 1024,
            allocated_memory_mb: 512,
            max_sandboxes: 5,
            current_sandboxes: 5,
        };

        assert!(!cap.can_fit(1, 100));
        assert!(!cap.can_fit(3, 100));
        assert!(!cap.can_fit(2, 512));
    }

    // ================================================================
    // Cache locality tests
    // ================================================================

    #[test]
    fn cache_locality_image_lookup() {
        let cache = CacheLocality {
            cached_images: vec!["alpine-3.18".into(), "ubuntu-22.04".into()],
            cached_snapshots: vec![],
        };

        assert!(cache.has_image("alpine-3.18"));
        assert!(cache.has_image("ubuntu-22.04"));
        assert!(!cache.has_image("debian-12"));
    }

    #[test]
    fn cache_locality_snapshot_lookup() {
        let cache = CacheLocality {
            cached_images: vec![],
            cached_snapshots: vec!["snp_abc".into()],
        };

        assert!(cache.has_snapshot("snp_abc"));
        assert!(!cache.has_snapshot("snp_xyz"));
    }

    // ================================================================
    // Cell health tests
    // ================================================================

    #[test]
    fn cell_health_can_admit() {
        assert!(CellHealth::Healthy.can_admit());
        assert!(CellHealth::Degraded.can_admit());
        assert!(!CellHealth::Draining.can_admit());
        assert!(!CellHealth::Unavailable.can_admit());
    }

    #[test]
    fn cell_health_as_str() {
        assert_eq!(CellHealth::Healthy.as_str(), "healthy");
        assert_eq!(CellHealth::Degraded.as_str(), "degraded");
        assert_eq!(CellHealth::Draining.as_str(), "draining");
        assert_eq!(CellHealth::Unavailable.as_str(), "unavailable");
    }

    // ================================================================
    // Custom weights tests
    // ================================================================

    #[test]
    fn custom_weights_affect_scoring() {
        let weights = ScoringWeights {
            capacity_headroom: 0.0,
            image_cache: 1.0,
            snapshot_cache: 0.0,
            admission_pressure: 0.0,
            region_preference: 0.0,
            snapshot_timing: 0.0,
        };
        let scheduler = RegionalScheduler::with_weights(weights);
        let mut request = make_request();
        request.image = "custom-image".into();

        let cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.cache.cached_images.push("custom-image".into());

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn custom_admission_pressure_threshold() {
        let scheduler = RegionalScheduler::new().with_max_admission_pressure(0.5);
        let request = make_request();

        let mut cell = make_cell("cel_1", "rgn_us-east-1", CellHealth::Healthy);
        cell.admission_pressure = 0.6;

        let result = scheduler.schedule(&request, &[cell]);
        assert!(result.is_err());
    }

    // ================================================================
    // Scheduler error display tests
    // ================================================================

    #[test]
    fn scheduler_error_display_messages() {
        let err = SchedulerError::NoCellsAvailable;
        assert!(err.to_string().contains("no cells available"));

        let err = SchedulerError::InsufficientCapacity {
            vcpus: 100,
            memory_mb: 50000,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50000"));

        let err = SchedulerError::PressureSaturated;
        assert!(err.to_string().contains("pressure"));
        assert!(err.is_throttled());

        let err = SchedulerError::UnsupportedRuntime {
            runtime: "RemoteFirecracker".into(),
        };
        assert!(err.to_string().contains("RemoteFirecracker"));
    }

    // ================================================================
    // Backpressure signal tests
    // ================================================================

    #[test]
    fn backpressure_constants_are_reasonable() {
        const _: () = assert!(BackpressureSignal::THROTTLE_THRESHOLD > 0.0);
        const _: () = assert!(BackpressureSignal::THROTTLE_THRESHOLD < 1.0);
        const _: () = assert!(BackpressureSignal::HEADROOM_THRESHOLD > 0.0);
        const _: () = assert!(BackpressureSignal::HEADROOM_THRESHOLD < 1.0);
    }

    // ================================================================
    // Serialization tests
    // ================================================================

    #[test]
    fn scheduler_response_serializes() {
        let response = SchedulerResponse {
            scheduled: true,
            cell_id: Some(CellId::from_string("cel_1")),
            placement: Some(PlacementInfo {
                region: Some("rgn_us-east-1".into()),
                cell: Some("cel_1".into()),
                host: None,
                runtime_backend: Some(RuntimeType::Firecracker),
                network_identity: None,
            }),
            reason: PlacementReason::BestScore,
            score_breakdown: None,
            candidate_scores: vec![],
            backpressure: BackpressureSignal {
                cell_admission_rate: 1.0,
                avg_headroom: 0.8,
                should_throttle: false,
                total_cells: 5,
                eligible_cells: 5,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("scheduled"));
        assert!(json.contains("cel_1"));
    }

    #[test]
    fn placement_reason_serde_roundtrip() {
        let reasons = vec![
            PlacementReason::BestScore,
            PlacementReason::OnlyCandidate,
            PlacementReason::CacheHit,
            PlacementReason::FailureDomainSpread,
            PlacementReason::NoCellAvailable {
                reason: "test".into(),
            },
        ];

        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: PlacementReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, reason);
        }
    }

    // ================================================================
    // Snapshot timing hint tests
    // ================================================================

    #[test]
    fn snapshot_timing_hint_as_score_values() {
        assert!((SnapshotTimingHint::QuiesceRecommended.as_score() - 1.0).abs() < f64::EPSILON);
        assert!((SnapshotTimingHint::QuiesceAcceptable.as_score() - 0.6).abs() < f64::EPSILON);
        assert!((SnapshotTimingHint::InsufficientData.as_score() - 0.5).abs() < f64::EPSILON);
        assert!((SnapshotTimingHint::Unavailable.as_score() - 0.5).abs() < f64::EPSILON);
        assert_eq!(SnapshotTimingHint::DeferActiveIo.as_score(), 0.0);
    }

    #[test]
    fn snapshot_timing_hint_as_str() {
        assert_eq!(
            SnapshotTimingHint::QuiesceRecommended.as_str(),
            "quiesce_recommended"
        );
        assert_eq!(
            SnapshotTimingHint::DeferActiveIo.as_str(),
            "defer_active_io"
        );
    }

    #[test]
    fn snapshot_timing_hint_distinct_variants() {
        let hints = [
            SnapshotTimingHint::QuiesceRecommended,
            SnapshotTimingHint::DeferActiveIo,
            SnapshotTimingHint::QuiesceAcceptable,
            SnapshotTimingHint::InsufficientData,
            SnapshotTimingHint::Unavailable,
        ];
        for (i, a) in hints.iter().enumerate() {
            for (j, b) in hints.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn schedule_prefers_cell_with_quiesce_recommended_timing() {
        let scheduler = RegionalScheduler::with_weights(ScoringWeights {
            capacity_headroom: 0.0,
            image_cache: 0.0,
            snapshot_cache: 0.0,
            admission_pressure: 0.0,
            region_preference: 0.0,
            snapshot_timing: 1.0,
        });
        let request = make_request();

        let mut cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        cell_a.snapshot_timing_hint = SnapshotTimingHint::DeferActiveIo;

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.snapshot_timing_hint = SnapshotTimingHint::QuiesceRecommended;

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_b");
    }

    #[test]
    fn snapshot_timing_hint_serde_roundtrip() {
        let hints = [
            SnapshotTimingHint::QuiesceRecommended,
            SnapshotTimingHint::DeferActiveIo,
        ];
        for hint in &hints {
            let json = serde_json::to_string(hint).unwrap();
            let back: SnapshotTimingHint = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, hint);
        }
    }

    mod snapshot_timing_hint_parse {
        use super::*;

        #[test]
        fn quiesce_recommended() {
            assert_eq!(
                SnapshotTimingHint::parse("quiesce_recommended"),
                Some(SnapshotTimingHint::QuiesceRecommended)
            );
        }

        #[test]
        fn defer_active_io() {
            assert_eq!(
                SnapshotTimingHint::parse("defer_active_io"),
                Some(SnapshotTimingHint::DeferActiveIo)
            );
        }

        #[test]
        fn quiesce_acceptable() {
            assert_eq!(
                SnapshotTimingHint::parse("quiesce_acceptable"),
                Some(SnapshotTimingHint::QuiesceAcceptable)
            );
        }

        #[test]
        fn insufficient_data() {
            assert_eq!(
                SnapshotTimingHint::parse("insufficient_data"),
                Some(SnapshotTimingHint::InsufficientData)
            );
        }

        #[test]
        fn unavailable() {
            assert_eq!(
                SnapshotTimingHint::parse("unavailable"),
                Some(SnapshotTimingHint::Unavailable)
            );
        }

        #[test]
        fn unknown_is_none() {
            assert_eq!(SnapshotTimingHint::parse("not_a_real_hint"), None);
        }
    }

    #[test]
    fn from_host_stats_unavailable_when_feature_disabled() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(false, Some("quiesce_recommended")),
            SnapshotTimingHint::Unavailable
        );
    }

    #[test]
    fn from_host_stats_unavailable_when_feature_disabled_and_hint_absent() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(false, None),
            SnapshotTimingHint::Unavailable
        );
    }

    #[test]
    fn from_host_stats_maps_live_hint() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(true, Some("quiesce_recommended")),
            SnapshotTimingHint::QuiesceRecommended
        );
    }

    #[test]
    fn from_host_stats_maps_defer_active_io() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(true, Some("defer_active_io")),
            SnapshotTimingHint::DeferActiveIo
        );
    }

    #[test]
    fn from_host_stats_missing_hint_is_insufficient_data() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(true, None),
            SnapshotTimingHint::InsufficientData
        );
    }

    #[test]
    fn from_host_stats_unknown_hint_is_insufficient_data() {
        assert_eq!(
            SnapshotTimingHint::from_host_stats(true, Some("bogus")),
            SnapshotTimingHint::InsufficientData
        );
    }

    #[test]
    fn from_host_stats_json_backward_compatible_when_fields_absent() {
        let legacy = serde_json::json!({
            "sandbox_count": 3,
            "draining": false,
        });
        assert_eq!(
            SnapshotTimingHint::from_host_stats_json(&legacy),
            SnapshotTimingHint::Unavailable
        );
        assert!((SnapshotTimingHint::Unavailable.as_score() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn from_host_stats_json_reads_live_fields() {
        let stats = serde_json::json!({
            "snapshot_timing_hint": "quiesce_recommended",
            "snapshot_timing_available": true,
        });
        assert_eq!(
            SnapshotTimingHint::from_host_stats_json(&stats),
            SnapshotTimingHint::QuiesceRecommended
        );
    }

    #[test]
    fn from_host_stats_json_returns_unavailable_when_feature_offline() {
        let offline = serde_json::json!({
            "snapshot_timing_hint": "quiesce_recommended",
            "snapshot_timing_available": false,
        });
        assert_eq!(
            SnapshotTimingHint::from_host_stats_json(&offline),
            SnapshotTimingHint::Unavailable
        );
    }

    #[test]
    fn host_snapshot_timing_stats_as_hint_from_typed_payload() {
        let stats = HostSnapshotTimingStats {
            snapshot_timing_available: true,
            snapshot_timing_hint: Some("quiesce_recommended".into()),
        };
        assert_eq!(stats.as_hint(), SnapshotTimingHint::QuiesceRecommended);
        assert_eq!(
            SnapshotTimingHint::from(&stats),
            SnapshotTimingHint::QuiesceRecommended
        );
    }

    #[test]
    fn host_snapshot_timing_stats_from_stats_value_ignores_other_fields() {
        let full_stats = serde_json::json!({
            "sandbox_count": 2,
            "draining": false,
            "snapshot_timing_hint": "defer_active_io",
            "snapshot_timing_available": true,
            "gc": { "removed": 1 },
        });
        let report = HostSnapshotTimingStats::from_stats_value(&full_stats);
        assert!(report.snapshot_timing_available);
        assert_eq!(
            report.snapshot_timing_hint.as_deref(),
            Some("defer_active_io")
        );
        assert_eq!(report.as_hint(), SnapshotTimingHint::DeferActiveIo);
    }

    #[test]
    fn host_snapshot_timing_stats_serde_roundtrip() {
        let stats = HostSnapshotTimingStats {
            snapshot_timing_available: true,
            snapshot_timing_hint: Some("quiesce_acceptable".into()),
        };
        let json = serde_json::to_value(&stats).unwrap();
        let back: HostSnapshotTimingStats = serde_json::from_value(json).unwrap();
        assert_eq!(back, stats);
    }

    #[test]
    fn host_snapshot_timing_stats_serde_defaults_absent_fields() {
        let stats: HostSnapshotTimingStats = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!stats.snapshot_timing_available);
        assert_eq!(stats.snapshot_timing_hint, None);
        assert_eq!(stats.as_hint(), SnapshotTimingHint::Unavailable);
    }

    #[test]
    fn aggregate_uses_most_conservative_hint() {
        let aggregated = SnapshotTimingHint::aggregate([
            SnapshotTimingHint::QuiesceRecommended,
            SnapshotTimingHint::DeferActiveIo,
            SnapshotTimingHint::QuiesceAcceptable,
        ]);
        assert_eq!(aggregated, SnapshotTimingHint::DeferActiveIo);
    }

    #[test]
    fn aggregate_empty_iterator_is_insufficient_data() {
        assert_eq!(
            SnapshotTimingHint::aggregate(std::iter::empty()),
            SnapshotTimingHint::InsufficientData
        );
    }

    #[test]
    fn apply_host_snapshot_timing_updates_cell_info() {
        let mut cell = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        cell.apply_host_snapshot_timing([
            SnapshotTimingHint::QuiesceRecommended,
            SnapshotTimingHint::QuiesceAcceptable,
        ]);
        assert_eq!(
            cell.snapshot_timing_hint,
            SnapshotTimingHint::QuiesceAcceptable
        );
    }

    #[test]
    fn snapshot_timing_hint_from_str_roundtrips_known_values() {
        assert_eq!(
            "quiesce_recommended".parse::<SnapshotTimingHint>(),
            Ok(SnapshotTimingHint::QuiesceRecommended)
        );
        assert!("not_a_real_hint".parse::<SnapshotTimingHint>().is_err());
    }

    #[test]
    fn hosts_without_timing_feature_score_neutrally() {
        // Both cells score 0.5 on SnapshotTiming (Unavailable vs InsufficientData).
        // Asserts neutral scoring and stable tie-break by cell ID (cel_a < cel_b).
        let scheduler = RegionalScheduler::with_weights(ScoringWeights {
            capacity_headroom: 0.0,
            image_cache: 0.0,
            snapshot_cache: 0.0,
            admission_pressure: 0.0,
            region_preference: 0.0,
            snapshot_timing: 1.0,
        });
        let request = make_request();

        let mut cell_a = make_cell("cel_a", "rgn_us-east-1", CellHealth::Healthy);
        cell_a.snapshot_timing_hint =
            SnapshotTimingHint::from_host_stats(false, Some("quiesce_recommended"));

        let mut cell_b = make_cell("cel_b", "rgn_us-east-1", CellHealth::Healthy);
        cell_b.snapshot_timing_hint = SnapshotTimingHint::from_host_stats(true, None);

        let result = scheduler.schedule(&request, &[cell_a, cell_b]).unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_a");
        let timing = result
            .score_breakdown
            .as_ref()
            .unwrap()
            .components
            .iter()
            .find(|c| c.name == ScoreDimension::SnapshotTiming)
            .unwrap();
        assert!((timing.score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn live_host_stats_influence_regional_placement() {
        let scheduler = RegionalScheduler::with_weights(ScoringWeights {
            capacity_headroom: 0.0,
            image_cache: 0.0,
            snapshot_cache: 0.0,
            admission_pressure: 0.0,
            region_preference: 0.0,
            snapshot_timing: 1.0,
        });
        let request = make_request();

        let mut cell_busy = make_cell("cel_busy", "rgn_us-east-1", CellHealth::Healthy);
        let busy_host_stats = [
            HostSnapshotTimingStats {
                snapshot_timing_available: true,
                snapshot_timing_hint: Some("defer_active_io".into()),
            },
            HostSnapshotTimingStats {
                snapshot_timing_available: true,
                snapshot_timing_hint: Some("quiesce_recommended".into()),
            },
        ];
        cell_busy.apply_host_snapshot_timing(busy_host_stats.iter().map(SnapshotTimingHint::from));
        assert_eq!(
            cell_busy.snapshot_timing_hint,
            SnapshotTimingHint::DeferActiveIo
        );

        let mut cell_quiet = make_cell("cel_quiet", "rgn_us-east-1", CellHealth::Healthy);
        let quiet_host_stats = [HostSnapshotTimingStats {
            snapshot_timing_available: true,
            snapshot_timing_hint: Some("quiesce_recommended".into()),
        }];
        cell_quiet
            .apply_host_snapshot_timing(quiet_host_stats.iter().map(SnapshotTimingHint::from));
        assert_eq!(
            cell_quiet.snapshot_timing_hint,
            SnapshotTimingHint::QuiesceRecommended
        );

        let result = scheduler
            .schedule(&request, &[cell_busy, cell_quiet])
            .unwrap();
        assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_quiet");
    }

    #[test]
    fn cell_info_serde_defaults_missing_snapshot_timing_hint() {
        let json = serde_json::json!({
            "cell_id": "cel_legacy",
            "region_id": "rgn_us-east-1",
            "health": "healthy",
            "capacity": {
                "total_vcpus": 10,
                "allocated_vcpus": 0,
                "total_memory_mb": 1024,
                "allocated_memory_mb": 0,
                "max_sandboxes": 5,
                "current_sandboxes": 0
            },
            "supported_runtimes": ["firecracker"],
            "failure_domain": "fd-1",
            "cache": { "cached_images": [], "cached_snapshots": [] },
            "admission_pressure": 0.0
        });
        let cell: CellInfo = serde_json::from_value(json).unwrap();
        assert_eq!(
            cell.snapshot_timing_hint,
            SnapshotTimingHint::InsufficientData
        );
        assert!((cell.snapshot_timing_hint.as_score() - 0.5).abs() < f64::EPSILON);
    }
}
