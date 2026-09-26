//! Cost and capacity planning model.
//!
//! Converts ADR-0012 validation outputs (active density, cell
//! availability, restore pressure, image cache) plus caller
//! demand and a pluggable [`PriceBook`] into host counts, cell sizing,
//! cache/storage estimates, cost by workload class, headroom/autoscaling
//! guidance, and per-stage rollout limits.
//!
//! Fail-closed rules (no silent extrapolation):
//!
//! - P0/P1 evidence never authorizes quotas. [`RolloutLimits`] stay `None`
//!   until the **limiting** evidence phase across density, restore, cache,
//!   and availability is P2 (preview) or P3 (beta/production).
//! - Density from an exec-axis report is not active density. Only
//!   [`DensityAxis::ActiveCount`] reports size hosts.
//! - Only ramp/soak restore reports measure sustainable concurrency. Spike
//!   reports do not.
//! - Only thrash reports calibrate cache sizing. Cold/warm reports carry the
//!   unproven lab default.
//! - Every unmeasured axis (create rate, exec rate, restore rate, audit
//!   pipeline, egress, cell packing) is listed in `unknowns` with a class-C
//!   finding that names the follow-up issue.
//! - Prices are caller-supplied. [`PriceBook::example_lab`] is a lab-only
//!   example and must not be used for procurement.
//!
//! This module does not generate load and does not set a launch proven
//! operating point. P0/P1 plans never authorize regional quotas.

use serde::{Deserialize, Serialize};

use crate::availability::CellAvailabilityReport;
use crate::capacity::{
    ActiveCapacityReport, CapacityFinding, CapacityScope, DensityAxis, FailureClass,
    ValidationPhase,
};
use crate::image_cache::{ImageCacheReport, ImageCacheScenario};
use crate::restore_capacity::RestoreScenario;
use crate::runtime::RuntimeType;

/// Hours billed per host per month (30.4 days). Used for host cost only.
const HOURS_PER_MONTH: f64 = 730.0;
/// Seconds per 30-day month. Used for audit event volume.
const SECONDS_PER_MONTH: f64 = 2_592_000.0;
/// Assumed average audit event size. Not measured; listed as an unknown.
const AVG_AUDIT_EVENT_BYTES: u64 = 1024;
/// Bytes per GiB for storage math.
const BYTES_PER_GIB: f64 = 1_073_741_824.0;
/// Target hosts per cell before failure-domain minima apply.
const DEFAULT_HOSTS_PER_CELL_TARGET: u64 = 20;

/// Launch stage from ADR-0012. Controls headroom and which evidence phase
/// may publish rollout limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchStage {
    PrivatePreview,
    PublicLimitedBeta,
    Production,
}

impl LaunchStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivatePreview => "private_preview",
            Self::PublicLimitedBeta => "public_limited_beta",
            Self::Production => "production",
        }
    }

    /// Unused-capacity fraction vs the saturation knee (ADR-0012 stage table).
    pub fn headroom(self) -> f64 {
        match self {
            Self::PrivatePreview => 0.50,
            Self::PublicLimitedBeta | Self::Production => 0.25,
        }
    }

    /// Minimum cells in the region for this stage.
    pub fn min_cells(self) -> u64 {
        match self {
            Self::PrivatePreview => 1,
            Self::PublicLimitedBeta => 2,
            Self::Production => 3,
        }
    }

    /// Whether `phase` evidence may publish this stage's rollout limit.
    /// Preview needs P2+; beta and production need P3+. `phase` is the
    /// limiting (lowest) evidence phase across the four reports.
    pub fn may_publish_rollout(self, phase: ValidationPhase) -> bool {
        match self {
            Self::PrivatePreview => phase.may_set_lpop(),
            Self::PublicLimitedBeta | Self::Production => {
                matches!(phase, ValidationPhase::P3 | ValidationPhase::P4)
            }
        }
    }
}

/// ADR-0012 workload profile under cost attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClass {
    Short,
    Session,
    Restore,
    Fork,
    Net,
    Cold,
}

impl TrafficClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Short => "WP-SHORT",
            Self::Session => "WP-SESSION",
            Self::Restore => "WP-RESTORE",
            Self::Fork => "WP-FORK",
            Self::Net => "WP-NET",
            Self::Cold => "WP-COLD",
        }
    }
}

/// Share of one workload class in the planning mix.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TrafficClassShare {
    pub class: TrafficClass,
    pub share: f64,
}

/// Default LPOP soak mix (`MIX-AGENT-V1`) from ADR-0012.
pub fn mix_agent_v1() -> Vec<TrafficClassShare> {
    vec![
        TrafficClassShare {
            class: TrafficClass::Short,
            share: 0.50,
        },
        TrafficClassShare {
            class: TrafficClass::Session,
            share: 0.20,
        },
        TrafficClassShare {
            class: TrafficClass::Restore,
            share: 0.15,
        },
        TrafficClassShare {
            class: TrafficClass::Fork,
            share: 0.05,
        },
        TrafficClassShare {
            class: TrafficClass::Net,
            share: 0.07,
        },
        TrafficClassShare {
            class: TrafficClass::Cold,
            share: 0.03,
        },
    ]
}

/// Caller-supplied prices. All values must be finite and non-negative;
/// invalid entries are clamped to zero with a class-A finding.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PriceBook {
    pub usd_per_host_hour: f64,
    pub cell_cache_usd_per_gb_month: f64,
    pub snapshot_storage_usd_per_gb_month: f64,
    pub egress_usd_per_gb: f64,
    pub audit_usd_per_million_events: f64,
}

impl PriceBook {
    /// Lab-only example prices. Not a quote; never use for procurement.
    pub fn example_lab() -> Self {
        Self {
            usd_per_host_hour: 1.50,
            cell_cache_usd_per_gb_month: 0.10,
            snapshot_storage_usd_per_gb_month: 0.023,
            egress_usd_per_gb: 0.09,
            audit_usd_per_million_events: 0.50,
        }
    }

    fn invalid_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !valid_price(self.usd_per_host_hour) {
            out.push("usd_per_host_hour");
        }
        if !valid_price(self.cell_cache_usd_per_gb_month) {
            out.push("cell_cache_usd_per_gb_month");
        }
        if !valid_price(self.snapshot_storage_usd_per_gb_month) {
            out.push("snapshot_storage_usd_per_gb_month");
        }
        if !valid_price(self.egress_usd_per_gb) {
            out.push("egress_usd_per_gb");
        }
        if !valid_price(self.audit_usd_per_million_events) {
            out.push("audit_usd_per_million_events");
        }
        out
    }

    fn sanitized(&self) -> Self {
        Self {
            usd_per_host_hour: sane_price(self.usd_per_host_hour),
            cell_cache_usd_per_gb_month: sane_price(self.cell_cache_usd_per_gb_month),
            snapshot_storage_usd_per_gb_month: sane_price(self.snapshot_storage_usd_per_gb_month),
            egress_usd_per_gb: sane_price(self.egress_usd_per_gb),
            audit_usd_per_million_events: sane_price(self.audit_usd_per_million_events),
        }
    }
}

fn valid_price(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn sane_price(value: f64) -> f64 {
    if valid_price(value) { value } else { 0.0 }
}

/// Measured active density consumed from a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredDensity {
    pub backend: RuntimeType,
    pub host_sku: String,
    pub safe_max_per_host: Option<u64>,
    pub warning_max_per_host: Option<u64>,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub report_digest: String,
}

impl MeasuredDensity {
    /// Build from a report. Exec-axis reports do not measure active
    /// density, so they contribute no host sizing.
    pub fn from_active_report(report: &ActiveCapacityReport) -> Self {
        let active_axis = report.axis == DensityAxis::ActiveCount;
        Self {
            backend: report.backend,
            host_sku: report.host_sku.clone(),
            safe_max_per_host: if active_axis {
                report.zones.safe_max
            } else {
                None
            },
            warning_max_per_host: if active_axis {
                report.zones.warning_max
            } else {
                None
            },
            phase: report.phase,
            scope: report.scope,
            report_digest: report.artifact_digest(),
        }
    }

    /// Placeholder for an unmeasured backend/SKU. Plans from this carry a
    /// class-A `missing_density_measurement` finding.
    pub fn unmeasured(backend: RuntimeType, host_sku: &str) -> Self {
        Self {
            backend,
            host_sku: host_sku.into(),
            safe_max_per_host: None,
            warning_max_per_host: None,
            phase: ValidationPhase::P0,
            scope: CapacityScope::Host,
            report_digest: "unmeasured".into(),
        }
    }
}

/// Measured restore pressure consumed from a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredRestore {
    /// Sustainable concurrent restores per host. `None` for spike reports:
    /// a storm does not measure sustainable concurrency.
    pub concurrent_restores_per_host: Option<u64>,
    /// Sustained restores/s per host. Untimed P0 windows cannot measure a
    /// rate, so this stays `None` until a timed P2+ run exists.
    pub restores_per_sec_per_host: Option<f64>,
    pub phase: ValidationPhase,
    pub report_digest: String,
}

impl MeasuredRestore {
    /// Build from a report. Uses `report.scenario`, not a caller
    /// override: a spike report never measures sustainable concurrency.
    pub fn from_restore_report(report: &crate::restore_capacity::RestorePressureReport) -> Self {
        let concurrent = match report.scenario {
            RestoreScenario::RampRestore | RestoreScenario::SoakRestore => report.zones.warning_max,
            RestoreScenario::SpikeRestore => None,
        };
        Self {
            concurrent_restores_per_host: concurrent,
            restores_per_sec_per_host: None,
            phase: report.phase,
            report_digest: report.artifact_digest(),
        }
    }

    pub fn unmeasured() -> Self {
        Self {
            concurrent_restores_per_host: None,
            restores_per_sec_per_host: None,
            phase: ValidationPhase::P0,
            report_digest: "unmeasured".into(),
        }
    }
}

/// Measured image-cache sizing consumed from a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredImageCache {
    pub host_local_bytes_per_host: Option<u64>,
    pub cell_cache_bytes_per_cell: Option<u64>,
    pub warm_hit_rate: Option<f64>,
    /// True only for thrash reports. Cold/warm reports carry the unproven
    /// lab default and must not calibrate procurement.
    pub sizing_calibrated: bool,
    pub phase: ValidationPhase,
    pub report_digest: String,
}

impl MeasuredImageCache {
    /// Build from a report. Uses `report.scenario`: only thrash
    /// calibrates sizing. Cold/warm keep the unproven lab default.
    pub fn from_image_report(report: &ImageCacheReport) -> Self {
        Self {
            host_local_bytes_per_host: Some(report.sizing.host_local_bytes),
            cell_cache_bytes_per_cell: Some(report.sizing.cell_cache_bytes),
            warm_hit_rate: report.cache.hit_rate,
            sizing_calibrated: matches!(report.scenario, ImageCacheScenario::Thrash),
            phase: report.phase,
            report_digest: report.artifact_digest(),
        }
    }

    pub fn unmeasured() -> Self {
        Self {
            host_local_bytes_per_host: None,
            cell_cache_bytes_per_cell: None,
            warm_hit_rate: None,
            sizing_calibrated: false,
            phase: ValidationPhase::P0,
            report_digest: "unmeasured".into(),
        }
    }
}

/// Measured surviving capacity consumed from a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredAvailability {
    pub cells_total: u64,
    pub cells_eligible_after_loss: u64,
    pub hosts_eligible_after_loss: u64,
    pub phase: ValidationPhase,
    pub report_digest: String,
}

impl MeasuredAvailability {
    pub fn from_availability_report(report: &CellAvailabilityReport) -> Self {
        Self {
            cells_total: report.surviving.cells_total,
            cells_eligible_after_loss: report.surviving.cells_eligible,
            hosts_eligible_after_loss: report.surviving.hosts_eligible,
            phase: report.phase,
            report_digest: report.artifact_digest(),
        }
    }

    pub fn unmeasured() -> Self {
        Self {
            cells_total: 0,
            cells_eligible_after_loss: 0,
            hosts_eligible_after_loss: 0,
            phase: ValidationPhase::P0,
            report_digest: "unmeasured".into(),
        }
    }
}

/// Per-region demand the plan sizes for. Totals scale by `regions`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WorkloadDemand {
    pub target_active: u64,
    pub creates_per_min: u64,
    pub concurrent_execs: u64,
    pub restores_per_sec: f64,
    pub audit_events_per_sec: f64,
    pub egress_gb_per_month: f64,
    pub snapshot_bytes_per_active: u64,
    pub regions: u32,
}

/// Input to [`plan_capacity`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningInput {
    pub density: MeasuredDensity,
    pub restore: MeasuredRestore,
    pub image_cache: MeasuredImageCache,
    pub availability: MeasuredAvailability,
    pub demand: WorkloadDemand,
    pub mix: Vec<TrafficClassShare>,
    pub prices: PriceBook,
    pub stage: LaunchStage,
    pub hosts_per_cell_target: u64,
}

impl PlanningInput {
    /// Lab-only P0 example. Evidence is synthetic; the plan authorizes
    /// nothing and carries Low confidence.
    pub fn lab_p0_example() -> Self {
        use crate::capacity::CapacityScope;
        Self {
            density: MeasuredDensity {
                backend: RuntimeType::Firecracker,
                host_sku: "lab-64vcpu".into(),
                safe_max_per_host: Some(24),
                warning_max_per_host: Some(32),
                phase: ValidationPhase::P0,
                scope: CapacityScope::Host,
                report_digest: "lab-p0".into(),
            },
            restore: MeasuredRestore {
                concurrent_restores_per_host: Some(5),
                restores_per_sec_per_host: None,
                phase: ValidationPhase::P0,
                report_digest: "lab-p0".into(),
            },
            image_cache: MeasuredImageCache {
                host_local_bytes_per_host: Some(5 * 1024 * 1024 * 1024),
                cell_cache_bytes_per_cell: Some(20 * 1024 * 1024 * 1024),
                warm_hit_rate: Some(0.95),
                sizing_calibrated: false,
                phase: ValidationPhase::P0,
                report_digest: "lab-p0".into(),
            },
            availability: MeasuredAvailability {
                cells_total: 2,
                cells_eligible_after_loss: 1,
                hosts_eligible_after_loss: 0,
                phase: ValidationPhase::P0,
                report_digest: "lab-p0".into(),
            },
            demand: WorkloadDemand {
                target_active: 1_000,
                creates_per_min: 200,
                concurrent_execs: 100,
                restores_per_sec: 5.0,
                audit_events_per_sec: 50.0,
                egress_gb_per_month: 1_000.0,
                snapshot_bytes_per_active: 256 * 1024 * 1024,
                regions: 1,
            },
            mix: mix_agent_v1(),
            prices: PriceBook::example_lab(),
            stage: LaunchStage::PrivatePreview,
            hosts_per_cell_target: DEFAULT_HOSTS_PER_CELL_TARGET,
        }
    }
}

/// Confidence in the plan outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Host counts derived from measured density plus stage headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPlan {
    pub usable_active_per_host: Option<u64>,
    /// Hosts for `target_active` before headroom.
    pub hosts_for_active: Option<u64>,
    /// Hosts per region after headroom.
    pub hosts_per_region: Option<u64>,
    pub hosts_per_cell: Option<u64>,
    pub cells_per_region: Option<u64>,
    pub total_hosts_all_regions: Option<u64>,
    /// Proposed topology after losing one cell. Not the drill count.
    pub surviving_hosts_after_one_cell_loss: Option<u64>,
    /// Proposed layout covers pre-headroom demand after one cell loss, and
    /// (when P2+ multi-cell evidence exists) measured
    /// `hosts_eligible_after_loss` also covers it.
    pub meets_one_cell_survival: bool,
}

/// Cache and storage sizing per region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStoragePlan {
    pub host_local_bytes_per_host: Option<u64>,
    pub cell_cache_bytes_per_cell: Option<u64>,
    pub snapshot_storage_bytes_per_region: Option<u64>,
    /// Assumption-based (`AVG_AUDIT_EVENT_BYTES` x demand x 30d). Always
    /// computed; always listed as an unknown until ST-PIPE is measured.
    pub audit_storage_bytes_per_region_per_month: u64,
}

/// Monthly cost of one workload class.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ClassCost {
    pub class: TrafficClass,
    pub share: f64,
    pub monthly_usd: f64,
}

/// Monthly cost breakdown. Host and storage costs are shared infrastructure
/// allocated by mix share; egress is attributed to `WP-NET` when the mix
/// carries it and allocated by share otherwise; audit is allocated by share.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub hosts_monthly_usd: f64,
    pub storage_monthly_usd: f64,
    pub egress_monthly_usd: f64,
    pub audit_monthly_usd: f64,
    pub total_monthly_usd: f64,
    pub by_class: Vec<ClassCost>,
}

/// Headroom and autoscaling guidance for the planned footprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeadroomAutoscale {
    pub headroom_fraction: f64,
    pub target_utilization: f64,
    pub usable_active_per_region: Option<u64>,
    pub headroom_active_slots: Option<u64>,
    pub scale_out_at_active: Option<u64>,
    pub recommendation: String,
}

/// Rollout cap for one launch stage. Rate caps stay `None` while their axes
/// are unmeasured; `max_active` is the binding cap.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StageLimit {
    pub max_active: u64,
    pub max_creates_per_min: Option<u64>,
    pub max_concurrent_execs: Option<u64>,
    pub max_restores_per_sec: Option<f64>,
}

/// Rollout limits by phase. `None` means the stage is not authorized by the
/// current evidence phase.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RolloutLimits {
    pub preview: Option<StageLimit>,
    pub beta: Option<StageLimit>,
    pub production: Option<StageLimit>,
}

/// One sensitivity row: one variable swept low/base/high.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensitivityRow {
    pub variable: String,
    pub low_value: f64,
    pub base_value: f64,
    pub high_value: f64,
    pub hosts_low: Option<u64>,
    pub hosts_base: Option<u64>,
    pub hosts_high: Option<u64>,
    pub cost_low_usd: f64,
    pub cost_base_usd: f64,
    pub cost_high_usd: f64,
}

/// Comparison of a predicted plan against a second validation run.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PlanComparison {
    pub predicted_hosts: Option<u64>,
    pub observed_hosts: Option<u64>,
    pub hosts_delta: Option<i64>,
    /// `(predicted - observed) / observed * 100`. `None` when observed is
    /// missing or zero.
    pub hosts_error_pct: Option<f64>,
    pub cost_delta_usd: f64,
    pub cost_error_pct: Option<f64>,
}

/// Capacity and cost plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapacityPlan {
    pub stage: LaunchStage,
    pub host_sku: String,
    pub backend: RuntimeType,
    pub hosts: HostPlan,
    pub cache_storage: CacheStoragePlan,
    pub cost: CostBreakdown,
    pub headroom: HeadroomAutoscale,
    pub rollout: RolloutLimits,
    pub confidence: Confidence,
    pub unknowns: Vec<String>,
    pub sensitivity: Vec<SensitivityRow>,
    pub findings: Vec<CapacityFinding>,
    pub evidence_digests: Vec<String>,
}

impl CapacityPlan {
    /// Content digest of the plan JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Cost and capacity plan (86)\n\n");
        out.push_str(&format!(
            "- Stage: {}\n- Backend: {}\n- Host SKU: {}\n- Confidence: {:?}\n",
            self.stage.as_str(),
            self.backend,
            self.host_sku,
            self.confidence
        ));
        out.push_str(&format!(
            "- Hosts per region: {}\n- Cells per region: {}\n- Hosts per cell: {}\n- Surviving hosts after one cell loss: {}\n",
            fmt_opt(self.hosts.hosts_per_region),
            fmt_opt(self.hosts.cells_per_region),
            fmt_opt(self.hosts.hosts_per_cell),
            fmt_opt(self.hosts.surviving_hosts_after_one_cell_loss)
        ));
        out.push_str(&format!(
            "- Monthly cost: ${:.2} (hosts ${:.2}, storage ${:.2}, egress ${:.2}, audit ${:.2})\n",
            self.cost.total_monthly_usd,
            self.cost.hosts_monthly_usd,
            self.cost.storage_monthly_usd,
            self.cost.egress_monthly_usd,
            self.cost.audit_monthly_usd
        ));
        out.push_str(&format!(
            "- Rollout limits: preview {}, beta {}, production {}\n",
            fmt_limit(self.rollout.preview),
            fmt_limit(self.rollout.beta),
            fmt_limit(self.rollout.production)
        ));
        if self.unknowns.is_empty() {
            out.push_str("- Unknowns: none\n");
        } else {
            out.push_str("- Unknowns:\n");
            for unknown in &self.unknowns {
                out.push_str(&format!("  - {unknown}\n"));
            }
        }
        if self.findings.is_empty() {
            out.push_str("- Findings: none\n");
        } else {
            out.push_str("- Findings:\n");
            for finding in &self.findings {
                out.push_str(&format!(
                    "  - class {:?}: {} ({})\n",
                    finding.class, finding.code, finding.detail
                ));
            }
        }
        out
    }
}

fn fmt_opt(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".into())
}

fn fmt_limit(limit: Option<StageLimit>) -> String {
    limit
        .map(|l| format!("max_active={}", l.max_active))
        .unwrap_or_else(|| "none".into())
}

fn finding(class: FailureClass, code: &str, detail: impl Into<String>) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: None,
    }
}

fn finding_follow(
    class: FailureClass,
    code: &str,
    detail: impl Into<String>,
    issue: &str,
) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: Some(issue.into()),
    }
}

/// Plan hosts, cells, cache, storage, cost, headroom, and rollout limits.
///
/// Sensitivity analysis is included. See [`plan_capacity_without_sensitivity`]
/// for the recursion-free core used by each sensitivity row.
pub fn plan_capacity(input: &PlanningInput) -> CapacityPlan {
    let mut plan = plan_capacity_without_sensitivity(input);
    plan.sensitivity = default_sensitivity(input);
    plan
}

/// Core planner without sensitivity rows.
pub fn plan_capacity_without_sensitivity(input: &PlanningInput) -> CapacityPlan {
    let mut findings = Vec::new();
    let mut unknowns = Vec::new();

    // Mix shares must sum to 1. Normalize with a class-B finding otherwise.
    let mix = normalized_mix(&input.mix, &mut findings);

    // Prices are caller-supplied; clamp invalid entries to zero.
    let bad_prices = input.prices.invalid_fields();
    if !bad_prices.is_empty() {
        findings.push(finding(
            FailureClass::A,
            "invalid_pricebook",
            format!(
                "price book has non-finite or negative entries ({}); clamped to zero",
                bad_prices.join(", ")
            ),
        ));
    }
    let prices = input.prices.sanitized();

    // Demand sanity. Zero regions is degenerate: per-region math proceeds
    // with a 1-region equivalent (never zero hosts) and totals are marked
    // per-region-only by the finding.
    let regions = input.demand.regions;
    if regions == 0 {
        findings.push(finding(
            FailureClass::A,
            "invalid_demand",
            "demand regions is 0; math uses a 1-region equivalent and totals are per-region only",
        ));
    }
    let regions_eff = u64::from(regions.max(1));

    // Backend eligibility gates rollout, never host math.
    if !input.density.backend.is_production_eligible() {
        findings.push(finding(
            FailureClass::A,
            "backend_not_production_eligible",
            format!(
                "{} is not production-eligible; no stage rollout is authorized",
                input.density.backend
            ),
        ));
    }

    // Measured density is the only host-sizing input.
    let usable = match input.density.warning_max_per_host {
        Some(limit) if limit > 0 => Some(limit),
        _ => {
            findings.push(finding_follow(
                FailureClass::A,
                "missing_density_measurement",
                "no measured warning-max density; hosts cannot be sized from assumptions",
                "63",
            ));
            None
        }
    };
    if input.density.phase == ValidationPhase::P0 || input.density.phase == ValidationPhase::P1 {
        findings.push(finding(
            FailureClass::C,
            "phase_cannot_set_lpop",
            format!(
                "{:?} may not set an LPOP; host counts are candidate inputs only",
                input.density.phase
            ),
        ));
    }

    // Host math: active binding first, then stage headroom.
    let headroom = input.stage.headroom();
    let hosts_for_active = usable.map(|per_host| input.demand.target_active.div_ceil(per_host));
    let hosts_per_region = hosts_for_active.map(|hosts| apply_headroom(hosts, headroom));

    // Cell layout with failure-domain minima and one-cell survival.
    let target_per_cell = input.hosts_per_cell_target.max(1);
    let (cells_per_region, hosts_per_cell, surviving, meets) = match hosts_per_region {
        Some(hosts) => {
            let layout = layout_cells(hosts, hosts_for_active, target_per_cell, input.stage);
            (Some(layout.0), Some(layout.1), Some(layout.2), layout.3)
        }
        None => (None, None, None, false),
    };
    if hosts_per_region.is_some_and(|hosts| hosts > 0) && !meets {
        findings.push(finding_follow(
            FailureClass::B,
            "survival_needs_extra_cell",
            "planned cells do not leave one-cell survival above pre-headroom demand even after growth",
            "64",
        ));
    }

    // Availability evidence is provisional before P2 or without 2+ cells.
    let measured_availability =
        input.availability.phase.may_set_lpop() && input.availability.cells_total >= 2;
    if !measured_availability {
        findings.push(finding_follow(
            FailureClass::C,
            "surviving_capacity_provisional",
            "surviving capacity is synthetic or single-cell; cell sizing is provisional",
            "64",
        ));
    }
    let measured_covers = match hosts_for_active {
        Some(need)
            if measured_availability && input.availability.hosts_eligible_after_loss < need =>
        {
            findings.push(finding_follow(
                FailureClass::B,
                "measured_survival_below_demand",
                format!(
                    "64 drill surviving hosts {} is below pre-headroom demand {need}",
                    input.availability.hosts_eligible_after_loss
                ),
                "64",
            ));
            false
        }
        _ => true,
    };
    let meets = meets && measured_covers;

    // Unmeasured rate axes. The plan sizes by active count only.
    push_rate_unknowns(input, &mut findings, &mut unknowns);

    // Cell packing from host-scope evidence is provisional.
    if input.density.scope == CapacityScope::Host {
        unknowns.push(
            "cell_packing: host-scope evidence only; the cell control plane knee is unproven (needs P2 cell validation)"
                .into(),
        );
        findings.push(finding_follow(
            FailureClass::C,
            "cell_packing_unproven",
            "host density may inform cell packing only after a cell test shows the cell control plane is not the knee",
            "63",
        ));
    }

    // Image cache sizing confidence.
    if !input.image_cache.sizing_calibrated {
        unknowns.push(
            "cache_sizing: working-set sizing is an uncalibrated lab default (cold/warm or synthetic); thrash calibration pending"
                .into(),
        );
        findings.push(finding_follow(
            FailureClass::C,
            "image_cache_unproven",
            "cache bytes are candidate inputs, not a published working set",
            "66",
        ));
    }

    // Cache and storage.
    let cache_storage = CacheStoragePlan {
        host_local_bytes_per_host: input.image_cache.host_local_bytes_per_host,
        cell_cache_bytes_per_cell: input.image_cache.cell_cache_bytes_per_cell,
        snapshot_storage_bytes_per_region: Some(
            input
                .demand
                .target_active
                .saturating_mul(input.demand.snapshot_bytes_per_active),
        ),
        audit_storage_bytes_per_region_per_month: (input.demand.audit_events_per_sec
            * SECONDS_PER_MONTH) as u64
            * AVG_AUDIT_EVENT_BYTES,
    };

    // Cost.
    let cost = cost_breakdown(
        input,
        &mix,
        &prices,
        hosts_per_region,
        cells_per_region,
        &cache_storage,
        regions_eff,
    );

    // Headroom and autoscaling.
    let usable_region = usable
        .zip(hosts_per_region)
        .map(|(per_host, hosts)| per_host.saturating_mul(hosts));
    let headroom_slots =
        usable_region.map(|usable| usable.saturating_sub(input.demand.target_active));
    let scale_out_at = usable_region.map(|usable| (usable as f64 * (1.0 - headroom)) as u64);
    let headroom_recommendation = match (hosts_per_region, usable_region, scale_out_at) {
        (Some(hosts), Some(usable), Some(scale_at)) => format!(
            "hold {hosts} hosts/region ({usable} usable active at warning density); add hosts when sustained active exceeds {scale_at} ({:.0}% utilization); keep one-cell survival above pre-headroom demand",
            (1.0 - headroom) * 100.0
        ),
        _ => "no autoscaling guidance without measured density".into(),
    };
    let headroom_plan = HeadroomAutoscale {
        headroom_fraction: headroom,
        target_utilization: 1.0 - headroom,
        usable_active_per_region: usable_region,
        headroom_active_slots: headroom_slots,
        scale_out_at_active: scale_out_at,
        recommendation: headroom_recommendation,
    };

    // Rollout limits per stage.
    let hosts = HostPlan {
        usable_active_per_host: usable,
        hosts_for_active,
        hosts_per_region,
        hosts_per_cell,
        cells_per_region,
        total_hosts_all_regions: hosts_per_region.map(|h| h.saturating_mul(regions_eff)),
        surviving_hosts_after_one_cell_loss: surviving,
        meets_one_cell_survival: meets,
    };
    let evidence_phase = limiting_evidence_phase(input);
    let rollout = RolloutLimits {
        preview: stage_limit(
            LaunchStage::PrivatePreview,
            input,
            evidence_phase,
            usable,
            hosts_for_active,
        ),
        beta: stage_limit(
            LaunchStage::PublicLimitedBeta,
            input,
            evidence_phase,
            usable,
            hosts_for_active,
        ),
        production: stage_limit(
            LaunchStage::Production,
            input,
            evidence_phase,
            usable,
            hosts_for_active,
        ),
    };
    if evidence_phase.may_set_lpop() && !LaunchStage::Production.may_publish_rollout(evidence_phase)
    {
        findings.push(finding_follow(
            FailureClass::C,
            "stage_needs_regional_evidence",
            "limiting evidence phase authorizes preview only; beta and production need P3 regional evidence",
            "91",
        ));
    }

    let confidence = confidence_for(input, usable);

    dedupe_findings(&mut findings);

    CapacityPlan {
        stage: input.stage,
        host_sku: input.density.host_sku.clone(),
        backend: input.density.backend,
        hosts,
        cache_storage,
        cost,
        headroom: headroom_plan,
        rollout,
        confidence,
        unknowns,
        sensitivity: Vec::new(),
        findings,
        evidence_digests: vec![
            input.density.report_digest.clone(),
            input.restore.report_digest.clone(),
            input.image_cache.report_digest.clone(),
            input.availability.report_digest.clone(),
        ],
    }
}

fn normalized_mix(
    mix: &[TrafficClassShare],
    findings: &mut Vec<CapacityFinding>,
) -> Vec<TrafficClassShare> {
    if mix.is_empty() {
        findings.push(finding(
            FailureClass::B,
            "mix_shares_unnormalized",
            "workload mix is empty; cost falls back to MIX-AGENT-V1",
        ));
        return mix_agent_v1();
    }
    let sum: f64 = mix.iter().map(|entry| entry.share).sum();
    if !sum.is_finite() || sum <= 0.0 {
        findings.push(finding(
            FailureClass::B,
            "mix_shares_unnormalized",
            "workload mix shares are not positive; cost falls back to MIX-AGENT-V1",
        ));
        return mix_agent_v1();
    }
    if (sum - 1.0).abs() > 0.001 {
        findings.push(finding(
            FailureClass::B,
            "mix_shares_unnormalized",
            format!("workload mix shares sum to {sum:.4}; cost normalizes them"),
        ));
    }
    mix.iter()
        .map(|entry| TrafficClassShare {
            class: entry.class,
            share: if entry.share.is_finite() && entry.share >= 0.0 {
                entry.share / sum
            } else {
                0.0
            },
        })
        .collect()
}

fn apply_headroom(hosts: u64, headroom: f64) -> u64 {
    if hosts == 0 {
        return 0;
    }
    let divisor = (1.0 - headroom).max(0.01);
    ((hosts as f64 / divisor).ceil() as u64).max(1)
}

/// Lay out `hosts` into cells: at least the stage minimum, at most
/// `target_per_cell` hosts per cell, grown until one-cell survival covers
/// pre-headroom demand.
fn layout_cells(
    hosts: u64,
    hosts_for_active: Option<u64>,
    target_per_cell: u64,
    stage: LaunchStage,
) -> (u64, u64, u64, bool) {
    if hosts == 0 {
        return (stage.min_cells(), 0, 0, true);
    }
    let mut cells = stage
        .min_cells()
        .max(hosts.div_ceil(target_per_cell))
        .max(1);
    for _ in 0..64 {
        let per_cell = hosts.div_ceil(cells);
        let surviving = hosts.saturating_sub(per_cell);
        let need = hosts_for_active.unwrap_or(hosts);
        if surviving >= need || cells >= hosts.max(1) {
            return (cells, per_cell, surviving, surviving >= need);
        }
        cells += 1;
    }
    let per_cell = hosts.div_ceil(cells);
    let surviving = hosts.saturating_sub(per_cell);
    (cells, per_cell, surviving, false)
}

fn push_rate_unknowns(
    input: &PlanningInput,
    findings: &mut Vec<CapacityFinding>,
    unknowns: &mut Vec<String>,
) {
    unknowns.push(
        "creates_per_min_per_host: S-RAMP-CREATE throughput is not consumed; plan sizes by active count only (22/91)"
            .into(),
    );
    findings.push(finding_follow(
        FailureClass::C,
        "creates_rate_unmeasured",
        "create throughput per host/cell is not in this plan's evidence",
        "22",
    ));
    unknowns.push(
        "exec_concurrency_per_host: S-RAMP-EXEC LPOP is not consumed; do not copy the active-count cap (63)"
            .into(),
    );
    findings.push(finding_follow(
        FailureClass::C,
        "exec_rate_unmeasured",
        "exec concurrency per host is not in this plan's evidence",
        "63",
    ));
    if input.restore.restores_per_sec_per_host.is_none() {
        unknowns.push(
            "restores_per_sec_per_host: restore windows are untimed; restore/s cannot size hosts yet (65/22)"
                .into(),
        );
        findings.push(finding_follow(
            FailureClass::C,
            "restore_rate_unmeasured",
            "sustained restores/s per host is not in this plan's evidence",
            "65",
        ));
    }
    unknowns.push(
        "audit_pipeline: ST-PIPE throughput and lag are not consumed; audit cost uses the demand assumption (91)"
            .into(),
    );
    findings.push(finding_follow(
        FailureClass::C,
        "audit_pipeline_unmeasured",
        "audit events/s capacity and max lag at LPOP are not in this plan's evidence",
        "91",
    ));
    unknowns.push(
        "egress_throughput: WP-NET/DNS/port-forwarding behavior is not load-validated; egress cost uses the demand assumption"
            .into(),
    );
    findings.push(finding_follow(
        FailureClass::C,
        "egress_unmeasured",
        "network egress and DNS/port-forwarding capacity are not in this plan's evidence",
        "22",
    ));
}

#[allow(clippy::too_many_arguments)]
fn cost_breakdown(
    input: &PlanningInput,
    mix: &[TrafficClassShare],
    prices: &PriceBook,
    hosts_per_region: Option<u64>,
    cells_per_region: Option<u64>,
    cache_storage: &CacheStoragePlan,
    regions: u64,
) -> CostBreakdown {
    let regions_f = regions as f64;
    let hosts_total = hosts_per_region.unwrap_or(0) as f64 * regions_f;
    let hosts_monthly = hosts_total * prices.usd_per_host_hour * HOURS_PER_MONTH;

    let snapshot_gib = cache_storage.snapshot_storage_bytes_per_region.unwrap_or(0) as f64
        / BYTES_PER_GIB
        * regions_f;
    let cell_cache_gib = input
        .image_cache
        .cell_cache_bytes_per_cell
        .zip(cells_per_region)
        .map(|(bytes, cells)| bytes as f64 * cells as f64 / BYTES_PER_GIB * regions_f)
        .unwrap_or(0.0);
    let storage_monthly = snapshot_gib * prices.snapshot_storage_usd_per_gb_month
        + cell_cache_gib * prices.cell_cache_usd_per_gb_month;

    let egress_monthly = input.demand.egress_gb_per_month * prices.egress_usd_per_gb * regions_f;

    let audit_events_month = input.demand.audit_events_per_sec * SECONDS_PER_MONTH * regions_f;
    let audit_monthly = audit_events_month / 1_000_000.0 * prices.audit_usd_per_million_events;

    let infra = hosts_monthly + storage_monthly;
    // Egress belongs to WP-NET when the mix carries it; otherwise it is
    // shared infrastructure allocated by mix share so class costs still sum
    // to the total.
    let has_net = mix.iter().any(|entry| entry.class == TrafficClass::Net);
    let mut by_class: Vec<ClassCost> = mix
        .iter()
        .map(|entry| ClassCost {
            class: entry.class,
            share: entry.share,
            monthly_usd: infra * entry.share
                + if has_net {
                    if entry.class == TrafficClass::Net {
                        egress_monthly
                    } else {
                        0.0
                    }
                } else {
                    egress_monthly * entry.share
                }
                + audit_monthly * entry.share,
        })
        .collect();
    by_class.sort_by(|a, b| a.class.as_str().cmp(b.class.as_str()));

    CostBreakdown {
        hosts_monthly_usd: hosts_monthly,
        storage_monthly_usd: storage_monthly,
        egress_monthly_usd: egress_monthly,
        audit_monthly_usd: audit_monthly,
        total_monthly_usd: hosts_monthly + storage_monthly + egress_monthly + audit_monthly,
        by_class,
    }
}

fn phase_rank(phase: ValidationPhase) -> u8 {
    match phase {
        ValidationPhase::P0 => 0,
        ValidationPhase::P1 => 1,
        ValidationPhase::P2 => 2,
        ValidationPhase::P3 => 3,
        ValidationPhase::P4 => 4,
    }
}

fn min_phase(left: ValidationPhase, right: ValidationPhase) -> ValidationPhase {
    if phase_rank(left) <= phase_rank(right) {
        left
    } else {
        right
    }
}

/// Lowest evidence phase among density, restore, cache, and availability.
fn limiting_evidence_phase(input: &PlanningInput) -> ValidationPhase {
    min_phase(
        min_phase(input.density.phase, input.restore.phase),
        min_phase(input.image_cache.phase, input.availability.phase),
    )
}

fn stage_limit(
    stage: LaunchStage,
    input: &PlanningInput,
    evidence_phase: ValidationPhase,
    usable_per_host: Option<u64>,
    hosts_for_active: Option<u64>,
) -> Option<StageLimit> {
    if !input.density.backend.is_production_eligible() {
        return None;
    }
    if !stage.may_publish_rollout(evidence_phase) {
        return None;
    }
    let usable = usable_per_host?;
    let base_hosts = hosts_for_active?;
    let hosts = apply_headroom(base_hosts, stage.headroom());
    let max_active = ((usable as f64 * hosts as f64) * (1.0 - stage.headroom())) as u64;
    Some(StageLimit {
        max_active,
        max_creates_per_min: None,
        max_concurrent_execs: None,
        max_restores_per_sec: None,
    })
}

fn confidence_for(input: &PlanningInput, usable: Option<u64>) -> Confidence {
    let evidence_phase = limiting_evidence_phase(input);
    if !evidence_phase.may_set_lpop() {
        return Confidence::Low;
    }
    if usable.is_none() || !input.density.backend.is_production_eligible() {
        return Confidence::Low;
    }
    if input.density.scope == CapacityScope::Host
        || input.restore.restores_per_sec_per_host.is_none()
        || !matches!(evidence_phase, ValidationPhase::P3 | ValidationPhase::P4)
    {
        return Confidence::Medium;
    }
    Confidence::High
}

fn dedupe_findings(findings: &mut Vec<CapacityFinding>) {
    let mut seen = Vec::new();
    findings.retain(|finding| {
        let key = (finding.class, finding.code.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

/// Sensitivity analysis over the major variables: active density, target
/// demand, snapshot size, host price, and egress volume. Each row re-runs
/// the planner (without nested sensitivity) at low/base/high.
pub fn default_sensitivity(input: &PlanningInput) -> Vec<SensitivityRow> {
    let mut rows = Vec::new();
    let base_density = input.density.warning_max_per_host.unwrap_or(0) as f64;

    rows.push(sweep(
        "warning_max_per_host",
        base_density * 0.8,
        base_density,
        base_density * 1.2,
        |candidate, value| {
            candidate.density.warning_max_per_host = nonzero_u64(value);
            candidate.density.safe_max_per_host = candidate
                .density
                .safe_max_per_host
                .map(|safe| (safe as f64 * value / base_density.max(1.0)) as u64);
        },
        input,
    ));
    rows.push(sweep(
        "target_active",
        input.demand.target_active as f64 * 0.8,
        input.demand.target_active as f64,
        input.demand.target_active as f64 * 1.2,
        |candidate, value| {
            candidate.demand.target_active = value.max(0.0) as u64;
        },
        input,
    ));
    rows.push(sweep(
        "snapshot_bytes_per_active",
        input.demand.snapshot_bytes_per_active as f64 * 0.5,
        input.demand.snapshot_bytes_per_active as f64,
        input.demand.snapshot_bytes_per_active as f64 * 1.5,
        |candidate, value| {
            candidate.demand.snapshot_bytes_per_active = value.max(0.0) as u64;
        },
        input,
    ));
    rows.push(sweep(
        "usd_per_host_hour",
        input.prices.usd_per_host_hour * 0.8,
        input.prices.usd_per_host_hour,
        input.prices.usd_per_host_hour * 1.2,
        |candidate, value| {
            candidate.prices.usd_per_host_hour = value.max(0.0);
        },
        input,
    ));
    rows.push(sweep(
        "egress_gb_per_month",
        input.demand.egress_gb_per_month * 0.5,
        input.demand.egress_gb_per_month,
        input.demand.egress_gb_per_month * 1.5,
        |candidate, value| {
            candidate.demand.egress_gb_per_month = value.max(0.0);
        },
        input,
    ));
    rows
}

fn nonzero_u64(value: f64) -> Option<u64> {
    let rounded = value.round() as u64;
    if rounded == 0 { None } else { Some(rounded) }
}

fn sweep(
    variable: &'static str,
    low: f64,
    base: f64,
    high: f64,
    apply: impl Fn(&mut PlanningInput, f64),
    input: &PlanningInput,
) -> SensitivityRow {
    let eval = |value: f64| {
        let mut candidate = input.clone();
        apply(&mut candidate, value);
        plan_capacity_without_sensitivity(&candidate)
    };
    let low_plan = eval(low);
    let base_plan = eval(base);
    let high_plan = eval(high);
    SensitivityRow {
        variable: variable.into(),
        low_value: low,
        base_value: base,
        high_value: high,
        hosts_low: low_plan.hosts.total_hosts_all_regions,
        hosts_base: base_plan.hosts.total_hosts_all_regions,
        hosts_high: high_plan.hosts.total_hosts_all_regions,
        cost_low_usd: low_plan.cost.total_monthly_usd,
        cost_base_usd: base_plan.cost.total_monthly_usd,
        cost_high_usd: high_plan.cost.total_monthly_usd,
    }
}

/// Relative forecast error in percent: `(predicted - observed) / observed *
/// 100`. Used to compare a plan prediction against a second validation run.
/// Returns `None` when the observed value is missing or zero.
pub fn forecast_error_pct(predicted: Option<u64>, observed: Option<u64>) -> Option<f64> {
    let observed = observed?;
    if observed == 0 {
        return None;
    }
    let predicted = predicted.unwrap_or(0);
    Some((predicted as f64 - observed as f64) / observed as f64 * 100.0)
}

/// Compare a predicted plan against the plan built from a second validation
/// run (same demand, fresh evidence).
pub fn compare_plans(predicted: &CapacityPlan, observed: &CapacityPlan) -> PlanComparison {
    let predicted_hosts = predicted.hosts.total_hosts_all_regions;
    let observed_hosts = observed.hosts.total_hosts_all_regions;
    let hosts_delta = match (predicted_hosts, observed_hosts) {
        (Some(p), Some(o)) => Some(p as i64 - o as i64),
        _ => None,
    };
    let cost_delta = predicted.cost.total_monthly_usd - observed.cost.total_monthly_usd;
    let cost_error = if observed.cost.total_monthly_usd > 0.0 {
        Some(cost_delta / observed.cost.total_monthly_usd * 100.0)
    } else {
        None
    };
    PlanComparison {
        predicted_hosts,
        observed_hosts,
        hosts_delta,
        hosts_error_pct: forecast_error_pct(predicted_hosts, observed_hosts),
        cost_delta_usd: cost_delta,
        cost_error_pct: cost_error,
    }
}

#[cfg(test)]
mod tests;
