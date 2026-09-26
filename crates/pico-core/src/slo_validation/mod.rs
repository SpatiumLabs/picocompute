//! G-14 SLO and LPOP evidence validation (ST-API/ST-CREATE/ST-PIPE).
//!
//! Composes ADR-0012 scenario coverage with the live `pico:slo:*`
//! recording-rule math from `o11y/rules/pico-recording-rules.yaml` and the
//! SLO policy in `docs/observability/slo-error-budget-policy.md`.
//!
//! Existing models already cover ST-ACTIVE/ST-EXEC
//! ([`crate::capacity`]), ST-RESTORE ([`crate::restore_capacity`]), ST-CACHE
//! ([`crate::image_cache`]), and ST-CELL ([`crate::availability`]). This
//! module covers the remaining rate axes (ST-API, ST-CREATE, ST-PIPE), the
//! burn-alert simulation, the freeze check, the full scenario-to-target
//! mapping, and the G-14 evidence bundle seam.
//!
//! P0 tests exercise the seam with synthetic series. P0/P1 bundles never set
//! an LPOP and never authorize quotas.

use serde::{Deserialize, Serialize};

use crate::capacity::{
    CapacityFinding, CapacityScope, DensityZone, FailureClass, ResourcePressureSample, SafetyFlags,
    ValidationPhase,
};
use crate::runtime::RuntimeType;

/// Fast-burn multiplier: spends the 30-day budget in about 50 hours.
pub const FAST_BURN_THRESHOLD: f64 = 14.4;
/// Slow-burn multiplier: spends the 30-day budget in about 5 days.
pub const SLOW_BURN_THRESHOLD: f64 = 6.0;
/// Minimum `pico:slo:valid:rate5m` for a fast-burn page (about 36 events/hour).
pub const FAST_VALID_RATE_FLOOR: f64 = 0.01;
/// Minimum `pico:slo:valid:rate30m` for a slow-burn ticket.
pub const SLOW_VALID_RATE_FLOOR: f64 = 0.003;
/// Freeze threshold: feature rollouts freeze below 25% remaining budget.
pub const FREEZE_BUDGET_THRESHOLD: f64 = 0.25;
/// Host-level cgroup memory-pressure bands (0-100), mirroring
/// [`crate::capacity::DensityThresholds`].
pub const MEMORY_PRESSURE_WARNING: f64 = 15.0;
pub const MEMORY_PRESSURE_SATURATION: f64 = 30.0;
/// Host utilization bands (0.0-1.0), mirroring
/// [`crate::capacity::DensityThresholds`].
pub const UTILIZATION_WARNING: f64 = 0.75;
pub const UTILIZATION_SATURATION: f64 = 0.90;
/// Harness version pinned into every P0 bundle.
pub const HARNESS_VERSION: &str = "g14-p0.1";
/// Default LPOP soak mix from ADR-0012.
pub const MIX_AGENT_V1: &str = "MIX-AGENT-V1";

/// SLO identifier matching the `slo` label in `pico:slo:*` series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloId {
    Create,
    Boot,
    Exec,
    Destroy,
    Suspend,
    Resume,
    Fork,
    Restore,
    Audit,
}

impl SloId {
    /// Value of the `slo` label in recording rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Boot => "boot",
            Self::Exec => "exec",
            Self::Destroy => "destroy",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Fork => "fork",
            Self::Restore => "restore",
            Self::Audit => "audit",
        }
    }

    /// Availability target from the SLO policy and recording rules.
    pub fn target(self) -> f64 {
        match self {
            Self::Create
            | Self::Boot
            | Self::Suspend
            | Self::Resume
            | Self::Fork
            | Self::Restore => 0.995,
            Self::Exec | Self::Destroy => 0.999,
            Self::Audit => 0.9999,
        }
    }

    /// Error budget as `1 - target`.
    pub fn budget(self) -> f64 {
        1.0 - self.target()
    }

    /// Whether this SLO gates the rollout freeze as user-facing availability.
    /// Audit is platform health: it pages on its own but does not count as
    /// user-facing budget for the 25% freeze rule.
    pub fn is_user_facing(self) -> bool {
        !matches!(self, Self::Audit)
    }

    /// All SLOs in recording-rule order.
    pub fn all() -> [Self; 9] {
        [
            Self::Create,
            Self::Boot,
            Self::Exec,
            Self::Destroy,
            Self::Suspend,
            Self::Resume,
            Self::Fork,
            Self::Restore,
            Self::Audit,
        ]
    }
}

/// Error ratio `bad/valid`. Returns `None` when there are no valid events,
/// which PromQL reports as no data (never as 0% errors).
pub fn error_ratio(bad: u64, valid: u64) -> Option<f64> {
    if valid == 0 {
        None
    } else {
        Some(bad as f64 / valid as f64)
    }
}

/// Burn rate `error_ratio/(1-target)`. Burn `1` spends the 30-day budget
/// exactly on schedule.
pub fn burn_rate(error_ratio_value: f64, target: f64) -> Option<f64> {
    let budget = 1.0 - target;
    if budget <= 0.0 {
        None
    } else {
        Some(error_ratio_value / budget)
    }
}

/// Budget remaining `clamp_min(1 - burn_30d, 0)`.
pub fn budget_remaining(error_ratio_30d: f64, target: f64) -> f64 {
    match burn_rate(error_ratio_30d, target) {
        Some(burn) => (1.0 - burn).clamp(0.0, 1.0),
        None => 0.0,
    }
}

/// Fast-burn predicate mirroring `PicoComputeSloBurnFast` (1h and 5m above 14.4x
/// with the quiet-region floor).
pub fn fast_fires(burn_1h: f64, burn_5m: f64, valid_rate_5m: f64) -> bool {
    burn_1h > FAST_BURN_THRESHOLD
        && burn_5m > FAST_BURN_THRESHOLD
        && valid_rate_5m > FAST_VALID_RATE_FLOOR
}

/// Slow-burn predicate mirroring `PicoComputeSloBurnSlow` (6h and 30m above 6x
/// with the quiet-region floor).
pub fn slow_fires(burn_6h: f64, burn_30m: f64, valid_rate_30m: f64) -> bool {
    burn_6h > SLOW_BURN_THRESHOLD
        && burn_30m > SLOW_BURN_THRESHOLD
        && valid_rate_30m > SLOW_VALID_RATE_FLOOR
}

/// Per-SLO evaluation across the recording-rule windows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloEvaluation {
    pub slo: SloId,
    pub error_ratio_5m: Option<f64>,
    pub error_ratio_30m: Option<f64>,
    pub error_ratio_1h: Option<f64>,
    pub error_ratio_6h: Option<f64>,
    pub error_ratio_30d: Option<f64>,
    pub burn_5m: Option<f64>,
    pub burn_30m: Option<f64>,
    pub burn_1h: Option<f64>,
    pub burn_6h: Option<f64>,
    pub budget_remaining: f64,
    pub valid_rate_5m: f64,
    pub valid_rate_30m: f64,
    pub fast_firing: bool,
    pub slow_firing: bool,
    pub exhausted: bool,
}

/// Raw counters for one SLO in one evaluation window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SloWindowCounts {
    pub slo: SloId,
    pub bad_5m: u64,
    pub valid_5m: u64,
    pub bad_30m: u64,
    pub valid_30m: u64,
    pub bad_1h: u64,
    pub valid_1h: u64,
    pub bad_6h: u64,
    pub valid_6h: u64,
    pub bad_30d: u64,
    pub valid_30d: u64,
    /// Mean valid event rate per second over 5m (for the fast floor).
    pub valid_rate_5m: f64,
    /// Mean valid event rate per second over 30m (for the slow floor).
    pub valid_rate_30m: f64,
}

impl SloWindowCounts {
    /// Healthy soak sample: zero bad events at the given valid volume.
    pub fn healthy(slo: SloId, valid: u64, valid_rate: f64) -> Self {
        Self {
            slo,
            bad_5m: 0,
            valid_5m: valid,
            bad_30m: 0,
            valid_30m: valid,
            bad_1h: 0,
            valid_1h: valid,
            bad_6h: 0,
            valid_6h: valid,
            bad_30d: 0,
            valid_30d: valid.max(1),
            valid_rate_5m: valid_rate,
            valid_rate_30m: valid_rate,
        }
    }
}

/// Evaluate one SLO across all windows, mirroring the recording rules.
pub fn evaluate_slo(counts: SloWindowCounts) -> SloEvaluation {
    let target = counts.slo.target();
    let error_ratio_5m = error_ratio(counts.bad_5m, counts.valid_5m);
    let error_ratio_30m = error_ratio(counts.bad_30m, counts.valid_30m);
    let error_ratio_1h = error_ratio(counts.bad_1h, counts.valid_1h);
    let error_ratio_6h = error_ratio(counts.bad_6h, counts.valid_6h);
    let error_ratio_30d = error_ratio(counts.bad_30d, counts.valid_30d);
    let burn_5m = error_ratio_5m.and_then(|r| burn_rate(r, target));
    let burn_30m = error_ratio_30m.and_then(|r| burn_rate(r, target));
    let burn_1h = error_ratio_1h.and_then(|r| burn_rate(r, target));
    let burn_6h = error_ratio_6h.and_then(|r| burn_rate(r, target));
    // No 30d data is unknown, never full budget: unknown blocks rollout via
    // `exhausted`, mirroring the telemetry-stale fail-closed rule.
    let budget = error_ratio_30d.map_or(0.0, |r| budget_remaining(r, target));
    let fast_firing = match (burn_1h, burn_5m) {
        (Some(b1h), Some(b5m)) => fast_fires(b1h, b5m, counts.valid_rate_5m),
        _ => false,
    };
    let slow_firing = match (burn_6h, burn_30m) {
        (Some(b6h), Some(b30m)) => slow_fires(b6h, b30m, counts.valid_rate_30m),
        _ => false,
    };
    SloEvaluation {
        slo: counts.slo,
        error_ratio_5m,
        error_ratio_30m,
        error_ratio_1h,
        error_ratio_6h,
        error_ratio_30d,
        burn_5m,
        burn_30m,
        burn_1h,
        burn_6h,
        budget_remaining: budget,
        valid_rate_5m: counts.valid_rate_5m,
        valid_rate_30m: counts.valid_rate_30m,
        fast_firing,
        slow_firing,
        exhausted: budget <= 0.0,
    }
}

/// Rollout freeze decision from the SLO policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FreezeDecision {
    pub fast_firing: Vec<String>,
    pub exhausted: Vec<String>,
    pub telemetry_stale: bool,
    pub min_user_budget_remaining: f64,
    pub passes: bool,
    pub reasons: Vec<String>,
}

/// Evaluate the freeze checklist: no fast-burn page, no exhausted budget, no
/// stale telemetry, and every user-facing SLO keeps at least 25% budget. A
/// current exception waives only the 25%-remaining rule; fast burn,
/// exhaustion, and stale telemetry still block. `reasons` holds exactly the
/// blocking reasons, so `passes` is always `reasons.is_empty()`.
pub fn evaluate_freeze(
    evaluations: &[SloEvaluation],
    telemetry_stale: bool,
    has_exception: bool,
) -> FreezeDecision {
    if evaluations.is_empty() {
        // No evaluations is unknown, not healthy: block rollout fail-closed.
        return FreezeDecision {
            fast_firing: Vec::new(),
            exhausted: Vec::new(),
            telemetry_stale,
            min_user_budget_remaining: 0.0,
            passes: false,
            reasons: vec!["no SLO evaluations; status is unknown, not healthy".into()],
        };
    }
    let mut fast_firing = Vec::new();
    let mut exhausted = Vec::new();
    let mut min_user_budget = 1.0_f64;
    for eval in evaluations {
        if eval.fast_firing {
            fast_firing.push(eval.slo.as_str().to_string());
        }
        if eval.exhausted {
            exhausted.push(eval.slo.as_str().to_string());
        }
        if eval.slo.is_user_facing() {
            min_user_budget = min_user_budget.min(eval.budget_remaining);
        }
    }
    let mut reasons = Vec::new();
    if !fast_firing.is_empty() {
        reasons.push(format!("fast burn firing: {}", fast_firing.join(",")));
    }
    if !exhausted.is_empty() {
        reasons.push(format!("budget exhausted: {}", exhausted.join(",")));
    }
    if telemetry_stale {
        reasons.push("slo telemetry stale".to_string());
    }
    if min_user_budget < FREEZE_BUDGET_THRESHOLD && !has_exception {
        reasons.push(format!(
            "user-facing budget {min_user_budget:.3} below {FREEZE_BUDGET_THRESHOLD}"
        ));
    }
    let passes = reasons.is_empty();
    FreezeDecision {
        fast_firing,
        exhausted,
        telemetry_stale,
        min_user_budget_remaining: min_user_budget,
        passes,
        reasons,
    }
}

/// ADR-0012 throughput scenarios owned by this module. The remaining
/// scenarios are owned by `capacity` (S-RAMP-ACTIVE, S-SOAK-ACTIVE, S-NOISY,
/// S-RAMP-EXEC), `restore_capacity` (S-RAMP-RESTORE, S-SPIKE-RESTORE,
/// S-SOAK-RESTORE), `image_cache` (S-CACHE-*), and `availability`
/// (S-FAIL-HOST, S-FAIL-CELL, S-RECOVER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThroughputScenario {
    /// Read-heavy plus create admission ramp on the regional API.
    #[serde(rename = "S-RAMP-API")]
    RampApi,
    /// Abrupt 2x-3x API offered load for a fixed window.
    #[serde(rename = "S-SPIKE-API")]
    SpikeApi,
    /// MIX-AGENT-V1 create/boot ramp.
    #[serde(rename = "S-RAMP-CREATE")]
    RampCreate,
    /// Create burst at 2x-3x LPOP.
    #[serde(rename = "S-SPIKE-CREATE")]
    SpikeCreate,
    /// Lifecycle mix while measuring audit lag and SLO series freshness.
    #[serde(rename = "S-RAMP-PIPE")]
    RampPipe,
    /// MIX-AGENT-V1 at LPOP for the stage duration.
    #[serde(rename = "S-SOAK-MIX")]
    SoakMix,
    /// Induced audit or telemetry backlog at LPOP.
    #[serde(rename = "S-PIPE-BACKPRESSURE")]
    PipeBackpressure,
}

impl ThroughputScenario {
    /// Scenario identifier used in evidence artifacts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RampApi => "S-RAMP-API",
            Self::SpikeApi => "S-SPIKE-API",
            Self::RampCreate => "S-RAMP-CREATE",
            Self::SpikeCreate => "S-SPIKE-CREATE",
            Self::RampPipe => "S-RAMP-PIPE",
            Self::SoakMix => "S-SOAK-MIX",
            Self::PipeBackpressure => "S-PIPE-BACKPRESSURE",
        }
    }

    /// SLO that judges availability for this scenario.
    pub fn slo(self) -> SloId {
        match self {
            Self::RampApi | Self::SpikeApi => SloId::Create,
            Self::RampCreate | Self::SpikeCreate | Self::SoakMix => SloId::Create,
            Self::RampPipe | Self::PipeBackpressure => SloId::Audit,
        }
    }

    /// Whether this scenario measures a sustainable rate (spikes do not).
    pub fn measures_sustainable_rate(self) -> bool {
        matches!(
            self,
            Self::RampApi | Self::RampCreate | Self::RampPipe | Self::SoakMix
        )
    }
}

/// One held load step for a throughput scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputObservation {
    pub offered: u64,
    pub admitted: u64,
    pub completed: u64,
    pub unavailable_rejects: u64,
    pub timeouts: u64,
    /// Client-caused denies excluded from availability per the SLO policy.
    pub excluded_rejects: u64,
    pub bad: u64,
    pub valid: u64,
    pub pressure: ResourcePressureSample,
    pub safety: SafetyFlags,
    pub scheduler_placed: bool,
    pub audit_lag_seconds: Option<f64>,
    pub slo_series_fresh: bool,
}

impl ThroughputObservation {
    /// Healthy step where every offered event is admitted and completed.
    pub fn healthy(offered: u64) -> Self {
        Self {
            offered,
            admitted: offered,
            completed: offered,
            unavailable_rejects: 0,
            timeouts: 0,
            excluded_rejects: 0,
            bad: 0,
            valid: offered.max(1),
            pressure: ResourcePressureSample::default(),
            safety: SafetyFlags::default(),
            scheduler_placed: true,
            audit_lag_seconds: Some(1.0),
            slo_series_fresh: true,
        }
    }
}

/// Why a throughput step landed in its zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputZoneReason {
    WithinEnvelope,
    SloErrorWarning,
    SloErrorSaturation,
    NoValidEvents,
    MemoryPressure,
    UtilizationPressure,
    TimeoutInsteadOfShed,
    SchedulerRejected,
    AuditLag,
    TelemetryStale,
    IsolationBroken,
    CleanupIncomplete,
    BackendChanged,
    ResourceLeak,
    CrossTenantPlacement,
}

/// Classified throughput step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedThroughputStep {
    pub offered: u64,
    pub zone: DensityZone,
    pub reasons: Vec<ThroughputZoneReason>,
    pub observation: ThroughputObservation,
}

/// Classify one throughput observation against its SLO budget.
pub fn classify_throughput(
    observation: &ThroughputObservation,
    scenario: ThroughputScenario,
) -> ClassifiedThroughputStep {
    let mut reasons = Vec::new();
    let safety = &observation.safety;
    if !safety.isolation_held {
        reasons.push(ThroughputZoneReason::IsolationBroken);
    }
    if !safety.cleanup_complete {
        reasons.push(ThroughputZoneReason::CleanupIncomplete);
    }
    if !safety.backend_unchanged {
        reasons.push(ThroughputZoneReason::BackendChanged);
    }
    if safety.leak_detected {
        reasons.push(ThroughputZoneReason::ResourceLeak);
    }
    if safety.dedicated_tenancy && safety.cross_tenant_placement {
        reasons.push(ThroughputZoneReason::CrossTenantPlacement);
    }
    let safety_fail = reasons.iter().any(|r| {
        matches!(
            r,
            ThroughputZoneReason::IsolationBroken
                | ThroughputZoneReason::CleanupIncomplete
                | ThroughputZoneReason::BackendChanged
                | ThroughputZoneReason::ResourceLeak
                | ThroughputZoneReason::CrossTenantPlacement
        )
    });

    if observation.timeouts > 0 && observation.unavailable_rejects > 0 {
        reasons.push(ThroughputZoneReason::TimeoutInsteadOfShed);
    }
    if !observation.scheduler_placed && observation.offered > observation.admitted {
        reasons.push(ThroughputZoneReason::SchedulerRejected);
    }
    if !observation.slo_series_fresh {
        reasons.push(ThroughputZoneReason::TelemetryStale);
    }
    if observation.audit_lag_seconds.is_some_and(|lag| lag > 30.0) {
        reasons.push(ThroughputZoneReason::AuditLag);
    }
    if observation.pressure.memory_cgroup >= MEMORY_PRESSURE_SATURATION {
        reasons.push(ThroughputZoneReason::MemoryPressure);
    }
    if pressure_utilization_saturated(&observation.pressure) {
        reasons.push(ThroughputZoneReason::UtilizationPressure);
    }

    let target = scenario.slo().target();
    let saturation = 1.0 - target;
    let warning = saturation / 2.0;
    let ratio = error_ratio(observation.bad, observation.valid);
    match ratio {
        // No terminal valid events is unknown, not healthy: fail closed.
        None => reasons.push(ThroughputZoneReason::NoValidEvents),
        Some(r) if r >= saturation => reasons.push(ThroughputZoneReason::SloErrorSaturation),
        Some(_) => {}
    }

    let saturating = safety_fail
        || reasons.iter().any(|r| {
            matches!(
                r,
                ThroughputZoneReason::TimeoutInsteadOfShed
                    | ThroughputZoneReason::SloErrorSaturation
                    | ThroughputZoneReason::NoValidEvents
                    | ThroughputZoneReason::MemoryPressure
                    | ThroughputZoneReason::UtilizationPressure
                    | ThroughputZoneReason::SchedulerRejected
                    | ThroughputZoneReason::TelemetryStale
                    | ThroughputZoneReason::AuditLag
            )
        });
    if saturating {
        return ClassifiedThroughputStep {
            offered: observation.offered,
            zone: DensityZone::Saturation,
            reasons,
            observation: observation.clone(),
        };
    }

    if observation.pressure.memory_cgroup >= MEMORY_PRESSURE_WARNING {
        reasons.push(ThroughputZoneReason::MemoryPressure);
    }
    if pressure_utilization_warning(&observation.pressure) {
        reasons.push(ThroughputZoneReason::UtilizationPressure);
    }
    if ratio.is_some_and(|r| r >= warning) {
        reasons.push(ThroughputZoneReason::SloErrorWarning);
    }
    let zone = if reasons.is_empty() {
        reasons.push(ThroughputZoneReason::WithinEnvelope);
        DensityZone::Safe
    } else {
        DensityZone::Warning
    };
    ClassifiedThroughputStep {
        offered: observation.offered,
        zone,
        reasons,
        observation: observation.clone(),
    }
}

/// Input to [`analyze_throughput`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputInput {
    pub scenario: ThroughputScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub steps: Vec<ThroughputObservation>,
}

/// Throughput report for one ST-API/ST-CREATE/ST-PIPE scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputReport {
    pub scenario: ThroughputScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub knee: Option<u64>,
    /// Always `None` before P2.
    pub proposed_lpop: Option<u64>,
    pub findings: Vec<CapacityFinding>,
    pub steps: Vec<ClassifiedThroughputStep>,
}

impl ThroughputReport {
    /// Content digest of the report JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Throughput report\n\n");
        out.push_str(&format!(
            "- Scenario: {}\n- Phase: {:?}\n- Scope: {:?}\n- Backend: {}\n- Host SKU: {}\n",
            self.scenario.as_str(),
            self.phase,
            self.scope,
            self.backend,
            self.host_sku
        ));
        out.push_str(&format!(
            "- Knee: {}\n- Proposed LPOP: {}\n",
            self.knee
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into()),
            self.proposed_lpop
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into()),
        ));
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

/// Classify a throughput series and emit the knee plus findings.
pub fn analyze_throughput(input: ThroughputInput) -> ThroughputReport {
    let mut steps: Vec<ClassifiedThroughputStep> = input
        .steps
        .iter()
        .map(|obs| classify_throughput(obs, input.scenario))
        .collect();
    steps.sort_by_key(|step| step.offered);

    let mut findings = Vec::new();
    if steps.is_empty() {
        findings.push(finding(
            FailureClass::A,
            "no_measurements",
            "throughput report has no steps",
        ));
    }
    if !input.phase.may_set_lpop() {
        findings.push(finding(
            FailureClass::C,
            "phase_cannot_set_lpop",
            format!(
                "{:?} may not set an LPOP; throughput knee is a candidate input only",
                input.phase
            ),
        ));
    }
    if !input.scenario.measures_sustainable_rate() {
        findings.push(finding(
            FailureClass::C,
            "spike_measures_shed_not_rate",
            format!(
                "{} measures shed behavior, not a sustainable rate",
                input.scenario.as_str()
            ),
        ));
    }
    let knee = steps.iter().find_map(|step| {
        if step.zone == DensityZone::Saturation {
            Some(step.offered)
        } else {
            None
        }
    });
    if knee.is_none() && !steps.is_empty() {
        findings.push(finding(
            FailureClass::C,
            "saturation_not_reached",
            "run did not reach a saturation knee",
        ));
    }
    for step in &steps {
        push_throughput_safety_findings(&mut findings, step);
    }
    dedupe_findings(&mut findings);

    ThroughputReport {
        scenario: input.scenario,
        phase: input.phase,
        scope: input.scope,
        backend: input.backend,
        host_sku: input.host_sku,
        knee,
        proposed_lpop: None,
        findings,
        steps,
    }
}

fn push_throughput_safety_findings(
    findings: &mut Vec<CapacityFinding>,
    step: &ClassifiedThroughputStep,
) {
    for reason in &step.reasons {
        let (class, code, detail) = match reason {
            ThroughputZoneReason::IsolationBroken => (
                FailureClass::A,
                "isolation_broken",
                "isolation floor failed under load",
            ),
            ThroughputZoneReason::CleanupIncomplete => (
                FailureClass::A,
                "cleanup_incomplete",
                "destroy left overlays, netns, cgroups, or leases",
            ),
            ThroughputZoneReason::BackendChanged => (
                FailureClass::A,
                "silent_backend_fallback",
                "backend selection changed under pressure",
            ),
            ThroughputZoneReason::ResourceLeak => (
                FailureClass::A,
                "resource_leak",
                "fd, cgroup, sandbox, or mount count grew without offered load",
            ),
            ThroughputZoneReason::CrossTenantPlacement => (
                FailureClass::A,
                "cross_tenant_placement",
                "dedicated tenancy allowed a noisy neighbor onto another tenant host",
            ),
            ThroughputZoneReason::TimeoutInsteadOfShed => (
                FailureClass::A,
                "timeout_instead_of_shed",
                "timeouts rose with unavailable rejects; shed path is not clean",
            ),
            ThroughputZoneReason::TelemetryStale => (
                FailureClass::A,
                "telemetry_stale",
                "required pico:slo:* series went stale instead of reporting errors",
            ),
            ThroughputZoneReason::AuditLag => (
                FailureClass::A,
                "audit_lag",
                "audit delivery lag exceeded the 30s SLO-AUDIT-LAG threshold",
            ),
            ThroughputZoneReason::SloErrorSaturation => (
                FailureClass::A,
                "slo_projection_miss",
                "error ratio left the SLO envelope at this step",
            ),
            ThroughputZoneReason::NoValidEvents => (
                FailureClass::A,
                "no_valid_events",
                "step recorded no terminal valid events; status is unknown, not healthy",
            ),
            _ => continue,
        };
        findings.push(CapacityFinding {
            class,
            code: code.into(),
            detail: detail.into(),
            follow_up_issue: None,
        });
    }
}

fn finding(class: FailureClass, code: &str, detail: impl Into<String>) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: None,
    }
}

/// Host utilization at or above the saturation band, mirroring
/// [`crate::capacity`].
fn pressure_utilization_saturated(pressure: &ResourcePressureSample) -> bool {
    pressure.cpu >= UTILIZATION_SATURATION
        || pressure.disk >= UTILIZATION_SATURATION
        || pressure.network >= UTILIZATION_SATURATION
        || pressure.process_slots >= UTILIZATION_SATURATION
}

/// Host utilization at or above the warning band, mirroring
/// [`crate::capacity`].
fn pressure_utilization_warning(pressure: &ResourcePressureSample) -> bool {
    pressure.cpu >= UTILIZATION_WARNING
        || pressure.disk >= UTILIZATION_WARNING
        || pressure.network >= UTILIZATION_WARNING
        || pressure.process_slots >= UTILIZATION_WARNING
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

/// Exact deployment profile under validation, per ADR-0012.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateProfile {
    pub region: String,
    pub cells: u64,
    pub host_sku: String,
    pub kernel: String,
    pub backend: RuntimeType,
    pub guest_image: String,
    pub config_revision: String,
    pub tenancy: String,
    pub mix_id: String,
}

impl CandidateProfile {
    /// P0 candidate: Firecracker on `lab-64vcpu` with dedicated tenancy and
    /// `MIX-AGENT-V1`. Synthetic only; never authorizes quotas.
    pub fn firecracker_lab_dedicated() -> Self {
        Self {
            region: "lab-region".into(),
            cells: 1,
            host_sku: "lab-64vcpu".into(),
            kernel: "lab-kernel-6.8".into(),
            backend: RuntimeType::Firecracker,
            guest_image: "agent-guest-v0.1.0".into(),
            config_revision: "g14-p0".into(),
            tenancy: "dedicated".into(),
            mix_id: MIX_AGENT_V1.into(),
        }
    }

    /// Human-readable profile identifier for report headers.
    pub fn identifier(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            self.region, self.host_sku, self.backend, self.tenancy, self.mix_id
        )
    }
}

/// LPOP tuple from ADR-0012. Every rate stays `None` for P0: the bundle
/// records knees and warning zones as candidate inputs, never as quotas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LpopTuple {
    pub admitted_api_rps: Option<u64>,
    pub create_per_min: Option<u64>,
    pub active_sandboxes: Option<u64>,
    pub concurrent_execs: Option<u64>,
    pub restore_per_sec: Option<f64>,
    pub cache_working_set_images: Option<u64>,
    pub cache_hit_rate: Option<f64>,
    pub surviving_cells: Option<u64>,
    pub audit_lag_p99_seconds: Option<f64>,
    pub headroom: f64,
    pub report_id: String,
    pub artifact_digest: String,
}

impl LpopTuple {
    /// P0 placeholder: no rate is proven, so no quota may be derived.
    pub fn p0_empty(report_id: &str, artifact_digest: &str) -> Self {
        Self {
            admitted_api_rps: None,
            create_per_min: None,
            active_sandboxes: None,
            concurrent_execs: None,
            restore_per_sec: None,
            cache_working_set_images: None,
            cache_hit_rate: None,
            surviving_cells: None,
            audit_lag_p99_seconds: None,
            headroom: 0.50,
            report_id: report_id.into(),
            artifact_digest: artifact_digest.into(),
        }
    }
}

/// One row of the ADR-0012 mapping-completeness table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingRow {
    pub target: String,
    pub required: Vec<String>,
    pub present: Vec<String>,
    pub missing: Vec<String>,
}

/// Check mapping completeness for the eight ST targets. Every scenario ID is
/// the ADR-0012 identifier (for example `S-RAMP-API`).
pub fn mapping_completeness(present: &[String]) -> Vec<MappingRow> {
    let targets: &[(&str, &[&str])] = &[
        ("ST-API", &["S-RAMP-API", "S-SPIKE-API", "S-SOAK-MIX"]),
        (
            "ST-CREATE",
            &["S-RAMP-CREATE", "S-SPIKE-CREATE", "S-SOAK-MIX"],
        ),
        ("ST-ACTIVE", &["S-RAMP-ACTIVE", "S-SOAK-ACTIVE", "S-NOISY"]),
        ("ST-EXEC", &["S-RAMP-EXEC", "S-NOISY", "S-SOAK-MIX"]),
        (
            "ST-RESTORE",
            &["S-RAMP-RESTORE", "S-SPIKE-RESTORE", "S-SOAK-RESTORE"],
        ),
        (
            "ST-CACHE",
            &["S-CACHE-COLD", "S-CACHE-WARM", "S-CACHE-THRASH"],
        ),
        ("ST-CELL", &["S-FAIL-HOST", "S-FAIL-CELL", "S-RECOVER"]),
        (
            "ST-PIPE",
            &["S-RAMP-PIPE", "S-PIPE-BACKPRESSURE", "S-SOAK-MIX"],
        ),
    ];
    targets
        .iter()
        .map(|(target, required)| {
            let required_vec: Vec<String> = required.iter().map(|s| (*s).to_string()).collect();
            let present_vec: Vec<String> = required_vec
                .iter()
                .filter(|id| present.iter().any(|p| p == *id))
                .cloned()
                .collect();
            let missing_vec: Vec<String> = required_vec
                .iter()
                .filter(|id| !present.iter().any(|p| p == *id))
                .cloned()
                .collect();
            MappingRow {
                target: (*target).to_string(),
                required: required_vec,
                present: present_vec,
                missing: missing_vec,
            }
        })
        .collect()
}

/// Recording-rule names that must exist, mirroring `burn_rate_sim.py`.
pub const REQUIRED_RECORDS: &[&str] = &[
    "pico:slo:availability_target",
    "pico:slo:bad:rate5m",
    "pico:slo:valid:rate5m",
    "pico:slo:error_ratio:5m",
    "pico:slo:error_ratio:30m",
    "pico:slo:error_ratio:1h",
    "pico:slo:error_ratio:6h",
    "pico:slo:error_ratio:30d",
    "pico:slo:burn:5m",
    "pico:slo:burn:30m",
    "pico:slo:burn:1h",
    "pico:slo:burn:6h",
    "pico:slo:budget_remaining",
];

/// Alert names that must exist, mirroring `burn_rate_sim.py`.
pub const REQUIRED_ALERTS: &[&str] = &[
    "PicoComputeSloBurnFast",
    "PicoComputeSloBurnSlow",
    "PicoComputeSloBudgetExhausted",
    "PicoComputeSloTelemetryStale",
];

/// Validate recording-rule text: every required record and alert is present
/// and the stale `outcome="error"` selector is gone. Returns missing names;
/// an empty vector means the file matches the SLO policy contract.
pub fn validate_recording_rules_text(text: &str) -> Vec<String> {
    let mut missing = Vec::new();
    for name in REQUIRED_RECORDS {
        if !text.contains(&format!("record: {name}")) {
            missing.push((*name).to_string());
        }
    }
    for name in REQUIRED_ALERTS {
        if !text.contains(&format!("alert: {name}")) {
            missing.push((*name).to_string());
        }
    }
    if text.contains("outcome=\"error\"") {
        missing.push("stale outcome=error SLI selector".to_string());
    }
    missing
}

/// G-14 evidence bundle for one candidate profile and revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct G14EvidenceBundle {
    pub report_id: String,
    pub harness_version: String,
    pub profile: CandidateProfile,
    pub candidate_revision: String,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub mix_id: String,
    pub scenarios_present: Vec<String>,
    pub mapping: Vec<MappingRow>,
    pub slo_evaluations: Vec<SloEvaluation>,
    pub freeze: FreezeDecision,
    pub throughput_reports: Vec<ThroughputReport>,
    /// Digests of composed capacity/restore/cache/availability reports.
    pub composed_digests: Vec<String>,
    /// Cost-model digest when a P0 plan was computed, else `None`.
    pub cost_digest: Option<String>,
    pub lpop: LpopTuple,
    pub findings: Vec<CapacityFinding>,
    pub limitations: Vec<String>,
}

impl G14EvidenceBundle {
    /// Content digest of the bundle JSON (hex-encoded blake3), computed with
    /// `lpop.artifact_digest` cleared so the recorded digest is reproducible:
    /// clear that field and rehash to verify.
    pub fn artifact_digest(&self) -> String {
        let mut canonical = self.clone();
        canonical.lpop.artifact_digest.clear();
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence record.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# G-14 evidence bundle\n\n");
        out.push_str(&format!(
            "- Report: {}\n- Harness: {}\n- Profile: {}\n- Revision: {}\n- Phase: {:?}\n- Scope: {:?}\n- Mix: {}\n",
            self.report_id,
            self.harness_version,
            self.profile.identifier(),
            self.candidate_revision,
            self.phase,
            self.scope,
            self.mix_id
        ));
        out.push_str(&format!(
            "- Freeze passes: {}\n- Min user budget remaining: {:.3}\n- Telemetry stale: {}\n",
            self.freeze.passes, self.freeze.min_user_budget_remaining, self.freeze.telemetry_stale
        ));
        out.push_str(&format!(
            "- Proposed LPOP: none (P0 phase_cannot_set_lpop)\n- Throughput reports: {}\n- SLOs evaluated: {}\n",
            self.throughput_reports.len(),
            self.slo_evaluations.len()
        ));
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

/// Input to [`build_g14_bundle`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct G14BundleInput {
    pub report_id: String,
    pub profile: CandidateProfile,
    pub candidate_revision: String,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub scenarios_present: Vec<String>,
    pub slo_counts: Vec<SloWindowCounts>,
    pub telemetry_stale: bool,
    pub freeze_exception: bool,
    pub throughput_reports: Vec<ThroughputReport>,
    pub composed_digests: Vec<String>,
    pub cost_digest: Option<String>,
}

/// Build a P0 G-14 bundle: evaluate every SLO, evaluate the freeze, check
/// mapping completeness, and force `proposed_lpop = none` with an explicit
/// phase finding.
pub fn build_g14_bundle(input: G14BundleInput) -> G14EvidenceBundle {
    let slo_evaluations: Vec<SloEvaluation> =
        input.slo_counts.into_iter().map(evaluate_slo).collect();
    let freeze = evaluate_freeze(
        &slo_evaluations,
        input.telemetry_stale,
        input.freeze_exception,
    );
    let mapping = mapping_completeness(&input.scenarios_present);
    let mut findings = Vec::new();
    if !input.phase.may_set_lpop() {
        findings.push(CapacityFinding {
            class: FailureClass::C,
            code: "phase_cannot_set_lpop".into(),
            detail: format!(
                "{:?} may not set an LPOP; bundle records candidate inputs only",
                input.phase
            ),
            follow_up_issue: None,
        });
    }
    for row in &mapping {
        if !row.missing.is_empty() {
            findings.push(CapacityFinding {
                class: FailureClass::A,
                code: "mapping_incomplete".into(),
                detail: format!("{} missing {}", row.target, row.missing.join(",")),
                follow_up_issue: None,
            });
        }
    }
    if input.telemetry_stale {
        findings.push(CapacityFinding {
            class: FailureClass::A,
            code: "telemetry_stale".into(),
            detail: "pico:slo:valid:rate5m absent; SLO status is unknown, not healthy".into(),
            follow_up_issue: None,
        });
    }
    for eval in &slo_evaluations {
        if eval.fast_firing {
            findings.push(CapacityFinding {
                class: FailureClass::A,
                code: "fast_burn_firing".into(),
                detail: format!("{} fast burn firing", eval.slo.as_str()),
                follow_up_issue: None,
            });
        }
        if eval.exhausted {
            findings.push(CapacityFinding {
                class: FailureClass::A,
                code: "budget_exhausted".into(),
                detail: format!("{} 30d error budget exhausted", eval.slo.as_str()),
                follow_up_issue: None,
            });
        }
    }
    // Include throughput-level class-A findings so the bundle stays
    // fail-closed when any composed scenario saturates on safety.
    for report in &input.throughput_reports {
        for finding in &report.findings {
            if finding.class == FailureClass::A && !findings.iter().any(|f| f.code == finding.code)
            {
                findings.push(CapacityFinding {
                    class: finding.class,
                    code: finding.code.clone(),
                    detail: format!("{}: {}", report.scenario.as_str(), finding.detail),
                    follow_up_issue: None,
                });
            }
        }
    }
    let limitations = vec![
        "P0 synthetic series only; no production-shaped host, cell, or regional candidate was measured.".into(),
        "Load generator is synthetic counters, not live Prometheus scrape; P2+ must scrape pico:slo:* from the candidate.".into(),
        "Latency SLOs stay diagnostic until histogram buckets include policy thresholds.".into(),
        "SLO-API uses the create proxy until pico.api.request.* is exported.".into(),
        "Bundle authorizes no quotas; every LpopTuple rate is none.".into(),
    ];
    let mut bundle = G14EvidenceBundle {
        report_id: input.report_id.clone(),
        harness_version: HARNESS_VERSION.into(),
        profile: input.profile,
        candidate_revision: input.candidate_revision,
        phase: input.phase,
        scope: input.scope,
        mix_id: MIX_AGENT_V1.into(),
        scenarios_present: input.scenarios_present,
        mapping,
        slo_evaluations,
        freeze,
        throughput_reports: input.throughput_reports,
        composed_digests: input.composed_digests,
        cost_digest: input.cost_digest,
        lpop: LpopTuple::p0_empty(&input.report_id, ""),
        findings,
        limitations,
    };
    // Seed the digest field empty so `artifact_digest` (which clears it before
    // hashing) reproduces the recorded value.
    let digest = bundle.artifact_digest();
    bundle.lpop.artifact_digest = digest;
    bundle
}

#[cfg(test)]
mod tests;
