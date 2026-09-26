//! Snapshot restore pressure model (ST-RESTORE).
//!
//! Classifies S-RAMP-RESTORE, S-SPIKE-RESTORE, and S-SOAK-RESTORE
//! observations and emits the report the load harness and
//! cost model consume. P0 tests exercise the model with synthetic
//! series. P1+ host runs must feed the same [`analyze_restore_pressure`]
//! seam.
//!
//! This module does not generate load and does not set a launch proven
//! operating point. P0/P1 reports never authorize regional quotas.

use serde::{Deserialize, Serialize};

use crate::capacity::{
    CapacityFinding, CapacityScope, DensityZone, FailureClass, ResourcePressureSample,
    ValidationPhase, ZoneBounds,
};
use crate::runtime::RuntimeType;
use crate::snapshot::cache_tiering::CacheTier;

/// ADR-0012 scenarios owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RestoreScenario {
    /// Concurrent warm restore/fork ramp.
    #[serde(rename = "S-RAMP-RESTORE")]
    RampRestore,
    /// Restore storm from one popular snapshot.
    #[serde(rename = "S-SPIKE-RESTORE")]
    SpikeRestore,
    /// Steady restore/fork at restore LPOP.
    #[serde(rename = "S-SOAK-RESTORE")]
    SoakRestore,
}

impl RestoreScenario {
    /// Axis used for zone bounds and the knee.
    pub fn axis(self) -> RestoreAxis {
        match self {
            Self::SpikeRestore => RestoreAxis::RestoreRate,
            Self::RampRestore | Self::SoakRestore => RestoreAxis::ConcurrentRestores,
        }
    }

    /// Scenario identifier used in evidence artifacts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RampRestore => "S-RAMP-RESTORE",
            Self::SpikeRestore => "S-SPIKE-RESTORE",
            Self::SoakRestore => "S-SOAK-RESTORE",
        }
    }
}

/// Measured quantity that defines a restore zone boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreAxis {
    /// Concurrent in-flight restores (ST-RESTORE concurrency).
    ConcurrentRestores,
    /// Offered restore rate in the sample window (ST-RESTORE throughput).
    RestoreRate,
}

/// Snapshot kind under restore. Lazy memory is a restore mode of the
/// memory profile, not a separate snapshot profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreSnapshotKind {
    /// Filesystem-only restore (portable v1).
    Filesystem,
    /// Eager memory restore.
    Memory,
    // Demand-paged memory restore.
    LazyMemory,
}

impl RestoreSnapshotKind {
    /// Identifier used in reports and metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Memory => "memory",
            Self::LazyMemory => "lazy_memory",
        }
    }
}

/// Thresholds that map a restore sample onto [`DensityZone`].
///
/// Availability SLOs are error ratios on terminal valid events.
/// Restore p99 is diagnostic until latency histogram buckets are budgeted.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RestoreThresholds {
    /// Inclusive upper bound of the safe restore-error band.
    pub restore_error_warning: f64,
    /// Inclusive lower bound of the saturation restore-error band.
    pub restore_error_saturation: f64,
    /// Diagnostic SLO-RESTORE-LAT p99 (1s). Does not saturate a zone.
    pub restore_p99_warning_secs: f64,
    /// Architecture p50 design target (200ms). Class-C when missed.
    pub restore_p50_design_secs: f64,
    /// Diagnostic exec p99 under concurrent restore.
    pub exec_p99_warning_secs: f64,
    pub utilization_warning: f64,
    pub utilization_saturation: f64,
    pub memory_pressure_warning: f64,
    pub memory_pressure_saturation: f64,
    /// Relative error band for advertised vs measured concurrent restores.
    pub calibration_error_band: f64,
    /// Warm-cache hit-rate warning (does not saturate if restores succeed).
    pub warm_hit_rate_warning: f64,
}

impl Default for RestoreThresholds {
    fn default() -> Self {
        Self {
            restore_error_warning: 0.0025,
            restore_error_saturation: 0.005,
            restore_p99_warning_secs: 1.0,
            restore_p50_design_secs: 0.2,
            exec_p99_warning_secs: 1.0,
            utilization_warning: 0.75,
            utilization_saturation: 0.90,
            memory_pressure_warning: 15.0,
            memory_pressure_saturation: 30.0,
            calibration_error_band: 0.15,
            warm_hit_rate_warning: 0.8,
        }
    }
}

/// Safety invariants that fail the run even when SLOs are green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreSafetyFlags {
    /// Isolation floor held.
    pub isolation_held: bool,
    /// Destroy/cleanup completed for failed restores.
    pub cleanup_complete: bool,
    /// Backend selection did not change under pressure.
    pub backend_unchanged: bool,
    /// fd/cgroup/sandbox/mount leak detected.
    pub leak_detected: bool,
    /// Snapshot lineage stayed bound to the intended parent.
    pub lineage_held: bool,
    /// No credential or undeclared secret material in artifacts.
    pub secret_free: bool,
}

impl Default for RestoreSafetyFlags {
    fn default() -> Self {
        Self {
            isolation_held: true,
            cleanup_complete: true,
            backend_unchanged: true,
            leak_detected: false,
            lineage_held: true,
            secret_free: true,
        }
    }
}

/// One held restore load step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreObservation {
    /// Concurrent in-flight restores.
    pub concurrent_restores: u64,
    /// Offered restore rate in this window.
    pub restore_rate: u64,
    /// Restore attempts offered.
    pub offered: u64,
    /// Restore attempts admitted.
    pub admitted: u64,
    /// Restore attempts completed.
    pub completed: u64,
    /// Intended `unavailable` shed.
    pub unavailable_rejects: u64,
    /// Timeouts (must not rise with shed).
    pub timeouts: u64,
    /// Partial restore cleanups. Always a bad restore event.
    pub partial_cleanups: u64,
    /// SLO-RESTORE error ratio on terminal valid events.
    pub restore_error_ratio: f64,
    pub restore_p50_seconds: Option<f64>,
    pub restore_p95_seconds: Option<f64>,
    pub restore_p99_seconds: Option<f64>,
    /// Exec p99 while restores run (contention).
    pub exec_p99_seconds: Option<f64>,
    pub snapshot_kind: RestoreSnapshotKind,
    pub storage_tier: CacheTier,
    pub snapshot_size_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    /// Snapshot-store backlog (objects or bytes waiting). Soak must not grow.
    pub snapshot_store_backlog: u64,
    /// Demand-paged faults when [`RestoreSnapshotKind::LazyMemory`].
    pub lazy_pages_faulted: Option<u64>,
    pub pressure: ResourcePressureSample,
    pub safety: RestoreSafetyFlags,
    pub scheduler_placed: bool,
    pub scheduler_should_throttle: bool,
    /// `snapshot_operation` audit events in this window.
    pub audit_events: u64,
}

impl RestoreObservation {
    /// Observation at `concurrent_restores` with remaining defaults (warm hit).
    pub fn at_concurrent(concurrent_restores: u64) -> Self {
        Self {
            concurrent_restores,
            restore_rate: concurrent_restores,
            offered: concurrent_restores,
            admitted: concurrent_restores,
            completed: concurrent_restores,
            unavailable_rejects: 0,
            timeouts: 0,
            partial_cleanups: 0,
            restore_error_ratio: 0.0,
            restore_p50_seconds: Some(0.08),
            restore_p95_seconds: Some(0.12),
            restore_p99_seconds: Some(0.18),
            exec_p99_seconds: Some(0.05),
            snapshot_kind: RestoreSnapshotKind::Filesystem,
            storage_tier: CacheTier::HostLocal,
            snapshot_size_bytes: 256 * 1024 * 1024,
            cache_hits: concurrent_restores,
            cache_misses: 0,
            snapshot_store_backlog: 0,
            lazy_pages_faulted: None,
            pressure: ResourcePressureSample::default(),
            safety: RestoreSafetyFlags::default(),
            scheduler_placed: true,
            scheduler_should_throttle: false,
            audit_events: concurrent_restores,
        }
    }

    fn axis_value(&self, axis: RestoreAxis) -> u64 {
        match axis {
            RestoreAxis::ConcurrentRestores => self.concurrent_restores,
            RestoreAxis::RestoreRate => self.restore_rate,
        }
    }
}

/// Why a step landed in its zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreZoneReason {
    WithinEnvelope,
    MemoryPressure,
    UtilizationPressure,
    RestoreErrorRatio,
    RestoreLatency,
    ExecLatency,
    SchedulerThrottle,
    SchedulerRejected,
    TimeoutInsteadOfShed,
    PartialCleanup,
    IsolationBroken,
    CleanupIncomplete,
    BackendChanged,
    ResourceLeak,
    LineageMixup,
    SecretMaterial,
    SnapshotStoreBacklog,
    CacheMiss,
}

/// Classified ramp/soak/spike step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedRestoreStep {
    /// Axis value for this step.
    pub axis_value: u64,
    /// Operating zone.
    pub zone: DensityZone,
    /// Why the step landed in that zone.
    pub reasons: Vec<RestoreZoneReason>,
    /// Source sample.
    pub observation: RestoreObservation,
}

/// p50/p95/p99 restore latency for one snapshot kind and storage tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreLatencySlice {
    pub snapshot_kind: RestoreSnapshotKind,
    pub storage_tier: CacheTier,
    pub p50_seconds: Option<f64>,
    pub p95_seconds: Option<f64>,
    pub p99_seconds: Option<f64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub completed: u64,
}

/// Aggregated cache hit/miss counts for the series.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RestoreCacheTelemetry {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: Option<f64>,
}

/// Advertised concurrent-restore cap vs measured warning-zone max.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreCalibration {
    pub advertised_limit: u64,
    pub measured_warning_max: Option<u64>,
    pub relative_error: Option<f64>,
    pub error_band: f64,
    pub within_band: bool,
    pub class: Option<FailureClass>,
}

/// Dashboards, alerts, traces, and audit kinds operators must watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreObservabilityEvidence {
    /// Grafana dashboard UIDs.
    pub dashboards: Vec<String>,
    /// Prometheus alert names.
    pub alerts: Vec<String>,
    /// Trace selectors (service/span/outcome).
    pub traces: Vec<String>,
    /// Audit event kinds.
    pub audit_kinds: Vec<String>,
}

impl RestoreObservabilityEvidence {
    /// P0 evidence set. Live scrape is not required; names must match
    /// dashboards, recording rules, and the snapshot-fork runbook.
    pub fn p0_required() -> Self {
        Self {
            dashboards: vec![
                "pico-snapshot-fork".into(),
                "pico-image-cache".into(),
                "pico-slo-error-budget".into(),
                "pico-lifecycle-operations".into(),
            ],
            alerts: vec![
                "PicoComputeRestoreSaturated".into(),
                "PicoComputeRestorePartialCleanup".into(),
                "PicoComputeSloBurnFast".into(),
            ],
            traces: vec!["restore_from_snapshot".into()],
            audit_kinds: vec!["snapshot_operation".into()],
        }
    }

    fn is_complete(&self) -> bool {
        let required = Self::p0_required();
        contains_all(&self.dashboards, &required.dashboards)
            && contains_all(&self.alerts, &required.alerts)
            && contains_all(&self.traces, &required.traces)
            && contains_all(&self.audit_kinds, &required.audit_kinds)
    }
}

fn contains_all(haystack: &[String], needles: &[String]) -> bool {
    needles
        .iter()
        .all(|need| haystack.iter().any(|h| h == need))
}

/// Input to [`analyze_restore_pressure`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestorePressureInput {
    /// Scenario under test.
    pub scenario: RestoreScenario,
    /// Validation phase. P0/P1 must not set an LPOP.
    pub phase: ValidationPhase,
    /// Aggregation scope.
    pub scope: CapacityScope,
    /// Runtime backend for this series.
    pub backend: RuntimeType,
    /// Host SKU identifier (for example `lab-64vcpu`).
    pub host_sku: String,
    /// Scheduler `max_concurrent_restores` (or measured equivalent).
    pub advertised_restore_limit: u64,
    /// Ordered load steps.
    pub steps: Vec<RestoreObservation>,
    pub thresholds: RestoreThresholds,
    /// Named dashboards, alerts, traces, and audit kinds.
    pub observability: RestoreObservabilityEvidence,
    /// True when Grafana/alertmanager were scraped in this run.
    pub live_observability: bool,
    /// True when sandboxd restore actually ran.
    pub restore_path_live: bool,
}

/// Restore pressure report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestorePressureReport {
    pub scenario: RestoreScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub axis: RestoreAxis,
    pub zones: ZoneBounds,
    pub knee: Option<u64>,
    /// Always `None` before P2.
    pub proposed_lpop: Option<u64>,
    pub calibration: RestoreCalibration,
    pub latency_by_kind_and_tier: Vec<RestoreLatencySlice>,
    pub cache: RestoreCacheTelemetry,
    pub findings: Vec<CapacityFinding>,
    pub steps: Vec<ClassifiedRestoreStep>,
    pub observability: RestoreObservabilityEvidence,
}

impl RestorePressureReport {
    /// Content digest of the report JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Snapshot restore pressure report\n\n");
        out.push_str(&format!(
            "- Scenario: {}\n- Phase: {:?}\n- Scope: {:?}\n- Backend: {}\n- Host SKU: {}\n",
            self.scenario.as_str(),
            self.phase,
            self.scope,
            self.backend,
            self.host_sku
        ));
        out.push_str(&format!(
            "- Safe max: {}\n- Warning max (LPOP cap): {}\n- Saturation onset/knee: {}\n- Proposed LPOP: {}\n",
            fmt_opt(self.zones.safe_max),
            fmt_opt(self.zones.warning_max),
            fmt_opt(self.knee),
            fmt_opt(self.proposed_lpop)
        ));
        out.push_str(&format!(
            "- Advertised restore limit: {}\n- Calibration within band: {}\n- Cache hit rate: {}\n",
            self.calibration.advertised_limit,
            self.calibration.within_band,
            self.cache
                .hit_rate
                .map(|rate| format!("{rate:.3}"))
                .unwrap_or_else(|| "none".into())
        ));
        if self.latency_by_kind_and_tier.is_empty() {
            out.push_str("- Latency by kind/tier: none\n");
        } else {
            out.push_str("- Latency by kind/tier:\n");
            for slice in &self.latency_by_kind_and_tier {
                out.push_str(&format!(
                    "  - {}/{}: p50={} p95={} p99={}\n",
                    slice.snapshot_kind.as_str(),
                    slice.storage_tier.as_str(),
                    fmt_lat(slice.p50_seconds),
                    fmt_lat(slice.p95_seconds),
                    fmt_lat(slice.p99_seconds)
                ));
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
        .unwrap_or_else(|| "none".to_string())
}

fn fmt_lat(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.3}s"))
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

/// Lab-host concurrent restore cap used by scheduler tests (`lab-64vcpu`).
pub fn lab_advertised_restore_limit() -> u64 {
    5
}

/// Classify one observation against the provided thresholds.
pub fn classify_restore(
    observation: &RestoreObservation,
    scenario: RestoreScenario,
    thresholds: &RestoreThresholds,
) -> ClassifiedRestoreStep {
    let mut reasons = Vec::new();
    let safety = &observation.safety;

    if !safety.isolation_held {
        reasons.push(RestoreZoneReason::IsolationBroken);
    }
    if !safety.cleanup_complete {
        reasons.push(RestoreZoneReason::CleanupIncomplete);
    }
    if !safety.backend_unchanged {
        reasons.push(RestoreZoneReason::BackendChanged);
    }
    if safety.leak_detected {
        reasons.push(RestoreZoneReason::ResourceLeak);
    }
    if !safety.lineage_held {
        reasons.push(RestoreZoneReason::LineageMixup);
    }
    if !safety.secret_free {
        reasons.push(RestoreZoneReason::SecretMaterial);
    }
    if observation.partial_cleanups > 0 {
        reasons.push(RestoreZoneReason::PartialCleanup);
    }
    if observation.timeouts > 0 && observation.unavailable_rejects > 0 {
        reasons.push(RestoreZoneReason::TimeoutInsteadOfShed);
    }
    if matches!(scenario, RestoreScenario::SoakRestore) && observation.snapshot_store_backlog > 0 {
        reasons.push(RestoreZoneReason::SnapshotStoreBacklog);
    }

    let safety_fail = reasons.iter().any(|r| {
        matches!(
            r,
            RestoreZoneReason::IsolationBroken
                | RestoreZoneReason::CleanupIncomplete
                | RestoreZoneReason::BackendChanged
                | RestoreZoneReason::ResourceLeak
                | RestoreZoneReason::LineageMixup
                | RestoreZoneReason::SecretMaterial
                | RestoreZoneReason::PartialCleanup
                | RestoreZoneReason::TimeoutInsteadOfShed
                | RestoreZoneReason::SnapshotStoreBacklog
        )
    });

    if observation.restore_error_ratio >= thresholds.restore_error_saturation {
        reasons.push(RestoreZoneReason::RestoreErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_saturation {
        reasons.push(RestoreZoneReason::MemoryPressure);
    }
    if utilization_saturated(&observation.pressure, thresholds) {
        reasons.push(RestoreZoneReason::UtilizationPressure);
    }
    if !observation.scheduler_placed && observation.offered > observation.admitted {
        reasons.push(RestoreZoneReason::SchedulerRejected);
    }

    let saturating = safety_fail
        || reasons.iter().any(|r| {
            matches!(
                r,
                RestoreZoneReason::RestoreErrorRatio
                    | RestoreZoneReason::MemoryPressure
                    | RestoreZoneReason::UtilizationPressure
                    | RestoreZoneReason::SchedulerRejected
            )
        });

    if saturating {
        return ClassifiedRestoreStep {
            axis_value: observation.axis_value(scenario.axis()),
            zone: DensityZone::Saturation,
            reasons,
            observation: observation.clone(),
        };
    }

    if observation.restore_error_ratio >= thresholds.restore_error_warning {
        reasons.push(RestoreZoneReason::RestoreErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_warning {
        reasons.push(RestoreZoneReason::MemoryPressure);
    }
    if utilization_warning(&observation.pressure, thresholds) {
        reasons.push(RestoreZoneReason::UtilizationPressure);
    }
    if observation
        .restore_p99_seconds
        .is_some_and(|p99| p99 >= thresholds.restore_p99_warning_secs)
    {
        reasons.push(RestoreZoneReason::RestoreLatency);
    }
    if observation
        .exec_p99_seconds
        .is_some_and(|p99| p99 >= thresholds.exec_p99_warning_secs)
    {
        reasons.push(RestoreZoneReason::ExecLatency);
    }
    if observation.scheduler_should_throttle {
        reasons.push(RestoreZoneReason::SchedulerThrottle);
    }
    if observation.cache_misses > 0 {
        reasons.push(RestoreZoneReason::CacheMiss);
    }

    let zone = if reasons.is_empty() {
        reasons.push(RestoreZoneReason::WithinEnvelope);
        DensityZone::Safe
    } else {
        DensityZone::Warning
    };

    ClassifiedRestoreStep {
        axis_value: observation.axis_value(scenario.axis()),
        zone,
        reasons,
        observation: observation.clone(),
    }
}

fn utilization_saturated(
    pressure: &ResourcePressureSample,
    thresholds: &RestoreThresholds,
) -> bool {
    pressure.cpu >= thresholds.utilization_saturation
        || pressure.disk >= thresholds.utilization_saturation
        || pressure.network >= thresholds.utilization_saturation
        || pressure.process_slots >= thresholds.utilization_saturation
}

fn utilization_warning(pressure: &ResourcePressureSample, thresholds: &RestoreThresholds) -> bool {
    pressure.cpu >= thresholds.utilization_warning
        || pressure.disk >= thresholds.utilization_warning
        || pressure.network >= thresholds.utilization_warning
        || pressure.process_slots >= thresholds.utilization_warning
}

/// Classify a restore series and emit zone bounds, latency slices, and cache telemetry.
pub fn analyze_restore_pressure(input: RestorePressureInput) -> RestorePressureReport {
    let axis = input.scenario.axis();
    let mut steps: Vec<ClassifiedRestoreStep> = input
        .steps
        .iter()
        .map(|obs| classify_restore(obs, input.scenario, &input.thresholds))
        .collect();
    steps.sort_by_key(|step| step.axis_value);

    let mut findings = Vec::new();
    if steps.is_empty() {
        findings.push(finding(
            FailureClass::A,
            "no_measurements",
            "restore report has no steps",
        ));
    }

    let zones = restore_zone_bounds(&steps);
    let knee = zones
        .saturation_onset
        .or_else(|| restore_goodput_knee(&steps));
    let proposed_lpop = if input.phase.may_set_lpop() {
        zones.warning_max
    } else {
        None
    };

    if !input.phase.may_set_lpop() {
        findings.push(finding(
            FailureClass::C,
            "phase_cannot_set_lpop",
            format!(
                "{:?} may not set an LPOP; warning max is a candidate input only",
                input.phase
            ),
        ));
    }

    if zones.saturation_onset.is_none() && !steps.is_empty() {
        findings.push(finding(
            FailureClass::C,
            "saturation_not_reached",
            "run did not reach a saturation knee",
        ));
    }

    for step in &steps {
        push_restore_findings(&mut findings, step, &input.thresholds);
    }

    if matches!(input.scenario, RestoreScenario::SoakRestore)
        && steps.iter().any(|s| s.zone == DensityZone::Saturation)
    {
        findings.push(finding(
            FailureClass::A,
            "soak_left_warning_zone",
            "S-SOAK-RESTORE entered saturation",
        ));
    }

    if matches!(input.scenario, RestoreScenario::SpikeRestore) {
        let spike_timeouts = steps.iter().any(|s| s.observation.timeouts > 0);
        let shed = steps.iter().any(|s| s.observation.unavailable_rejects > 0);
        if spike_timeouts {
            findings.push(finding(
                FailureClass::A,
                "spike_timeouts",
                "S-SPIKE-RESTORE timed out instead of shedding",
            ));
        } else if !shed && steps.iter().any(|s| s.zone == DensityZone::Saturation) {
            findings.push(finding(
                FailureClass::A,
                "spike_did_not_shed",
                "restore storm saturated without unavailable rejects",
            ));
        }
    }

    let cache = cache_telemetry(&steps);
    if let Some(host_local_rate) = host_local_hit_rate(&steps)
        && host_local_rate < input.thresholds.warm_hit_rate_warning
    {
        findings.push(finding(
            FailureClass::B,
            "warm_cache_hit_rate_low",
            format!(
                "host-local hit rate {host_local_rate:.3} is below {}",
                input.thresholds.warm_hit_rate_warning
            ),
        ));
    }

    let calibration = if axis == RestoreAxis::ConcurrentRestores {
        calibrate_restore_limit(
            input.advertised_restore_limit,
            packing_calibration_measurement(&steps, &zones),
            input.thresholds.calibration_error_band,
        )
    } else {
        RestoreCalibration {
            advertised_limit: input.advertised_restore_limit,
            measured_warning_max: None,
            relative_error: None,
            error_band: input.thresholds.calibration_error_band,
            within_band: true,
            class: None,
        }
    };
    if let Some(class) = calibration.class {
        let code = match class {
            FailureClass::A => "scheduler_over_advertises",
            FailureClass::B => "scheduler_under_advertises",
            FailureClass::C => "scheduler_unmeasured",
        };
        findings.push(finding(
            class,
            code,
            format!(
                "advertised {} vs measured warning max {:?}",
                calibration.advertised_limit, calibration.measured_warning_max
            ),
        ));
    }

    if !input.restore_path_live {
        findings.push(finding_follow(
            FailureClass::C,
            "restore_path_not_live",
            "host restore via sandboxd is fail-closed; this series is synthetic",
            "48",
        ));
    }
    if !steps
        .iter()
        .any(|s| s.observation.snapshot_kind == RestoreSnapshotKind::LazyMemory)
    {
        findings.push(finding_follow(
            FailureClass::C,
            "lazy_restore_untested",
            "lazy memory restore was not in the series",
            "51",
        ));
    }
    if !input.live_observability {
        findings.push(finding(
            FailureClass::C,
            "live_dashboard_not_exercised",
            "named dashboards and alerts are the operator evidence set; live scrape was not run",
        ));
    }
    if !input.observability.is_complete() {
        findings.push(finding(
            FailureClass::B,
            "observability_evidence_incomplete",
            "report is missing a required dashboard, alert, trace, or audit kind",
        ));
    }
    findings.push(finding_follow(
        FailureClass::C,
        "harness_not_driving_live",
        "live S-RAMP-RESTORE/S-SPIKE-RESTORE/S-SOAK-RESTORE require the 22 harness",
        "22",
    ));
    findings.push(finding_follow(
        FailureClass::C,
        "cache_tier_labels_missing",
        "pico_snapshot_cache_hits/misses are not labeled by tier; report slices use observation fields",
        "82",
    ));

    dedupe_findings(&mut findings);

    RestorePressureReport {
        scenario: input.scenario,
        phase: input.phase,
        scope: input.scope,
        backend: input.backend,
        host_sku: input.host_sku,
        axis,
        zones,
        knee,
        proposed_lpop,
        calibration,
        latency_by_kind_and_tier: latency_slices(&steps),
        cache,
        findings,
        steps,
        observability: input.observability,
    }
}

fn packing_calibration_measurement(
    steps: &[ClassifiedRestoreStep],
    zones: &ZoneBounds,
) -> Option<u64> {
    let reached_knee = steps.iter().any(|step| step.zone >= DensityZone::Warning);
    if reached_knee {
        zones.warning_max
    } else {
        None
    }
}

fn calibrate_restore_limit(
    advertised_limit: u64,
    measured_warning_max: Option<u64>,
    error_band: f64,
) -> RestoreCalibration {
    let Some(measured) = measured_warning_max else {
        return RestoreCalibration {
            advertised_limit,
            measured_warning_max: None,
            relative_error: None,
            error_band,
            within_band: advertised_limit == 0,
            class: if advertised_limit == 0 {
                None
            } else {
                Some(FailureClass::C)
            },
        };
    };
    if measured == 0 {
        return RestoreCalibration {
            advertised_limit,
            measured_warning_max: Some(0),
            relative_error: Some(advertised_limit as f64),
            error_band,
            within_band: advertised_limit == 0,
            class: if advertised_limit > 0 {
                Some(FailureClass::A)
            } else {
                None
            },
        };
    }
    let relative_error = (advertised_limit as f64 - measured as f64) / measured as f64;
    let within_band = relative_error.abs() <= error_band;
    let class = if within_band {
        None
    } else if relative_error > error_band {
        Some(FailureClass::A)
    } else {
        Some(FailureClass::B)
    };
    RestoreCalibration {
        advertised_limit,
        measured_warning_max: Some(measured),
        relative_error: Some(relative_error),
        error_band,
        within_band,
        class,
    }
}

fn restore_zone_bounds(steps: &[ClassifiedRestoreStep]) -> ZoneBounds {
    let collapsed = collapse_worst_zone_per_axis(steps);
    let mut safe_max = None;
    let mut warning_max = None;
    let mut saturation_onset = None;
    let mut left_safe = false;
    for (axis_value, zone) in collapsed {
        match zone {
            DensityZone::Safe => {
                if !left_safe && saturation_onset.is_none() {
                    safe_max = Some(axis_value);
                    warning_max = Some(axis_value);
                }
            }
            DensityZone::Warning => {
                left_safe = true;
                if saturation_onset.is_none() {
                    warning_max = Some(axis_value);
                }
            }
            DensityZone::Saturation => {
                left_safe = true;
                if saturation_onset.is_none() {
                    saturation_onset = Some(axis_value);
                }
            }
        }
    }
    ZoneBounds {
        safe_max,
        warning_max,
        saturation_onset,
    }
}

fn collapse_worst_zone_per_axis(steps: &[ClassifiedRestoreStep]) -> Vec<(u64, DensityZone)> {
    let mut out = Vec::new();
    for step in steps {
        match out.last_mut() {
            Some((axis, zone)) if *axis == step.axis_value => {
                if step.zone > *zone {
                    *zone = step.zone;
                }
            }
            _ => out.push((step.axis_value, step.zone)),
        }
    }
    out
}

fn restore_goodput_knee(steps: &[ClassifiedRestoreStep]) -> Option<u64> {
    let mut prev_completed: Option<u64> = None;
    for step in steps {
        if let Some(prev) = prev_completed
            && step.observation.completed <= prev
            && step.observation.offered > step.observation.completed
        {
            return Some(step.axis_value);
        }
        prev_completed = Some(step.observation.completed);
    }
    None
}

fn cache_telemetry(steps: &[ClassifiedRestoreStep]) -> RestoreCacheTelemetry {
    let hits = steps.iter().map(|s| s.observation.cache_hits).sum();
    let misses = steps.iter().map(|s| s.observation.cache_misses).sum();
    RestoreCacheTelemetry {
        hits,
        misses,
        hit_rate: hit_rate(hits, misses),
    }
}

fn host_local_hit_rate(steps: &[ClassifiedRestoreStep]) -> Option<f64> {
    let hits = steps
        .iter()
        .filter(|s| s.observation.storage_tier == CacheTier::HostLocal)
        .map(|s| s.observation.cache_hits)
        .sum();
    let misses = steps
        .iter()
        .filter(|s| s.observation.storage_tier == CacheTier::HostLocal)
        .map(|s| s.observation.cache_misses)
        .sum();
    hit_rate(hits, misses)
}

fn hit_rate(hits: u64, misses: u64) -> Option<f64> {
    let lookups = hits + misses;
    if lookups == 0 {
        None
    } else {
        Some(hits as f64 / lookups as f64)
    }
}

fn latency_slices(steps: &[ClassifiedRestoreStep]) -> Vec<RestoreLatencySlice> {
    let mut slices: Vec<RestoreLatencySlice> = Vec::new();
    for step in steps {
        let obs = &step.observation;
        if let Some(existing) = slices.iter_mut().find(|slice| {
            slice.snapshot_kind == obs.snapshot_kind && slice.storage_tier == obs.storage_tier
        }) {
            existing.p50_seconds = max_opt(existing.p50_seconds, obs.restore_p50_seconds);
            existing.p95_seconds = max_opt(existing.p95_seconds, obs.restore_p95_seconds);
            existing.p99_seconds = max_opt(existing.p99_seconds, obs.restore_p99_seconds);
            existing.cache_hits = existing.cache_hits.saturating_add(obs.cache_hits);
            existing.cache_misses = existing.cache_misses.saturating_add(obs.cache_misses);
            existing.completed = existing.completed.saturating_add(obs.completed);
        } else {
            slices.push(RestoreLatencySlice {
                snapshot_kind: obs.snapshot_kind,
                storage_tier: obs.storage_tier,
                p50_seconds: obs.restore_p50_seconds,
                p95_seconds: obs.restore_p95_seconds,
                p99_seconds: obs.restore_p99_seconds,
                cache_hits: obs.cache_hits,
                cache_misses: obs.cache_misses,
                completed: obs.completed,
            });
        }
    }
    slices.sort_by_key(|slice| (slice.snapshot_kind.as_str(), slice.storage_tier.as_str()));
    slices
}

fn max_opt(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn push_restore_findings(
    findings: &mut Vec<CapacityFinding>,
    step: &ClassifiedRestoreStep,
    thresholds: &RestoreThresholds,
) {
    for reason in &step.reasons {
        let item = match reason {
            RestoreZoneReason::IsolationBroken => Some(finding(
                FailureClass::A,
                "isolation_broken",
                "isolation floor failed under restore load",
            )),
            RestoreZoneReason::CleanupIncomplete => Some(finding(
                FailureClass::A,
                "cleanup_incomplete",
                "restore left overlays, netns, cgroups, or leases",
            )),
            RestoreZoneReason::BackendChanged => Some(finding(
                FailureClass::A,
                "silent_backend_fallback",
                "backend selection changed under restore pressure",
            )),
            RestoreZoneReason::ResourceLeak => Some(finding(
                FailureClass::A,
                "resource_leak",
                "fd, cgroup, sandbox, or mount count grew without offered load",
            )),
            RestoreZoneReason::LineageMixup => Some(finding(
                FailureClass::A,
                "lineage_mixup",
                "restore mixed snapshot lineage",
            )),
            RestoreZoneReason::SecretMaterial => Some(finding(
                FailureClass::A,
                "secret_material_in_artifact",
                "credential or undeclared secret state appeared in a snapshot artifact",
            )),
            RestoreZoneReason::PartialCleanup => Some(finding(
                FailureClass::A,
                "partial_cleanup",
                "partial restore cleanup is a bad restore event",
            )),
            RestoreZoneReason::TimeoutInsteadOfShed => Some(finding(
                FailureClass::A,
                "timeout_instead_of_shed",
                "timeouts rose with unavailable rejects; shed path is not clean",
            )),
            RestoreZoneReason::SnapshotStoreBacklog => Some(finding(
                FailureClass::A,
                "snapshot_store_backlog",
                "snapshot-store backlog grew during soak",
            )),
            RestoreZoneReason::RestoreLatency => Some(finding(
                FailureClass::B,
                "restore_p99_diagnostic",
                "restore p99 crossed the diagnostic SLO-RESTORE-LAT threshold",
            )),
            RestoreZoneReason::ExecLatency => Some(finding(
                FailureClass::B,
                "exec_p99_under_restore",
                "exec p99 crossed the diagnostic threshold during restore",
            )),
            RestoreZoneReason::WithinEnvelope => {
                if step
                    .observation
                    .restore_p50_seconds
                    .is_some_and(|p50| p50 > thresholds.restore_p50_design_secs)
                {
                    Some(finding(
                        FailureClass::C,
                        "restore_p50_above_design",
                        "restore p50 exceeded the architecture 200ms design target",
                    ))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(item) = item {
            findings.push(item);
        }
    }
    if step.observation.audit_events == 0
        && (step.observation.admitted > 0 || step.observation.unavailable_rejects > 0)
    {
        findings.push(finding(
            FailureClass::B,
            "audit_missing_on_restore",
            "restore window emitted no snapshot_operation audit events",
        ));
    }
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

/// Compare zone bounds across backends for the same host SKU and scenario.
pub fn compare_restore_backends(reports: &[RestorePressureReport]) -> Vec<RestoreBackendRow> {
    reports
        .iter()
        .map(|report| RestoreBackendRow {
            backend: report.backend,
            host_sku: report.host_sku.clone(),
            safe_max: report.zones.safe_max,
            warning_max: report.zones.warning_max,
            saturation_onset: report.zones.saturation_onset,
        })
        .collect()
}

/// One row of a restore backend comparison table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreBackendRow {
    pub backend: RuntimeType,
    pub host_sku: String,
    pub safe_max: Option<u64>,
    pub warning_max: Option<u64>,
    pub saturation_onset: Option<u64>,
}

#[cfg(test)]
mod tests;
