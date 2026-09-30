//! Active sandbox capacity model (ST-ACTIVE / ST-EXEC).
//!
//! Classifies measured density into safe, warning, and saturation zones,
//! compares scheduler advertised packing with measured admits, and emits
//! the report the load harness and cost model
//! consume. P0 tests exercise the model with synthetic series. P1+ host
//! runs must feed the same [`analyze_active_capacity`] seam.
//!
//! This module does not generate load and does not set a launch proven
//! operating point. P0/P1 reports never authorize regional quotas.

use serde::{Deserialize, Serialize};

use crate::cell_scheduler::HostCapacity;
use crate::runtime::RuntimeType;
use crate::scheduler::CellCapacity;

/// ADR-0012 scenarios owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapacityScenario {
    /// Fill hosts with WP-SESSION, then exec.
    #[serde(rename = "S-RAMP-ACTIVE")]
    RampActive,
    /// WP-SESSION at warning-zone density.
    #[serde(rename = "S-SOAK-ACTIVE")]
    SoakActive,
    /// Noisy-neighbor isolation under shared or dedicated tenancy.
    #[serde(rename = "S-NOISY")]
    Noisy,
    /// Concurrent execs on a fixed active set.
    #[serde(rename = "S-RAMP-EXEC")]
    RampExec,
}

impl CapacityScenario {
    /// Axis used for zone bounds and the knee.
    pub fn axis(self) -> DensityAxis {
        match self {
            Self::RampExec => DensityAxis::ExecConcurrency,
            Self::RampActive | Self::SoakActive | Self::Noisy => DensityAxis::ActiveCount,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RampActive => "S-RAMP-ACTIVE",
            Self::SoakActive => "S-SOAK-ACTIVE",
            Self::Noisy => "S-NOISY",
            Self::RampExec => "S-RAMP-EXEC",
        }
    }
}

/// Measured quantity that defines a zone boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DensityAxis {
    /// Active sandbox count (ST-ACTIVE).
    ActiveCount,
    /// Concurrent platform execs (ST-EXEC).
    ExecConcurrency,
}

/// Validation phase from ADR-0012. Only P2+ may propose an LPOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationPhase {
    /// Local/CI smoke. No density claim.
    P0,
    /// One production-shaped host. Input to cell tests, not an LPOP.
    P1,
    /// One production-shaped cell. Preview LPOP only.
    P2,
    /// Regional candidate.
    P3,
    /// G-14 evidence bundle.
    P4,
}

impl ValidationPhase {
    /// Whether a report from this phase may propose an LPOP tuple.
    pub fn may_set_lpop(self) -> bool {
        matches!(self, Self::P2 | Self::P3 | Self::P4)
    }
}

/// Aggregation scope for a density report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityScope {
    Host,
    Cell,
    Region,
}

/// Operating zone for a measured step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DensityZone {
    Safe,
    Warning,
    Saturation,
}

impl DensityZone {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Warning => "warning",
            Self::Saturation => "saturation",
        }
    }
}

/// ADR-0012 failure class for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureClass {
    /// Blocks the requested launch stage.
    A,
    /// Does not block if quota is capped below the issue.
    B,
    /// Design-target gap. Not a G-14 miss.
    C,
}

/// Resource that binds advertised packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingResource {
    Vcpu,
    Memory,
    Disk,
    ProcessSlot,
    SandboxSlot,
}

/// Per-sandbox request used to translate scheduler capacity into a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPackingShape {
    pub vcpus: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

impl Default for SandboxPackingShape {
    fn default() -> Self {
        Self {
            vcpus: 2,
            memory_mb: 512,
            disk_mb: 1024,
        }
    }
}

impl SandboxPackingShape {
    /// Default sandbox from [`crate::metadata::ResourceLimits`] plus 1 GiB disk.
    pub fn platform_default() -> Self {
        Self::default()
    }
}

/// Thresholds that map a measurement onto [`DensityZone`].
///
/// Memory pressure uses the host-level `pico_cgroup_memory_pressure`
/// gauge (0-100). Utilization pressures are 0.0-1.0. Availability SLOs
/// are error ratios on terminal valid events.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DensityThresholds {
    /// Inclusive upper bound of the safe memory-pressure band.
    pub memory_pressure_warning: f64,
    /// Inclusive lower bound of the saturation memory-pressure band.
    pub memory_pressure_saturation: f64,
    pub utilization_warning: f64,
    pub utilization_saturation: f64,
    pub exec_error_warning: f64,
    pub exec_error_saturation: f64,
    pub boot_error_warning: f64,
    pub boot_error_saturation: f64,
    pub exec_p99_warning_secs: f64,
    /// Upper diagnostic p99 band. Still Warning / class-B: p99 cannot
    /// saturate a density zone until latency SLOs are budgeted.
    pub exec_p99_saturation_secs: f64,
    /// Relative error band for advertised vs measured (e.g. 0.15 = 15%).
    pub calibration_error_band: f64,
}

impl Default for DensityThresholds {
    fn default() -> Self {
        Self {
            memory_pressure_warning: 15.0,
            memory_pressure_saturation: 30.0,
            utilization_warning: 0.75,
            utilization_saturation: 0.90,
            exec_error_warning: 0.0005,
            exec_error_saturation: 0.001,
            boot_error_warning: 0.0025,
            boot_error_saturation: 0.005,
            exec_p99_warning_secs: 1.0,
            exec_p99_saturation_secs: 5.0,
            calibration_error_band: 0.15,
        }
    }
}

/// Resource pressure sampled at one ramp or soak step.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ResourcePressureSample {
    /// Host-level cgroup `memory.pressure` some avg10 (0-100).
    pub memory_cgroup: f64,
    /// CPU utilization or stall fraction (0-1).
    pub cpu: f64,
    /// Disk utilization (0-1).
    pub disk: f64,
    /// Network utilization (0-1).
    pub network: f64,
    /// Process-slot utilization (0-1).
    pub process_slots: f64,
    /// Open file descriptors on the host or cell control plane.
    pub fds: u64,
}

impl Default for ResourcePressureSample {
    fn default() -> Self {
        Self {
            memory_cgroup: 0.0,
            cpu: 0.0,
            disk: 0.0,
            network: 0.0,
            process_slots: 0.0,
            fds: 0,
        }
    }
}

/// Safety invariants that fail the run even when SLOs are green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyFlags {
    pub isolation_held: bool,
    pub cleanup_complete: bool,
    pub backend_unchanged: bool,
    pub heartbeat_fresh: bool,
    pub leak_detected: bool,
    pub dedicated_tenancy: bool,
    pub cross_tenant_placement: bool,
}

impl Default for SafetyFlags {
    fn default() -> Self {
        Self {
            isolation_held: true,
            cleanup_complete: true,
            backend_unchanged: true,
            heartbeat_fresh: true,
            leak_detected: false,
            dedicated_tenancy: true,
            cross_tenant_placement: false,
        }
    }
}

/// One held load step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DensityObservation {
    pub active_count: u64,
    pub concurrent_execs: u64,
    pub offered: u64,
    pub admitted: u64,
    pub completed: u64,
    pub unavailable_rejects: u64,
    pub timeouts: u64,
    pub exec_error_ratio: f64,
    pub boot_error_ratio: f64,
    pub exec_p99_seconds: Option<f64>,
    pub pressure: ResourcePressureSample,
    pub safety: SafetyFlags,
    pub scheduler_placed: bool,
    pub scheduler_should_throttle: bool,
    pub advertised_remaining: u64,
}

impl DensityObservation {
    /// Observation at `active_count` with remaining defaults (healthy idle).
    pub fn at_active(active_count: u64) -> Self {
        Self {
            active_count,
            concurrent_execs: 0,
            offered: active_count,
            admitted: active_count,
            completed: active_count,
            unavailable_rejects: 0,
            timeouts: 0,
            exec_error_ratio: 0.0,
            boot_error_ratio: 0.0,
            exec_p99_seconds: Some(0.05),
            pressure: ResourcePressureSample::default(),
            safety: SafetyFlags::default(),
            scheduler_placed: true,
            scheduler_should_throttle: false,
            advertised_remaining: 0,
        }
    }

    fn axis_value(&self, axis: DensityAxis) -> u64 {
        match axis {
            DensityAxis::ActiveCount => self.active_count,
            DensityAxis::ExecConcurrency => self.concurrent_execs,
        }
    }
}

/// Why a step landed in its zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneReason {
    WithinEnvelope,
    MemoryPressure,
    UtilizationPressure,
    ExecErrorRatio,
    BootErrorRatio,
    ExecLatency,
    SchedulerThrottle,
    SchedulerRejected,
    TimeoutInsteadOfShed,
    IsolationBroken,
    CleanupIncomplete,
    BackendChanged,
    HeartbeatStale,
    ResourceLeak,
    CrossTenantPlacement,
}

/// Classified ramp/soak step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedStep {
    pub axis_value: u64,
    pub zone: DensityZone,
    pub reasons: Vec<ZoneReason>,
    pub observation: DensityObservation,
}

/// Safe / warning / saturation bounds on the scenario axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneBounds {
    /// Maximum axis value that stayed entirely in [`DensityZone::Safe`].
    pub safe_max: Option<u64>,
    /// Maximum axis value that stayed in warning or better. This is the
    /// LPOP cap when the phase may set an LPOP.
    pub warning_max: Option<u64>,
    /// First axis value classified as saturation (the knee when caused by
    /// goodput or SLO/pressure).
    pub saturation_onset: Option<u64>,
}

/// Scheduler advertised packing vs measured warning-zone density.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchedulerCalibration {
    pub advertised_limit: u64,
    pub measured_warning_max: Option<u64>,
    pub relative_error: Option<f64>,
    pub error_band: f64,
    pub within_band: bool,
    pub binding: Option<BindingResource>,
    pub class: Option<FailureClass>,
}

/// One class-A/B/C finding attached to a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityFinding {
    pub class: FailureClass,
    pub code: String,
    pub detail: String,
    pub follow_up_issue: Option<String>,
}

/// Input to [`analyze_active_capacity`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveCapacityInput {
    pub scenario: CapacityScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub packing_shape: SandboxPackingShape,
    pub advertised_limit: u64,
    pub binding: Option<BindingResource>,
    pub steps: Vec<DensityObservation>,
    pub thresholds: DensityThresholds,
}

/// Capacity report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveCapacityReport {
    pub scenario: CapacityScenario,
    pub phase: ValidationPhase,
    pub scope: CapacityScope,
    pub backend: RuntimeType,
    pub host_sku: String,
    pub axis: DensityAxis,
    pub zones: ZoneBounds,
    pub knee: Option<u64>,
    pub proposed_lpop: Option<u64>,
    pub calibration: SchedulerCalibration,
    pub findings: Vec<CapacityFinding>,
    pub steps: Vec<ClassifiedStep>,
}

impl ActiveCapacityReport {
    /// Content digest of the report JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Active sandbox capacity report\n\n");
        out.push_str(&format!(
            "- Scenario: {}\n- Phase: {:?}\n- Scope: {:?}\n- Backend: {}\n- Host SKU: {}\n",
            self.scenario.as_str(),
            self.phase,
            self.scope,
            self.backend,
            self.host_sku
        ));
        out.push_str(&format!(
            "- Safe max: {}\n- Warning max (LPOP cap): {}\n- Saturation onset / knee: {}\n- Proposed LPOP: {}\n",
            fmt_opt(self.zones.safe_max),
            fmt_opt(self.zones.warning_max),
            fmt_opt(self.knee),
            fmt_opt(self.proposed_lpop)
        ));
        out.push_str(&format!(
            "- Advertised limit: {}\n- Calibration within band: {}\n",
            self.calibration.advertised_limit, self.calibration.within_band
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

fn fmt_opt(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Advertised host packing and the resource that binds it.
pub fn advertised_host_limit(
    capacity: &HostCapacity,
    shape: SandboxPackingShape,
) -> (u64, BindingResource) {
    let empty = HostCapacity {
        allocated_vcpus: 0,
        allocated_memory_mb: 0,
        used_disk_mb: 0,
        allocated_network_mbps: 0,
        used_process_slots: 0,
        ..*capacity
    };
    let limit = empty.remaining_fit_count(shape.vcpus, shape.memory_mb, shape.disk_mb);
    let vcpu = empty
        .total_vcpus
        .checked_div(u64::from(shape.vcpus))
        .unwrap_or(u64::MAX);
    let memory = empty
        .total_memory_mb
        .checked_div(shape.memory_mb)
        .unwrap_or(u64::MAX);
    let disk = empty
        .total_disk_mb
        .checked_div(shape.disk_mb)
        .unwrap_or(u64::MAX);
    let binding = if limit == vcpu {
        BindingResource::Vcpu
    } else if limit == memory {
        BindingResource::Memory
    } else if limit == disk {
        BindingResource::Disk
    } else {
        BindingResource::ProcessSlot
    };
    (limit, binding)
}

/// Advertised cell packing and the resource that binds it.
pub fn advertised_cell_limit(
    capacity: &CellCapacity,
    shape: SandboxPackingShape,
) -> (u64, BindingResource) {
    let empty = CellCapacity {
        allocated_vcpus: 0,
        allocated_memory_mb: 0,
        current_sandboxes: 0,
        be_pool: None,
        ..*capacity
    };
    let limit = empty.remaining_fit_count(shape.vcpus, shape.memory_mb);
    let vcpu = empty
        .total_vcpus
        .checked_div(u64::from(shape.vcpus))
        .unwrap_or(u64::MAX);
    let memory = empty
        .total_memory_mb
        .checked_div(shape.memory_mb)
        .unwrap_or(u64::MAX);
    let binding = if limit == vcpu {
        BindingResource::Vcpu
    } else if limit == memory {
        BindingResource::Memory
    } else {
        BindingResource::SandboxSlot
    };
    (limit, binding)
}

/// Compare scheduler advertised capacity with the measured warning-zone max.
pub fn calibrate_advertised_capacity(
    advertised_limit: u64,
    measured_warning_max: Option<u64>,
    error_band: f64,
    binding: Option<BindingResource>,
) -> SchedulerCalibration {
    let Some(measured) = measured_warning_max else {
        return SchedulerCalibration {
            advertised_limit,
            measured_warning_max: None,
            relative_error: None,
            error_band,
            within_band: advertised_limit == 0,
            binding,
            class: if advertised_limit == 0 {
                None
            } else {
                Some(FailureClass::C)
            },
        };
    };
    if measured == 0 {
        let class = if advertised_limit > 0 {
            Some(FailureClass::A)
        } else {
            None
        };
        return SchedulerCalibration {
            advertised_limit,
            measured_warning_max: Some(0),
            relative_error: Some(advertised_limit as f64),
            error_band,
            within_band: advertised_limit == 0,
            binding,
            class,
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
    SchedulerCalibration {
        advertised_limit,
        measured_warning_max: Some(measured),
        relative_error: Some(relative_error),
        error_band,
        within_band,
        binding,
        class,
    }
}

/// Classify one observation against the default or provided thresholds.
pub fn classify_density(
    observation: &DensityObservation,
    scenario: CapacityScenario,
    thresholds: &DensityThresholds,
) -> ClassifiedStep {
    let mut reasons = Vec::new();
    let safety = &observation.safety;

    if !safety.isolation_held {
        reasons.push(ZoneReason::IsolationBroken);
    }
    if !safety.cleanup_complete {
        reasons.push(ZoneReason::CleanupIncomplete);
    }
    if !safety.backend_unchanged {
        reasons.push(ZoneReason::BackendChanged);
    }
    if safety.leak_detected {
        reasons.push(ZoneReason::ResourceLeak);
    }
    if safety.dedicated_tenancy && safety.cross_tenant_placement {
        reasons.push(ZoneReason::CrossTenantPlacement);
    }
    if !safety.heartbeat_fresh && matches!(scenario, CapacityScenario::SoakActive) {
        reasons.push(ZoneReason::HeartbeatStale);
    }

    let safety_fail = reasons.iter().any(|r| {
        matches!(
            r,
            ZoneReason::IsolationBroken
                | ZoneReason::CleanupIncomplete
                | ZoneReason::BackendChanged
                | ZoneReason::ResourceLeak
                | ZoneReason::CrossTenantPlacement
        )
    });

    if observation.timeouts > 0 && observation.unavailable_rejects > 0 {
        reasons.push(ZoneReason::TimeoutInsteadOfShed);
    }

    if observation.exec_error_ratio >= thresholds.exec_error_saturation {
        reasons.push(ZoneReason::ExecErrorRatio);
    }
    if observation.boot_error_ratio >= thresholds.boot_error_saturation {
        reasons.push(ZoneReason::BootErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_saturation {
        reasons.push(ZoneReason::MemoryPressure);
    }
    if utilization_saturated(&observation.pressure, thresholds) {
        reasons.push(ZoneReason::UtilizationPressure);
    }
    if !observation.scheduler_placed && observation.offered > observation.admitted {
        reasons.push(ZoneReason::SchedulerRejected);
    }

    let saturating = safety_fail
        || reasons.iter().any(|r| {
            matches!(
                r,
                ZoneReason::TimeoutInsteadOfShed
                    | ZoneReason::ExecErrorRatio
                    | ZoneReason::BootErrorRatio
                    | ZoneReason::MemoryPressure
                    | ZoneReason::UtilizationPressure
                    | ZoneReason::SchedulerRejected
                    | ZoneReason::HeartbeatStale
            )
        });

    if saturating {
        return ClassifiedStep {
            axis_value: observation.axis_value(scenario.axis()),
            zone: DensityZone::Saturation,
            reasons,
            observation: observation.clone(),
        };
    }

    if observation.exec_error_ratio >= thresholds.exec_error_warning {
        reasons.push(ZoneReason::ExecErrorRatio);
    }
    if observation.boot_error_ratio >= thresholds.boot_error_warning {
        reasons.push(ZoneReason::BootErrorRatio);
    }
    if observation.pressure.memory_cgroup >= thresholds.memory_pressure_warning {
        reasons.push(ZoneReason::MemoryPressure);
    }
    if utilization_warning(&observation.pressure, thresholds) {
        reasons.push(ZoneReason::UtilizationPressure);
    }
    if observation.exec_p99_seconds.is_some_and(|p99| {
        p99 >= thresholds.exec_p99_warning_secs || p99 >= thresholds.exec_p99_saturation_secs
    }) {
        reasons.push(ZoneReason::ExecLatency);
    }
    if observation.scheduler_should_throttle {
        reasons.push(ZoneReason::SchedulerThrottle);
    }

    let zone = if reasons.is_empty() {
        reasons.push(ZoneReason::WithinEnvelope);
        DensityZone::Safe
    } else {
        DensityZone::Warning
    };

    ClassifiedStep {
        axis_value: observation.axis_value(scenario.axis()),
        zone,
        reasons,
        observation: observation.clone(),
    }
}

fn utilization_saturated(
    pressure: &ResourcePressureSample,
    thresholds: &DensityThresholds,
) -> bool {
    pressure.cpu >= thresholds.utilization_saturation
        || pressure.disk >= thresholds.utilization_saturation
        || pressure.network >= thresholds.utilization_saturation
        || pressure.process_slots >= thresholds.utilization_saturation
}

fn utilization_warning(pressure: &ResourcePressureSample, thresholds: &DensityThresholds) -> bool {
    pressure.cpu >= thresholds.utilization_warning
        || pressure.disk >= thresholds.utilization_warning
        || pressure.network >= thresholds.utilization_warning
        || pressure.process_slots >= thresholds.utilization_warning
}

/// Classify a ramp/soak/noisy series and emit zone bounds plus calibration.
pub fn analyze_active_capacity(input: ActiveCapacityInput) -> ActiveCapacityReport {
    let axis = input.scenario.axis();
    let mut steps: Vec<ClassifiedStep> = input
        .steps
        .iter()
        .map(|obs| classify_density(obs, input.scenario, &input.thresholds))
        .collect();
    steps.sort_by_key(|step| step.axis_value);

    let mut findings = Vec::new();
    if steps.is_empty() {
        findings.push(CapacityFinding {
            class: FailureClass::A,
            code: "no_measurements".into(),
            detail: "capacity report has no steps".into(),
            follow_up_issue: None,
        });
    }

    let zones = zone_bounds(&steps);
    let knee = zones.saturation_onset.or_else(|| goodput_knee(&steps));
    let proposed_lpop = if input.phase.may_set_lpop() {
        zones.warning_max
    } else {
        None
    };

    if !input.phase.may_set_lpop() {
        findings.push(CapacityFinding {
            class: FailureClass::C,
            code: "phase_cannot_set_lpop".into(),
            detail: format!(
                "{:?} may not set an LPOP; warning max is a candidate input only",
                input.phase
            ),
            follow_up_issue: None,
        });
    }

    if zones.saturation_onset.is_none() && !steps.is_empty() {
        findings.push(CapacityFinding {
            class: FailureClass::C,
            code: "saturation_not_reached".into(),
            detail: "run did not reach a saturation knee".into(),
            follow_up_issue: None,
        });
    }

    for step in &steps {
        push_safety_findings(&mut findings, step);
    }

    if matches!(input.scenario, CapacityScenario::SoakActive)
        && steps.iter().any(|s| s.zone == DensityZone::Saturation)
    {
        findings.push(CapacityFinding {
            class: FailureClass::A,
            code: "soak_left_warning_zone".into(),
            detail: "S-SOAK-ACTIVE entered saturation".into(),
            follow_up_issue: None,
        });
    }

    let calibration = if axis == DensityAxis::ActiveCount {
        calibrate_advertised_capacity(
            input.advertised_limit,
            packing_calibration_measurement(&steps, &zones),
            input.thresholds.calibration_error_band,
            input.binding,
        )
    } else {
        SchedulerCalibration {
            advertised_limit: input.advertised_limit,
            measured_warning_max: None,
            relative_error: None,
            error_band: input.thresholds.calibration_error_band,
            within_band: true,
            binding: input.binding,
            class: None,
        }
    };
    if let Some(class) = calibration.class {
        let code = match class {
            FailureClass::A => "scheduler_over_advertises",
            FailureClass::B => "scheduler_under_advertises",
            FailureClass::C => "scheduler_unmeasured",
        };
        findings.push(CapacityFinding {
            class,
            code: code.into(),
            detail: format!(
                "advertised {} vs measured warning max {:?}",
                calibration.advertised_limit, calibration.measured_warning_max
            ),
            follow_up_issue: None,
        });
    }

    dedupe_findings(&mut findings);

    ActiveCapacityReport {
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
        findings,
        steps,
    }
}

fn packing_calibration_measurement(steps: &[ClassifiedStep], zones: &ZoneBounds) -> Option<u64> {
    let reached_knee = steps.iter().any(|step| step.zone >= DensityZone::Warning);
    if reached_knee {
        zones.warning_max
    } else {
        None
    }
}

fn zone_bounds(steps: &[ClassifiedStep]) -> ZoneBounds {
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

fn collapse_worst_zone_per_axis(steps: &[ClassifiedStep]) -> Vec<(u64, DensityZone)> {
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

fn goodput_knee(steps: &[ClassifiedStep]) -> Option<u64> {
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

fn push_safety_findings(findings: &mut Vec<CapacityFinding>, step: &ClassifiedStep) {
    for reason in &step.reasons {
        let (class, code, detail) = match reason {
            ZoneReason::IsolationBroken => (
                FailureClass::A,
                "isolation_broken",
                "isolation floor failed under load",
            ),
            ZoneReason::CleanupIncomplete => (
                FailureClass::A,
                "cleanup_incomplete",
                "destroy left overlays, netns, cgroups, or leases",
            ),
            ZoneReason::BackendChanged => (
                FailureClass::A,
                "silent_backend_fallback",
                "backend selection changed under pressure",
            ),
            ZoneReason::ResourceLeak => (
                FailureClass::A,
                "resource_leak",
                "fd, cgroup, sandbox, or mount count grew without offered load",
            ),
            ZoneReason::CrossTenantPlacement => (
                FailureClass::A,
                "cross_tenant_placement",
                "dedicated tenancy allowed a noisy neighbor onto another tenant host",
            ),
            ZoneReason::TimeoutInsteadOfShed => (
                FailureClass::A,
                "timeout_instead_of_shed",
                "timeouts rose with unavailable rejects; shed path is not clean",
            ),
            ZoneReason::HeartbeatStale => (
                FailureClass::A,
                "heartbeat_stale",
                "host heartbeats left SLO-HOST freshness during soak",
            ),
            ZoneReason::ExecLatency => (
                FailureClass::B,
                "exec_p99_diagnostic",
                "exec p99 crossed the diagnostic threshold",
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
pub fn compare_backends(reports: &[ActiveCapacityReport]) -> Vec<BackendZoneRow> {
    reports
        .iter()
        .map(|report| BackendZoneRow {
            backend: report.backend,
            host_sku: report.host_sku.clone(),
            safe_max: report.zones.safe_max,
            warning_max: report.zones.warning_max,
            saturation_onset: report.zones.saturation_onset,
        })
        .collect()
}

/// One row of a backend comparison table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendZoneRow {
    pub backend: RuntimeType,
    pub host_sku: String,
    pub safe_max: Option<u64>,
    pub warning_max: Option<u64>,
    pub saturation_onset: Option<u64>,
}

#[cfg(test)]
mod tests;
