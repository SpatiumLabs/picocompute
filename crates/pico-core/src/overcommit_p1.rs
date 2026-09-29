//! P1 gating analysis for the LS/BE overcommit track.
//!
//! Pure-data helpers that evaluate the gating plan from the P0 spike report
//! (section 5) through the same [`crate::capacity::analyze_active_capacity`]
//! seam the load harness feeds. Host I/O stays out: the only host query used
//! here is the side-effect-free [`crate::overcommit::probe_core_scheduling`]
//! probe, and every other input is a measured report, a scheduler response,
//! or an explicit byte count.
//!
//! ## What each helper proves
//!
//! - [`compare_ls_warning_max`] keeps the LS warning-max stable between the
//!   LS-only baseline ramp and the LS+BE mixed ramp.
//! - [`verify_be_overcommit_bits`] requires every BE admit beyond strict
//!   capacity to carry `overcommit_applied`, and forbids the bit on LS.
//! - [`sweep_mode_order_ok`] enforces the runbook order for shared-base
//!   characterization (`SharedPageCache` before `PmemDax`).
//! - [`smt_inflation_pct`] plus [`classify_smt_inflation`] records noisy-neighbor
//!   inflation against the external 45.2%/17.3% reference without claiming it.
//! - [`core_sched_branch`] maps the probe result onto the comparison the SKU
//!   supports (cookie-tagged vs SMT-exclusion-only).
//! - [`check_soak_holds`] and [`check_noisy_holds`] read the class-A findings
//!   (`soak_left_warning_zone`, `heartbeat_stale`, `isolation_broken`) from a
//!   capacity report.
//! - [`compare_exec_knees`] keeps the exec-concurrency knee separate from the
//!   active-count cap.
//! - [`measure_reclaim_freed_bytes`] ties balloon plus idle-reclaim bytes to
//!   the suspend memory profile (`Memory` frees, `Filesystem` frees nothing).
//! - [`graduation_for_mechanism`] graduates a mechanism only when its SLO
//!   window is green and its class-A invariants hold.
//!
//! Nothing here sets a launch proven operating point. P1 reports keep
//! `proposed_lpop = none` per [`crate::capacity::ValidationPhase::P1`]; the
//! active-sandbox defaults stay unchanged until a production-shaped host run
//! provides measured knees.

use serde::{Deserialize, Serialize};

use crate::capacity::ActiveCapacityReport;
use crate::capacity::CapacityScenario;
use crate::capacity::DensityAxis;
use crate::cell_scheduler::CellSchedulerResponse;
use crate::overcommit::{
    BalloonPolicy, BaseSharingMode, CoreSchedSupport, OvercommitPolicy, ServiceClass,
    balloon_target, idle_reclaim_plan,
};
use crate::snapshot::SnapshotProfile;

/// External SMT inflation reference, high end, in percent.
///
/// External input from the prior system design note (45.2% inflation without
/// mitigation). Recorded here so P1 runs can place their measured inflation
/// next to it, never as a pass threshold by itself.
pub const DSEC_SMT_INFLATION_HIGH_PCT: f64 = 45.2;

/// External SMT inflation reference, low end, in percent.
///
/// External input from the same design note (17.3% inflation with mitigation).
/// A P1 S-NOISY run inside or below this band is consistent with the reference;
/// a run above it is still evidence, not a failure by itself.
pub const DSEC_SMT_INFLATION_LOW_PCT: f64 = 17.3;

/// LS baseline stability between the LS-only ramp and the LS+BE mixed ramp.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LsBaselineVerdict {
    /// Warning-max from the LS-only baseline report.
    pub baseline_warning_max: Option<u64>,
    /// Warning-max from the LS slice of the mixed report.
    pub mixed_ls_warning_max: Option<u64>,
    /// True when both maxima exist and match exactly.
    pub ls_unchanged: bool,
}

/// Compares the LS warning-max across the baseline and mixed ramps.
///
/// The mixed report passed in must be the LS slice (or an LS-only re-run at
/// the same ratios): BE packing must never move the LS knee earlier. A `None`
/// on either side fails closed because an unmeasured LS knee cannot prove
/// stability.
#[must_use]
pub fn compare_ls_warning_max(
    baseline: &ActiveCapacityReport,
    mixed_ls: &ActiveCapacityReport,
) -> LsBaselineVerdict {
    let baseline_warning_max = baseline.zones.warning_max;
    let mixed_ls_warning_max = mixed_ls.zones.warning_max;
    let ls_unchanged = match (baseline_warning_max, mixed_ls_warning_max) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    LsBaselineVerdict {
        baseline_warning_max,
        mixed_ls_warning_max,
        ls_unchanged,
    }
}

/// One placement outcome for the overcommit-bit audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeBitRecord {
    /// Class of the admitted request.
    pub service_class: ServiceClass,
    /// True when the winner could not have fit the request strict.
    pub beyond_strict: bool,
    /// Bit echoed by the scheduler response.
    pub overcommit_applied: bool,
}

/// Builds a bit record from a scheduler response plus the strict-fit fact.
///
/// `beyond_strict` comes from the caller (strict `can_fit` on the winner
/// before overcommit scaling): the response alone cannot know whether the
/// admit consumed overcommit budget.
#[must_use]
pub fn bit_record_from_response(
    response: &CellSchedulerResponse,
    beyond_strict: bool,
) -> BeBitRecord {
    BeBitRecord {
        service_class: response.service_class,
        beyond_strict,
        overcommit_applied: response.overcommit_applied,
    }
}

/// Audit verdict for the `overcommit_applied` bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeBitVerdict {
    /// BE admits beyond strict capacity.
    pub be_beyond_strict: usize,
    /// BE admits beyond strict missing the bit.
    pub be_missing_bit: usize,
    /// BE admits within strict capacity wrongly carrying the bit.
    pub be_false_positive: usize,
    /// LS admits observed.
    pub ls_total: usize,
    /// LS admits wrongly carrying the bit.
    pub ls_false_positive: usize,
    /// True when every BE admit beyond strict carries the bit, no BE within
    /// strict carries it, and no LS does.
    pub passes: bool,
}

/// Verifies the overcommit-bit contract across one ramp.
///
/// Every BE admit that consumed budget beyond strict capacity must carry
/// `overcommit_applied`. BE admits within strict capacity and LS admits must
/// never carry it, so S-NOISY evidence can separate strict admits from
/// overcommit admits without ambiguity.
#[must_use]
pub fn verify_be_overcommit_bits(records: &[BeBitRecord]) -> BeBitVerdict {
    let mut be_beyond_strict = 0;
    let mut be_missing_bit = 0;
    let mut be_false_positive = 0;
    let mut ls_total = 0;
    let mut ls_false_positive = 0;
    for record in records {
        match record.service_class {
            ServiceClass::BestEffort => {
                if record.beyond_strict {
                    be_beyond_strict += 1;
                    if !record.overcommit_applied {
                        be_missing_bit += 1;
                    }
                } else if record.overcommit_applied {
                    be_false_positive += 1;
                }
            }
            ServiceClass::LatencySensitive => {
                ls_total += 1;
                if record.overcommit_applied {
                    ls_false_positive += 1;
                }
            }
        }
    }
    BeBitVerdict {
        be_beyond_strict,
        be_missing_bit,
        be_false_positive,
        ls_total,
        ls_false_positive,
        passes: be_missing_bit == 0 && be_false_positive == 0 && ls_false_positive == 0,
    }
}

/// One BE sweep point: policy plus measured zone maxima.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OvercommitSweepPoint {
    /// Human label for the report table (for example `2.0x-cpu/2.0x-mem/128MiB-shared-page-cache`).
    pub label: String,
    /// Policy evaluated at this point.
    pub policy: OvercommitPolicy,
    /// Warning-max for the mixed LS+BE ramp at this point.
    pub mixed_warning_max: Option<u64>,
    /// Warning-max for the LS slice at this point.
    pub ls_warning_max: Option<u64>,
    /// True when isolation, cleanup, and audit held at this point.
    pub isolation_held: bool,
}

/// Summary across one BE overcommit sweep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SweepSummary {
    /// Number of sweep points.
    pub points: usize,
    /// True when every point kept the LS warning-max equal to the baseline.
    pub ls_stable_at_all_points: bool,
    /// True when every point held isolation.
    pub all_isolated: bool,
    /// Largest mixed warning-max observed (BE gain candidate, not an LPOP).
    pub max_mixed_warning_max: Option<u64>,
}

/// Summarizes a BE sweep against one LS baseline.
///
/// `baseline_warning_max` is the LS-only warning-max the sweep must not move.
/// Points with an unmeasured LS slice fail the stability check: a missing LS
/// knee cannot prove LS stayed put.
#[must_use]
pub fn summarize_sweep(
    points: &[OvercommitSweepPoint],
    baseline_warning_max: Option<u64>,
) -> SweepSummary {
    let mut ls_stable = true;
    let mut isolated = true;
    let mut max_mixed: Option<u64> = None;
    for point in points {
        if point.ls_warning_max != baseline_warning_max {
            ls_stable = false;
        }
        if baseline_warning_max.is_none() || point.ls_warning_max.is_none() {
            ls_stable = false;
        }
        if !point.isolation_held {
            isolated = false;
        }
        max_mixed = match (max_mixed, point.mixed_warning_max) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (None, b) => b,
            (a, None) => a,
        };
    }
    SweepSummary {
        points: points.len(),
        ls_stable_at_all_points: ls_stable && !points.is_empty(),
        all_isolated: isolated && !points.is_empty(),
        max_mixed_warning_max: max_mixed,
    }
}

/// Checks the runbook order for shared-base characterization.
///
/// The P0 runbook characterizes `be_shared_base_mb` per image under
/// `SharedPageCache` first, then under `PmemDax`. This predicate returns true
/// when no `PmemDax` point appears before a `SharedPageCache` point: it keeps
/// the report table honest without imposing a policy on the scheduler itself.
#[must_use]
pub fn sweep_mode_order_ok(points: &[OvercommitSweepPoint]) -> bool {
    let mut seen_pmem = false;
    for point in points {
        match point.policy.base_sharing {
            BaseSharingMode::PmemDax => seen_pmem = true,
            BaseSharingMode::SharedPageCache => {
                if seen_pmem {
                    return false;
                }
            }
            BaseSharingMode::None => {}
        }
    }
    true
}

/// Computes SMT inflation in percent: `(noisy - baseline)/baseline * 100`.
///
/// Returns `None` (fail closed) when either input is non-finite, the
/// baseline is not positive, or the noisy value is negative: a zero or
/// negative baseline would make the ratio meaningless, negative latency is
/// impossible, and non-finite inputs must never become a report number.
#[must_use]
pub fn smt_inflation_pct(baseline_p99_secs: f64, noisy_p99_secs: f64) -> Option<f64> {
    if !baseline_p99_secs.is_finite()
        || !noisy_p99_secs.is_finite()
        || baseline_p99_secs <= 0.0
        || noisy_p99_secs < 0.0
    {
        return None;
    }
    Some((noisy_p99_secs - baseline_p99_secs) / baseline_p99_secs * 100.0)
}

/// Placement of a measured inflation against the external reference band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtInflationBand {
    /// At or below the mitigated reference (17.3%).
    AtOrBelowReference,
    /// Between the mitigated and unmitigated references.
    WithinReference,
    /// Above the unmitigated reference (45.2%).
    AboveReference,
}

impl SmtInflationBand {
    /// Short label for report tables.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtOrBelowReference => "at_or_below_reference",
            Self::WithinReference => "within_reference",
            Self::AboveReference => "above_reference",
        }
    }
}

/// Classifies a measured inflation against the 17.3%/45.2% reference.
///
/// The band is descriptive context for the P1 report, not a pass threshold:
/// S-NOISY passes on SLO plus class-A invariants, with the band recorded
/// alongside.
#[must_use]
pub fn classify_smt_inflation(inflation_pct: f64) -> SmtInflationBand {
    if inflation_pct <= DSEC_SMT_INFLATION_LOW_PCT {
        SmtInflationBand::AtOrBelowReference
    } else if inflation_pct <= DSEC_SMT_INFLATION_HIGH_PCT {
        SmtInflationBand::WithinReference
    } else {
        SmtInflationBand::AboveReference
    }
}

/// Comparison the SKU supports for the S-NOISY core-scheduling question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreSchedBranch {
    /// Kernel plus host support core scheduling: compare cookie-tagged VMM
    /// threads against SMT-exclusion-only.
    CookieTaggedVsSmtExclusion,
    /// No core-scheduling support: the SMT-exclusion path is the baseline.
    SmtExclusionOnly,
}

impl CoreSchedBranch {
    /// Short label for report tables.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CookieTaggedVsSmtExclusion => "cookie_tagged_vs_smt_exclusion",
            Self::SmtExclusionOnly => "smt_exclusion_only",
        }
    }
}

/// Maps the probe result onto the comparison the P1 run must attempt.
///
/// `Supported` requires the cookie-tagged comparison when the host enables
/// tagging; any `Unsupported` reason keeps the SMT-exclusion-only baseline so
/// the report never claims an unevaluated mechanism.
#[must_use]
pub fn core_sched_branch(support: &CoreSchedSupport) -> CoreSchedBranch {
    match support {
        CoreSchedSupport::Supported => CoreSchedBranch::CookieTaggedVsSmtExclusion,
        CoreSchedSupport::Unsupported { .. } => CoreSchedBranch::SmtExclusionOnly,
    }
}

/// Soak verdict read from a S-SOAK-ACTIVE capacity report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakVerdict {
    /// True when no `soak_left_warning_zone` finding is present.
    pub stayed_in_warning_zone: bool,
    /// True when no `heartbeat_stale` finding is present.
    pub heartbeats_fresh: bool,
    /// True when no `resource_leak` finding is present.
    pub no_leak: bool,
    /// True when all three hold on a S-SOAK-ACTIVE report.
    pub passes: bool,
}

/// Checks the S-SOAK-ACTIVE gate from report findings.
///
/// The capacity model emits `soak_left_warning_zone` when any soak step
/// reaches saturation, `heartbeat_stale` for stale host heartbeats, and
/// `resource_leak` for leak detection. All three must be absent at the
/// warning-zone LS+BE mix. A report from any other scenario fails closed:
/// findings from the wrong scenario cannot prove the soak gate.
#[must_use]
pub fn check_soak_holds(report: &ActiveCapacityReport) -> SoakVerdict {
    let has = |code: &str| report.findings.iter().any(|f| f.code == code);
    let stayed = !has("soak_left_warning_zone");
    let fresh = !has("heartbeat_stale");
    let no_leak = !has("resource_leak");
    let scenario_ok = report.scenario == CapacityScenario::SoakActive;
    SoakVerdict {
        stayed_in_warning_zone: stayed,
        heartbeats_fresh: fresh,
        no_leak,
        passes: stayed && fresh && no_leak && scenario_ok,
    }
}

/// Noisy-neighbor verdict for one S-NOISY comparison.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NoisyVerdict {
    /// True when no isolation or cross-tenant finding is present.
    pub isolation_held: bool,
    /// Measured SMT inflation in percent, when computable.
    pub inflation_pct: Option<f64>,
    /// Band of the measured inflation against the external reference.
    pub inflation_band: Option<SmtInflationBand>,
    /// Core-scheduling comparison the SKU supports.
    pub core_branch: CoreSchedBranch,
    /// True when the report is S-NOISY, isolation held, and inflation was computable.
    pub passes: bool,
}

/// Checks the S-NOISY gate: isolation plus a recorded inflation number.
///
/// Isolation reads the class-A findings (`isolation_broken`,
/// `cross_tenant_placement`): a break fails even when latency looks green.
/// Inflation needs both p99 inputs; an uncomputable inflation fails the
/// recording requirement (the run happened but produced no comparable
/// number), never silently passes. A report from any other scenario fails
/// closed: findings from the wrong scenario cannot prove the noisy gate.
#[must_use]
pub fn check_noisy_holds(
    report: &ActiveCapacityReport,
    baseline_p99_secs: f64,
    noisy_p99_secs: f64,
    core_support: &CoreSchedSupport,
) -> NoisyVerdict {
    let has = |code: &str| report.findings.iter().any(|f| f.code == code);
    let isolation_held = !has("isolation_broken") && !has("cross_tenant_placement");
    let inflation_pct = smt_inflation_pct(baseline_p99_secs, noisy_p99_secs);
    let inflation_band = inflation_pct.map(classify_smt_inflation);
    let scenario_ok = report.scenario == CapacityScenario::Noisy;
    NoisyVerdict {
        isolation_held,
        inflation_pct,
        inflation_band,
        core_branch: core_sched_branch(core_support),
        passes: scenario_ok && isolation_held && inflation_pct.is_some(),
    }
}

/// Exec-knee comparison between strict and LS+BE S-RAMP-EXEC runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecKneeComparison {
    /// Knee from the strict exec run.
    pub strict_knee: Option<u64>,
    /// Knee from the mixed LS+BE exec run.
    pub mixed_knee: Option<u64>,
    /// True when both exec reports use the exec-concurrency axis.
    pub both_on_exec_axis: bool,
    /// True when the mixed exec knee differs from the active-count cap.
    pub separate_from_active_cap: bool,
}

/// Compares exec-concurrency knees and keeps them separate from active count.
///
/// The exec LPOP lives on the concurrency axis and must be reported
/// separately: copying the active-count warning-max into the exec row hides
/// the contention knee the scenario exists to find. `active_warning_max` is
/// the S-RAMP-ACTIVE warning-max for the same backend and SKU; when the mixed
/// exec knee equals it exactly the comparison flags `separate_from_active_cap
/// = false` so the report cannot present a copy as a measurement. An
/// unmeasured mixed knee is never separate: there is no knee to compare, and
/// the missing knee stays visible in the report as `none`.
#[must_use]
pub fn compare_exec_knees(
    strict_exec: &ActiveCapacityReport,
    mixed_exec: &ActiveCapacityReport,
    active_warning_max: Option<u64>,
) -> ExecKneeComparison {
    let both_on_exec_axis = strict_exec.axis == DensityAxis::ExecConcurrency
        && mixed_exec.axis == DensityAxis::ExecConcurrency;
    let strict_knee = strict_exec.knee;
    let mixed_knee = mixed_exec.knee;
    let separate_from_active_cap = match (mixed_knee, active_warning_max) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(knee), Some(active)) => knee != active,
    };
    ExecKneeComparison {
        strict_knee,
        mixed_knee,
        both_on_exec_axis,
        separate_from_active_cap,
    }
}

/// Reclaim comparison tied to the suspend memory profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReclaimComparison {
    /// Balloon inflate bytes from the guest free-page hint.
    pub balloon_freed_bytes: u64,
    /// Idle-reclaim bytes under the `Memory` profile.
    pub memory_profile_freed_bytes: u64,
    /// Idle-reclaim bytes under the `Filesystem` profile (must be zero).
    pub filesystem_profile_freed_bytes: u64,
    /// True when the filesystem profile frees nothing.
    pub filesystem_is_zero: bool,
}

/// Measures balloon plus idle-reclaim freed bytes against the suspend profile.
///
/// A `Filesystem` snapshot preserves no guest memory, so there is nothing to
/// balloon or reclaim and the helper expects zero there. The `Memory` side
/// reuses the container throttle-plus-`memory.reclaim` plan math; a zero or
/// tiny limit yields zero freed bytes rather than an error, because a P1
/// measurement row with no reclaim is data, not a control failure.
#[must_use]
pub fn measure_reclaim_freed_bytes(
    memory_limit_bytes: u64,
    guest_free_hint_bytes: u64,
    policy: &BalloonPolicy,
) -> ReclaimComparison {
    let balloon_freed_bytes = balloon_target(memory_limit_bytes, guest_free_hint_bytes, policy)
        .map(|target| target.inflate_bytes)
        .unwrap_or(0);
    let memory_profile_freed_bytes = idle_reclaim_plan(memory_limit_bytes, SnapshotProfile::Memory)
        .ok()
        .flatten()
        .map(|plan| plan.reclaim_bytes)
        .unwrap_or(0);
    let filesystem_profile_freed_bytes =
        idle_reclaim_plan(memory_limit_bytes, SnapshotProfile::Filesystem)
            .ok()
            .flatten()
            .map(|plan| plan.reclaim_bytes)
            .unwrap_or(0);
    ReclaimComparison {
        balloon_freed_bytes,
        memory_profile_freed_bytes,
        filesystem_profile_freed_bytes,
        filesystem_is_zero: filesystem_profile_freed_bytes == 0,
    }
}

/// Overcommit mechanisms evaluated by the P1 runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum P1Mechanism {
    /// Scaled vCPU totals for BE fit.
    CpuOvercommit,
    /// Scaled memory totals for BE fit.
    MemoryOvercommit,
    /// Shared-base discount under page-cache-friendly shared mounts.
    SharedBasePageCache,
    /// Shared-base discount under virtio-pmem with DAX.
    SharedBasePmemDax,
    /// SCHED_IDLE plus class cgroup controls for BE.
    SchedIdleControls,
    /// SMT sibling exclusion for LS/BE placement.
    SmtExclusion,
    /// Core-scheduling cookie tagging of VMM threads.
    CoreSchedTagging,
    /// Balloon plus idle-reclaim against the suspend profile.
    BalloonReclaim,
}

impl P1Mechanism {
    /// Short label for report tables.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpuOvercommit => "cpu_overcommit",
            Self::MemoryOvercommit => "memory_overcommit",
            Self::SharedBasePageCache => "shared_base_page_cache",
            Self::SharedBasePmemDax => "shared_base_pmem_dax",
            Self::SchedIdleControls => "sched_idle_controls",
            Self::SmtExclusion => "smt_exclusion",
            Self::CoreSchedTagging => "core_sched_tagging",
            Self::BalloonReclaim => "balloon_reclaim",
        }
    }

    /// All mechanisms in report order.
    pub const ALL: &[Self] = &[
        Self::CpuOvercommit,
        Self::MemoryOvercommit,
        Self::SharedBasePageCache,
        Self::SharedBasePmemDax,
        Self::SchedIdleControls,
        Self::SmtExclusion,
        Self::CoreSchedTagging,
        Self::BalloonReclaim,
    ];
}

/// Graduation decision for one mechanism.
///
/// A mechanism graduates to an implementation follow-up only when its SLO
/// window stayed green and its class-A invariants held for the same run.
/// Either condition alone is insufficient: green SLOs with broken isolation
/// stay held, and intact invariants with a missed SLO stay held.
#[must_use]
pub fn graduation_for_mechanism(slo_green: bool, class_a_hold: bool) -> bool {
    slo_green && class_a_hold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capacity::ActiveCapacityInput;
    use crate::capacity::BindingResource;
    use crate::capacity::CapacityScenario;
    use crate::capacity::CapacityScope;
    use crate::capacity::DensityObservation;
    use crate::capacity::DensityThresholds;
    use crate::capacity::SandboxPackingShape;
    use crate::capacity::ValidationPhase;
    use crate::capacity::analyze_active_capacity;
    use crate::runtime::RuntimeType;

    fn report_for(
        scenario: CapacityScenario,
        actives: &[u64],
        pressure_at: Option<(u64, f64)>,
    ) -> ActiveCapacityReport {
        let mut steps: Vec<DensityObservation> = actives
            .iter()
            .map(|n| DensityObservation::at_active(*n))
            .collect();
        if let Some((at, pressure)) = pressure_at {
            for step in &mut steps {
                if step.active_count == at {
                    step.pressure.memory_cgroup = pressure;
                }
            }
        }
        analyze_active_capacity(ActiveCapacityInput {
            scenario,
            phase: ValidationPhase::P1,
            scope: CapacityScope::Host,
            backend: RuntimeType::Firecracker,
            host_sku: "lab-64vcpu".into(),
            packing_shape: SandboxPackingShape::platform_default(),
            advertised_limit: 32,
            binding: Some(BindingResource::Vcpu),
            steps,
            thresholds: DensityThresholds::default(),
        })
    }

    fn exec_report_for(concurrency: &[(u64, f64)]) -> ActiveCapacityReport {
        let steps: Vec<DensityObservation> = concurrency
            .iter()
            .map(|(conc, err)| {
                let mut obs = DensityObservation::at_active(16);
                obs.concurrent_execs = *conc;
                obs.exec_error_ratio = *err;
                obs
            })
            .collect();
        analyze_active_capacity(ActiveCapacityInput {
            scenario: CapacityScenario::RampExec,
            phase: ValidationPhase::P1,
            scope: CapacityScope::Host,
            backend: RuntimeType::Firecracker,
            host_sku: "lab-64vcpu".into(),
            packing_shape: SandboxPackingShape::platform_default(),
            advertised_limit: 32,
            binding: Some(BindingResource::Vcpu),
            steps,
            thresholds: DensityThresholds::default(),
        })
    }

    #[test]
    fn ls_baseline_match_passes_when_warning_max_equal() {
        let baseline = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let mixed = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let verdict = compare_ls_warning_max(&baseline, &mixed);
        assert!(verdict.ls_unchanged);
        assert_eq!(verdict.baseline_warning_max, verdict.mixed_ls_warning_max);
    }

    #[test]
    fn ls_baseline_fails_when_mixed_moves_earlier() {
        let baseline = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let mixed = report_for(CapacityScenario::RampActive, &[8, 12, 16], Some((12, 35.0)));
        let verdict = compare_ls_warning_max(&baseline, &mixed);
        assert!(!verdict.ls_unchanged);
        assert_ne!(verdict.baseline_warning_max, verdict.mixed_ls_warning_max);
    }

    #[test]
    fn ls_baseline_fails_closed_on_unmeasured_knee() {
        // Empty baseline has no warning-max, so stability must fail closed
        // even against a measured mixed ramp.
        let baseline = report_for(CapacityScenario::RampActive, &[], None);
        let mixed = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let verdict = compare_ls_warning_max(&baseline, &mixed);
        assert!(!verdict.ls_unchanged);
        assert_eq!(verdict.baseline_warning_max, None);
    }

    #[test]
    fn be_bits_require_bit_beyond_strict_and_forbid_it_on_ls() {
        let records = [
            BeBitRecord {
                service_class: ServiceClass::BestEffort,
                beyond_strict: true,
                overcommit_applied: true,
            },
            BeBitRecord {
                service_class: ServiceClass::BestEffort,
                beyond_strict: false,
                overcommit_applied: false,
            },
            BeBitRecord {
                service_class: ServiceClass::LatencySensitive,
                beyond_strict: false,
                overcommit_applied: false,
            },
        ];
        let verdict = verify_be_overcommit_bits(&records);
        assert!(verdict.passes);
        assert_eq!(verdict.be_beyond_strict, 1);
    }

    #[test]
    fn be_bits_fail_on_missing_bit_or_ls_false_positive() {
        let missing = [BeBitRecord {
            service_class: ServiceClass::BestEffort,
            beyond_strict: true,
            overcommit_applied: false,
        }];
        assert!(!verify_be_overcommit_bits(&missing).passes);
        let ls_leak = [BeBitRecord {
            service_class: ServiceClass::LatencySensitive,
            beyond_strict: false,
            overcommit_applied: true,
        }];
        let verdict = verify_be_overcommit_bits(&ls_leak);
        assert!(!verdict.passes);
        assert_eq!(verdict.ls_false_positive, 1);
    }

    #[test]
    fn be_bits_fail_on_within_strict_false_positive() {
        let spurious = [BeBitRecord {
            service_class: ServiceClass::BestEffort,
            beyond_strict: false,
            overcommit_applied: true,
        }];
        let verdict = verify_be_overcommit_bits(&spurious);
        assert!(!verdict.passes);
        assert_eq!(verdict.be_false_positive, 1);
    }

    #[test]
    fn sweep_summary_tracks_ls_stability_and_isolation() {
        let policy = OvercommitPolicy {
            enabled: true,
            be_cpu_overcommit: 2.0,
            be_memory_overcommit: 2.0,
            be_shared_base_mb: 128,
            base_sharing: BaseSharingMode::SharedPageCache,
        };
        let points = vec![
            OvercommitSweepPoint {
                label: "2x-page-cache".into(),
                policy,
                mixed_warning_max: Some(48),
                ls_warning_max: Some(16),
                isolation_held: true,
            },
            OvercommitSweepPoint {
                label: "2x-pmem".into(),
                policy: OvercommitPolicy {
                    base_sharing: BaseSharingMode::PmemDax,
                    ..policy
                },
                mixed_warning_max: Some(52),
                ls_warning_max: Some(16),
                isolation_held: true,
            },
        ];
        let summary = summarize_sweep(&points, Some(16));
        assert!(summary.ls_stable_at_all_points);
        assert!(summary.all_isolated);
        assert_eq!(summary.max_mixed_warning_max, Some(52));
        assert!(sweep_mode_order_ok(&points));
    }

    #[test]
    fn sweep_order_rejects_pmem_before_page_cache() {
        let base = OvercommitPolicy {
            enabled: true,
            be_cpu_overcommit: 2.0,
            be_memory_overcommit: 2.0,
            be_shared_base_mb: 128,
            base_sharing: BaseSharingMode::SharedPageCache,
        };
        let reordered = vec![
            OvercommitSweepPoint {
                label: "pmem-first".into(),
                policy: OvercommitPolicy {
                    base_sharing: BaseSharingMode::PmemDax,
                    ..base
                },
                mixed_warning_max: Some(52),
                ls_warning_max: Some(16),
                isolation_held: true,
            },
            OvercommitSweepPoint {
                label: "page-cache-second".into(),
                policy: base,
                mixed_warning_max: Some(48),
                ls_warning_max: Some(16),
                isolation_held: true,
            },
        ];
        assert!(!sweep_mode_order_ok(&reordered));
    }

    #[test]
    fn smt_inflation_matches_reference_band() {
        // 45.2% unmitigated reference: 100ms baseline to 145.2ms noisy.
        let high = smt_inflation_pct(0.1, 0.1452).unwrap();
        assert!((high - 45.2).abs() < 0.01);
        assert_eq!(
            classify_smt_inflation(high),
            SmtInflationBand::WithinReference
        );
        // 17.3% mitigated reference: 100ms baseline to 117.3ms noisy.
        let low = smt_inflation_pct(0.1, 0.1173).unwrap();
        assert!((low - 17.3).abs() < 0.01);
        assert_eq!(
            classify_smt_inflation(low),
            SmtInflationBand::AtOrBelowReference
        );
        assert_eq!(
            classify_smt_inflation(60.0),
            SmtInflationBand::AboveReference
        );
    }

    #[test]
    fn smt_inflation_fails_closed_on_bad_inputs() {
        assert_eq!(smt_inflation_pct(0.0, 0.1), None);
        assert_eq!(smt_inflation_pct(f64::NAN, 0.1), None);
        assert_eq!(smt_inflation_pct(0.1, f64::INFINITY), None);
        assert_eq!(smt_inflation_pct(-0.1, 0.1), None);
        assert_eq!(smt_inflation_pct(0.1, -0.05), None);
    }

    #[test]
    fn core_branch_maps_probe_result() {
        assert_eq!(
            core_sched_branch(&CoreSchedSupport::Supported),
            CoreSchedBranch::CookieTaggedVsSmtExclusion
        );
        assert_eq!(
            core_sched_branch(&CoreSchedSupport::Unsupported {
                reason: "test host"
            }),
            CoreSchedBranch::SmtExclusionOnly
        );
    }

    #[test]
    fn soak_holds_on_warning_zone_mix_without_leak() {
        let mut steps = Vec::new();
        for _ in 0..3 {
            let mut obs = DensityObservation::at_active(16);
            obs.pressure.memory_cgroup = 16.0;
            steps.push(obs);
        }
        let report = analyze_active_capacity(ActiveCapacityInput {
            scenario: CapacityScenario::SoakActive,
            phase: ValidationPhase::P1,
            scope: CapacityScope::Host,
            backend: RuntimeType::Firecracker,
            host_sku: "lab-64vcpu".into(),
            packing_shape: SandboxPackingShape::platform_default(),
            advertised_limit: 16,
            binding: Some(BindingResource::Vcpu),
            steps,
            thresholds: DensityThresholds::default(),
        });
        let verdict = check_soak_holds(&report);
        assert!(verdict.passes);
        assert!(report.proposed_lpop.is_none());
    }

    #[test]
    fn soak_fails_on_saturation_or_stale_heartbeat() {
        let mut sat = DensityObservation::at_active(16);
        sat.pressure.memory_cgroup = 40.0;
        let report = analyze_active_capacity(ActiveCapacityInput {
            scenario: CapacityScenario::SoakActive,
            phase: ValidationPhase::P1,
            scope: CapacityScope::Host,
            backend: RuntimeType::Firecracker,
            host_sku: "lab-64vcpu".into(),
            packing_shape: SandboxPackingShape::platform_default(),
            advertised_limit: 16,
            binding: Some(BindingResource::Vcpu),
            steps: vec![sat],
            thresholds: DensityThresholds::default(),
        });
        let verdict = check_soak_holds(&report);
        assert!(!verdict.passes);
        assert!(!verdict.stayed_in_warning_zone);
    }

    #[test]
    fn soak_fails_closed_on_wrong_scenario() {
        let report = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let verdict = check_soak_holds(&report);
        assert!(!verdict.passes);
    }

    #[test]
    fn noisy_holds_with_isolation_and_computable_inflation() {
        let report = report_for(CapacityScenario::Noisy, &[8], None);
        let verdict = check_noisy_holds(
            &report,
            0.1,
            0.1173,
            &CoreSchedSupport::Unsupported {
                reason: "synthetic host",
            },
        );
        assert!(verdict.passes);
        assert!(verdict.isolation_held);
        assert_eq!(
            verdict.inflation_band,
            Some(SmtInflationBand::AtOrBelowReference)
        );
        assert_eq!(verdict.core_branch, CoreSchedBranch::SmtExclusionOnly);
    }

    #[test]
    fn noisy_fails_on_isolation_break_even_with_green_latency() {
        let mut obs = DensityObservation::at_active(8);
        obs.safety.isolation_held = false;
        let report = analyze_active_capacity(ActiveCapacityInput {
            scenario: CapacityScenario::Noisy,
            phase: ValidationPhase::P1,
            scope: CapacityScope::Host,
            backend: RuntimeType::Firecracker,
            host_sku: "lab-64vcpu".into(),
            packing_shape: SandboxPackingShape::platform_default(),
            advertised_limit: 8,
            binding: Some(BindingResource::Vcpu),
            steps: vec![obs],
            thresholds: DensityThresholds::default(),
        });
        let verdict = check_noisy_holds(&report, 0.1, 0.11, &CoreSchedSupport::Supported);
        assert!(!verdict.passes);
        assert!(!verdict.isolation_held);
    }

    #[test]
    fn noisy_fails_closed_on_wrong_scenario() {
        let report = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        let verdict = check_noisy_holds(&report, 0.1, 0.11, &CoreSchedSupport::Supported);
        assert!(!verdict.passes);
    }

    #[test]
    fn exec_knees_stay_on_concurrency_axis_and_separate_from_active() {
        let strict = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0), (32, 0.02)]);
        let mixed = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0), (16, 0.02)]);
        let cmp = compare_exec_knees(&strict, &mixed, Some(24));
        assert!(cmp.both_on_exec_axis);
        assert!(cmp.separate_from_active_cap);
        assert_eq!(cmp.strict_knee, Some(32));
        assert_eq!(cmp.mixed_knee, Some(16));
    }

    #[test]
    fn exec_knee_flags_copy_from_active_cap() {
        let strict = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0), (24, 0.02)]);
        let mixed = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0), (24, 0.02)]);
        let cmp = compare_exec_knees(&strict, &mixed, Some(24));
        assert!(cmp.both_on_exec_axis);
        assert!(!cmp.separate_from_active_cap);
    }

    #[test]
    fn exec_knee_unmeasured_mixed_is_not_separate() {
        let strict = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0), (32, 0.02)]);
        let mut mixed = exec_report_for(&[(1, 0.0), (4, 0.0), (8, 0.0)]);
        mixed.knee = None;
        let cmp = compare_exec_knees(&strict, &mixed, Some(24));
        assert!(!cmp.separate_from_active_cap);
    }

    #[test]
    fn reclaim_ties_freed_bytes_to_memory_profile() {
        let policy = BalloonPolicy {
            enabled: true,
            reclaim_fraction: 0.5,
        };
        let limit = 512 * 1024 * 1024u64;
        let cmp = measure_reclaim_freed_bytes(limit, 256 * 1024 * 1024u64, &policy);
        assert_eq!(cmp.balloon_freed_bytes, 128 * 1024 * 1024u64);
        assert_eq!(cmp.memory_profile_freed_bytes, limit);
        assert_eq!(cmp.filesystem_profile_freed_bytes, 0);
        assert!(cmp.filesystem_is_zero);
    }

    #[test]
    fn reclaim_reports_zero_without_hint_or_limit() {
        let policy = BalloonPolicy {
            enabled: true,
            reclaim_fraction: 0.5,
        };
        let cmp = measure_reclaim_freed_bytes(0, 0, &policy);
        assert_eq!(cmp.balloon_freed_bytes, 0);
        assert_eq!(cmp.memory_profile_freed_bytes, 0);
        assert!(cmp.filesystem_is_zero);
    }

    #[test]
    fn graduation_needs_both_slo_and_class_a() {
        assert!(graduation_for_mechanism(true, true));
        assert!(!graduation_for_mechanism(true, false));
        assert!(!graduation_for_mechanism(false, true));
        assert!(!graduation_for_mechanism(false, false));
    }

    #[test]
    fn p1_phase_never_proposes_lpop() {
        let report = report_for(CapacityScenario::RampActive, &[8, 12, 16], None);
        assert_eq!(report.phase, ValidationPhase::P1);
        assert!(report.proposed_lpop.is_none());
    }

    #[test]
    fn mechanism_labels_cover_report_order() {
        let labels: Vec<&str> = P1Mechanism::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "cpu_overcommit",
                "memory_overcommit",
                "shared_base_page_cache",
                "shared_base_pmem_dax",
                "sched_idle_controls",
                "smt_exclusion",
                "core_sched_tagging",
                "balloon_reclaim",
            ]
        );
    }
}
