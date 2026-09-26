use super::*;
use crate::availability::{AvailabilityScenario, ObservabilityEvidence, SurvivingCapacity};
use crate::capacity::{
    ActiveCapacityInput, BindingResource, CapacityScenario, CapacityScope, DensityObservation,
    DensityThresholds, SandboxPackingShape, ValidationPhase, ZoneBounds, analyze_active_capacity,
};
use crate::image_cache::{
    ImageCacheAxis, ImageCacheCalibration, ImageCacheObservabilityEvidence, ImageCacheScenario,
    ImageCacheSizeRecommendation, ImageCacheTelemetry,
};
use crate::restore_capacity::{
    RestoreAxis, RestoreCacheTelemetry, RestoreCalibration, RestoreObservabilityEvidence,
    RestorePressureReport, RestoreScenario,
};
use crate::runtime::RuntimeType;

fn density_steps(active_counts: &[u64]) -> Vec<DensityObservation> {
    active_counts
        .iter()
        .map(|count| DensityObservation::at_active(*count))
        .collect()
}

fn saturated_step(active: u64) -> DensityObservation {
    let mut obs = DensityObservation::at_active(active);
    obs.offered = active;
    obs.admitted = active - 8;
    obs.completed = active - 8;
    obs.unavailable_rejects = 8;
    obs.pressure.memory_cgroup = 45.0;
    obs.scheduler_placed = false;
    obs
}

fn active_report(warning_target: u64) -> ActiveCapacityReport {
    let mut steps = density_steps(&[8, 16, 24]);
    steps.push(DensityObservation::at_active(warning_target));
    steps.push(saturated_step(warning_target + 8));
    analyze_active_capacity(ActiveCapacityInput {
        scenario: CapacityScenario::RampActive,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        packing_shape: SandboxPackingShape::platform_default(),
        advertised_limit: warning_target,
        binding: Some(BindingResource::Vcpu),
        steps,
        thresholds: DensityThresholds::default(),
    })
}

fn p0_input() -> PlanningInput {
    PlanningInput::lab_p0_example()
}

fn has_finding(plan: &CapacityPlan, class: FailureClass, code: &str) -> bool {
    plan.findings
        .iter()
        .any(|finding| finding.class == class && finding.code == code)
}

#[test]
fn p0_never_authorizes_rollout() {
    let plan = plan_capacity(&p0_input());
    assert_eq!(plan.rollout.preview, None);
    assert_eq!(plan.rollout.beta, None);
    assert_eq!(plan.rollout.production, None);
    assert!(has_finding(&plan, FailureClass::C, "phase_cannot_set_lpop"));
    assert_eq!(plan.confidence, Confidence::Low);
}

fn p2_evidence(input: &mut PlanningInput) {
    input.density.phase = ValidationPhase::P2;
    input.density.scope = CapacityScope::Cell;
    input.restore.phase = ValidationPhase::P2;
    input.image_cache.phase = ValidationPhase::P2;
    input.availability.phase = ValidationPhase::P2;
    input.availability.cells_total = 3;
    input.availability.cells_eligible_after_loss = 2;
    input.availability.hosts_eligible_after_loss = 40;
}

fn p3_evidence(input: &mut PlanningInput) {
    input.density.phase = ValidationPhase::P3;
    input.density.scope = CapacityScope::Region;
    input.restore.restores_per_sec_per_host = Some(2.0);
    input.restore.phase = ValidationPhase::P3;
    input.image_cache.sizing_calibrated = true;
    input.image_cache.phase = ValidationPhase::P3;
    input.availability.phase = ValidationPhase::P3;
    input.availability.cells_total = 3;
    input.availability.cells_eligible_after_loss = 2;
    input.availability.hosts_eligible_after_loss = 40;
}

#[test]
fn p2_authorizes_preview_only() {
    let mut input = p0_input();
    p2_evidence(&mut input);
    input.stage = LaunchStage::Production;
    let plan = plan_capacity(&input);
    let preview = plan.rollout.preview.expect("preview authorized");
    // Preview fleet is 64 hosts at 50% headroom, not the production 43-host fleet.
    assert_eq!(preview.max_active, 1024);
    assert_eq!(plan.rollout.beta, None);
    assert_eq!(plan.rollout.production, None);
    assert!(has_finding(
        &plan,
        FailureClass::C,
        "stage_needs_regional_evidence"
    ));
}

#[test]
fn p3_authorizes_all_stages() {
    let mut input = p0_input();
    p3_evidence(&mut input);
    input.stage = LaunchStage::Production;
    let plan = plan_capacity(&input);
    let preview = plan.rollout.preview.expect("preview");
    let production = plan.rollout.production.expect("production");
    assert!(plan.rollout.beta.is_some());
    assert_eq!(preview.max_active, 1024);
    assert_eq!(production.max_active, 1032);
    assert_eq!(plan.confidence, Confidence::High);
}

#[test]
fn p3_density_alone_does_not_authorize_production() {
    let mut input = p0_input();
    input.density.phase = ValidationPhase::P3;
    input.density.scope = CapacityScope::Region;
    let plan = plan_capacity(&input);
    assert_eq!(plan.rollout.preview, None);
    assert_eq!(plan.rollout.beta, None);
    assert_eq!(plan.rollout.production, None);
    assert_eq!(plan.confidence, Confidence::Low);
}

#[test]
fn missing_density_is_class_a_with_follow_up() {
    let mut input = p0_input();
    input.density.warning_max_per_host = None;
    let plan = plan_capacity(&input);
    assert_eq!(plan.hosts.hosts_per_region, None);
    assert_eq!(plan.hosts.total_hosts_all_regions, None);
    assert!(has_finding(
        &plan,
        FailureClass::A,
        "missing_density_measurement"
    ));
    let finding = plan
        .findings
        .iter()
        .find(|finding| finding.code == "missing_density_measurement")
        .expect("missing density finding");
    assert_eq!(finding.follow_up_issue.as_deref(), Some("63"));
}

#[test]
fn host_math_applies_headroom() {
    // warning 32, target 1000: ceil(1000/32) = 32, preview headroom 50%
    // gives ceil(32/0.5) = 64 hosts.
    let mut input = p0_input();
    input.density.safe_max_per_host = Some(24);
    input.density.warning_max_per_host = Some(32);
    let plan = plan_capacity(&input);
    assert_eq!(plan.hosts.usable_active_per_host, Some(32));
    assert_eq!(plan.hosts.hosts_for_active, Some(32));
    assert_eq!(plan.hosts.hosts_per_region, Some(64));
    assert_eq!(plan.hosts.total_hosts_all_regions, Some(64));
}

#[test]
fn production_layout_survives_one_cell_loss() {
    let mut input = p0_input();
    input.stage = LaunchStage::Production;
    let plan = plan_capacity(&input);
    // 32 pre-headroom hosts, 43 with 25% headroom, grown to 4 cells so the
    // 32 surviving hosts still cover pre-headroom demand.
    assert_eq!(plan.hosts.hosts_for_active, Some(32));
    assert_eq!(plan.hosts.hosts_per_region, Some(43));
    assert_eq!(plan.hosts.cells_per_region, Some(4));
    assert_eq!(plan.hosts.hosts_per_cell, Some(11));
    assert_eq!(plan.hosts.surviving_hosts_after_one_cell_loss, Some(32));
    assert!(plan.hosts.meets_one_cell_survival);
}

#[test]
fn backend_not_production_eligible_blocks_rollout() {
    let mut input = p0_input();
    input.density.backend = RuntimeType::RemoteFirecracker;
    let plan = plan_capacity(&input);
    assert_eq!(plan.rollout.preview, None);
    assert_eq!(plan.rollout.beta, None);
    assert_eq!(plan.rollout.production, None);
    assert!(has_finding(
        &plan,
        FailureClass::A,
        "backend_not_production_eligible"
    ));
    assert_eq!(plan.confidence, Confidence::Low);
}

#[test]
fn full_active_report_feeds_host_sizing() {
    let report = active_report(32);
    assert_eq!(report.zones.warning_max, Some(32));
    let density = MeasuredDensity::from_active_report(&report);
    assert_eq!(density.warning_max_per_host, Some(32));

    let mut input = p0_input();
    input.density = density;
    let plan = plan_capacity(&input);
    assert_eq!(plan.hosts.usable_active_per_host, Some(32));
    assert_eq!(plan.hosts.hosts_for_active, Some(32));
    assert!(!plan.evidence_digests.is_empty());
    assert_eq!(plan.artifact_digest().len(), 64);
    let markdown = plan.to_markdown();
    assert!(markdown.contains("Cost and capacity plan"));
    assert!(markdown.contains("lab-64vcpu"));
}

#[test]
fn exec_axis_report_sizes_no_hosts() {
    let scenarios = vec![(4, false), (8, false), (12, false), (16, true)];
    let steps: Vec<DensityObservation> = scenarios
        .into_iter()
        .map(|(execs, saturated)| {
            let mut obs = DensityObservation::at_active(execs);
            obs.concurrent_execs = execs;
            if saturated {
                obs.pressure.memory_cgroup = 45.0;
                obs.scheduler_placed = false;
                obs.unavailable_rejects = 4;
            }
            obs
        })
        .collect();
    let report = analyze_active_capacity(ActiveCapacityInput {
        scenario: CapacityScenario::RampExec,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        packing_shape: SandboxPackingShape::platform_default(),
        advertised_limit: 32,
        binding: Some(BindingResource::Vcpu),
        steps,
        thresholds: DensityThresholds::default(),
    });
    assert_eq!(report.axis, DensityAxis::ExecConcurrency);
    let density = MeasuredDensity::from_active_report(&report);
    assert_eq!(density.warning_max_per_host, None);

    let mut input = p0_input();
    input.density = density;
    let plan = plan_capacity(&input);
    assert_eq!(plan.hosts.hosts_per_region, None);
    assert!(has_finding(
        &plan,
        FailureClass::A,
        "missing_density_measurement"
    ));
}

#[test]
fn second_run_comparison_reports_forecast_error() {
    let mut first_input = p0_input();
    first_input.density.warning_max_per_host = Some(32);
    let mut second_input = p0_input();
    second_input.density.warning_max_per_host = Some(24);
    let predicted = plan_capacity(&first_input);
    let observed = plan_capacity(&second_input);
    // Lower measured density needs more hosts: 32 vs 42 pre-cell-growth.
    assert_eq!(predicted.hosts.hosts_for_active, Some(32));
    assert_eq!(observed.hosts.hosts_for_active, Some(42));
    let comparison = compare_plans(&predicted, &observed);
    assert_eq!(comparison.hosts_delta, Some(-20));
    let error = comparison.hosts_error_pct.expect("error pct");
    assert!(error < 0.0, "predicted fewer hosts than observed");
    assert!((error - (-20.0 / 84.0 * 100.0)).abs() < 1.0);
    assert!(
        forecast_error_pct(Some(10), Some(0)).is_none(),
        "zero observed has no error pct"
    );
    assert!(
        forecast_error_pct(Some(10), None).is_none(),
        "missing observed has no error pct"
    );
}

#[test]
fn sensitivity_moves_hosts_and_cost_monotonically() {
    let plan = plan_capacity(&p0_input());
    assert_eq!(plan.sensitivity.len(), 5);
    let density_row = plan
        .sensitivity
        .iter()
        .find(|row| row.variable == "warning_max_per_host")
        .expect("density row");
    assert!(
        density_row.hosts_low.unwrap_or(0) >= density_row.hosts_base.unwrap_or(0),
        "lower density needs at least as many hosts"
    );
    assert!(
        density_row.hosts_high.unwrap_or(u64::MAX) <= density_row.hosts_base.unwrap_or(0),
        "higher density needs at most as many hosts"
    );
    let price_row = plan
        .sensitivity
        .iter()
        .find(|row| row.variable == "usd_per_host_hour")
        .expect("price row");
    assert!(price_row.cost_low_usd <= price_row.cost_base_usd);
    assert!(price_row.cost_high_usd >= price_row.cost_base_usd);
    // Host count does not move with price.
    assert_eq!(price_row.hosts_low, price_row.hosts_base);
    assert_eq!(price_row.hosts_high, price_row.hosts_base);
}

#[test]
fn invalid_pricebook_is_class_a_and_clamped() {
    let mut input = p0_input();
    input.prices.usd_per_host_hour = -2.0;
    input.prices.egress_usd_per_gb = f64::NAN;
    let plan = plan_capacity(&input);
    assert!(has_finding(&plan, FailureClass::A, "invalid_pricebook"));
    assert_eq!(plan.cost.hosts_monthly_usd, 0.0);
    assert_eq!(plan.cost.egress_monthly_usd, 0.0);
}

#[test]
fn mix_shares_normalize_with_class_b() {
    let mut input = p0_input();
    input.mix = vec![
        TrafficClassShare {
            class: TrafficClass::Short,
            share: 1.0,
        },
        TrafficClassShare {
            class: TrafficClass::Session,
            share: 1.0,
        },
    ];
    let plan = plan_capacity(&input);
    assert!(has_finding(
        &plan,
        FailureClass::B,
        "mix_shares_unnormalized"
    ));
    let total: f64 = plan.cost.by_class.iter().map(|entry| entry.share).sum();
    assert!((total - 1.0).abs() < 1e-9);
    let class_total: f64 = plan
        .cost
        .by_class
        .iter()
        .map(|entry| entry.monthly_usd)
        .sum();
    assert!((class_total - plan.cost.total_monthly_usd).abs() < 0.01);
}

#[test]
fn zero_regions_keep_per_region_math_with_finding() {
    let mut input = p0_input();
    input.demand.regions = 0;
    let plan = plan_capacity(&input);
    // Fail closed toward over-provisioning: a 1-region equivalent, never
    // zero hosts.
    assert!(plan.hosts.hosts_per_region.is_some());
    assert_eq!(
        plan.hosts.total_hosts_all_regions,
        plan.hosts.hosts_per_region
    );
    assert!(has_finding(&plan, FailureClass::A, "invalid_demand"));
}

#[test]
fn cost_math_matches_hand_calculation() {
    let input = p0_input();
    let plan = plan_capacity(&input);
    // 64 preview hosts at $1.50/h for 730h.
    assert!((plan.cost.hosts_monthly_usd - 64.0 * 1.50 * 730.0).abs() < 0.01);
    // 1000 active x 256MiB snapshots.
    let snapshot_gib = 1_000.0 * 268_435_456.0 / BYTES_PER_GIB;
    // 20GiB cell cache x 4 preview cells (64 hosts / 20 target, min 1).
    let cell_gib = 20.0 * 4.0;
    let expected_storage = snapshot_gib * 0.023 + cell_gib * 0.10;
    assert!((plan.cost.storage_monthly_usd - expected_storage).abs() < 0.05);
    // Egress attributed entirely to WP-NET.
    let net = plan
        .cost
        .by_class
        .iter()
        .find(|entry| entry.class == TrafficClass::Net)
        .expect("net class");
    assert!(net.monthly_usd >= plan.cost.egress_monthly_usd);
}

fn restore_report_for(scenario: RestoreScenario) -> RestorePressureReport {
    RestorePressureReport {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        axis: RestoreAxis::ConcurrentRestores,
        zones: ZoneBounds {
            safe_max: Some(3),
            warning_max: Some(5),
            saturation_onset: Some(6),
        },
        knee: Some(6),
        proposed_lpop: None,
        calibration: RestoreCalibration {
            advertised_limit: 5,
            measured_warning_max: Some(5),
            relative_error: Some(0.0),
            error_band: 0.15,
            within_band: true,
            class: None,
        },
        latency_by_kind_and_tier: Vec::new(),
        cache: RestoreCacheTelemetry {
            hits: 90,
            misses: 10,
            hit_rate: Some(0.9),
        },
        findings: Vec::new(),
        steps: Vec::new(),
        observability: RestoreObservabilityEvidence::p0_required(),
    }
}

#[test]
fn spike_restore_measures_no_sustainable_concurrency() {
    let ramp = restore_report_for(RestoreScenario::RampRestore);
    assert_eq!(
        MeasuredRestore::from_restore_report(&ramp).concurrent_restores_per_host,
        Some(5)
    );
    let spike = restore_report_for(RestoreScenario::SpikeRestore);
    assert_eq!(
        MeasuredRestore::from_restore_report(&spike).concurrent_restores_per_host,
        None
    );
}

fn image_report_for(scenario: ImageCacheScenario) -> crate::image_cache::ImageCacheReport {
    crate::image_cache::ImageCacheReport {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        axis: ImageCacheAxis::WorkingSetImages,
        zones: ZoneBounds {
            safe_max: Some(8),
            warning_max: Some(8),
            saturation_onset: Some(12),
        },
        knee: Some(12),
        proposed_lpop: None,
        calibration: ImageCacheCalibration {
            advertised_bytes: 8 * 1024 * 1024 * 1024,
            recommended_bytes: 5 * 1024 * 1024 * 1024,
            measured_working_set_images: Some(8),
            relative_error: None,
            error_band: 0.15,
            within_band: true,
            class: None,
        },
        sizing: ImageCacheSizeRecommendation {
            host_local_bytes: 5 * 1024 * 1024 * 1024,
            cell_cache_bytes: 20 * 1024 * 1024 * 1024,
            working_set_images: 8,
            typical_image_bytes: 512 * 1024 * 1024,
            headroom: 0.25,
        },
        latency_by_profile_and_tier: Vec::new(),
        cache: ImageCacheTelemetry {
            hits: 95,
            misses: 5,
            evictions: 0,
            hit_rate: Some(0.95),
        },
        findings: Vec::new(),
        steps: Vec::new(),
        observability: ImageCacheObservabilityEvidence::p0_required(),
    }
}

#[test]
fn only_thrash_calibrates_cache_sizing() {
    let cold = image_report_for(ImageCacheScenario::Cold);
    assert!(!MeasuredImageCache::from_image_report(&cold).sizing_calibrated);
    let thrash = image_report_for(ImageCacheScenario::Thrash);
    assert!(MeasuredImageCache::from_image_report(&thrash).sizing_calibrated);
    // Uncalibrated sizing keeps the plan's cache unknown.
    let mut input = p0_input();
    input.image_cache.sizing_calibrated = false;
    let plan = plan_capacity(&input);
    assert!(has_finding(&plan, FailureClass::C, "image_cache_unproven"));
}

#[test]
fn measured_survival_below_demand_is_class_b() {
    let mut input = p0_input();
    p2_evidence(&mut input);
    input.availability.hosts_eligible_after_loss = 0;
    let plan = plan_capacity(&input);
    assert!(!plan.hosts.meets_one_cell_survival);
    assert!(has_finding(
        &plan,
        FailureClass::B,
        "measured_survival_below_demand"
    ));
}

#[test]
fn availability_report_feeds_surviving_capacity() {
    let report = crate::availability::CellAvailabilityReport {
        scenario: AvailabilityScenario::FailCell,
        phase: ValidationPhase::P2,
        scope: CapacityScope::Cell,
        surviving: SurvivingCapacity {
            cells_total: 3,
            cells_eligible: 2,
            hosts_total: 60,
            hosts_eligible: 40,
            existing_on_failed_domain: 20,
            new_placements_on_failed_domain: 0,
        },
        proposed_lpop: None,
        findings: Vec::new(),
        observations: Vec::new(),
        observability: ObservabilityEvidence::p0_required(),
    };
    let measured = MeasuredAvailability::from_availability_report(&report);
    assert_eq!(measured.cells_total, 3);
    assert_eq!(measured.cells_eligible_after_loss, 2);
    assert_eq!(measured.hosts_eligible_after_loss, 40);
}

#[test]
fn plan_round_trips_through_json() {
    let plan = plan_capacity(&p0_input());
    let json = serde_json::to_vec(&plan).expect("serialize plan");
    let back: CapacityPlan = serde_json::from_slice(&json).expect("deserialize plan");
    assert_eq!(plan, back);
}
