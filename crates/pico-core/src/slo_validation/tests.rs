use super::*;
use crate::capacity::{CapacityScope, ValidationPhase};
use crate::runtime::RuntimeType;

fn throughput_input(
    scenario: ThroughputScenario,
    steps: Vec<ThroughputObservation>,
) -> ThroughputInput {
    ThroughputInput {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        steps,
    }
}

fn full_matrix_present() -> Vec<String> {
    [
        "S-RAMP-API",
        "S-SPIKE-API",
        "S-RAMP-CREATE",
        "S-SPIKE-CREATE",
        "S-RAMP-ACTIVE",
        "S-SOAK-MIX",
        "S-SOAK-ACTIVE",
        "S-RAMP-EXEC",
        "S-NOISY",
        "S-RAMP-RESTORE",
        "S-SPIKE-RESTORE",
        "S-SOAK-RESTORE",
        "S-CACHE-COLD",
        "S-CACHE-WARM",
        "S-CACHE-THRASH",
        "S-FAIL-HOST",
        "S-FAIL-CELL",
        "S-RECOVER",
        "S-RAMP-PIPE",
        "S-PIPE-BACKPRESSURE",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn healthy_counts() -> Vec<SloWindowCounts> {
    SloId::all()
        .iter()
        .map(|slo| SloWindowCounts::healthy(*slo, 10_000, 5.0))
        .collect()
}

#[test]
fn slo_targets_match_recording_rules() {
    assert_eq!(SloId::Create.target(), 0.995);
    assert_eq!(SloId::Boot.target(), 0.995);
    assert_eq!(SloId::Exec.target(), 0.999);
    assert_eq!(SloId::Destroy.target(), 0.999);
    assert_eq!(SloId::Audit.target(), 0.9999);
    assert!(SloId::Create.is_user_facing());
    assert!(!SloId::Audit.is_user_facing());
}

#[test]
fn burn_math_matches_policy_worked_example() {
    // 99.5% SLO: 7.2% errors is exactly 14.4x burn.
    let burn = burn_rate(0.072, 0.995).expect("budget valid");
    assert!((burn - FAST_BURN_THRESHOLD).abs() < 1e-9);
    assert!((budget_remaining(0.005, 0.995) - 0.0).abs() < 1e-9);
    assert!((budget_remaining(0.0, 0.995) - 1.0).abs() < 1e-9);
    assert!((budget_remaining(0.0025, 0.995) - 0.5).abs() < 1e-9);
    // 99.9% exec: 1.44% errors is 14.4x.
    let exec_fast = FAST_BURN_THRESHOLD * (1.0 - SloId::Exec.target());
    assert!((exec_fast - 0.0144).abs() < 1e-9);
    // 30d budget at 14.4x exhausts in about 50 hours.
    let hours = 30.0 * 24.0 / FAST_BURN_THRESHOLD;
    assert!((hours - 50.0).abs() < 0.1);
}

#[test]
fn error_ratio_empty_is_no_data_not_zero() {
    assert_eq!(error_ratio(0, 0), None);
    assert_eq!(error_ratio(1, 2), Some(0.5));
}

#[test]
fn fast_burn_needs_both_windows_and_floor() {
    assert!(fast_fires(14.5, 14.5, 0.02));
    assert!(!fast_fires(14.5, 14.5, 0.001));
    assert!(!fast_fires(14.5, 1.0, 0.02));
    assert!(!fast_fires(1.0, 14.5, 0.02));
}

#[test]
fn slow_burn_needs_both_windows_and_floor() {
    assert!(slow_fires(6.1, 6.1, 0.01));
    assert!(!slow_fires(6.1, 5.0, 0.01));
    assert!(!slow_fires(6.1, 6.1, 0.001));
}

#[test]
fn quiet_region_does_not_page_despite_huge_ratio() {
    let ratio = error_ratio(1, 2).expect("valid");
    let burn = burn_rate(ratio, SloId::Create.target()).expect("budget valid");
    assert!(burn > FAST_BURN_THRESHOLD);
    // 2 events in 5 minutes is below the 0.01/s floor.
    assert!(!fast_fires(burn, burn, 2.0 / 300.0));
}

#[test]
fn fast_burn_simulation_pages_and_slow_tickets() {
    // Simulate 7.3% errors on the 99.5% create SLO at healthy volume
    // (14.6x burn, just above the 14.4x fast threshold).
    let counts = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 73,
        valid_5m: 1_000,
        bad_30m: 438,
        valid_30m: 6_000,
        bad_1h: 876,
        valid_1h: 12_000,
        bad_6h: 5_256,
        valid_6h: 72_000,
        bad_30d: 73,
        valid_30d: 1_000,
        valid_rate_5m: 3.33,
        valid_rate_30m: 3.33,
    };
    let eval = evaluate_slo(counts);
    assert!(eval.fast_firing);
    assert!(eval.slow_firing);
    assert!((eval.budget_remaining - 0.0).abs() < 1e-9);
}

#[test]
fn slow_only_simulation_tickets_without_paging() {
    // 3.1% errors on 99.5% is 6.2x: slow fires, fast does not.
    let counts = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 31,
        valid_5m: 1_000,
        bad_30m: 186,
        valid_30m: 6_000,
        bad_1h: 372,
        valid_1h: 12_000,
        bad_6h: 2_232,
        valid_6h: 72_000,
        bad_30d: 31,
        valid_30d: 1_000,
        valid_rate_5m: 3.33,
        valid_rate_30m: 3.33,
    };
    let eval = evaluate_slo(counts);
    assert!(!eval.fast_firing);
    assert!(eval.slow_firing);
}

#[test]
fn healthy_soak_passes_freeze_with_full_budget() {
    let evals: Vec<SloEvaluation> = healthy_counts().into_iter().map(evaluate_slo).collect();
    let freeze = evaluate_freeze(&evals, false, false);
    assert!(freeze.passes);
    assert!((freeze.min_user_budget_remaining - 1.0).abs() < 1e-9);
    assert!(freeze.reasons.is_empty());
}

#[test]
fn freeze_blocks_on_fast_burn_and_stale_telemetry() {
    let evals: Vec<SloEvaluation> = healthy_counts().into_iter().map(evaluate_slo).collect();
    let stale = evaluate_freeze(&evals, true, false);
    assert!(!stale.passes);

    let mut burning = evals;
    burning[0].fast_firing = true;
    let frozen = evaluate_freeze(&burning, false, false);
    assert!(!frozen.passes);
    assert_eq!(frozen.fast_firing, vec!["create".to_string()]);
}

#[test]
fn throughput_healthy_ramp_stays_safe_or_warning() {
    let input = throughput_input(
        ThroughputScenario::RampCreate,
        vec![
            ThroughputObservation::healthy(100),
            ThroughputObservation::healthy(200),
        ],
    );
    let report = analyze_throughput(input);
    assert!(report.knee.is_none());
    assert_eq!(report.proposed_lpop, None);
    assert!(
        report
            .steps
            .iter()
            .all(|s| s.zone != DensityZone::Saturation)
    );
}

#[test]
fn throughput_timeout_instead_of_shed_is_class_a() {
    let mut obs = ThroughputObservation::healthy(500);
    obs.timeouts = 25;
    obs.unavailable_rejects = 100;
    obs.bad = 25;
    obs.valid = 500;
    let report = analyze_throughput(throughput_input(ThroughputScenario::RampApi, vec![obs]));
    assert_eq!(report.knee, Some(500));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.class == FailureClass::A && f.code == "timeout_instead_of_shed")
    );
}

#[test]
fn throughput_stale_series_is_class_a() {
    let mut obs = ThroughputObservation::healthy(300);
    obs.slo_series_fresh = false;
    let report = analyze_throughput(throughput_input(ThroughputScenario::RampPipe, vec![obs]));
    assert_eq!(report.knee, Some(300));
    assert!(report.findings.iter().any(|f| f.code == "telemetry_stale"));
}

#[test]
fn throughput_audit_lag_is_class_a() {
    let mut obs = ThroughputObservation::healthy(300);
    obs.audit_lag_seconds = Some(45.0);
    let report = analyze_throughput(throughput_input(ThroughputScenario::RampPipe, vec![obs]));
    assert!(report.findings.iter().any(|f| f.code == "audit_lag"));
}

#[test]
fn spike_report_marks_shed_not_rate() {
    let report = analyze_throughput(throughput_input(
        ThroughputScenario::SpikeCreate,
        vec![ThroughputObservation::healthy(1_000)],
    ));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "spike_measures_shed_not_rate")
    );
}

#[test]
fn mapping_completeness_covers_full_matrix() {
    let rows = mapping_completeness(&full_matrix_present());
    assert_eq!(rows.len(), 8);
    assert!(rows.iter().all(|row| row.missing.is_empty()));
}

#[test]
fn mapping_completeness_flags_missing_cell_drill() {
    let mut present = full_matrix_present();
    present.retain(|id| id != "S-FAIL-CELL");
    let rows = mapping_completeness(&present);
    let cell = rows
        .iter()
        .find(|row| row.target == "ST-CELL")
        .expect("cell row");
    assert_eq!(cell.missing, vec!["S-FAIL-CELL".to_string()]);
}

#[test]
fn recording_rules_match_deployed_file() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../o11y/rules/pico-recording-rules.yaml"
    );
    let text = std::fs::read_to_string(path).expect("recording rules readable");
    assert_eq!(validate_recording_rules_text(&text), Vec::<String>::new());
}

#[test]
fn recording_rules_reject_stale_error_selector() {
    let bad = "record: pico:slo:bad:rate5m\n  expr: outcome=\"error\"\n";
    assert!(
        validate_recording_rules_text(bad)
            .iter()
            .any(|m| m.contains("stale"))
    );
}

#[test]
fn g14_bundle_p0_sets_no_lpop_and_records_phase() {
    let throughput = analyze_throughput(throughput_input(
        ThroughputScenario::SoakMix,
        vec![ThroughputObservation::healthy(500)],
    ));
    let bundle = build_g14_bundle(G14BundleInput {
        report_id: "g14-p0".into(),
        profile: CandidateProfile::firecracker_lab_dedicated(),
        candidate_revision: "test-rev".into(),
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        scenarios_present: full_matrix_present(),
        slo_counts: healthy_counts(),
        telemetry_stale: false,
        freeze_exception: false,
        throughput_reports: vec![throughput],
        composed_digests: vec!["digest-capacity".into()],
        cost_digest: None,
    });
    assert!(bundle.freeze.passes);
    assert_eq!(bundle.lpop.admitted_api_rps, None);
    assert_eq!(bundle.mapping.len(), 8);
    assert!(
        bundle
            .findings
            .iter()
            .any(|f| f.code == "phase_cannot_set_lpop")
    );
    assert!(!bundle.artifact_digest().is_empty());
    assert!(bundle.to_markdown().contains("G-14 evidence bundle"));
}

#[test]
fn g14_bundle_is_fail_closed_on_fast_burn() {
    let mut counts = healthy_counts();
    counts[0] = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 73,
        valid_5m: 1_000,
        bad_30m: 438,
        valid_30m: 6_000,
        bad_1h: 876,
        valid_1h: 12_000,
        bad_6h: 5_256,
        valid_6h: 72_000,
        bad_30d: 73,
        valid_30d: 1_000,
        valid_rate_5m: 3.33,
        valid_rate_30m: 3.33,
    };
    let bundle = build_g14_bundle(G14BundleInput {
        report_id: "g14-p0-burn".into(),
        profile: CandidateProfile::firecracker_lab_dedicated(),
        candidate_revision: "test-rev".into(),
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        scenarios_present: full_matrix_present(),
        slo_counts: counts,
        telemetry_stale: false,
        freeze_exception: false,
        throughput_reports: vec![],
        composed_digests: vec![],
        cost_digest: None,
    });
    assert!(!bundle.freeze.passes);
    assert!(bundle.findings.iter().any(|f| f.code == "fast_burn_firing"));
}

#[test]
fn candidate_profile_pins_firecracker_lab() {
    let profile = CandidateProfile::firecracker_lab_dedicated();
    assert_eq!(profile.backend, RuntimeType::Firecracker);
    assert_eq!(profile.host_sku, "lab-64vcpu");
    assert_eq!(profile.tenancy, "dedicated");
    assert_eq!(profile.mix_id, MIX_AGENT_V1);
}

#[test]
fn throughput_pressure_bands_mirror_capacity() {
    let mut memory = ThroughputObservation::healthy(200);
    memory.pressure.memory_cgroup = 45.0;
    let saturated = classify_throughput(&memory, ThroughputScenario::RampCreate);
    assert_eq!(saturated.zone, DensityZone::Saturation);
    assert!(
        saturated
            .reasons
            .contains(&ThroughputZoneReason::MemoryPressure)
    );

    let mut cpu = ThroughputObservation::healthy(200);
    cpu.pressure.cpu = 0.95;
    let cpu_saturated = classify_throughput(&cpu, ThroughputScenario::RampCreate);
    assert_eq!(cpu_saturated.zone, DensityZone::Saturation);
    assert!(
        cpu_saturated
            .reasons
            .contains(&ThroughputZoneReason::UtilizationPressure)
    );

    let mut warning = ThroughputObservation::healthy(200);
    warning.pressure.memory_cgroup = 20.0;
    let warned = classify_throughput(&warning, ThroughputScenario::RampCreate);
    assert_eq!(warned.zone, DensityZone::Warning);
    assert!(
        warned
            .reasons
            .contains(&ThroughputZoneReason::MemoryPressure)
    );
}

#[test]
fn throughput_no_valid_events_fails_closed() {
    let obs = ThroughputObservation {
        offered: 100,
        admitted: 100,
        completed: 100,
        unavailable_rejects: 0,
        timeouts: 0,
        excluded_rejects: 0,
        bad: 0,
        valid: 0,
        pressure: ResourcePressureSample::default(),
        safety: SafetyFlags::default(),
        scheduler_placed: true,
        audit_lag_seconds: Some(1.0),
        slo_series_fresh: true,
    };
    let step = classify_throughput(&obs, ThroughputScenario::RampCreate);
    assert_eq!(step.zone, DensityZone::Saturation);
    assert!(step.reasons.contains(&ThroughputZoneReason::NoValidEvents));
    let report = analyze_throughput(throughput_input(ThroughputScenario::RampCreate, vec![obs]));
    assert!(report.findings.iter().any(|f| f.code == "no_valid_events"));
}

#[test]
fn evaluate_slo_without_30d_data_yields_no_budget() {
    let counts = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 0,
        valid_5m: 0,
        bad_30m: 0,
        valid_30m: 0,
        bad_1h: 0,
        valid_1h: 0,
        bad_6h: 0,
        valid_6h: 0,
        bad_30d: 0,
        valid_30d: 0,
        valid_rate_5m: 0.0,
        valid_rate_30m: 0.0,
    };
    let eval = evaluate_slo(counts);
    assert!(!eval.fast_firing);
    assert!(!eval.slow_firing);
    assert_eq!(eval.budget_remaining, 0.0);
    assert!(eval.exhausted);
}

#[test]
fn freeze_with_no_evaluations_fails_closed() {
    let freeze = evaluate_freeze(&[], false, false);
    assert!(!freeze.passes);
    assert!(!freeze.reasons.is_empty());
}

#[test]
fn freeze_exception_waives_budget_only() {
    // 0.45% errors on the 99.5% create SLO: 10% budget left, no burn alert.
    let counts = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 4,
        valid_5m: 1_000,
        bad_30m: 27,
        valid_30m: 6_000,
        bad_1h: 54,
        valid_1h: 12_000,
        bad_6h: 324,
        valid_6h: 72_000,
        bad_30d: 45,
        valid_30d: 10_000,
        valid_rate_5m: 3.33,
        valid_rate_30m: 3.33,
    };
    let eval = evaluate_slo(counts);
    assert!((eval.budget_remaining - 0.1).abs() < 1e-9);
    assert!(!eval.fast_firing && !eval.exhausted);
    let mut evals: Vec<SloEvaluation> = healthy_counts().into_iter().map(evaluate_slo).collect();
    evals[0] = eval;
    let waived = evaluate_freeze(&evals, false, true);
    assert!(waived.passes);
    assert!(waived.reasons.is_empty());
    assert!(!evaluate_freeze(&evals, false, false).passes);

    let mut burning: Vec<SloEvaluation> = healthy_counts().into_iter().map(evaluate_slo).collect();
    burning[0].fast_firing = true;
    assert!(!evaluate_freeze(&burning, false, true).passes);
}

#[test]
fn bundle_digest_is_reproducible() {
    let throughput = analyze_throughput(throughput_input(
        ThroughputScenario::SoakMix,
        vec![ThroughputObservation::healthy(500)],
    ));
    let bundle = build_g14_bundle(G14BundleInput {
        report_id: "g14-p0".into(),
        profile: CandidateProfile::firecracker_lab_dedicated(),
        candidate_revision: "test-rev".into(),
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        scenarios_present: full_matrix_present(),
        slo_counts: healthy_counts(),
        telemetry_stale: false,
        freeze_exception: false,
        throughput_reports: vec![throughput],
        composed_digests: vec!["digest-capacity".into()],
        cost_digest: None,
    });
    assert_eq!(bundle.artifact_digest(), bundle.lpop.artifact_digest);
}

#[test]
fn bundle_records_exhausted_budget_without_fast_burn() {
    // Past incident: 30d budget spent while current windows are healthy.
    let mut counts = healthy_counts();
    counts[0] = SloWindowCounts {
        slo: SloId::Create,
        bad_5m: 0,
        valid_5m: 1_000,
        bad_30m: 0,
        valid_30m: 6_000,
        bad_1h: 0,
        valid_1h: 12_000,
        bad_6h: 0,
        valid_6h: 72_000,
        bad_30d: 60,
        valid_30d: 1_000,
        valid_rate_5m: 3.33,
        valid_rate_30m: 3.33,
    };
    let bundle = build_g14_bundle(G14BundleInput {
        report_id: "g14-p0-exhausted".into(),
        profile: CandidateProfile::firecracker_lab_dedicated(),
        candidate_revision: "test-rev".into(),
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        scenarios_present: full_matrix_present(),
        slo_counts: counts,
        telemetry_stale: false,
        freeze_exception: false,
        throughput_reports: vec![],
        composed_digests: vec![],
        cost_digest: None,
    });
    assert!(!bundle.freeze.passes);
    assert!(bundle.findings.iter().any(|f| f.code == "budget_exhausted"));
    assert!(!bundle.findings.iter().any(|f| f.code == "fast_burn_firing"));
}
