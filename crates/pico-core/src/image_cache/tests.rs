use super::*;
use crate::capacity::{CapacityScope, DensityZone, FailureClass, ValidationPhase};
use crate::runtime::RuntimeType;

fn input(
    scenario: ImageCacheScenario,
    steps: Vec<ImageCacheObservation>,
    advertised: u64,
) -> ImageCacheInput {
    ImageCacheInput {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        advertised_cache_bytes: advertised,
        steps,
        thresholds: ImageCacheThresholds::default(),
        observability: ImageCacheObservabilityEvidence::p0_required(),
        live_observability: false,
        image_path_live: false,
        overlay_path_live: false,
    }
}

fn has_code(report: &ImageCacheReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

fn class_of(report: &ImageCacheReport, code: &str) -> Option<FailureClass> {
    report
        .findings
        .iter()
        .find(|f| f.code == code)
        .map(|f| f.class)
}

fn advertised() -> u64 {
    lab_cache_size_recommendation().host_local_bytes
}

#[test]
fn classify_warm_safe_when_hit_and_slo_hold() {
    let step = classify_image_cache(
        &ImageCacheObservation::warm_at_concurrent(2),
        ImageCacheScenario::Warm,
        &ImageCacheThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Safe);
    assert_eq!(step.reasons, vec![ImageCacheZoneReason::WithinEnvelope]);
}

#[test]
fn classify_cold_miss_stays_safe() {
    let step = classify_image_cache(
        &ImageCacheObservation::cold_at_concurrent(2),
        ImageCacheScenario::Cold,
        &ImageCacheThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Safe);
    assert!(!step.reasons.contains(&ImageCacheZoneReason::CacheMiss));
}

#[test]
fn classify_warm_miss_is_warning() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(2);
    obs.cache_hits = 0;
    obs.cache_misses = 2;
    obs.cache_result = ImageCacheResult::Miss;
    let step = classify_image_cache(
        &obs,
        ImageCacheScenario::Warm,
        &ImageCacheThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Warning);
    assert!(step.reasons.contains(&ImageCacheZoneReason::CacheMiss));
}

#[test]
fn cold_versus_warm_latency_by_profile_and_host() {
    let mut cold = ImageCacheObservation::cold_at_concurrent(2);
    cold.image_profile = ImageProfile::Agent;
    let mut warm = ImageCacheObservation::warm_at_concurrent(2);
    warm.image_profile = ImageProfile::Agent;
    let cold_report =
        analyze_image_cache(input(ImageCacheScenario::Cold, vec![cold], advertised()));
    let warm_report =
        analyze_image_cache(input(ImageCacheScenario::Warm, vec![warm], advertised()));
    let cold_slice = &cold_report.latency_by_profile_and_tier[0];
    let warm_slice = &warm_report.latency_by_profile_and_tier[0];
    assert_eq!(cold_slice.host_sku, "lab-64vcpu");
    assert_eq!(warm_slice.host_sku, "lab-64vcpu");
    assert_eq!(cold_slice.image_profile, ImageProfile::Agent);
    assert_eq!(cold_slice.cache_result, ImageCacheResult::Miss);
    assert_eq!(warm_slice.cache_result, ImageCacheResult::Hit);
    assert!(cold_slice.prepare_p50_seconds > warm_slice.prepare_p50_seconds);
    assert_eq!(cold_slice.verify_p99_seconds, warm_slice.verify_p99_seconds);
}

#[test]
fn cell_cache_miss_is_warning_on_warm() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(4);
    obs.cache_tier = CacheTier::CellCache;
    obs.cache_hits = 1;
    obs.cache_misses = 3;
    obs.cache_result = ImageCacheResult::Miss;
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Warning);
    assert_eq!(report.steps[0].observation.cache_tier, CacheTier::CellCache);
}

#[test]
fn concurrent_duplicate_fetch_is_class_b() {
    let mut obs = ImageCacheObservation::cold_at_concurrent(8);
    obs.duplicate_fetches = 7;
    let report = analyze_image_cache(input(ImageCacheScenario::Cold, vec![obs], advertised()));
    assert_eq!(
        class_of(&report, "prepare_not_single_flight"),
        Some(FailureClass::B)
    );
}

#[test]
fn thrash_eviction_without_corruption_stays_warning() {
    let fit = ImageCacheObservation::thrash_at_working_set(8, 8);
    let overflow = ImageCacheObservation::thrash_at_working_set(16, 8);
    let report = analyze_image_cache(input(
        ImageCacheScenario::Thrash,
        vec![fit, overflow],
        advertised(),
    ));
    assert_eq!(report.axis, ImageCacheAxis::WorkingSetImages);
    assert_eq!(report.cache.evictions, 8);
    let overflow_step = report
        .steps
        .iter()
        .find(|s| s.observation.working_set_images == 16)
        .expect("overflow");
    assert_eq!(overflow_step.zone, DensityZone::Warning);
    assert!(!has_code(&report, "thrash_broke_supply_chain"));
    assert_eq!(report.sizing.working_set_images, 8);
    assert_eq!(report.calibration.measured_working_set_images, Some(8));
    assert!(report.calibration.within_band);
    assert!(!has_code(&report, "cache_under_sized"));
}

#[test]
fn thrash_wrong_digest_is_class_a() {
    let mut overflow = ImageCacheObservation::thrash_at_working_set(16, 8);
    overflow.wrong_digest_served = 1;
    overflow.safety.digest_held = false;
    let report = analyze_image_cache(input(
        ImageCacheScenario::Thrash,
        vec![overflow],
        advertised(),
    ));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
    assert_eq!(
        class_of(&report, "wrong_digest_served"),
        Some(FailureClass::A)
    );
    assert!(has_code(&report, "thrash_broke_supply_chain"));
}

#[test]
fn unsigned_and_unpinned_are_class_a() {
    let mut unsigned = ImageCacheObservation::warm_at_concurrent(1);
    unsigned.unsigned_served = 1;
    let mut unpinned = ImageCacheObservation::cold_at_concurrent(1);
    unpinned.unpinned_served = 1;
    unpinned.safety.pinned = false;
    let report = analyze_image_cache(input(
        ImageCacheScenario::Cold,
        vec![unsigned, unpinned],
        advertised(),
    ));
    assert_eq!(
        class_of(&report, "unsigned_image_served"),
        Some(FailureClass::A)
    );
    assert_eq!(
        class_of(&report, "unpinned_image_served"),
        Some(FailureClass::A)
    );
}

#[test]
fn fail_closed_verify_deny_is_not_unsigned_served() {
    let mut obs = ImageCacheObservation::cold_at_concurrent(2);
    obs.completed = 0;
    obs.boot_reason_image = 2;
    obs.safety.signature_verified = false;
    let report = analyze_image_cache(input(ImageCacheScenario::Cold, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Safe);
    assert!(!has_code(&report, "unsigned_image_served"));
    assert!(!has_code(&report, "unverified_image_served"));
}

#[test]
fn unverified_served_is_not_labeled_unsigned() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(1);
    obs.unverified_served = 1;
    obs.safety.signature_verified = false;
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(
        class_of(&report, "unverified_image_served"),
        Some(FailureClass::A)
    );
    assert!(!has_code(&report, "unsigned_image_served"));
}

#[test]
fn verification_skip_on_hit_is_class_a() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(4);
    obs.safety.verification_skipped = true;
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
    assert_eq!(
        class_of(&report, "verification_skipped"),
        Some(FailureClass::A)
    );
}

#[test]
fn verify_overhead_is_measured_and_diagnostic() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(2);
    obs.verify_p99_seconds = Some(0.2);
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Warning);
    assert_eq!(
        class_of(&report, "verify_p99_diagnostic"),
        Some(FailureClass::B)
    );
    assert_eq!(
        report.latency_by_profile_and_tier[0].verify_p99_seconds,
        Some(0.2)
    );
}

#[test]
fn overlay_latency_is_measured_and_diagnostic() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(2);
    obs.overlay_p99_seconds = Some(0.8);
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Warning);
    assert_eq!(
        class_of(&report, "overlay_p99_diagnostic"),
        Some(FailureClass::B)
    );
}

#[test]
fn disk_pressure_saturates() {
    let mut obs = ImageCacheObservation::warm_at_concurrent(4);
    obs.pressure.disk = 0.95;
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![obs], advertised()));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
}

#[test]
fn warm_hit_rate_finding_uses_host_local() {
    let mut host_local = ImageCacheObservation::warm_at_concurrent(10);
    host_local.cache_hits = 8;
    host_local.cache_misses = 2;
    let mut cell = ImageCacheObservation::warm_at_concurrent(20);
    cell.cache_tier = CacheTier::CellCache;
    cell.cache_hits = 20;
    cell.cache_misses = 0;
    let mixed = analyze_image_cache(input(
        ImageCacheScenario::Warm,
        vec![host_local, cell],
        advertised(),
    ));
    assert_eq!(
        class_of(&mixed, "warm_cache_hit_rate_low"),
        Some(FailureClass::B)
    );

    let warm = analyze_image_cache(input(
        ImageCacheScenario::Warm,
        vec![ImageCacheObservation::warm_at_concurrent(10)],
        advertised(),
    ));
    assert!(!has_code(&warm, "warm_cache_hit_rate_low"));
    assert_eq!(
        warm.sizing.working_set_images,
        lab_host_local_working_set_images()
    );
    assert!(warm.calibration.measured_working_set_images.is_none());
    assert!(!has_code(&warm, "cache_over_sized"));
}

#[test]
fn recommended_sizing_uses_working_set_and_headroom() {
    let obs = ImageCacheObservation::thrash_at_working_set(8, 8);
    let report = analyze_image_cache(input(ImageCacheScenario::Thrash, vec![obs], advertised()));
    assert_eq!(report.sizing.working_set_images, 8);
    assert_eq!(
        report.sizing.host_local_bytes,
        recommend_cache_bytes(8, lab_typical_image_bytes(), 0.25)
    );
    assert_eq!(
        report.sizing.cell_cache_bytes,
        recommend_cache_bytes(32, lab_typical_image_bytes(), 0.25)
    );
    assert!(report.calibration.within_band);
}

#[test]
fn undersized_cache_is_class_a() {
    let obs = ImageCacheObservation::thrash_at_working_set(8, 8);
    let report = analyze_image_cache(input(ImageCacheScenario::Thrash, vec![obs], 1024));
    assert_eq!(
        class_of(&report, "cache_under_sized"),
        Some(FailureClass::A)
    );
}

#[test]
fn lpop_cap_is_warning_max_not_knee() {
    let mut steps = vec![ImageCacheObservation::warm_at_concurrent(2)];
    let mut warning = ImageCacheObservation::warm_at_concurrent(4);
    warning.scheduler_should_throttle = true;
    steps.push(warning);
    let mut sat = ImageCacheObservation::warm_at_concurrent(8);
    sat.boot_error_ratio = 0.02;
    steps.push(sat);

    let mut cfg = input(ImageCacheScenario::Warm, steps, advertised());
    cfg.phase = ValidationPhase::P2;
    let report = analyze_image_cache(cfg);
    assert_eq!(report.proposed_lpop, Some(4));
    assert_eq!(report.knee, Some(8));
    assert_ne!(report.proposed_lpop, report.knee);
}

#[test]
fn follow_up_bottlenecks_are_attached() {
    let report = analyze_image_cache(input(
        ImageCacheScenario::Warm,
        vec![ImageCacheObservation::warm_at_concurrent(1)],
        advertised(),
    ));
    assert_eq!(
        class_of(&report, "image_path_not_live"),
        Some(FailureClass::C)
    );
    assert_eq!(
        class_of(&report, "overlay_path_not_live"),
        Some(FailureClass::C)
    );
    assert_eq!(
        class_of(&report, "harness_not_driving_live"),
        Some(FailureClass::C)
    );
    assert_eq!(
        class_of(&report, "image_cache_result_labels_missing"),
        Some(FailureClass::C)
    );
    assert_eq!(
        report
            .findings
            .iter()
            .find(|f| f.code == "image_path_not_live")
            .and_then(|f| f.follow_up_issue.as_deref()),
        Some("BSD-184")
    );
}

#[test]
fn observability_incomplete_is_class_b() {
    let mut cfg = input(
        ImageCacheScenario::Warm,
        vec![ImageCacheObservation::warm_at_concurrent(1)],
        advertised(),
    );
    cfg.observability.alerts.clear();
    let report = analyze_image_cache(cfg);
    assert_eq!(
        class_of(&report, "observability_evidence_incomplete"),
        Some(FailureClass::B)
    );
}

#[test]
fn report_json_roundtrip_and_markdown() {
    let report = analyze_image_cache(input(
        ImageCacheScenario::Warm,
        vec![ImageCacheObservation::warm_at_concurrent(2)],
        advertised(),
    ));
    let json = serde_json::to_string(&report).expect("json");
    let parsed: ImageCacheReport = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.scenario, ImageCacheScenario::Warm);
    let md = report.to_markdown();
    assert!(md.contains("S-CACHE-WARM"));
    assert!(md.contains("minimal/host_local/hit"));
    assert!(!report.artifact_digest().is_empty());
}

#[test]
fn empty_series_is_class_a() {
    let report = analyze_image_cache(input(ImageCacheScenario::Warm, vec![], advertised()));
    assert_eq!(class_of(&report, "no_measurements"), Some(FailureClass::A));
}

#[test]
fn compare_profiles_emits_rows() {
    let mut agent = ImageCacheObservation::warm_at_concurrent(2);
    agent.image_profile = ImageProfile::Agent;
    let mut session = ImageCacheObservation::cold_at_concurrent(2);
    session.image_profile = ImageProfile::Session;
    let warm = analyze_image_cache(input(ImageCacheScenario::Warm, vec![agent], advertised()));
    let cold = analyze_image_cache(input(ImageCacheScenario::Cold, vec![session], advertised()));
    let rows = compare_image_profiles(&[warm, cold]);
    assert_eq!(rows.len(), 2);
}

#[test]
fn tenant_layer_leak_is_class_a() {
    let mut obs = ImageCacheObservation::thrash_at_working_set(12, 8);
    obs.tenant_layer_leaks = 1;
    let report = analyze_image_cache(input(ImageCacheScenario::Thrash, vec![obs], advertised()));
    assert_eq!(
        class_of(&report, "tenant_layer_leak"),
        Some(FailureClass::A)
    );
}

#[test]
fn lab_recommendation_is_stable() {
    let rec = lab_cache_size_recommendation();
    assert_eq!(rec.working_set_images, 8);
    assert_eq!(rec.typical_image_bytes, 512 * 1024 * 1024);
    assert_eq!(rec.host_local_bytes, 5 * 1024 * 1024 * 1024);
    assert_eq!(rec.cell_cache_bytes, 20 * 1024 * 1024 * 1024);
}
