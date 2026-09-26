use super::*;
use crate::capacity::{CapacityScope, DensityZone, FailureClass, ValidationPhase};
use crate::cell_scheduler::{
    CellScheduler, CellSchedulerRequest, HostCacheState, HostCapacity, HostHealth, HostInfo,
    HostPressure,
};
use crate::identity::HostId;
use crate::runtime::RuntimeType;
use crate::scheduler::SnapshotTimingHint;

fn input(
    scenario: RestoreScenario,
    steps: Vec<RestoreObservation>,
    advertised: u64,
) -> RestorePressureInput {
    RestorePressureInput {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        advertised_restore_limit: advertised,
        steps,
        thresholds: RestoreThresholds::default(),
        observability: RestoreObservabilityEvidence::p0_required(),
        live_observability: false,
        restore_path_live: false,
    }
}

fn has_code(report: &RestorePressureReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

fn class_of(report: &RestorePressureReport, code: &str) -> Option<FailureClass> {
    report
        .findings
        .iter()
        .find(|f| f.code == code)
        .map(|f| f.class)
}

fn default_host_capacity() -> HostCapacity {
    HostCapacity {
        total_vcpus: 64,
        allocated_vcpus: 0,
        total_memory_mb: 65536,
        allocated_memory_mb: 0,
        total_disk_mb: 500_000,
        used_disk_mb: 0,
        total_network_mbps: 10_000,
        allocated_network_mbps: 0,
        max_process_slots: 100,
        used_process_slots: 0,
    }
}

fn make_host(id: &str) -> HostInfo {
    HostInfo {
        host_id: HostId::from_string(id),
        health: HostHealth::Healthy,
        capacity: default_host_capacity(),
        supported_runtimes: vec![RuntimeType::Firecracker],
        cache: HostCacheState {
            cached_images: vec!["alpine-3.18".into()],
            cached_snapshots: vec!["snp_warm".into()],
        },
        pressure: HostPressure {
            in_flight_creates: 0,
            in_flight_restores: 0,
            max_concurrent_creates: 10,
            max_concurrent_restores: lab_advertised_restore_limit() as u32,
        },
        current_sandboxes: 0,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn restore_request() -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: "sbx_restore".into(),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        runtime: Some(RuntimeType::Firecracker),
        image: "alpine-3.18".into(),
        snapshot_id: Some("snp_warm".into()),
        is_restore: true,
    }
}

#[test]
fn classify_safe_when_pressure_and_slo_hold() {
    let step = classify_restore(
        &RestoreObservation::at_concurrent(2),
        RestoreScenario::RampRestore,
        &RestoreThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Safe);
    assert_eq!(step.reasons, vec![RestoreZoneReason::WithinEnvelope]);
}

#[test]
fn classify_warning_on_cache_miss() {
    let mut obs = RestoreObservation::at_concurrent(2);
    obs.cache_hits = 0;
    obs.cache_misses = 2;
    obs.storage_tier = CacheTier::RegionalObjectStore;
    let step = classify_restore(
        &obs,
        RestoreScenario::RampRestore,
        &RestoreThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Warning);
    assert!(step.reasons.contains(&RestoreZoneReason::CacheMiss));
}

#[test]
fn ramp_identifies_safe_warning_and_saturation_zones() {
    let mut steps = Vec::new();
    for n in [1, 2, 3] {
        steps.push(RestoreObservation::at_concurrent(n));
    }
    let mut warning = RestoreObservation::at_concurrent(4);
    warning.pressure.memory_cgroup = 18.0;
    steps.push(warning);
    let mut sat = RestoreObservation::at_concurrent(6);
    sat.pressure.memory_cgroup = 35.0;
    sat.scheduler_placed = false;
    sat.admitted = 4;
    sat.completed = 4;
    sat.unavailable_rejects = 2;
    steps.push(sat);

    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, steps, 4));
    assert_eq!(report.zones.safe_max, Some(3));
    assert_eq!(report.zones.warning_max, Some(4));
    assert_eq!(report.zones.saturation_onset, Some(6));
    assert_eq!(report.knee, Some(6));
    assert!(report.proposed_lpop.is_none());
    assert_eq!(report.calibration.measured_warning_max, Some(4));
    assert!(report.calibration.within_band);
    assert!(has_code(&report, "phase_cannot_set_lpop"));
}

#[test]
fn lpop_cap_is_warning_max_not_knee() {
    let mut steps = vec![RestoreObservation::at_concurrent(2)];
    let mut warning = RestoreObservation::at_concurrent(4);
    warning.scheduler_should_throttle = true;
    steps.push(warning);
    let mut sat = RestoreObservation::at_concurrent(8);
    sat.restore_error_ratio = 0.02;
    steps.push(sat);

    let mut cfg = input(RestoreScenario::RampRestore, steps, 4);
    cfg.phase = ValidationPhase::P2;
    let report = analyze_restore_pressure(cfg);
    assert_eq!(report.proposed_lpop, Some(4));
    assert_eq!(report.knee, Some(8));
    assert_ne!(report.proposed_lpop, report.knee);
}

#[test]
fn report_includes_latency_by_kind_and_tier() {
    let mut fs_warm = RestoreObservation::at_concurrent(2);
    fs_warm.snapshot_kind = RestoreSnapshotKind::Filesystem;
    fs_warm.storage_tier = CacheTier::HostLocal;
    fs_warm.restore_p50_seconds = Some(0.05);
    fs_warm.restore_p95_seconds = Some(0.09);
    fs_warm.restore_p99_seconds = Some(0.15);

    let mut mem_cell = RestoreObservation::at_concurrent(2);
    mem_cell.snapshot_kind = RestoreSnapshotKind::Memory;
    mem_cell.storage_tier = CacheTier::CellCache;
    mem_cell.restore_p50_seconds = Some(0.12);
    mem_cell.restore_p95_seconds = Some(0.40);
    mem_cell.restore_p99_seconds = Some(0.80);
    mem_cell.cache_hits = 1;
    mem_cell.cache_misses = 1;

    let report = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![fs_warm, mem_cell],
        5,
    ));
    assert_eq!(report.latency_by_kind_and_tier.len(), 2);
    let fs = report
        .latency_by_kind_and_tier
        .iter()
        .find(|s| s.snapshot_kind == RestoreSnapshotKind::Filesystem)
        .expect("filesystem slice");
    assert_eq!(fs.storage_tier, CacheTier::HostLocal);
    assert_eq!(fs.p50_seconds, Some(0.05));
    assert_eq!(fs.p99_seconds, Some(0.15));
    let mem = report
        .latency_by_kind_and_tier
        .iter()
        .find(|s| s.snapshot_kind == RestoreSnapshotKind::Memory)
        .expect("memory slice");
    assert_eq!(mem.storage_tier, CacheTier::CellCache);
    assert_eq!(mem.p99_seconds, Some(0.80));
}

#[test]
fn cache_hit_miss_is_measured() {
    let mut warm = RestoreObservation::at_concurrent(4);
    warm.cache_hits = 4;
    warm.cache_misses = 0;
    let mut cold = RestoreObservation::at_concurrent(4);
    cold.cache_hits = 0;
    cold.cache_misses = 4;
    cold.storage_tier = CacheTier::RegionalObjectStore;
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![warm, cold], 5));
    assert_eq!(report.cache.hits, 4);
    assert_eq!(report.cache.misses, 4);
    assert_eq!(report.cache.hit_rate, Some(0.5));
}

#[test]
fn warm_cache_finding_uses_host_local_hit_rate() {
    let mut host_local = RestoreObservation::at_concurrent(10);
    host_local.cache_hits = 9;
    host_local.cache_misses = 1;
    let mut regional = RestoreObservation::at_concurrent(20);
    regional.cache_hits = 0;
    regional.cache_misses = 20;
    regional.storage_tier = CacheTier::RegionalObjectStore;
    let mixed = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![host_local, regional],
        5,
    ));
    assert!(
        !mixed
            .findings
            .iter()
            .any(|f| f.code == "warm_cache_hit_rate_low")
    );

    let mut cold_local = RestoreObservation::at_concurrent(10);
    cold_local.cache_hits = 1;
    cold_local.cache_misses = 9;
    let mut cell_hits = RestoreObservation::at_concurrent(20);
    cell_hits.cache_hits = 20;
    cell_hits.cache_misses = 0;
    cell_hits.storage_tier = CacheTier::CellCache;
    let host_local_miss = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![cold_local, cell_hits],
        5,
    ));
    assert_eq!(
        class_of(&host_local_miss, "warm_cache_hit_rate_low"),
        Some(FailureClass::B)
    );
}

#[test]
fn warm_versus_cold_cache_keeps_cold_in_warning() {
    let warm = RestoreObservation::at_concurrent(2);
    let mut cold = RestoreObservation::at_concurrent(2);
    cold.cache_hits = 0;
    cold.cache_misses = 2;
    cold.storage_tier = CacheTier::RegionalObjectStore;
    cold.restore_p50_seconds = Some(0.40);
    cold.restore_p99_seconds = Some(0.90);
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![warm, cold], 5));
    let cold_step = report
        .steps
        .iter()
        .find(|s| s.observation.storage_tier == CacheTier::RegionalObjectStore)
        .expect("cold step");
    assert_eq!(cold_step.zone, DensityZone::Warning);
    let warm_step = report
        .steps
        .iter()
        .find(|s| s.observation.storage_tier == CacheTier::HostLocal)
        .expect("warm step");
    assert_eq!(warm_step.zone, DensityZone::Safe);
}

#[test]
fn partial_cleanup_is_class_a() {
    let mut obs = RestoreObservation::at_concurrent(2);
    obs.partial_cleanups = 1;
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![obs], 5));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
    assert_eq!(class_of(&report, "partial_cleanup"), Some(FailureClass::A));
}

#[test]
fn lineage_and_secrets_are_class_a() {
    let mut lineage = RestoreObservation::at_concurrent(2);
    lineage.safety.lineage_held = false;
    let mut secret = RestoreObservation::at_concurrent(2);
    secret.safety.secret_free = false;
    let report = analyze_restore_pressure(input(
        RestoreScenario::SoakRestore,
        vec![lineage, secret],
        5,
    ));
    assert_eq!(class_of(&report, "lineage_mixup"), Some(FailureClass::A));
    assert_eq!(
        class_of(&report, "secret_material_in_artifact"),
        Some(FailureClass::A)
    );
}

#[test]
fn soak_fails_on_snapshot_store_backlog() {
    let mut obs = RestoreObservation::at_concurrent(3);
    obs.pressure.memory_cgroup = 16.0;
    obs.snapshot_store_backlog = 12;
    let report = analyze_restore_pressure(input(RestoreScenario::SoakRestore, vec![obs], 5));
    assert_eq!(
        class_of(&report, "snapshot_store_backlog"),
        Some(FailureClass::A)
    );
    assert!(has_code(&report, "soak_left_warning_zone"));
}

#[test]
fn spike_must_shed_without_timeouts() {
    let mut spike = RestoreObservation::at_concurrent(5);
    spike.restore_rate = 15;
    spike.offered = 15;
    spike.admitted = 5;
    spike.completed = 5;
    spike.unavailable_rejects = 10;
    spike.scheduler_placed = false;
    let report = analyze_restore_pressure(input(RestoreScenario::SpikeRestore, vec![spike], 5));
    assert_eq!(report.axis, RestoreAxis::RestoreRate);
    assert!(!has_code(&report, "spike_timeouts"));
    assert!(!has_code(&report, "spike_did_not_shed"));
}

#[test]
fn spike_timeouts_are_class_a() {
    let mut spike = RestoreObservation::at_concurrent(5);
    spike.restore_rate = 15;
    spike.offered = 15;
    spike.admitted = 5;
    spike.completed = 5;
    spike.unavailable_rejects = 5;
    spike.timeouts = 5;
    spike.scheduler_placed = false;
    let report = analyze_restore_pressure(input(RestoreScenario::SpikeRestore, vec![spike], 5));
    assert_eq!(class_of(&report, "spike_timeouts"), Some(FailureClass::A));
    assert_eq!(
        class_of(&report, "timeout_instead_of_shed"),
        Some(FailureClass::A)
    );
}

#[test]
fn exec_latency_under_restore_is_warning_and_class_b() {
    let mut obs = RestoreObservation::at_concurrent(3);
    obs.exec_p99_seconds = Some(1.5);
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![obs], 5));
    assert_eq!(report.steps[0].zone, DensityZone::Warning);
    assert_eq!(
        class_of(&report, "exec_p99_under_restore"),
        Some(FailureClass::B)
    );
}

#[test]
fn restore_p99_diagnostic_does_not_saturate() {
    let mut obs = RestoreObservation::at_concurrent(3);
    obs.restore_p99_seconds = Some(1.4);
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![obs], 5));
    assert_eq!(report.steps[0].zone, DensityZone::Warning);
    assert_eq!(
        class_of(&report, "restore_p99_diagnostic"),
        Some(FailureClass::B)
    );
}

#[test]
fn lazy_restore_untested_is_class_c() {
    let report = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![RestoreObservation::at_concurrent(2)],
        5,
    ));
    assert_eq!(
        class_of(&report, "lazy_restore_untested"),
        Some(FailureClass::C)
    );
    assert_eq!(
        report
            .findings
            .iter()
            .find(|f| f.code == "lazy_restore_untested")
            .and_then(|f| f.follow_up_issue.as_deref()),
        Some("51")
    );
}

#[test]
fn lazy_restore_series_drops_untested_finding() {
    let mut obs = RestoreObservation::at_concurrent(1);
    obs.snapshot_kind = RestoreSnapshotKind::LazyMemory;
    obs.lazy_pages_faulted = Some(128);
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![obs], 5));
    assert!(!has_code(&report, "lazy_restore_untested"));
}

#[test]
fn follow_up_bottlenecks_are_attached() {
    let report = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![RestoreObservation::at_concurrent(1)],
        5,
    ));
    assert_eq!(
        class_of(&report, "restore_path_not_live"),
        Some(FailureClass::C)
    );
    assert_eq!(
        class_of(&report, "harness_not_driving_live"),
        Some(FailureClass::C)
    );
    assert_eq!(
        class_of(&report, "cache_tier_labels_missing"),
        Some(FailureClass::C)
    );
}

#[test]
fn observability_incomplete_is_class_b() {
    let mut cfg = input(
        RestoreScenario::RampRestore,
        vec![RestoreObservation::at_concurrent(1)],
        5,
    );
    cfg.observability.alerts.clear();
    let report = analyze_restore_pressure(cfg);
    assert_eq!(
        class_of(&report, "observability_evidence_incomplete"),
        Some(FailureClass::B)
    );
}

#[test]
fn backend_comparison_reports_per_runtime() {
    let fc = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![
            RestoreObservation::at_concurrent(2),
            RestoreObservation::at_concurrent(4),
        ],
        5,
    ));
    let mut gvisor_input = input(
        RestoreScenario::RampRestore,
        {
            let mut warning = RestoreObservation::at_concurrent(2);
            warning.pressure.memory_cgroup = 16.0;
            let mut sat = RestoreObservation::at_concurrent(3);
            sat.pressure.memory_cgroup = 40.0;
            vec![RestoreObservation::at_concurrent(1), warning, sat]
        },
        5,
    );
    gvisor_input.backend = RuntimeType::GVisor;
    let gvisor = analyze_restore_pressure(gvisor_input);
    let rows = compare_restore_backends(&[fc, gvisor]);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].backend, RuntimeType::Firecracker);
    assert_eq!(rows[0].warning_max, Some(4));
    assert_eq!(rows[1].backend, RuntimeType::GVisor);
    assert_eq!(rows[1].warning_max, Some(2));
}

#[test]
fn report_json_roundtrip_and_markdown() {
    let report = analyze_restore_pressure(input(
        RestoreScenario::RampRestore,
        vec![RestoreObservation::at_concurrent(2)],
        5,
    ));
    let json = serde_json::to_string(&report).expect("json");
    let parsed: RestorePressureReport = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.scenario, RestoreScenario::RampRestore);
    let md = report.to_markdown();
    assert!(md.contains("S-RAMP-RESTORE"));
    assert!(md.contains("filesystem/host_local"));
    assert!(!report.artifact_digest().is_empty());
}

#[test]
fn scheduler_restore_ramp_matches_advertised_limit() {
    let scheduler = CellScheduler::new();
    let req = restore_request();
    let mut host = make_host("hst_1");
    let advertised = u64::from(host.pressure.max_concurrent_restores);
    assert_eq!(advertised, lab_advertised_restore_limit());

    let mut measured = 0;
    let mut steps = Vec::new();
    loop {
        match scheduler.schedule(&req, std::slice::from_ref(&host)) {
            Ok(response) => {
                assert!(response.placed);
                host.pressure.in_flight_restores += 1;
                measured += 1;
                let mut obs = RestoreObservation::at_concurrent(measured);
                obs.scheduler_should_throttle = response.backpressure.should_throttle;
                steps.push(obs);
            }
            Err(_) => {
                let mut obs = RestoreObservation::at_concurrent(measured + 1);
                obs.offered = measured + 1;
                obs.admitted = measured;
                obs.completed = measured;
                obs.unavailable_rejects = 1;
                obs.scheduler_placed = false;
                steps.push(obs);
                break;
            }
        }
    }

    assert_eq!(measured, advertised);
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, steps, advertised));
    assert_eq!(report.zones.saturation_onset, Some(advertised + 1));
    assert_eq!(report.calibration.class, None);
    assert!(report.calibration.within_band);
}

#[test]
fn empty_series_is_class_a() {
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![], 5));
    assert_eq!(class_of(&report, "no_measurements"), Some(FailureClass::A));
}

#[test]
fn audit_missing_on_restore_is_class_b() {
    let mut obs = RestoreObservation::at_concurrent(2);
    obs.audit_events = 0;
    let report = analyze_restore_pressure(input(RestoreScenario::RampRestore, vec![obs], 5));
    assert_eq!(
        class_of(&report, "audit_missing_on_restore"),
        Some(FailureClass::B)
    );
}
