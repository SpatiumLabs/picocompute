use super::*;
use crate::cell_scheduler::{
    CellScheduler, CellSchedulerRequest, HostCacheState, HostCapacity, HostHealth, HostInfo,
    HostPressure,
};
use crate::identity::HostId;
use crate::scheduler::{CellCapacity, SnapshotTimingHint};

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
            cached_snapshots: vec![],
        },
        pressure: HostPressure {
            in_flight_creates: 0,
            in_flight_restores: 0,
            max_concurrent_creates: 10,
            max_concurrent_restores: 5,
        },
        current_sandboxes: 0,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn occupy(host: &mut HostInfo, req: &CellSchedulerRequest) {
    host.capacity.allocated_vcpus += u64::from(req.vcpus);
    host.capacity.allocated_memory_mb += req.memory_mb;
    host.capacity.used_disk_mb += req.disk_mb;
    host.capacity.used_process_slots += 1;
    host.current_sandboxes += 1;
}

fn request() -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: "sbx_cap".into(),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        runtime: Some(RuntimeType::Firecracker),
        image: "alpine-3.18".into(),
        snapshot_id: None,
        is_restore: false,
    }
}

fn input(
    scenario: CapacityScenario,
    steps: Vec<DensityObservation>,
    advertised: u64,
) -> ActiveCapacityInput {
    ActiveCapacityInput {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Host,
        backend: RuntimeType::Firecracker,
        host_sku: "lab-64vcpu".into(),
        packing_shape: SandboxPackingShape::platform_default(),
        advertised_limit: advertised,
        binding: Some(BindingResource::Vcpu),
        steps,
        thresholds: DensityThresholds::default(),
    }
}

#[test]
fn packing_is_min_of_vcpu_memory_disk_and_slots() {
    let cap = default_host_capacity();
    let shape = SandboxPackingShape::platform_default();
    let (limit, binding) = advertised_host_limit(&cap, shape);
    assert_eq!(limit, 32);
    assert_eq!(binding, BindingResource::Vcpu);
    assert_eq!(
        cap.remaining_fit_count(shape.vcpus, shape.memory_mb, shape.disk_mb),
        32
    );
}

#[test]
fn process_slots_bind_when_tighter_than_vcpu() {
    let mut cap = default_host_capacity();
    cap.max_process_slots = 10;
    let (limit, binding) = advertised_host_limit(&cap, SandboxPackingShape::platform_default());
    assert_eq!(limit, 10);
    assert_eq!(binding, BindingResource::ProcessSlot);
}

#[test]
fn cell_packing_uses_sandbox_slots_when_tighter() {
    let cell = CellCapacity {
        total_vcpus: 128,
        allocated_vcpus: 0,
        total_memory_mb: 131_072,
        allocated_memory_mb: 0,
        max_sandboxes: 20,
        current_sandboxes: 0,
    };
    let (limit, binding) = advertised_cell_limit(&cell, SandboxPackingShape::platform_default());
    assert_eq!(limit, 20);
    assert_eq!(binding, BindingResource::SandboxSlot);
}

#[test]
fn classify_safe_when_pressure_and_slo_hold() {
    let step = classify_density(
        &DensityObservation::at_active(8),
        CapacityScenario::RampActive,
        &DensityThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Safe);
    assert_eq!(step.reasons, vec![ZoneReason::WithinEnvelope]);
}

#[test]
fn classify_warning_at_memory_pressure_15() {
    let mut obs = DensityObservation::at_active(16);
    obs.pressure.memory_cgroup = 15.0;
    let step = classify_density(
        &obs,
        CapacityScenario::RampActive,
        &DensityThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Warning);
    assert!(step.reasons.contains(&ZoneReason::MemoryPressure));
}

#[test]
fn classify_saturation_at_memory_pressure_30() {
    let mut obs = DensityObservation::at_active(24);
    obs.pressure.memory_cgroup = 30.0;
    let step = classify_density(
        &obs,
        CapacityScenario::RampActive,
        &DensityThresholds::default(),
    );
    assert_eq!(step.zone, DensityZone::Saturation);
}

#[test]
fn isolation_break_is_class_a_saturation() {
    let mut obs = DensityObservation::at_active(4);
    obs.safety.isolation_held = false;
    let report = analyze_active_capacity(input(CapacityScenario::RampActive, vec![obs], 32));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.class == FailureClass::A && f.code == "isolation_broken")
    );
}

#[test]
fn ramp_identifies_safe_warning_and_saturation_zones() {
    let mut steps = Vec::new();
    for n in [4, 8, 12] {
        steps.push(DensityObservation::at_active(n));
    }
    let mut warning = DensityObservation::at_active(16);
    warning.pressure.memory_cgroup = 18.0;
    steps.push(warning);
    let mut sat = DensityObservation::at_active(24);
    sat.pressure.memory_cgroup = 35.0;
    sat.scheduler_placed = false;
    sat.admitted = 16;
    sat.completed = 16;
    sat.unavailable_rejects = 8;
    steps.push(sat);

    let report = analyze_active_capacity(input(CapacityScenario::RampActive, steps, 16));
    assert_eq!(report.zones.safe_max, Some(12));
    assert_eq!(report.zones.warning_max, Some(16));
    assert_eq!(report.zones.saturation_onset, Some(24));
    assert_eq!(report.knee, Some(24));
    assert!(report.proposed_lpop.is_none());
    assert_eq!(report.calibration.measured_warning_max, Some(16));
    assert!(report.calibration.within_band);
}

#[test]
fn lpop_cap_is_warning_max_not_knee() {
    let mut steps = vec![DensityObservation::at_active(8)];
    let mut warning = DensityObservation::at_active(12);
    warning.scheduler_should_throttle = true;
    steps.push(warning);
    let mut sat = DensityObservation::at_active(20);
    sat.exec_error_ratio = 0.02;
    steps.push(sat);

    let mut cfg = input(CapacityScenario::RampActive, steps, 12);
    cfg.phase = ValidationPhase::P2;
    let report = analyze_active_capacity(cfg);
    assert_eq!(report.proposed_lpop, Some(12));
    assert_eq!(report.knee, Some(20));
    assert_ne!(report.proposed_lpop, report.knee);
}

#[test]
fn scheduler_over_advertise_is_class_a() {
    let mut warning = DensityObservation::at_active(10);
    warning.pressure.memory_cgroup = 16.0;
    let mut sat = DensityObservation::at_active(12);
    sat.pressure.memory_cgroup = 40.0;
    let report = analyze_active_capacity(input(
        CapacityScenario::RampActive,
        vec![DensityObservation::at_active(8), warning, sat],
        32,
    ));
    assert!(!report.calibration.within_band);
    assert_eq!(report.calibration.class, Some(FailureClass::A));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "scheduler_over_advertises")
    );
}

#[test]
fn scheduler_under_advertise_is_class_b() {
    let mut sat = DensityObservation::at_active(32);
    sat.pressure.memory_cgroup = 40.0;
    let report = analyze_active_capacity(input(
        CapacityScenario::RampActive,
        vec![
            DensityObservation::at_active(8),
            DensityObservation::at_active(16),
            DensityObservation::at_active(24),
            sat,
        ],
        8,
    ));
    assert_eq!(report.calibration.class, Some(FailureClass::B));
    assert_eq!(report.calibration.measured_warning_max, Some(24));
}

#[test]
fn soak_passes_at_warning_density_without_leaks() {
    let mut steps = Vec::new();
    for _ in 0..5 {
        let mut obs = DensityObservation::at_active(16);
        obs.pressure.memory_cgroup = 16.0;
        obs.safety.heartbeat_fresh = true;
        steps.push(obs);
    }
    let report = analyze_active_capacity(input(CapacityScenario::SoakActive, steps, 16));
    assert!(report.steps.iter().all(|s| s.zone == DensityZone::Warning));
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == "soak_left_warning_zone" || f.code == "resource_leak")
    );
}

#[test]
fn soak_fails_on_fd_leak_and_stale_heartbeat() {
    let mut leak = DensityObservation::at_active(16);
    leak.pressure.memory_cgroup = 16.0;
    leak.safety.leak_detected = true;
    let mut stale = DensityObservation::at_active(16);
    stale.pressure.memory_cgroup = 16.0;
    stale.safety.heartbeat_fresh = false;
    let report =
        analyze_active_capacity(input(CapacityScenario::SoakActive, vec![leak, stale], 16));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "resource_leak" && f.class == FailureClass::A)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "heartbeat_stale" && f.class == FailureClass::A)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "soak_left_warning_zone")
    );
}

#[test]
fn exec_latency_under_density_is_warning_and_class_b() {
    let mut steps = Vec::new();
    for (n, p99) in [(4, 0.04), (8, 0.08), (16, 1.5)] {
        let mut obs = DensityObservation::at_active(n);
        obs.concurrent_execs = 4;
        obs.exec_p99_seconds = Some(p99);
        steps.push(obs);
    }
    let report = analyze_active_capacity(input(CapacityScenario::RampActive, steps, 16));
    assert_eq!(report.zones.safe_max, Some(8));
    assert_eq!(report.zones.warning_max, Some(16));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.class == FailureClass::B && f.code == "exec_p99_diagnostic")
    );
}

#[test]
fn ramp_exec_zones_use_concurrency_axis() {
    let mut steps = Vec::new();
    for conc in [1, 4, 8, 32] {
        let mut obs = DensityObservation::at_active(16);
        obs.concurrent_execs = conc;
        obs.exec_error_ratio = if conc >= 32 { 0.02 } else { 0.0 };
        steps.push(obs);
    }
    let report = analyze_active_capacity(input(CapacityScenario::RampExec, steps, 16));
    assert_eq!(report.axis, DensityAxis::ExecConcurrency);
    assert_eq!(report.zones.safe_max, Some(8));
    assert_eq!(report.zones.saturation_onset, Some(32));
    assert!(report.calibration.measured_warning_max.is_none());
    assert_eq!(report.calibration.class, None);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == "scheduler_over_advertises")
    );
}

#[test]
fn incomplete_safe_ramp_does_not_over_advertise() {
    let report = analyze_active_capacity(input(
        CapacityScenario::RampActive,
        vec![
            DensityObservation::at_active(4),
            DensityObservation::at_active(8),
        ],
        32,
    ));
    assert_eq!(report.zones.safe_max, Some(8));
    assert!(report.calibration.measured_warning_max.is_none());
    assert_eq!(report.calibration.class, Some(FailureClass::C));
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == "scheduler_over_advertises")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "scheduler_unmeasured")
    );
}

#[test]
fn later_safe_sample_does_not_raise_lpop_cap() {
    let mut warning = DensityObservation::at_active(12);
    warning.pressure.memory_cgroup = 16.0;
    let later_safe = DensityObservation::at_active(20);
    let mut sat = DensityObservation::at_active(24);
    sat.pressure.memory_cgroup = 40.0;
    let mut cfg = input(
        CapacityScenario::RampActive,
        vec![DensityObservation::at_active(8), warning, later_safe, sat],
        12,
    );
    cfg.phase = ValidationPhase::P2;
    let report = analyze_active_capacity(cfg);
    assert_eq!(report.zones.safe_max, Some(8));
    assert_eq!(report.zones.warning_max, Some(12));
    assert_eq!(report.proposed_lpop, Some(12));
}

#[test]
fn same_axis_value_prefers_worst_zone() {
    let mut warning = DensityObservation::at_active(16);
    warning.pressure.memory_cgroup = 16.0;
    let report = analyze_active_capacity(input(
        CapacityScenario::SoakActive,
        vec![DensityObservation::at_active(16), warning],
        16,
    ));
    assert_eq!(report.zones.safe_max, None);
    assert_eq!(report.zones.warning_max, Some(16));
}

#[test]
fn noisy_neighbor_dedicated_tenancy_rejects_cross_tenant() {
    let mut obs = DensityObservation::at_active(8);
    obs.safety.dedicated_tenancy = true;
    obs.safety.cross_tenant_placement = true;
    let report = analyze_active_capacity(input(CapacityScenario::Noisy, vec![obs], 8));
    assert_eq!(report.steps[0].zone, DensityZone::Saturation);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "cross_tenant_placement")
    );
}

#[test]
fn noisy_neighbor_shared_tenancy_keeps_slo_in_envelope() {
    let mut obs = DensityObservation::at_active(8);
    obs.safety.dedicated_tenancy = false;
    obs.safety.cross_tenant_placement = true;
    obs.exec_error_ratio = 0.0;
    let report = analyze_active_capacity(input(CapacityScenario::Noisy, vec![obs], 8));
    assert_eq!(report.steps[0].zone, DensityZone::Safe);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == "cross_tenant_placement")
    );
}

#[test]
fn backend_comparison_reports_per_runtime() {
    let fc = analyze_active_capacity(input(
        CapacityScenario::RampActive,
        vec![
            DensityObservation::at_active(8),
            DensityObservation::at_active(16),
        ],
        16,
    ));
    let mut gvisor_input = input(
        CapacityScenario::RampActive,
        {
            let mut warning = DensityObservation::at_active(8);
            warning.pressure.memory_cgroup = 16.0;
            let mut sat = DensityObservation::at_active(12);
            sat.pressure.memory_cgroup = 40.0;
            vec![DensityObservation::at_active(4), warning, sat]
        },
        16,
    );
    gvisor_input.backend = RuntimeType::GVisor;
    let gvisor = analyze_active_capacity(gvisor_input);
    let rows = compare_backends(&[fc, gvisor]);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].backend, RuntimeType::Firecracker);
    assert_eq!(rows[0].warning_max, Some(16));
    assert_eq!(rows[1].backend, RuntimeType::GVisor);
    assert_eq!(rows[1].warning_max, Some(8));
}

#[test]
fn report_json_roundtrip_and_markdown() {
    let report = analyze_active_capacity(input(
        CapacityScenario::RampActive,
        vec![DensityObservation::at_active(4)],
        32,
    ));
    let json = serde_json::to_string(&report).expect("json");
    let parsed: ActiveCapacityReport = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.scenario, CapacityScenario::RampActive);
    let md = report.to_markdown();
    assert!(md.contains("S-RAMP-ACTIVE"));
    assert!(!report.artifact_digest().is_empty());
}

#[test]
fn scheduler_ramp_matches_advertised_vcpu_packing() {
    let scheduler = CellScheduler::new();
    let req = request();
    let mut host = make_host("hst_1");
    let shape = SandboxPackingShape {
        vcpus: req.vcpus,
        memory_mb: req.memory_mb,
        disk_mb: req.disk_mb,
    };
    let (advertised, binding) = advertised_host_limit(&host.capacity, shape);
    assert_eq!(binding, BindingResource::Vcpu);

    let mut measured = 0;
    let mut steps = Vec::new();
    loop {
        let remaining = host
            .capacity
            .remaining_fit_count(req.vcpus, req.memory_mb, req.disk_mb);
        match scheduler.schedule(&req, std::slice::from_ref(&host)) {
            Ok(response) => {
                assert!(response.placed);
                occupy(&mut host, &req);
                measured += 1;
                let mut obs = DensityObservation::at_active(measured);
                obs.advertised_remaining = remaining.saturating_sub(1);
                obs.scheduler_should_throttle = response.backpressure.should_throttle;
                let occupancy = measured as f64 / advertised as f64;
                obs.pressure.process_slots = occupancy * 0.4;
                obs.pressure.cpu = occupancy * 0.4;
                steps.push(obs);
            }
            Err(_) => {
                let mut obs = DensityObservation::at_active(measured + 1);
                obs.offered = measured + 1;
                obs.admitted = measured;
                obs.completed = measured;
                obs.unavailable_rejects = 1;
                obs.scheduler_placed = false;
                obs.advertised_remaining = remaining;
                steps.push(obs);
                break;
            }
        }
    }

    assert_eq!(measured, advertised);
    let report = analyze_active_capacity(input(CapacityScenario::RampActive, steps, advertised));
    assert_eq!(report.zones.saturation_onset, Some(advertised + 1));
    assert_eq!(report.calibration.class, None);
    assert!(report.calibration.within_band);
}

#[test]
fn empty_series_is_class_a() {
    let report = analyze_active_capacity(input(CapacityScenario::RampActive, vec![], 32));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "no_measurements" && f.class == FailureClass::A)
    );
}
