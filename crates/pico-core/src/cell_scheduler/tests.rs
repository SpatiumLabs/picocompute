use super::*;
use crate::identity::HostId;
use crate::overcommit::{BaseSharingMode, OvercommitPolicy};

fn make_host(id: &str, health: HostHealth) -> HostInfo {
    HostInfo {
        host_id: HostId::from_string(id),
        health,
        capacity: HostCapacity {
            total_vcpus: 64,
            allocated_vcpus: 16,
            total_memory_mb: 65536,
            allocated_memory_mb: 16384,
            total_disk_mb: 500_000,
            used_disk_mb: 100_000,
            total_network_mbps: 10_000,
            allocated_network_mbps: 2_000,
            max_process_slots: 100,
            used_process_slots: 20,
        },
        supported_runtimes: vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        cache: HostCacheState {
            cached_images: vec!["alpine-3.18".into()],
            cached_snapshots: vec![],
        },
        pressure: HostPressure {
            in_flight_creates: 1,
            in_flight_restores: 0,
            max_concurrent_creates: 10,
            max_concurrent_restores: 5,
        },
        current_sandboxes: 20,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn make_request() -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: "sbx_test".into(),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        runtime: Some(RuntimeType::Firecracker),
        image: "alpine-3.18".into(),
        snapshot_id: None,
        is_restore: false,
        service_class: ServiceClass::LatencySensitive,
    }
}

// ================================================================
// Hard constraint tests
// ================================================================

#[test]
fn schedule_with_no_hosts_returns_error() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let result = scheduler.schedule(&request, &[]);
    assert!(matches!(result, Err(CellSchedulerError::NoHostsAvailable)));
}

#[test]
fn schedule_rejects_unhealthy_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Draining),
        make_host("hst_2", HostHealth::Unavailable),
        make_host("hst_3", HostHealth::DisabledForPlacement),
    ];
    let result = scheduler.schedule(&request, &hosts);
    assert!(result.is_err());
}

#[test]
fn schedule_rejects_insufficient_capacity() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.vcpus = 200;
    request.memory_mb = 500_000;
    request.disk_mb = 1_000_000;
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];
    let result = scheduler.schedule(&request, &hosts);
    assert!(matches!(
        result,
        Err(CellSchedulerError::InsufficientCapacity { .. })
    ));
}

#[test]
fn schedule_rejects_unsupported_runtime() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.runtime = Some(RuntimeType::RemoteFirecracker);
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];
    let result = scheduler.schedule(&request, &hosts);
    assert!(matches!(
        result,
        Err(CellSchedulerError::UnsupportedRuntime { .. })
    ));
}

#[test]
fn schedule_rejects_saturated_create_pressure() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.pressure.in_flight_creates = 10;
    let result = scheduler.schedule(&request, &[host]);
    assert!(matches!(result, Err(CellSchedulerError::PressureSaturated)));
    let err: crate::error::SandboxError = result.unwrap_err().into();
    assert!(matches!(
        err,
        crate::error::SandboxError::PlacementThrottled { .. }
    ));
}

#[test]
fn schedule_rejects_saturated_restore_pressure() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.is_restore = true;
    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.pressure.in_flight_restores = 5;
    let result = scheduler.schedule(&request, &[host]);
    assert!(matches!(result, Err(CellSchedulerError::PressureSaturated)));
}

#[test]
fn schedule_rejects_high_combined_pressure() {
    let scheduler = CellScheduler::new().with_max_pressure(0.5);
    let request = make_request();
    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.pressure.in_flight_creates = 8;
    let result = scheduler.schedule(&request, &[host]);
    assert!(matches!(result, Err(CellSchedulerError::PressureSaturated)));
}

#[test]
fn schedule_accepts_degraded_host() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_host("hst_1", HostHealth::Degraded)];
    let result = scheduler.schedule(&request, &hosts);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.placed);
    assert_eq!(response.reason, HostPlacementReason::OnlyCandidate);
}

#[test]
fn schedule_avoids_draining_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Draining),
        make_host("hst_2", HostHealth::Healthy),
    ];
    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_2");
}

#[test]
fn schedule_avoids_disabled_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::DisabledForPlacement),
        make_host("hst_2", HostHealth::Healthy),
    ];
    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_2");
}

// ================================================================
// Scoring tests
// ================================================================

#[test]
fn schedule_prefers_host_with_more_headroom() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut host_a = make_host("hst_a", HostHealth::Healthy);
    host_a.capacity.allocated_vcpus = 60;
    host_a.capacity.allocated_memory_mb = 60_000;

    let host_b = make_host("hst_b", HostHealth::Healthy);

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn schedule_prefers_host_with_cached_image() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.image = "ubuntu-22.04".into();

    let host_a = make_host("hst_a", HostHealth::Healthy);

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.cache.cached_images.push("ubuntu-22.04".into());

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn schedule_prefers_host_with_cached_snapshot() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.snapshot_id = Some("snp_123".into());

    let host_a = make_host("hst_a", HostHealth::Healthy);

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.cache.cached_snapshots.push("snp_123".into());

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn schedule_prefers_host_with_lower_pressure() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut host_a = make_host("hst_a", HostHealth::Healthy);
    host_a.pressure.in_flight_creates = 8;

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.pressure.in_flight_creates = 0;

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn schedule_prefers_host_with_fewer_sandboxes() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut host_a = make_host("hst_a", HostHealth::Healthy);
    host_a.current_sandboxes = 80;

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.current_sandboxes = 5;

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn schedule_prefers_host_with_more_disk() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut host_a = make_host("hst_a", HostHealth::Healthy);
    host_a.capacity.used_disk_mb = 480_000;

    let host_b = make_host("hst_b", HostHealth::Healthy);

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

// ================================================================
// Tie-breaking tests
// ================================================================

#[test]
fn schedule_breaks_ties_deterministically_by_host_id() {
    // Two fresh instances see the same snapshot with no overlay history, so
    // the tie-break must not depend on input order. (Consecutive decisions
    // on one instance intentionally diverge via the in-flight overlay.)
    let first = CellScheduler::new();
    let second = CellScheduler::new();
    let request = make_request();

    let host_a = make_host("hst_a", HostHealth::Healthy);
    let host_b = make_host("hst_b", HostHealth::Healthy);

    let result1 = first
        .schedule(&request, &[host_a.clone(), host_b.clone()])
        .unwrap();
    let result2 = second.schedule(&request, &[host_b, host_a]).unwrap();

    assert_eq!(result1.host_id, result2.host_id);
}

// ================================================================
// Placement reason tests
// ================================================================

#[test]
fn schedule_returns_only_candidate_when_single_host() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.reason, HostPlacementReason::OnlyCandidate);
}

#[test]
fn schedule_returns_best_score_for_multiple_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Healthy),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(matches!(
        result.reason,
        HostPlacementReason::BestScore | HostPlacementReason::CacheHit
    ));
}

#[test]
fn schedule_returns_cache_hit_when_dominant() {
    let weights = CellScoringWeights {
        capacity_headroom: 0.0,
        cache_locality: 1.0,
        pressure: 0.0,
        sandbox_spread: 0.0,
        disk_availability: 0.0,
    };
    let scheduler = CellScheduler::with_weights(weights);
    let mut request = make_request();
    request.image = "custom-image".into();

    let host_a = make_host("hst_a", HostHealth::Healthy);

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.cache.cached_images.push("custom-image".into());

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.reason, HostPlacementReason::CacheHit);
}

// ================================================================
// Backpressure tests
// ================================================================

#[test]
fn backpressure_signals_no_throttle_when_healthy() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Healthy),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(!result.backpressure.should_throttle);
    assert_eq!(result.backpressure.total_hosts, 2);
    assert_eq!(result.backpressure.eligible_hosts, 2);
}

#[test]
fn backpressure_signals_throttle_when_few_eligible() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut hosts: Vec<HostInfo> = (0..10)
        .map(|i| make_host(&format!("hst_{i}"), HostHealth::Healthy))
        .collect();

    for host in hosts.iter_mut().take(9) {
        host.health = HostHealth::Unavailable;
    }

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(result.backpressure.should_throttle);
    assert_eq!(result.backpressure.eligible_hosts, 1);
    assert_eq!(result.backpressure.total_hosts, 10);
}

// ================================================================
// Score breakdown tests
// ================================================================

#[test]
fn score_breakdown_contains_all_components() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    let breakdown = result.score_breakdown.unwrap();

    let dims: Vec<HostScoreDimension> = breakdown.components.iter().map(|c| c.name).collect();
    assert!(dims.contains(&HostScoreDimension::CapacityHeadroom));
    assert!(dims.contains(&HostScoreDimension::CacheLocality));
    assert!(dims.contains(&HostScoreDimension::Pressure));
    assert!(dims.contains(&HostScoreDimension::SandboxSpread));
    assert!(dims.contains(&HostScoreDimension::DiskAvailability));
}

#[test]
fn score_breakdown_total_matches_sum() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    let breakdown = result.score_breakdown.unwrap();

    let sum: f64 = breakdown.components.iter().map(|c| c.contribution).sum();
    assert!((breakdown.total_score - sum).abs() < f64::EPSILON);
}

#[test]
fn candidate_scores_include_all_eligible_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Healthy),
        make_host("hst_3", HostHealth::Unavailable),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.candidate_scores.len(), 2);
}

// ================================================================
// Rejection tracking tests
// ================================================================

#[test]
fn rejections_include_filtered_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Draining),
        make_host("hst_3", HostHealth::Unavailable),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.rejections.len(), 2);
}

#[test]
fn rejection_counts_aggregate_correctly() {
    let rejections = vec![
        HostRejection {
            host_id: HostId::from_string("hst_1"),
            reason: "host is unavailable".into(),
        },
        HostRejection {
            host_id: HostId::from_string("hst_2"),
            reason: "host is unavailable".into(),
        },
        HostRejection {
            host_id: HostId::from_string("hst_3"),
            reason: "insufficient capacity".into(),
        },
    ];

    let counts = CellScheduler::aggregate_rejections(&rejections);
    let unavailable = counts.iter().find(|c| c.reason == "unavailable").unwrap();
    let capacity = counts
        .iter()
        .find(|c| c.reason == "insufficient_capacity")
        .unwrap();
    assert_eq!(unavailable.count, 2);
    assert_eq!(capacity.count, 1);
}

// ================================================================
// Metrics tests
// ================================================================

#[test]
fn metrics_populated_on_success() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Healthy),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.metrics.hosts_evaluated, 2);
    assert_eq!(result.metrics.hosts_passed_constraints, 2);
    assert!(result.metrics.selected_host_score > 0.0);
}

#[test]
fn metrics_include_rejection_counts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Draining),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(!result.metrics.rejection_counts.is_empty());
}

// ================================================================
// Host capacity tests
// ================================================================

#[test]
fn host_capacity_headroom_calculations() {
    let cap = HostCapacity {
        total_vcpus: 64,
        allocated_vcpus: 16,
        total_memory_mb: 65536,
        allocated_memory_mb: 16384,
        total_disk_mb: 500_000,
        used_disk_mb: 100_000,
        total_network_mbps: 10_000,
        allocated_network_mbps: 2_000,
        max_process_slots: 100,
        used_process_slots: 20,
    };

    assert!((cap.vcpu_headroom() - 0.75).abs() < f64::EPSILON);
    assert!((cap.memory_headroom() - 0.75).abs() < f64::EPSILON);
    assert!((cap.disk_headroom() - 0.8).abs() < f64::EPSILON);
    assert!((cap.network_headroom() - 0.8).abs() < f64::EPSILON);
    assert!((cap.process_slot_headroom() - 0.8).abs() < f64::EPSILON);
}

#[test]
fn host_capacity_zero_total_returns_zero_headroom() {
    let cap = HostCapacity {
        total_vcpus: 0,
        allocated_vcpus: 0,
        total_memory_mb: 0,
        allocated_memory_mb: 0,
        total_disk_mb: 0,
        used_disk_mb: 0,
        total_network_mbps: 0,
        allocated_network_mbps: 0,
        max_process_slots: 0,
        used_process_slots: 0,
    };

    assert_eq!(cap.vcpu_headroom(), 0.0);
    assert_eq!(cap.memory_headroom(), 0.0);
    assert_eq!(cap.disk_headroom(), 0.0);
    assert_eq!(cap.network_headroom(), 0.0);
    assert_eq!(cap.process_slot_headroom(), 0.0);
}

#[test]
fn host_capacity_can_fit_checks_all_dimensions() {
    let cap = HostCapacity {
        total_vcpus: 10,
        allocated_vcpus: 8,
        total_memory_mb: 1024,
        allocated_memory_mb: 512,
        total_disk_mb: 10_000,
        used_disk_mb: 9_500,
        total_network_mbps: 1000,
        allocated_network_mbps: 100,
        max_process_slots: 5,
        used_process_slots: 5,
    };

    assert!(!cap.can_fit(1, 100, 100));
    assert!(!cap.can_fit(3, 100, 100));
    assert!(!cap.can_fit(1, 600, 100));
    assert!(!cap.can_fit(1, 100, 600));
}

#[test]
fn host_capacity_remaining_fit_count_is_min_across_resources() {
    let cap = HostCapacity {
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
    };

    assert_eq!(cap.remaining_fit_count(2, 512, 1024), 32);
    assert_eq!(
        cap.remaining_fit_count(2, 512, 1024) > 0,
        cap.can_fit(2, 512, 1024)
    );
}

// ================================================================
// Host pressure tests
// ================================================================

#[test]
fn host_pressure_calculations() {
    let pressure = HostPressure {
        in_flight_creates: 3,
        in_flight_restores: 2,
        max_concurrent_creates: 10,
        max_concurrent_restores: 5,
    };

    assert!((pressure.create_pressure() - 0.3).abs() < f64::EPSILON);
    assert!((pressure.restore_pressure() - 0.4).abs() < f64::EPSILON);
    assert!((pressure.combined_pressure() - 0.4).abs() < f64::EPSILON);
    assert!(pressure.can_accept_create());
    assert!(pressure.can_accept_restore());
}

#[test]
fn host_pressure_saturated() {
    let pressure = HostPressure {
        in_flight_creates: 10,
        in_flight_restores: 5,
        max_concurrent_creates: 10,
        max_concurrent_restores: 5,
    };

    assert!(!pressure.can_accept_create());
    assert!(!pressure.can_accept_restore());
    assert!((pressure.combined_pressure() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn host_pressure_zero_max_returns_saturated() {
    let pressure = HostPressure {
        in_flight_creates: 0,
        in_flight_restores: 0,
        max_concurrent_creates: 0,
        max_concurrent_restores: 0,
    };

    assert!((pressure.create_pressure() - 1.0).abs() < f64::EPSILON);
    assert!((pressure.restore_pressure() - 1.0).abs() < f64::EPSILON);
}

// ================================================================
// Host health tests
// ================================================================

#[test]
fn host_health_can_admit() {
    assert!(HostHealth::Healthy.can_admit());
    assert!(HostHealth::Degraded.can_admit());
    assert!(!HostHealth::Draining.can_admit());
    assert!(!HostHealth::DisabledForPlacement.can_admit());
    assert!(!HostHealth::Unavailable.can_admit());
    assert!(!HostHealth::Quarantined.can_admit());
}

#[test]
fn host_health_as_str() {
    assert_eq!(HostHealth::Healthy.as_str(), "healthy");
    assert_eq!(HostHealth::Degraded.as_str(), "degraded");
    assert_eq!(HostHealth::Draining.as_str(), "draining");
    assert_eq!(
        HostHealth::DisabledForPlacement.as_str(),
        "disabled_for_placement"
    );
    assert_eq!(HostHealth::Unavailable.as_str(), "unavailable");
    assert_eq!(HostHealth::Quarantined.as_str(), "quarantined");
}

#[test]
fn schedule_rejects_quarantined_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Quarantined),
        make_host("hst_2", HostHealth::Healthy),
    ];
    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(result.placed);
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_2");
}

#[test]
fn schedule_all_quarantined_returns_error() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_host("hst_1", HostHealth::Quarantined),
        make_host("hst_2", HostHealth::Quarantined),
    ];
    let result = scheduler.schedule(&request, &hosts);
    assert!(result.is_err());
}

// ================================================================
// Cache state tests
// ================================================================

#[test]
fn cache_state_image_lookup() {
    let cache = HostCacheState {
        cached_images: vec!["alpine-3.18".into(), "ubuntu-22.04".into()],
        cached_snapshots: vec![],
    };

    assert!(cache.has_image("alpine-3.18"));
    assert!(cache.has_image("ubuntu-22.04"));
    assert!(!cache.has_image("debian-12"));
}

#[test]
fn cache_state_snapshot_lookup() {
    let cache = HostCacheState {
        cached_images: vec![],
        cached_snapshots: vec!["snp_abc".into()],
    };

    assert!(cache.has_snapshot("snp_abc"));
    assert!(!cache.has_snapshot("snp_xyz"));
}

// ================================================================
// Custom weights tests
// ================================================================

#[test]
fn custom_weights_affect_scoring() {
    let weights = CellScoringWeights {
        capacity_headroom: 0.0,
        cache_locality: 1.0,
        pressure: 0.0,
        sandbox_spread: 0.0,
        disk_availability: 0.0,
    };
    let scheduler = CellScheduler::with_weights(weights);
    let mut request = make_request();
    request.image = "custom-image".into();

    let host_a = make_host("hst_a", HostHealth::Healthy);

    let mut host_b = make_host("hst_b", HostHealth::Healthy);
    host_b.cache.cached_images.push("custom-image".into());

    let result = scheduler.schedule(&request, &[host_a, host_b]).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

#[test]
fn custom_pressure_threshold() {
    let scheduler = CellScheduler::new().with_max_pressure(0.5);
    let request = make_request();

    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.pressure.in_flight_creates = 7;

    let result = scheduler.schedule(&request, &[host]);
    assert!(result.is_err());
}

// ================================================================
// Error display tests
// ================================================================

#[test]
fn cell_scheduler_error_display_messages() {
    let err = CellSchedulerError::NoHostsAvailable;
    assert!(err.to_string().contains("no hosts available"));

    let err = CellSchedulerError::InsufficientCapacity {
        vcpus: 100,
        memory_mb: 50_000,
        disk_mb: 1_000_000,
    };
    assert!(err.to_string().contains("100"));
    assert!(err.to_string().contains("50000"));

    let err = CellSchedulerError::UnsupportedRuntime {
        runtime: "RemoteFirecracker".into(),
    };
    assert!(err.to_string().contains("RemoteFirecracker"));

    let err = CellSchedulerError::AllHostsDraining;
    assert!(err.to_string().contains("draining"));

    let err = CellSchedulerError::PressureSaturated;
    assert!(err.to_string().contains("pressure"));
}

// ================================================================
// Host inventory tests
// ================================================================

#[test]
fn inventory_upsert_and_snapshot() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);
    assert_eq!(inv.len(), 1);
    assert!(!inv.is_empty());

    let snapshot = inv.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].host_id.as_str(), "hst_1");
}

#[test]
fn inventory_remove() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);
    assert_eq!(inv.len(), 1);

    let removed = inv.remove(&HostId::from_string("hst_1"));
    assert!(removed.is_some());
    assert_eq!(inv.len(), 0);
}

#[test]
fn inventory_expire_stale_hosts() {
    let inv = HostInventory::with_stale_ttl(30);
    let host = make_host("hst_1", HostHealth::Healthy);

    let old_time = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    inv.upsert(host, old_time);

    let now = OffsetDateTime::now_utc();
    let expired = inv.expire_stale(now);
    assert_eq!(expired.len(), 1);
    assert_eq!(inv.len(), 0);
}

#[test]
fn inventory_does_not_expire_fresh_hosts() {
    let inv = HostInventory::with_stale_ttl(300);
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);

    let expired = inv.expire_stale(now);
    assert!(expired.is_empty());
    assert_eq!(inv.len(), 1);
}

#[test]
fn inventory_refresh_capacity() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);

    let new_capacity = HostCapacity {
        total_vcpus: 128,
        allocated_vcpus: 32,
        total_memory_mb: 131_072,
        allocated_memory_mb: 32_768,
        total_disk_mb: 1_000_000,
        used_disk_mb: 200_000,
        total_network_mbps: 25_000,
        allocated_network_mbps: 5_000,
        max_process_slots: 200,
        used_process_slots: 40,
    };

    inv.refresh_capacity(&HostId::from_string("hst_1"), new_capacity, now);

    let snapshot = inv.snapshot();
    assert_eq!(snapshot[0].capacity.total_vcpus, 128);
}

#[test]
fn inventory_refresh_pressure() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);

    let new_pressure = HostPressure {
        in_flight_creates: 5,
        in_flight_restores: 3,
        max_concurrent_creates: 10,
        max_concurrent_restores: 5,
    };

    inv.refresh_pressure(&HostId::from_string("hst_1"), new_pressure, now);

    let snapshot = inv.snapshot();
    assert_eq!(snapshot[0].pressure.in_flight_creates, 5);
}

#[test]
fn inventory_update_health() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);

    inv.update_health(&HostId::from_string("hst_1"), HostHealth::Draining, now);

    let snapshot = inv.snapshot();
    assert_eq!(snapshot[0].health, HostHealth::Draining);
}

#[test]
fn inventory_refresh_snapshot_timing() {
    let inv = HostInventory::new();
    let host = make_host("hst_1", HostHealth::Healthy);
    let now = OffsetDateTime::now_utc();

    inv.upsert(host, now);
    inv.refresh_snapshot_timing(
        &HostId::from_string("hst_1"),
        SnapshotTimingHint::QuiesceRecommended,
        now,
    );

    let snapshot = inv.snapshot();
    assert_eq!(
        snapshot[0].snapshot_timing_hint,
        SnapshotTimingHint::QuiesceRecommended
    );
}

#[test]
fn inventory_aggregate_snapshot_timing_is_conservative() {
    let inv = HostInventory::new();
    let now = OffsetDateTime::now_utc();

    inv.upsert(make_host("hst_quiet", HostHealth::Healthy), now);
    inv.upsert(make_host("hst_busy", HostHealth::Healthy), now);
    inv.refresh_snapshot_timing(
        &HostId::from_string("hst_quiet"),
        SnapshotTimingHint::QuiesceRecommended,
        now,
    );
    inv.refresh_snapshot_timing(
        &HostId::from_string("hst_busy"),
        SnapshotTimingHint::DeferActiveIo,
        now,
    );

    assert_eq!(
        inv.aggregate_snapshot_timing(),
        SnapshotTimingHint::DeferActiveIo
    );
}

#[test]
fn inventory_aggregate_snapshot_timing_empty_is_insufficient_data() {
    let inv = HostInventory::new();
    assert_eq!(
        inv.aggregate_snapshot_timing(),
        SnapshotTimingHint::InsufficientData
    );
}

#[test]
fn host_info_serde_defaults_missing_snapshot_timing_hint() {
    let json = serde_json::json!({
        "host_id": "hst_legacy",
        "health": "healthy",
        "capacity": {
            "total_vcpus": 64,
            "allocated_vcpus": 0,
            "total_memory_mb": 65536,
            "allocated_memory_mb": 0,
            "total_disk_mb": 500000,
            "used_disk_mb": 0,
            "total_network_mbps": 10000,
            "allocated_network_mbps": 0,
            "max_process_slots": 100,
            "used_process_slots": 0
        },
        "supported_runtimes": ["firecracker"],
        "cache": { "cached_images": [], "cached_snapshots": [] },
        "pressure": {
            "in_flight_creates": 0,
            "in_flight_restores": 0,
            "max_concurrent_creates": 10,
            "max_concurrent_restores": 5
        },
        "current_sandboxes": 0
    });
    let host: HostInfo = serde_json::from_value(json).unwrap();
    assert_eq!(
        host.snapshot_timing_hint,
        SnapshotTimingHint::InsufficientData
    );
}

#[test]
fn inventory_feeds_cell_info_snapshot_timing_for_regional_scheduler() {
    use crate::identity::{CellId, RegionId, TenantId};
    use crate::scheduler::{
        CacheLocality, CellCapacity, CellHealth, CellInfo, RegionalScheduler, SchedulerRequest,
        ScoringWeights,
    };

    let inv = HostInventory::new();
    let now = OffsetDateTime::now_utc();

    inv.upsert(make_host("hst_a", HostHealth::Healthy), now);
    inv.upsert(make_host("hst_b", HostHealth::Healthy), now);
    inv.refresh_snapshot_timing(
        &HostId::from_string("hst_a"),
        SnapshotTimingHint::from_host_stats(true, Some("quiesce_recommended")),
        now,
    );
    inv.refresh_snapshot_timing(
        &HostId::from_string("hst_b"),
        SnapshotTimingHint::from_host_stats(true, Some("quiesce_recommended")),
        now,
    );

    let mut cell = CellInfo {
        cell_id: CellId::from_string("cel_live"),
        region_id: RegionId::from_string("rgn_us-east-1"),
        health: CellHealth::Healthy,
        capacity: CellCapacity {
            total_vcpus: 100,
            allocated_vcpus: 20,
            total_memory_mb: 10240,
            allocated_memory_mb: 2048,
            max_sandboxes: 50,
            current_sandboxes: 10,
            be_pool: None,
        },
        supported_runtimes: vec![RuntimeType::Firecracker],
        failure_domain: "fd-1".into(),
        cache: CacheLocality {
            cached_images: vec![],
            cached_snapshots: vec![],
        },
        admission_pressure: 0.1,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    };
    // Prefer inventory aggregate over snapshot().map to avoid cloning HostInfo
    // when only the Copy timing hints are needed.
    cell.snapshot_timing_hint = inv.aggregate_snapshot_timing();
    assert_eq!(
        cell.snapshot_timing_hint,
        SnapshotTimingHint::QuiesceRecommended
    );

    let mut cell_legacy = cell.clone();
    cell_legacy.cell_id = CellId::from_string("cel_legacy");
    cell_legacy.snapshot_timing_hint = SnapshotTimingHint::from_host_stats(false, None);

    let scheduler = RegionalScheduler::with_weights(ScoringWeights {
        capacity_headroom: 0.0,
        image_cache: 0.0,
        snapshot_cache: 0.0,
        admission_pressure: 0.0,
        region_preference: 0.0,
        snapshot_timing: 1.0,
    });
    let request = SchedulerRequest {
        tenant_id: TenantId::from_string("tnt_test"),
        vcpus: 2,
        memory_mb: 512,
        runtime: Some(RuntimeType::Firecracker),
        image: "alpine".into(),
        snapshot_id: None,
        preferred_region: None,
        avoid_failure_domains: vec![],
        sandbox_id: "sbx_test".into(),
        service_class: ServiceClass::LatencySensitive,
    };

    let result = scheduler.schedule(&request, &[cell_legacy, cell]).unwrap();
    assert_eq!(result.cell_id.as_ref().unwrap().as_str(), "cel_live");
}

// ================================================================
// Simulation tests
// ================================================================

#[test]
fn simulation_overloaded_cell_still_schedules() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut hosts: Vec<HostInfo> = (0..5)
        .map(|i| make_host(&format!("hst_{i}"), HostHealth::Healthy))
        .collect();

    for host in hosts.iter_mut().take(4) {
        host.capacity.allocated_vcpus = 62;
        host.capacity.allocated_memory_mb = 64_000;
        host.capacity.used_disk_mb = 499_000;
        host.capacity.used_process_slots = 99;
    }

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(result.placed);
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_4");
}

#[test]
fn simulation_mixed_health_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let hosts = vec![
        make_host("hst_1", HostHealth::Unavailable),
        make_host("hst_2", HostHealth::Healthy),
        make_host("hst_3", HostHealth::Draining),
        make_host("hst_4", HostHealth::Degraded),
    ];

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(result.placed);
    let host_id = result.host_id.as_ref().unwrap().as_str();
    assert!(host_id == "hst_2" || host_id == "hst_4");
}

#[test]
fn simulation_all_hosts_saturated_triggers_throttle() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut hosts: Vec<HostInfo> = (0..10)
        .map(|i| make_host(&format!("hst_{i}"), HostHealth::Healthy))
        .collect();

    for host in hosts.iter_mut() {
        host.capacity.allocated_vcpus = 62;
        host.capacity.allocated_memory_mb = 65_024;
        host.capacity.used_disk_mb = 498_976;
        host.capacity.allocated_network_mbps = 9_900;
        host.capacity.used_process_slots = 99;
    }

    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert!(result.backpressure.should_throttle);
    assert!(result.backpressure.avg_headroom < CellBackpressureSignal::HEADROOM_THRESHOLD);
}

#[test]
fn simulation_cache_locality_affects_placement() {
    let scheduler = CellScheduler::new();
    let mut request = make_request();
    request.image = "ml-toolkit-2.0".into();
    request.snapshot_id = Some("snp_warm".into());

    let host_cold = make_host("hst_cold", HostHealth::Healthy);

    let mut host_warm = make_host("hst_warm", HostHealth::Healthy);
    host_warm.cache.cached_images.push("ml-toolkit-2.0".into());
    host_warm.cache.cached_snapshots.push("snp_warm".into());

    let result = scheduler
        .schedule(&request, &[host_cold, host_warm])
        .unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_warm");
}

#[test]
fn simulation_pressure_drives_spread() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let mut host_busy = make_host("hst_busy", HostHealth::Healthy);
    host_busy.pressure.in_flight_creates = 7;
    host_busy.current_sandboxes = 80;

    let host_idle = make_host("hst_idle", HostHealth::Healthy);

    let result = scheduler
        .schedule(&request, &[host_busy, host_idle])
        .unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_idle");
}

#[test]
fn simulation_all_draining_returns_specific_error() {
    let scheduler = CellScheduler::new();
    let request = make_request();

    let hosts = vec![
        make_host("hst_1", HostHealth::Draining),
        make_host("hst_2", HostHealth::Draining),
        make_host("hst_3", HostHealth::DisabledForPlacement),
    ];

    let result = scheduler.schedule(&request, &hosts);
    assert!(matches!(result, Err(CellSchedulerError::AllHostsDraining)));
}

// ================================================================
// Best-effort overcommit gate tests (overcommit track)
// ================================================================

/// Host with zero strict default-shape slots left.
fn make_full_host(id: &str) -> HostInfo {
    let mut host = make_host(id, HostHealth::Healthy);
    host.capacity.allocated_vcpus = 64;
    host.capacity.allocated_memory_mb = 65536;
    host
}

/// Host with exactly one strict default-shape slot left (2 vCPU, 512 MiB).
fn make_single_slot_host(id: &str) -> HostInfo {
    let mut host = make_host(id, HostHealth::Healthy);
    host.capacity.allocated_vcpus = 62;
    host.capacity.allocated_memory_mb = 65024;
    host
}

fn be_request() -> CellSchedulerRequest {
    let mut request = make_request();
    request.service_class = ServiceClass::BestEffort;
    request
}

fn enabled_policy() -> OvercommitPolicy {
    OvercommitPolicy {
        enabled: true,
        be_cpu_overcommit: 2.0,
        be_memory_overcommit: 2.0,
        be_shared_base_mb: 0,
        base_sharing: BaseSharingMode::None,
    }
}

#[test]
fn be_request_packs_strict_while_policy_disabled() {
    // Default posture: the gate is off, so a best-effort request on a
    // full host is rejected exactly like a latency-sensitive one.
    let scheduler = CellScheduler::new();
    assert!(!scheduler.overcommit_policy().enabled);
    let hosts = vec![make_full_host("hst_1")];

    let be_result = scheduler.schedule(&be_request(), &hosts);
    assert!(matches!(
        be_result,
        Err(CellSchedulerError::InsufficientCapacity { .. })
    ));

    let ls_result = scheduler.schedule(&make_request(), &hosts);
    assert!(matches!(
        ls_result,
        Err(CellSchedulerError::InsufficientCapacity { .. })
    ));
}

#[test]
fn be_request_admits_beyond_strict_when_policy_enabled() {
    // Full host: the default shape fits no strict slot, but 2x
    // overcommit opens 64 vCPU of best-effort budget.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let hosts = vec![make_full_host("hst_1")];

    let response = scheduler
        .schedule(&be_request(), &hosts)
        .expect("BE must pack against overcommitted capacity");
    assert!(response.placed);
    assert_eq!(response.service_class, ServiceClass::BestEffort);
    assert!(
        response.overcommit_applied,
        "admit beyond strict capacity must set the overcommit bit"
    );
}

#[test]
fn ls_request_never_consumes_overcommit_budget() {
    // The default shape on a full host stays rejected for
    // latency-sensitive requests even with the policy enabled.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let hosts = vec![make_full_host("hst_1")];

    let result = scheduler.schedule(&make_request(), &hosts);
    assert!(matches!(
        result,
        Err(CellSchedulerError::InsufficientCapacity { .. })
    ));
}

#[test]
fn strict_be_admit_leaves_overcommit_bit_clear() {
    // A best-effort request that fits strict is a normal admit: the bit
    // separates strict admits from overcommit admits for S-NOISY.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let hosts = vec![make_single_slot_host("hst_1")];

    let response = scheduler
        .schedule(&be_request(), &hosts)
        .expect("BE must fit the remaining strict slot");
    assert!(response.placed);
    assert!(!response.overcommit_applied);
}

#[test]
fn placement_audit_carries_service_class_and_bit() {
    use std::sync::Arc;

    use crate::event_bus::{AuditEventSink, InMemoryAuditSink};
    use crate::identity::{AuditEventDetails, AuditEventKind};
    // BE admit beyond strict carries the bit in audit.
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(crate::identity::Hlc::new());
    let sink_trait: Arc<dyn AuditEventSink> = Arc::clone(&sink) as Arc<dyn AuditEventSink>;
    let scheduler = CellScheduler::new()
        .with_overcommit_policy(enabled_policy())
        .with_audit_sink(sink_trait, Arc::clone(&hlc));
    // Fill the host so only overcommit budget fits: BE beyond strict.
    let mut host = make_single_slot_host("hst_audit");
    host.capacity.allocated_vcpus = host.capacity.total_vcpus;
    host.capacity.allocated_memory_mb = host.capacity.total_memory_mb;
    // With 2x overcommit the effective totals still fit one BE shape.
    let response = scheduler
        .schedule(&be_request(), &[host])
        .expect("BE beyond strict must place under enabled policy");
    assert!(response.overcommit_applied);

    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome {
            service_class,
            overcommit_applied,
            ..
        }) => {
            assert_eq!(*service_class, ServiceClass::BestEffort);
            assert!(*overcommit_applied);
        }
        d => panic!("expected placement outcome, got {d:?}"),
    }

    // LS admit in the same setup carries LS with no bit.
    let sink2 = Arc::new(InMemoryAuditSink::new());
    let sink2_trait: Arc<dyn AuditEventSink> = Arc::clone(&sink2) as Arc<dyn AuditEventSink>;
    let scheduler2 = CellScheduler::new()
        .with_overcommit_policy(enabled_policy())
        .with_audit_sink(sink2_trait, Arc::clone(&hlc));
    let hosts = vec![make_single_slot_host("hst_audit_ls")];
    let ls_resp = scheduler2
        .schedule(&make_request(), &hosts)
        .expect("LS must place within strict");
    assert!(!ls_resp.overcommit_applied);
    let outcomes = sink2.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome {
            service_class,
            overcommit_applied,
            ..
        }) => {
            assert_eq!(*service_class, ServiceClass::LatencySensitive);
            assert!(!overcommit_applied);
        }
        d => panic!("expected placement outcome, got {d:?}"),
    }
}

#[test]
fn placement_rejection_audit_never_carries_bit() {
    use std::sync::Arc;

    use crate::event_bus::{AuditEventSink, InMemoryAuditSink};
    use crate::identity::{AuditEventDetails, AuditEventKind};
    let sink = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(crate::identity::Hlc::new());
    let sink_trait: Arc<dyn AuditEventSink> = Arc::clone(&sink) as Arc<dyn AuditEventSink>;
    let scheduler = CellScheduler::new()
        .with_overcommit_policy(enabled_policy())
        .with_audit_sink(sink_trait, Arc::clone(&hlc));
    let host = make_full_host("hst_full");
    let mut be = be_request();
    be.vcpus = 200;
    let _ = scheduler.schedule(&be, &[host]);
    let outcomes = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].details {
        Some(AuditEventDetails::PlacementOutcome {
            overcommit_applied,
            service_class,
            ..
        }) => {
            assert!(!overcommit_applied);
            assert_eq!(*service_class, ServiceClass::BestEffort);
        }
        d => panic!("expected placement outcome, got {d:?}"),
    }
}

#[test]
fn be_rejection_names_overcommit_budget_while_staying_typed() {
    // The message names the exhausted budget for operators, while the
    // `capacity` keyword keeps the insufficient-capacity classification.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let host = make_full_host("hst_1");
    let mut be = be_request();
    be.vcpus = 200;
    let result = scheduler.schedule(&be, &[host]);
    assert!(matches!(
        result,
        Err(CellSchedulerError::InsufficientCapacity { .. })
    ));
}

#[test]
fn be_rejection_message_is_exact_when_budget_binds() {
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let host = make_full_host("hst_1");
    let mut be = be_request();
    be.vcpus = 200;
    let err = scheduler
        .check_hard_constraints(&host, &be)
        .expect_err("over-budget BE must fail the constraint");
    assert_eq!(
        err,
        "insufficient capacity (best-effort overcommit budget exhausted)"
    );
}

#[test]
fn be_rejection_stays_plain_when_disk_binds() {
    // Disk is never overcommitted: a disk-bound failure must not blame
    // the overcommit budget even for best-effort under an enabled policy.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.capacity.used_disk_mb = host.capacity.total_disk_mb;
    let err = scheduler
        .check_hard_constraints(&host, &be_request())
        .expect_err("disk-full host must fail the constraint");
    assert_eq!(err, "insufficient capacity");
}

#[test]
fn be_rejection_stays_plain_when_slots_bind() {
    // Process slots are never overcommitted either.
    let scheduler = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let mut host = make_host("hst_1", HostHealth::Healthy);
    host.capacity.used_process_slots = host.capacity.max_process_slots;
    let err = scheduler
        .check_hard_constraints(&host, &be_request())
        .expect_err("slot-full host must fail the constraint");
    assert_eq!(err, "insufficient capacity");
}

#[test]
fn invalid_overcommit_policy_fails_placement_closed() {
    let bad = OvercommitPolicy {
        enabled: true,
        be_cpu_overcommit: 0.5,
        ..OvercommitPolicy::default()
    };
    let scheduler = CellScheduler::new().with_overcommit_policy(bad);
    let hosts = vec![make_host("hst_1", HostHealth::Healthy)];
    let result = scheduler.schedule(&make_request(), &hosts);
    let err = result.expect_err("invalid policy must fail closed");
    assert!(matches!(
        err,
        CellSchedulerError::InvalidOvercommitPolicy { .. }
    ));
    assert!(!err.is_throttled(), "config errors are not retryable");
}

#[test]
fn request_without_service_class_deserializes_to_ls() {
    // Payloads written before the overcommit track keep strict packing.
    let json = serde_json::json!({
        "sandbox_id": "sbx_old",
        "vcpus": 2,
        "memory_mb": 512,
        "disk_mb": 1024,
        "runtime": "firecracker",
        "image": "alpine-3.18",
        "snapshot_id": null,
        "is_restore": false,
    });
    let request: CellSchedulerRequest = serde_json::from_value(json).unwrap();
    assert_eq!(request.service_class, ServiceClass::LatencySensitive);
}

#[test]
fn response_without_overcommit_fields_deserializes_to_strict() {
    let json = serde_json::json!({
        "placed": true,
        "host_id": "hst_1",
        "reason": {"type": "best_score"},
        "score_breakdown": null,
        "candidate_scores": [],
        "rejections": [],
        "backpressure": {
            "host_admission_rate": 1.0,
            "avg_headroom": 0.8,
            "should_throttle": false,
            "total_hosts": 1,
            "eligible_hosts": 1,
        },
        "metrics": {
            "placement_latency_us": 1,
            "selected_host_score": 1.0,
            "hosts_evaluated": 1,
            "hosts_passed_constraints": 1,
            "rejection_counts": [],
            "avg_capacity_pressure": 0.0,
        },
        "selection": {"sampled": false, "sample_size": 1, "eligible": 1},
        "overlay_adjusted": false,
    });
    let response: CellSchedulerResponse = serde_json::from_value(json).unwrap();
    assert_eq!(response.service_class, ServiceClass::LatencySensitive);
    assert!(!response.overcommit_applied);
}

// ================================================================
// Serialization tests
// ================================================================

#[test]
fn cell_scheduler_response_serializes() {
    let response = CellSchedulerResponse {
        placed: true,
        host_id: Some(HostId::from_string("hst_1")),
        reason: HostPlacementReason::BestScore,
        score_breakdown: None,
        candidate_scores: vec![],
        rejections: vec![],
        backpressure: CellBackpressureSignal {
            host_admission_rate: 1.0,
            avg_headroom: 0.8,
            should_throttle: false,
            total_hosts: 5,
            eligible_hosts: 5,
        },
        metrics: PlacementMetrics {
            placement_latency_us: 150,
            selected_host_score: 0.85,
            hosts_evaluated: 5,
            hosts_passed_constraints: 5,
            rejection_counts: vec![],
            avg_capacity_pressure: 0.15,
        },
        selection: SelectionDetail {
            sampled: false,
            sample_size: 5,
            eligible: 5,
        },
        overlay_adjusted: false,
        service_class: ServiceClass::LatencySensitive,
        overcommit_applied: false,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("placed"));
    assert!(json.contains("hst_1"));
}

#[test]
fn host_placement_reason_serde_roundtrip() {
    let reasons = vec![
        HostPlacementReason::BestScore,
        HostPlacementReason::OnlyCandidate,
        HostPlacementReason::CacheHit,
        HostPlacementReason::NoHostAvailable {
            reason: "test".into(),
        },
    ];

    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: HostPlacementReason = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, reason);
    }
}

#[test]
fn host_health_serde_roundtrip() {
    let healths = vec![
        HostHealth::Healthy,
        HostHealth::Degraded,
        HostHealth::Draining,
        HostHealth::DisabledForPlacement,
        HostHealth::Unavailable,
        HostHealth::Quarantined,
    ];

    for health in &healths {
        let json = serde_json::to_string(health).unwrap();
        let back: HostHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, health);
    }
}

// ================================================================
// Integration-style test: inventory + scheduler
// ================================================================

#[test]
fn integration_inventory_feeds_scheduler() {
    let inv = HostInventory::new();
    let scheduler = CellScheduler::new();
    let request = make_request();
    let now = OffsetDateTime::now_utc();

    inv.upsert(make_host("hst_1", HostHealth::Healthy), now);
    inv.upsert(make_host("hst_2", HostHealth::Healthy), now);
    inv.upsert(make_host("hst_3", HostHealth::Draining), now);

    let hosts = inv.snapshot();
    let result = scheduler.schedule(&request, &hosts).unwrap();

    assert!(result.placed);
    assert_eq!(result.metrics.hosts_evaluated, 3);
    assert_eq!(result.metrics.hosts_passed_constraints, 2);

    let stale_time = now + time::Duration::seconds(120);
    let expired = inv.expire_stale(stale_time);
    assert_eq!(expired.len(), 3);
    assert!(inv.is_empty());
}

#[test]
fn integration_capacity_report_updates_scoring() {
    let inv = HostInventory::new();
    let scheduler = CellScheduler::new();
    let request = make_request();
    let now = OffsetDateTime::now_utc();

    inv.upsert(make_host("hst_a", HostHealth::Healthy), now);
    inv.upsert(make_host("hst_b", HostHealth::Healthy), now);

    let saturated = HostCapacity {
        total_vcpus: 64,
        allocated_vcpus: 60,
        total_memory_mb: 65536,
        allocated_memory_mb: 60_000,
        total_disk_mb: 500_000,
        used_disk_mb: 490_000,
        total_network_mbps: 10_000,
        allocated_network_mbps: 9_000,
        max_process_slots: 100,
        used_process_slots: 95,
    };
    inv.refresh_capacity(&HostId::from_string("hst_a"), saturated, now);

    let hosts = inv.snapshot();
    let result = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(result.host_id.as_ref().unwrap().as_str(), "hst_b");
}

// ================================================================
// Backpressure constants tests
// ================================================================

#[test]
fn backpressure_constants_are_reasonable() {
    const _: () = assert!(CellBackpressureSignal::THROTTLE_THRESHOLD > 0.0);
    const _: () = assert!(CellBackpressureSignal::THROTTLE_THRESHOLD < 1.0);
    const _: () = assert!(CellBackpressureSignal::HEADROOM_THRESHOLD > 0.0);
    const _: () = assert!(CellBackpressureSignal::HEADROOM_THRESHOLD < 1.0);
}

// ================================================================
// Scoring dimension tests
// ================================================================

#[test]
fn host_score_dimension_as_str() {
    assert_eq!(
        HostScoreDimension::CapacityHeadroom.as_str(),
        "capacity_headroom"
    );
    assert_eq!(HostScoreDimension::CacheLocality.as_str(), "cache_locality");
    assert_eq!(HostScoreDimension::Pressure.as_str(), "pressure");
    assert_eq!(HostScoreDimension::SandboxSpread.as_str(), "sandbox_spread");
    assert_eq!(
        HostScoreDimension::DiskAvailability.as_str(),
        "disk_availability"
    );
}

#[test]
fn host_score_dimension_all_contains_all_variants() {
    assert_eq!(HostScoreDimension::ALL.len(), 5);
}

// ================================================================
// Weights tests
// ================================================================

#[test]
fn weights_weight_for_returns_correct_values() {
    let weights = CellScoringWeights::default();
    assert!((weights.weight_for(HostScoreDimension::CapacityHeadroom) - 0.30).abs() < f64::EPSILON);
    assert!((weights.weight_for(HostScoreDimension::CacheLocality) - 0.25).abs() < f64::EPSILON);
    assert!((weights.weight_for(HostScoreDimension::Pressure) - 0.20).abs() < f64::EPSILON);
    assert!((weights.weight_for(HostScoreDimension::SandboxSpread) - 0.10).abs() < f64::EPSILON);
    assert!((weights.weight_for(HostScoreDimension::DiskAvailability) - 0.15).abs() < f64::EPSILON);
}

// ================================================================
// Burst hardening: sampling and in-flight overlay
// ================================================================

/// Hosts that each fit exactly two request shapes, for spread tests.
fn make_tight_host(id: &str) -> HostInfo {
    let mut host = make_host(id, HostHealth::Healthy);
    host.capacity = HostCapacity {
        total_vcpus: 4,
        allocated_vcpus: 0,
        total_memory_mb: 1024,
        allocated_memory_mb: 0,
        total_disk_mb: 500_000,
        used_disk_mb: 0,
        total_network_mbps: 10_000,
        allocated_network_mbps: 0,
        max_process_slots: 100,
        used_process_slots: 0,
    };
    host.pressure = HostPressure {
        in_flight_creates: 0,
        in_flight_restores: 0,
        max_concurrent_creates: 10,
        max_concurrent_restores: 5,
    };
    host.current_sandboxes = 0;
    host
}

#[test]
fn default_selection_reports_full_best() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_tight_host("hst_1")];
    let response = scheduler.schedule(&request, &hosts).unwrap();
    assert!(!response.selection.sampled);
    assert_eq!(response.selection.eligible, 1);
    assert!(!response.overlay_adjusted);
}

#[test]
fn sampled_selection_reports_sample_detail() {
    let scheduler = CellScheduler::new()
        .with_selection(SelectionMode::PowerOfK { k: 1 })
        .with_sampling_seed(9);
    let request = make_request();
    let hosts = vec![make_tight_host("hst_1"), make_tight_host("hst_2")];
    let response = scheduler.schedule(&request, &hosts).unwrap();
    assert!(response.selection.sampled);
    assert_eq!(response.selection.sample_size, 1);
    assert_eq!(response.selection.eligible, 2);
    assert!(!response.overlay_adjusted);
}

#[test]
fn in_flight_overlay_spreads_identical_hosts() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![
        make_tight_host("hst_1"),
        make_tight_host("hst_2"),
        make_tight_host("hst_3"),
    ];
    // Each tight host fits exactly two requests. Identical snapshots would
    // herd every decision onto hst_1; the overlay folds each placement back
    // in, so six consecutive decisions fill every host exactly twice.
    let mut counts = [0u32; 3];
    for _ in 0..6 {
        let response = scheduler.schedule(&request, &hosts).unwrap();
        match response.host_id.as_ref().unwrap().as_str() {
            "hst_1" => counts[0] += 1,
            "hst_2" => counts[1] += 1,
            "hst_3" => counts[2] += 1,
            other => panic!("unexpected host {other}"),
        }
    }
    assert_eq!(counts, [2, 2, 2]);
    // The seventh placement no longer fits anywhere: typed retryable shed,
    // not a silent over-admission.
    let shed = scheduler.schedule(&request, &hosts).unwrap_err();
    assert!(matches!(
        shed,
        CellSchedulerError::InsufficientCapacity { .. }
    ));
    assert!(shed.is_throttled());
}

#[test]
fn acknowledge_placement_releases_overlay() {
    let scheduler = CellScheduler::new();
    let request = make_request();
    let hosts = vec![make_tight_host("hst_1")];
    for _ in 0..2 {
        let response = scheduler.schedule(&request, &hosts).unwrap();
        assert_eq!(response.host_id.as_ref().unwrap().as_str(), "hst_1");
    }
    // Overlay now covers the only host, so the next decision sheds.
    assert!(scheduler.schedule(&request, &hosts).is_err());
    assert!(scheduler.acknowledge_placement("hst_1"));
    assert!(!scheduler.acknowledge_placement("hst_1"));
    let retry = scheduler.schedule(&request, &hosts).unwrap();
    assert_eq!(retry.host_id.as_ref().unwrap().as_str(), "hst_1");
}

#[test]
fn disabled_overlay_restores_herding_baseline() {
    let scheduler = CellScheduler::new().with_overlay_limits(60, 0);
    let request = make_request();
    let hosts = vec![make_tight_host("hst_1"), make_tight_host("hst_2")];
    // Without the overlay the stale snapshot never moves, so every decision
    // herds onto the tie-break winner. This pins the baseline the overlay
    // fixes; production keeps the overlay enabled.
    for _ in 0..4 {
        let response = scheduler.schedule(&request, &hosts).unwrap();
        assert_eq!(response.host_id.as_ref().unwrap().as_str(), "hst_1");
        assert!(!response.overlay_adjusted);
    }
}

// ================================================================
// Class-aware scoring tests (BE bin-packing follow-up)
// ================================================================

/// Two hosts identical except vCPU/memory utilization and sandbox count.
/// Disk, network, slots, cache, pressure, and runtimes match so only the
/// overcommittable bin-pack axes (plus spread) decide: disk and fixed
/// resources stay spread-oriented for every class and must not tip the
/// decision.
fn make_binpack_hosts() -> (HostInfo, HostInfo) {
    let mut full = make_host("hst_full", HostHealth::Healthy);
    full.capacity.allocated_vcpus = 60;
    full.capacity.allocated_memory_mb = 60_000;
    full.current_sandboxes = 80;
    full.cache.cached_images = vec!["img".into()];

    let mut empty = make_host("hst_empty", HostHealth::Healthy);
    empty.capacity.allocated_vcpus = 4;
    empty.capacity.allocated_memory_mb = 2048;
    empty.current_sandboxes = 2;
    empty.cache.cached_images = vec!["img".into()];
    empty.pressure = full.pressure;

    (full, empty)
}

fn be_binpack_request() -> CellSchedulerRequest {
    let mut req = make_request();
    req.service_class = ServiceClass::BestEffort;
    req.image = "img".into();
    req
}

#[test]
fn ls_prefers_empty_host_while_be_binpacks_full() {
    let (full, empty) = make_binpack_hosts();
    let enabled = enabled_policy();

    // LS spreads to the empty host regardless of the overcommit gate.
    for policy in [OvercommitPolicy::default(), enabled] {
        let scheduler = CellScheduler::new().with_overcommit_policy(policy);
        let ls = scheduler
            .schedule(&make_request_with_image(), &[full.clone(), empty.clone()])
            .unwrap();
        assert_eq!(
            ls.host_id.as_ref().unwrap().as_str(),
            "hst_empty",
            "LS must spread even with BE bin-packing enabled"
        );
    }

    // BE with the gate off packs like LS (empty host).
    let off = CellScheduler::new();
    let be_off = off
        .schedule(&be_binpack_request(), &[full.clone(), empty.clone()])
        .unwrap();
    assert_eq!(be_off.host_id.as_ref().unwrap().as_str(), "hst_empty");

    // BE with the gate on bin-packs toward the full host.
    let on = CellScheduler::new().with_overcommit_policy(enabled);
    let be_on = on.schedule(&be_binpack_request(), &[full, empty]).unwrap();
    assert_eq!(be_on.host_id.as_ref().unwrap().as_str(), "hst_full");
}

fn make_request_with_image() -> CellSchedulerRequest {
    let mut req = make_request();
    req.image = "img".into();
    req
}

#[test]
fn ls_scores_identical_with_policy_on_or_off() {
    // Scoring changes must not move the LS warning-max vs the step-1
    // baseline: an LS request scores byte-identical with the policy
    // disabled or enabled.
    let (full, empty) = make_binpack_hosts();
    let req = make_request_with_image();
    let off = CellScheduler::new();
    let on = CellScheduler::new().with_overcommit_policy(enabled_policy());

    for host in [full, empty] {
        let max = 80;
        let off_score = off.score_host(&host, &req, max);
        let on_score = on.score_host(&host, &req, max);
        assert_eq!(
            off_score, on_score,
            "LS breakdown must not move with the BE gate"
        );
    }
}

#[test]
fn be_tie_break_stays_deterministic_by_host_id() {
    // Two identical full hosts: BE bin-packing scores tie, so the
    // placement-engine ID order decides regardless of input order.
    let (full, _) = make_binpack_hosts();
    let mut a = full.clone();
    a.host_id = HostId::from_string("hst_a");
    let mut b = full;
    b.host_id = HostId::from_string("hst_b");

    let first = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let second = CellScheduler::new().with_overcommit_policy(enabled_policy());
    let req = be_binpack_request();

    let r1 = first.schedule(&req, &[a.clone(), b.clone()]).unwrap();
    let r2 = second.schedule(&req, &[b, a]).unwrap();
    assert_eq!(r1.host_id, r2.host_id);
}
