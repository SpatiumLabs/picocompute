//! Burst placement hardening: power-of-k sampling plus in-flight overlay.
//!
//! S-SPIKE-CREATE style coverage for bursty create load against a stale
//! snapshot. One scheduler instance serves a whole burst from a single
//! host snapshot (the snapshot never refreshes mid-burst, as under watcher
//! poll intervals). The overlay must spread the burst across hosts without
//! over-admitting, sampling must elect varying winners, and exhaustion
//! must shed as a typed retryable error rather than a timeout or panic.

use std::collections::HashMap;

use pico_core::identity::HostId;
use pico_core::{
    CellScheduler, CellSchedulerError, CellSchedulerRequest, HostCacheState, HostCapacity,
    HostHealth, HostInfo, HostPressure, RuntimeType, SelectionMode, SnapshotTimingHint,
};

fn burst_host(id: &str) -> HostInfo {
    HostInfo {
        host_id: HostId::from_string(id),
        health: HostHealth::Healthy,
        capacity: HostCapacity {
            total_vcpus: 20,
            allocated_vcpus: 0,
            total_memory_mb: 5120,
            allocated_memory_mb: 0,
            total_disk_mb: 500_000,
            used_disk_mb: 0,
            total_network_mbps: 10_000,
            allocated_network_mbps: 0,
            max_process_slots: 100,
            used_process_slots: 0,
        },
        supported_runtimes: vec![RuntimeType::Firecracker],
        cache: HostCacheState {
            cached_images: vec!["burst-image".into()],
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

fn burst_request(sandbox_id: &str) -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: sandbox_id.into(),
        vcpus: 2,
        memory_mb: 512,
        disk_mb: 1024,
        runtime: Some(RuntimeType::Firecracker),
        image: "burst-image".into(),
        snapshot_id: None,
        is_restore: false,
    }
}

/// Stale snapshot burst spreads across hosts with no over-admission.
///
/// Six identical hosts each fit exactly ten requests. Sixty sequential
/// decisions from one snapshot must place all sixty with exactly ten per
/// host, then shed the sixty-first as typed retryable exhaustion.
#[test]
fn stale_snapshot_burst_spreads_without_overcommit() {
    let scheduler = CellScheduler::new()
        .with_selection(SelectionMode::PowerOfK { k: 2 })
        .with_sampling_seed(11);
    let hosts = vec![
        burst_host("hst_1"),
        burst_host("hst_2"),
        burst_host("hst_3"),
        burst_host("hst_4"),
        burst_host("hst_5"),
        burst_host("hst_6"),
    ];

    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut sampled = 0u32;
    let mut overlay_hits = 0u32;
    for i in 0..60 {
        let response = scheduler
            .schedule(&burst_request(&format!("sbx_burst_{i:03}")), &hosts)
            .unwrap_or_else(|err| panic!("burst placement {i} must admit, got {err:?}"));
        assert!(response.placed);
        if response.selection.sampled {
            sampled += 1;
        }
        if response.overlay_adjusted {
            overlay_hits += 1;
        }
        *counts
            .entry(response.host_id.unwrap().as_str().to_string())
            .or_insert(0) += 1;
    }

    assert_eq!(counts.len(), 6, "burst must reach every host");
    for (host, count) in &counts {
        assert_eq!(*count, 10, "host {host} must fill exactly, got {count}");
    }
    assert!(sampled > 0, "power-of-k must elect from samples");
    assert_eq!(
        overlay_hits, 59,
        "every decision after the first must see the overlay"
    );

    let shed = scheduler
        .schedule(&burst_request("sbx_burst_060"), &hosts)
        .unwrap_err();
    assert!(
        matches!(shed, CellSchedulerError::InsufficientCapacity { .. }),
        "exhaustion must shed typed, got {shed:?}"
    );
    assert!(shed.is_throttled(), "exhaustion shed must stay retryable");
}

/// Without the overlay a stale snapshot herds the whole burst one way.
///
/// Same burst with overlay recording disabled pins the pre-overlay
/// baseline: every decision elects the tie-break winner. The host would
/// then fail closed at boot, but placement itself over-admits sixty deep
/// on one host, which is the failure the overlay removes.
#[test]
fn disabled_overlay_herds_stale_snapshot_burst() {
    let scheduler = CellScheduler::new().with_overlay_limits(60, 0);
    let hosts = vec![
        burst_host("hst_1"),
        burst_host("hst_2"),
        burst_host("hst_3"),
        burst_host("hst_4"),
        burst_host("hst_5"),
        burst_host("hst_6"),
    ];

    for i in 0..60 {
        let response = scheduler
            .schedule(&burst_request(&format!("sbx_herd_{i:03}")), &hosts)
            .unwrap();
        assert_eq!(response.host_id.unwrap().as_str(), "hst_1");
        assert!(!response.overlay_adjusted);
    }
}
