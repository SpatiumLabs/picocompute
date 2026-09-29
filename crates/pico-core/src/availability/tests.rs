use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::*;
use crate::cell_scheduler::{
    CellScheduler, CellSchedulerRequest, HostCacheState, HostCapacity, HostHealth, HostInfo,
    HostInventory, HostPressure,
};
use crate::event_bus::InMemoryAuditSink;
use crate::host_quarantine::{AlertCondition, AlertStateManager, HostAlertEvaluation};
use crate::identity::{AuditEventDetails, AuditEventKind, CellId, Hlc, HostId, RegionId, TenantId};
use crate::overcommit::ServiceClass;
use crate::runtime::RuntimeType;
use crate::scheduler::{
    CacheLocality, CellCapacity, CellHealth, CellInfo, RegionalScheduler, SchedulerRequest,
    SnapshotTimingHint,
};

fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp")
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

fn make_host(id: &str, health: HostHealth) -> HostInfo {
    HostInfo {
        host_id: HostId::from_string(id),
        health,
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
        current_sandboxes: 4,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn host_request() -> CellSchedulerRequest {
    CellSchedulerRequest {
        sandbox_id: "sbx_avail".into(),
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

fn make_cell(id: &str, health: CellHealth) -> CellInfo {
    CellInfo {
        cell_id: CellId::from_string(id),
        region_id: RegionId::from_string("rgn_us-east-1"),
        health,
        capacity: CellCapacity {
            total_vcpus: 100,
            allocated_vcpus: 20,
            total_memory_mb: 10240,
            allocated_memory_mb: 2048,
            max_sandboxes: 50,
            current_sandboxes: 10,
        },
        supported_runtimes: vec![RuntimeType::Firecracker],
        failure_domain: format!("fd-{id}"),
        cache: CacheLocality {
            cached_images: vec!["alpine-3.18".into()],
            cached_snapshots: vec![],
        },
        admission_pressure: 0.2,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    }
}

fn cell_request() -> SchedulerRequest {
    SchedulerRequest {
        tenant_id: TenantId::from_string("tnt_test"),
        vcpus: 2,
        memory_mb: 512,
        runtime: Some(RuntimeType::Firecracker),
        image: "alpine-3.18".into(),
        snapshot_id: None,
        preferred_region: None,
        avoid_failure_domains: vec![],
        sandbox_id: "sbx_avail".into(),
    }
}

fn p0_input(
    scenario: AvailabilityScenario,
    observations: Vec<AvailabilityObservation>,
    surviving: SurvivingCapacity,
) -> CellAvailabilityInput {
    CellAvailabilityInput {
        scenario,
        phase: ValidationPhase::P0,
        scope: CapacityScope::Region,
        observations,
        observability: ObservabilityEvidence::p0_required(),
        live_observability: false,
        measured_fencing: false,
        measured_orphan_reconcile: false,
        surviving,
    }
}

fn has_code(report: &CellAvailabilityReport, code: &str) -> bool {
    report.findings.iter().any(|f| f.code == code)
}

fn class_of(report: &CellAvailabilityReport, code: &str) -> Option<FailureClass> {
    report
        .findings
        .iter()
        .find(|f| f.code == code)
        .map(|f| f.class)
}

fn placement_candidates(events: &[crate::identity::AuditEvent]) -> Option<usize> {
    events.iter().find_map(|event| match &event.details {
        Some(AuditEventDetails::PlacementOutcome {
            candidates_evaluated,
            ..
        }) => Some(*candidates_evaluated),
        _ => None,
    })
}

#[test]
fn fail_cell_stops_new_placement_on_unavailable_cell() {
    let scheduler = RegionalScheduler::new();
    let req = cell_request();
    let mut cells = vec![
        make_cell("cel_a", CellHealth::Healthy),
        make_cell("cel_b", CellHealth::Healthy),
    ];
    cells[0].capacity.current_sandboxes = 10;
    cells[1].capacity.current_sandboxes = 10;

    let before = scheduler.schedule(&req, &cells).expect("pre");
    assert_eq!(before.cell_id.as_ref().map(|c| c.as_str()), Some("cel_a"));

    cells[0].health = CellHealth::Unavailable;
    let existing_a = cells[0].capacity.current_sandboxes;
    let mut placed_failed = 0;
    let mut placed_surviving = 0;
    let mut rejected = 0;
    for i in 0..8 {
        let mut req = cell_request();
        req.sandbox_id = format!("sbx_{i}");
        match scheduler.schedule(&req, &cells) {
            Ok(resp) => {
                let id = resp.cell_id.expect("cell").as_str().to_string();
                if id == "cel_a" {
                    placed_failed += 1;
                } else {
                    placed_surviving += 1;
                }
            }
            Err(_) => rejected += 1,
        }
    }
    assert_eq!(placed_failed, 0);
    assert_eq!(placed_surviving, 8);
    assert_eq!(rejected, 0);
    assert_eq!(cells[0].capacity.current_sandboxes, existing_a);

    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.failed_cell_id = Some("cel_a".into());
    failure.offered = 8;
    failure.admitted = 8;
    failure.placements_on_surviving_domain = 8;
    failure.existing_on_failed_before = existing_a;
    failure.existing_on_failed_after = existing_a;
    failure.eligible_cells = 1;
    failure.total_cells = 2;
    failure.audit_events = 1;
    failure.throttle_honored = true;

    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 1,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: existing_a,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert!(!has_code(&report, "placement_to_unavailable"));
    assert_eq!(report.proposed_lpop, None);
    assert_eq!(
        class_of(&report, "phase_cannot_set_lpop"),
        Some(FailureClass::C)
    );
}

#[test]
fn fail_cell_total_loss_sheds_instead_of_retrying() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let scheduler = RegionalScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), Arc::new(Hlc::new()));
    let cells = vec![
        make_cell("cel_a", CellHealth::Unavailable),
        make_cell("cel_b", CellHealth::Draining),
    ];
    let result = scheduler.schedule(&cell_request(), &cells);
    assert!(result.is_err());
    let events = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(placement_candidates(&events), Some(2));

    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.offered = 1;
    failure.rejected = 1;
    failure.retries_after_reject = 0;
    failure.should_throttle = true;
    failure.throttle_honored = true;
    failure.eligible_cells = 0;
    failure.total_cells = 2;
    failure.audit_events = 1;
    failure.existing_on_failed_before = 10;
    failure.existing_on_failed_after = 10;

    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 0,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 10,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert!(!has_code(&report, "uncontrolled_retry"));
    assert!(!has_code(&report, "admitted_with_no_eligible_cell"));
}

#[test]
fn uncontrolled_retry_is_class_a() {
    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.offered = 4;
    failure.rejected = 1;
    failure.retries_after_reject = 3;
    failure.eligible_cells = 0;
    failure.total_cells = 2;
    failure.audit_events = 1;
    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 0,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 0,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert_eq!(
        class_of(&report, "uncontrolled_retry"),
        Some(FailureClass::A)
    );
}

#[test]
fn fail_host_skips_unavailable_and_keeps_existing() {
    let scheduler = CellScheduler::new();
    let mut hosts = vec![
        make_host("hst_1", HostHealth::Healthy),
        make_host("hst_2", HostHealth::Healthy),
    ];
    hosts[0].current_sandboxes = 4;
    let existing = hosts[0].current_sandboxes;
    hosts[0].health = HostHealth::Unavailable;

    let mut placed_failed = 0;
    let mut placed_surviving = 0;
    for i in 0..4 {
        let mut req = host_request();
        req.sandbox_id = format!("sbx_{i}");
        if let Ok(resp) = scheduler.schedule(&req, &hosts) {
            if resp.host_id.as_ref().map(|h| h.as_str()) == Some("hst_1") {
                placed_failed += 1;
            } else {
                placed_surviving += 1;
            }
        }
    }
    assert_eq!(placed_failed, 0);
    assert_eq!(placed_surviving, 4);
    assert_eq!(hosts[0].current_sandboxes, existing);

    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.failed_host_id = Some("hst_1".into());
    failure.offered = 4;
    failure.admitted = 4;
    failure.placements_on_surviving_domain = 4;
    failure.existing_on_failed_before = existing;
    failure.existing_on_failed_after = existing;
    failure.eligible_hosts = 1;
    failure.total_hosts = 2;
    failure.audit_events = 1;

    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailHost,
        vec![failure],
        SurvivingCapacity {
            cells_total: 1,
            cells_eligible: 1,
            hosts_total: 2,
            hosts_eligible: 1,
            existing_on_failed_domain: existing,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert!(!has_code(&report, "existing_sandbox_mutated"));
    assert_eq!(class_of(&report, "fencing_untested"), Some(FailureClass::C));
}

#[test]
fn host_capacity_stale_expires_then_quarantines() {
    let inventory = HostInventory::with_stale_ttl(60);
    let host = make_host("hst_stale", HostHealth::Healthy);
    let host_id = host.host_id.clone();
    inventory.upsert(host, t0());
    assert_eq!(inventory.len(), 1);

    let expired = inventory.expire_stale(t0() + Duration::seconds(61));
    assert_eq!(expired, vec![host_id.clone()]);
    assert!(inventory.is_empty());

    let sink = Arc::new(InMemoryAuditSink::new());
    let scheduler = CellScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), Arc::new(Hlc::new()));
    let result = scheduler.schedule(&host_request(), &inventory.snapshot());
    assert!(result.is_err());
    let events = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(placement_candidates(&events), Some(0));

    let manager = AlertStateManager::new();
    let eval = HostAlertEvaluation::new().with_capacity_staleness(180);
    let alerts = manager.evaluate_host(
        &host_id,
        &CellId::from_string("cel_a"),
        &RegionId::from_string("rgn_us-east-1"),
        &eval,
        t0() + Duration::seconds(180),
    );
    assert_eq!(
        alerts[0].condition,
        AlertCondition::CapacityReportingStaleness
    );
    assert!(manager.is_quarantined(&host_id));

    let mut remaining = make_host("hst_stale", HostHealth::Healthy);
    remaining.health = remaining
        .health
        .with_quarantine(manager.is_quarantined(&host_id));
    assert_eq!(remaining.health, HostHealth::Quarantined);
    assert!(
        scheduler
            .schedule(&host_request(), std::slice::from_ref(&remaining))
            .is_err()
    );

    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.failed_host_id = Some("hst_stale".into());
    failure.offered = 1;
    failure.rejected = 1;
    failure.should_throttle = true;
    failure.throttle_honored = true;
    failure.stale_hosts_expired = 1;
    failure.quarantine_alerts = 1;
    failure.eligible_hosts = 0;
    failure.total_hosts = 1;
    failure.audit_events = 1;
    failure.existing_on_failed_before = 4;
    failure.existing_on_failed_after = 4;

    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailHost,
        vec![failure],
        SurvivingCapacity {
            cells_total: 1,
            cells_eligible: 1,
            hosts_total: 1,
            hosts_eligible: 0,
            existing_on_failed_domain: 4,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert!(!has_code(&report, "placement_to_unavailable"));
}

#[test]
fn regional_failover_and_recovery_resume() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let scheduler = RegionalScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), Arc::new(Hlc::new()));
    let mut cells = vec![
        make_cell("cel_a", CellHealth::Healthy),
        make_cell("cel_b", CellHealth::Healthy),
    ];

    cells[0].health = CellHealth::Unavailable;
    let fail = scheduler
        .schedule(&cell_request(), &cells)
        .expect("failover");
    assert_eq!(fail.cell_id.as_ref().map(|c| c.as_str()), Some("cel_b"));
    assert!(!fail.backpressure.should_throttle);

    cells[0].health = CellHealth::Healthy;
    let recovered = scheduler
        .schedule(&cell_request(), &cells)
        .expect("recover");
    assert!(recovered.scheduled);
    assert!(sink.len() >= 2);

    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.failed_cell_id = Some("cel_a".into());
    failure.offered = 1;
    failure.admitted = 1;
    failure.placements_on_surviving_domain = 1;
    failure.eligible_cells = 1;
    failure.total_cells = 2;
    failure.audit_events = 1;
    failure.existing_on_failed_before = 10;
    failure.existing_on_failed_after = 10;

    let mut recovery = AvailabilityObservation::at_epoch(AvailabilityEpoch::Recovery);
    recovery.offered = 1;
    recovery.admitted = 1;
    recovery.eligible_cells = 2;
    recovery.total_cells = 2;
    recovery.audit_events = 1;
    recovery.backlog_drained = false;

    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::Recover,
        vec![failure, recovery],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 2,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 10,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert!(!has_code(&report, "recovery_did_not_resume"));
    assert_eq!(
        class_of(&report, "audit_backlog_untested"),
        Some(FailureClass::C)
    );
}

#[test]
fn backpressure_throttles_when_few_cells_remain() {
    let scheduler = RegionalScheduler::new();
    let mut cells: Vec<CellInfo> = (0..10)
        .map(|i| make_cell(&format!("cel_{i}"), CellHealth::Healthy))
        .collect();
    for cell in cells.iter_mut().take(9) {
        cell.health = CellHealth::Unavailable;
    }
    let result = scheduler
        .schedule(&cell_request(), &cells)
        .expect("one eligible");
    assert!(result.backpressure.should_throttle);
    assert_eq!(result.backpressure.eligible_cells, 1);
    assert_eq!(result.cell_id.as_ref().map(|c| c.as_str()), Some("cel_9"));
}

#[test]
fn degraded_control_path_still_admits_existing_count_unchanged() {
    let scheduler = RegionalScheduler::new();
    let mut cell = make_cell("cel_a", CellHealth::Degraded);
    cell.capacity.current_sandboxes = 7;
    let existing = cell.capacity.current_sandboxes;
    let result = scheduler
        .schedule(&cell_request(), std::slice::from_ref(&cell))
        .expect("degraded admits");
    assert!(result.scheduled);
    assert_eq!(cell.capacity.current_sandboxes, existing);
}

#[test]
fn split_brain_is_class_a() {
    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.split_brain = true;
    failure.audit_events = 1;
    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 1,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 0,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert_eq!(class_of(&report, "split_brain"), Some(FailureClass::A));
}

#[test]
fn empty_series_is_class_a() {
    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![],
        SurvivingCapacity {
            cells_total: 0,
            cells_eligible: 0,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 0,
            new_placements_on_failed_domain: 0,
        },
    ));
    assert_eq!(class_of(&report, "no_measurements"), Some(FailureClass::A));
}

#[test]
fn report_json_roundtrip_and_markdown() {
    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.failed_cell_id = Some("cel_a".into());
    failure.offered = 1;
    failure.rejected = 1;
    failure.audit_events = 1;
    failure.eligible_cells = 0;
    failure.total_cells = 1;
    failure.throttle_honored = true;
    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 1,
            cells_eligible: 0,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 10,
            new_placements_on_failed_domain: 0,
        },
    ));
    let json = serde_json::to_string(&report).expect("json");
    let parsed: CellAvailabilityReport = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.scenario, AvailabilityScenario::FailCell);
    let md = report.to_markdown();
    assert!(md.contains("S-FAIL-CELL"));
    assert!(md.contains("Proposed LPOP: none"));
    assert!(!report.artifact_digest().is_empty());
    assert!(has_code(&report, "live_dashboard_not_exercised"));
    assert!(has_code(&report, "schedulers_not_on_create_path"));
}

#[test]
fn placement_to_unavailable_is_class_a() {
    let mut failure = AvailabilityObservation::at_epoch(AvailabilityEpoch::Failure);
    failure.placements_on_failed_domain = 2;
    failure.offered = 2;
    failure.admitted = 2;
    failure.audit_events = 1;
    let report = analyze_cell_availability(p0_input(
        AvailabilityScenario::FailCell,
        vec![failure],
        SurvivingCapacity {
            cells_total: 2,
            cells_eligible: 1,
            hosts_total: 0,
            hosts_eligible: 0,
            existing_on_failed_domain: 0,
            new_placements_on_failed_domain: 2,
        },
    ));
    assert_eq!(
        class_of(&report, "placement_to_unavailable"),
        Some(FailureClass::A)
    );
}

#[test]
fn empty_region_emits_reject_audit() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let scheduler = RegionalScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), Arc::new(Hlc::new()));
    assert!(scheduler.schedule(&cell_request(), &[]).is_err());
    let events = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(placement_candidates(&events), Some(0));
}

#[test]
fn reject_audit_counts_evaluated_hosts_not_eligible() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let scheduler = CellScheduler::new()
        .with_audit_sink(Arc::<InMemoryAuditSink>::clone(&sink), Arc::new(Hlc::new()));
    let hosts = vec![
        make_host("hst_1", HostHealth::Unavailable),
        make_host("hst_2", HostHealth::Unavailable),
        make_host("hst_3", HostHealth::Draining),
    ];
    assert!(scheduler.schedule(&host_request(), &hosts).is_err());
    let events = sink.events_by_kind(AuditEventKind::PlacementOutcome);
    assert_eq!(placement_candidates(&events), Some(3));
}

#[test]
fn host_health_quarantine_overlay_preserves_drain() {
    assert_eq!(
        HostHealth::Healthy.with_quarantine(true),
        HostHealth::Quarantined
    );
    assert_eq!(
        HostHealth::Draining.with_quarantine(true),
        HostHealth::Draining
    );
    assert_eq!(
        HostHealth::Healthy.with_quarantine(false),
        HostHealth::Healthy
    );
}
