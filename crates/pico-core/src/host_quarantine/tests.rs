use super::*;
use crate::identity::{CellId, HostId, RegionId};
use time::OffsetDateTime;

fn make_ids() -> (HostId, CellId, RegionId) {
    (
        HostId::from_string("hst_test01"),
        CellId::from_string("cel_us_east"),
        RegionId::from_string("rgn_us_east_1"),
    )
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// ================================================================
// Alert condition tests
// ================================================================

#[test]
fn alert_condition_as_str() {
    assert_eq!(
        AlertCondition::RepeatedRuntimeOutcomes.as_str(),
        "repeated_runtime_outcomes"
    );
    assert_eq!(
        AlertCondition::CleanupOrReconciliationIssue.as_str(),
        "cleanup_or_reconciliation_issue"
    );
    assert_eq!(AlertCondition::StaleResources.as_str(), "stale_resources");
    assert_eq!(
        AlertCondition::CapacityReportingStaleness.as_str(),
        "capacity_reporting_staleness"
    );
    assert_eq!(
        AlertCondition::ResourcePressure.as_str(),
        "resource_pressure"
    );
}

#[test]
fn alert_condition_recommended_action_is_non_empty() {
    for condition in &[
        AlertCondition::RepeatedRuntimeOutcomes,
        AlertCondition::CleanupOrReconciliationIssue,
        AlertCondition::StaleResources,
        AlertCondition::CapacityReportingStaleness,
        AlertCondition::ResourcePressure,
    ] {
        let action = condition.recommended_action();
        assert!(
            !action.is_empty(),
            "recommended_action empty for {condition:?}"
        );
    }
}

#[test]
fn alert_condition_default_severity() {
    assert_eq!(
        AlertCondition::RepeatedRuntimeOutcomes.default_severity(),
        AlertSeverity::Page
    );
    assert_eq!(
        AlertCondition::StaleResources.default_severity(),
        AlertSeverity::Page
    );
    assert_eq!(
        AlertCondition::CleanupOrReconciliationIssue.default_severity(),
        AlertSeverity::Quarantine
    );
    assert_eq!(
        AlertCondition::CapacityReportingStaleness.default_severity(),
        AlertSeverity::Quarantine
    );
    assert_eq!(
        AlertCondition::ResourcePressure.default_severity(),
        AlertSeverity::Drain
    );
}

// ================================================================
// Alert severity tests
// ================================================================

#[test]
fn alert_severity_as_str() {
    assert_eq!(AlertSeverity::Drain.as_str(), "drain");
    assert_eq!(AlertSeverity::Quarantine.as_str(), "quarantine");
    assert_eq!(AlertSeverity::Page.as_str(), "page");
}

#[test]
fn alert_severity_ordering() {
    assert!(AlertSeverity::Drain < AlertSeverity::Quarantine);
    assert!(AlertSeverity::Quarantine < AlertSeverity::Page);
}

#[test]
fn alert_severity_serde_roundtrip() {
    for severity in &[
        AlertSeverity::Drain,
        AlertSeverity::Quarantine,
        AlertSeverity::Page,
    ] {
        let json = serde_json::to_string(severity).unwrap();
        let back: AlertSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, severity);
    }
}

// ================================================================
// Alert condition serde tests
// ================================================================

#[test]
fn alert_condition_serde_roundtrip() {
    for condition in &[
        AlertCondition::RepeatedRuntimeOutcomes,
        AlertCondition::CleanupOrReconciliationIssue,
        AlertCondition::StaleResources,
        AlertCondition::CapacityReportingStaleness,
        AlertCondition::ResourcePressure,
    ] {
        let json = serde_json::to_string(condition).unwrap();
        let back: AlertCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, condition);
    }
}

// ================================================================
// HostAlert tests
// ================================================================

#[test]
fn host_alert_creation() {
    let (host_id, cell_id, region_id) = make_ids();
    let t = now();
    let alert = HostAlert::new(
        host_id.clone(),
        cell_id.clone(),
        region_id.clone(),
        AlertCondition::ResourcePressure,
        "cpu pressure at 0.95".into(),
        t,
    );

    assert_eq!(alert.host_id, host_id);
    assert_eq!(alert.cell_id, cell_id);
    assert_eq!(alert.region_id, region_id);
    assert_eq!(alert.condition, AlertCondition::ResourcePressure);
    assert_eq!(alert.severity, AlertSeverity::Drain);
    assert!(alert.is_active());
    assert!(!alert.acknowledged);
    assert!(alert.resolved_at.is_none());
    assert!(!alert.alert_id.is_empty());
    assert!(!alert.recommended_action.is_empty());
}

#[test]
fn host_alert_with_severity_override() {
    let (host_id, cell_id, region_id) = make_ids();
    let alert = HostAlert::new(
        host_id,
        cell_id,
        region_id,
        AlertCondition::ResourcePressure,
        "high pressure".into(),
        now(),
    )
    .with_severity(AlertSeverity::Page);

    assert_eq!(alert.severity, AlertSeverity::Page);
}

#[test]
fn host_alert_serde_roundtrip() {
    let (host_id, cell_id, region_id) = make_ids();
    let alert = HostAlert::new(
        host_id,
        cell_id,
        region_id,
        AlertCondition::RepeatedRuntimeOutcomes,
        "test alert".into(),
        now(),
    );

    let json = serde_json::to_string(&alert).unwrap();
    let back: HostAlert = serde_json::from_str(&json).unwrap();

    assert_eq!(back.host_id, alert.host_id);
    assert_eq!(back.condition, alert.condition);
    assert_eq!(back.severity, alert.severity);
    assert_eq!(back.reason, alert.reason);
    assert_eq!(back.alert_id, alert.alert_id);
}

#[test]
fn host_alert_is_active_returns_false_when_resolved() {
    let (host_id, cell_id, region_id) = make_ids();
    let mut alert = HostAlert::new(
        host_id,
        cell_id,
        region_id,
        AlertCondition::ResourcePressure,
        "test".into(),
        now(),
    );
    alert.resolved_at = Some(now());
    assert!(!alert.is_active());
}

// ================================================================
// AlertStateManager tests
// ================================================================

#[test]
fn manager_evaluates_runtime_failures() {
    let manager = AlertStateManager::new().with_runtime_outcome_threshold(3);
    let (host_id, cell_id, region_id) = make_ids();
    let t = now();

    let eval = HostAlertEvaluation::new().with_runtime_failures(5);

    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, t);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].condition, AlertCondition::RepeatedRuntimeOutcomes);
    assert_eq!(alerts[0].severity, AlertSeverity::Page);
}

#[test]
fn manager_evaluates_runtime_failures_below_threshold() {
    let manager = AlertStateManager::new().with_runtime_outcome_threshold(5);
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_runtime_failures(3);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert!(alerts.is_empty());
}

#[test]
fn manager_evaluates_cleanup_issues() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_cleanup_issues(true);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].condition,
        AlertCondition::CleanupOrReconciliationIssue
    );
    assert_eq!(alerts[0].severity, AlertSeverity::Quarantine);
}

#[test]
fn manager_evaluates_stale_resources() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].condition, AlertCondition::StaleResources);
    assert_eq!(alerts[0].severity, AlertSeverity::Page);
}

#[test]
fn manager_evaluates_capacity_staleness() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_capacity_staleness(300);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].condition,
        AlertCondition::CapacityReportingStaleness
    );
}

#[test]
fn manager_evaluates_resource_pressure() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_pressure(0.95, 0.92, 0.30, 0.20);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].condition, AlertCondition::ResourcePressure);
    assert_eq!(alerts[0].severity, AlertSeverity::Drain);
}

#[test]
fn manager_evaluates_resource_pressure_below_threshold() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_pressure(0.50, 0.60, 0.30, 0.20);
    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert!(alerts.is_empty());
}

#[test]
fn manager_evaluates_multiple_conditions() {
    let manager = AlertStateManager::new().with_runtime_outcome_threshold(3);
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new()
        .with_runtime_failures(5)
        .with_cleanup_issues(true)
        .with_stale_resources(true)
        .with_capacity_staleness(300)
        .with_pressure(0.95, 0.92, 0.93, 0.94);

    let alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());
    assert_eq!(alerts.len(), 5);
}

#[test]
fn manager_does_not_duplicate_already_active_alert() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    let t = now();

    let first_alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, t);
    assert_eq!(first_alerts.len(), 1);

    let second_alerts = manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, t);
    assert!(second_alerts.is_empty());
    assert_eq!(manager.active_count(), 1);
}

#[test]
fn manager_acknowledge_alert() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());

    assert!(manager.acknowledge(&host_id, AlertCondition::StaleResources));
    let alerts = manager.active_alerts_for_host(&host_id);
    assert!(alerts[0].acknowledged);
}

#[test]
fn manager_acknowledge_nonexistent_alert_returns_false() {
    let manager = AlertStateManager::new();
    let host_id = HostId::from_string("hst_unknown");
    assert!(!manager.acknowledge(&host_id, AlertCondition::StaleResources));
}

#[test]
fn manager_resolve_alert() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    let t = now();
    manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, t);

    assert!(manager.is_quarantined(&host_id));
    assert!(manager.resolve(&host_id, AlertCondition::StaleResources, t));
    assert!(!manager.is_quarantined(&host_id));
    assert_eq!(manager.active_count(), 0);
    assert_eq!(manager.resolved_count(), 1);
}

#[test]
fn manager_resolve_nonexistent_alert_returns_false() {
    let manager = AlertStateManager::new();
    let host_id = HostId::from_string("hst_unknown");
    assert!(!manager.resolve(&host_id, AlertCondition::StaleResources, now()));
}

#[test]
fn manager_is_quarantined() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();
    let other_host = HostId::from_string("hst_other");

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    manager.evaluate_host(&host_id, &cell_id, &region_id, &eval, now());

    assert!(manager.is_quarantined(&host_id));
    assert!(!manager.is_quarantined(&other_host));
}

#[test]
fn manager_quarantined_host_ids() {
    let manager = AlertStateManager::new();
    let h1 = HostId::from_string("hst_01");
    let h2 = HostId::from_string("hst_02");
    let c = CellId::from_string("cel_test");
    let r = RegionId::from_string("rgn_test");

    let eval1 = HostAlertEvaluation::new().with_stale_resources(true);
    let eval2 = HostAlertEvaluation::new().with_cleanup_issues(true);
    manager.evaluate_host(&h1, &c, &r, &eval1, now());
    manager.evaluate_host(&h2, &c, &r, &eval2, now());

    let ids = manager.quarantined_host_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().any(|id| id.as_str() == "hst_01"));
    assert!(ids.iter().any(|id| id.as_str() == "hst_02"));
}

#[test]
fn manager_quarantined_host_ids_deduplicates() {
    let manager = AlertStateManager::new();
    let host = HostId::from_string("hst_multi");
    let cell = CellId::from_string("cel_test");
    let region = RegionId::from_string("rgn_test");

    let eval = HostAlertEvaluation::new()
        .with_stale_resources(true)
        .with_cleanup_issues(true)
        .with_runtime_failures(7);
    manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert!(manager.is_quarantined(&host));
    assert_eq!(manager.quarantined_host_ids().len(), 1);
}

#[test]
fn manager_active_alerts_returns_all() {
    let manager = AlertStateManager::new();
    let h1 = HostId::from_string("hst_01");
    let h2 = HostId::from_string("hst_02");
    let c = CellId::from_string("cel_test");
    let r = RegionId::from_string("rgn_test");

    manager.evaluate_host(
        &h1,
        &c,
        &r,
        &HostAlertEvaluation::new().with_stale_resources(true),
        now(),
    );
    manager.evaluate_host(
        &h2,
        &c,
        &r,
        &HostAlertEvaluation::new().with_cleanup_issues(true),
        now(),
    );

    assert_eq!(manager.active_alerts().len(), 2);
}

#[test]
fn manager_active_alerts_for_host_filters_correctly() {
    let manager = AlertStateManager::new();
    let h1 = HostId::from_string("hst_01");
    let h2 = HostId::from_string("hst_02");
    let c = CellId::from_string("cel_test");
    let r = RegionId::from_string("rgn_test");

    manager.evaluate_host(
        &h1,
        &c,
        &r,
        &HostAlertEvaluation::new().with_stale_resources(true),
        now(),
    );
    manager.evaluate_host(
        &h2,
        &c,
        &r,
        &HostAlertEvaluation::new().with_cleanup_issues(true),
        now(),
    );

    let host1_alerts = manager.active_alerts_for_host(&h1);
    assert_eq!(host1_alerts.len(), 1);
    assert_eq!(host1_alerts[0].host_id, h1);
}

// ================================================================
// HostAlertEvaluation tests
// ================================================================

#[test]
fn evaluation_defaults_are_zero() {
    let eval = HostAlertEvaluation::default();
    assert_eq!(eval.consecutive_runtime_failures, 0);
    assert!(!eval.cleanup_issues_detected);
    assert!(!eval.stale_resources_detected);
    assert_eq!(eval.seconds_since_capacity_report, 0);
    assert_eq!(eval.cpu_pressure, 0.0);
    assert_eq!(eval.memory_pressure, 0.0);
    assert_eq!(eval.disk_pressure, 0.0);
    assert_eq!(eval.slot_pressure, 0.0);
}

#[test]
fn evaluation_builder_sets_all_fields() {
    let eval = HostAlertEvaluation::new()
        .with_runtime_failures(3)
        .with_cleanup_issues(true)
        .with_stale_resources(true)
        .with_capacity_staleness(180)
        .with_pressure(0.91, 0.92, 0.93, 0.94);

    assert_eq!(eval.consecutive_runtime_failures, 3);
    assert!(eval.cleanup_issues_detected);
    assert!(eval.stale_resources_detected);
    assert_eq!(eval.seconds_since_capacity_report, 180);
    assert_eq!(eval.cpu_pressure, 0.91);
    assert_eq!(eval.memory_pressure, 0.92);
    assert_eq!(eval.disk_pressure, 0.93);
    assert_eq!(eval.slot_pressure, 0.94);
}

// ================================================================
// Alert condition reason tests
// ================================================================

#[test]
fn alert_reason_includes_runtime_failure_count() {
    let (host_id, cell_id, region_id) = make_ids();
    let alert = HostAlert::new(
        host_id,
        cell_id,
        region_id,
        AlertCondition::RepeatedRuntimeOutcomes,
        "7 consecutive runtime failures detected".into(),
        now(),
    );
    assert!(alert.reason.contains("7"));
    assert!(alert.reason.contains("runtime"));
}

#[test]
fn alert_reason_includes_pressure_details() {
    let (host_id, cell_id, region_id) = make_ids();
    let alert = HostAlert::new(
        host_id,
        cell_id,
        region_id,
        AlertCondition::ResourcePressure,
        "resource pressure exceeded threshold: cpu=0.95, memory=0.92".into(),
        now(),
    );
    assert!(alert.reason.contains("cpu"));
    assert!(alert.reason.contains("memory"));
}

// ================================================================
// Synthetic alert tests (matching issue acceptance criteria)
// ================================================================

#[test]
fn synthetic_alert_runtime_outcomes() {
    let manager = AlertStateManager::new().with_runtime_outcome_threshold(5);
    let host = HostId::from_string("hst_syn_runtime");
    let cell = CellId::from_string("cel_syn");
    let region = RegionId::from_string("rgn_syn");

    let eval = HostAlertEvaluation::new().with_runtime_failures(7);
    let alerts = manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(alert.host_id.as_str(), "hst_syn_runtime");
    assert_eq!(alert.cell_id.as_str(), "cel_syn");
    assert_eq!(alert.region_id.as_str(), "rgn_syn");
    assert_eq!(alert.condition, AlertCondition::RepeatedRuntimeOutcomes);
    assert_eq!(alert.severity, AlertSeverity::Page);
    assert!(!alert.reason.is_empty());
    assert!(!alert.recommended_action.is_empty());
    assert!(alert.first_seen <= alert.last_seen);
}

#[test]
fn synthetic_alert_cleanup_reconciliation() {
    let manager = AlertStateManager::new();
    let host = HostId::from_string("hst_syn_cleanup");
    let cell = CellId::from_string("cel_syn");
    let region = RegionId::from_string("rgn_syn");

    let eval = HostAlertEvaluation::new().with_cleanup_issues(true);
    let alerts = manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(
        alert.condition,
        AlertCondition::CleanupOrReconciliationIssue
    );
    assert_eq!(alert.severity, AlertSeverity::Quarantine);
    assert!(alert.recommended_action.contains("reconciliation"));
}

#[test]
fn synthetic_alert_stale_resources() {
    let manager = AlertStateManager::new();
    let host = HostId::from_string("hst_syn_stale");
    let cell = CellId::from_string("cel_syn");
    let region = RegionId::from_string("rgn_syn");

    let eval = HostAlertEvaluation::new().with_stale_resources(true);
    let alerts = manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(alert.condition, AlertCondition::StaleResources);
    assert_eq!(alert.severity, AlertSeverity::Page);
}

#[test]
fn synthetic_alert_capacity_staleness() {
    let manager = AlertStateManager::new();
    let host = HostId::from_string("hst_syn_cap");
    let cell = CellId::from_string("cel_syn");
    let region = RegionId::from_string("rgn_syn");

    let eval = HostAlertEvaluation::new().with_capacity_staleness(600);
    let alerts = manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(alert.condition, AlertCondition::CapacityReportingStaleness);
    assert_eq!(alert.severity, AlertSeverity::Quarantine);
    assert!(alert.reason.contains("600"));
}

#[test]
fn synthetic_alert_resource_pressure() {
    let manager = AlertStateManager::new();
    let host = HostId::from_string("hst_syn_press");
    let cell = CellId::from_string("cel_syn");
    let region = RegionId::from_string("rgn_syn");

    let eval = HostAlertEvaluation::new().with_pressure(0.91, 0.92, 0.93, 0.94);
    let alerts = manager.evaluate_host(&host, &cell, &region, &eval, now());

    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(alert.condition, AlertCondition::ResourcePressure);
    assert_eq!(alert.severity, AlertSeverity::Drain);
}

// ================================================================
// Scheduler integration test: quarantined host exclusion
// ================================================================

#[test]
fn integration_quarantined_hosts_excluded_from_active_alerts() {
    let manager = AlertStateManager::new().with_runtime_outcome_threshold(3);
    let host = HostId::from_string("hst_quarantined");
    let cell = CellId::from_string("cel_test");
    let region = RegionId::from_string("rgn_test");
    let t = now();

    let eval = HostAlertEvaluation::new().with_runtime_failures(5);
    manager.evaluate_host(&host, &cell, &region, &eval, t);

    assert!(manager.is_quarantined(&host));
    assert!(!manager.is_quarantined(&HostId::from_string("hst_healthy")));

    let quarantined = manager.quarantined_host_ids();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].as_str(), "hst_quarantined");

    manager.resolve(&host, AlertCondition::RepeatedRuntimeOutcomes, t);
    assert!(!manager.is_quarantined(&host));
}

// ================================================================
// Alert auto-resolution test
// ================================================================

#[test]
fn integration_alert_auto_resolves_after_condition_clears() {
    let manager = AlertStateManager::new()
        .with_alert_auto_resolve_staleness_secs(5)
        .with_runtime_outcome_threshold(3);
    let host = HostId::from_string("hst_autoresolve");
    let cell = CellId::from_string("cel_test");
    let region = RegionId::from_string("rgn_test");
    let t = now();

    let eval = HostAlertEvaluation::new().with_runtime_failures(5);
    manager.evaluate_host(&host, &cell, &region, &eval, t);
    assert_eq!(manager.active_count(), 1);

    let later = t + time::Duration::seconds(60);
    let cleared = HostAlertEvaluation::new();
    manager.evaluate_host(&host, &cell, &region, &cleared, later);
    assert_eq!(manager.active_count(), 0);
    assert_eq!(manager.resolved_count(), 1);
}

// ================================================================
// Gauge metric tests
// ================================================================

#[test]
fn gauge_alerts_active_updated_after_evaluate() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();

    manager.evaluate_host(
        &host_id,
        &cell_id,
        &region_id,
        &HostAlertEvaluation::new()
            .with_stale_resources(true)
            .with_cleanup_issues(true),
        now(),
    );

    assert_eq!(manager.active_count(), 2);
}

#[test]
fn gauge_hosts_quarantined_tracks_unique_hosts() {
    let manager = AlertStateManager::new();
    let h1 = HostId::from_string("hst_a");
    let h2 = HostId::from_string("hst_b");
    let cell = CellId::from_string("cel_test");
    let region = RegionId::from_string("rgn_test");
    let t = now();

    manager.evaluate_host(
        &h1,
        &cell,
        &region,
        &HostAlertEvaluation::new().with_stale_resources(true),
        t,
    );
    manager.evaluate_host(
        &h2,
        &cell,
        &region,
        &HostAlertEvaluation::new().with_cleanup_issues(true),
        t,
    );

    assert_eq!(manager.quarantined_host_ids().len(), 2);
}

#[test]
fn gauge_cleared_after_resolve() {
    let manager = AlertStateManager::new();
    let (host_id, cell_id, region_id) = make_ids();
    let t = now();

    manager.evaluate_host(
        &host_id,
        &cell_id,
        &region_id,
        &HostAlertEvaluation::new().with_stale_resources(true),
        t,
    );
    assert_eq!(manager.active_count(), 1);

    manager.resolve(&host_id, AlertCondition::StaleResources, t);
    assert_eq!(manager.active_count(), 0);
    assert!(manager.quarantined_host_ids().is_empty());
}
