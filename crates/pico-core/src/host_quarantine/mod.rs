//! Host quarantine alerts and state management.
//!
//! The host quarantine system evaluates host health signals against defined
//! alert conditions and maps detected issues to actionable alerts with
//! severity levels. Quarantined hosts are excluded from scheduler placement
//! until the alert is resolved or acknowledged.
//!
//! # Typical usage
//!
//! ```rust
//! use pico_core::{AlertStateManager, HostAlertEvaluation};
//! use pico_core::identity::{HostId, CellId, RegionId};
//!
//! let manager = AlertStateManager::new()
//!     .with_runtime_outcome_threshold(5)
//!     .with_pressure_threshold(0.90);
//!
//! let host = HostId::from_string("hst_01");
//! let cell = CellId::from_string("cel_east");
//! let region = RegionId::from_string("rgn_us_east_1");
//!
//! // During each reconciliation/metrics collection cycle:
//! let eval = HostAlertEvaluation::new()
//!     .with_runtime_failures(3)
//!     .with_pressure(0.85, 0.70, 0.30, 0.20);
//! let new_alerts = manager.evaluate_host(&host, &cell, &region, &eval, time::OffsetDateTime::now_utc());
//!
//! // Then, in the scheduler placement path:
//! if manager.is_quarantined(&host) {
//!     // skip host for new sandbox placement
//! }
//! ```
//!
//! ## Design
//!
//! - [`AlertCondition`] enumerates the trigger categories (repeated runtime
//!   outcomes, cleanup/reconciliation drift, stale resources, capacity
//!   staleness, resource pressure).
//! - [`AlertSeverity`] maps conditions to operational actions: `Page` demands
//!   immediate human response, `Quarantine` stops new placement but defers
//!   paging, `Drain` allows draining existing workloads without paging.
//! - [`HostAlert`] carries alert identity, host/cell/region attribution, timing,
//!   and a recommended action string.
//! - [`AlertStateManager`] tracks active alerts, evaluates alert conditions,
//!   supports resolution, and emits metrics for observability.

pub mod metrics;

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use pico_telemetry::metrics::{Labels, attr};

use crate::identity::{CellId, HostId, RegionId};

use self::metrics::QUARANTINE_METRICS;

/// Operational severity of a host quarantine alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Low severity - drain existing workloads, avoid new placement, no page.
    Drain,
    /// Medium severity - quarantine host immediately, defer page to working hours.
    Quarantine,
    /// High severity - immediate page to on-call responder.
    Page,
}

impl AlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drain => "drain",
            Self::Quarantine => "quarantine",
            Self::Page => "page",
        }
    }
}

/// Conditions that can trigger a host quarantine alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertCondition {
    RepeatedRuntimeOutcomes,
    CleanupOrReconciliationIssue,
    StaleResources,
    CapacityReportingStaleness,
    ResourcePressure,
}

impl AlertCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RepeatedRuntimeOutcomes => "repeated_runtime_outcomes",
            Self::CleanupOrReconciliationIssue => "cleanup_or_reconciliation_issue",
            Self::StaleResources => "stale_resources",
            Self::CapacityReportingStaleness => "capacity_reporting_staleness",
            Self::ResourcePressure => "resource_pressure",
        }
    }

    fn recommended_action(self) -> &'static str {
        match self {
            Self::RepeatedRuntimeOutcomes => {
                "Inspect runtime logs and kernel output on host. Review recent sandbox lifecycle \
                 events. Check for hardware faults, kernel bugs, or runtime version mismatches. \
                 If isolated to a specific runtime or image, drain affected sandboxes and cordon \
                 host until root cause is confirmed."
            }
            Self::CleanupOrReconciliationIssue => {
                "Run reconciliation pass with --dry-run to inspect remaining resources. Check \
                 network agent and cgroup state for orphaned interfaces or controllers. If safe, \
                 run fenced cleanup; otherwise escalate to SRE for manual intervention."
            }
            Self::StaleResources => {
                "Identify ambiguous resources via sandboxd ledger and reconciliation output. \
                 Verify fencing tokens for affected sandboxes. If no live sandbox holds a valid \
                 lease, initiate garbage collection with operator approval. Escalate if resources \
                 span multiple hosts or cells."
            }
            Self::CapacityReportingStaleness => {
                "Check host-agent process health and connectivity to telemetry pipeline. Verify \
                 OTLP exporter is running and metrics-agent is forwarding. Restart host-agent if \
                 unresponsive; if metrics pipeline is broken, investigate collector or gateway \
                 health."
            }
            Self::ResourcePressure => {
                "Review host capacity allocation vs. actual usage. Consider draining low-priority \
                 sandboxes, scaling out the cell, or adjusting overcommit ratios. If pressure is \
                 sustained, add capacity before the host hits hard limits."
            }
        }
    }

    fn default_severity(self) -> AlertSeverity {
        match self {
            Self::RepeatedRuntimeOutcomes | Self::StaleResources => AlertSeverity::Page,
            Self::CleanupOrReconciliationIssue | Self::CapacityReportingStaleness => {
                AlertSeverity::Quarantine
            }
            Self::ResourcePressure => AlertSeverity::Drain,
        }
    }
}

/// A single host quarantine alert record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAlert {
    pub alert_id: String,
    pub host_id: HostId,
    pub cell_id: CellId,
    pub region_id: RegionId,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub reason: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub recommended_action: String,
    pub acknowledged: bool,
    pub resolved_at: Option<OffsetDateTime>,
}

impl HostAlert {
    pub fn new(
        host_id: HostId,
        cell_id: CellId,
        region_id: RegionId,
        condition: AlertCondition,
        reason: String,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            alert_id: crate::types::new_ulid("alert"),
            host_id,
            cell_id,
            region_id,
            condition,
            severity: condition.default_severity(),
            reason,
            first_seen: now,
            last_seen: now,
            recommended_action: condition.recommended_action().to_string(),
            acknowledged: false,
            resolved_at: None,
        }
    }

    pub fn with_severity(mut self, severity: AlertSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn is_active(&self) -> bool {
        self.resolved_at.is_none()
    }
}

/// Manages the lifecycle of host quarantine alerts.
pub struct AlertStateManager {
    active: RwLock<HashMap<(String, AlertCondition), HostAlert>>,
    resolved: RwLock<Vec<HostAlert>>,
    max_resolved: usize,
    resolve_retention_secs: i64,
    runtime_outcome_threshold: usize,
    pressure_threshold: f64,
    /// Duration after which a missing capacity report triggers a staleness alert.
    capacity_staleness_secs: i64,
    /// Duration after which an alert whose condition is no longer observed
    /// (last_seen is old) is auto-resolved. Separate from capacity staleness
    /// to avoid overloading the same knob.
    alert_auto_resolve_staleness_secs: i64,
}

impl AlertStateManager {
    pub fn new() -> Self {
        Self {
            active: RwLock::new(HashMap::new()),
            resolved: RwLock::new(Vec::new()),
            max_resolved: 1024,
            resolve_retention_secs: 3600,
            runtime_outcome_threshold: 5,
            pressure_threshold: 0.90,
            capacity_staleness_secs: 120,
            alert_auto_resolve_staleness_secs: 120,
        }
    }

    pub fn with_runtime_outcome_threshold(mut self, threshold: usize) -> Self {
        self.runtime_outcome_threshold = threshold;
        self
    }

    pub fn with_pressure_threshold(mut self, threshold: f64) -> Self {
        self.pressure_threshold = threshold;
        self
    }

    pub fn with_capacity_staleness_secs(mut self, secs: i64) -> Self {
        self.capacity_staleness_secs = secs;
        self
    }

    pub fn with_alert_auto_resolve_staleness_secs(mut self, secs: i64) -> Self {
        self.alert_auto_resolve_staleness_secs = secs;
        self
    }

    /// Evaluate a host against alert conditions and produce any new or
    /// updated alerts. Returns alerts that are newly fired or re-triggered.
    pub fn evaluate_host(
        &self,
        host_id: &HostId,
        cell_id: &CellId,
        region_id: &RegionId,
        eval: &HostAlertEvaluation,
        now: OffsetDateTime,
    ) -> Vec<HostAlert> {
        let mut new_alerts = Vec::new();
        let conditions = self.evaluate_conditions(eval);
        let mut active = self.active.write();

        for condition in conditions {
            let key = (host_id.as_str().to_string(), condition);
            if let Some(existing) = active.get_mut(&key) {
                existing.last_seen = now;
                if existing.is_active() {
                    continue;
                }
                existing.resolved_at = None;
            } else {
                let alert = HostAlert::new(
                    host_id.clone(),
                    cell_id.clone(),
                    region_id.clone(),
                    condition,
                    self.condition_reason(condition, eval),
                    now,
                );
                active.insert(key, alert.clone());
                new_alerts.push(alert.clone());
                QUARANTINE_METRICS.alerts_fired.inc(
                    &Labels::host()
                        .with(attr::HOST_ID, host_id.as_str())
                        .with(attr::SEVERITY, condition.default_severity().as_str())
                        .with(attr::CONDITION, condition.as_str()),
                );
            }
        }

        let stale_keys: Vec<(String, AlertCondition)> = active
            .iter()
            .filter(|(_, alert)| {
                alert.is_active()
                    && (now - alert.last_seen).whole_seconds()
                        > self.alert_auto_resolve_staleness_secs
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in stale_keys {
            if let Some(alert) = active.remove(&key) {
                let mut resolved_alert = alert;
                resolved_alert.resolved_at = Some(now);
                let mut resolved = self.resolved.write();
                resolved.push(resolved_alert);
                self.prune_resolved(&mut resolved, now);
                QUARANTINE_METRICS.alerts_resolved.inc(
                    &Labels::host()
                        .with(attr::HOST_ID, key.0.as_str())
                        .with(attr::CONDITION, key.1.as_str()),
                );
            }
        }

        self.refresh_gauges(&active);
        new_alerts
    }

    fn evaluate_conditions(&self, eval: &HostAlertEvaluation) -> Vec<AlertCondition> {
        let mut conditions = Vec::new();

        if eval.consecutive_runtime_failures >= self.runtime_outcome_threshold {
            conditions.push(AlertCondition::RepeatedRuntimeOutcomes);
        }

        if eval.cleanup_issues_detected {
            conditions.push(AlertCondition::CleanupOrReconciliationIssue);
        }

        if eval.stale_resources_detected {
            conditions.push(AlertCondition::StaleResources);
        }

        if eval.seconds_since_capacity_report > self.capacity_staleness_secs {
            conditions.push(AlertCondition::CapacityReportingStaleness);
        }

        if eval.cpu_pressure >= self.pressure_threshold
            || eval.memory_pressure >= self.pressure_threshold
            || eval.disk_pressure >= self.pressure_threshold
            || eval.slot_pressure >= self.pressure_threshold
        {
            conditions.push(AlertCondition::ResourcePressure);
        }

        conditions
    }

    fn condition_reason(&self, condition: AlertCondition, eval: &HostAlertEvaluation) -> String {
        match condition {
            AlertCondition::RepeatedRuntimeOutcomes => {
                format!(
                    "{} consecutive runtime failures detected",
                    eval.consecutive_runtime_failures
                )
            }
            AlertCondition::CleanupOrReconciliationIssue => {
                "cleanup or reconciliation issue detected".to_string()
            }
            AlertCondition::StaleResources => {
                "stale resources that cannot be safely removed".to_string()
            }
            AlertCondition::CapacityReportingStaleness => {
                format!(
                    "capacity report stale for {} seconds",
                    eval.seconds_since_capacity_report
                )
            }
            AlertCondition::ResourcePressure => {
                let mut pressures = Vec::new();
                if eval.cpu_pressure >= self.pressure_threshold {
                    pressures.push(format!("cpu={:.2}", eval.cpu_pressure));
                }
                if eval.memory_pressure >= self.pressure_threshold {
                    pressures.push(format!("memory={:.2}", eval.memory_pressure));
                }
                if eval.disk_pressure >= self.pressure_threshold {
                    pressures.push(format!("disk={:.2}", eval.disk_pressure));
                }
                if eval.slot_pressure >= self.pressure_threshold {
                    pressures.push(format!("slots={:.2}", eval.slot_pressure));
                }
                format!(
                    "resource pressure exceeded threshold: {}",
                    pressures.join(", ")
                )
            }
        }
    }

    fn prune_resolved(&self, resolved: &mut Vec<HostAlert>, now: OffsetDateTime) {
        if resolved.len() <= self.max_resolved {
            return;
        }
        resolved.sort_by_key(|a| a.resolved_at.unwrap_or(now));
        let cutoff = now - time::Duration::seconds(self.resolve_retention_secs);
        resolved.retain(|a| a.resolved_at.is_none_or(|r| r > cutoff));
        let excess = resolved.len().saturating_sub(self.max_resolved);
        if excess > 0 {
            resolved.drain(0..excess);
        }
    }

    fn refresh_gauges(&self, active: &HashMap<(String, AlertCondition), HostAlert>) {
        let active_count = active.len() as f64;
        QUARANTINE_METRICS
            .alerts_active
            .set(active_count, &Labels::host());

        let mut host_set: HashSet<&str> = HashSet::new();
        for (key, _) in active.iter() {
            host_set.insert(&key.0);
        }
        QUARANTINE_METRICS
            .hosts_quarantined
            .set(host_set.len() as f64, &Labels::host());
    }

    pub fn acknowledge(&self, host_id: &HostId, condition: AlertCondition) -> bool {
        let mut active = self.active.write();
        let key = (host_id.as_str().to_string(), condition);
        if let Some(alert) = active.get_mut(&key) {
            alert.acknowledged = true;
            self.refresh_gauges(&active);
            true
        } else {
            false
        }
    }

    pub fn resolve(
        &self,
        host_id: &HostId,
        condition: AlertCondition,
        now: OffsetDateTime,
    ) -> bool {
        let key = (host_id.as_str().to_string(), condition);
        let mut active = self.active.write();
        if let Some(alert) = active.remove(&key) {
            let mut resolved_alert = alert;
            resolved_alert.resolved_at = Some(now);
            let mut resolved = self.resolved.write();
            resolved.push(resolved_alert);
            self.prune_resolved(&mut resolved, now);
            QUARANTINE_METRICS.alerts_resolved.inc(
                &Labels::host()
                    .with(attr::HOST_ID, key.0.as_str())
                    .with(attr::CONDITION, key.1.as_str()),
            );
            self.refresh_gauges(&active);
            true
        } else {
            false
        }
    }

    pub fn active_alerts(&self) -> Vec<HostAlert> {
        self.active.read().values().cloned().collect()
    }

    pub fn active_alerts_for_host(&self, host_id: &HostId) -> Vec<HostAlert> {
        self.active
            .read()
            .iter()
            .filter(|((hid, _), _)| hid == host_id.as_str())
            .map(|(_, a)| a.clone())
            .collect()
    }

    pub fn is_quarantined(&self, host_id: &HostId) -> bool {
        self.active
            .read()
            .iter()
            .any(|((hid, _), _)| hid == host_id.as_str())
    }

    pub fn quarantined_host_ids(&self) -> Vec<HostId> {
        let active = self.active.read();
        let mut seen: HashSet<&str> = HashSet::new();
        active
            .keys()
            .filter(|(hid, _)| seen.insert(hid))
            .map(|(hid, _)| HostId::from_string(hid.as_str()))
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.active.read().len()
    }

    pub fn resolved_count(&self) -> usize {
        self.resolved.read().len()
    }
}

impl Default for AlertStateManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Input data for evaluating a host against alert conditions.
///
/// Decoupled from the scheduler's `HostInfo` so that alert evaluation
/// can be driven by metrics, reconciliation output, or synthetic test
/// fixtures without depending on the scheduler data model.
#[derive(Debug, Clone)]
pub struct HostAlertEvaluation {
    pub consecutive_runtime_failures: usize,
    pub cleanup_issues_detected: bool,
    pub stale_resources_detected: bool,
    pub seconds_since_capacity_report: i64,
    pub cpu_pressure: f64,
    pub memory_pressure: f64,
    pub disk_pressure: f64,
    pub slot_pressure: f64,
}

impl Default for HostAlertEvaluation {
    fn default() -> Self {
        Self {
            consecutive_runtime_failures: 0,
            cleanup_issues_detected: false,
            stale_resources_detected: false,
            seconds_since_capacity_report: 0,
            cpu_pressure: 0.0,
            memory_pressure: 0.0,
            disk_pressure: 0.0,
            slot_pressure: 0.0,
        }
    }
}

impl HostAlertEvaluation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runtime_failures(mut self, count: usize) -> Self {
        self.consecutive_runtime_failures = count;
        self
    }

    pub fn with_cleanup_issues(mut self, detected: bool) -> Self {
        self.cleanup_issues_detected = detected;
        self
    }

    pub fn with_stale_resources(mut self, detected: bool) -> Self {
        self.stale_resources_detected = detected;
        self
    }

    pub fn with_capacity_staleness(mut self, seconds: i64) -> Self {
        self.seconds_since_capacity_report = seconds;
        self
    }

    pub fn with_pressure(mut self, cpu: f64, memory: f64, disk: f64, slots: f64) -> Self {
        self.cpu_pressure = cpu;
        self.memory_pressure = memory;
        self.disk_pressure = disk;
        self.slot_pressure = slots;
        self
    }
}

#[cfg(test)]
mod tests;
