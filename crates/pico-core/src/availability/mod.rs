//! Cell and host unavailability validation (ST-CELL).
//!
//! Analyzes S-FAIL-HOST, S-FAIL-CELL, and S-RECOVER observations and emits
//! the report the load harness and rollout checklist
//! consume. P0 tests exercise the model with synthetic scheduler
//! snapshots. P1+ host/cell runs must feed the same
//! [`analyze_cell_availability`] seam.
//!
//! This module does not generate load and does not set a launch proven
//! operating point. P0/P1 reports never authorize regional quotas.
//! Schedulers never migrate or destroy running sandboxes; fencing and
//! orphan reconcile stay on the host-agent/sandboxd path.

use serde::{Deserialize, Serialize};

use crate::capacity::{CapacityFinding, CapacityScope, FailureClass, ValidationPhase};

/// ADR-0012 scenarios owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AvailabilityScenario {
    /// Drain or kill one host under MIX-AGENT-V1.
    #[serde(rename = "S-FAIL-HOST")]
    FailHost,
    /// Mark one cell unavailable under regional load.
    #[serde(rename = "S-FAIL-CELL")]
    FailCell,
    /// Restore the failed domain and drain backlog.
    #[serde(rename = "S-RECOVER")]
    Recover,
}

impl AvailabilityScenario {
    /// Scenario identifier used in evidence artifacts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailHost => "S-FAIL-HOST",
            Self::FailCell => "S-FAIL-CELL",
            Self::Recover => "S-RECOVER",
        }
    }
}

/// Window in a fail/recover drill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityEpoch {
    /// Healthy baseline before the injected fault.
    Pre,
    /// Fault is active.
    Failure,
    /// Failed domain restored.
    Recovery,
}

/// Dashboards, alerts, traces, and audit kinds operators must watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityEvidence {
    /// Grafana dashboard UIDs.
    pub dashboards: Vec<String>,
    /// Prometheus alert names.
    pub alerts: Vec<String>,
    /// Trace selectors (service/span/outcome).
    pub traces: Vec<String>,
    /// Audit event kinds.
    pub audit_kinds: Vec<String>,
}

impl ObservabilityEvidence {
    /// P0 evidence set. Live scrape is not required; names must match
    /// dashboards, recording rules, and the scheduling runbook.
    pub fn p0_required() -> Self {
        Self {
            dashboards: vec![
                "pico-scheduling-capacity".into(),
                "pico-host-health".into(),
                "pico-control-plane".into(),
                "pico-cleanup-reconciliation".into(),
                "pico-audit-telemetry".into(),
            ],
            alerts: vec![
                "PicoComputeHostQuarantined".into(),
                "PicoComputeCellCannotPlace".into(),
            ],
            traces: vec!["create outcome=placement_failed".into()],
            audit_kinds: vec!["placement_outcome".into()],
        }
    }

    fn is_complete(&self) -> bool {
        let required = Self::p0_required();
        contains_all(&self.dashboards, &required.dashboards)
            && contains_all(&self.alerts, &required.alerts)
            && contains_all(&self.traces, &required.traces)
            && contains_all(&self.audit_kinds, &required.audit_kinds)
    }
}

fn contains_all(haystack: &[String], needles: &[String]) -> bool {
    needles
        .iter()
        .all(|need| haystack.iter().any(|h| h == need))
}

/// Surviving placement capacity after a host or cell fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivingCapacity {
    /// Cells in the regional snapshot.
    pub cells_total: u64,
    /// Cells that still admit.
    pub cells_eligible: u64,
    /// Hosts in the cell snapshot.
    pub hosts_total: u64,
    /// Hosts that still admit.
    pub hosts_eligible: u64,
    /// Sandboxes already running on the failed domain.
    pub existing_on_failed_domain: u64,
    /// New placements that landed on the failed domain (must be 0).
    pub new_placements_on_failed_domain: u64,
}

/// One pre/failure/recovery sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AvailabilityObservation {
    /// Drill window this sample belongs to.
    pub epoch: AvailabilityEpoch,
    /// Cell marked unavailable or drained, if any.
    pub failed_cell_id: Option<String>,
    /// Host marked unavailable, drained, stale, or quarantined, if any.
    pub failed_host_id: Option<String>,
    /// Placement attempts offered in this window.
    pub offered: u64,
    /// Placement attempts admitted.
    pub admitted: u64,
    /// Admits that selected the failed cell or host.
    pub placements_on_failed_domain: u64,
    /// Admits that selected a surviving cell or host.
    pub placements_on_surviving_domain: u64,
    /// Hard rejects (`Err` or non-admitting filter).
    pub rejected: u64,
    /// Extra `schedule()` calls after reject. Any value above 0 is class-A.
    pub retries_after_reject: u64,
    /// Scheduler `should_throttle`, or true when `schedule()` returned `Err`.
    pub should_throttle: bool,
    /// Caller stopped offering load once shed was signaled.
    pub throttle_honored: bool,
    /// Running sandbox count on the failed domain before the sample.
    pub existing_on_failed_before: u64,
    /// Running sandbox count on the failed domain after the sample.
    pub existing_on_failed_after: u64,
    /// Host-agent fenced those sandboxes (not a scheduler action).
    pub fenced: bool,
    /// Split-brain metadata observed.
    pub split_brain: bool,
    /// Hosts removed by inventory TTL.
    pub stale_hosts_expired: u64,
    /// Active quarantine alerts after evaluation.
    pub quarantine_alerts: u64,
    /// `placement_outcome` audit events in this window.
    pub audit_events: u64,
    /// Cells that passed hard constraints.
    pub eligible_cells: u64,
    /// Cells evaluated.
    pub total_cells: u64,
    /// Hosts that passed hard constraints.
    pub eligible_hosts: u64,
    /// Hosts evaluated.
    pub total_hosts: u64,
    /// Audit/telemetry backlog drained after recovery.
    pub backlog_drained: bool,
}

impl AvailabilityObservation {
    /// Empty sample for `epoch` with no failed domain.
    pub fn at_epoch(epoch: AvailabilityEpoch) -> Self {
        Self {
            epoch,
            failed_cell_id: None,
            failed_host_id: None,
            offered: 0,
            admitted: 0,
            placements_on_failed_domain: 0,
            placements_on_surviving_domain: 0,
            rejected: 0,
            retries_after_reject: 0,
            should_throttle: false,
            throttle_honored: true,
            existing_on_failed_before: 0,
            existing_on_failed_after: 0,
            fenced: false,
            split_brain: false,
            stale_hosts_expired: 0,
            quarantine_alerts: 0,
            audit_events: 0,
            eligible_cells: 0,
            total_cells: 0,
            eligible_hosts: 0,
            total_hosts: 0,
            backlog_drained: false,
        }
    }
}

/// Input to [`analyze_cell_availability`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellAvailabilityInput {
    /// Scenario under test.
    pub scenario: AvailabilityScenario,
    /// Validation phase. P0/P1 must not set an LPOP.
    pub phase: ValidationPhase,
    /// Aggregation scope.
    pub scope: CapacityScope,
    /// Ordered pre/failure/recovery samples.
    pub observations: Vec<AvailabilityObservation>,
    /// Named dashboards, alerts, traces, and audit kinds.
    pub observability: ObservabilityEvidence,
    /// True when Grafana/alertmanager were scraped in this run.
    pub live_observability: bool,
    /// True when host-agent fencing was actually observed.
    pub measured_fencing: bool,
    /// True when orphan reconcile was actually observed.
    pub measured_orphan_reconcile: bool,
    /// Surviving capacity after the fault.
    pub surviving: SurvivingCapacity,
}

/// Availability report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellAvailabilityReport {
    /// Scenario under test.
    pub scenario: AvailabilityScenario,
    /// Validation phase.
    pub phase: ValidationPhase,
    /// Aggregation scope.
    pub scope: CapacityScope,
    /// Surviving capacity after the fault.
    pub surviving: SurvivingCapacity,
    /// Always `None` before P2.
    pub proposed_lpop: Option<u64>,
    /// Class-A/B/C findings.
    pub findings: Vec<CapacityFinding>,
    /// Echo of input samples.
    pub observations: Vec<AvailabilityObservation>,
    /// Operator evidence names.
    pub observability: ObservabilityEvidence,
}

impl CellAvailabilityReport {
    /// Content digest of the report JSON (hex-encoded blake3).
    pub fn artifact_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Short Markdown summary for the evidence bundle.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Cell unavailability report\n\n");
        out.push_str(&format!(
            "- Scenario: {}\n- Phase: {:?}\n- Scope: {:?}\n",
            self.scenario.as_str(),
            self.phase,
            self.scope
        ));
        out.push_str(&format!(
            "- Eligible cells: {}/{}\n- Eligible hosts: {}/{}\n- Existing on failed domain: {}\n- New placements on failed domain: {}\n- Proposed LPOP: {}\n",
            self.surviving.cells_eligible,
            self.surviving.cells_total,
            self.surviving.hosts_eligible,
            self.surviving.hosts_total,
            self.surviving.existing_on_failed_domain,
            self.surviving.new_placements_on_failed_domain,
            self.proposed_lpop
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into())
        ));
        if self.findings.is_empty() {
            out.push_str("- Findings: none\n");
        } else {
            out.push_str("- Findings:\n");
            for finding in &self.findings {
                out.push_str(&format!(
                    "  - class {:?}: {} ({})\n",
                    finding.class, finding.code, finding.detail
                ));
            }
        }
        out
    }
}

fn finding(class: FailureClass, code: &str, detail: impl Into<String>) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: None,
    }
}

fn finding_follow(
    class: FailureClass,
    code: &str,
    detail: impl Into<String>,
    issue: &str,
) -> CapacityFinding {
    CapacityFinding {
        class,
        code: code.into(),
        detail: detail.into(),
        follow_up_issue: Some(issue.into()),
    }
}

/// Classify a fail/recover series and emit findings plus surviving capacity.
pub fn analyze_cell_availability(input: CellAvailabilityInput) -> CellAvailabilityReport {
    let mut findings = Vec::new();
    if input.observations.is_empty() {
        findings.push(finding(
            FailureClass::A,
            "no_measurements",
            "availability report has no observations",
        ));
    }

    if !input.phase.may_set_lpop() {
        findings.push(finding(
            FailureClass::C,
            "phase_cannot_set_lpop",
            format!(
                "{:?} may not set an LPOP; surviving capacity is a candidate input only",
                input.phase
            ),
        ));
    }

    if input.surviving.new_placements_on_failed_domain > 0 {
        findings.push(finding(
            FailureClass::A,
            "placement_to_unavailable",
            format!(
                "{} new placements landed on the failed domain",
                input.surviving.new_placements_on_failed_domain
            ),
        ));
    }

    for obs in &input.observations {
        if obs.placements_on_failed_domain > 0 && obs.epoch == AvailabilityEpoch::Failure {
            findings.push(finding(
                FailureClass::A,
                "placement_to_unavailable",
                format!(
                    "failure window placed {} onto the failed domain",
                    obs.placements_on_failed_domain
                ),
            ));
        }
        if obs.split_brain {
            findings.push(finding(
                FailureClass::A,
                "split_brain",
                "split-brain metadata observed during the drill",
            ));
        }
        if obs.retries_after_reject > 0 {
            findings.push(finding(
                FailureClass::A,
                "uncontrolled_retry",
                format!(
                    "{} extra schedule() calls after reject; shed instead of retry",
                    obs.retries_after_reject
                ),
            ));
        }
        if obs.epoch == AvailabilityEpoch::Failure
            && obs.existing_on_failed_after != obs.existing_on_failed_before
            && !obs.fenced
        {
            findings.push(finding(
                FailureClass::A,
                "existing_sandbox_mutated",
                "running sandbox count on the failed domain changed without fencing",
            ));
        }
        if obs.epoch == AvailabilityEpoch::Failure
            && obs.eligible_cells == 0
            && obs.total_cells > 0
            && obs.offered > 0
            && obs.admitted > 0
        {
            findings.push(finding(
                FailureClass::A,
                "admitted_with_no_eligible_cell",
                "regional scheduler admitted work with zero eligible cells",
            ));
        }
        if obs.epoch == AvailabilityEpoch::Failure
            && obs.eligible_hosts == 0
            && obs.total_hosts > 0
            && obs.offered > 0
            && obs.admitted > 0
            && matches!(input.scenario, AvailabilityScenario::FailHost)
        {
            findings.push(finding(
                FailureClass::A,
                "admitted_with_no_eligible_host",
                "cell scheduler admitted work with zero eligible hosts",
            ));
        }
        if obs.epoch == AvailabilityEpoch::Failure
            && obs.audit_events == 0
            && (obs.admitted > 0 || obs.rejected > 0)
        {
            findings.push(finding_follow(
                FailureClass::B,
                "audit_missing_on_placement",
                "placement window emitted no placement_outcome audit events",
                "64",
            ));
        }
    }

    let failure = input
        .observations
        .iter()
        .find(|obs| obs.epoch == AvailabilityEpoch::Failure);
    let recovery = input
        .observations
        .iter()
        .find(|obs| obs.epoch == AvailabilityEpoch::Recovery);

    if matches!(
        input.scenario,
        AvailabilityScenario::FailCell | AvailabilityScenario::FailHost
    ) && let Some(obs) = failure
        && obs.eligible_cells + obs.eligible_hosts > 0
        && obs.offered > 0
        && obs.placements_on_surviving_domain == 0
        && obs.rejected == 0
    {
        findings.push(finding(
            FailureClass::A,
            "failover_did_not_shift",
            "surviving capacity existed but no placement shifted to it",
        ));
    }

    if matches!(input.scenario, AvailabilityScenario::Recover) {
        if recovery.is_none() {
            findings.push(finding(
                FailureClass::A,
                "recovery_window_missing",
                "S-RECOVER has no recovery observation",
            ));
        } else if let Some(obs) = recovery
            && obs.offered > 0
            && obs.admitted == 0
            && (obs.eligible_cells > 0 || obs.eligible_hosts > 0)
        {
            findings.push(finding(
                FailureClass::A,
                "recovery_did_not_resume",
                "restored domain did not admit new placements",
            ));
        }
        if let Some(obs) = recovery
            && !obs.backlog_drained
        {
            findings.push(finding_follow(
                FailureClass::C,
                "audit_backlog_untested",
                "S-RECOVER did not measure SLO-AUDIT-LAG drain",
                "22",
            ));
        }
    }

    if !input.measured_fencing {
        findings.push(finding_follow(
            FailureClass::C,
            "fencing_untested",
            "existing sandboxes stay until host-agent fence/drain; not measured in this run",
            "64",
        ));
    }
    if !input.measured_orphan_reconcile {
        findings.push(finding_follow(
            FailureClass::C,
            "orphan_reconcile_untested",
            "orphan reconcile after cell/host loss is not measured in this run",
            "64",
        ));
    }
    if !input.live_observability {
        findings.push(finding(
            FailureClass::C,
            "live_dashboard_not_exercised",
            "named dashboards and alerts are the operator evidence set; live scrape was not run",
        ));
    }
    if !input.observability.is_complete() {
        findings.push(finding(
            FailureClass::B,
            "observability_evidence_incomplete",
            "report is missing a required dashboard, alert, trace, or audit kind",
        ));
    }

    findings.push(finding_follow(
        FailureClass::C,
        "schedulers_not_on_create_path",
        "API create does not yet call RegionalScheduler/CellScheduler",
        "130",
    ));

    dedupe_findings(&mut findings);

    CellAvailabilityReport {
        scenario: input.scenario,
        phase: input.phase,
        scope: input.scope,
        surviving: input.surviving,
        proposed_lpop: None,
        findings,
        observations: input.observations,
        observability: input.observability,
    }
}

fn dedupe_findings(findings: &mut Vec<CapacityFinding>) {
    let mut seen = Vec::new();
    findings.retain(|finding| {
        let key = (finding.class, finding.code.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

#[cfg(test)]
mod tests;
