//! Ordered sequence validator for the RR-01 emergency drain, revoke,
//! rebuild, and patch exercise (G-16).
//!
//! The mechanical cordon/drain/rebuild/re-admit path lives in the
//! host-rebuild runbook. This module encodes the emergency ordering on top
//! of it so a drill or test can prove the sequence ran in order, with
//! ticket evidence, audit IDs, timings, boundary validation for the exact
//! profile, and no identity or address reuse before absence is proven.
//!
//! Design notes:
//! - Validation only. This module performs no RPC, no mutation, and no
//!   ledger writes. Callers record the returned state in the incident
//!   ticket and the durable audit store.
//! - Stages advance one step at a time with monotonic timestamps.
//!   Skipping a stage fails closed.
//! - Rebuild cites the approved pipeline build and pinned digest. Patch
//!   triage itself stays with the vulnerability response path.
//! - Verify requires a passing isolation boundary suite for the exact
//!   profile. A failed suite keeps the host out of placement.
//! - Re-admit reuses [`crate::operator::validate_readmit`] so both paths
//!   share one gate.
//! - Retired sandbox identities and network addresses become reusable
//!   only after absence is proven. Reuse before proof fails closed.
//!
//! ```rust
//! use pico_core::EmergencyExercise;
//! use pico_core::ReadmitChecks;
//!
//! let mut exercise = EmergencyExercise::begin("INC-1", "hst_01", "cel_east", "region_test", "SYNTH-ADV-01")
//!     .expect("valid exercise");
//! exercise.record_cordon(2, vec!["host_disabled:evt-1".to_string()]).expect("cordon");
//! exercise.record_drain(12, vec!["host_disabled:evt-2".to_string()]).expect("drain");
//! exercise.record_revoke(17, vec!["LeaseRevoked:evt-3".to_string()]).expect("revoke");
//! exercise.freeze_evidence(19, vec!["cleanup_disposition:evt-4".to_string()]).expect("freeze");
//! exercise.record_rebuild(49, "build-2026-09-22", "sha256:good", vec!["placement_outcome:evt-5".to_string()]).expect("rebuild");
//! exercise.record_verify(59, "firecracker-linux-kvm-2026-09-22", true, vec!["runtime_outcome:evt-6".to_string()]).expect("verify");
//! let checks = ReadmitChecks {
//!     quarantine_gauge_zero: true,
//!     capacity_age_secs: 12,
//!     health_admitting: true,
//!     reconciliation_clean: true,
//!     five_minute_watch_clean: true,
//! };
//! exercise.record_readmit(64, &checks, vec!["lifecycle_transition:evt-7".to_string()]).expect("readmit");
//! assert!(exercise.missing_evidence().is_empty());
//! ```

use crate::operator::{ReadmitChecks, validate_readmit, validate_ticket};

/// Ordered stages of the emergency exercise.
///
/// Each stage maps to a host-rebuild runbook step plus the advisory and
/// boundary-validation steps the residual-risk exercise owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyStage {
    /// Simulated critical host advisory triaged with ticket and scope.
    AdvisoryTriaged,
    /// Host excluded from scheduler placement.
    Cordoned,
    /// Running sandboxes drained or completed, count at zero or window expired.
    Drained,
    /// Sandbox and egress leases revoked with operation identity.
    Revoked,
    /// Audit and receipt evidence pinned in the ticket.
    EvidenceFrozen,
    /// Host rebuilt from the approved pipeline build and digest.
    Rebuilt,
    /// Isolation boundary suite passed for the exact profile.
    Verified,
    /// Re-admit gates passed with the 5m watch clean.
    Readmitted,
    /// Tenant notice sent and ticket closed with full timings.
    Closed,
}

impl EmergencyStage {
    /// Returns the stable stage name used in tickets and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdvisoryTriaged => "advisory-triaged",
            Self::Cordoned => "cordoned",
            Self::Drained => "drained",
            Self::Revoked => "revoked",
            Self::EvidenceFrozen => "evidence-frozen",
            Self::Rebuilt => "rebuilt",
            Self::Verified => "verified",
            Self::Readmitted => "readmitted",
            Self::Closed => "closed",
        }
    }

    /// Returns the next stage in the required order, or `None` when closed.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::AdvisoryTriaged => Some(Self::Cordoned),
            Self::Cordoned => Some(Self::Drained),
            Self::Drained => Some(Self::Revoked),
            Self::Revoked => Some(Self::EvidenceFrozen),
            Self::EvidenceFrozen => Some(Self::Rebuilt),
            Self::Rebuilt => Some(Self::Verified),
            Self::Verified => Some(Self::Readmitted),
            Self::Readmitted => Some(Self::Closed),
            Self::Closed => None,
        }
    }
}

/// Sequence failures for the emergency exercise.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmergencyError {
    /// Ticket, host, cell, region, or advisory reference is missing or invalid.
    #[error("invalid exercise scope: {reason}")]
    InvalidScope {
        /// Which scope field was rejected and why.
        reason: String,
    },
    /// A stage was attempted out of order.
    #[error("out of order: expected {expected}, got {got}")]
    OutOfOrder {
        /// Stage the exercise is waiting for.
        expected: String,
        /// Stage that was attempted.
        got: String,
    },
    /// Timestamp moved backwards.
    #[error("stale timestamp: {got}s precedes {last}s")]
    StaleTimestamp {
        /// Last recorded timestamp in seconds.
        last: u64,
        /// Attempted timestamp in seconds.
        got: u64,
    },
    /// A stage recorded no audit event IDs.
    #[error("stage {stage} needs at least one audit event ID")]
    MissingAudit {
        /// Stage that lacked audit evidence.
        stage: String,
    },
    /// Rebuild cited no approved build or digest.
    #[error("rebuild needs an approved build and pinned digest")]
    MissingBuild,
    /// Verify lacked an exact profile or a passing suite.
    #[error("verify needs a passing isolation boundary suite for the exact profile")]
    BoundarySuiteFailed,
    /// Re-admit gates failed; the reason comes from the shared gate.
    #[error("re-admit blocked: {reason}")]
    ReadmitBlocked {
        /// Which gate failed and why.
        reason: String,
    },
    /// Identity or address reuse was attempted before absence was proven.
    #[error("reuse before absence proof for {value}")]
    ReuseBeforeAbsence {
        /// Identity or address value that is not yet reusable.
        value: String,
    },
    /// Evidence is incomplete; the listed audit kinds are missing.
    #[error("incomplete evidence, missing: {missing}")]
    IncompleteEvidence {
        /// Comma-separated missing audit kinds.
        missing: String,
    },
}

impl From<crate::operator::OperatorError> for EmergencyError {
    fn from(err: crate::operator::OperatorError) -> Self {
        Self::InvalidScope {
            reason: err.to_string(),
        }
    }
}

/// Audit evidence kinds the exercise requires at close.
pub const REQUIRED_DRAIN_AUDIT_KIND: &str = "host_disabled";
/// Audit kind proving leases were revoked with operation identity.
pub const REQUIRED_REVOKE_AUDIT_KIND: &str = "LeaseRevoked";
/// Audit kind proving the rebuild placement outcome was recorded.
pub const REQUIRED_REBUILD_AUDIT_KIND: &str = "placement_outcome";

/// Ordered validator for one emergency exercise run.
#[derive(Debug, Clone)]
pub struct EmergencyExercise {
    ticket: String,
    host: String,
    cell: String,
    region: String,
    advisory_id: String,
    stage: EmergencyStage,
    /// Elapsed seconds since exercise start, per completed stage.
    timestamps: Vec<(EmergencyStage, u64)>,
    /// Recorded `(kind, id)` audit pairs. The kind is the prefix before
    /// the first `:` in the recorded string, or the full string.
    audit_ids: Vec<(String, String)>,
    build: Option<String>,
    digest: Option<String>,
    profile: Option<String>,
    boundary_suite_passed: bool,
    retired: Vec<String>,
    absence_proven: Vec<String>,
}

impl EmergencyExercise {
    /// Starts an exercise for a simulated critical host advisory.
    ///
    /// All scope fields must be non-blank; the ticket follows the shared
    /// operator ticket rules. Timestamps start at 0 for the triage stage.
    pub fn begin(
        ticket: &str,
        host: &str,
        cell: &str,
        region: &str,
        advisory_id: &str,
    ) -> Result<Self, EmergencyError> {
        let validated = validate_ticket(ticket)?;
        for (name, value) in [
            ("host", host),
            ("cell", cell),
            ("region", region),
            ("advisory", advisory_id),
        ] {
            if value.trim().is_empty() {
                return Err(EmergencyError::InvalidScope {
                    reason: format!("{name} is required"),
                });
            }
        }
        Ok(Self {
            ticket: validated.id().to_string(),
            host: host.trim().to_string(),
            cell: cell.trim().to_string(),
            region: region.trim().to_string(),
            advisory_id: advisory_id.trim().to_string(),
            stage: EmergencyStage::AdvisoryTriaged,
            timestamps: vec![(EmergencyStage::AdvisoryTriaged, 0)],
            audit_ids: Vec::new(),
            build: None,
            digest: None,
            profile: None,
            boundary_suite_passed: false,
            retired: Vec::new(),
            absence_proven: Vec::new(),
        })
    }

    /// Returns the incident ticket that owns this exercise.
    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    /// Returns the current stage.
    pub fn stage(&self) -> EmergencyStage {
        self.stage
    }

    /// Returns the host under exercise.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the cell under exercise.
    pub fn cell(&self) -> &str {
        &self.cell
    }

    /// Returns the region under exercise.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the advisory under exercise.
    pub fn advisory_id(&self) -> &str {
        &self.advisory_id
    }

    fn advance(
        &mut self,
        expected: EmergencyStage,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        let next = self
            .stage
            .next()
            .ok_or_else(|| EmergencyError::OutOfOrder {
                expected: "closed (terminal)".to_string(),
                got: expected.as_str().to_string(),
            })?;
        if next != expected {
            return Err(EmergencyError::OutOfOrder {
                expected: next.as_str().to_string(),
                got: expected.as_str().to_string(),
            });
        }
        let last = self.timestamps.last().map(|(_, t)| *t).unwrap_or(0);
        if elapsed_secs < last {
            return Err(EmergencyError::StaleTimestamp {
                last,
                got: elapsed_secs,
            });
        }
        if audit_ids.is_empty() {
            return Err(EmergencyError::MissingAudit {
                stage: expected.as_str().to_string(),
            });
        }
        for id in audit_ids {
            let kind = id.split(':').next().unwrap_or(&id).to_string();
            self.audit_ids.push((kind, id));
        }
        self.timestamps.push((expected, elapsed_secs));
        self.stage = expected;
        Ok(())
    }

    /// Records scheduler exclusion for the host.
    pub fn record_cordon(
        &mut self,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        self.advance(EmergencyStage::Cordoned, elapsed_secs, audit_ids)
    }

    /// Records drain completion for the host.
    pub fn record_drain(
        &mut self,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        self.advance(EmergencyStage::Drained, elapsed_secs, audit_ids)
    }

    /// Records lease and credential revocation with operation identity.
    pub fn record_revoke(
        &mut self,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        self.advance(EmergencyStage::Revoked, elapsed_secs, audit_ids)
    }

    /// Records the evidence-freeze step.
    pub fn freeze_evidence(
        &mut self,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        self.advance(EmergencyStage::EvidenceFrozen, elapsed_secs, audit_ids)
    }

    /// Records a rebuild from the approved pipeline build and digest.
    pub fn record_rebuild(
        &mut self,
        elapsed_secs: u64,
        build: &str,
        digest: &str,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        if build.trim().is_empty() || digest.trim().is_empty() {
            return Err(EmergencyError::MissingBuild);
        }
        self.advance(EmergencyStage::Rebuilt, elapsed_secs, audit_ids)?;
        self.build = Some(build.trim().to_string());
        self.digest = Some(digest.trim().to_string());
        Ok(())
    }

    /// Records boundary validation for the exact profile.
    ///
    /// `suite_passed` must be true and `profile` must name the exact
    /// deployment profile under test. A failed suite keeps the host out
    /// of placement.
    pub fn record_verify(
        &mut self,
        elapsed_secs: u64,
        profile: &str,
        suite_passed: bool,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        if profile.trim().is_empty() || !suite_passed {
            return Err(EmergencyError::BoundarySuiteFailed);
        }
        self.advance(EmergencyStage::Verified, elapsed_secs, audit_ids)?;
        self.profile = Some(profile.trim().to_string());
        self.boundary_suite_passed = true;
        Ok(())
    }

    /// Records re-admit through the shared re-admit gates.
    pub fn record_readmit(
        &mut self,
        elapsed_secs: u64,
        checks: &ReadmitChecks,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        validate_readmit(checks).map_err(|e| EmergencyError::ReadmitBlocked {
            reason: e.to_string(),
        })?;
        self.advance(EmergencyStage::Readmitted, elapsed_secs, audit_ids)
    }

    /// Closes the exercise after tenant notice and the full record.
    pub fn close(
        &mut self,
        elapsed_secs: u64,
        audit_ids: Vec<String>,
    ) -> Result<(), EmergencyError> {
        let missing = self.missing_evidence();
        if !missing.is_empty() {
            return Err(EmergencyError::IncompleteEvidence {
                missing: missing.join(","),
            });
        }
        self.advance(EmergencyStage::Closed, elapsed_secs, audit_ids)
    }

    /// Retires a sandbox identity or network address at revoke time.
    ///
    /// Retired values stay non-reusable until [`Self::prove_absence`]
    /// records absence proof.
    pub fn retire(&mut self, value: &str) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() && !self.retired.contains(&trimmed) {
            self.retired.push(trimmed);
        }
    }

    /// Records absence proof for a retired identity or address.
    pub fn prove_absence(&mut self, value: &str) {
        let trimmed = value.trim().to_string();
        if self.retired.contains(&trimmed) && !self.absence_proven.contains(&trimmed) {
            self.absence_proven.push(trimmed);
        }
    }

    /// Returns true when a value may be reused after absence proof.
    pub fn is_reusable(&self, value: &str) -> bool {
        let trimmed = value.trim();
        if !self.retired.iter().any(|r| r == trimmed) {
            return true;
        }
        self.absence_proven.iter().any(|a| a == trimmed)
    }

    /// Checks reuse before absence proof and fails closed.
    pub fn check_reuse(&self, value: &str) -> Result<(), EmergencyError> {
        if self.is_reusable(value) {
            Ok(())
        } else {
            Err(EmergencyError::ReuseBeforeAbsence {
                value: value.trim().to_string(),
            })
        }
    }

    /// Returns the elapsed seconds recorded for a stage, if completed.
    pub fn timestamp_for(&self, stage: EmergencyStage) -> Option<u64> {
        self.timestamps
            .iter()
            .find(|(s, _)| *s == stage)
            .map(|(_, t)| *t)
    }

    /// Returns time-to-drain: cordon to drain completion in seconds.
    pub fn time_to_drain_secs(&self) -> Option<u64> {
        match (
            self.timestamp_for(EmergencyStage::Cordoned),
            self.timestamp_for(EmergencyStage::Drained),
        ) {
            (Some(cordon), Some(drain)) => drain.checked_sub(cordon),
            _ => None,
        }
    }

    /// Returns time-to-rebuild: drain completion to rebuild in seconds.
    pub fn time_to_rebuild_secs(&self) -> Option<u64> {
        match (
            self.timestamp_for(EmergencyStage::Drained),
            self.timestamp_for(EmergencyStage::Rebuilt),
        ) {
            (Some(drain), Some(rebuilt)) => rebuilt.checked_sub(drain),
            _ => None,
        }
    }

    /// Lists required audit kinds still missing from the record.
    ///
    /// Returns an empty list when evidence is complete.
    pub fn missing_evidence(&self) -> Vec<String> {
        let mut missing = Vec::new();
        let kinds: Vec<&str> = self.audit_ids.iter().map(|(k, _)| k.as_str()).collect();
        if !kinds.contains(&REQUIRED_DRAIN_AUDIT_KIND) {
            missing.push(REQUIRED_DRAIN_AUDIT_KIND.to_string());
        }
        if !kinds.contains(&REQUIRED_REVOKE_AUDIT_KIND) {
            missing.push(REQUIRED_REVOKE_AUDIT_KIND.to_string());
        }
        if !kinds.contains(&REQUIRED_REBUILD_AUDIT_KIND) {
            missing.push(REQUIRED_REBUILD_AUDIT_KIND.to_string());
        }
        if self.build.is_none() || self.digest.is_none() {
            missing.push("approved-build".to_string());
        }
        if !self.boundary_suite_passed || self.profile.is_none() {
            missing.push("boundary-suite".to_string());
        }
        missing
    }

    /// Returns a one-line summary for the ticket and drill record.
    pub fn summary(&self) -> String {
        format!(
            "ticket={} host={} cell={} region={} advisory={} stage={} drain={:?} rebuild={:?} missing={}",
            self.ticket,
            self.host,
            self.cell,
            self.region,
            self.advisory_id,
            self.stage.as_str(),
            self.time_to_drain_secs(),
            self.time_to_rebuild_secs(),
            self.missing_evidence().join(","),
        )
    }
}

#[cfg(test)]
mod tests;
