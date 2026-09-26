//! Operator evidence gates for quarantine and fenced cleanup (G-04).
//!
//! The in-process [`crate::host_quarantine::AlertStateManager`] API exists and
//! is unit-tested, but the operator path needs a ticket plus fencing-token
//! evidence. This module encodes that approved path so the CLI helper and
//! runbooks share one validation seam.
//!
//! Design notes:
//! - Validation only. This module performs no mutation, no RPC, and no ledger
//!   writes. Callers record the returned evidence in the incident ticket.
//! - Acknowledge never clears a page without a condition owner.
//! - Resolve requires the condition to be gone. Do not resolve just to
//!   restore capacity.
//! - Fenced cleanup requires at least one fencing token. Mismatched tokens
//!   are a control-plane bug, not a local rm.
//! - Ledger inspect is read-only. The allowlist names the permitted queries.
//!   There is no write, delete, or edit path here.
//! - Drain is one-way. There is intentionally no undrain helper. Re-admit
//!   follows the checklist in [`validate_readmit`].
//!
//! ```rust
//! use pico_core::{validate_acknowledge, validate_readmit, ReadmitChecks};
//!
//! validate_acknowledge("INC-123", "sre-picocompute").expect("valid ack");
//! let checks = ReadmitChecks {
//!     quarantine_gauge_zero: true,
//!     capacity_age_secs: 12,
//!     health_admitting: true,
//!     reconciliation_clean: true,
//!     five_minute_watch_clean: true,
//! };
//! validate_readmit(&checks).expect("re-admit gates pass");
//! ```

use crate::host_quarantine::AlertCondition;
use crate::identity::FencingToken;

/// Validated incident ticket reference.
///
/// The ticket holds host, cell, region, reason, approvals, timestamps, and
/// audit event IDs for the operation. Validation checks format only; review
/// status lives in the tracker, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorTicket {
    id: String,
}

impl OperatorTicket {
    /// Returns the ticket ID as recorded in the incident ticket.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Evidence that an acknowledge was gated on ticket plus condition owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeEvidence {
    /// Ticket ID that owns this acknowledge.
    pub ticket: String,
    /// Condition owner who accepts the page (team or person, not empty).
    pub owner: String,
}

/// Evidence that a resolve was gated on ticket plus cleared condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveEvidence {
    /// Ticket ID that owns this resolve.
    pub ticket: String,
}

/// Evidence that a fenced cleanup was gated on ticket plus fencing tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FencedCleanupEvidence {
    /// Ticket ID that owns this cleanup.
    pub ticket: String,
    /// Fencing tokens presented as evidence (at least one).
    pub tokens: Vec<FencingToken>,
}

/// Evidence that a ledger inspect was scoped to read-only queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInspectEvidence {
    /// Ticket ID that owns this inspect.
    pub ticket: String,
    /// The read-only query that was approved.
    pub query: LedgerInspectQuery,
}

/// Evidence that a drain was gated on a ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainEvidence {
    /// Ticket ID that owns this drain.
    pub ticket: String,
}

/// Read-only ledger queries permitted for operator inspect.
///
/// Any query not in this enum is rejected by [`validate_ledger_inspect`].
/// There is no write, delete, or edit query. Ledger edits by hand remain
/// prohibited without a reviewed incident ticket and are not representable
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerInspectQuery {
    /// Single sandbox status (`sandbox_status`).
    SandboxStatus,
    /// All sandbox statuses (`list_sandbox_statuses`).
    ListSandboxes,
    /// Receipts for one sandbox (`list_receipts`).
    ListReceipts,
    /// GC statistics for the last pass.
    GcStats,
    /// Reconciliation findings (`reconciliation_findings`).
    Findings,
}

impl LedgerInspectQuery {
    /// Returns the stable query name used in tickets and CLI flags.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SandboxStatus => "sandbox-status",
            Self::ListSandboxes => "list-sandboxes",
            Self::ListReceipts => "list-receipts",
            Self::GcStats => "gc-stats",
            Self::Findings => "findings",
        }
    }

    /// Parses a CLI-provided query name. Returns `None` for unknown names,
    /// including any write-like query.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "sandbox-status" => Self::SandboxStatus,
            "list-sandboxes" => Self::ListSandboxes,
            "list-receipts" => Self::ListReceipts,
            "gc-stats" => Self::GcStats,
            "findings" => Self::Findings,
            _ => return None,
        })
    }

    /// All permitted read-only queries, in CLI help order.
    pub fn all() -> &'static [LedgerInspectQuery] {
        &[
            LedgerInspectQuery::SandboxStatus,
            LedgerInspectQuery::ListSandboxes,
            LedgerInspectQuery::ListReceipts,
            LedgerInspectQuery::GcStats,
            LedgerInspectQuery::Findings,
        ]
    }
}

/// Re-admit checklist for returning a host to placement.
///
/// Mirrors the host-rebuild re-admit gates: quarantine gauge at zero,
/// fresh capacity, admitting health (`ready` or `degraded` only), a clean
/// reconciliation pass, and a 5m watch with no new quarantine alert.
/// There is no undrain shortcut; every gate must pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadmitChecks {
    /// True when `pico_quarantine_hosts_quarantined` is 0 for the host.
    pub quarantine_gauge_zero: bool,
    /// Age of the last capacity report in seconds (must be under 60).
    pub capacity_age_secs: u64,
    /// True when host health is `ready` or `degraded` (admitting states).
    pub health_admitting: bool,
    /// True when a reconciliation pass shows zero orphans and zero
    /// review-required with healthy network reconciliation.
    pub reconciliation_clean: bool,
    /// True when a 5m watch shows no new quarantine alert on the host.
    pub five_minute_watch_clean: bool,
}

/// Marker explaining why no undrain helper exists.
///
/// Drain is sticky by design. A drained host returns to placement only
/// through the re-admit checklist, never through an undrain RPC. This
/// constant gives the CLI and runbooks one shared string to print.
pub const UNDRAIN_NOT_SUPPORTED: &str =
    "no undrain helper exists by design; re-admit follows the checklist only";

/// Operator gate failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperatorError {
    /// Ticket is missing or blank.
    #[error("incident ticket is required; open or update the ticket before mutating")]
    MissingTicket,
    /// Ticket format is rejected.
    #[error("invalid incident ticket {ticket:?}: {reason}")]
    InvalidTicket {
        /// Ticket value that was rejected.
        ticket: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Acknowledge without a condition owner.
    #[error("acknowledge needs a condition owner; never clear a page without an owner")]
    MissingOwner,
    /// Resolve while the condition is still present.
    #[error("resolve needs a cleared condition; do not resolve just to restore capacity")]
    ConditionNotCleared,
    /// Fenced cleanup without fencing-token evidence.
    #[error("fenced cleanup needs at least one fencing token (epoch.sequence)")]
    MissingFencingTokens,
    /// Unknown alert condition name.
    #[error(
        "unknown quarantine condition {condition:?}; expected one of: repeated_runtime_outcomes, cleanup_or_reconciliation_issue, stale_resources, capacity_reporting_staleness, resource_pressure"
    )]
    UnknownCondition {
        /// Condition value that was rejected.
        condition: String,
    },
    /// Unknown or prohibited ledger query.
    #[error(
        "ledger inspect query {query:?} is not allowed; use one of: sandbox-status, list-sandboxes, list-receipts, gc-stats, findings"
    )]
    ProhibitedLedgerQuery {
        /// Query value that was rejected.
        query: String,
    },
    /// Re-admit gate failure with the specific gate that failed.
    #[error("re-admit blocked: {reason}")]
    ReadmitBlocked {
        /// Which gate failed and why.
        reason: String,
    },
}

/// Returns true when a value uses the ticket charset: alphanumerics plus
/// `-_/:#:.` and space.
fn has_ticket_charset(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '#' | ':' | '.' | ' '))
}

/// Validates a ticket reference and returns the normalized form.
///
/// Rules: trimmed length 3 to 128, charset limited to alphanumerics plus
/// `-_/#:.` and space, at least one alphanumeric, and rejects bare
/// placeholders (`tbd`, `todo`, `xxx`, `none`, `null`, `test`).
pub fn validate_ticket(raw: &str) -> Result<OperatorTicket, OperatorError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OperatorError::MissingTicket);
    }
    if trimmed.len() < 3 || trimmed.len() > 128 {
        return Err(OperatorError::InvalidTicket {
            ticket: raw.to_string(),
            reason: "ticket must be 3 to 128 characters".to_string(),
        });
    }
    if !has_ticket_charset(trimmed) {
        return Err(OperatorError::InvalidTicket {
            ticket: raw.to_string(),
            reason:
                "ticket uses an unsupported character; use letters, digits, space, and -_/#:. only"
                    .to_string(),
        });
    }
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(OperatorError::InvalidTicket {
            ticket: raw.to_string(),
            reason: "ticket must contain at least one letter or digit".to_string(),
        });
    }
    let lowered = trimmed.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "tbd" | "todo" | "xxx" | "none" | "null" | "test"
    ) {
        return Err(OperatorError::InvalidTicket {
            ticket: raw.to_string(),
            reason: "ticket is a placeholder; use the real incident ticket".to_string(),
        });
    }
    Ok(OperatorTicket {
        id: trimmed.to_string(),
    })
}

/// Parses a quarantine condition name from CLI input.
pub fn parse_condition(value: &str) -> Result<AlertCondition, OperatorError> {
    match value {
        "repeated_runtime_outcomes" => Ok(AlertCondition::RepeatedRuntimeOutcomes),
        "cleanup_or_reconciliation_issue" => Ok(AlertCondition::CleanupOrReconciliationIssue),
        "stale_resources" => Ok(AlertCondition::StaleResources),
        "capacity_reporting_staleness" => Ok(AlertCondition::CapacityReportingStaleness),
        "resource_pressure" => Ok(AlertCondition::ResourcePressure),
        _ => Err(OperatorError::UnknownCondition {
            condition: value.to_string(),
        }),
    }
}

/// Validates an acknowledge: ticket plus condition owner.
///
/// Acknowledge marks the alert seen but keeps the host out of placement.
/// It never clears a page without an owner.
pub fn validate_acknowledge(
    ticket_raw: &str,
    owner_raw: &str,
) -> Result<AcknowledgeEvidence, OperatorError> {
    let ticket = validate_ticket(ticket_raw)?;
    let owner = owner_raw.trim();
    if owner.len() < 2 || owner.len() > 128 || !has_ticket_charset(owner) {
        return Err(OperatorError::MissingOwner);
    }
    Ok(AcknowledgeEvidence {
        ticket: ticket.id,
        owner: owner.to_string(),
    })
}

/// Validates a resolve: ticket plus proof the condition is gone.
///
/// `condition_cleared` must be true. Auto-resolve after 120s of a cleared
/// condition is the default; manual resolve is only for the cleared case
/// with an approved owner re-admitting the host.
pub fn validate_resolve(
    ticket_raw: &str,
    condition_cleared: bool,
) -> Result<ResolveEvidence, OperatorError> {
    let ticket = validate_ticket(ticket_raw)?;
    if !condition_cleared {
        return Err(OperatorError::ConditionNotCleared);
    }
    Ok(ResolveEvidence { ticket: ticket.id })
}

/// Validates a fenced cleanup: ticket plus at least one fencing token.
///
/// Tokens are `epoch.sequence` (for example `42.7`). The caller parses
/// them with [`FencingToken`] before calling; this gate enforces
/// non-emptiness. Token mismatch against live leases is a control-plane
/// bug; the operator stops and pages instead of running a local rm.
pub fn validate_fenced_cleanup(
    ticket_raw: &str,
    tokens: &[FencingToken],
) -> Result<FencedCleanupEvidence, OperatorError> {
    let ticket = validate_ticket(ticket_raw)?;
    if tokens.is_empty() {
        return Err(OperatorError::MissingFencingTokens);
    }
    Ok(FencedCleanupEvidence {
        ticket: ticket.id,
        tokens: tokens.to_vec(),
    })
}

/// Validates a ledger inspect: ticket plus an allowlisted read-only query.
///
/// Ledger edits by hand are prohibited and have no representation here.
/// Use the returned query name when recording evidence in the ticket.
pub fn validate_ledger_inspect(
    ticket_raw: &str,
    query_raw: &str,
) -> Result<LedgerInspectEvidence, OperatorError> {
    let ticket = validate_ticket(ticket_raw)?;
    let query = LedgerInspectQuery::parse(query_raw.trim()).ok_or_else(|| {
        OperatorError::ProhibitedLedgerQuery {
            query: query_raw.to_string(),
        }
    })?;
    Ok(LedgerInspectEvidence {
        ticket: ticket.id,
        query,
    })
}

/// Validates a drain: ticket-gated call to the existing drain RPC.
///
/// Drain stops admission of new sandboxes and is bearer-auth mutation that
/// needs SRE on-call approval recorded in the ticket. There is no undrain;
/// see [`validate_readmit`] and [`UNDRAIN_NOT_SUPPORTED`].
pub fn validate_drain(ticket_raw: &str) -> Result<DrainEvidence, OperatorError> {
    let ticket = validate_ticket(ticket_raw)?;
    Ok(DrainEvidence { ticket: ticket.id })
}

/// Validates the re-admit checklist. Every gate must pass.
///
/// - `quarantine_gauge_zero`: `pico_quarantine_hosts_quarantined` is 0.
/// - `capacity_age_secs`: under 60 (inventory drops the host at 60s).
/// - `health_admitting`: `ready` or `degraded` only.
/// - `reconciliation_clean`: zero orphans and zero review-required.
/// - `five_minute_watch_clean`: no new quarantine alert in the 5m watch.
pub fn validate_readmit(checks: &ReadmitChecks) -> Result<(), OperatorError> {
    if !checks.quarantine_gauge_zero {
        return Err(OperatorError::ReadmitBlocked {
            reason: "quarantine gauge is not zero for the host".to_string(),
        });
    }
    if checks.capacity_age_secs >= 60 {
        return Err(OperatorError::ReadmitBlocked {
            reason: "capacity report is stale (age must be under 60s)".to_string(),
        });
    }
    if !checks.health_admitting {
        return Err(OperatorError::ReadmitBlocked {
            reason: "host health is not admitting (need ready or degraded)".to_string(),
        });
    }
    if !checks.reconciliation_clean {
        return Err(OperatorError::ReadmitBlocked {
            reason: "reconciliation is not clean (need zero orphans and zero review-required)"
                .to_string(),
        });
    }
    if !checks.five_minute_watch_clean {
        return Err(OperatorError::ReadmitBlocked {
            reason: "5m watch is not clean (new quarantine alert fired)".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
