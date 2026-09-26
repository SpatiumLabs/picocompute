//! Audit event types for recording significant platform occurrences.
//!
//! Per ADR-0001, every lifecycle state transition produces an audit event
//! written to the regional event log. Events carry an HLC timestamp for
//! causal ordering across distributed components.

use serde::{Deserialize, Serialize};
use strum::Display;

use super::fencing::FencingToken;
use super::hlc::HlcTimestamp;
use super::ids::{AuditEventId, OperationId, SandboxId, TenantId};
use super::principal::{PrincipalId, ServiceId};

/// Bounded action taxonomy for audit event correlation.
///
/// Per ADR-0009, the `action` field on every audit event must be a
/// bounded value. This enum provides type-safe constructors for common
/// actions while the builder still accepts raw `impl Into<String>`
/// for future extensibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Serialize, Deserialize)]
#[strum(serialize_all = "snake_case")]
pub enum AuditAction {
    Create,
    Destroy,
    Suspend,
    Resume,
    Fork,
    Place,
    EnforceLease,
    EgressDeny,
    PortForward,
    Issue,
    Cleanup,
    SyscallMonitor,
}

impl From<AuditAction> for String {
    fn from(a: AuditAction) -> String {
        a.to_string()
    }
}

/// Bounded outcome taxonomy for audit event correlation.
///
/// Per ADR-0009, the `outcome` field must be a canonical terminal
/// result. Each variant serializes to snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Serialize, Deserialize)]
#[strum(serialize_all = "snake_case")]
pub enum AuditOutcome {
    Allow,
    Deny,
    Success,
    Failed,
    Enforced,
    Issued,
    Revoked,
    Expired,
    Delivered,
    Denied,
    Resolved,
}

impl From<AuditOutcome> for String {
    fn from(o: AuditOutcome) -> String {
        o.to_string()
    }
}

/// Bounded producer taxonomy for audit event correlation.
///
/// Identifies the service or component that produced the event.
/// Per ADR-0009, producer is a required bounded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Serialize, Deserialize)]
#[strum(serialize_all = "kebab-case")]
pub enum AuditProducer {
    Scheduler,
    #[strum(serialize = "lease-manager")]
    LeaseManager,
    #[strum(serialize = "network-agent")]
    NetworkAgent,
    #[strum(serialize = "host-agent")]
    HostAgent,
    Sandboxd,
    #[strum(serialize = "policy-engine")]
    PolicyEngine,
    #[strum(serialize = "audit-sink")]
    AuditSink,
    #[strum(serialize = "runtime-hardening")]
    RuntimeHardening,
}

impl From<AuditProducer> for String {
    fn from(p: AuditProducer) -> String {
        p.to_string()
    }
}

/// Kinds of audit events that can be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A sandbox lifecycle state transition.
    LifecycleTransition,
    /// An access lease was issued.
    LeaseIssued,
    /// An access lease was renewed.
    LeaseRenewed,
    /// An access lease expired.
    LeaseExpired,
    /// An access lease was revoked.
    LeaseRevoked,
    /// An access lease validation was denied.
    LeaseDenied,
    /// A lease was validated and enforced at the data plane.
    LeaseEnforced,
    /// A policy configuration changed.
    PolicyChange,
    /// A policy evaluation decision (allow or deny).
    PolicyDecision,
    /// A quota check rejected the request.
    QuotaRejection,
    /// A scheduler placement decision outcome.
    PlacementOutcome,
    /// A runtime operation outcome (prepare, start, stop, suspend, resume).
    RuntimeOutcome,
    /// A host was disabled for placement.
    HostDisabled,
    /// A network enforcement event (egress, DNS, port-forward decision).
    NetworkEnforcement,
    /// A credential issuance, denial, or revocation event.
    CredentialIssuance,
    /// A credential request was denied.
    CredentialDenied,
    /// A credential was revoked.
    CredentialRevoked,
    /// A snapshot operation outcome (create, restore, fork, integrity).
    SnapshotOperation,
    /// A cleanup or reconciliation disposition event.
    CleanupDisposition,
    /// An audit pipeline delivery or disposition event.
    AuditDelivery,
    /// A snapshot metadata access (read or list).
    SnapshotMetadataAccess,
    /// A syscall was captured by the eBPF audit monitor.
    SyscallMonitored,
}

/// Current audit event schema version.
///
/// v1: initial schema with lifecycle, lease, policy, quota,
///     placement, runtime, and host-disabled events.
/// v2: added LeaseEnforced, NetworkEnforcement, CredentialIssuance,
///     SnapshotOperation, CleanupDisposition, and AuditDelivery kinds
///     plus top-level correlation fields (producer, request_id, action,
///     outcome, reason, policy_decision_id, lease_id).
/// v3: added SnapshotMetadataAccess kind and details for snapshot
/// metadata read and list operations.
pub const AUDIT_SCHEMA_VERSION: u32 = 3;

/// Typed event-specific payload for audit events.
///
/// Each variant carries the diagnostic details relevant to a particular
/// event kind. Secrets are never included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventDetails {
    /// Lifecycle state transition details.
    LifecycleTransition { fencing_token: Option<FencingToken> },
    /// Policy evaluation decision details.
    PolicyDecision {
        decision_id: String,
        action: String,
        outcome: String,
        policy_epoch: u64,
        reason: Option<String>,
    },
    /// Quota rejection details.
    QuotaRejection {
        decision_id: String,
        resource: String,
        limit: u64,
        current: u64,
    },
    /// Scheduler placement outcome details.
    PlacementOutcome {
        cell_id: Option<String>,
        host_id: Option<String>,
        reason: String,
        score: Option<f64>,
        candidates_evaluated: usize,
    },
    /// Runtime operation outcome details.
    RuntimeOutcome {
        operation: String,
        success: bool,
        error: Option<String>,
    },
    /// Host disabled-for-placement details.
    HostDisabled { host_id: String, reason: String },
    /// Lease operation details.
    LeaseOperation {
        lease_id: String,
        action: String,
        policy_decision_id: Option<String>,
        reason: Option<String>,
    },
    /// Lease enforcement details (data-plane validation passed).
    LeaseEnforcement {
        lease_id: String,
        enforcing_component: String,
        sandbox_id: String,
        tenant_id: String,
        policy_decision_id: Option<String>,
    },
    /// Network enforcement details (egress, DNS, port-forward).
    NetworkEnforcement {
        action: String,
        destination: Option<String>,
        outcome: String,
        reason: Option<String>,
        lease_id: Option<String>,
    },
    /// Credential issuance or revocation details.
    CredentialIssuance {
        action: String,
        outcome: String,
        reason: Option<String>,
        credential_type: String,
        lease_id: Option<String>,
    },
    /// Snapshot operation details (create, restore, fork, integrity).
    SnapshotOperation {
        operation: String,
        outcome: String,
        reason: Option<String>,
        snapshot_id: Option<String>,
        parent_snapshot_id: Option<String>,
        state_profile: Option<String>,
    },
    /// Cleanup or reconciliation disposition details.
    CleanupDisposition {
        disposition: String,
        reason: String,
        affected_resources: Option<Vec<String>>,
        quarantine: bool,
    },
    /// Audit pipeline delivery or integrity event.
    AuditDelivery {
        outcome: String,
        reason: Option<String>,
        batch_size: Option<usize>,
        retry_count: Option<u32>,
    },
    /// Snapshot metadata access details (read or list).
    SnapshotMetadataAccess {
        /// "read" for single-snapshot access, "list" for paginated queries.
        operation: String,
        /// Outcome of the access attempt ("success" or "failed").
        outcome: String,
        /// The snapshot ID that was read, if this is a read operation.
        snapshot_id: Option<String>,
        /// The tenant context for the access.
        tenant_id: Option<String>,
        /// Human-readable description of the query filter, if any.
        filter: Option<String>,
        /// Number of snapshots returned (list operations only).
        result_count: Option<usize>,
    },
    /// Syscall capture from eBPF tracepoint monitor.
    SyscallCapture {
        /// Syscall name, e.g. "openat", "execve", "connect".
        syscall: String,
        /// First argument register value.
        arg0: u64,
        /// Second argument register value.
        arg1: u64,
        /// Third argument register value.
        arg2: u64,
        /// Fourth argument register value.
        arg3: u64,
        /// Return value (only meaningful on sys_exit).
        retval: i64,
        /// Process ID that issued the syscall.
        pid: u32,
        /// Thread ID that issued the syscall.
        tid: u32,
        /// User ID of the calling process.
        uid: u32,
        /// Group ID of the calling process.
        gid: u32,
        /// Namespaced timestamp in nanoseconds.
        timestamp_ns: u64,
        /// First string argument if present (e.g. filename, device path).
        string_arg0: Option<String>,
        /// Second string argument if present (e.g. mountpoint, fstype).
        string_arg1: Option<String>,
        /// Whether this is the syscall entry (true) or exit (false).
        is_enter: bool,
    },
}

/// An immutable audit event recording a significant occurrence.
///
/// Per ADR-0001, every lifecycle state transition produces an audit
/// event written to the regional event log. Events carry an HLC
/// timestamp for causal ordering across distributed components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Unique event identifier.
    pub id: AuditEventId,
    /// Hybrid logical clock timestamp for causal ordering.
    pub hlc_ts: HlcTimestamp,
    /// The kind of event.
    pub kind: AuditEventKind,
    /// The sandbox this event relates to, if applicable.
    pub sandbox_id: Option<SandboxId>,
    /// Tenant this event relates to, if applicable.
    pub tenant_id: Option<TenantId>,
    /// The previous lifecycle state, if applicable.
    pub from_state: Option<String>,
    /// The new lifecycle state.
    pub to_state: Option<String>,
    /// Identity that initiated the action.
    pub principal: Option<PrincipalId>,
    /// Identity of the service that committed the change.
    pub service: Option<ServiceId>,
    /// Operation ID if this event records a specific operation.
    pub operation_id: Option<OperationId>,
    /// Trace ID for cross-component correlation.
    pub trace_id: Option<String>,
    /// Idempotency key from the initiating request.
    pub idempotency_key: Option<String>,
    /// Failure information if this records a failure.
    pub failure: Option<crate::metadata::FailureInfo>,
    /// Typed event-specific diagnostic details.
    pub details: Option<AuditEventDetails>,
    /// ISO 8601 wall-clock time (for display; HLC provides ordering).
    pub recorded_at: String,
    /// Epoch at the time of the event.
    pub epoch: Option<u64>,
    /// Fencing token at the time of the event.
    pub fencing_token: Option<FencingToken>,
    /// Producing service identity (v2).
    #[serde(default)]
    pub producer: Option<String>,
    /// Request ID that initiated this event (v2).
    #[serde(default)]
    pub request_id: Option<String>,
    /// Bounded action that this event records (v2).
    #[serde(default)]
    pub action: Option<String>,
    /// Canonical terminal outcome (v2).
    #[serde(default)]
    pub outcome: Option<String>,
    /// Structured reason for the outcome (v2).
    #[serde(default)]
    pub reason: Option<String>,
    /// Policy decision ID for policy-governed events (v2).
    #[serde(default)]
    pub policy_decision_id: Option<String>,
    /// Lease ID for lease lifecycle or enforcement events (v2).
    #[serde(default)]
    pub lease_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serialization_roundtrip() {
        let event = AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            id: AuditEventId::generate(),
            hlc_ts: HlcTimestamp::now(),
            kind: AuditEventKind::LifecycleTransition,
            sandbox_id: Some(SandboxId::generate()),
            tenant_id: Some(TenantId::generate()),
            from_state: Some("Pending".into()),
            to_state: Some("Scheduled".into()),
            principal: Some(PrincipalId::new("user:alice")),
            service: Some(ServiceId::new("scheduler")),
            operation_id: Some(OperationId::generate()),
            trace_id: Some("trace-abc".into()),
            idempotency_key: Some("idem-123".into()),
            failure: None,
            details: Some(AuditEventDetails::LifecycleTransition {
                fencing_token: Some(FencingToken {
                    epoch: 1,
                    sequence: 0,
                }),
            }),
            recorded_at: "2026-01-01T00:00:00Z".into(),
            epoch: Some(1),
            fencing_token: Some(FencingToken {
                epoch: 1,
                sequence: 0,
            }),
            producer: Some("scheduler".into()),
            request_id: Some("req_001".into()),
            action: Some("Create".into()),
            outcome: Some("Success".into()),
            reason: None,
            policy_decision_id: Some("pdc_001".into()),
            lease_id: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, back.id);
        assert_eq!(event.hlc_ts, back.hlc_ts);
        assert_eq!(event.kind, back.kind);
        assert_eq!(event.schema_version, back.schema_version);
        assert_eq!(event.details, back.details);
    }
}
