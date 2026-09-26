//! Zero-trust access lease manager.
//!
//! Implements the access lease model from ADR-0001. Leases are
//! time-bound, scoped authorization tokens issued by the control plane after
//! policy evaluation and validated by data-plane components before granting
//! access to sandbox operations.
//!
//! ## Lease lifecycle
//!
//! 1. **Issue**: Control plane evaluates policy, issues a signed lease with
//!    expiry and scope bounds.
//! 2. **Validate**: Data-plane components verify signature, expiry, sandbox
//!    match, action match, and revocation status.
//! 3. **Renew**: Client requests a fresh policy decision; new lease replaces
//!    the previous one.
//! 4. **Revoke**: Policy change or admin action revokes the lease; data-plane
//!    components terminate active connections.
//! 5. **Expire**: Short-lived leases auto-expire; cleanup removes stale records.

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::SandboxError;
use crate::event_bus::{AuditEventBuilder, AuditEventSink, NoopAuditSink, emit_lease_enforced};
use crate::identity::{
    AuditEventDetails, AuditEventKind, AuditOutcome, AuditProducer, Hlc, LeaseId, OperationId,
    PolicyDecisionId, PrincipalId, SandboxId, TenantId,
};
use crate::policy::PolicyDecision;
use crate::types::now_iso;

/// Actions that can be authorized by an access lease.
///
/// Each action maps to a distinct data-plane access path. Leases are scoped
/// to a single action; compound operations require multiple leases or an
/// admin override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseAction {
    /// Exec stream into a sandbox (stdin/stdout/stderr).
    Exec,
    /// File transfer (read/write/list) within a sandbox workspace.
    FileTransfer,
    /// Port forwarding to expose sandbox-internal services.
    PortForward,
    /// Egress exception to allow network traffic out of the sandbox.
    EgressException,
    /// Snapshot, restore, or fork a sandbox.
    SnapshotOperation,
    /// Admin override bypassing standard policy checks.
    AdminOverride,
    /// Fetch runtime credentials from a secrets broker.
    CredentialAccess,
}

impl From<LeaseAction> for String {
    fn from(a: LeaseAction) -> String {
        a.as_str().to_string()
    }
}

impl LeaseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FileTransfer => "file_transfer",
            Self::PortForward => "port_forward",
            Self::EgressException => "egress_exception",
            Self::SnapshotOperation => "snapshot_operation",
            Self::AdminOverride => "admin_override",
            Self::CredentialAccess => "credential_access",
        }
    }

    /// Parses a snake_case action name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "exec" => Some(Self::Exec),
            "file_transfer" => Some(Self::FileTransfer),
            "port_forward" => Some(Self::PortForward),
            "egress_exception" => Some(Self::EgressException),
            "snapshot_operation" => Some(Self::SnapshotOperation),
            "admin_override" => Some(Self::AdminOverride),
            "credential_access" => Some(Self::CredentialAccess),
            _ => None,
        }
    }

    /// Whether issuance must include action-specific scope bounds.
    pub fn requires_explicit_scope(self) -> bool {
        matches!(
            self,
            Self::PortForward | Self::FileTransfer | Self::EgressException | Self::CredentialAccess
        )
    }

    /// Maps a lease action onto the policy action evaluated at issuance.
    pub fn to_policy_action(self) -> Option<crate::policy::PolicyAction> {
        match self {
            Self::Exec => Some(crate::policy::PolicyAction::Exec),
            Self::FileTransfer => Some(crate::policy::PolicyAction::FileAccess),
            Self::PortForward => Some(crate::policy::PolicyAction::PortForward),
            Self::CredentialAccess => Some(crate::policy::PolicyAction::CredentialAccess),
            Self::EgressException => Some(crate::policy::PolicyAction::EgressException),
            Self::SnapshotOperation => Some(crate::policy::PolicyAction::SnapshotOperation),
            Self::AdminOverride => None,
        }
    }
}

/// Default TTL for newly issued access leases.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 3600;

/// Bounds on what a lease permits within its action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseScope {
    /// Specific ports allowed for port-forward leases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Allowed file paths for file-transfer leases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Egress CIDR blocks for egress exception leases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_cidrs: Vec<String>,
    /// Credential types allowed for CredentialAccess leases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_types: Vec<String>,
}

impl LeaseScope {
    /// Returns an unbounded scope (admin override or unrestricted action).
    pub fn unbounded() -> Self {
        Self {
            ports: Vec::new(),
            paths: Vec::new(),
            egress_cidrs: Vec::new(),
            credential_types: Vec::new(),
        }
    }

    /// Whether this scope carries the bounds required for `action`.
    ///
    /// Empty vectors are treated as unbounded by [`check_lease_scope`], so
    /// bounded actions must present at least one entry.
    pub fn has_bounds_for(&self, action: LeaseAction) -> bool {
        match action {
            LeaseAction::PortForward => !self.ports.is_empty(),
            LeaseAction::FileTransfer => !self.paths.is_empty(),
            LeaseAction::EgressException => !self.egress_cidrs.is_empty(),
            LeaseAction::CredentialAccess => !self.credential_types.is_empty(),
            LeaseAction::Exec | LeaseAction::SnapshotOperation | LeaseAction::AdminOverride => true,
        }
    }
}

/// Revocation status of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationState {
    /// Lease is active and may be used for authorization.
    Active,
    /// Lease has been revoked and must be rejected.
    Revoked { reason: RevocationReason },
}

/// Why a lease was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Policy update invalidated the lease's policy epoch.
    PolicyChanged,
    /// Administrator explicitly revoked the lease.
    AdminAction,
    /// The sandbox was destroyed or the tenant was suspended.
    ResourceRemoved,
    /// The principal's identity was invalidated.
    IdentityInvalidated,
}

/// Identity of the operation revoking leases on the destroy path.
///
/// Carried onto each `LeaseRevoked` audit event so the revoke trail
/// correlates with the destroying lifecycle commit (issue 140).
///
/// Prefer `principal: None` so each revoke keeps the lease subject as
/// principal and the destroy identity travels via `operation_id`. Setting
/// `principal` overwrites the subject and loses who the lease was issued
/// to (recoverable only via `lease_id` lookup); it exists for callers
/// that must attribute the revoke to the destroyer.
#[derive(Debug, Clone, Default)]
pub struct DestroyRevocationContext {
    /// Destroy operation that triggered the revocation.
    pub operation_id: Option<OperationId>,
    /// Actor that initiated destroy. When `None`, each revoke event
    /// keeps the lease subject as principal.
    pub principal: Option<PrincipalId>,
}

/// An access lease authorizing a specific operation on a sandbox.
///
/// Leases are short-lived bearer tokens. The data plane validates them on
/// every access attempt: signature, expiry, sandbox, action, scope, and
/// revocation status must all pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessLease {
    /// Unique lease identifier.
    pub lease_id: LeaseId,
    /// Tenant that owns the sandbox.
    pub tenant_id: TenantId,
    /// Authenticated principal this lease was issued to.
    pub subject: PrincipalId,
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Authorized operation.
    pub action: LeaseAction,
    /// Bounds on the lease (ports, paths, CIDRs).
    pub scope: LeaseScope,
    /// Policy decision that authorized this lease.
    pub policy_decision_id: PolicyDecisionId,
    /// Policy epoch at the time of issuance.
    pub policy_epoch: u64,
    /// When the lease was issued (ISO 8601 UTC).
    pub issued_at: String,
    /// When the lease expires (ISO 8601 UTC).
    pub expires_at: String,
    /// Whether the lease is active, renewed, or revoked.
    pub revocation_state: RevocationState,
    /// Ed25519 signature over the lease fields, issued by the control plane.
    ///
    /// The signature covers the canonical serialization of `lease_id`,
    /// `tenant_id`, `subject`, `sandbox_id`, `action`, `scope`,
    /// `policy_decision_id`, `policy_epoch`, `issued_at`, `expires_at`,
    /// `revocation_state` in that order. When `None`, the lease is unsigned
    /// and must not be trusted outside the immediate request context.
    #[serde(skip)]
    pub signature: Option<Vec<u8>>,
}

/// Reasons a lease validation can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// The lease has expired.
    Expired { expires_at: String, current: String },
    /// The lease has been revoked.
    Revoked { reason: RevocationReason },
    /// The lease is for a different sandbox.
    WrongSandbox { expected: String, actual: String },
    /// The lease is for a different tenant.
    WrongTenant { expected: String, actual: String },
    /// The lease does not authorize the requested action.
    WrongAction {
        expected: LeaseAction,
        actual: LeaseAction,
    },
    /// The lease's policy epoch is stale.
    StalePolicyEpoch {
        lease_epoch: u64,
        current_epoch: u64,
    },
    /// The requested scope exceeds what the lease allows.
    ScopeExceeded { detail: String },
    /// The lease signature is invalid or missing.
    InvalidSignature,
    /// The lease was not found.
    NotFound { lease_id: String },
    /// The presented lease blob could not be decoded.
    Malformed { detail: String },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired {
                expires_at,
                current,
            } => {
                write!(f, "lease expired at {expires_at} (current: {current})")
            }
            Self::Revoked { reason } => {
                write!(f, "lease revoked: {reason:?}")
            }
            Self::WrongSandbox { expected, actual } => {
                write!(f, "lease for sandbox {actual}, expected {expected}")
            }
            Self::WrongTenant { expected, actual } => {
                write!(f, "lease for tenant {actual}, expected {expected}")
            }
            Self::WrongAction { expected, actual } => {
                write!(
                    f,
                    "lease authorizes {}, not {}",
                    actual.as_str(),
                    expected.as_str()
                )
            }
            Self::StalePolicyEpoch {
                lease_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "stale policy epoch: lease={lease_epoch}, current={current_epoch}"
                )
            }
            Self::ScopeExceeded { detail } => {
                write!(f, "lease scope exceeded: {detail}")
            }
            Self::InvalidSignature => {
                write!(f, "invalid or missing lease signature")
            }
            Self::NotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            }
            Self::Malformed { detail } => {
                write!(f, "malformed lease: {detail}")
            }
        }
    }
}

/// Manager for access lease lifecycle.
///
/// Thread-safe: uses `RwLock` for the lease store. Designed to sit between
/// the policy engine and data-plane components.
///
/// Emits audit events (LeaseIssued, LeaseRenewed, LeaseExpired,
/// LeaseRevoked, LeaseDenied) on each lifecycle transition.
pub struct LeaseManager {
    /// Active leases indexed by lease ID.
    leases: RwLock<HashMap<LeaseId, AccessLease>>,
    /// Set of revoked lease IDs for fast lookup (separate from the lease store
    /// so expired leases can be pruned while revocation state persists).
    revoked: RwLock<HashSet<LeaseId>>,
    /// Monotonic counter for deterministic ordering of actions.
    sequence: AtomicU64,
    /// Audit event sink for emitting lease lifecycle events.
    audit_sink: Arc<dyn AuditEventSink>,
    /// HLC generator for event timestamps.
    hlc: Arc<Hlc>,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            sequence: AtomicU64::new(0),
            audit_sink: Arc::new(NoopAuditSink),
            hlc: Arc::new(Hlc::new()),
        }
    }

    /// Create a lease manager with an audit event sink.
    pub fn with_audit_sink(audit_sink: Arc<dyn AuditEventSink>, hlc: Arc<Hlc>) -> Self {
        Self {
            leases: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            sequence: AtomicU64::new(0),
            audit_sink,
            hlc,
        }
    }

    /// Issue a new lease.
    ///
    /// Creates a lease with the given parameters. The caller is responsible
    /// for evaluating policy before calling this method. The returned lease
    /// is stored in the manager and can be validated later.
    #[expect(
        clippy::too_many_arguments,
        reason = "all parameters are independently required by ADR-0001 lease schema"
    )]
    pub fn issue(
        &self,
        tenant_id: TenantId,
        subject: PrincipalId,
        sandbox_id: SandboxId,
        action: LeaseAction,
        scope: LeaseScope,
        decision: &PolicyDecision,
        ttl_secs: u64,
    ) -> AccessLease {
        let lease_id = LeaseId::generate();
        let issued_at = now_iso();

        // Compute expiry: issued_at + ttl_secs
        let expires_at = {
            let fmt = time::format_description::well_known::Iso8601::DEFAULT;
            let issued_dt = time::OffsetDateTime::parse(&issued_at, &fmt)
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
            let expiry_dt = issued_dt + time::Duration::seconds(ttl_secs as i64);
            expiry_dt.format(&fmt).unwrap_or_else(|_| now_iso())
        };

        let lease = AccessLease {
            lease_id,
            tenant_id,
            subject,
            sandbox_id,
            action,
            scope,
            policy_decision_id: decision.decision_id.clone(),
            policy_epoch: decision.policy_epoch,
            issued_at,
            expires_at,
            revocation_state: RevocationState::Active,
            signature: None,
        };

        self.leases
            .write()
            .insert(lease.lease_id.clone(), lease.clone());

        let _ = self.audit_sink.emit(
            AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::LeaseIssued)
                .sandbox_id(lease.sandbox_id.clone())
                .tenant_id(lease.tenant_id.clone())
                .principal(lease.subject.clone())
                .action(lease.action)
                .outcome(AuditOutcome::Issued)
                .details(AuditEventDetails::LeaseOperation {
                    lease_id: lease.lease_id.as_str().to_string(),
                    action: lease.action.as_str().to_string(),
                    policy_decision_id: Some(lease.policy_decision_id.as_str().to_string()),
                    reason: None,
                })
                .epoch(lease.policy_epoch)
                .build(),
        );

        lease
    }

    /// Renew a lease with a fresh policy decision.
    ///
    /// The old lease is revoked and a new one is issued. Renewal requires a
    /// fresh policy evaluation to ensure the principal is still authorized.
    pub fn renew(
        &self,
        lease_id: &LeaseId,
        decision: &PolicyDecision,
        ttl_secs: u64,
    ) -> Result<AccessLease, SandboxError> {
        let old = {
            let leases = self.leases.read();
            leases
                .get(lease_id)
                .cloned()
                .ok_or_else(|| SandboxError::Other(format!("lease not found: {lease_id}")))?
        };

        // Revoke the old lease first
        self.revoke(lease_id, RevocationReason::PolicyChanged)?;

        // Issue a fresh lease with the same parameters but a new decision
        let new_lease = self.issue(
            old.tenant_id,
            old.subject,
            old.sandbox_id,
            old.action,
            old.scope,
            decision,
            ttl_secs,
        );

        Ok(new_lease)
    }

    /// Revoke a lease, preventing further use.
    ///
    /// Marks the lease as revoked and adds its ID to the revocation set.
    /// Data-plane validations will reject any access attempt with this lease.
    pub fn revoke(&self, lease_id: &LeaseId, reason: RevocationReason) -> Result<(), SandboxError> {
        self.revoke_with_context(lease_id, reason, None)
    }

    /// Revoke a lease with the destroying operation identity attached.
    ///
    /// `ctx` carries the destroy `operation_id` (and optional destroyer
    /// principal) onto the `LeaseRevoked` audit event. When the context
    /// principal is `None`, the event keeps the lease subject as principal.
    pub fn revoke_with_context(
        &self,
        lease_id: &LeaseId,
        reason: RevocationReason,
        ctx: Option<&DestroyRevocationContext>,
    ) -> Result<(), SandboxError> {
        let (sandbox_id, tenant_id, subject, action, policy_decision_id) = {
            let mut leases = self.leases.write();
            let lease = leases
                .get_mut(lease_id)
                .ok_or_else(|| SandboxError::Other(format!("lease not found: {lease_id}")))?;

            if lease.revocation_state != RevocationState::Active {
                return Err(SandboxError::Conflict(format!(
                    "lease {lease_id} is already revoked"
                )));
            }

            lease.revocation_state = RevocationState::Revoked { reason };
            (
                lease.sandbox_id.clone(),
                lease.tenant_id.clone(),
                lease.subject.clone(),
                lease.action,
                lease.policy_decision_id.clone(),
            )
        };

        self.revoked.write().insert(lease_id.clone());

        let operation_id = ctx.and_then(|c| c.operation_id.clone());
        let principal = ctx.and_then(|c| c.principal.clone()).unwrap_or(subject);
        let mut builder =
            AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::LeaseRevoked)
                .sandbox_id(sandbox_id)
                .tenant_id(tenant_id)
                .principal(principal)
                .action(action)
                .outcome(AuditOutcome::Revoked)
                .producer(AuditProducer::LeaseManager)
                .details(AuditEventDetails::LeaseOperation {
                    lease_id: lease_id.as_str().to_string(),
                    action: action.as_str().to_string(),
                    policy_decision_id: Some(policy_decision_id.as_str().to_string()),
                    reason: Some(format!("{reason:?}")),
                });
        if let Some(op) = operation_id {
            builder = builder.operation_id(op);
        }
        let _ = self.audit_sink.emit(builder.build());

        Ok(())
    }

    /// Revoke every active lease bound to `sandbox_id`.
    ///
    /// Destroy-path helper (issue 140): after the `Destroying` commit and
    /// before `Destroyed` completes, the control plane must revoke all
    /// leases for the sandbox with `RevocationReason::ResourceRemoved`
    /// so no credential (or other) lease validates afterwards.
    /// Already-revoked and foreign-sandbox leases are skipped. Returns
    /// the revoked lease IDs in deterministic (sorted) order.
    ///
    /// Callers must fence issuance once `Destroying` is entered (reject
    /// new leases for the sandbox). This drains races where a lease was
    /// issued concurrently with revoke by looping until no active lease
    /// remains; without fencing a racing issuer could still mint after
    /// the final drain.
    pub fn revoke_for_sandbox(
        &self,
        sandbox_id: &SandboxId,
        reason: RevocationReason,
    ) -> Vec<LeaseId> {
        self.revoke_for_sandbox_with_context(sandbox_id, reason, None)
    }

    /// [`revoke_for_sandbox`](Self::revoke_for_sandbox) with the destroying
    /// operation identity attached to every `LeaseRevoked` event.
    pub fn revoke_for_sandbox_with_context(
        &self,
        sandbox_id: &SandboxId,
        reason: RevocationReason,
        ctx: Option<&DestroyRevocationContext>,
    ) -> Vec<LeaseId> {
        let mut revoked = Vec::new();
        loop {
            // Snapshot under a short read guard, then drop it before
            // revoking: `revoke_with_context` takes a write guard, so
            // holding the read guard across the call would deadlock
            // `parking_lot::RwLock` in the same thread.
            let targets: Vec<LeaseId> = {
                let leases = self.leases.read();
                let mut ids: Vec<LeaseId> = leases
                    .iter()
                    .filter(|(_, lease)| {
                        &lease.sandbox_id == sandbox_id
                            && lease.revocation_state == RevocationState::Active
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                ids
            };
            if targets.is_empty() {
                break;
            }
            let mut progress = false;
            for id in targets {
                if self.revoke_with_context(&id, reason, ctx).is_ok() {
                    revoked.push(id);
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        revoked.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        revoked
    }

    /// Active (non-revoked) leases bound to `sandbox_id`, in sorted ID order.
    pub fn active_leases_for_sandbox(&self, sandbox_id: &SandboxId) -> Vec<AccessLease> {
        let mut out: Vec<AccessLease> = {
            let leases = self.leases.read();
            leases
                .values()
                .filter(|lease| {
                    &lease.sandbox_id == sandbox_id
                        && lease.revocation_state == RevocationState::Active
                })
                .cloned()
                .collect()
        };
        out.sort_by(|a, b| a.lease_id.as_str().cmp(b.lease_id.as_str()));
        out
    }

    /// Validate a lease for a given operation context.
    ///
    /// Checks: existence, revocation, expiry, sandbox match, tenant match,
    /// action match, policy epoch staleness, and scope. Returns `Ok(())` if
    /// the lease authorizes the operation, or a `LeaseValidationError` if
    /// any check fails.
    pub fn validate(
        &self,
        lease_id: &LeaseId,
        sandbox_id: &SandboxId,
        tenant_id: &TenantId,
        action: LeaseAction,
        current_policy_epoch: u64,
    ) -> Result<AccessLease, LeaseValidationError> {
        let lease = {
            let leases = self.leases.read();
            leases
                .get(lease_id)
                .cloned()
                .ok_or_else(|| LeaseValidationError::NotFound {
                    lease_id: lease_id.to_string(),
                })?
        };

        let validation_result =
            check_lease_claims(&lease, sandbox_id, tenant_id, action, current_policy_epoch);

        if let Err(ref err) = validation_result {
            let _ = self.audit_sink.emit(
                AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::LeaseDenied)
                    .sandbox_id(sandbox_id.clone())
                    .tenant_id(tenant_id.clone())
                    .action(action)
                    .outcome(AuditOutcome::Denied)
                    .producer(AuditProducer::LeaseManager)
                    .details(AuditEventDetails::LeaseOperation {
                        lease_id: lease_id.as_str().to_string(),
                        action: action.as_str().to_string(),
                        policy_decision_id: None,
                        reason: Some(err.to_string()),
                    })
                    .build(),
            );
            Err(err.clone())
        } else {
            emit_lease_enforced(
                self.audit_sink.as_ref(),
                &self.hlc,
                lease_id.as_str(),
                AuditProducer::LeaseManager,
                sandbox_id.as_str(),
                tenant_id.as_str(),
                Some(lease.policy_decision_id.as_str().to_string()),
            );
            Ok(lease)
        }
    }

    /// Validate a lease and check scope bounds.
    ///
    /// Like [`validate`] but also checks that the requested scope (e.g.,
    /// specific ports, paths) falls within the lease's allowed scope.
    pub fn validate_with_scope(
        &self,
        lease_id: &LeaseId,
        sandbox_id: &SandboxId,
        tenant_id: &TenantId,
        action: LeaseAction,
        requested_scope: &LeaseScope,
        current_policy_epoch: u64,
    ) -> Result<AccessLease, LeaseValidationError> {
        let lease = self.validate(
            lease_id,
            sandbox_id,
            tenant_id,
            action,
            current_policy_epoch,
        )?;
        check_lease_scope(&lease, requested_scope)?;
        Ok(lease)
    }

    /// Remove expired leases from the store.
    ///
    /// Returns the number of leases removed. Also prunes the revocation
    /// set of expired IDs to prevent unbounded memory growth.
    pub fn cleanup_expired(&self) -> usize {
        let current = now_iso();
        let (removed, expired_leases) = {
            let mut leases = self.leases.write();
            let mut revoked = self.revoked.write();
            let before = leases.len();
            let mut expired: Vec<AccessLease> = Vec::new();
            leases.retain(|id, lease| {
                let is_expired = has_lease_expired(&lease.expires_at, &current);
                if is_expired {
                    revoked.remove(id);
                    expired.push(lease.clone());
                }
                !is_expired
            });
            (before - leases.len(), expired)
        };

        for lease in &expired_leases {
            let _ = self.audit_sink.emit(
                AuditEventBuilder::new(Arc::clone(&self.hlc), AuditEventKind::LeaseExpired)
                    .sandbox_id(lease.sandbox_id.clone())
                    .tenant_id(lease.tenant_id.clone())
                    .principal(lease.subject.clone())
                    .action(lease.action)
                    .outcome(AuditOutcome::Expired)
                    .producer(AuditProducer::LeaseManager)
                    .details(AuditEventDetails::LeaseOperation {
                        lease_id: lease.lease_id.as_str().to_string(),
                        action: lease.action.as_str().to_string(),
                        policy_decision_id: None,
                        reason: Some(format!("expired at {}", lease.expires_at)),
                    })
                    .build(),
            );
        }

        removed
    }

    /// Get a lease by ID.
    pub fn get(&self, lease_id: &LeaseId) -> Option<AccessLease> {
        self.leases.read().get(lease_id).cloned()
    }

    /// Check if a lease ID is in the revocation set.
    pub fn is_revoked(&self, lease_id: &LeaseId) -> bool {
        self.revoked.read().contains(lease_id)
    }

    /// Get the next monotonic sequence number.
    pub fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::AcqRel)
    }

    /// Returns the total number of active leases (non-revoked).
    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.leases
            .read()
            .values()
            .filter(|l| l.revocation_state == RevocationState::Active)
            .count()
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Claim checks for a presented lease (expiry, sandbox, tenant, action, epoch).
pub fn check_lease_claims(
    lease: &AccessLease,
    sandbox_id: &SandboxId,
    tenant_id: &TenantId,
    action: LeaseAction,
    current_policy_epoch: u64,
) -> Result<(), LeaseValidationError> {
    match lease.revocation_state {
        RevocationState::Active => {}
        RevocationState::Revoked { reason } => {
            return Err(LeaseValidationError::Revoked { reason });
        }
    }

    let current = now_iso();
    if has_lease_expired(&lease.expires_at, &current) {
        return Err(LeaseValidationError::Expired {
            expires_at: lease.expires_at.clone(),
            current,
        });
    }

    if &lease.sandbox_id != sandbox_id {
        return Err(LeaseValidationError::WrongSandbox {
            expected: sandbox_id.to_string(),
            actual: lease.sandbox_id.to_string(),
        });
    }

    if &lease.tenant_id != tenant_id {
        return Err(LeaseValidationError::WrongTenant {
            expected: tenant_id.to_string(),
            actual: lease.tenant_id.to_string(),
        });
    }

    if lease.action != action {
        return Err(LeaseValidationError::WrongAction {
            expected: action,
            actual: lease.action,
        });
    }

    if lease.policy_epoch < current_policy_epoch {
        return Err(LeaseValidationError::StalePolicyEpoch {
            lease_epoch: lease.policy_epoch,
            current_epoch: current_policy_epoch,
        });
    }

    Ok(())
}

/// Checks that `requested` is within `lease.scope`. Empty lease bounds are unbounded.
pub fn check_lease_scope(
    lease: &AccessLease,
    requested: &LeaseScope,
) -> Result<(), LeaseValidationError> {
    for port in &requested.ports {
        if !lease.scope.ports.is_empty() && !lease.scope.ports.contains(port) {
            return Err(LeaseValidationError::ScopeExceeded {
                detail: format!("port {port} not in allowed scope"),
            });
        }
    }

    for path in &requested.paths {
        if !lease.scope.paths.is_empty()
            && !lease
                .scope
                .paths
                .iter()
                .any(|allowed| path.starts_with(allowed))
        {
            return Err(LeaseValidationError::ScopeExceeded {
                detail: format!("path {path} not in allowed scope"),
            });
        }
    }

    for cidr in &requested.egress_cidrs {
        if !lease.scope.egress_cidrs.is_empty() && !lease.scope.egress_cidrs.contains(cidr) {
            return Err(LeaseValidationError::ScopeExceeded {
                detail: format!("egress CIDR {cidr} not in allowed scope"),
            });
        }
    }

    for credential_type in &requested.credential_types {
        if !lease.scope.credential_types.is_empty()
            && !lease.scope.credential_types.contains(credential_type)
        {
            return Err(LeaseValidationError::ScopeExceeded {
                detail: format!("credential type {credential_type} not in allowed scope"),
            });
        }
    }

    Ok(())
}

/// Checks whether a lease timestamp has passed the current time.
///
/// Uses a lenient comparison: `expires_at <= current` means expired.
pub fn has_lease_expired(expires_at: &str, current: &str) -> bool {
    let fmt = time::format_description::well_known::Iso8601::DEFAULT;
    let expiry = time::OffsetDateTime::parse(expires_at, &fmt);
    let now = time::OffsetDateTime::parse(current, &fmt);

    match (expiry, now) {
        (Ok(exp), Ok(now)) => exp <= now,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyAction, PolicyEngine};

    const DEFAULT_LEASE_TTL_SECS: u64 = 3600;

    fn default_allow_policy() -> &'static str {
        r#"
permit(
    principal,
    action,
    resource
);
"#
    }

    fn make_decision(engine: &PolicyEngine) -> PolicyDecision {
        let principal = PrincipalId::new("user:test");
        let tenant = TenantId::generate();
        engine.evaluate(&principal, &tenant, PolicyAction::Exec)
    }

    // ──── Lease issue and retrieval ────

    #[test]
    fn issue_lease_and_retrieve() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject.clone(),
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            300,
        );

        assert!(lease.lease_id.as_str().starts_with("lse_"));
        assert_eq!(lease.tenant_id, tenant);
        assert_eq!(lease.subject, subject);
        assert_eq!(lease.sandbox_id, sandbox);
        assert_eq!(lease.action, LeaseAction::Exec);
        assert_eq!(lease.policy_epoch, decision.policy_epoch);
        assert_eq!(lease.revocation_state, RevocationState::Active);

        let retrieved = mgr.get(&lease.lease_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), lease);
    }

    #[test]
    fn issue_multiple_leases_unique_ids() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:bob");
        let sandbox = SandboxId::generate();

        let lease1 = mgr.issue(
            tenant.clone(),
            subject.clone(),
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            300,
        );

        let lease2 = mgr.issue(
            tenant.clone(),
            subject.clone(),
            sandbox.clone(),
            LeaseAction::FileTransfer,
            LeaseScope::unbounded(),
            &decision,
            600,
        );

        assert_ne!(lease1.lease_id, lease2.lease_id);
        assert_eq!(mgr.active_count(), 2);
    }

    // ──── Lease validation: happy path ────

    #[test]
    fn validate_active_lease() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );

        assert!(result.is_ok());
    }

    // ──── Lease validation: negative tests ────

    #[test]
    fn validate_rejects_not_found() {
        let mgr = LeaseManager::new();
        let fake_id = LeaseId::generate();

        let result = mgr.validate(
            &fake_id,
            &SandboxId::generate(),
            &TenantId::generate(),
            LeaseAction::Exec,
            1,
        );

        assert!(matches!(result, Err(LeaseValidationError::NotFound { .. })));
    }

    #[test]
    fn validate_rejects_revoked_lease() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        mgr.revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );

        assert!(matches!(result, Err(LeaseValidationError::Revoked { .. })));
    }

    #[test]
    fn validate_rejects_expired_lease() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        // Issue a short-lived lease, then mutate expires_at to simulate immediate expiry
        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            1,
        );

        // Override expires_at to simulate immediate expiry
        mgr.leases
            .write()
            .get_mut(&lease.lease_id)
            .unwrap()
            .expires_at = "2020-01-01T00:00:00Z".into();

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );

        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn validate_rejects_wrong_sandbox() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();
        let other_sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox,
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = mgr.validate(
            &lease.lease_id,
            &other_sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::WrongSandbox { .. })
        ));
    }

    #[test]
    fn validate_rejects_wrong_tenant() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let other_tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant,
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &other_tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::WrongTenant { .. })
        ));
    }

    #[test]
    fn validate_rejects_wrong_action() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::FileTransfer,
            decision.policy_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::WrongAction { .. })
        ));
    }

    #[test]
    fn validate_rejects_stale_policy_epoch() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Validate with a newer epoch than the lease's
        let newer_epoch = decision.policy_epoch + 1;
        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            newer_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::StalePolicyEpoch { .. })
        ));
    }

    // ──── Lease renewal ────

    #[test]
    fn renew_lease_produces_new_lease_and_revokes_old() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            subject,
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            300,
        );

        // Load new policies to get a different epoch
        engine.load_policies(default_allow_policy()).unwrap();
        let new_decision = make_decision(&engine);

        let renewed = mgr.renew(&lease.lease_id, &new_decision, 300).unwrap();

        // Old lease should be revoked
        assert!(mgr.is_revoked(&lease.lease_id));

        // New lease should be active
        assert_eq!(renewed.revocation_state, RevocationState::Active);
        assert_ne!(renewed.lease_id, lease.lease_id);
        assert_eq!(renewed.sandbox_id, sandbox);
        assert_eq!(renewed.action, LeaseAction::Exec);
        assert_eq!(renewed.policy_epoch, new_decision.policy_epoch);
    }

    #[test]
    fn renew_nonexistent_lease_fails() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let fake_id = LeaseId::generate();

        let result = mgr.renew(&fake_id, &decision, 300);
        assert!(result.is_err());
    }

    // ──── Lease revocation ────

    #[test]
    fn revoke_marks_lease_and_adds_to_revocation_set() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant,
            subject,
            sandbox,
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        mgr.revoke(&lease.lease_id, RevocationReason::PolicyChanged)
            .unwrap();

        assert!(mgr.is_revoked(&lease.lease_id));

        let retrieved = mgr.get(&lease.lease_id).unwrap();
        assert_eq!(
            retrieved.revocation_state,
            RevocationState::Revoked {
                reason: RevocationReason::PolicyChanged
            }
        );
    }

    #[test]
    fn double_revoke_fails() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let lease = mgr.issue(
            TenantId::generate(),
            PrincipalId::new("user:alice"),
            SandboxId::generate(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        mgr.revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();
        let result = mgr.revoke(&lease.lease_id, RevocationReason::PolicyChanged);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_nonexistent_lease_fails() {
        let mgr = LeaseManager::new();
        let result = mgr.revoke(&LeaseId::generate(), RevocationReason::AdminAction);
        assert!(result.is_err());
    }

    // ──── Scope validation ────

    #[test]
    fn validate_with_scope_port_bounds() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let scope = LeaseScope {
            ports: vec![8080, 3000],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec![],
        };

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::PortForward,
            scope,
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Allowed port
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::PortForward,
            &LeaseScope {
                ports: vec![8080],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(result.is_ok());

        // Disallowed port
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::PortForward,
            &LeaseScope {
                ports: vec![9999],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(matches!(
            result,
            Err(LeaseValidationError::ScopeExceeded { .. })
        ));
    }

    #[test]
    fn validate_with_scope_path_prefix_bounds() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let scope = LeaseScope {
            ports: vec![],
            paths: vec!["/workspace/".into()],
            egress_cidrs: vec![],
            credential_types: vec![],
        };

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::FileTransfer,
            scope,
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Allowed path
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::FileTransfer,
            &LeaseScope {
                ports: vec![],
                paths: vec!["/workspace/output.txt".into()],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(result.is_ok());

        // Disallowed path
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::FileTransfer,
            &LeaseScope {
                ports: vec![],
                paths: vec!["/etc/passwd".into()],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(matches!(
            result,
            Err(LeaseValidationError::ScopeExceeded { .. })
        ));
    }

    #[test]
    fn validate_with_scope_egress_cidr_bounds() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let scope = LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec!["10.0.0.0/8".into()],
            credential_types: vec![],
        };

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::EgressException,
            scope,
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Allowed CIDR
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::EgressException,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec!["10.0.0.0/8".into()],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(result.is_ok());

        // Disallowed CIDR
        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::EgressException,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec!["192.168.0.0/16".into()],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(matches!(
            result,
            Err(LeaseValidationError::ScopeExceeded { .. })
        ));
    }

    #[test]
    fn unbounded_scope_allows_anything() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::SnapshotOperation,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::SnapshotOperation,
            &LeaseScope {
                ports: vec![9999],
                paths: vec!["/anywhere".into()],
                egress_cidrs: vec!["0.0.0.0/0".into()],
                credential_types: vec![],
            },
            decision.policy_epoch,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_with_scope_credential_type_bounds() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let scope = LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: vec!["aws".into()],
        };

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::CredentialAccess,
            scope,
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let allowed = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            decision.policy_epoch,
        );
        assert!(allowed.is_ok());

        let denied = mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["gcp".into()],
            },
            decision.policy_epoch,
        );
        assert!(matches!(
            denied,
            Err(LeaseValidationError::ScopeExceeded { .. })
        ));
    }

    // ──── Cleanup ────

    #[test]
    fn cleanup_removes_expired_leases() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant,
            subject,
            sandbox,
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Force expiry
        mgr.leases
            .write()
            .get_mut(&lease.lease_id)
            .unwrap()
            .expires_at = "2020-01-01T00:00:00Z".into();

        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 1);
        assert!(mgr.get(&lease.lease_id).is_none());
    }

    #[test]
    fn cleanup_removes_revoked_from_revocation_set() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let lease = mgr.issue(
            TenantId::generate(),
            PrincipalId::new("user:alice"),
            SandboxId::generate(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        mgr.revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();
        assert!(mgr.is_revoked(&lease.lease_id));

        // Force expiry
        mgr.leases
            .write()
            .get_mut(&lease.lease_id)
            .unwrap()
            .expires_at = "2020-01-01T00:00:00Z".into();

        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 1);
        assert!(mgr.get(&lease.lease_id).is_none());
        assert!(!mgr.is_revoked(&lease.lease_id));
    }

    #[test]
    fn cleanup_keeps_active_leases() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let lease = mgr.issue(
            TenantId::generate(),
            PrincipalId::new("user:alice"),
            SandboxId::generate(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 0);
        assert!(mgr.get(&lease.lease_id).is_some());
    }

    // ──── Serialization ────

    #[test]
    fn lease_serialization_roundtrip() {
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();
        let decision = make_decision(&engine);

        let lease = AccessLease {
            lease_id: LeaseId::generate(),
            tenant_id: TenantId::generate(),
            subject: PrincipalId::new("user:alice"),
            sandbox_id: SandboxId::generate(),
            action: LeaseAction::Exec,
            scope: LeaseScope {
                ports: vec![8080],
                paths: vec!["/tmp".into()],
                egress_cidrs: vec!["10.0.0.0/8".into()],
                credential_types: vec![],
            },
            policy_decision_id: decision.decision_id,
            policy_epoch: 1,
            issued_at: "2026-06-01T00:00:00Z".into(),
            expires_at: "2026-06-02T00:00:00Z".into(),
            revocation_state: RevocationState::Active,
            signature: None,
        };

        let json = serde_json::to_string(&lease).unwrap();
        let back: AccessLease = serde_json::from_str(&json).unwrap();

        assert_eq!(back.lease_id, lease.lease_id);
        assert_eq!(back.tenant_id, lease.tenant_id);
        assert_eq!(back.subject, lease.subject);
        assert_eq!(back.sandbox_id, lease.sandbox_id);
        assert_eq!(back.action, lease.action);
        assert_eq!(back.scope, lease.scope);
        assert_eq!(back.policy_decision_id, lease.policy_decision_id);
        assert_eq!(back.policy_epoch, lease.policy_epoch);
        assert_eq!(back.issued_at, lease.issued_at);
        assert_eq!(back.expires_at, lease.expires_at);
        assert_eq!(back.revocation_state, lease.revocation_state);
    }

    // ──── Edge cases ────

    #[test]
    fn issuing_with_zero_ttl_is_immediately_expired() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            0,
        );

        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );
        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn validate_with_valid_epoch_when_same() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();

        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();

        let lease = mgr.issue(
            tenant.clone(),
            PrincipalId::new("user:alice"),
            sandbox.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Same epoch is fine
        let result = mgr.validate(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::Exec,
            decision.policy_epoch,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn sequence_number_is_monotonic() {
        let mgr = LeaseManager::new();
        let s1 = mgr.next_sequence();
        let s2 = mgr.next_sequence();
        let s3 = mgr.next_sequence();
        assert!(s1 < s2);
        assert!(s2 < s3);
    }

    #[test]
    fn has_lease_expired_detects_expiry() {
        assert!(has_lease_expired(
            "2020-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z"
        ));
        assert!(!has_lease_expired(
            "2026-06-10T00:00:00Z",
            "2025-01-01T00:00:00Z"
        ));
        assert!(has_lease_expired(
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z"
        ));
    }

    #[test]
    fn lease_action_display_matches_serde() {
        assert_eq!(LeaseAction::Exec.as_str(), "exec");
        assert_eq!(LeaseAction::FileTransfer.as_str(), "file_transfer");
        assert_eq!(LeaseAction::PortForward.as_str(), "port_forward");
        assert_eq!(LeaseAction::EgressException.as_str(), "egress_exception");
        assert_eq!(
            LeaseAction::SnapshotOperation.as_str(),
            "snapshot_operation"
        );
        assert_eq!(LeaseAction::AdminOverride.as_str(), "admin_override");
        assert_eq!(LeaseAction::CredentialAccess.as_str(), "credential_access");
    }

    #[test]
    fn revocation_state_serde_roundtrip() {
        let state = RevocationState::Revoked {
            reason: RevocationReason::PolicyChanged,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("revoked"));
        assert!(json.contains("policy_changed"));

        let back: RevocationState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);

        let active = RevocationState::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert!(json.contains("active"));
        let back: RevocationState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, active);
    }

    #[test]
    fn lease_validation_error_display() {
        let err = LeaseValidationError::Expired {
            expires_at: "2020-01-01T00:00:00Z".into(),
            current: "2026-01-01T00:00:00Z".into(),
        };
        assert!(err.to_string().contains("expired"));

        let err = LeaseValidationError::WrongSandbox {
            expected: "sbx_a".into(),
            actual: "sbx_b".into(),
        };
        assert!(err.to_string().contains("sbx_a"));
    }

    #[test]
    fn lease_action_all_variants_covered() {
        let actions = [
            LeaseAction::Exec,
            LeaseAction::FileTransfer,
            LeaseAction::PortForward,
            LeaseAction::EgressException,
            LeaseAction::SnapshotOperation,
            LeaseAction::AdminOverride,
            LeaseAction::CredentialAccess,
        ];

        let mut seen = hashbrown::HashSet::new();
        for action in &actions {
            let s = action.as_str();
            assert!(seen.insert(s), "duplicate action string: {s}");
            let name = format!("{action:?}");
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn bounded_actions_require_explicit_scope() {
        assert!(LeaseAction::PortForward.requires_explicit_scope());
        assert!(!LeaseAction::Exec.requires_explicit_scope());
        assert!(!LeaseScope::unbounded().has_bounds_for(LeaseAction::PortForward));
        assert!(
            LeaseScope {
                ports: vec![8080],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            }
            .has_bounds_for(LeaseAction::PortForward)
        );
    }

    // ──── Destroy-path revocation (issue 140) ────

    #[test]
    fn revoke_for_sandbox_revokes_all_actions_and_skips_foreign() {
        use crate::event_bus::InMemoryAuditSink;
        use std::sync::Arc;

        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(crate::identity::Hlc::new());
        let mgr =
            LeaseManager::with_audit_sink(sink as Arc<dyn crate::event_bus::AuditEventSink>, hlc);
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();
        let decision = make_decision(&engine);

        let sbx = SandboxId::generate();
        let other = SandboxId::generate();
        let tenant = TenantId::generate();
        let subject = PrincipalId::new("user:alice");

        let a = mgr.issue(
            tenant.clone(),
            subject.clone(),
            sbx.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );
        let b = mgr.issue(
            tenant.clone(),
            subject.clone(),
            sbx.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );
        let foreign = mgr.issue(
            tenant.clone(),
            subject,
            other.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let revoked = mgr.revoke_for_sandbox(&sbx, RevocationReason::ResourceRemoved);
        assert_eq!(revoked.len(), 2);
        assert!(revoked.contains(&a.lease_id));
        assert!(revoked.contains(&b.lease_id));

        for (id, action) in [
            (&a.lease_id, LeaseAction::Exec),
            (&b.lease_id, LeaseAction::CredentialAccess),
        ] {
            assert!(matches!(
                mgr.validate(id, &sbx, &tenant, action, decision.policy_epoch),
                Err(LeaseValidationError::Revoked { .. })
            ));
        }
        assert!(
            mgr.validate(
                &foreign.lease_id,
                &other,
                &tenant,
                LeaseAction::Exec,
                decision.policy_epoch
            )
            .is_ok()
        );
        assert!(mgr.active_leases_for_sandbox(&sbx).is_empty());
    }

    #[test]
    fn revoke_for_sandbox_is_idempotent_and_skips_revoked() {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();
        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sbx = SandboxId::generate();

        let lease = mgr.issue(
            tenant,
            PrincipalId::new("user:alice"),
            sbx.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );
        mgr.revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();
        assert!(
            mgr.revoke_for_sandbox(&sbx, RevocationReason::ResourceRemoved)
                .is_empty()
        );
        assert!(
            mgr.revoke_for_sandbox(&SandboxId::generate(), RevocationReason::ResourceRemoved)
                .is_empty()
        );
    }

    #[test]
    fn revoke_with_context_carries_operation_identity() {
        use crate::event_bus::InMemoryAuditSink;
        use crate::identity::OperationId;
        use std::sync::Arc;

        let sink = Arc::new(InMemoryAuditSink::new());
        let hlc = Arc::new(crate::identity::Hlc::new());
        let mgr = LeaseManager::with_audit_sink(
            Arc::<InMemoryAuditSink>::clone(&sink) as Arc<dyn crate::event_bus::AuditEventSink>,
            hlc,
        );
        let engine = PolicyEngine::new();
        engine.load_policies(default_allow_policy()).unwrap();
        let decision = make_decision(&engine);
        let tenant = TenantId::generate();
        let sbx = SandboxId::generate();

        let lease = mgr.issue(
            tenant,
            PrincipalId::new("user:alice"),
            sbx.clone(),
            LeaseAction::Exec,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );
        let op = OperationId::generate();
        let ctx = DestroyRevocationContext {
            operation_id: Some(op.clone()),
            principal: Some(PrincipalId::new("user:destroyer")),
        };
        mgr.revoke_for_sandbox_with_context(&sbx, RevocationReason::ResourceRemoved, Some(&ctx));

        let events = sink.events_by_kind(crate::identity::AuditEventKind::LeaseRevoked);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id.as_ref(), Some(&op));
        assert_eq!(
            events[0].principal.as_ref(),
            Some(&PrincipalId::new("user:destroyer"))
        );
        match &events[0].details {
            Some(crate::identity::AuditEventDetails::LeaseOperation { lease_id, .. }) => {
                assert_eq!(lease_id, lease.lease_id.as_str());
            }
            d => panic!("lease revoke must carry lease identity, got {d:?}"),
        }
    }
}
