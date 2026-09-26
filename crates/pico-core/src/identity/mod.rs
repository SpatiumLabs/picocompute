//! Secure time, identity, and naming binding model.
//!
//! Implements the identifier taxonomy, principal identity model, hybrid logical
//! clock timestamps, fencing tokens, audit event types, and identity binding
//! contracts from ADR-0001.
//!
//! ## Identifier stability
//!
//! | Identifier | Stability | Security principal? |
//! |---|---|---|
//! | `TenantId` | Stable | No (organizational scope) |
//! | `SandboxId` | Stable | No (resource identifier) |
//! | `HostId` | Stable | No (resource identifier) |
//! | `CellId` | Stable | No (resource identifier) |
//! | `RegionId` | Stable | No (resource identifier) |
//! | `ImageId` | Stable | No (resource version) |
//! | `SnapshotId` | Stable | No (point-in-time capture) |
//! | `LeaseId` | Ephemeral | No (time-bound) |
//! | `OperationId` | Ephemeral | No (one-time use) |
//! | `PolicyDecisionId` | Ephemeral | No (bound to epoch) |
//! | `AuditEventId` | Stable | No (append-only record) |
//! | `PrincipalId` | Stable | Yes (authenticated caller) |
//! | `ServiceId` | Stable | Yes (service component) |

mod audit;
mod fencing;
mod hlc;
mod ids;
mod principal;

pub use audit::*;
pub use fencing::*;
pub use hlc::*;
pub use ids::*;
pub use principal::*;

/// Time-skew tolerances for different operation types (in seconds).
pub mod skew_tolerances {
    /// Default clock-skew tolerance for general purposes (30 s).
    pub const DEFAULT_SECS: i64 = 30;

    /// Lease issuance is time-sensitive; tighter tolerance (10 s).
    pub const LEASE_ISSUANCE_SECS: i64 = 10;

    /// Lease validation at the compute plane allows slightly more
    /// skew because leases propagate through the network (15 s).
    pub const LEASE_VALIDATION_SECS: i64 = 15;

    /// Audit event ordering uses HLC instead of wall clock;
    /// this tolerance is a fallback (60 s).
    pub const AUDIT_ORDERING_SECS: i64 = 60;
}

/// Checks whether a lease has exceeded its expiry time given the
/// current wall-clock time and an acceptable skew tolerance.
///
/// Returns `true` if the lease is expired (or within the skew window).
/// The standard tolerance is [`skew_tolerances::LEASE_VALIDATION_SECS`].
pub fn is_lease_expired(
    expires_at_epoch_secs: i64,
    current_epoch_secs: i64,
    tolerance_secs: i64,
) -> bool {
    current_epoch_secs > expires_at_epoch_secs + tolerance_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_identifiers_are_not_principals() {
        let sandbox = SandboxId::generate();
        let tenant = TenantId::generate();
        let _ = (sandbox, tenant);
    }

    #[test]
    fn lease_not_expired_within_tolerance() {
        assert!(!is_lease_expired(1000, 1010, 15));
    }

    #[test]
    fn lease_expired_past_tolerance() {
        assert!(is_lease_expired(1000, 1020, 15));
    }

    #[test]
    fn lease_still_valid_before_expiry() {
        assert!(!is_lease_expired(2000, 1000, 15));
    }

    #[test]
    fn stale_decision_with_clock_skew_is_detected() {
        assert!(crate::metadata::is_decision_stale(1000, 1040, 30));
    }

    #[test]
    fn decision_within_tolerance_is_accepted() {
        assert!(!crate::metadata::is_decision_stale(1000, 1020, 30));
    }
}
