//! Principal and service identity types.
//!
//! These types represent authenticated callers and service components
//! that participate in PicoCompute's zero-trust authorization model.

use serde::{Deserialize, Serialize};
use std::fmt;

/// An authenticated identity that is a security principal.
///
/// Represents a user, service account, or machine identity that has been
/// authenticated by the control plane. This is what leases are issued to
/// and what audit events record as the initiating actor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Creates a principal identifier from an authenticated identity string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An identity representing a PicoCompute service component.
///
/// Used for service-to-service authentication where the identity of a
/// component (e.g., host-agent, guest-agent, cell controller) must be
/// verified independently of the principal that initiated the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceId(String);

impl ServiceId {
    /// Creates a service identity from a component name.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A workload-level identity for service-to-service authentication.
///
/// Distinct from `PrincipalId` in that it represents the identity of a
/// running workload rather than the human or service account that
/// initiated it. Used for intra-platform authorization checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadIdentity(String);

impl WorkloadIdentity {
    /// Creates a workload identity from a string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkloadIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Binds a specific principal to a service component for an operation.
///
/// This is the contract that proves which authenticated caller initiated
/// an operation being executed by a service component. The service
/// component must verify that the principal is authorized before acting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityBinding {
    /// The authenticated principal that initiated the action.
    pub principal: PrincipalId,
    /// The service component executing the action.
    pub service: ServiceId,
    /// When this binding was issued (ISO 8601 UTC).
    pub issued_at: String,
    /// When this binding expires (ISO 8601 UTC).
    pub expires_at: String,
    /// Ed25519 signature over the binding fields, issued by the control plane.
    ///
    /// The signature covers the canonical serialization of `principal`,
    /// `service`, `issued_at`, `expires_at` in that order. The signing key
    /// is the control plane's Ed25519 private key; the public key is
    /// distributed to all compute-plane components for verification.
    /// When `None`, the binding is unsigned and must not be trusted
    /// outside the immediate request context.
    #[serde(skip)]
    pub signature: Option<Vec<u8>>,
}

/// Service-to-service authentication binding.
///
/// Used when one PicoCompute service component (e.g., the cell controller)
/// calls another (e.g., the host agent). The caller proves its identity
/// to the callee, which verifies the binding before accepting the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceBinding {
    /// The calling service component.
    pub caller: ServiceId,
    /// The target service component.
    pub target: ServiceId,
    /// The workload context, if applicable.
    pub workload: Option<WorkloadIdentity>,
    /// When this binding was issued (ISO 8601 UTC).
    pub issued_at: String,
    /// When this binding expires (ISO 8601 UTC).
    pub expires_at: String,
    /// Ed25519 signature over the binding fields, issued by the control plane.
    ///
    /// The signature covers the canonical serialization of `caller`, `target`,
    /// `workload`, `issued_at`, `expires_at` in that order. When `None`, the
    /// binding is unsigned and must not be trusted outside the immediate
    /// request context.
    #[serde(skip)]
    pub signature: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_id_is_security_principal() {
        let p = PrincipalId::new("user:alice@example.com");
        assert_eq!(p.as_str(), "user:alice@example.com");
    }

    #[test]
    fn service_id_identifies_component() {
        let s = ServiceId::new("host-agent");
        assert_eq!(s.as_str(), "host-agent");
    }

    #[test]
    fn workload_identity_roundtrip() {
        let w = WorkloadIdentity::new("sandbox:sbx_01JXYZ");
        let json = serde_json::to_string(&w).unwrap();
        let back: WorkloadIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn identity_binding_links_principal_to_service() {
        let binding = IdentityBinding {
            principal: PrincipalId::new("user:alice"),
            service: ServiceId::new("host-agent"),
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:05:00Z".into(),
            signature: None,
        };
        assert_eq!(binding.principal.as_str(), "user:alice");
        assert_eq!(binding.service.as_str(), "host-agent");
    }

    #[test]
    fn service_binding_for_component_call() {
        let binding = ServiceBinding {
            caller: ServiceId::new("cell-controller"),
            target: ServiceId::new("host-agent"),
            workload: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:05:00Z".into(),
            signature: None,
        };
        assert_eq!(binding.caller.as_str(), "cell-controller");
    }

    #[test]
    fn identity_binding_must_match_principal() {
        let binding = IdentityBinding {
            principal: PrincipalId::new("user:alice"),
            service: ServiceId::new("host-agent"),
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:05:00Z".into(),
            signature: None,
        };

        let wrong_principal = PrincipalId::new("user:eve");
        assert_ne!(binding.principal, wrong_principal);
    }

    #[test]
    fn service_binding_must_match_caller() {
        let binding = ServiceBinding {
            caller: ServiceId::new("cell-controller"),
            target: ServiceId::new("host-agent"),
            workload: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:05:00Z".into(),
            signature: None,
        };

        let impersonator = ServiceId::new("rogue-agent");
        assert_ne!(binding.caller, impersonator);
    }

    #[test]
    fn principal_and_service_are_distinct_types() {
        let p = PrincipalId::new("user:alice");
        let s = ServiceId::new("host-agent");
        assert_eq!(p.as_str(), "user:alice");
        assert_eq!(s.as_str(), "host-agent");
    }
}
