//! Types for runtime secrets broker integration.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::{LeaseId, PolicyDecisionId, SandboxId, TenantId};

/// A request to fetch credentials from a secrets broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Tenant that owns the sandbox.
    pub tenant_id: TenantId,
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Logical operation identity.
    pub operation_id: String,
    /// Policy decision that authorized the request.
    pub policy_decision_id: Option<PolicyDecisionId>,
    /// Access lease bound to the request.
    pub lease_id: Option<LeaseId>,
    /// Requested credential types.
    pub credential_types: Vec<String>,
}

/// A single credential value returned by the broker.
///
/// The value is zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredentialValue {
    /// Human-readable credential name (safe to log).
    #[zeroize(skip)]
    pub name: String,
    /// Raw credential bytes.
    pub value: Vec<u8>,
}

impl CredentialValue {
    /// Create a credential value from a UTF-8 string.
    pub fn from_string(name: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            name: name.into(),
            value: value.into_bytes(),
        }
    }
}

/// A bundle of credentials returned for one request.
#[derive(Debug, Clone)]
pub struct CredentialBundle {
    /// Lease ID that authorized the bundle, if any.
    pub lease_id: Option<LeaseId>,
    /// Wall-clock expiry time in ISO 8601 UTC, if known.
    pub expires_at: Option<String>,
    /// Credentials to inject into the sandbox.
    pub credentials: Vec<CredentialValue>,
}

/// A reference to an injected credential file inside the sandbox.
#[derive(Debug, Clone)]
pub struct CredentialRef {
    /// Credential name.
    pub name: String,
    /// Absolute path inside the sandbox.
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_value_zeroizes_on_drop() {
        let mut value = CredentialValue::from_string("api_key", "super-secret");
        value.value.zeroize();
        assert!(value.value.iter().all(|&b| b == 0));
    }

    #[test]
    fn credential_request_serializes() {
        let request = CredentialRequest {
            tenant_id: TenantId::generate(),
            sandbox_id: SandboxId::generate(),
            operation_id: "op_001".into(),
            policy_decision_id: None,
            lease_id: None,
            credential_types: vec!["aws".into()],
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("aws"));
    }
}
