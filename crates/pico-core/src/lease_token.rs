//! Signed access-lease blobs for cross-process enforcement.
//!
//! [`LeaseAuthority`] is the issue/enforce seam: the control plane signs, and
//! edge/host adapters verify without sharing the issuer's in-memory store.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::identity::{LeaseId, PolicyDecisionId, PrincipalId, SandboxId, TenantId};
use crate::leases::{
    AccessLease, LeaseAction, LeaseScope, LeaseValidationError, RevocationState,
    check_lease_claims, check_lease_scope,
};

const SIGNING_KEY_LEN: usize = 32;
const VERIFYING_KEY_LEN: usize = 32;

/// Signs and verifies access-lease blobs.
#[derive(Clone)]
pub struct LeaseAuthority {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

/// Context an enforcer checks a presented lease against.
pub struct EnforceContext<'a> {
    /// Target sandbox.
    pub sandbox_id: &'a SandboxId,
    /// Tenant that owns the sandbox.
    pub tenant_id: &'a TenantId,
    /// Requested data-plane action.
    pub action: LeaseAction,
    /// Requested scope bounds.
    pub scope: &'a LeaseScope,
    /// Current policy epoch at the enforcer.
    pub policy_epoch: u64,
}

#[derive(Serialize, Deserialize)]
struct LeaseWire {
    lease_id: LeaseId,
    tenant_id: TenantId,
    subject: PrincipalId,
    sandbox_id: SandboxId,
    action: LeaseAction,
    scope: LeaseScope,
    policy_decision_id: PolicyDecisionId,
    policy_epoch: u64,
    issued_at: String,
    expires_at: String,
    revocation_state: RevocationState,
    signature: String,
}

impl LeaseAuthority {
    /// Generates an ephemeral signing authority. Suitable for tests and
    /// single-process boot when no key is configured.
    pub fn generate() -> Self {
        let mut seed = [0u8; SIGNING_KEY_LEN];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key: Some(signing_key),
            verifying_key,
        }
    }

    /// Loads a signing authority from a base64-encoded 32-byte seed.
    pub fn from_signing_key_base64(encoded: &str) -> Result<Self, String> {
        let seed = decode_fixed::<SIGNING_KEY_LEN>(encoded, "signing key")?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key,
        })
    }

    /// Loads a verify-only authority from a base64-encoded 32-byte public key.
    pub fn from_verifying_key_base64(encoded: &str) -> Result<Self, String> {
        let bytes = decode_fixed::<VERIFYING_KEY_LEN>(encoded, "verifying key")?;
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid verifying key: {e}"))?;
        Ok(Self {
            signing_key: None,
            verifying_key,
        })
    }

    /// Returns the base64-encoded verifying key for distribution to enforcers.
    pub fn verifying_key_base64(&self) -> String {
        BASE64.encode(self.verifying_key.as_bytes())
    }

    /// Signs `lease` in place. Fails if this authority is verify-only.
    pub fn sign(&self, lease: &mut AccessLease) -> Result<(), String> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| "lease authority has no signing key".to_string())?;
        let payload = canonical_bytes(lease).map_err(|e| e.to_string())?;
        let signature = signing_key.sign(&payload);
        lease.signature = Some(signature.to_bytes().to_vec());
        Ok(())
    }

    /// Verifies the signature on a presented lease.
    pub fn verify_signature(&self, lease: &AccessLease) -> Result<(), LeaseValidationError> {
        let Some(sig_bytes) = lease.signature.as_ref() else {
            return Err(LeaseValidationError::InvalidSignature);
        };
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LeaseValidationError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_array);
        let payload = canonical_bytes(lease).map_err(|_| LeaseValidationError::InvalidSignature)?;
        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| LeaseValidationError::InvalidSignature)
    }

    /// Enforces a presented lease: signature, claims, and scope.
    pub fn enforce(
        &self,
        lease: &AccessLease,
        ctx: &EnforceContext<'_>,
    ) -> Result<(), LeaseValidationError> {
        self.verify_signature(lease)?;
        check_lease_claims(
            lease,
            ctx.sandbox_id,
            ctx.tenant_id,
            ctx.action,
            ctx.policy_epoch,
        )?;
        check_lease_scope(lease, ctx.scope)
    }

    /// Enforces a blob, then rejects it if `is_revoked` reports the lease id.
    ///
    /// Blob enforcement is offline; revocation is only visible to enforcers
    /// that share a revocation set with the issuer. Edge without a store
    /// relies on lease TTL.
    pub fn enforce_blob_revocable(
        &self,
        blob: &str,
        ctx: &EnforceContext<'_>,
        is_revoked: impl Fn(&crate::identity::LeaseId) -> bool,
    ) -> Result<AccessLease, LeaseValidationError> {
        let lease = self.enforce_blob(blob, ctx)?;
        if is_revoked(&lease.lease_id) {
            return Err(LeaseValidationError::Revoked {
                reason: crate::leases::RevocationReason::AdminAction,
            });
        }
        Ok(lease)
    }

    /// Decodes a blob and enforces it.
    pub fn enforce_blob(
        &self,
        blob: &str,
        ctx: &EnforceContext<'_>,
    ) -> Result<AccessLease, LeaseValidationError> {
        let lease = decode_lease_blob(blob)?;
        self.enforce(&lease, ctx)?;
        Ok(lease)
    }
}

/// Encodes a signed lease as a base64 JSON blob for headers and request bodies.
pub fn encode_lease_blob(lease: &AccessLease) -> Result<String, String> {
    let signature = lease
        .signature
        .as_ref()
        .ok_or_else(|| "lease is unsigned".to_string())?;
    let wire = LeaseWire {
        lease_id: lease.lease_id.clone(),
        tenant_id: lease.tenant_id.clone(),
        subject: lease.subject.clone(),
        sandbox_id: lease.sandbox_id.clone(),
        action: lease.action,
        scope: lease.scope.clone(),
        policy_decision_id: lease.policy_decision_id.clone(),
        policy_epoch: lease.policy_epoch,
        issued_at: lease.issued_at.clone(),
        expires_at: lease.expires_at.clone(),
        revocation_state: lease.revocation_state,
        signature: BASE64.encode(signature),
    };
    let json = serde_json::to_vec(&wire).map_err(|e| e.to_string())?;
    Ok(BASE64.encode(json))
}

/// Decodes a base64 JSON lease blob.
pub fn decode_lease_blob(blob: &str) -> Result<AccessLease, LeaseValidationError> {
    let json = BASE64
        .decode(blob.as_bytes())
        .map_err(|e| LeaseValidationError::Malformed {
            detail: format!("base64: {e}"),
        })?;
    let wire: LeaseWire =
        serde_json::from_slice(&json).map_err(|e| LeaseValidationError::Malformed {
            detail: format!("json: {e}"),
        })?;
    let signature =
        BASE64
            .decode(wire.signature.as_bytes())
            .map_err(|e| LeaseValidationError::Malformed {
                detail: format!("signature base64: {e}"),
            })?;
    Ok(AccessLease {
        lease_id: wire.lease_id,
        tenant_id: wire.tenant_id,
        subject: wire.subject,
        sandbox_id: wire.sandbox_id,
        action: wire.action,
        scope: wire.scope,
        policy_decision_id: wire.policy_decision_id,
        policy_epoch: wire.policy_epoch,
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
        revocation_state: wire.revocation_state,
        signature: Some(signature),
    })
}

fn canonical_bytes(lease: &AccessLease) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::json!([
        lease.lease_id.as_str(),
        lease.tenant_id.as_str(),
        lease.subject.as_str(),
        lease.sandbox_id.as_str(),
        lease.action.as_str(),
        lease.scope,
        lease.policy_decision_id.as_str(),
        lease.policy_epoch,
        lease.issued_at,
        lease.expires_at,
        lease.revocation_state,
    ]);
    serde_json::to_vec(&payload)
}

fn decode_fixed<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(encoded.as_bytes())
        .map_err(|e| format!("failed to decode {label}: {e}"))?;
    if bytes.len() != N {
        return Err(format!("{label} must be {N} bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leases::{LeaseManager, LeaseScope};
    use crate::policy::{PolicyAction, PolicyEngine};

    fn issued_lease() -> AccessLease {
        let mgr = LeaseManager::new();
        let engine = PolicyEngine::new();
        engine
            .load_policies("permit(principal, action, resource);")
            .unwrap();
        let tenant = TenantId::generate();
        let principal = PrincipalId::new("user:test");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::PortForward);
        mgr.issue(
            tenant,
            principal,
            SandboxId::generate(),
            LeaseAction::PortForward,
            LeaseScope {
                ports: vec![8080],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            &decision,
            3600,
        )
    }

    #[test]
    fn signed_blob_roundtrip_enforces() {
        let authority = LeaseAuthority::generate();
        let mut lease = issued_lease();
        authority.sign(&mut lease).unwrap();
        let blob = encode_lease_blob(&lease).unwrap();

        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope {
                ports: vec![8080],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            policy_epoch: lease.policy_epoch,
        };
        assert!(authority.enforce_blob(&blob, &ctx).is_ok());
    }

    #[test]
    fn forged_blob_is_rejected() {
        let issuer = LeaseAuthority::generate();
        let other = LeaseAuthority::generate();
        let mut lease = issued_lease();
        issuer.sign(&mut lease).unwrap();
        let blob = encode_lease_blob(&lease).unwrap();

        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope::unbounded(),
            policy_epoch: lease.policy_epoch,
        };
        assert!(matches!(
            other.enforce_blob(&blob, &ctx),
            Err(LeaseValidationError::InvalidSignature)
        ));
    }

    #[test]
    fn unsigned_lease_is_rejected() {
        let authority = LeaseAuthority::generate();
        let lease = issued_lease();
        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope::unbounded(),
            policy_epoch: lease.policy_epoch,
        };
        assert!(matches!(
            authority.enforce(&lease, &ctx),
            Err(LeaseValidationError::InvalidSignature)
        ));
    }

    #[test]
    fn scope_mismatch_is_rejected() {
        let authority = LeaseAuthority::generate();
        let mut lease = issued_lease();
        authority.sign(&mut lease).unwrap();
        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope {
                ports: vec![9999],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec![],
            },
            policy_epoch: lease.policy_epoch,
        };
        assert!(matches!(
            authority.enforce(&lease, &ctx),
            Err(LeaseValidationError::ScopeExceeded { .. })
        ));
    }

    #[test]
    fn revoked_blob_is_rejected_when_checker_says_so() {
        let authority = LeaseAuthority::generate();
        let mut lease = issued_lease();
        authority.sign(&mut lease).unwrap();
        let blob = encode_lease_blob(&lease).unwrap();
        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope::unbounded(),
            policy_epoch: lease.policy_epoch,
        };
        let revoked_id = lease.lease_id.clone();
        assert!(matches!(
            authority.enforce_blob_revocable(&blob, &ctx, |id| id == &revoked_id),
            Err(LeaseValidationError::Revoked { .. })
        ));
        assert!(
            authority
                .enforce_blob_revocable(&blob, &ctx, |_| false)
                .is_ok()
        );
    }

    #[test]
    fn verifying_key_roundtrip() {
        let issuer = LeaseAuthority::generate();
        let encoded = issuer.verifying_key_base64();
        let verifier = LeaseAuthority::from_verifying_key_base64(&encoded).unwrap();
        let mut lease = issued_lease();
        issuer.sign(&mut lease).unwrap();
        let ctx = EnforceContext {
            sandbox_id: &lease.sandbox_id,
            tenant_id: &lease.tenant_id,
            action: LeaseAction::PortForward,
            scope: &LeaseScope::unbounded(),
            policy_epoch: lease.policy_epoch,
        };
        assert!(verifier.enforce(&lease, &ctx).is_ok());
    }
}
