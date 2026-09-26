//! Secrets coordination owned by sandboxd.
//!
//! Host-agent admits the lease and passes a credential inject request (with
//! optional inline material for tests). sandboxd optionally fetches the broker,
//! injects through the framed guest session, and emits audit events.

use std::sync::Arc;

use pico_core::event_bus::{AuditEventBuilder, AuditEventSink};
use pico_core::leases::{LeaseAction, LeaseManager, LeaseScope, LeaseValidationError};
use pico_core::secrets::{
    CredentialBundle, CredentialRequest, CredentialValue, SecretsBroker, SecretsBrokerError,
};
use pico_core::{
    AuditEventDetails, AuditEventKind, AuditOutcome, AuditProducer, Hlc, LeaseId, PolicyDecisionId,
    SandboxId, TenantId,
};
use pico_guest_protocol::operational_v1::SecretCredential;
use pico_sandboxd_proto::v1::{CredentialInjectSpec, NamedCredential};

use crate::guest::GuestConnection;

/// Errors from secrets coordination inside sandboxd.
#[derive(Debug, thiserror::Error)]
pub enum SecretsCoordinationError {
    /// Lease validation failed.
    #[error("lease validation failed: {0}")]
    LeaseValidation(LeaseValidationError),
    /// Secrets broker returned an error.
    #[error("broker error: {0}")]
    Broker(#[from] SecretsBrokerError),
    /// Guest injection RPC failed.
    #[error("guest injection failed: {0}")]
    GuestInjection(String),
    /// Request was incomplete or inconsistent.
    #[error("invalid inject request: {0}")]
    InvalidRequest(String),
}

impl From<LeaseValidationError> for SecretsCoordinationError {
    fn from(err: LeaseValidationError) -> Self {
        Self::LeaseValidation(err)
    }
}

/// Coordinates credential fetch + guest injection inside sandboxd.
pub struct SecretsCoordinator {
    broker: Option<Arc<dyn SecretsBroker>>,
    lease_manager: Option<Arc<LeaseManager>>,
    audit_sink: Arc<dyn AuditEventSink>,
    hlc: Arc<Hlc>,
}

impl SecretsCoordinator {
    /// Creates a coordinator. Broker and lease manager are optional so tests
    /// can inject inline material without a broker.
    pub fn new(
        broker: Option<Arc<dyn SecretsBroker>>,
        lease_manager: Option<Arc<LeaseManager>>,
        audit_sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
    ) -> Self {
        Self {
            broker,
            lease_manager,
            audit_sink,
            hlc,
        }
    }

    /// Validates lease (when configured), resolves credentials, and injects.
    pub async fn inject(
        &self,
        sandbox_id: &SandboxId,
        operation_id: &str,
        policy_epoch: u64,
        spec: &CredentialInjectSpec,
        guest_conn: &mut GuestConnection,
    ) -> Result<CredentialBundle, SecretsCoordinationError> {
        if spec.tenant_id.is_empty() {
            return Err(SecretsCoordinationError::InvalidRequest(
                "tenant_id is required".into(),
            ));
        }
        if spec.lease_id.is_empty() {
            return Err(SecretsCoordinationError::InvalidRequest(
                "lease_id is required".into(),
            ));
        }

        let tenant_id = TenantId::from_string(spec.tenant_id.as_str());
        let lease_id = LeaseId::from_string(spec.lease_id.as_str());
        let policy_decision_id = if spec.policy_decision_id.is_empty() {
            None
        } else {
            Some(PolicyDecisionId::from_string(
                spec.policy_decision_id.as_str(),
            ))
        };

        let credential_types = credential_types_from_spec(&spec.credentials);
        let has_inline = spec
            .credentials
            .iter()
            .any(|c| c.material.as_ref().is_some_and(|m| !m.is_empty()));

        if let Some(lease_manager) = &self.lease_manager {
            let requested_scope = LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: credential_types.clone(),
            };
            lease_manager
                .validate_with_scope(
                    &lease_id,
                    sandbox_id,
                    &tenant_id,
                    LeaseAction::CredentialAccess,
                    &requested_scope,
                    policy_epoch,
                )
                .map_err(|e| {
                    self.emit_credential_issuance(
                        &tenant_id,
                        sandbox_id,
                        Some(lease_id.as_str()),
                        policy_decision_id.as_ref().map(|id| id.as_str()),
                        AuditOutcome::Denied,
                        Some(e.to_string()),
                        &credential_types,
                    );
                    SecretsCoordinationError::LeaseValidation(e)
                })?;
        }

        let bundle = if has_inline {
            bundle_from_inline(spec)?
        } else {
            let broker = self.broker.as_ref().ok_or_else(|| {
                SecretsCoordinationError::InvalidRequest(
                    "no inline credential material and no secrets broker configured".into(),
                )
            })?;
            let request = CredentialRequest {
                tenant_id: tenant_id.clone(),
                sandbox_id: sandbox_id.clone(),
                operation_id: operation_id.into(),
                policy_decision_id: policy_decision_id.clone(),
                lease_id: Some(lease_id.clone()),
                credential_types: credential_types.clone(),
            };
            broker.fetch_credentials(&request).await.inspect_err(|e| {
                self.emit_credential_issuance(
                    &tenant_id,
                    sandbox_id,
                    Some(lease_id.as_str()),
                    policy_decision_id.as_ref().map(|id| id.as_str()),
                    AuditOutcome::Denied,
                    Some(e.to_string()),
                    &credential_types,
                );
            })?
        };

        let credentials: Vec<SecretCredential> = bundle
            .credentials
            .iter()
            .map(|c| SecretCredential {
                name: c.name.clone(),
                content: c.value.clone(),
                mode: 0o400,
            })
            .collect();

        guest_conn
            .inject_secrets(
                lease_id.as_str(),
                policy_decision_id
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or(""),
                &credentials,
                operation_id,
            )
            .await
            .inspect_err(|e| {
                // The lease admitted this request, so a failed guest write is
                // audited as Failed rather than Denied.
                self.emit_credential_issuance(
                    &tenant_id,
                    sandbox_id,
                    Some(lease_id.as_str()),
                    policy_decision_id.as_ref().map(|id| id.as_str()),
                    AuditOutcome::Failed,
                    Some(e.to_string()),
                    &credential_types,
                );
            })
            .map_err(|e| SecretsCoordinationError::GuestInjection(e.to_string()))?;

        self.emit_credential_issuance(
            &tenant_id,
            sandbox_id,
            Some(lease_id.as_str()),
            policy_decision_id.as_ref().map(|id| id.as_str()),
            AuditOutcome::Success,
            None,
            &credential_types,
        );

        Ok(bundle)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "all fields are independently required by the audit event schema"
    )]
    fn emit_credential_issuance(
        &self,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        lease_id: Option<&str>,
        policy_decision_id: Option<&str>,
        outcome: AuditOutcome,
        reason: Option<String>,
        credential_types: &[String],
    ) {
        let kind = match outcome {
            AuditOutcome::Revoked => AuditEventKind::CredentialRevoked,
            AuditOutcome::Deny | AuditOutcome::Denied => AuditEventKind::CredentialDenied,
            _ => AuditEventKind::CredentialIssuance,
        };
        let _ = self.audit_sink.emit(
            AuditEventBuilder::new(Arc::clone(&self.hlc), kind)
                .sandbox_id(sandbox_id.clone())
                .tenant_id(tenant_id.clone())
                .lease_id(lease_id.unwrap_or(""))
                .policy_decision_id(policy_decision_id.unwrap_or(""))
                .outcome(outcome)
                .producer(AuditProducer::Sandboxd)
                .details(AuditEventDetails::CredentialIssuance {
                    action: "credential_access".into(),
                    outcome: outcome.to_string(),
                    reason,
                    credential_type: credential_types.join(","),
                    lease_id: lease_id.map(str::to_string),
                })
                .build(),
        );
    }
}

fn credential_types_from_spec(credentials: &[NamedCredential]) -> Vec<String> {
    let mut types: Vec<String> = credentials
        .iter()
        .map(|c| {
            if c.kind.is_empty() {
                c.name.clone()
            } else {
                c.kind.clone()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();
    types.sort();
    types.dedup();
    types
}

fn bundle_from_inline(
    spec: &CredentialInjectSpec,
) -> Result<CredentialBundle, SecretsCoordinationError> {
    let mut credentials = Vec::with_capacity(spec.credentials.len());
    for cred in &spec.credentials {
        let material = cred.material.as_ref().ok_or_else(|| {
            SecretsCoordinationError::InvalidRequest(format!(
                "credential {} missing material for inline inject",
                cred.name
            ))
        })?;
        if material.is_empty() {
            return Err(SecretsCoordinationError::InvalidRequest(format!(
                "credential {} has empty material",
                cred.name
            )));
        }
        let name = if cred.name.is_empty() {
            cred.kind.clone()
        } else {
            cred.name.clone()
        };
        if name.is_empty() {
            return Err(SecretsCoordinationError::InvalidRequest(
                "credential name or kind is required".into(),
            ));
        }
        credentials.push(CredentialValue {
            name,
            value: material.clone(),
        });
    }
    Ok(CredentialBundle {
        credentials,
        lease_id: Some(LeaseId::from_string(spec.lease_id.as_str())),
        expires_at: None,
    })
}
