//! In-memory secrets broker for tests.

use hashbrown::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use crate::secrets::broker::SecretsBroker;
use crate::secrets::error::SecretsBrokerError;
use crate::secrets::types::{CredentialBundle, CredentialRequest, CredentialValue};

/// A credential fixture held by the mock broker.
#[derive(Debug, Clone)]
pub struct MockCredential {
    pub credential_type: String,
    pub name: String,
    pub value: Vec<u8>,
}

/// In-memory secrets broker with programmable responses.
#[derive(Clone, Default)]
pub struct MockSecretsBroker {
    store: Arc<RwLock<HashMap<String, Vec<MockCredential>>>>,
    deny_tenants: Arc<RwLock<Vec<String>>>,
}

impl MockSecretsBroker {
    /// Create an empty mock broker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed credentials for a tenant.
    pub fn seed(&self, tenant_id: impl Into<String>, credentials: Vec<MockCredential>) {
        self.store
            .write()
            .unwrap()
            .insert(tenant_id.into(), credentials);
    }

    /// Deny all credential requests for a tenant.
    pub fn deny_tenant(&self, tenant_id: impl Into<String>) {
        self.deny_tenants.write().unwrap().push(tenant_id.into());
    }
}

#[async_trait]
impl SecretsBroker for MockSecretsBroker {
    async fn fetch_credentials(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialBundle, SecretsBrokerError> {
        let tenant = request.tenant_id.as_str();

        if self
            .deny_tenants
            .read()
            .unwrap()
            .contains(&tenant.to_string())
        {
            return Err(SecretsBrokerError::Denied("tenant denied".into()));
        }

        let store = self.store.read().unwrap();
        let available = store.get(tenant).cloned().unwrap_or_default();

        let credentials: Vec<CredentialValue> = request
            .credential_types
            .iter()
            .flat_map(|requested_type| {
                available
                    .iter()
                    .filter(move |c| &c.credential_type == requested_type)
                    .map(move |c| CredentialValue {
                        name: c.name.clone(),
                        value: c.value.clone(),
                    })
            })
            .collect();

        if credentials.is_empty() && !request.credential_types.is_empty() {
            return Err(SecretsBrokerError::UnknownCredentialType(
                request.credential_types.join(","),
            ));
        }

        Ok(CredentialBundle {
            lease_id: request.lease_id.clone(),
            expires_at: None,
            credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_matching_credentials() {
        let broker = MockSecretsBroker::new();
        broker.seed(
            "tnt_001",
            vec![MockCredential {
                credential_type: "aws".into(),
                name: "AWS_ACCESS_KEY_ID".into(),
                value: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            }],
        );

        let request = CredentialRequest {
            tenant_id: crate::identity::TenantId::from_string("tnt_001"),
            sandbox_id: crate::identity::SandboxId::generate(),
            operation_id: "op_001".into(),
            policy_decision_id: None,
            lease_id: None,
            credential_types: vec!["aws".into()],
        };

        let bundle = broker.fetch_credentials(&request).await.unwrap();
        assert_eq!(bundle.credentials.len(), 1);
        assert_eq!(bundle.credentials[0].name, "AWS_ACCESS_KEY_ID");
    }

    #[tokio::test]
    async fn denied_tenant_returns_error() {
        let broker = MockSecretsBroker::new();
        broker.deny_tenant("tnt_002");

        let request = CredentialRequest {
            tenant_id: crate::identity::TenantId::from_string("tnt_002"),
            sandbox_id: crate::identity::SandboxId::generate(),
            operation_id: "op_001".into(),
            policy_decision_id: None,
            lease_id: None,
            credential_types: vec!["aws".into()],
        };

        let result = broker.fetch_credentials(&request).await;
        assert!(matches!(result, Err(SecretsBrokerError::Denied(_))));
    }
}
