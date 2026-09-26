//! Concrete HTTP secrets broker client.

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Url};

use crate::identity::LeaseId;
use crate::secrets::broker::SecretsBroker;
use crate::secrets::error::SecretsBrokerError;
use crate::secrets::types::{CredentialBundle, CredentialRequest, CredentialValue};

/// Maximum bytes to include from broker error response bodies.
///
/// Prevents unbounded error bodies from inflating error messages or logs.
const MAX_ERROR_BODY_BYTES: usize = 512;

/// Configuration for the HTTP secrets broker.
#[derive(Debug, Clone)]
pub struct HttpBrokerConfig {
    /// Base URL of the secrets broker.
    pub endpoint: Url,
    /// Static bearer token for broker authentication.
    pub auth_token: Option<String>,
    /// Request timeout.
    pub timeout: std::time::Duration,
}

impl HttpBrokerConfig {
    /// Create a config from an endpoint string.
    pub fn from_endpoint(endpoint: impl AsRef<str>) -> Result<Self, SecretsBrokerError> {
        let endpoint = Url::parse(endpoint.as_ref()).map_err(|e| {
            SecretsBrokerError::InvalidResponse(format!("invalid broker endpoint: {e}"))
        })?;
        Ok(Self {
            endpoint,
            auth_token: None,
            timeout: std::time::Duration::from_secs(10),
        })
    }
}

/// HTTP/JSON secrets broker client.
#[derive(Debug, Clone)]
pub struct HttpSecretsBroker {
    client: Client,
    config: HttpBrokerConfig,
}

impl HttpSecretsBroker {
    /// Create a new HTTP broker client.
    pub fn new(config: HttpBrokerConfig) -> Result<Self, SecretsBrokerError> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SecretsBrokerError::Unavailable(e.to_string()))?;
        Ok(Self { client, config })
    }
}

/// Broker response payload. Secret values are kept in `Vec<u8>`.
#[derive(Debug, serde::Deserialize)]
struct BrokerCredentialResponse {
    name: String,
    value: String,
}

#[derive(Debug, serde::Deserialize)]
struct BrokerResponse {
    lease_id: Option<String>,
    expires_at: Option<String>,
    credentials: Vec<BrokerCredentialResponse>,
}

#[async_trait]
impl SecretsBroker for HttpSecretsBroker {
    async fn fetch_credentials(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialBundle, SecretsBrokerError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(token) = &self.config.auth_token {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|e| SecretsBrokerError::RequestFailed(format!("bad auth token: {e}")))?;
            headers.insert(AUTHORIZATION, value);
        }

        let body = serde_json::to_vec(request)
            .map_err(|e| SecretsBrokerError::RequestFailed(e.to_string()))?;

        let response = self
            .client
            .post(self.config.endpoint.clone())
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| SecretsBrokerError::Unavailable(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(SecretsBrokerError::Denied(format!(
                "broker denied: {status}"
            )));
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let truncated = if text.len() > MAX_ERROR_BODY_BYTES {
                format!(
                    "{}... (truncated from {} bytes)",
                    &text[..MAX_ERROR_BODY_BYTES],
                    text.len()
                )
            } else {
                text
            };
            return Err(SecretsBrokerError::RequestFailed(format!(
                "broker returned {status}: {truncated}"
            )));
        }

        let parsed: BrokerResponse = response
            .json()
            .await
            .map_err(|e| SecretsBrokerError::InvalidResponse(e.to_string()))?;

        let credentials = parsed
            .credentials
            .into_iter()
            .map(|c| CredentialValue {
                name: c.name,
                value: c.value.into_bytes(),
            })
            .collect();

        Ok(CredentialBundle {
            lease_id: parsed
                .lease_id
                .map(LeaseId::from_string)
                .or(request.lease_id.clone()),
            expires_at: parsed.expires_at,
            credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{LeaseId, PolicyDecisionId, SandboxId, TenantId};
    use tokio::io::AsyncReadExt;

    async fn spawn_broker_server(response_body: String) -> (tokio::task::JoinHandle<()>, Url) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            use tokio::io::AsyncWriteExt;
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let url = Url::parse(&format!("http://{addr}/secrets")).unwrap();
        (handle, url)
    }

    #[tokio::test]
    async fn http_broker_fetches_credentials() {
        let body = r#"{"credentials":[{"name":"API_KEY","value":"secret123"}]}"#.to_string();
        let (handle, url) = spawn_broker_server(body).await;

        let config = HttpBrokerConfig {
            endpoint: url,
            auth_token: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let broker = HttpSecretsBroker::new(config).unwrap();

        let request = CredentialRequest {
            tenant_id: TenantId::generate(),
            sandbox_id: SandboxId::generate(),
            operation_id: "op_001".into(),
            policy_decision_id: Some(PolicyDecisionId::generate()),
            lease_id: Some(LeaseId::generate()),
            credential_types: vec!["api".into()],
        };

        let bundle = broker.fetch_credentials(&request).await.unwrap();
        assert_eq!(bundle.credentials.len(), 1);
        assert_eq!(bundle.credentials[0].name, "API_KEY");
        assert_eq!(bundle.credentials[0].value, b"secret123");

        handle.await.unwrap();
    }
}
