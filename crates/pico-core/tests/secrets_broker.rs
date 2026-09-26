//! Integration tests for the secrets broker abstraction.
//!
//! Validates:
//! - Mock broker fetch, deny, and unknown-type behaviour
//! - HTTP broker against a local test server
//! - Snapshot exclusion for secret-class mounts
//! - Audit event redaction for CredentialIssuance payloads

use pico_core::event_bus::redact_event;
use pico_core::secrets::{
    CredentialRequest, SecretsBroker, SecretsBrokerError,
    mock::{MockCredential, MockSecretsBroker},
};
use pico_core::{
    AuditEventDetails, AuditEventKind, AuditOutcome, Hlc, SandboxId, TenantId,
    event_bus::AuditEventBuilder,
    mount::{MountClass, MountContract, MountEntry, PathLifecycle},
};
use std::sync::Arc;

// ──── Mock broker: successful fetch with matching credential types ────

#[tokio::test]
async fn fetch_matching_credentials_via_mock() {
    let broker = MockSecretsBroker::new();
    broker.seed(
        "tnt_alpha",
        vec![
            MockCredential {
                credential_type: "aws".into(),
                name: "AWS_ACCESS_KEY_ID".into(),
                value: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            },
            MockCredential {
                credential_type: "gcp".into(),
                name: "GCP_SA_KEY".into(),
                value: b"gcp-sa-json-blob".to_vec(),
            },
        ],
    );

    let request = CredentialRequest {
        tenant_id: TenantId::from_string("tnt_alpha"),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_fetch".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec!["aws".into(), "gcp".into()],
    };

    let bundle = broker.fetch_credentials(&request).await.unwrap();
    assert_eq!(bundle.credentials.len(), 2);
    let names: Vec<&str> = bundle.credentials.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"AWS_ACCESS_KEY_ID"));
    assert!(names.contains(&"GCP_SA_KEY"));
}

#[tokio::test]
async fn fetch_subset_of_available_credential_types() {
    let broker = MockSecretsBroker::new();
    broker.seed(
        "tnt_alpha",
        vec![
            MockCredential {
                credential_type: "aws".into(),
                name: "AWS_ACCESS_KEY_ID".into(),
                value: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            },
            MockCredential {
                credential_type: "gcp".into(),
                name: "GCP_SA_KEY".into(),
                value: b"gcp-sa-json-blob".to_vec(),
            },
        ],
    );

    let request = CredentialRequest {
        tenant_id: TenantId::from_string("tnt_alpha"),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_subset".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec!["aws".into()],
    };

    let bundle = broker.fetch_credentials(&request).await.unwrap();
    assert_eq!(bundle.credentials.len(), 1);
    assert_eq!(bundle.credentials[0].name, "AWS_ACCESS_KEY_ID");
}

// ──── Mock broker: denied tenant ────

#[tokio::test]
async fn denied_tenant_returns_denied_error() {
    let broker = MockSecretsBroker::new();
    broker.deny_tenant("tnt_blocked");

    let request = CredentialRequest {
        tenant_id: TenantId::from_string("tnt_blocked"),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_denied".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec!["aws".into()],
    };

    let result = broker.fetch_credentials(&request).await;
    assert!(matches!(result, Err(SecretsBrokerError::Denied(_))));
}

// ──── Mock broker: unknown credential type ────

#[tokio::test]
async fn unknown_credential_type_returns_error() {
    let broker = MockSecretsBroker::new();

    let request = CredentialRequest {
        tenant_id: TenantId::generate(),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_unknown".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec!["nonexistent".into()],
    };

    let result = broker.fetch_credentials(&request).await;
    assert!(
        matches!(result, Err(SecretsBrokerError::UnknownCredentialType(_))),
        "expected UnknownCredentialType, got {result:?}"
    );
}

// ──── Mock broker: empty credential_types returns empty bundle ────

#[tokio::test]
async fn empty_credential_types_returns_empty_bundle() {
    let broker = MockSecretsBroker::new();
    broker.seed(
        "tnt_alpha",
        vec![MockCredential {
            credential_type: "aws".into(),
            name: "AWS_KEY".into(),
            value: b"test".to_vec(),
        }],
    );

    let request = CredentialRequest {
        tenant_id: TenantId::from_string("tnt_alpha"),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_empty".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec![],
    };

    let bundle = broker.fetch_credentials(&request).await.unwrap();
    assert!(bundle.credentials.is_empty());
}

// ──── HTTP broker with local test server ────

#[tokio::test]
async fn http_broker_fetches_credentials_from_local_server() {
    use pico_core::secrets::http::{HttpBrokerConfig, HttpSecretsBroker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await.unwrap();
        let body = r#"{"credentials":[{"name":"API_KEY","value":"secret-abc-123"},{"name":"DB_PASS","value":"db-secret-456"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let url = reqwest::Url::parse(&format!("http://{addr}/secrets")).unwrap();
    let config = HttpBrokerConfig {
        endpoint: url,
        auth_token: None,
        timeout: std::time::Duration::from_secs(5),
    };
    let broker = HttpSecretsBroker::new(config).unwrap();

    let request = CredentialRequest {
        tenant_id: TenantId::generate(),
        sandbox_id: SandboxId::generate(),
        operation_id: "op_http".into(),
        policy_decision_id: None,
        lease_id: None,
        credential_types: vec!["api".into()],
    };

    let bundle = broker.fetch_credentials(&request).await.unwrap();
    assert_eq!(bundle.credentials.len(), 2);
    assert_eq!(bundle.credentials[0].name, "API_KEY");
    assert_eq!(bundle.credentials[0].value, b"secret-abc-123");
    assert_eq!(bundle.credentials[1].name, "DB_PASS");
    assert_eq!(bundle.credentials[1].value, b"db-secret-456");

    server.await.unwrap();
}

// ──── Snapshot exclusion: secret class ────

#[test]
fn mount_contract_with_secret_class_excludes_it_from_snapshot() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![
            MountEntry {
                path: "/workspace".into(),
                class: MountClass::Workspace,
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            },
            MountEntry {
                path: "/run/pico/secrets".into(),
                class: MountClass::Secret,
                writable: false,
                lifecycle: PathLifecycle::Ephemeral,
            },
            MountEntry {
                path: "/run/pico/tmp".into(),
                class: MountClass::RuntimeTmp,
                writable: true,
                lifecycle: PathLifecycle::Ephemeral,
            },
        ],
    };

    let excluded = contract.snapshot_excluded_classes();
    assert!(excluded.contains(&"secret".to_string()));
    assert!(excluded.contains(&"runtime_tmp".to_string()));
    assert!(!excluded.contains(&"workspace".to_string()));
}

#[test]
fn mount_contract_without_secret_class_does_not_exclude_it() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![MountEntry {
            path: "/workspace".into(),
            class: MountClass::Workspace,
            writable: true,
            lifecycle: PathLifecycle::Persistent,
        }],
    };

    let excluded = contract.snapshot_excluded_classes();
    assert!(!excluded.contains(&"secret".to_string()));
}

// ──── Log redaction: CredentialIssuance events ────

#[test]
fn redact_credential_issuance_preserves_safe_fields() {
    let hlc = Arc::new(Hlc::new());

    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::CredentialIssuance)
        .sandbox_id(SandboxId::from_string("sbx_redact"))
        .tenant_id(TenantId::from_string("tnt_redact"))
        .outcome(AuditOutcome::Success)
        .lease_id("lse_redact")
        .details(AuditEventDetails::CredentialIssuance {
            action: "issue".into(),
            outcome: "success".into(),
            reason: None,
            credential_type: "short_lived_token".into(),
            lease_id: Some("lse_redact".into()),
        })
        .build();

    redact_event(&mut event);

    let details = event.details.as_ref().unwrap();
    match details {
        AuditEventDetails::CredentialIssuance {
            action,
            outcome,
            reason,
            credential_type,
            lease_id,
        } => {
            assert_eq!(action, "issue");
            assert_eq!(outcome, "success");
            assert!(reason.is_none());
            assert_eq!(credential_type, "short_lived_token");
            assert_eq!(lease_id.as_deref(), Some("lse_redact"));
        }
        _ => panic!("expected CredentialIssuance details"),
    }
}

#[test]
fn redact_credential_issuance_strips_sensitive_reason() {
    let hlc = Arc::new(Hlc::new());

    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::CredentialIssuance)
        .details(AuditEventDetails::CredentialIssuance {
            action: "issue".into(),
            outcome: "denied".into(),
            reason: Some("api_key validation failed".into()),
            credential_type: "aws".into(),
            lease_id: None,
        })
        .build();

    redact_event(&mut event);

    let details = event.details.as_ref().unwrap();
    match details {
        AuditEventDetails::CredentialIssuance { reason, .. } => {
            assert_eq!(
                reason.as_deref(),
                Some("[redacted]"),
                "sensitive reason should be redacted"
            );
        }
        _ => panic!("expected CredentialIssuance details"),
    }
}

#[test]
fn redact_credential_issuance_preserves_safe_reason() {
    let hlc = Arc::new(Hlc::new());

    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::CredentialIssuance)
        .details(AuditEventDetails::CredentialIssuance {
            action: "issue".into(),
            outcome: "success".into(),
            reason: Some("credential refreshed on resume".into()),
            credential_type: "gcp".into(),
            lease_id: None,
        })
        .build();

    redact_event(&mut event);

    let details = event.details.as_ref().unwrap();
    match details {
        AuditEventDetails::CredentialIssuance { reason, .. } => {
            assert_eq!(
                reason.as_deref(),
                Some("credential refreshed on resume"),
                "safe reason should be preserved"
            );
        }
        _ => panic!("expected CredentialIssuance details"),
    }
}

#[test]
fn redact_credential_issuance_strips_url_in_reason() {
    let hlc = Arc::new(Hlc::new());

    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::CredentialIssuance)
        .details(AuditEventDetails::CredentialIssuance {
            action: "issue".into(),
            outcome: "failed".into(),
            reason: Some("broker error: https://secrets.internal/api/v1/fetch".into()),
            credential_type: "aws".into(),
            lease_id: None,
        })
        .build();

    redact_event(&mut event);

    let details = event.details.as_ref().unwrap();
    match details {
        AuditEventDetails::CredentialIssuance { reason, .. } => {
            assert_eq!(reason.as_deref(), Some("[redacted]"));
        }
        _ => panic!("expected CredentialIssuance details"),
    }
}
