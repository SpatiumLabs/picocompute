//! Secrets inject + DNS attach ownership tests for sandboxd.

use std::sync::Arc;
use std::time::Duration;

use pico_core::event_bus::InMemoryAuditSink;
use pico_core::{
    AuditEventDetails, FencingToken, Hlc, OperationId, RuntimeBackend, SandboxConfig, SandboxId,
};
use pico_network_agent::dns_attachment::DnsAttachmentConfig;
use pico_network_agent::receipt::{ResourceKind, ResourceReceipt as NetworkResourceReceipt};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::dns::DnsAttachProvisioner;
use pico_sandboxd::{
    CommandContext, DnsAttachConfig, DnsAttachManager, HostResourceSpec, OutcomeStatus,
    SandboxSupervisor, SecretsCoordinator,
};
use tonic::async_trait;

mod common;
use common::mock_guest;

/// Fake DNS provisioner: records attach receipts without touching nftables.
#[derive(Debug, Default)]
struct FakeDnsProvisioner;

#[async_trait]
impl DnsAttachProvisioner for FakeDnsProvisioner {
    async fn provision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        Ok(vec![NetworkResourceReceipt {
            sandbox_id: config.sandbox_id.clone(),
            resource_name: format!("dns-attachment-{}", config.proxy_addr),
            kind: ResourceKind::DnsAttachment,
            created: true,
            provision_latency: Duration::ZERO,
        }])
    }

    async fn deprovision(
        &self,
        config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        Ok(vec![NetworkResourceReceipt {
            sandbox_id: config.sandbox_id.clone(),
            resource_name: format!("dns-attachment-{}", config.proxy_addr),
            kind: ResourceKind::DnsAttachment,
            created: false,
            provision_latency: Duration::ZERO,
        }])
    }
}

/// Provisioner that always fails attach (e.g. nftables missing on the host).
#[derive(Debug, Default)]
struct FailingDnsProvisioner;

#[async_trait]
impl DnsAttachProvisioner for FailingDnsProvisioner {
    async fn provision(
        &self,
        _config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        Err("nftables unavailable".into())
    }

    async fn deprovision(
        &self,
        _config: &DnsAttachmentConfig,
    ) -> Result<Vec<NetworkResourceReceipt>, String> {
        Ok(Vec::new())
    }
}

fn sandbox_id(name: &str) -> SandboxId {
    SandboxId::from_string(format!("sbx_{name}"))
}

fn config(id: &SandboxId) -> SandboxConfig {
    SandboxConfig {
        id: id.as_str().into(),
        network_isolated: true,
        ..Default::default()
    }
}

fn command(id: &SandboxId, timeout: Duration) -> CommandContext {
    CommandContext::with_timeout(
        id.clone(),
        OperationId::generate(),
        FencingToken::default(),
        1,
        timeout,
    )
}

fn mock_backend() -> Arc<dyn RuntimeBackend> {
    Arc::new(MockBackend::default())
}

fn host_spec() -> HostResourceSpec {
    HostResourceSpec {
        vcpus: 1,
        memory_mb: 256,
        tenant_id: Some("tnt_test".into()),
        ..HostResourceSpec::default()
    }
}

async fn present_receipt_classes(supervisor: &SandboxSupervisor, id: &SandboxId) -> Vec<String> {
    supervisor
        .resource_receipts(id)
        .await
        .unwrap()
        .into_iter()
        .filter(|receipt| receipt.cleanup_state == "present")
        .map(|receipt| receipt.class)
        .collect()
}

#[tokio::test]
async fn dns_attach_disabled_boot_has_no_dns_receipt() {
    let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
    let id = sandbox_id("dns_disabled");
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);

    let boot = supervisor
        .boot(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !classes.iter().any(|c| c == "dns_attachment"),
        "disabled DNS must not record receipts: {classes:?}"
    );
}

#[tokio::test]
async fn dns_attach_enabled_records_ledger_receipt_on_boot() {
    let port = 19000 + (std::process::id() % 1000) as u16;
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_dns(Arc::new(
            DnsAttachManager::new(DnsAttachConfig {
                listen_addr: Some(listen),
            })
            .with_provisioner(Arc::new(FakeDnsProvisioner)),
        ));

    let id = sandbox_id("dns_enabled");
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);

    let boot = supervisor
        .boot(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        classes.iter().any(|c| c == "dns_attachment"),
        "expected dns_attachment receipt after boot, got {classes:?}"
    );

    let destroy = supervisor
        .destroy(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded);

    let after = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !after.iter().any(|c| c == "dns_attachment"),
        "dns_attachment should be released after destroy: {after:?}"
    );
}

#[tokio::test]
async fn inject_secrets_requires_guest_session() {
    let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
    let id = sandbox_id("secrets_no_session");
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);

    let err = supervisor
        .inject_secrets(
            &id,
            OperationId::generate().as_str(),
            1,
            &pico_sandboxd_proto::v1::CredentialInjectSpec {
                tenant_id: "tnt_test".into(),
                lease_id: "lease_test".into(),
                policy_decision_id: String::new(),
                credentials: vec![pico_sandboxd_proto::v1::NamedCredential {
                    name: "api_key".into(),
                    kind: "api_key".into(),
                    attributes: Default::default(),
                    material: Some(b"secret-value".to_vec()),
                }],
            },
        )
        .await
        .expect_err("inject without guest session must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("guest session") || msg.contains("no guest session"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn dns_attach_failure_fails_boot_closed_without_receipts() {
    let port = 20000 + (std::process::id() % 1000) as u16;
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_dns(Arc::new(
            DnsAttachManager::new(DnsAttachConfig {
                listen_addr: Some(listen),
            })
            .with_provisioner(Arc::new(FailingDnsProvisioner)),
        ));

    let id = sandbox_id("dns_fail");
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);

    let boot = supervisor
        .boot(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        boot.status,
        OutcomeStatus::Failed,
        "boot must fail closed when DNS attach fails: {boot:?}"
    );
    let msg = boot.message.unwrap_or_default();
    assert!(
        msg.contains("DNS attachment failed"),
        "unexpected boot message: {msg}"
    );

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !classes.iter().any(|c| c == "dns_attachment"),
        "failed attach must not record receipts: {classes:?}"
    );
}

#[tokio::test]
async fn dns_attach_failure_with_partial_cleanup_requires_review() {
    let port = 21000 + (std::process::id() % 1000) as u16;
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_dns(Arc::new(
            DnsAttachManager::new(DnsAttachConfig {
                listen_addr: Some(listen),
            })
            .with_provisioner(Arc::new(FailingDnsProvisioner)),
        ));

    let id = sandbox_id("dns_fail_partial");
    let backend: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::PartialCleanup {
            remaining: vec!["mock-tap".into()],
        }),
        ..MockBackendConfig::default()
    }));
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            backend,
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);

    let boot = supervisor
        .boot(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        boot.status,
        OutcomeStatus::RequiresReview,
        "partial cleanup after DNS attach failure must surface for review: {boot:?}"
    );
}

#[tokio::test]
async fn inject_secrets_guest_failure_reports_detail_and_audits_event() {
    let id = sandbox_id("secrets_guest_fail");
    // Keep the socket path short: overlong Unix socket paths exceed SUN_LEN
    // and fail bind.
    let socket_dir = tempfile::TempDir::new().unwrap();
    let socket_path = socket_dir.path().join("guest.sock");
    mock_guest::spawn_mock_guest_session_unix_with_inject(
        id.as_str(),
        &socket_path,
        mock_guest::InjectBehavior::Failure {
            code: "tmpfs_write_failed".into(),
            message: "no space on secrets tmpfs".into(),
        },
    )
    .await;

    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(true)
        .with_secrets(Arc::new(SecretsCoordinator::new(
            None,
            None,
            Arc::<InMemoryAuditSink>::clone(&audit_sink),
            Arc::new(Hlc::new()),
        )));

    let backend: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::new(MockBackendConfig {
        guest_transport_path: socket_path.display().to_string(),
        ..MockBackendConfig::default()
    }));
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            backend,
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Succeeded);
    let boot = supervisor
        .boot(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(boot.status, OutcomeStatus::Succeeded);

    let err = supervisor
        .inject_secrets(
            &id,
            OperationId::generate().as_str(),
            1,
            &pico_sandboxd_proto::v1::CredentialInjectSpec {
                tenant_id: "tnt_test".into(),
                lease_id: "lease_test".into(),
                policy_decision_id: String::new(),
                credentials: vec![pico_sandboxd_proto::v1::NamedCredential {
                    name: "api_key".into(),
                    kind: "api_key".into(),
                    attributes: Default::default(),
                    material: Some(b"secret-value".to_vec()),
                }],
            },
        )
        .await
        .expect_err("guest-reported failure must surface");
    let msg = err.to_string();
    assert!(
        msg.contains("tmpfs_write_failed"),
        "guest failure detail must be preserved, got: {msg}"
    );

    let events = audit_sink.events();
    assert!(
        events.iter().any(|event| matches!(
            &event.details,
            Some(AuditEventDetails::CredentialIssuance {
                outcome,
                reason: Some(reason),
                ..
            }) if outcome == "failed" && reason.contains("tmpfs_write_failed")
        )),
        "expected a failed credential issuance audit event, got {events:?}"
    );
}
