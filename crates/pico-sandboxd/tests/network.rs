//! Network pipeline ownership tests for sandboxd.

use std::sync::Arc;
use std::time::Duration;

use pico_core::{
    BackendOperation, FencingToken, NonReadyReason, OperationId, RuntimeBackend, SandboxConfig,
    SandboxId,
};
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};
use pico_network_agent::receipt::{
    CleanupReceipt, ProvisionReceipt, ResourceKind, ResourceReceipt as NetworkResourceReceipt,
};
use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};
use pico_sandboxd::{
    CommandContext, HostResourceSpec, NetworkAttachManager, NetworkProvisioner, OutcomeStatus,
    SandboxSupervisor,
};
use tonic::async_trait;

struct FakeNetworkProvisioner;

#[async_trait]
impl NetworkProvisioner for FakeNetworkProvisioner {
    async fn provision(
        &self,
        identity: &SandboxNetworkIdentity,
    ) -> Result<ProvisionReceipt, String> {
        let mut receipt =
            ProvisionReceipt::new(identity.sandbox_id.clone(), identity.backend_class, 1);
        receipt.push(NetworkResourceReceipt {
            sandbox_id: identity.sandbox_id.clone(),
            resource_name: identity.if_name.clone(),
            kind: match identity.backend_class {
                BackendClass::MicroVm => ResourceKind::Tap,
                BackendClass::Container => ResourceKind::Veth,
            },
            created: true,
            provision_latency: Duration::ZERO,
        });
        receipt.finalize(Duration::ZERO);
        Ok(receipt)
    }

    async fn deprovision(
        &self,
        identity: &SandboxNetworkIdentity,
        _receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt {
        let mut cleanup = CleanupReceipt::new(identity.sandbox_id.clone());
        cleanup.push_removed(NetworkResourceReceipt {
            sandbox_id: identity.sandbox_id.clone(),
            resource_name: identity.if_name.clone(),
            kind: ResourceKind::Tap,
            created: false,
            provision_latency: Duration::ZERO,
        });
        cleanup.finalize(Duration::ZERO);
        cleanup
    }
}

struct EmptyCleanupProvisioner;

#[async_trait]
impl NetworkProvisioner for EmptyCleanupProvisioner {
    async fn provision(
        &self,
        identity: &SandboxNetworkIdentity,
    ) -> Result<ProvisionReceipt, String> {
        FakeNetworkProvisioner.provision(identity).await
    }

    async fn deprovision(
        &self,
        identity: &SandboxNetworkIdentity,
        _receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt {
        CleanupReceipt::new(identity.sandbox_id.clone())
    }
}

struct FailingNetworkProvisioner;

#[async_trait]
impl NetworkProvisioner for FailingNetworkProvisioner {
    async fn provision(
        &self,
        _identity: &SandboxNetworkIdentity,
    ) -> Result<ProvisionReceipt, String> {
        Err("netlink unavailable".into())
    }

    async fn deprovision(
        &self,
        identity: &SandboxNetworkIdentity,
        _receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt {
        CleanupReceipt::new(identity.sandbox_id.clone())
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
async fn network_disabled_prepare_has_no_tap_receipt() {
    let supervisor = SandboxSupervisor::in_memory().with_guest_session(false);
    let id = sandbox_id("net_disabled");
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

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !classes.iter().any(|c| c == "tap" || c == "veth"),
        "disabled network must not record TAP receipts: {classes:?}"
    );
}

#[tokio::test]
async fn network_enabled_records_tap_receipt_on_prepare() {
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_network(Arc::new(
            NetworkAttachManager::new().with_provisioner(Arc::new(FakeNetworkProvisioner)),
        ));
    let id = sandbox_id("net_enabled");
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

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        classes.iter().any(|c| c == "tap"),
        "expected tap receipt after prepare, got {classes:?}"
    );

    let destroy = supervisor
        .destroy(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded);

    let after = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !after.iter().any(|c| c == "tap"),
        "tap should be released after destroy: {after:?}"
    );
}

#[tokio::test]
async fn network_provision_failure_fails_prepare_closed() {
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_network(Arc::new(
            NetworkAttachManager::new().with_provisioner(Arc::new(FailingNetworkProvisioner)),
        ));
    let id = sandbox_id("net_fail");
    let prep = supervisor
        .prepare(
            command(&id, Duration::from_secs(5)),
            mock_backend(),
            &config(&id),
            &host_spec(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status, OutcomeStatus::Failed);
    assert!(
        prep.message
            .as_deref()
            .is_some_and(|m| m.contains("network provision failed")),
        "unexpected message: {:?}",
        prep.message
    );

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !classes.iter().any(|c| c == "tap"),
        "failed provision must not leave present tap receipts: {classes:?}"
    );
}

#[tokio::test]
async fn failed_backend_prepare_releases_network_receipts() {
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_network(Arc::new(
            NetworkAttachManager::new().with_provisioner(Arc::new(FakeNetworkProvisioner)),
        ));
    let id = sandbox_id("net_backend_fail");
    let backend: Arc<dyn RuntimeBackend> = Arc::new(MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::NotReady {
            operation: BackendOperation::Prepare,
            reason: NonReadyReason::Backend,
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
    assert_eq!(prep.status, OutcomeStatus::Failed);

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        !classes.iter().any(|c| c == "tap"),
        "rolled-back prepare must release tap receipts: {classes:?}"
    );
}

#[tokio::test]
async fn empty_cleanup_does_not_mark_tap_released() {
    let supervisor = SandboxSupervisor::in_memory()
        .with_guest_session(false)
        .with_network(Arc::new(
            NetworkAttachManager::new().with_provisioner(Arc::new(EmptyCleanupProvisioner)),
        ));
    let id = sandbox_id("net_empty_cleanup");
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

    let destroy = supervisor
        .destroy(command(&id, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(destroy.status, OutcomeStatus::Succeeded);

    let classes = present_receipt_classes(&supervisor, &id).await;
    assert!(
        classes.iter().any(|c| c == "tap"),
        "unproven cleanup must leave tap present: {classes:?}"
    );
}
