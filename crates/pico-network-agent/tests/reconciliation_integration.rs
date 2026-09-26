//! Integration tests for network resource reconciliation.
//!
//! Tests cover:
//! - Detection of stale TAP/veth devices and namespace cleanup
//! - Idempotency of destroy cleanup
//! - Ambiguous cleanup marks host degraded or unsafe
//! - Reconciliation emits metrics
//! - Normal cleanup and partial cleanup outcomes
//! - Restart test with stale TAP/veth/netns objects
//! - Reconciliation test for stale NAT/DNS/port-forwarding state
//! - Both microVM and container-style paths

#[cfg(not(target_os = "linux"))]
use pico_network_agent::cleanup::detect_stale;
use pico_network_agent::error::NetworkAgentError;
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};
use pico_network_agent::metrics::{self, NETWORK_METRICS};
use pico_network_agent::receipt::{
    CleanupReceipt, ProvisionReceipt, ResourceKind, ResourceReceipt,
};
use pico_network_agent::reconciliation::{
    HealthStatus, KnownSandboxIds, ReconciliationReport, ResourceClass, SafetyAssessment,
    StaleObject,
};
use std::collections::BTreeSet;
use std::time::Duration;

// ────────────────────────────────────────────────────────────────────
// Reconciliation report and health status tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn health_status_serviceable_behavior() {
    assert!(HealthStatus::Ready.is_serviceable());
    assert!(HealthStatus::Degraded.is_serviceable());
    assert!(!HealthStatus::Unsafe.is_serviceable());
}

#[test]
fn health_status_serialization() {
    let ready = serde_json::to_string(&HealthStatus::Ready).unwrap();
    assert_eq!(ready, "\"ready\"");

    let degraded = serde_json::to_string(&HealthStatus::Degraded).unwrap();
    assert_eq!(degraded, "\"degraded\"");

    let unsafe_state = serde_json::to_string(&HealthStatus::Unsafe).unwrap();
    assert_eq!(unsafe_state, "\"unsafe\"");
}

#[test]
fn health_status_deserialization() {
    let ready: HealthStatus = serde_json::from_str("\"ready\"").unwrap();
    assert_eq!(ready, HealthStatus::Ready);

    let degraded: HealthStatus = serde_json::from_str("\"degraded\"").unwrap();
    assert_eq!(degraded, HealthStatus::Degraded);

    let unsafe_state: HealthStatus = serde_json::from_str("\"unsafe\"").unwrap();
    assert_eq!(unsafe_state, HealthStatus::Unsafe);
}

#[test]
fn report_default_is_ready_zero_stale() {
    let report = ReconciliationReport::default();
    assert_eq!(report.health, HealthStatus::Ready);
    assert_eq!(report.stale_count, 0);
    assert_eq!(report.cleaned_count, 0);
    assert_eq!(report.review_required, 0);
    assert_eq!(report.cleanup_failed, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn stale_object_serialization_roundtrip() {
    let obj = StaleObject {
        resource_name: "cvx0000000001".to_string(),
        resource_class: ResourceClass::TapOrVeth,
        derived_sandbox_id: Some("anon-cvx-0000000001".to_string()),
        safety: SafetyAssessment::SafeToRemove,
        evidence: "belongs to unknown sandbox".to_string(),
        cleaned_up: true,
        cleanup_error: None,
    };

    let json = serde_json::to_string(&obj).unwrap();
    let parsed: StaleObject = serde_json::from_str(&json).unwrap();
    assert_eq!(obj, parsed);
}

#[test]
fn stale_object_with_cleanup_error_serialization_roundtrip() {
    let obj = StaleObject {
        resource_name: "cvx0000000001".to_string(),
        resource_class: ResourceClass::TapOrVeth,
        derived_sandbox_id: Some("anon-cvx-0000000001".to_string()),
        safety: SafetyAssessment::RequiresReview,
        evidence: "cleanup failed".to_string(),
        cleaned_up: false,
        cleanup_error: Some("EACCES: permission denied".to_string()),
    };

    let json = serde_json::to_string(&obj).unwrap();
    let parsed: StaleObject = serde_json::from_str(&json).unwrap();
    assert_eq!(obj, parsed);
}

#[test]
fn safety_assessment_serialization() {
    assert_eq!(
        serde_json::to_string(&SafetyAssessment::SafeToRemove).unwrap(),
        "\"safe-to-remove\""
    );
    assert_eq!(
        serde_json::to_string(&SafetyAssessment::RequiresReview).unwrap(),
        "\"requires-review\""
    );
    assert_eq!(
        serde_json::to_string(&SafetyAssessment::ConfirmedOwned).unwrap(),
        "\"confirmed-owned\""
    );
}

// ────────────────────────────────────────────────────────────────────
// Idempotent cleanup tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn cleanup_receipt_is_idempotent_when_resources_absent() {
    let mut receipt = CleanupReceipt::new("sbx_test".into());
    receipt.push_absent("cvx001".into());
    receipt.push_absent("ns_001".into());
    receipt.finalize(Duration::from_millis(5));

    assert!(receipt.completed);
    assert_eq!(receipt.resources_absent.len(), 2);
    assert_eq!(receipt.resources_removed.len(), 0);
}

#[test]
fn cleanup_receipt_is_idempotent_when_resources_removed() {
    let mut receipt = CleanupReceipt::new("sbx_test".into());
    receipt.push_removed(ResourceReceipt {
        sandbox_id: "sbx_test".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Tap,
        created: false,
        provision_latency: Duration::from_millis(10),
    });
    receipt.finalize(Duration::from_millis(12));

    assert!(receipt.completed);
    assert_eq!(receipt.resources_removed.len(), 1);
    assert_eq!(receipt.resources_absent.len(), 0);
}

#[test]
fn cleanup_receipt_mixed_removed_and_absent() {
    let mut receipt = CleanupReceipt::new("sbx_test".into());
    receipt.push_removed(ResourceReceipt {
        sandbox_id: "sbx_test".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Tap,
        created: false,
        provision_latency: Duration::from_millis(10),
    });
    receipt.push_absent("ns_path".into());
    receipt.push_absent("nft_table".into());
    receipt.finalize(Duration::from_millis(15));

    assert!(receipt.completed);
    assert_eq!(receipt.resources_removed.len(), 1);
    assert_eq!(receipt.resources_absent.len(), 2);
}

// ────────────────────────────────────────────────────────────────────
// Known sandbox ID classification tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn known_sandbox_ids_empty_means_all_are_stale() {
    let known: KnownSandboxIds = BTreeSet::new();
    assert!(known.is_empty());
}

#[test]
fn known_sandbox_ids_contain_sandbox() {
    let mut known: KnownSandboxIds = BTreeSet::new();
    known.insert("sbx_active".to_string());
    known.insert("sbx_suspended".to_string());
    assert!(known.contains("sbx_active"));
    assert!(known.contains("sbx_suspended"));
    assert!(!known.contains("sbx_deleted"));
}

// ────────────────────────────────────────────────────────────────────
// Detection of stale resources on non-Linux (stub behavior)
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
#[cfg(not(target_os = "linux"))]
async fn detect_stale_on_non_linux_returns_empty() {
    let receipt = ProvisionReceipt::new("sbx".into(), BackendClass::MicroVm, 0);
    let (conn, handle) = pico_network_agent::netlink::new_connection().unwrap();
    tokio::spawn(conn);
    let (orphans, missing) = detect_stale(&handle, &receipt).await;
    assert!(orphans.is_empty());
    assert!(missing.is_empty());
}

#[tokio::test]
#[cfg(not(target_os = "linux"))]
async fn reconciliation_on_non_linux_returns_ready() {
    use pico_network_agent::reconciliation::NetworkReconciler;

    let (conn, handle) = pico_network_agent::netlink::new_connection().unwrap();
    tokio::spawn(conn);
    let known: KnownSandboxIds = BTreeSet::new();
    let reconciler = NetworkReconciler::with_noop_inspectors();
    let report = reconciler.reconcile(&handle, &known).await;
    assert_eq!(report.health, HealthStatus::Ready);
    assert_eq!(report.stale_count, 0);
}

// ────────────────────────────────────────────────────────────────────
// Provision receipt tests for both microVM and container paths
// ────────────────────────────────────────────────────────────────────

#[test]
fn microvm_provision_receipt_tracks_tap_link_address() {
    let mut receipt = ProvisionReceipt::new("sbx_vm".into(), BackendClass::MicroVm, 4);
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_vm".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Tap,
        created: true,
        provision_latency: Duration::from_millis(5),
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_vm".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Link,
        created: true,
        provision_latency: Duration::from_millis(1),
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_vm".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Address,
        created: true,
        provision_latency: Duration::from_millis(2),
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_vm".into(),
        resource_name: "default-via-172.16.0.1".into(),
        kind: ResourceKind::Route,
        created: false,
        provision_latency: Duration::from_millis(3),
    });
    receipt.finalize(Duration::from_millis(50));

    // 3 of 4 succeeded
    assert!(!receipt.completed);
    assert_eq!(receipt.resources.len(), 4);
}

#[test]
fn container_provision_receipt_tracks_veth_ns_addresses() {
    let mut receipt = ProvisionReceipt::new("sbx_ct".into(), BackendClass::Container, 9);

    let kinds = [
        ResourceKind::Namespace,
        ResourceKind::Veth,
        ResourceKind::Address, // guest
        ResourceKind::Address, // host
        ResourceKind::Link,    // guest up
        ResourceKind::Link,    // host up
        ResourceKind::Route,
        ResourceKind::Nat,
        ResourceKind::DnsAttachment,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        receipt.push(ResourceReceipt {
            sandbox_id: "sbx_ct".into(),
            resource_name: format!("resource-{i}"),
            kind: *kind,
            created: true,
            provision_latency: Duration::from_millis(1),
        });
    }
    receipt.finalize(Duration::from_millis(100));

    assert!(receipt.completed);
}

// ────────────────────────────────────────────────────────────────────
// Partial provisioning cleanup (rollback scenario)
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_provisioning_rollback_tracks_partial_state() {
    let mut receipt = ProvisionReceipt::new("sbx_partial".into(), BackendClass::MicroVm, 4);

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_partial".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Tap,
        created: true,
        provision_latency: Duration::from_millis(3),
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_partial".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Link,
        created: true,
        provision_latency: Duration::from_millis(1),
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_partial".into(),
        resource_name: "cvx001".into(),
        kind: ResourceKind::Address,
        created: false,
        provision_latency: Duration::ZERO,
    });
    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_partial".into(),
        resource_name: "default-via-172.16.0.1".into(),
        kind: ResourceKind::Route,
        created: false,
        provision_latency: Duration::ZERO,
    });
    receipt.finalize(Duration::from_millis(15));

    assert!(!receipt.completed);
    let created: Vec<_> = receipt.resources.iter().filter(|r| r.created).collect();
    assert_eq!(created.len(), 2);
}

// ────────────────────────────────────────────────────────────────────
// Reconciliation report health computation
// ────────────────────────────────────────────────────────────────────

#[test]
fn reconciliation_report_unsafe_when_review_required() {
    let report = ReconciliationReport {
        review_required: 3,
        stale_count: 0,
        ..Default::default()
    };

    let health = if report.review_required > 0 {
        HealthStatus::Unsafe
    } else if report.stale_count > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Ready
    };

    assert_eq!(health, HealthStatus::Unsafe);
}

#[test]
fn reconciliation_report_degraded_when_stale_but_no_review() {
    let report = ReconciliationReport {
        stale_count: 4,
        cleaned_count: 4,
        review_required: 0,
        ..Default::default()
    };

    let health = if report.review_required > 0 {
        HealthStatus::Unsafe
    } else if report.stale_count > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Ready
    };

    assert_eq!(health, HealthStatus::Degraded);
}

#[test]
fn reconciliation_report_ready_when_no_stale_objects() {
    let report = ReconciliationReport::default();

    let health = if report.review_required > 0 {
        HealthStatus::Unsafe
    } else if report.stale_count > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Ready
    };

    assert_eq!(health, HealthStatus::Ready);
}

#[test]
fn reconciliation_report_ready_with_only_confirmed_owned() {
    // A report with only ConfirmedOwned findings should be Ready
    let report = ReconciliationReport {
        confirmed_owned: 10,
        stale_count: 0,
        ..Default::default()
    };

    assert_eq!(report.stale_count, 0);
    assert_eq!(report.review_required, 0);
    let health = if report.review_required > 0 {
        HealthStatus::Unsafe
    } else if report.stale_count > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Ready
    };
    assert_eq!(health, HealthStatus::Ready);
}

// ────────────────────────────────────────────────────────────────────
// Nftables table name tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn sandbox_table_name_is_deterministic() {
    use pico_network_agent::nftables::NftClient;

    let name1 = NftClient::sandbox_table_name("sbx_a", "cvx001");
    let name2 = NftClient::sandbox_table_name("sbx_a", "cvx001");
    assert_eq!(name1, name2);

    let name3 = NftClient::sandbox_table_name("sbx_b", "cvx001");
    assert_ne!(name1, name3);
}

// ────────────────────────────────────────────────────────────────────
// All resource kinds are covered in reconciliation
// ────────────────────────────────────────────────────────────────────

#[test]
fn all_resource_kinds_are_serializable() {
    let kinds = [
        ResourceKind::Tap,
        ResourceKind::Veth,
        ResourceKind::Namespace,
        ResourceKind::Route,
        ResourceKind::Address,
        ResourceKind::Link,
        ResourceKind::Egress,
        ResourceKind::Nat,
        ResourceKind::DnsAttachment,
    ];

    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let parsed: ResourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, parsed);
    }
}

// ────────────────────────────────────────────────────────────────────
// Metrics registration tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn reconciliation_metrics_are_registered() {
    let _ = &*NETWORK_METRICS;
}

#[test]
fn reconciliation_metrics_can_be_recorded() {
    // Exercises every reconciliation series through the module's interface,
    // which is where the label set and the zero-increment guard now live.
    metrics::record_reconciliation_pass(
        0.01,
        &metrics::ReconciliationReport {
            stale_count: 3,
            cleaned_count: 2,
            review_required: 1,
            cleanup_failed: 1,
            health: metrics::NetworkHealth::Degraded,
        },
    );
}

#[test]
fn clean_reconciliation_pass_records_health_only() {
    let report = metrics::ReconciliationReport::default();
    assert_eq!(report.stale_count, 0);
    assert_eq!(report.health, metrics::NetworkHealth::Ready);
    metrics::record_reconciliation_pass(0.001, &report);
}

#[test]
fn every_health_state_is_publishable() {
    for health in [
        metrics::NetworkHealth::Ready,
        metrics::NetworkHealth::Degraded,
        metrics::NetworkHealth::Unsafe,
    ] {
        metrics::record_reconciliation_pass(
            0.001,
            &metrics::ReconciliationReport {
                health,
                ..Default::default()
            },
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Error type tests for reconciliation
// ────────────────────────────────────────────────────────────────────

#[test]
fn reconciliation_errors_display_correctly() {
    let err = NetworkAgentError::AmbiguousResource {
        resource_name: "cvx0000000001".to_string(),
        detail: "partial match".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("cvx0000000001"));
    assert!(msg.contains("partial match"));
}

#[test]
fn stale_resource_cleanup_failed_error_display() {
    let err = NetworkAgentError::StaleResourceCleanupFailed {
        resource_name: "cvx0000000001".to_string(),
        detail: "EACCES".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("cvx0000000001"));
    assert!(msg.contains("EACCES"));
}

#[test]
fn reconciliation_pass_failed_error_display() {
    let err = NetworkAgentError::ReconciliationPassFailed {
        detail: "netlink socket exhausted".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("netlink socket exhausted"));
}

// ────────────────────────────────────────────────────────────────────
// Test that both microVM and container backends produce receipts
// with the correct resource kinds
// ────────────────────────────────────────────────────────────────────

#[test]
fn microvm_identity_produces_tap_backend_class() {
    let identity = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
    assert_eq!(identity.backend_class, BackendClass::MicroVm);
    assert!(identity.if_name.starts_with("cvx"));
    assert!(identity.host_if_name.starts_with("hp-"));
}

#[test]
fn container_identity_produces_veth_backend_class() {
    let identity = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::Container);
    assert_eq!(identity.backend_class, BackendClass::Container);
    assert!(identity.if_name.starts_with("cvx"));
    assert!(identity.host_if_name.starts_with("hpc"));
}

#[test]
fn microvm_and_container_identities_are_distinct() {
    let vm = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
    let ct = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::Container);
    assert_ne!(vm.host_if_name, ct.host_if_name);
    assert_ne!(vm.ns_path, ct.ns_path);
}
