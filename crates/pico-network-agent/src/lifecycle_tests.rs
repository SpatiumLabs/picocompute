use super::*;
use crate::identity::{BackendClass, SandboxNetworkIdentity};

// ── Helper constructors ─────────────────────────────────

fn test_identity(sandbox_id: &str, backend: BackendClass) -> SandboxNetworkIdentity {
    SandboxNetworkIdentity::for_sandbox(sandbox_id, backend)
}

fn test_suspend_receipt(sandbox_id: &str, policy_epoch: u64) -> SuspendReceipt {
    SuspendReceipt {
        sandbox_id: sandbox_id.to_string(),
        policy_epoch,
        network_identity: test_identity(sandbox_id, BackendClass::MicroVm),
        resource_receipts: vec![],
        egress_policy_snapshot: None,
        dns_attachment_snapshot: None,
        nat_config_snapshot: None,
        connections_dropped: 0,
        suspended_at: now_iso(),
        operation_id: "opr_suspend_01".to_string(),
    }
}

// ── Policy epoch validation tests ────────────────────────

#[test]
fn validate_policy_epoch_accepts_advancing_epoch() {
    assert!(validate_policy_epoch("sbx", 5, 5).is_ok());
    assert!(validate_policy_epoch("sbx", 5, 10).is_ok());
    assert!(validate_policy_epoch("sbx", 0, 0).is_err()); // zero rejected
    assert!(validate_policy_epoch("sbx", 1, 0).is_err()); // zero rejected
}

#[test]
fn validate_policy_epoch_rejects_stale_epoch() {
    let result = validate_policy_epoch("sbx_test", 10, 5);
    assert!(result.is_err());
    match result {
        Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id,
            expected,
            actual,
        }) => {
            assert_eq!(sandbox_id, "sbx_test");
            assert!(expected.contains("10"));
            assert_eq!(actual, 5);
        }
        other => panic!("expected StalePolicyEpoch, got {other:?}"),
    }
}

#[test]
fn validate_policy_epoch_rejects_zero() {
    let result = validate_policy_epoch("sbx_test", 5, 0);
    assert!(result.is_err());
    match result {
        Err(crate::error::NetworkAgentError::StalePolicyEpoch { actual, .. }) => {
            assert_eq!(actual, 0);
        }
        other => panic!("expected StalePolicyEpoch, got {other:?}"),
    }
}

// ── Fork identity independence tests ──────────────────────

#[test]
fn fork_produces_different_identity_from_parent() {
    let parent_id = test_identity("parent_sbx", BackendClass::MicroVm);
    let child_id = SandboxNetworkIdentity::for_sandbox("child_sbx", BackendClass::MicroVm);

    assert_ne!(parent_id.if_name, child_id.if_name);
    assert_ne!(parent_id.host_if_name, child_id.host_if_name);
    assert_ne!(parent_id.guest_ip, child_id.guest_ip);
    assert_ne!(parent_id.guest_mac, child_id.guest_mac);
    assert_ne!(parent_id.ns_path, child_id.ns_path);
}

#[test]
fn fork_identity_is_deterministic() {
    let id1 = SandboxNetworkIdentity::for_sandbox("child_a", BackendClass::MicroVm);
    let id2 = SandboxNetworkIdentity::for_sandbox("child_a", BackendClass::MicroVm);
    assert_eq!(id1, id2);
}

#[test]
fn fork_different_backend_class_produces_different_identity() {
    let vm = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
    let ct = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::Container);
    assert_ne!(vm.host_if_name, ct.host_if_name);
    assert_ne!(vm.ns_path, ct.ns_path);
    assert_ne!(vm.backend_class, ct.backend_class);
}

fn resume_request(sandbox_id: &str, current_epoch: u64, suspend_epoch: u64) -> ResumeRequest {
    let identity = test_identity(sandbox_id, BackendClass::MicroVm);
    ResumeRequest {
        sandbox_id: sandbox_id.to_string(),
        tenant_id: "tnt_test".to_string(),
        current_policy_epoch: current_epoch,
        network_identity: identity,
        suspend_receipt: test_suspend_receipt(sandbox_id, suspend_epoch),
        lineage_id: "lineage_01".to_string(),
        operation_id: "opr_resume_01".to_string(),
    }
}

// ── Resume validation tests ───────────────────────────────

#[test]
fn validate_resume_accepts_current_or_equal_epoch() {
    assert!(validate_resume(&resume_request("sbx_resume", 2, 1)).is_ok());
    assert!(validate_resume(&resume_request("sbx_resume", 5, 5)).is_ok());
}

#[test]
fn validate_resume_rejects_stale_and_zero_epoch() {
    let stale = validate_resume(&resume_request("sbx_resume", 4, 9)).expect_err("older epoch");
    assert!(matches!(
        stale,
        crate::error::NetworkAgentError::StalePolicyEpoch { actual: 4, .. }
    ));
    let unset = validate_resume(&resume_request("sbx_resume", 0, 1)).expect_err("unset epoch");
    assert!(matches!(
        unset,
        crate::error::NetworkAgentError::StalePolicyEpoch { actual: 0, .. }
    ));
}

#[test]
fn validate_resume_rejects_identity_that_is_not_derived() {
    let mut request = resume_request("sbx_resume", 2, 1);
    let mut forged = test_identity("sbx_resume", BackendClass::MicroVm);
    forged.guest_mac = "02:fc:00:00:00:01".to_string();
    request.network_identity = forged.clone();
    request.suspend_receipt.network_identity = forged;
    let err = validate_resume(&request).expect_err("forged copies");
    match err {
        crate::error::NetworkAgentError::IdentityConflict { detail, .. } => {
            assert!(detail.contains("derived identity"));
        }
        other => panic!("expected IdentityConflict, got {other:?}"),
    }
}

#[test]
fn validate_resume_rejects_suspend_receipt_sandbox_mismatch() {
    let mut request = resume_request("sbx_resume", 2, 1);
    request.suspend_receipt.sandbox_id = "other_sbx".to_string();
    let err = validate_resume(&request).expect_err("suspend sandbox");
    match err {
        crate::error::NetworkAgentError::IdentityConflict { detail, .. } => {
            assert!(detail.contains("other_sbx"));
        }
        other => panic!("expected IdentityConflict, got {other:?}"),
    }
}

// ── Fork identity decision tests ──────────────────────────

fn fork_request(parent: &str, child: &str, epoch: u64) -> ForkRequest {
    ForkRequest {
        parent_sandbox_id: parent.to_string(),
        child_sandbox_id: child.to_string(),
        child_tenant_id: "tnt_test".to_string(),
        child_policy_epoch: epoch,
        child_backend_class: BackendClass::MicroVm,
        parent_suspend_receipt: test_suspend_receipt(parent, 1),
        lineage_id: "lineage_01".to_string(),
        operation_id: "opr_fork_01".to_string(),
    }
}

#[test]
fn derive_child_identity_does_not_reuse_parent() {
    let request = fork_request("parent_sbx", "child_sbx", 3);
    let child = derive_child_network_identity(&request).expect("distinct child");
    let parent = &request.parent_suspend_receipt.network_identity;
    assert_ne!(child.sandbox_id, parent.sandbox_id);
    assert_ne!(child.if_name, parent.if_name);
    assert_ne!(child.host_if_name, parent.host_if_name);
    assert_ne!(child.guest_ip, parent.guest_ip);
    assert_ne!(child.guest_mac, parent.guest_mac);
    assert_ne!(child.ns_path, parent.ns_path);
    assert!(child.if_name.len() <= 15);
    assert!(child.host_if_name.len() <= 15);
}

#[test]
fn derive_child_identity_rejects_zero_epoch() {
    let request = fork_request("parent_sbx", "child_sbx", 0);
    let err = derive_child_network_identity(&request).expect_err("unset epoch");
    assert!(matches!(
        err,
        crate::error::NetworkAgentError::StalePolicyEpoch { actual: 0, .. }
    ));
}

#[test]
fn derive_child_identity_rejects_same_sandbox() {
    let request = fork_request("same_sbx", "same_sbx", 2);
    let err = derive_child_network_identity(&request).expect_err("same id");
    assert!(matches!(
        err,
        crate::error::NetworkAgentError::IdentityConflict { .. }
    ));
}

#[test]
fn derive_child_identity_rejects_parent_collision() {
    let mut request = fork_request("parent_sbx", "child_sbx", 2);
    let child = test_identity("child_sbx", BackendClass::MicroVm);
    request
        .parent_suspend_receipt
        .network_identity
        .host_if_name
        .clone_from(&child.host_if_name);
    let err = derive_child_network_identity(&request).expect_err("host peer collision");
    assert!(matches!(
        err,
        crate::error::NetworkAgentError::IdentityConflict { .. }
    ));
}

// ── Port-forwarding inheritance tests ─────────────────────

#[test]
fn fork_receipt_records_port_forwarding_blocked() {
    // ForkReceipt always has port_forwarding_blocked = true.
    let receipt = ForkReceipt {
        parent_sandbox_id: "parent_sbx".to_string(),
        child_sandbox_id: "child_sbx".to_string(),
        child_network_identity: test_identity("child_sbx", BackendClass::MicroVm),
        port_forwarding_blocked: true,
        child_resource_receipts: vec![],
        forked_at: now_iso(),
        operation_id: "opr_fork_01".to_string(),
    };

    assert!(receipt.port_forwarding_blocked);
    // Parent and child have different sandbox IDs
    assert_ne!(receipt.parent_sandbox_id, receipt.child_sandbox_id);
    // Child has a different network identity
    assert_ne!(
        receipt.child_network_identity.sandbox_id,
        receipt.parent_sandbox_id
    );
}

#[test]
fn fork_never_uses_parent_mac() {
    let parent_id = test_identity("parent", BackendClass::MicroVm);
    let child_id = test_identity("child", BackendClass::MicroVm);

    assert_ne!(parent_id.guest_mac, child_id.guest_mac);
}

#[test]
fn fork_never_uses_parent_ip() {
    let parent_id = test_identity("parent", BackendClass::MicroVm);
    let child_id = test_identity("child", BackendClass::MicroVm);

    assert_ne!(parent_id.guest_ip, child_id.guest_ip);
}

// ── Suspend receipt serialization ─────────────────────────

#[test]
fn suspend_receipt_serde_roundtrip() {
    let receipt = test_suspend_receipt("sbx_test", 5);
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: SuspendReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.sandbox_id, parsed.sandbox_id);
    assert_eq!(receipt.policy_epoch, parsed.policy_epoch);
    assert_eq!(receipt.network_identity, parsed.network_identity);
}

#[test]
fn resume_receipt_serde_roundtrip() {
    let receipt = ResumeReceipt {
        sandbox_id: "sbx_test".to_string(),
        policy_epoch_validated: true,
        applied_policy_epoch: 3,
        resource_receipts: vec![],
        resources_rebuilt: true,
        resumed_at: now_iso(),
        operation_id: "opr_01".to_string(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: ResumeReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.sandbox_id, parsed.sandbox_id);
    assert_eq!(
        receipt.policy_epoch_validated,
        parsed.policy_epoch_validated
    );
    assert_eq!(receipt.applied_policy_epoch, parsed.applied_policy_epoch);
}

#[test]
fn fork_receipt_serde_roundtrip() {
    let receipt = ForkReceipt {
        parent_sandbox_id: "parent".to_string(),
        child_sandbox_id: "child".to_string(),
        child_network_identity: test_identity("child", BackendClass::MicroVm),
        port_forwarding_blocked: true,
        child_resource_receipts: vec![],
        forked_at: now_iso(),
        operation_id: "opr_fork_01".to_string(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: ForkReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.parent_sandbox_id, parsed.parent_sandbox_id);
    assert_eq!(receipt.child_sandbox_id, parsed.child_sandbox_id);
    assert!(parsed.port_forwarding_blocked);
    assert_eq!(
        receipt.child_network_identity,
        parsed.child_network_identity
    );
}

// ── Snapshot types serialization ──────────────────────────

#[test]
fn egress_policy_snapshot_serde_roundtrip() {
    let snapshot = EgressPolicySnapshot {
        table_name: "pico-sbx-test-cvx001".to_string(),
        allowed_cidrs: vec!["0.0.0.0/0".to_string()],
        policy_decision_id: "pdc_test".to_string(),
        lease_id: Some("lse_test".to_string()),
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let parsed: EgressPolicySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot.table_name, parsed.table_name);
    assert_eq!(snapshot.allowed_cidrs, parsed.allowed_cidrs);
}

#[test]
fn dns_attachment_snapshot_serde_roundtrip() {
    let snapshot = DnsAttachmentSnapshot {
        if_name: "cvx001".to_string(),
        proxy_listen_addr: "127.0.0.53".to_string(),
        proxy_listen_port: 53,
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let parsed: DnsAttachmentSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot.if_name, parsed.if_name);
    assert_eq!(snapshot.proxy_listen_port, parsed.proxy_listen_port);
}

#[test]
fn nat_config_snapshot_serde_roundtrip() {
    let snapshot = NatConfigSnapshot {
        table_name: "pico-sbx-test-cvx001".to_string(),
        if_name: "cvx001".to_string(),
        host_if_name: "eth0".to_string(),
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let parsed: NatConfigSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot.table_name, parsed.table_name);
    assert_eq!(snapshot.host_if_name, parsed.host_if_name);
}
