use pico_network_agent::egress::EgressPolicy;
use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};
use pico_network_agent::receipt::{ResourceKind, ResourceReceipt};

use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn ebpf_policy_deterministic_ifindex() {
    let identity_1 = SandboxNetworkIdentity::for_sandbox("sbx_ebpf_test", BackendClass::MicroVm);
    let identity_2 = SandboxNetworkIdentity::for_sandbox("sbx_ebpf_test", BackendClass::MicroVm);

    assert_eq!(identity_1.if_name, identity_2.if_name);
    assert_eq!(identity_1.host_if_name, identity_2.host_if_name);
    assert_eq!(identity_1.guest_ip, identity_2.guest_ip);
}

#[test]
fn ebpf_resource_kind_exists() {
    let receipt = ResourceReceipt {
        sandbox_id: "sbx_test".into(),
        resource_name: "ebpf-xdp-cvx001".into(),
        kind: ResourceKind::EbpF,
        created: true,
        provision_latency: Duration::from_millis(1),
    };

    assert!(receipt.created);
    assert_eq!(receipt.kind, ResourceKind::EbpF);
    assert!(receipt.resource_name.contains("ebpf-xdp"));
}

#[test]
fn ebpf_receipt_serde_roundtrip() {
    let receipt = ResourceReceipt {
        sandbox_id: "sbx_test".into(),
        resource_name: "ebpf-xdp-cvx001".into(),
        kind: ResourceKind::EbpF,
        created: true,
        provision_latency: Duration::from_millis(5),
    };

    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: ResourceReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(receipt.sandbox_id, parsed.sandbox_id);
    assert_eq!(receipt.kind, parsed.kind);
    assert!(parsed.created);
}

#[test]
fn ebpf_policy_mirrors_egress_allow_list() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_ebpf_01".into(),
        tenant_id: "tnt_01".into(),
        if_name: "cvx001".into(),
        allowed_cidrs: vec!["1.1.1.1/32".into(), "8.8.8.8/32".into()],
        policy_decision_id: "pdc_01".into(),
        lease_id: Some("lse_01".into()),
    };

    assert_eq!(policy.allowed_cidrs.len(), 2);

    let rules = policy.compile_rules();
    let egress_allows: Vec<_> = rules
        .iter()
        .filter(|r| r.identity.rule_purpose == "egress-allow")
        .collect();
    assert_eq!(egress_allows.len(), 2);
}

#[test]
fn ebpf_deny_by_default_mirrors_nftables() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_ebpf_02".into(),
        tenant_id: "tnt_01".into(),
        if_name: "cvx002".into(),
        allowed_cidrs: vec![],
        policy_decision_id: "pdc_01".into(),
        lease_id: None,
    };

    let rules = policy.compile_rules();
    assert!(
        rules
            .iter()
            .any(|r| r.identity.rule_purpose == "default-deny"),
        "deny-by-default with no CIDRs must include a default deny"
    );
}

#[test]
fn ebpf_anti_spoofing_different_sandboxes_have_different_ips() {
    let identity = SandboxNetworkIdentity::for_sandbox("sbx_spoof_test", BackendClass::MicroVm);
    let second = SandboxNetworkIdentity::for_sandbox("sbx_spoof_test", BackendClass::MicroVm);
    assert_eq!(
        identity.guest_ip, second.guest_ip,
        "guest IP must be deterministic"
    );

    let different = SandboxNetworkIdentity::for_sandbox("other_sbx", BackendClass::MicroVm);
    assert_ne!(
        identity.guest_ip, different.guest_ip,
        "different sandboxes must have different IPs for anti-spoofing"
    );
}

#[test]
fn ebpf_capability_registered() {
    use pico_core::runtime::{BackendCapabilities, BackendCapability};

    let capabilities =
        BackendCapabilities::from([BackendCapability::Boot, BackendCapability::EbpFNetworking]);

    assert!(capabilities.contains(BackendCapability::EbpFNetworking));
    assert!(capabilities.contains(BackendCapability::Boot));
    assert!(!capabilities.contains(BackendCapability::Exec));
}

#[test]
fn ebpf_capability_serde_roundtrip() {
    use pico_core::runtime::{BackendCapabilities, BackendCapability};

    let caps = BackendCapabilities::from([
        BackendCapability::Boot,
        BackendCapability::EbpFNetworking,
        BackendCapability::Exec,
    ]);

    let json = serde_json::to_string(&caps).unwrap();
    let parsed: BackendCapabilities = serde_json::from_str(&json).unwrap();

    assert!(parsed.contains(BackendCapability::EbpFNetworking));
    assert!(parsed.contains(BackendCapability::Boot));
}

#[test]
fn ebpf_guest_ip_convertible_to_u32() {
    let identity = SandboxNetworkIdentity::for_sandbox("sbx_conv", BackendClass::MicroVm);
    let ip_u32 = u32::from_be_bytes(identity.guest_ip.octets());
    let roundtrip = Ipv4Addr::from(ip_u32.to_be_bytes());

    assert_eq!(identity.guest_ip, roundtrip);
}

#[test]
fn ebpf_sandbox_identity_deterministic() {
    let id_1 = SandboxNetworkIdentity::for_sandbox("sbx_ebpf_det", BackendClass::MicroVm);
    let id_2 = SandboxNetworkIdentity::for_sandbox("sbx_ebpf_det", BackendClass::MicroVm);

    assert_eq!(id_1, id_2);
    assert_eq!(id_1.if_name, id_2.if_name);
    assert_eq!(id_1.guest_ip, id_2.guest_ip);
    assert_eq!(id_1.host_ip, id_2.host_ip);
}
