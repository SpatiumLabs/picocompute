//! Integration tests for sandbox egress policy and NAT setup.
//!
//! Tests cover:
//! - Egress policy compilation for allowed/denied/lease-based egress
//! - Internal network protection (RFC 1918, CGNAT, link-local)
//! - NAT masquerade rule generation
//! - Policy update (flush + reinstall)
//! - Cleanup idempotency
//! - Identity binding (tenant, sandbox, policy decision, lease)
//! - Serialization roundtrips for durable reconciliation

use pico_network_agent::bandwidth::{BandwidthLimit, format_rate, validate_bandwidth_limit};
use pico_network_agent::egress::EgressPolicy;
use pico_network_agent::identity::{BackendClass, INTERNAL_NETWORKS};
use pico_network_agent::nat::NatConfig;
use pico_network_agent::nftables::{NftClient, NftRule, NftRuleIdentity};
use pico_network_agent::receipt::{ProvisionReceipt, ResourceKind, ResourceReceipt};

use std::time::Duration;

// ────────────────────────────────────────────────────────────────────
// Egress policy compilation tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn egress_policy_compile_with_allowed_cidrs() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_01".into(),
        tenant_id: "tnt_01".into(),
        if_name: "cvx001".into(),
        allowed_cidrs: vec!["1.1.1.1/32".into(), "8.8.8.8/32".into()],
        policy_decision_id: "pdc_01".into(),
        lease_id: Some("lse_01".into()),
    };

    let rules = policy.compile_rules();

    // Must include conntrack established/related
    let ct_rule = rules
        .iter()
        .find(|r| r.identity.rule_purpose == "ct-state")
        .expect("must have ct state rule");
    assert!(ct_rule.expression.contains("ct state established,related"));

    // Must include interface binding on every verdict rule
    let verdict_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.identity.rule_purpose != "ct-state")
        .collect();
    assert!(!verdict_rules.is_empty());
    for rule in &verdict_rules {
        assert!(
            rule.expression.contains("iif cvx001"),
            "every verdict rule must bind to sandbox interface via iif"
        );
    }

    // Must have accept rules for each allowed CIDR
    let accept_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.identity.rule_purpose == "egress-allow")
        .collect();
    assert_eq!(accept_rules.len(), 2);
    assert!(
        accept_rules
            .iter()
            .any(|r| r.expression.contains("1.1.1.1/32")),
        "must accept 1.1.1.1/32"
    );
    assert!(
        accept_rules
            .iter()
            .any(|r| r.expression.contains("8.8.8.8/32")),
        "must accept 8.8.8.8/32"
    );

    // Should deny all internal networks not in the allowed set
    let internal_deny_count = rules
        .iter()
        .filter(|r| r.identity.rule_purpose == "internal-deny")
        .count();
    assert_eq!(internal_deny_count, INTERNAL_NETWORKS.len());

    // No default-deny when CIDRs are specified
    assert!(
        !rules
            .iter()
            .any(|r| r.identity.rule_purpose == "default-deny")
    );
}

#[test]
fn egress_policy_compile_with_no_cidrs_is_deny_all() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_02".into(),
        tenant_id: "tnt_02".into(),
        if_name: "cvx002".into(),
        allowed_cidrs: vec![],
        policy_decision_id: "pdc_02".into(),
        lease_id: None,
    };

    let rules = policy.compile_rules();

    // Must have ct-state
    assert!(rules.iter().any(|r| r.identity.rule_purpose == "ct-state"));

    // All verdict rules must bind to the sandbox interface
    for rule in &rules {
        if rule.identity.rule_purpose != "ct-state" {
            assert!(rule.expression.contains("iif cvx002"));
        }
    }

    // Must deny all internal networks
    assert_eq!(
        rules
            .iter()
            .filter(|r| r.identity.rule_purpose == "internal-deny")
            .count(),
        INTERNAL_NETWORKS.len()
    );

    // Must have a default-deny rule
    assert!(
        rules
            .iter()
            .any(|r| r.identity.rule_purpose == "default-deny"),
        "no-CIDR policy must include default-deny"
    );
}

#[test]
fn egress_policy_internal_networks_are_protected_by_default() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_03".into(),
        tenant_id: "tnt_03".into(),
        if_name: "cvx003".into(),
        allowed_cidrs: vec!["0.0.0.0/0".into()],
        policy_decision_id: "pdc_03".into(),
        lease_id: None,
    };

    let rules = policy.compile_rules();

    // Even with 0.0.0.0/0, internal networks should have explicit deny rules
    // (since 0.0.0.0/0 does not match the specific internal network strings)
    let internal_deny: Vec<_> = rules
        .iter()
        .filter(|r| r.identity.rule_purpose == "internal-deny")
        .collect();
    assert!(
        !internal_deny.is_empty(),
        "internal networks must be denied even with wide allow"
    );
}

#[test]
fn egress_policy_lease_internal_network_exception() {
    // When a lease explicitly allows an internal network, the deny rule
    // for that network must be omitted
    let policy = EgressPolicy {
        sandbox_id: "sbx_04".into(),
        tenant_id: "tnt_04".into(),
        if_name: "cvx004".into(),
        allowed_cidrs: vec!["192.168.0.0/16".into()],
        policy_decision_id: "pdc_04".into(),
        lease_id: Some("lse_04".into()),
    };

    let rules = policy.compile_rules();

    // 192.168.0.0/16 should be an accept rule, not a deny
    let has_accept = rules.iter().any(|r| {
        r.identity.rule_purpose == "egress-allow" && r.expression.contains("192.168.0.0/16")
    });
    assert!(
        has_accept,
        "explicitly allowed internal network must be accepted"
    );

    // 192.168.0.0/16 should NOT have an internal-deny rule
    let has_deny = rules.iter().any(|r| {
        r.identity.rule_purpose == "internal-deny" && r.expression.contains("192.168.0.0/16")
    });
    assert!(
        !has_deny,
        "explicitly allowed internal network must not be denied"
    );

    // But other internal networks should still be denied
    assert!(
        rules.iter().any(|r| {
            r.identity.rule_purpose == "internal-deny" && r.expression.contains("10.0.0.0/8")
        }),
        "other internal networks must still be denied"
    );
}

#[test]
fn egress_policy_protects_loopback() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_05".into(),
        tenant_id: "tnt_05".into(),
        if_name: "cvx005".into(),
        allowed_cidrs: vec!["0.0.0.0/0".into()],
        policy_decision_id: "pdc_05".into(),
        lease_id: None,
    };

    let rules = policy.compile_rules();
    assert!(
        INTERNAL_NETWORKS.contains(&"127.0.0.0/8"),
        "127.0.0.0/8 must be in internal networks list"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.identity.rule_purpose == "internal-deny"
                && r.expression.contains("127.0.0.0/8")),
        "loopback must be denied by default"
    );
}

// ────────────────────────────────────────────────────────────────────
// NAT rule generation tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn nat_config_compile_produces_masquerade_rule() {
    let config = NatConfig {
        sandbox_id: "sbx_06".into(),
        tenant_id: "tnt_06".into(),
        if_name: "cvx006".into(),
        host_if_name: "eth0".into(),
        policy_decision_id: "pdc_06".into(),
    };

    let rules = config.compile_rules();
    assert_eq!(rules.len(), 1);

    let rule = &rules[0];
    assert_eq!(rule.family, "inet");
    assert_eq!(rule.chain, "snat");
    assert!(rule.expression.contains("masquerade"));
    assert!(rule.expression.contains("iif cvx006"));
    assert!(rule.expression.contains("oif eth0"));
}

#[test]
fn nat_config_table_name_matches_egress() {
    let config = NatConfig {
        sandbox_id: "sbx_07".into(),
        tenant_id: "tnt_07".into(),
        if_name: "cvx007".into(),
        host_if_name: "eth0".into(),
        policy_decision_id: "pdc_07".into(),
    };

    let egress_policy = EgressPolicy {
        sandbox_id: "sbx_07".into(),
        tenant_id: "tnt_07".into(),
        if_name: "cvx007".into(),
        allowed_cidrs: vec![],
        policy_decision_id: "pdc_07".into(),
        lease_id: None,
    };

    assert_eq!(config.table_name(), egress_policy.table_name());
}

// ────────────────────────────────────────────────────────────────────
// Identity binding tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn egress_policy_rule_identity_binds_all_context() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_08".into(),
        tenant_id: "tnt_08".into(),
        if_name: "cvx008".into(),
        allowed_cidrs: vec!["10.0.0.0/8".into()],
        policy_decision_id: "pdc_08".into(),
        lease_id: Some("lse_08".into()),
    };

    let rules = policy.compile_rules();

    for rule in &rules {
        assert_eq!(rule.identity.sandbox_id, "sbx_08");
        assert_eq!(rule.identity.tenant_id, "tnt_08");
        assert_eq!(rule.identity.policy_decision_id, "pdc_08");
        assert_eq!(rule.identity.lease_id, Some("lse_08".into()));
    }
}

#[test]
fn egress_policy_without_lease_has_no_lease_id() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_09".into(),
        tenant_id: "tnt_09".into(),
        if_name: "cvx009".into(),
        allowed_cidrs: vec!["0.0.0.0/0".into()],
        policy_decision_id: "pdc_09".into(),
        lease_id: None,
    };

    let rules = policy.compile_rules();

    for rule in &rules {
        assert!(
            rule.identity.lease_id.is_none(),
            "rules without lease must not have lease_id"
        );
    }
}

#[test]
fn nat_config_rule_identity_binds_sandbox_and_tenant() {
    let config = NatConfig {
        sandbox_id: "sbx_10".into(),
        tenant_id: "tnt_10".into(),
        if_name: "cvx010".into(),
        host_if_name: "eth0".into(),
        policy_decision_id: "pdc_10".into(),
    };

    let rules = config.compile_rules();
    for rule in &rules {
        assert_eq!(rule.identity.sandbox_id, "sbx_10");
        assert_eq!(rule.identity.tenant_id, "tnt_10");
        assert_eq!(rule.identity.policy_decision_id, "pdc_10");
        assert!(rule.identity.lease_id.is_none());
    }
}

#[test]
fn identity_comment_embeds_all_ids() {
    let rule = NftRule {
        family: "inet".into(),
        table: "pico-sbx-test".into(),
        chain: "forward".into(),
        expression: "accept".into(),
        identity: NftRuleIdentity {
            sandbox_id: "sbx_11".into(),
            tenant_id: "tnt_11".into(),
            policy_decision_id: "pdc_11".into(),
            lease_id: Some("lse_11".into()),
            rule_purpose: "test".into(),
        },
    };

    let comment = NftClient::identity_comment(&rule.identity);
    assert!(comment.contains("sbid=sbx_11"));
    assert!(comment.contains("tid=tnt_11"));
    assert!(comment.contains("pdid=pdc_11"));
    assert!(comment.contains("lid=lse_11"));
}

// ────────────────────────────────────────────────────────────────────
// Policy update tests (flush + reinstall)
// ────────────────────────────────────────────────────────────────────

#[test]
fn egress_policy_update_changes_rules() {
    let policy_v1 = EgressPolicy {
        sandbox_id: "sbx_12".into(),
        tenant_id: "tnt_12".into(),
        if_name: "cvx012".into(),
        allowed_cidrs: vec!["10.0.0.0/8".into()],
        policy_decision_id: "pdc_v1".into(),
        lease_id: Some("lse_v1".into()),
    };

    let rules_v1 = policy_v1.compile_rules();

    let policy_v2 = EgressPolicy {
        sandbox_id: "sbx_12".into(),
        tenant_id: "tnt_12".into(),
        if_name: "cvx012".into(),
        allowed_cidrs: vec!["0.0.0.0/0".into()],
        policy_decision_id: "pdc_v2".into(),
        lease_id: Some("lse_v2".into()),
    };

    let rules_v2 = policy_v2.compile_rules();

    // Rules should differ (different policy_decision_id, different CIDRs)
    assert_ne!(rules_v1, rules_v2);

    // V2 has updated policy decision ID
    for rule in &rules_v2 {
        assert_eq!(rule.identity.policy_decision_id, "pdc_v2");
        assert_eq!(rule.identity.lease_id, Some("lse_v2".into()));
    }
}

#[test]
fn egress_policy_update_same_policy_is_idempotent() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_13".into(),
        tenant_id: "tnt_13".into(),
        if_name: "cvx013".into(),
        allowed_cidrs: vec!["10.0.0.0/8".into(), "8.8.8.8/32".into()],
        policy_decision_id: "pdc_13".into(),
        lease_id: Some("lse_13".into()),
    };

    let rules1 = policy.compile_rules();
    let rules2 = policy.compile_rules();
    assert_eq!(rules1, rules2, "same policy should produce identical rules");
}

#[test]
fn egress_policy_revoke_removes_all_egress() {
    let policy_active = EgressPolicy {
        sandbox_id: "sbx_14".into(),
        tenant_id: "tnt_14".into(),
        if_name: "cvx014".into(),
        allowed_cidrs: vec!["1.1.1.1/32".into()],
        policy_decision_id: "pdc_14".into(),
        lease_id: Some("lse_14".into()),
    };

    let rules_active = policy_active.compile_rules();
    assert!(
        rules_active
            .iter()
            .any(|r| r.identity.rule_purpose == "egress-allow"),
        "active policy must have egress-allow rules"
    );

    // After revocation, policy has no CIDRs and no lease
    let policy_revoked = EgressPolicy {
        sandbox_id: "sbx_14".into(),
        tenant_id: "tnt_14".into(),
        if_name: "cvx014".into(),
        allowed_cidrs: vec![],
        policy_decision_id: "pdc_revoked".into(),
        lease_id: None,
    };

    let rules_revoked = policy_revoked.compile_rules();
    assert!(
        !rules_revoked
            .iter()
            .any(|r| r.identity.rule_purpose == "egress-allow"),
        "revoked policy must have no egress-allow rules"
    );
    assert!(
        rules_revoked
            .iter()
            .any(|r| r.identity.rule_purpose == "default-deny"),
        "revoked policy must have default-deny"
    );
}

// ────────────────────────────────────────────────────────────────────
// Resource receipt tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn provision_receipt_includes_egress_and_nat() {
    let mut receipt = ProvisionReceipt::new(
        "sbx_15".into(),
        BackendClass::MicroVm,
        6, // tap, link_up, address, route, egress, nat
    );

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_15".into(),
        resource_name: "cvx015".into(),
        kind: ResourceKind::Tap,
        created: true,
        provision_latency: Duration::from_millis(10),
    });

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_15".into(),
        resource_name: "pico-sbx-sbx_15-cvx015".into(),
        kind: ResourceKind::Egress,
        created: true,
        provision_latency: Duration::from_millis(5),
    });

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_15".into(),
        resource_name: "pico-sbx-sbx_15-cvx015".into(),
        kind: ResourceKind::Nat,
        created: true,
        provision_latency: Duration::from_millis(3),
    });

    receipt.finalize(Duration::from_millis(100));

    let egress_receipts: Vec<_> = receipt
        .resources
        .iter()
        .filter(|r| r.kind == ResourceKind::Egress)
        .collect();
    assert_eq!(egress_receipts.len(), 1);

    let nat_receipts: Vec<_> = receipt
        .resources
        .iter()
        .filter(|r| r.kind == ResourceKind::Nat)
        .collect();
    assert_eq!(nat_receipts.len(), 1);
}

// ────────────────────────────────────────────────────────────────────
// Serialization roundtrips
// ────────────────────────────────────────────────────────────────────

#[test]
fn egress_policy_serde_roundtrip() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_16".into(),
        tenant_id: "tnt_16".into(),
        if_name: "cvx016".into(),
        allowed_cidrs: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
        policy_decision_id: "pdc_16".into(),
        lease_id: Some("lse_16".into()),
    };

    let rules = policy.compile_rules();
    let json = serde_json::to_string(&rules).unwrap();
    let parsed: Vec<NftRule> = serde_json::from_str(&json).unwrap();
    assert_eq!(rules, parsed);
}

#[test]
fn nat_config_serde_roundtrip() {
    let config = NatConfig {
        sandbox_id: "sbx_17".into(),
        tenant_id: "tnt_17".into(),
        if_name: "cvx017".into(),
        host_if_name: "eth0".into(),
        policy_decision_id: "pdc_17".into(),
    };

    let rules = config.compile_rules();
    let json = serde_json::to_string(&rules).unwrap();
    let parsed: Vec<NftRule> = serde_json::from_str(&json).unwrap();
    assert_eq!(rules, parsed);
}

#[test]
fn provision_receipt_with_egress_nat_serde_roundtrip() {
    let mut receipt = ProvisionReceipt::new(
        "sbx_17".into(),
        BackendClass::Container,
        11, // ns, veth, ns_move, guest_addr, host_addr, guest_up, host_up, route, egress, nat
    );

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_17".into(),
        resource_name: "cvx017".into(),
        kind: ResourceKind::Veth,
        created: true,
        provision_latency: Duration::from_millis(20),
    });

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_17".into(),
        resource_name: "pico-sbx-sbx_17-cvx017".into(),
        kind: ResourceKind::Egress,
        created: true,
        provision_latency: Duration::from_millis(5),
    });

    receipt.push(ResourceReceipt {
        sandbox_id: "sbx_17".into(),
        resource_name: "pico-sbx-sbx_17-cvx017".into(),
        kind: ResourceKind::Nat,
        created: true,
        provision_latency: Duration::from_millis(3),
    });

    receipt.finalize(Duration::from_millis(50));
    assert!(!receipt.completed); // 3 of 11

    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: ProvisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.total_attempted, parsed.total_attempted);
    assert_eq!(receipt.resources.len(), parsed.resources.len());
}

// ────────────────────────────────────────────────────────────────────
// Identity -- nftables naming tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn nft_sandbox_table_name_is_deterministic() {
    let name1 = NftClient::sandbox_table_name("sbx_18", "cvx018");
    let name2 = NftClient::sandbox_table_name("sbx_18", "cvx018");

    assert_eq!(name1, name2);
    assert!(name1.starts_with("pico-sbx-"));
    assert!(name1.contains("cvx018"));
}

#[test]
fn different_sandboxes_have_different_nft_tables() {
    let name1 = NftClient::sandbox_table_name("sbx_a", "cvx_a");
    let name2 = NftClient::sandbox_table_name("sbx_b", "cvx_b");
    assert_ne!(name1, name2);
}

#[test]
fn same_sandbox_different_if_produces_different_table() {
    let name1 = NftClient::sandbox_table_name("sbx_x", "cvx001");
    let name2 = NftClient::sandbox_table_name("sbx_x", "cvx002");
    assert_ne!(name1, name2);
}

// ────────────────────────────────────────────────────────────────────
// Internal networks protection tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn internal_networks_list_includes_rfc1918() {
    assert!(INTERNAL_NETWORKS.contains(&"10.0.0.0/8"));
    assert!(INTERNAL_NETWORKS.contains(&"172.16.0.0/12"));
    assert!(INTERNAL_NETWORKS.contains(&"192.168.0.0/16"));
}

#[test]
fn internal_networks_list_includes_cgnat_and_link_local() {
    assert!(INTERNAL_NETWORKS.contains(&"100.64.0.0/10"));
    assert!(INTERNAL_NETWORKS.contains(&"169.254.0.0/16"));
}

#[test]
fn internal_networks_list_includes_loopback() {
    assert!(INTERNAL_NETWORKS.contains(&"127.0.0.0/8"));
}

#[test]
fn internal_networks_list_includes_multicast() {
    assert!(INTERNAL_NETWORKS.contains(&"224.0.0.0/4"));
}

// ────────────────────────────────────────────────────────────────────
// Error variant display tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn egress_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::EgressDenied {
        sandbox_id: "sbx_err".into(),
        reason: "no lease".into(),
    };
    assert!(err.to_string().contains("sbx_err"));
    assert!(err.to_string().contains("no lease"));
}

#[test]
fn nat_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::NatSetupFailed {
        sandbox_id: "sbx_err".into(),
        detail: "nft command failed".into(),
    };
    assert!(err.to_string().contains("sbx_err"));
    assert!(err.to_string().contains("nft command failed"));
}

#[test]
fn nftables_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::Nftables {
        operation: "add_rule".into(),
        detail: "syntax error".into(),
    };
    assert!(err.to_string().contains("add_rule"));
    assert!(err.to_string().contains("syntax error"));
}

#[test]
fn egress_lease_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::EgressLeaseInvalid {
        lease_id: "lse_bad".into(),
    };
    assert!(err.to_string().contains("lse_bad"));
}

// ────────────────────────────────────────────────────────────────────
// CIDR validation tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn validate_cidr_accepts_standard_cidrs() {
    use pico_network_agent::egress::validate_cidr;

    assert!(validate_cidr("10.0.0.0/8").is_ok());
    assert!(validate_cidr("192.168.1.0/24").is_ok());
    assert!(validate_cidr("0.0.0.0/0").is_ok());
    assert!(validate_cidr("1.1.1.1/32").is_ok());
    assert!(validate_cidr("172.16.0.0/12").is_ok());
    assert!(validate_cidr("100.64.0.0/10").is_ok());
    assert!(validate_cidr("169.254.0.0/16").is_ok());
}

#[test]
fn validate_cidr_rejects_malformed() {
    use pico_network_agent::egress::validate_cidr;

    assert!(validate_cidr("not-a-cidr").is_err());
    assert!(validate_cidr("").is_err());
    assert!(validate_cidr("10.0.0.0").is_err());
    assert!(validate_cidr("/24").is_err());
    assert!(validate_cidr("10.0.0.0/").is_err());
    assert!(validate_cidr("10.0.0.0/33").is_err());
    assert!(validate_cidr("10.0.0.0/-1").is_err());
    assert!(validate_cidr("10.0.0.0/abc").is_err());
    assert!(validate_cidr("256.0.0.0/8").is_err());
    assert!(validate_cidr("10.0.0.0/8/extra").is_err());
}

#[test]
fn validate_cidrs_stops_at_first_error() {
    use pico_network_agent::egress::validate_cidrs;

    let cidrs = vec!["10.0.0.0/8".into(), "bad-cidr".into(), "0.0.0.0/0".into()];
    let result = validate_cidrs(&cidrs);
    assert!(result.is_err());
}

#[test]
fn validate_cidrs_empty_is_ok() {
    use pico_network_agent::egress::validate_cidrs;

    assert!(validate_cidrs(&[]).is_ok());
}

// ────────────────────────────────────────────────────────────────────
// Atomic ruleset generation tests
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn compile_ruleset_produces_valid_nft_structure() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_rs".into(),
        tenant_id: "tnt_rs".into(),
        if_name: "cvx999".into(),
        allowed_cidrs: vec!["1.1.1.1/32".into()],
        policy_decision_id: "pdc_rs".into(),
        lease_id: Some("lse_rs".into()),
    };

    let ruleset = policy.compile_ruleset();

    // Table declaration
    assert!(ruleset.starts_with("table inet"));
    assert!(ruleset.contains(&policy.table_name()));

    // Chain with hook and drop policy
    assert!(ruleset.contains("type filter hook forward priority 0; policy drop;"));

    // Conntrack
    assert!(ruleset.contains("ct state established,related accept"));

    // Interface binding on verdict rules
    assert!(ruleset.contains("iif cvx999"));

    // Accept rule for allowed CIDR
    assert!(ruleset.contains("1.1.1.1/32"));

    // Proper closure
    assert!(ruleset.ends_with("}\n"));
}

#[cfg(target_os = "linux")]
#[test]
fn compile_ruleset_no_cidrs_has_default_deny() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_rs2".into(),
        tenant_id: "tnt_rs2".into(),
        if_name: "cvx998".into(),
        allowed_cidrs: vec![],
        policy_decision_id: "pdc_rs2".into(),
        lease_id: None,
    };

    let ruleset = policy.compile_ruleset();

    // Must have a default drop rule for the sandbox interface
    assert!(ruleset.contains("iif cvx998 drop"));

    // Must NOT have any iif-bound accept rules (no egress CIDRs allowed)
    assert!(!ruleset.contains("iif cvx998 accept"));
}

#[cfg(target_os = "linux")]
#[test]
fn compile_ruleset_includes_all_internal_network_denies() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_rs3".into(),
        tenant_id: "tnt_rs3".into(),
        if_name: "cvx997".into(),
        allowed_cidrs: vec!["0.0.0.0/0".into()],
        policy_decision_id: "pdc_rs3".into(),
        lease_id: None,
    };

    let ruleset = policy.compile_ruleset();

    // All internal networks should be denied (since 0.0.0.0/0 is not
    // an exact match for any of them)
    for net in INTERNAL_NETWORKS {
        assert!(
            ruleset.contains(&format!("ip daddr {net} drop")),
            "ruleset must deny internal network {net}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn compile_ruleset_matches_compile_rules_output() {
    let policy = EgressPolicy {
        sandbox_id: "sbx_rs4".into(),
        tenant_id: "tnt_rs4".into(),
        if_name: "cvx996".into(),
        allowed_cidrs: vec!["10.0.0.0/8".into(), "8.8.8.8/32".into()],
        policy_decision_id: "pdc_rs4".into(),
        lease_id: Some("lse_rs4".into()),
    };

    let rules = policy.compile_rules();
    let ruleset = policy.compile_ruleset();

    // Every egress-allow rule expression should appear in the ruleset
    for rule in &rules {
        if rule.identity.rule_purpose == "egress-allow" {
            assert!(
                ruleset.contains(&rule.expression),
                "ruleset missing: {}",
                rule.expression
            );
        }
    }

    // Every internal-deny rule expression should appear in the ruleset
    for rule in &rules {
        if rule.identity.rule_purpose == "internal-deny" {
            assert!(
                ruleset.contains(&rule.expression),
                "ruleset missing: {}",
                rule.expression
            );
        }
    }
}

#[test]
fn invalid_cidr_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::InvalidCidr {
        cidr: "bad/99".into(),
    };
    assert!(err.to_string().contains("bad/99"));
}

// ────────────────────────────────────────────────────────────────────
// Bandwidth shaping tests
// ────────────────────────────────────────────────────────────────────

#[test]
fn bandwidth_limit_validation_accepts_valid() {
    assert!(validate_bandwidth_limit(0).is_ok());
    assert!(validate_bandwidth_limit(1_000_000).is_ok());
    assert!(validate_bandwidth_limit(10_000_000_000).is_ok());
}

#[test]
fn bandwidth_limit_validation_rejects_oversized() {
    assert!(validate_bandwidth_limit(10_000_000_001).is_err());
    assert!(validate_bandwidth_limit(u64::MAX).is_err());
}

#[test]
fn bandwidth_format_rate_various_units() {
    assert_eq!(format_rate(500), "500bps");
    assert_eq!(format_rate(64_000), "64kbps");
    assert_eq!(format_rate(10_000_000), "10mbps");
    assert_eq!(format_rate(1_500_000), "1.5mbps");
}

#[test]
fn bandwidth_limit_zero_is_unlimited_noop() {
    let limit = BandwidthLimit {
        sandbox_id: "sbx_bw".into(),
        tenant_id: None,
        if_name: "cvx_bw".into(),
        limit_bps: 0,
        burst_kb: None,
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(pico_network_agent::bandwidth::provision_bandwidth(&limit));
    assert!(result.is_ok());
    let receipts = result.unwrap();
    assert!(receipts.is_empty(), "zero limit must produce no receipts");
}

#[test]
fn bandwidth_limit_serde_roundtrip() {
    let limit = BandwidthLimit {
        sandbox_id: "sbx_bw_serde".into(),
        tenant_id: None,
        if_name: "cvx_serde".into(),
        limit_bps: 100_000_000, // 100 Mbps
        burst_kb: None,
    };

    let json = serde_json::to_string(&limit).unwrap();
    let parsed: BandwidthLimit = serde_json::from_str(&json).unwrap();
    assert_eq!(limit.sandbox_id, parsed.sandbox_id);
    assert_eq!(limit.tenant_id, parsed.tenant_id);
    assert_eq!(limit.if_name, parsed.if_name);
    assert_eq!(limit.limit_bps, parsed.limit_bps);
    assert_eq!(limit.burst_kb, parsed.burst_kb);
}

#[test]
fn bandwidth_limit_preserves_tenant_for_metric_attribution() {
    // `tenant_id` is what the redaction policy swaps in for `sandbox_id` on the
    // `network.bandwidth.limit_configured` gauge, so it has to survive a
    // round-trip through the control plane.
    let limit = BandwidthLimit {
        sandbox_id: "sbx_bw_tenant".into(),
        tenant_id: Some("tnt_bw".into()),
        if_name: "cvx_tenant".into(),
        limit_bps: 1_000_000,
        burst_kb: None,
    };

    let json = serde_json::to_string(&limit).unwrap();
    let parsed: BandwidthLimit = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.tenant_id.as_deref(), Some("tnt_bw"));
}

#[test]
fn bandwidth_limit_serde_with_custom_burst() {
    let limit = BandwidthLimit {
        sandbox_id: "sbx_bw_serde2".into(),
        tenant_id: None,
        if_name: "cvx_serde2".into(),
        limit_bps: 10_000_000,
        burst_kb: Some(64),
    };

    let json = serde_json::to_string(&limit).unwrap();
    let parsed: BandwidthLimit = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.burst_kb, Some(64));
}

#[test]
fn bandwidth_deprovision_is_idempotent() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // Deprovision of a non-existent interface should succeed
    let result = runtime.block_on(pico_network_agent::bandwidth::deprovision_bandwidth(
        "sbx_bw_idem",
        "nonexistent_if",
    ));
    assert!(result.is_ok());
}

#[test]
fn bandwidth_update_to_zero_removes_shaping() {
    let limit = BandwidthLimit {
        sandbox_id: "sbx_bw_update".into(),
        tenant_id: None,
        if_name: "cvx_update".into(),
        limit_bps: 0,
        burst_kb: None,
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(pico_network_agent::bandwidth::update_bandwidth(&limit));
    assert!(result.is_ok(), "updating to zero should not fail");
}

#[test]
fn bandwidth_error_displays_correctly() {
    use pico_network_agent::error::NetworkAgentError;

    let err = NetworkAgentError::BandwidthLimitInvalid {
        sandbox_id: "sbx_err".into(),
        limit_bps: 99_000_000_000,
        reason: "exceeds maximum".into(),
    };
    assert!(err.to_string().contains("sbx_err"));
    assert!(err.to_string().contains("exceeds maximum"));

    let err = NetworkAgentError::BandwidthSetupFailed {
        sandbox_id: "sbx_err2".into(),
        detail: "tc command failed".into(),
    };
    assert!(err.to_string().contains("sbx_err2"));

    let err = NetworkAgentError::BandwidthTcExec {
        operation: "qdisc add".into(),
        detail: "RTNETLINK".into(),
    };
    assert!(err.to_string().contains("qdisc add"));
    assert!(err.to_string().contains("RTNETLINK"));

    let err = NetworkAgentError::BandwidthCleanupFailed {
        sandbox_id: "sbx_err3".into(),
        detail: "interface not found".into(),
    };
    assert!(err.to_string().contains("sbx_err3"));
}
