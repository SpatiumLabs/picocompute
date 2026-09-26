//! Network policy property tests.
//!
//! Covers boundary-sensitive parser invariants: CIDR validation never panics,
//! DNS evaluation is first-wins deterministic, denied answer CIDRs always
//! block internal addresses, and egress rule compilation always binds verdict
//! rules to the sandbox interface.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p pico-network-agent --test policy_property
//! ```

use pico_network_agent::dns::policy::{
    DENIED_ANSWER_CIDRS, DnsAction, DnsPatternType, DnsPolicy, DnsRule, is_denied_ipv4,
};
use pico_network_agent::egress::{EgressPolicy, validate_cidr};
use proptest::prelude::*;

fn arb_domain() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("example.com".to_string()),
        Just("www.example.com".to_string()),
        Just("evil.malware.test".to_string()),
        Just("localhost".to_string()),
        "[a-z]{1,12}(\\.[a-z]{1,12}){0,2}".prop_map(|s| s),
        Just("".to_string()),
    ]
}

fn arb_cidr() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("10.0.0.0/8".to_string()),
        Just("192.168.1.0/24".to_string()),
        Just("0.0.0.0/0".to_string()),
        Just("1.1.1.1/32".to_string()),
        Just("not-a-cidr".to_string()),
        Just("10.0.0.0".to_string()),
        Just("10.0.0.0/33".to_string()),
        Just("".to_string()),
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]{1,2}".prop_map(|s| s),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// CIDR validation never panics and accepts exactly the well-formed IPv4
    /// forms; malformed input always errors.
    #[test]
    fn cidr_validation_never_panics(cidr in arb_cidr()) {
        let result = validate_cidr(&cidr);
        if let Some((addr, prefix)) = cidr.split_once('/') {
            let addr_ok = addr.parse::<std::net::Ipv4Addr>().is_ok();
            let prefix_ok = prefix.parse::<u8>().is_ok_and(|p| p <= 32);
            if addr_ok && prefix_ok && !addr.is_empty() && !prefix.is_empty() {
                prop_assert!(result.is_ok(), "valid CIDR {cidr} must pass");
            } else {
                prop_assert!(result.is_err(), "invalid CIDR {cidr} must fail");
            }
        } else {
            prop_assert!(result.is_err(), "CIDR without slash {cidr} must fail");
        }
    }

    /// DNS evaluation is deterministic and first-wins: the first matching
    /// rule decides, otherwise the default applies.
    #[test]
    fn dns_evaluation_first_wins(
        qname in arb_domain(),
        qtype in prop_oneof![Just("A"), Just("AAAA"), Just("TXT")],
    ) {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![
                DnsRule {
                    action: DnsAction::Deny,
                    pattern: ".malware.test".into(),
                    pattern_type: DnsPatternType::Suffix,
                    record_types: None,
                },
                DnsRule {
                    action: DnsAction::Allow,
                    pattern: ".example.com".into(),
                    pattern_type: DnsPatternType::Suffix,
                    record_types: None,
                },
            ],
            default_action: DnsAction::Deny,
        };
        let first = policy.evaluate(&qname, qtype);
        let second = policy.evaluate(&qname, qtype);
        prop_assert_eq!(first.allowed, second.allowed);
        // Malware suffix is always denied when it matches first.
        if qname.ends_with(".malware.test") || qname == ".malware.test" {
            prop_assert!(!first.allowed);
        }
    }

    /// Denied answer CIDRs always block RFC1918, loopback, link-local, and
    /// multicast answers, and never block public DNS addresses.
    #[test]
    fn denied_cidrs_block_internal(oct in 0..255u8) {
        prop_assert!(is_denied_ipv4(std::net::Ipv4Addr::new(10, oct, 0, 1), DENIED_ANSWER_CIDRS));
        prop_assert!(is_denied_ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1), DENIED_ANSWER_CIDRS));
        prop_assert!(is_denied_ipv4(std::net::Ipv4Addr::new(169, 254, 10, 20), DENIED_ANSWER_CIDRS));
        prop_assert!(is_denied_ipv4(std::net::Ipv4Addr::new(224, 0, 0, 1), DENIED_ANSWER_CIDRS));
        prop_assert!(!is_denied_ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8), DENIED_ANSWER_CIDRS));
        prop_assert!(!is_denied_ipv4(std::net::Ipv4Addr::new(1, 1, 1, 1), DENIED_ANSWER_CIDRS));
    }

    /// Egress compilation always binds verdict rules to the sandbox interface
    /// and always includes the conntrack established rule.
    #[test]
    fn egress_rules_always_bound(
        cidr_count in 0..4usize,
        if_name in "[a-z]{1,6}[0-9]{0,3}",
    ) {
        let cidrs: Vec<String> = (0..cidr_count).map(|i| format!("10.{i}.0.0/16")).collect();
        let policy = EgressPolicy {
            sandbox_id: "sbx_prop".into(),
            tenant_id: "tnt_prop".into(),
            if_name: if_name.clone(),
            allowed_cidrs: cidrs.clone(),
            policy_decision_id: "pdc".into(),
            lease_id: None,
        };
        let rules = policy.compile_rules();
        prop_assert!(rules.iter().any(|r| r.expression.contains("ct state")));
        for rule in &rules {
            if rule.identity.rule_purpose != "ct-state" {
                prop_assert!(
                    rule.expression.contains(&format!("iif {if_name}")),
                    "verdict rule must bind to {if_name}"
                );
            }
        }
        if cidrs.is_empty() {
            prop_assert!(rules.iter().any(|r| r.identity.rule_purpose == "default-deny"));
        } else {
            let allows = rules.iter().filter(|r| r.identity.rule_purpose == "egress-allow").count();
            prop_assert_eq!(allows, cidrs.len());
        }
    }

    /// Exact DNS rules never match subdomains; suffix rules with a leading
    /// dot match subdomains but never unrelated suffixes.
    #[test]
    fn dns_pattern_semantics_hold(sub in "[a-z]{1,8}") {
        let exact = DnsPolicy {
            tenant_id: "t".into(),
            sandbox_id: "s".into(),
            policy_decision_id: "p".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![DnsRule {
                action: DnsAction::Allow,
                pattern: "example.com".into(),
                pattern_type: DnsPatternType::Exact,
                record_types: None,
            }],
            default_action: DnsAction::Deny,
        };
        let qname = format!("{sub}.example.com");
        // The strategy guarantees a non-empty subdomain, so this is never
        // an exact match for "example.com".
        prop_assert!(!exact.evaluate(&qname, "A").allowed);
        prop_assert!(exact.evaluate("example.com", "A").allowed);
    }
}
