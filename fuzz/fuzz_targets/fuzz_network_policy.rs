//! Fuzz target for network policy parsers.
//!
//! Exercises CIDR validation, DNS policy evaluation, denied-answer checks,
//! and egress rule compilation over arbitrary bytes. Must never panic and
//! must keep verdict rules bound to the sandbox interface.

#![no_main]

use pico_network_agent::dns::policy::{
    DENIED_ANSWER_CIDRS, DnsAction, DnsPatternType, DnsPolicy, DnsRule, is_denied_ipv4,
};
use pico_network_agent::egress::{EgressPolicy, validate_cidr, validate_cidrs};
use libfuzzer_sys::fuzz_target;

fn fuzz_one(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // CIDR parser over the whole input and over line splits.
    let _ = validate_cidr(text);
    let parts: Vec<String> = text.split_whitespace().take(8).map(str::to_string).collect();
    let _ = validate_cidrs(&parts);
    // DNS evaluation with fuzz-derived names.
    let qname: String = text.chars().take(64).collect();
    let policy = DnsPolicy {
        tenant_id: "tnt_fuzz".into(),
        sandbox_id: "sbx_fuzz".into(),
        policy_decision_id: "pdc_fuzz".into(),
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
    let _ = policy.evaluate(&qname, "A");
    let _ = policy.evaluate(&qname, "AAAA");
    // IPv4 deny check over fuzz-derived octets.
    let bytes = data.first().copied().unwrap_or(0);
    let ip = std::net::Ipv4Addr::new(10, bytes, 0, 1);
    let _ = is_denied_ipv4(ip, DENIED_ANSWER_CIDRS);
    // Egress compilation with fuzz-derived CIDRs and interface.
    let egress = EgressPolicy {
        sandbox_id: "sbx_fuzz".into(),
        tenant_id: "tnt_fuzz".into(),
        if_name: format!("fuzz{}", bytes % 10),
        allowed_cidrs: parts,
        policy_decision_id: "pdc_fuzz".into(),
        lease_id: None,
    };
    let rules = egress.compile_rules();
    for rule in &rules {
        if rule.identity.rule_purpose != "ct-state" {
            assert!(rule.expression.contains("iif "));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});
