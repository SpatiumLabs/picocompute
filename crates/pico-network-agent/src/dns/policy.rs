//! DNS policy types: rules, evaluation, and deny-by-default behaviour.
//!
//! Every sandbox DNS query is evaluated against an ordered list of
//! allow/deny rules keyed by domain, suffix, and optional record type.
//! Matches are first-wins. Unmatched queries fall through to a
//! per-policy default action (default deny for production).

use hashbrown::HashSet;

/// Whether a DNS rule allows or denies matching queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAction {
    Allow,
    Deny,
}

/// Type of domain pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPatternType {
    /// Match the query name exactly (e.g. `example.com` matches only `example.com`).
    Exact,
    /// Match the query name as a suffix (e.g. `.example.com` matches `www.example.com`).
    Suffix,
}

/// A single DNS rule ordering a per-domain action.
#[derive(Debug, Clone)]
pub struct DnsRule {
    pub action: DnsAction,
    pub pattern: String,
    pub pattern_type: DnsPatternType,
    /// Specific record types this rule applies to. `None` means all types.
    pub record_types: Option<HashSet<String>>,
}

/// Per-tenant DNS policy applied to one or more sandboxes.
///
/// Rules are evaluated in order; the first matching rule determines the
/// decision. If no rule matches, `default_action` applies.
#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub tenant_id: String,
    pub sandbox_id: String,
    pub policy_decision_id: String,
    pub policy_epoch: u64,
    pub workload_class: Option<String>,
    pub rules: Vec<DnsRule>,
    pub default_action: DnsAction,
}

impl DnsPolicy {
    /// Evaluate whether a DNS query is allowed under this policy.
    ///
    /// Rules are evaluated first-to-last. The first rule whose pattern
    /// and (optional) record types match determines the decision.
    /// If no rule matches, the default action applies.
    #[must_use]
    pub fn evaluate(&self, qname: &str, qtype: &str) -> DnsDecision {
        for rule in &self.rules {
            let domain_matches = match rule.pattern_type {
                DnsPatternType::Exact => qname == rule.pattern.as_str(),
                DnsPatternType::Suffix => {
                    if !qname.ends_with(&rule.pattern) {
                        false
                    } else if rule.pattern.starts_with('.') || qname.len() == rule.pattern.len() {
                        true
                    } else {
                        let prefix_len = qname.len() - rule.pattern.len();
                        prefix_len > 0 && qname.as_bytes()[prefix_len - 1] == b'.'
                    }
                }
            };
            if !domain_matches {
                continue;
            }
            if let Some(ref types) = rule.record_types
                && !types.contains(qtype)
            {
                continue;
            }
            let allowed = matches!(rule.action, DnsAction::Allow);
            return DnsDecision {
                allowed,
                reason: format!("{:?} rule matched: {}", rule.action, rule.pattern),
                matched_rule: Some(rule.pattern.clone()),
            };
        }
        let allowed = matches!(self.default_action, DnsAction::Allow);
        DnsDecision {
            allowed,
            reason: "default action".into(),
            matched_rule: None,
        }
    }
}

/// Result of a DNS policy evaluation.
#[derive(Debug, Clone)]
pub struct DnsDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
}

/// Configuration for the DNS proxy.
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Socket address the proxy listens on (UDP + TCP).
    pub listen_addr: std::net::SocketAddr,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53)),
                53,
            ),
        }
    }
}

/// Domains that PicoCompute denies by default regardless of tenant policy.
pub const DEFAULT_DENY_SUFFIXES: &[&str] = &[
    ".internal",
    ".local",
    "localhost",
    ".localhost",
    ".metadata.google.internal",
    "metadata.google.internal",
];

/// Check whether a resolved IPv4 address falls inside a denied CIDR range.
pub fn is_denied_ipv4(ip: std::net::Ipv4Addr, denied_cidrs: &[(&str, u8)]) -> bool {
    let ip_u32 = u32::from(ip);
    for &(net_str, prefix_len) in denied_cidrs {
        let Ok(net) = net_str.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let net_u32 = u32::from(net);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0)
        };
        if ip_u32 & mask == net_u32 & mask {
            return true;
        }
    }
    false
}

/// IPv4 CIDRs that resolved answers must never contain.
///
/// These mirror `INTERNAL_NETWORKS` from `crate::identity` and add
/// additional platform protection. Format: (network_addr, prefix_len).
pub const DENIED_ANSWER_CIDRS: &[(&str, u8)] = &[
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("100.64.0.0", 10),
    ("169.254.0.0", 16),
    ("127.0.0.0", 8),
    ("224.0.0.0", 4),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy_allow_all() -> DnsPolicy {
        DnsPolicy {
            tenant_id: "tnt_test".into(),
            sandbox_id: "sbx_test".into(),
            policy_decision_id: "pdc_test".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![DnsRule {
                action: DnsAction::Allow,
                pattern: ".example.com".into(),
                pattern_type: DnsPatternType::Suffix,
                record_types: None,
            }],
            default_action: DnsAction::Deny,
        }
    }

    fn test_policy_deny_suffix() -> DnsPolicy {
        DnsPolicy {
            tenant_id: "tnt_test".into(),
            sandbox_id: "sbx_test".into(),
            policy_decision_id: "pdc_test".into(),
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
        }
    }

    #[test]
    fn exact_rules_match() {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![DnsRule {
                action: DnsAction::Allow,
                pattern: "api.example.com".into(),
                pattern_type: DnsPatternType::Exact,
                record_types: None,
            }],
            default_action: DnsAction::Deny,
        };
        let d = policy.evaluate("api.example.com", "A");
        assert!(d.allowed);
        assert!(d.matched_rule.is_some());
    }

    #[test]
    fn exact_rules_reject_subdomain() {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
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
        let d = policy.evaluate("www.example.com", "A");
        assert!(!d.allowed);
        assert!(d.matched_rule.is_none());
    }

    #[test]
    fn suffix_rules_match_subdomain() {
        let d = test_policy_allow_all().evaluate("www.example.com", "A");
        assert!(d.allowed);
    }

    #[test]
    fn suffix_rules_match_exact() {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![DnsRule {
                action: DnsAction::Allow,
                pattern: "example.com".into(),
                pattern_type: DnsPatternType::Suffix,
                record_types: None,
            }],
            default_action: DnsAction::Deny,
        };
        let d = policy.evaluate("example.com", "A");
        assert!(d.allowed);
        let d2 = policy.evaluate("www.example.com", "A");
        assert!(d2.allowed);
    }

    #[test]
    fn unmatched_queries_fall_through_to_default() {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![],
            default_action: DnsAction::Deny,
        };
        let d = policy.evaluate("anything.test", "A");
        assert!(!d.allowed);
        assert_eq!(d.reason, "default action");
    }

    #[test]
    fn deny_rules_take_precedence_when_first() {
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![
                DnsRule {
                    action: DnsAction::Deny,
                    pattern: ".example.com".into(),
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
        let d = policy.evaluate("www.example.com", "A");
        assert!(!d.allowed);
    }

    #[test]
    fn record_type_filter_is_honoured() {
        let mut a_only = HashSet::new();
        a_only.insert("A".into());
        let policy = DnsPolicy {
            tenant_id: "tnt".into(),
            sandbox_id: "sbx".into(),
            policy_decision_id: "pdc".into(),
            policy_epoch: 1,
            workload_class: None,
            rules: vec![DnsRule {
                action: DnsAction::Allow,
                pattern: ".example.com".into(),
                pattern_type: DnsPatternType::Suffix,
                record_types: Some(a_only),
            }],
            default_action: DnsAction::Deny,
        };
        assert!(policy.evaluate("www.example.com", "A").allowed);
        assert!(!policy.evaluate("www.example.com", "AAAA").allowed);
    }

    #[test]
    fn deny_order_works() {
        let d = test_policy_deny_suffix().evaluate("evil.malware.test", "A");
        assert!(!d.allowed);
        assert!(d.matched_rule.unwrap().contains("malware"));
    }

    #[test]
    fn allow_after_deny_works() {
        let d = test_policy_deny_suffix().evaluate("safe.example.com", "A");
        assert!(d.allowed);
    }

    #[test]
    fn is_denied_ipv4_blocks_internal() {
        assert!(is_denied_ipv4(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            DENIED_ANSWER_CIDRS
        ));
        assert!(is_denied_ipv4(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            DENIED_ANSWER_CIDRS
        ));
        assert!(is_denied_ipv4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            DENIED_ANSWER_CIDRS
        ));
    }

    #[test]
    fn public_ip_not_denied() {
        assert!(!is_denied_ipv4(
            std::net::Ipv4Addr::new(8, 8, 8, 8),
            DENIED_ANSWER_CIDRS
        ));
        assert!(!is_denied_ipv4(
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            DENIED_ANSWER_CIDRS
        ));
    }
}
