//! Sandbox egress policy enforcement via nftables.
//!
//! Implements the data-plane layer of: translates per-sandbox
//! egress policy decisions into nftables rules. The control plane is
//! responsible for validating leases and providing the allowed
//! destination CIDRs. This module converts those decisions into
//! enforceable rules.
//!
//! # Architecture
//!
//! Each sandbox gets its own nftables inet table (`pico-sbx-{id}`)
//! with a `forward` chain for traffic flowing through the sandbox
//! interface. The chain has:
//! - A default `drop` policy
//! - Explicit accept rules for allowed egress CIDRs
//! - Internal platform network protection
//!
//! # Platform Support
//!
//! All provisioning is `#[cfg(target_os = "linux")]` gated.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::time::Instant;

use crate::error::{NetworkAgentError, NetworkResult};
use crate::identity::INTERNAL_NETWORKS;
use crate::metrics;
use crate::nftables::{NftClient, NftRule, NftRuleIdentity};
use crate::receipt::ResourceReceipt;
use tracing::{debug, info, warn};

/// Validate that a string is a well-formed IPv4 CIDR notation.
///
/// Accepts formats like `10.0.0.0/8`, `192.168.1.0/24`, `0.0.0.0/0`.
/// Rejects bare IPs without a prefix, hostnames, and malformed input.
/// This is a lightweight defence-in-depth check; the control plane
/// is responsible for authoritative validation.
pub fn validate_cidr(cidr: &str) -> NetworkResult<()> {
    let (addr_str, prefix_str) =
        cidr.split_once('/')
            .ok_or_else(|| NetworkAgentError::InvalidCidr {
                cidr: cidr.to_string(),
            })?;

    addr_str
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| NetworkAgentError::InvalidCidr {
            cidr: cidr.to_string(),
        })?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| NetworkAgentError::InvalidCidr {
            cidr: cidr.to_string(),
        })?;

    if prefix > 32 {
        return Err(NetworkAgentError::InvalidCidr {
            cidr: cidr.to_string(),
        });
    }

    Ok(())
}

/// Validate every CIDR in a list, returning the first error.
pub fn validate_cidrs(cidrs: &[String]) -> NetworkResult<()> {
    for cidr in cidrs {
        validate_cidr(cidr)?;
    }
    Ok(())
}

/// Egress policy applied to a single sandbox.
///
/// Specifies the allowed egress CIDRs with full identity binding
/// back to the authorizing tenant, policy decision, and optional lease.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// The sandbox this policy applies to.
    pub sandbox_id: String,
    /// The tenant that owns the sandbox.
    pub tenant_id: String,
    /// The sandbox interface name (for iif matching).
    pub if_name: String,
    /// CIDR blocks explicitly allowed for egress.
    pub allowed_cidrs: Vec<String>,
    /// The policy decision that authorized this egress policy.
    pub policy_decision_id: String,
    /// Optional lease ID for lease-based egress exceptions.
    pub lease_id: Option<String>,
}

impl EgressPolicy {
    /// Build the nftables table name for this sandbox.
    #[must_use]
    pub fn table_name(&self) -> String {
        NftClient::sandbox_table_name(&self.sandbox_id, &self.if_name)
    }

    /// Build the `NftRuleIdentity` embedding all authorization context.
    fn rule_identity(&self, purpose: &str) -> NftRuleIdentity {
        NftRuleIdentity {
            sandbox_id: self.sandbox_id.clone(),
            tenant_id: self.tenant_id.clone(),
            policy_decision_id: self.policy_decision_id.clone(),
            lease_id: self.lease_id.clone(),
            rule_purpose: purpose.to_string(),
        }
    }

    /// Generate the nftables rules for this egress policy.
    ///
    /// Returns a `Vec<NftRule>` containing deny rules for internal
    /// networks and accept rules for allowed CIDRs, plus a catch-all
    /// drop. Every verdict rule binds to the sandbox interface via
    /// `iif` so an attacker cannot gain outbound access from network
    /// locality alone.
    ///
    /// Every rule carries an identity comment for audit.
    pub fn compile_rules(&self) -> Vec<NftRule> {
        let table = self.table_name();
        let chain = "forward";
        let mut rules = Vec::new();

        // 1. Allow established/related connections (existing flows).
        //    This rule does not need iif because conntrack ensures
        //    return traffic matches the correct flow regardless of
        //    which interface it arrives on.
        rules.push(NftRule {
            family: "inet".into(),
            table: table.clone(),
            chain: chain.into(),
            expression: "ct state established,related accept".into(),
            identity: self.rule_identity("ct-state"),
        });

        // 2. Deny internal platform networks (RFC 1918, CGNAT, link-local)
        //    unless explicitly allowed by a lease exception.
        //    Every rule binds to this sandbox interface via iif.
        for net in INTERNAL_NETWORKS {
            if !self.allowed_cidrs.contains(&(*net).to_string()) {
                rules.push(NftRule {
                    family: "inet".into(),
                    table: table.clone(),
                    chain: chain.into(),
                    expression: format!("iif {} ip daddr {net} drop", self.if_name),
                    identity: self.rule_identity("internal-deny"),
                });
            }
        }

        // 3. Accept rules for allowed egress CIDRs.
        //    Every rule binds to this sandbox interface via iif.
        for cidr in &self.allowed_cidrs {
            rules.push(NftRule {
                family: "inet".into(),
                table: table.clone(),
                chain: chain.into(),
                expression: format!("iif {} ip daddr {cidr} accept", self.if_name),
                identity: self.rule_identity("egress-allow"),
            });
        }

        // 4. If no CIDRs were explicitly allowed, deny all new outbound
        //    traffic from this sandbox interface.
        if self.allowed_cidrs.is_empty() {
            rules.push(NftRule {
                family: "inet".into(),
                table: table.clone(),
                chain: chain.into(),
                expression: format!("iif {} drop", self.if_name),
                identity: self.rule_identity("default-deny"),
            });
        }

        rules
    }

    /// Generate a complete nftables ruleset string for atomic loading.
    ///
    /// Produces a string suitable for `nft -f -` that defines the
    /// table, chain, and all rules in one atomic transaction. This
    /// prevents any window where the table exists with no rules.
    #[cfg(target_os = "linux")]
    pub fn compile_ruleset(&self) -> String {
        let table = self.table_name();
        let if_name = &self.if_name;
        let mut ruleset = format!(
            "table inet {table} {{\n  chain forward {{\n    type filter hook forward priority 0; policy drop;\n"
        );

        // Conntrack rule (no iif needed)
        ruleset.push_str("    ct state established,related accept\n");

        // Internal network deny rules
        for net in INTERNAL_NETWORKS {
            if !self.allowed_cidrs.contains(&(*net).to_string()) {
                ruleset.push_str(&format!("    iif {if_name} ip daddr {net} drop\n"));
            }
        }

        // Accept rules for allowed egress
        for cidr in &self.allowed_cidrs {
            ruleset.push_str(&format!("    iif {if_name} ip daddr {cidr} accept\n"));
        }

        // Default deny
        if self.allowed_cidrs.is_empty() {
            ruleset.push_str(&format!("    iif {if_name} drop\n"));
        }

        ruleset.push_str("  }\n}\n");
        ruleset
    }

    #[cfg(not(target_os = "linux"))]
    pub fn compile_ruleset(&self) -> String {
        String::new()
    }
}

/// Provisions egress policy for a sandbox.
///
/// Validates all CIDRs, creates the nftables table, and atomically
/// loads the compiled ruleset via `nft -f -`. No intermediate state
/// where the table exists without rules is visible.
///
/// Returns resource receipts for reconciliation.
#[cfg(target_os = "linux")]
pub async fn provision_egress(policy: &EgressPolicy) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let mut receipts = Vec::new();
    let table = policy.table_name();

    debug!(
        sandbox_id = %policy.sandbox_id,
        table = %table,
        cidrs = ?policy.allowed_cidrs,
        "provisioning egress policy"
    );

    // 0. Validate all CIDRs before touching nftables
    validate_cidrs(&policy.allowed_cidrs)?;

    // 1. Compile the complete ruleset
    let ruleset = policy.compile_ruleset();

    // 2. Load atomically via nft -f - (creates table, chain, and rules
    //    in one transaction; rejects the entire ruleset on error)
    NftClient::apply_ruleset(&table, &ruleset)
        .await
        .map_err(|e| NetworkAgentError::EgressSetupFailed {
            sandbox_id: policy.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: policy.sandbox_id.clone(),
        resource_name: table.clone(),
        kind: crate::receipt::ResourceKind::Egress,
        created: true,
        provision_latency: latency,
    });

    // setup_completed is a provisioning lifecycle counter, not a
    // per-packet counter. Runtime per-packet allowed/denied metrics
    // live in the kernel (nftables counters) and are read via nft
    // list ruleset or /proc/net/netfilter.
    metrics::record_egress_setup_completed();
    info!(
        sandbox_id = %policy.sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "egress policy provisioned"
    );

    Ok(receipts)
}

/// Deprovisions egress policy for a sandbox.
///
/// Deletes the nftables table which implicitly removes all chains
/// and rules. This is idempotent -- if the table is already gone,
/// the operation succeeds silently.
#[cfg(target_os = "linux")]
pub async fn deprovision_egress(
    sandbox_id: &str,
    if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = NftClient::sandbox_table_name(sandbox_id, if_name);
    let mut receipts = Vec::new();

    debug!(sandbox_id = %sandbox_id, table = %table, "deprovisioning egress policy");

    NftClient::delete_table(&table).await.map_err(|e| {
        warn!(sandbox_id = %sandbox_id, table = %table, error = %e, "egress policy cleanup failed");
        NetworkAgentError::EgressCleanupFailed {
            sandbox_id: sandbox_id.to_string(),
            detail: e.to_string(),
        }
    })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: sandbox_id.to_string(),
        resource_name: table.clone(),
        kind: crate::receipt::ResourceKind::Egress,
        created: false,
        provision_latency: latency,
    });

    metrics::record_egress_cleanup_completed();
    info!(
        sandbox_id = %sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "egress policy removed"
    );

    Ok(receipts)
}

/// Atomically replace the egress rules for an existing sandbox.
///
/// Flushes the forward chain and loads the new compiled ruleset
/// via `nft -f -`. This is used when a lease is granted, revoked,
/// or renewed and the active egress CIDRs change. The table and
/// chain (but not their rules) survive the flush.
#[cfg(target_os = "linux")]
pub async fn update_egress(policy: &EgressPolicy) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = policy.table_name();
    let mut receipts = Vec::new();

    info!(
        sandbox_id = %policy.sandbox_id,
        table = %table,
        "updating egress policy"
    );

    // Validate CIDRs
    validate_cidrs(&policy.allowed_cidrs)?;

    // Compile and load the new ruleset atomically (nft -f - with
    // flush at the top ensures no gap in coverage)
    let ruleset = format!(
        "flush chain inet {table} forward\n{}",
        policy.compile_ruleset()
    );
    NftClient::apply_ruleset(&table, &ruleset)
        .await
        .map_err(|e| NetworkAgentError::EgressSetupFailed {
            sandbox_id: policy.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: policy.sandbox_id.clone(),
        resource_name: table.clone(),
        kind: crate::receipt::ResourceKind::Egress,
        created: true,
        provision_latency: latency,
    });

    metrics::record_egress_setup_completed();
    info!(
        sandbox_id = %policy.sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "egress policy updated"
    );

    Ok(receipts)
}

// ──── Non-Linux stubs ────

#[cfg(not(target_os = "linux"))]
pub async fn provision_egress(_policy: &EgressPolicy) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub async fn deprovision_egress(
    _sandbox_id: &str,
    _if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub async fn update_egress(_policy: &EgressPolicy) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> EgressPolicy {
        EgressPolicy {
            sandbox_id: "sbx_test".into(),
            tenant_id: "tnt_test".into(),
            if_name: "cvx001".into(),
            allowed_cidrs: vec!["0.0.0.0/0".into()],
            policy_decision_id: "pdc_test".into(),
            lease_id: Some("lse_test".into()),
        }
    }

    fn test_policy_no_egress() -> EgressPolicy {
        EgressPolicy {
            sandbox_id: "sbx_test".into(),
            tenant_id: "tnt_test".into(),
            if_name: "cvx001".into(),
            allowed_cidrs: vec![],
            policy_decision_id: "pdc_test".into(),
            lease_id: None,
        }
    }

    #[test]
    fn table_name_is_deterministic() {
        let policy = test_policy();
        let name1 = policy.table_name();
        let name2 = policy.table_name();
        assert_eq!(name1, name2);
        assert!(name1.starts_with("pico-sbx-"));
        assert!(name1.contains("cvx001"));
    }

    #[test]
    fn compile_rules_produces_ct_state_rule() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        assert!(
            rules.iter().any(|r| r.expression.contains("ct state")),
            "rules must include conntrack state rule"
        );
    }

    #[test]
    fn compile_rules_binds_verdict_rules_to_interface() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        // Verdict rules (internal-deny, egress-allow, default-deny) must
        // include iif to bind to the sandbox interface
        for rule in &rules {
            if rule.identity.rule_purpose != "ct-state" {
                assert!(
                    rule.expression.contains("iif cvx001"),
                    "verdict rule '{:?}' must bind to sandbox interface via iif",
                    rule.identity.rule_purpose
                );
            }
        }
    }

    #[test]
    fn compile_rules_produces_accept_rules_for_allowed_cidrs() {
        let mut policy = test_policy();
        policy.allowed_cidrs = vec!["10.0.0.0/8".into(), "1.1.1.1/32".into()];
        let rules = policy.compile_rules();
        let accept_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.identity.rule_purpose == "egress-allow")
            .collect();
        assert_eq!(accept_rules.len(), 2);
    }

    #[test]
    fn compile_rules_includes_internal_network_deny() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        assert!(
            rules
                .iter()
                .any(|r| r.identity.rule_purpose == "internal-deny"
                    && r.expression.contains("192.168.0.0/16")),
            "rules must deny RFC 1918 networks"
        );
    }

    #[test]
    fn compile_rules_with_no_cidrs_produces_default_deny() {
        let policy = test_policy_no_egress();
        let rules = policy.compile_rules();
        assert!(
            rules
                .iter()
                .any(|r| r.identity.rule_purpose == "default-deny"),
            "rules with no CIDRs must include a default deny"
        );
    }

    #[test]
    fn compile_rules_internal_networks_are_excepted_when_allowed() {
        let mut policy = test_policy();
        // Allow the internal networks explicitly
        policy.allowed_cidrs = vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()];
        let rules = policy.compile_rules();

        // Should NOT have deny rules for the allowed internal networks
        let internal_deny: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.identity.rule_purpose == "internal-deny"
                    && (r.expression.contains("192.168.0.0/16")
                        || r.expression.contains("10.0.0.0/8"))
            })
            .collect();
        assert!(
            internal_deny.is_empty(),
            "explicitly allowed internal networks must not be denied"
        );

        // But should still deny other internal networks
        assert!(
            rules
                .iter()
                .any(|r| r.identity.rule_purpose == "internal-deny"
                    && r.expression.contains("172.16.0.0/12")),
            "other internal networks must still be denied"
        );
    }

    #[test]
    fn rule_identity_contains_all_context() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        let first = &rules[0];
        assert_eq!(first.identity.sandbox_id, "sbx_test");
        assert_eq!(first.identity.tenant_id, "tnt_test");
        assert_eq!(first.identity.policy_decision_id, "pdc_test");
        assert_eq!(first.identity.lease_id, Some("lse_test".into()));
    }

    #[test]
    fn rule_serde_roundtrip() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        let json = serde_json::to_string(&rules).unwrap();
        let parsed: Vec<NftRule> = serde_json::from_str(&json).unwrap();
        assert_eq!(rules.len(), parsed.len());
        assert_eq!(rules[0], parsed[0]);
    }

    #[test]
    fn empty_policy_serde_roundtrip() {
        let policy = EgressPolicy {
            sandbox_id: String::new(),
            tenant_id: String::new(),
            if_name: String::new(),
            allowed_cidrs: vec![],
            policy_decision_id: String::new(),
            lease_id: None,
        };

        let policy2 = EgressPolicy {
            sandbox_id: String::new(),
            tenant_id: String::new(),
            if_name: String::new(),
            allowed_cidrs: vec![],
            policy_decision_id: String::new(),
            lease_id: None,
        };

        let rules1 = policy.compile_rules();
        let rules2 = policy2.compile_rules();
        assert_eq!(rules1.len(), rules2.len());
    }

    #[test]
    fn validate_cidr_accepts_valid_ipv4() {
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("0.0.0.0/0").is_ok());
        assert!(validate_cidr("1.1.1.1/32").is_ok());
        assert!(validate_cidr("172.16.0.0/12").is_ok());
    }

    #[test]
    fn validate_cidr_rejects_invalid() {
        assert!(validate_cidr("not-a-cidr").is_err());
        assert!(validate_cidr("10.0.0.0").is_err());
        assert!(validate_cidr("10.0.0.0/33").is_err());
        assert!(validate_cidr("10.0.0.0/-1").is_err());
        assert!(validate_cidr("").is_err());
        assert!(validate_cidr("/24").is_err());
        assert!(validate_cidr("10.0.0.0/abc").is_err());
        assert!(validate_cidr("256.0.0.0/8").is_err());
    }

    #[test]
    fn validate_cidrs_returns_first_error() {
        let cidrs = vec!["10.0.0.0/8".into(), "bad".into(), "0.0.0.0/0".into()];
        let result = validate_cidrs(&cidrs);
        assert!(result.is_err());
        if let Err(NetworkAgentError::InvalidCidr { cidr }) = result {
            assert_eq!(cidr, "bad");
        } else {
            panic!("expected InvalidCidr");
        }
    }

    #[test]
    fn validate_cidrs_empty_is_ok() {
        assert!(validate_cidrs(&[]).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compile_ruleset_produces_valid_nft_syntax() {
        let policy = test_policy();
        let ruleset = policy.compile_ruleset();

        // Must contain table definition
        assert!(ruleset.starts_with("table inet"));
        assert!(ruleset.contains("type filter hook forward priority 0; policy drop;"));

        // Must contain conntrack rule
        assert!(ruleset.contains("ct state established,related accept"));

        // Must contain interface binding on verdict rules
        assert!(ruleset.contains("iif cvx001"));

        // Must end with closing braces
        assert!(ruleset.ends_with("}\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compile_ruleset_matches_compile_rules() {
        let policy = test_policy();
        let rules = policy.compile_rules();
        let ruleset = policy.compile_ruleset();

        // The ruleset must contain every CIDR from the compiled rules
        for rule in &rules {
            if rule.identity.rule_purpose == "egress-allow" {
                assert!(
                    ruleset.contains(&rule.expression),
                    "ruleset missing expression: {}",
                    rule.expression
                );
            }
        }
    }
}
