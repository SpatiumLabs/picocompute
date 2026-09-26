//! NAT/masquerade setup for sandbox outbound traffic.
//!
//! Provides SNAT (source NAT) so sandbox traffic is masqueraded
//! behind the host IP address. Each sandbox gets a NAT chain in its
//! own nftables table with per-interface identity binding.
//!
//! # Platform Support
//!
//! All provisioning is `#[cfg(target_os = "linux")]` gated.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::time::Instant;

use crate::error::{NetworkAgentError, NetworkResult};
use crate::metrics;
use crate::nftables::{NftClient, NftRule, NftRuleIdentity};
use crate::receipt::ResourceReceipt;
use tracing::{debug, info, warn};

/// NAT configuration for a sandbox's outbound traffic.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// The sandbox this NAT config applies to.
    pub sandbox_id: String,
    /// The tenant that owns the sandbox.
    pub tenant_id: String,
    /// The sandbox interface name (for oif matching).
    pub if_name: String,
    /// The host gateway interface name (outbound interface).
    pub host_if_name: String,
    /// The policy decision that authorized this NAT configuration.
    pub policy_decision_id: String,
}

impl NatConfig {
    /// Build the nftables table name matching the egress policy.
    #[must_use]
    pub fn table_name(&self) -> String {
        NftClient::sandbox_table_name(&self.sandbox_id, &self.if_name)
    }

    fn rule_identity(&self, purpose: &str) -> NftRuleIdentity {
        NftRuleIdentity {
            sandbox_id: self.sandbox_id.clone(),
            tenant_id: self.tenant_id.clone(),
            policy_decision_id: self.policy_decision_id.clone(),
            lease_id: None,
            rule_purpose: purpose.to_string(),
        }
    }

    /// Generate the NAT/masquerade rules.
    ///
    /// Creates rules that SNAT traffic from this sandbox's interface
    /// to the host gateway interface's address.
    pub fn compile_rules(&self) -> Vec<NftRule> {
        let table = self.table_name();
        let mut rules = Vec::new();

        // SNAT rule: masquerade outbound traffic from sandbox iface
        rules.push(NftRule {
            family: "inet".into(),
            table: table.clone(),
            chain: "snat".into(),
            expression: format!("iif {} oif {} masquerade", self.if_name, self.host_if_name),
            identity: self.rule_identity("snat-masquerade"),
        });

        rules
    }
}

/// Provisions NAT/masquerade rules for a sandbox.
///
/// Creates a `snat` chain in the sandbox's nftables table and
/// installs the masquerade rules.
#[cfg(target_os = "linux")]
pub async fn provision_nat(config: &NatConfig) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = config.table_name();
    let mut receipts = Vec::new();

    debug!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        if_name = %config.if_name,
        host_if = %config.host_if_name,
        "provisioning NAT rules"
    );

    // Create the NAT chain (postrouting hook)
    NftClient::create_chain(&table, "snat", "postrouting", 100, "accept")
        .await
        .map_err(|e| NetworkAgentError::NatSetupFailed {
            sandbox_id: config.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    // Install the masquerade rule
    let rules = config.compile_rules();
    for rule in &rules {
        NftClient::add_rule(rule)
            .await
            .map_err(|e| NetworkAgentError::NatSetupFailed {
                sandbox_id: config.sandbox_id.clone(),
                detail: e.to_string(),
            })?;
    }

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: config.sandbox_id.clone(),
        resource_name: table.clone(),
        kind: crate::receipt::ResourceKind::Nat,
        created: true,
        provision_latency: latency,
    });

    metrics::record_nat_setup_completed();
    info!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "NAT rules provisioned"
    );

    Ok(receipts)
}

/// Deprovisions NAT rules for a sandbox.
///
/// Flushes the `snat` chain. Idempotent -- if the chain does not
/// exist, the operation succeeds silently.
#[cfg(target_os = "linux")]
pub async fn deprovision_nat(
    sandbox_id: &str,
    if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = NftClient::sandbox_table_name(sandbox_id, if_name);
    let mut receipts = Vec::new();

    debug!(sandbox_id = %sandbox_id, table = %table, "deprovisioning NAT rules");

    NftClient::flush_chain(&table, "snat").await.map_err(|e| {
        warn!(sandbox_id = %sandbox_id, table = %table, error = %e, "NAT cleanup failed");
        NetworkAgentError::NatTeardownFailed {
            sandbox_id: sandbox_id.to_string(),
            detail: e.to_string(),
        }
    })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: sandbox_id.to_string(),
        resource_name: table.clone(),
        kind: crate::receipt::ResourceKind::Nat,
        created: false,
        provision_latency: latency,
    });

    info!(
        sandbox_id = %sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "NAT rules removed"
    );

    Ok(receipts)
}

// ──── Non-Linux stubs ────

#[cfg(not(target_os = "linux"))]
pub async fn provision_nat(_config: &NatConfig) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub async fn deprovision_nat(
    _sandbox_id: &str,
    _if_name: &str,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> NatConfig {
        NatConfig {
            sandbox_id: "sbx_test".into(),
            tenant_id: "tnt_test".into(),
            if_name: "cvx001".into(),
            host_if_name: "eth0".into(),
            policy_decision_id: "pdc_test".into(),
        }
    }

    #[test]
    fn table_name_matches_identity() {
        let config = test_config();
        let name = config.table_name();
        assert!(name.starts_with("pico-sbx-"));
        assert!(name.contains("cvx001"));
    }

    #[test]
    fn compile_rules_produces_masquerade_rule() {
        let config = test_config();
        let rules = config.compile_rules();
        assert_eq!(rules.len(), 1);
        assert!(
            rules[0].expression.contains("masquerade"),
            "NAT rules must include masquerade"
        );
        assert!(
            rules[0].expression.contains("iif cvx001"),
            "NAT rule must bind to sandbox interface"
        );
        assert!(
            rules[0].expression.contains("oif eth0"),
            "NAT rule must specify host outbound interface"
        );
    }

    #[test]
    fn rule_identity_has_no_lease() {
        let config = test_config();
        let rules = config.compile_rules();
        assert!(rules[0].identity.lease_id.is_none());
        assert_eq!(rules[0].identity.rule_purpose, "snat-masquerade");
    }

    #[test]
    fn rule_serde_roundtrip() {
        let config = test_config();
        let rules = config.compile_rules();
        let json = serde_json::to_string(&rules).unwrap();
        let parsed: Vec<NftRule> = serde_json::from_str(&json).unwrap();
        assert_eq!(rules, parsed);
    }
}
