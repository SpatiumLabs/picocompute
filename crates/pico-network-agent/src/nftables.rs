//! nftables rule management via the `nft` CLI.
//!
//! Provides a typed interface for creating and deleting nftables tables,
//! chains, and rules. Uses the system `nft` binary, which is mature and
//! well-tested on Linux. Rule identity is tracked through structured
//! comments for audit, reconciliation, and cleanup.
//!
//! # Platform Support
//!
//! All operations are `#[cfg(target_os = "linux")]` gated. Non-Linux
//! platforms use stubs that return `NetworkAgentError::UnsupportedPlatform`.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::process::Stdio;

use tokio::process::Command;
use tracing::debug;

use crate::error::{NetworkAgentError, NetworkResult};

const NFT_BIN: &str = "nft";
const PICO_TABLE_PREFIX: &str = "pico";

/// An nftables client wrapping the system `nft` binary.
///
/// Executes nft commands via `std::process::Command` spawned through
/// tokio for async compatibility. All rule changes are applied
/// atomically where possible.
pub struct NftClient;

/// A single nftables rule with identity metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NftRule {
    /// The nftables family: ip, ip6, inet.
    pub family: String,
    /// The nftables table name.
    pub table: String,
    /// The nftables chain name.
    pub chain: String,
    /// The nftables rule expression.
    pub expression: String,
    /// Structured identity comment embedded in the rule.
    pub identity: NftRuleIdentity,
}

/// Structured identity metadata embedded in nftables rule comments.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NftRuleIdentity {
    pub sandbox_id: String,
    pub tenant_id: String,
    pub policy_decision_id: String,
    pub lease_id: Option<String>,
    pub rule_purpose: String,
}

impl NftClient {
    /// Build a per-sandbox nftables table name.
    ///
    /// Uses a deterministic prefix to ensure table names can be
    /// derived from identity alone. All sandbox policy for a given
    /// sandbox lives under this table.
    #[must_use]
    pub fn sandbox_table_name(sandbox_id: &str, if_name: &str) -> String {
        format!("{PICO_TABLE_PREFIX}-sbx-{sandbox_id}-{if_name}")
    }

    /// Build the identity comment string for embedding in rules.
    pub fn identity_comment(identity: &NftRuleIdentity) -> String {
        format!(
            "sbid={} tid={} pdid={}{}",
            identity.sandbox_id,
            identity.tenant_id,
            identity.policy_decision_id,
            identity
                .lease_id
                .as_ref()
                .map_or_else(String::new, |lid| format!(" lid={lid}"))
        )
    }

    /// Create an inet nftables table if it does not exist.
    #[cfg(target_os = "linux")]
    pub async fn create_table(table: &str) -> NetworkResult<()> {
        let output = Command::new(NFT_BIN)
            .args(["add", "table", "inet", table])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "create_table".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Table already exists is not a failure
            if stderr.contains("exists") {
                debug!(table = %table, "nftables table already exists");
                return Ok(());
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("create_table {table}"),
                detail: stderr.into_owned(),
            });
        }

        debug!(table = %table, "nftables table created");
        Ok(())
    }

    /// Delete an inet nftables table.
    #[cfg(target_os = "linux")]
    pub async fn delete_table(table: &str) -> NetworkResult<()> {
        let output = Command::new(NFT_BIN)
            .args(["delete", "table", "inet", table])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "delete_table".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Table not found is not a failure (idempotent)
            if stderr.contains("No such file") || stderr.contains("not found") {
                debug!(table = %table, "nftables table not found, nothing to delete");
                return Ok(());
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("delete_table {table}"),
                detail: stderr.into_owned(),
            });
        }

        debug!(table = %table, "nftables table deleted");
        Ok(())
    }

    /// Create a base chain in a table.
    #[cfg(target_os = "linux")]
    pub async fn create_chain(
        table: &str,
        chain: &str,
        hook: &str,
        priority: i32,
        policy: &str,
    ) -> NetworkResult<()> {
        let output = Command::new(NFT_BIN)
            .args([
                "add",
                "chain",
                "inet",
                table,
                chain,
                "{",
                "type",
                "filter",
                "hook",
                hook,
                "priority",
                &priority.to_string(),
                ";",
                "policy",
                policy,
                "}",
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "create_chain".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("exists") {
                debug!(table = %table, chain = %chain, "chain already exists");
                return Ok(());
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("create_chain {chain} in {table}"),
                detail: stderr.into_owned(),
            });
        }

        debug!(table = %table, chain = %chain, "chain created");
        Ok(())
    }

    /// Add a rule to a chain with identity comment.
    #[cfg(target_os = "linux")]
    pub async fn add_rule(rule: &NftRule) -> NetworkResult<()> {
        let comment = Self::identity_comment(&rule.identity);
        let output = Command::new(NFT_BIN)
            .args([
                "add",
                "rule",
                "inet",
                &rule.table,
                &rule.chain,
                &rule.expression,
                "comment",
                &format!("\"{comment}\""),
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "add_rule".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkAgentError::Nftables {
                operation: format!("add_rule to {}.{}", rule.table, rule.chain),
                detail: stderr.into_owned(),
            });
        }

        debug!(
            table = %rule.table,
            chain = %rule.chain,
            purpose = %rule.identity.rule_purpose,
            "nftables rule added"
        );
        Ok(())
    }

    /// Flush (delete all rules from) a chain.
    #[cfg(target_os = "linux")]
    pub async fn flush_chain(table: &str, chain: &str) -> NetworkResult<()> {
        let output = Command::new(NFT_BIN)
            .args(["flush", "chain", "inet", table, chain])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "flush_chain".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file") || stderr.contains("not found") {
                debug!(table = %table, chain = %chain, "chain not found, nothing to flush");
                return Ok(());
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("flush_chain {chain} in {table}"),
                detail: stderr.into_owned(),
            });
        }

        debug!(table = %table, chain = %chain, "chain flushed");
        Ok(())
    }

    /// Apply a complete nftables ruleset from a string.
    ///
    /// Uses `nft -f -` to atomically load rules from stdin.
    /// Returns the output on success or an error on failure.
    #[cfg(target_os = "linux")]
    pub async fn apply_ruleset(table: &str, ruleset: &str) -> NetworkResult<String> {
        let mut child = Command::new(NFT_BIN)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "apply_ruleset".into(),
                detail: e.to_string(),
            })?;

        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .await
                .map_err(|e| NetworkAgentError::Nftables {
                    operation: "write_ruleset_stdin".into(),
                    detail: e.to_string(),
                })?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "apply_ruleset".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkAgentError::Nftables {
                operation: format!("apply_ruleset for {table}"),
                detail: stderr.into_owned(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(stdout)
    }

    /// List all rules in a table as JSON.
    #[cfg(target_os = "linux")]
    pub async fn list_table_json(table: &str) -> NetworkResult<String> {
        let output = Command::new(NFT_BIN)
            .args(["-j", "list", "table", "inet", table])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "list_table".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file") || stderr.contains("not found") {
                return Err(NetworkAgentError::Nftables {
                    operation: format!("list_table {table}"),
                    detail: "table not found".into(),
                });
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("list_table {table}"),
                detail: stderr.into_owned(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Delete a chain (and all its rules) from a table.
    #[cfg(target_os = "linux")]
    pub async fn delete_chain_in_table(table: &str, chain: &str) -> NetworkResult<()> {
        let output = Command::new(NFT_BIN)
            .args(["delete", "chain", "inet", table, chain])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| NetworkAgentError::Nftables {
                operation: "delete_chain_in_table".into(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file") || stderr.contains("not found") {
                debug!(table = %table, chain = %chain, "chain not found, nothing to delete");
                return Ok(());
            }
            return Err(NetworkAgentError::Nftables {
                operation: format!("delete_chain_in_table {chain} in {table}"),
                detail: stderr.into_owned(),
            });
        }

        debug!(table = %table, chain = %chain, "chain deleted");
        Ok(())
    }

    /// Check whether an nftables table exists.
    #[cfg(target_os = "linux")]
    pub async fn table_exists(table: &str) -> bool {
        NftClient::list_table_json(table).await.is_ok()
    }

    // ──── Non-Linux stubs ────

    #[cfg(not(target_os = "linux"))]
    pub async fn create_table(_table: &str) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn delete_table(_table: &str) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn create_chain(
        _table: &str,
        _chain: &str,
        _hook: &str,
        _priority: i32,
        _policy: &str,
    ) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn add_rule(_rule: &NftRule) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn flush_chain(_table: &str, _chain: &str) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn delete_chain_in_table(_table: &str, _chain: &str) -> NetworkResult<()> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn apply_ruleset(_table: &str, _ruleset: &str) -> NetworkResult<String> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn list_table_json(_table: &str) -> NetworkResult<String> {
        Err(NetworkAgentError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn table_exists(_table: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_table_name_is_deterministic() {
        let name1 = NftClient::sandbox_table_name("sbx_abc", "cvx001");
        let name2 = NftClient::sandbox_table_name("sbx_abc", "cvx001");
        assert_eq!(name1, name2);
        assert!(name1.starts_with("pico-sbx-"));
        assert!(name1.contains("cvx001"));
    }

    #[test]
    fn identity_comment_contains_all_ids() {
        let identity = NftRuleIdentity {
            sandbox_id: "sbx_01".into(),
            tenant_id: "tnt_01".into(),
            policy_decision_id: "pdc_01".into(),
            lease_id: Some("lse_01".into()),
            rule_purpose: "egress_allow".into(),
        };

        let comment = NftClient::identity_comment(&identity);
        assert!(comment.contains("sbid=sbx_01"));
        assert!(comment.contains("tid=tnt_01"));
        assert!(comment.contains("pdid=pdc_01"));
        assert!(comment.contains("lid=lse_01"));
    }

    #[test]
    fn identity_comment_without_lease() {
        let identity = NftRuleIdentity {
            sandbox_id: "sbx_01".into(),
            tenant_id: "tnt_01".into(),
            policy_decision_id: "pdc_01".into(),
            lease_id: None,
            rule_purpose: "base_deny".into(),
        };

        let comment = NftClient::identity_comment(&identity);
        assert!(!comment.contains("lid="));
    }

    #[test]
    fn nft_rule_serde_roundtrip() {
        let rule = NftRule {
            family: "inet".into(),
            table: "pico-sbx-test".into(),
            chain: "forward".into(),
            expression: "ip daddr 10.0.0.0/8 accept".into(),
            identity: NftRuleIdentity {
                sandbox_id: "sbx_test".into(),
                tenant_id: "tnt_test".into(),
                policy_decision_id: "pdc_test".into(),
                lease_id: Some("lse_test".into()),
                rule_purpose: "egress_allow".into(),
            },
        };

        let json = serde_json::to_string(&rule).unwrap();
        let parsed: NftRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, parsed);
    }
}
