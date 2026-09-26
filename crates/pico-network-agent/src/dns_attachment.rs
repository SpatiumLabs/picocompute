//! DNS attachment provisioning -- nftables prerouting redirect for sandbox DNS.
//!
//! Installs a prerouting chain in the sandbox's nftables table that
//! redirects UDP and TCP port 53 traffic from the sandbox interface
//! to the PicoCompute DNS policy proxy listener.
//!
//! The redirect ensures that every sandbox DNS query passes through
//! the policy-aware proxy before any upstream resolution occurs.
//!
//! # Platform Support
//!
//! All provisioning is `#[cfg(target_os = "linux")]` gated.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::net::SocketAddr;
use std::time::Instant;

use crate::error::{NetworkAgentError, NetworkResult};
use crate::nftables::NftClient;
use crate::receipt::{ResourceKind, ResourceReceipt};
use tracing::{debug, info, warn};

/// Configuration for attaching a sandbox to the DNS proxy.
#[derive(Debug, Clone)]
pub struct DnsAttachmentConfig {
    /// The sandbox identifier.
    pub sandbox_id: String,
    /// The tenant identifier.
    pub tenant_id: String,
    /// The sandbox interface name (for iif matching).
    pub if_name: String,
    /// The address the DNS proxy listens on.
    pub proxy_addr: SocketAddr,
}

impl DnsAttachmentConfig {
    /// Build the nftables table name matching the sandbox.
    #[must_use]
    pub fn table_name(&self) -> String {
        NftClient::sandbox_table_name(&self.sandbox_id, &self.if_name)
    }

    /// Compile the complete nftables ruleset for DNS attachment.
    #[cfg(target_os = "linux")]
    pub fn compile_ruleset(&self) -> String {
        let table = self.table_name();
        let if_name = &self.if_name;
        let addr = self.proxy_addr.ip();
        let port = self.proxy_addr.port();

        debug_assert!(
            if_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "if_name must contain only alphanumeric, hyphen, or underscore characters"
        );

        format!(
            // The prerouting chain uses priority -100 (before egress forward
            // chain and SNAT postrouting), ensuring DNS traffic is redirected
            // to the proxy before any other nftables rules in the sandbox table
            // evaluate the packet. If rule-ordering conflicts arise with future
            // egress rules, adjust priority accordingly.
            "table inet {table} {{\n  chain prerouting {{\n    type nat hook prerouting priority -100;\n    iif {if_name} ip protocol udp th dport 53 dnat to {addr}:{port}\n    iif {if_name} ip protocol tcp th dport 53 dnat to {addr}:{port}\n  }}\n}}\n"
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn compile_ruleset(&self) -> String {
        String::new()
    }
}

/// Provision the DNS attachment for a sandbox.
///
/// Adds a prerouting chain with DNAT rules to the sandbox's nftables
/// table. Returns resource receipts for reconciliation.
///
/// The rules redirect all UDP and TCP port 53 traffic from the sandbox
/// interface to the configured proxy listener address.
#[cfg(target_os = "linux")]
pub async fn provision_dns_attachment(
    config: &DnsAttachmentConfig,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = config.table_name();
    let mut receipts = Vec::new();

    debug!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        proxy = %config.proxy_addr,
        "provisioning DNS attachment"
    );

    let ruleset = config.compile_ruleset();
    NftClient::apply_ruleset(&table, &ruleset)
        .await
        .map_err(|e| NetworkAgentError::DnsAttachmentFailed {
            sandbox_id: config.sandbox_id.clone(),
            detail: e.to_string(),
        })?;

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: config.sandbox_id.clone(),
        resource_name: format!("dns-attachment-{}", config.proxy_addr),
        kind: ResourceKind::DnsAttachment,
        created: true,
        provision_latency: latency,
    });

    info!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        proxy = %config.proxy_addr,
        latency_ms = latency.as_millis(),
        "DNS attachment provisioned"
    );

    Ok(receipts)
}

/// Deprovision the DNS attachment for a sandbox.
///
/// Deletes the prerouting chain from the sandbox's nftables table.
/// Idempotent -- succeeds silently if the chain is already gone.
#[cfg(target_os = "linux")]
pub async fn deprovision_dns_attachment(
    config: &DnsAttachmentConfig,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let table = config.table_name();
    let mut receipts = Vec::new();

    debug!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        "deprovisioning DNS attachment"
    );

    // Deleting the chain removes all rules in it
    NftClient::delete_chain_in_table(&table, "prerouting")
        .await
        .map_err(|e| {
            warn!(sandbox_id = %config.sandbox_id, table = %table, error = %e, "DNS attachment cleanup failed");
        })
        .ok();

    let latency = start.elapsed();

    receipts.push(ResourceReceipt {
        sandbox_id: config.sandbox_id.clone(),
        resource_name: format!("dns-attachment-{}", config.proxy_addr),
        kind: ResourceKind::DnsAttachment,
        created: false,
        provision_latency: latency,
    });

    info!(
        sandbox_id = %config.sandbox_id,
        table = %table,
        latency_ms = latency.as_millis(),
        "DNS attachment removed"
    );

    Ok(receipts)
}

// Non-Linux stubs

#[cfg(not(target_os = "linux"))]
pub async fn provision_dns_attachment(
    _config: &DnsAttachmentConfig,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub async fn deprovision_dns_attachment(
    _config: &DnsAttachmentConfig,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}
