//! Idempotent cleanup and partial rollback for network resources.
//!
//! Handles three scenarios:
//! 1. Normal destroy cleanup: remove all resources in deterministic order.
//! 2. Rollback: clean up partially-created resources on provisioning failure.
//! 3. Reconciliation: detect stale or orphaned objects from receipts.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::collections::BTreeSet;
use std::time::Instant;

use tokio_stream::StreamExt;

use crate::metrics;
use crate::netlink::Handle;
use tracing::{info, warn};

use crate::error::NetworkResult;
use crate::identity::SandboxNetworkIdentity;
use crate::receipt::{CleanupReceipt, ProvisionReceipt, ResourceKind, ResourceReceipt};

/// Roll back partially provisioned resources.
///
/// When provisioning fails mid-way, this cleans up whatever was already
/// created. Resources that don't exist yet (because the failure happened
/// before their creation) are silently skipped.
pub async fn rollback(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
    receipts: &[ResourceReceipt],
) -> CleanupReceipt {
    let start = Instant::now();
    let mut cleanup = CleanupReceipt::new(identity.sandbox_id.clone());

    warn!(
        sandbox_id = %identity.sandbox_id,
        partial_count = receipts.len(),
        "network_rollback_started"
    );

    for receipt in receipts.iter().rev() {
        match receipt.kind {
            ResourceKind::Tap => {
                if let Err(err) = crate::tap::deprovision_tap(identity, handle).await {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove TAP");
                }
            }
            ResourceKind::Veth => {
                if let Err(err) = crate::veth::deprovision_veth(identity, handle).await {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove veth");
                }
            }
            ResourceKind::Namespace => {
                if let Err(err) = crate::veth::deprovision_veth(identity, handle).await {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove namespace");
                }
            }
            ResourceKind::Route => {
                if let Err(err) = crate::route::deprovision_routes(identity, handle).await {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove route");
                }
            }
            ResourceKind::Egress => {
                if let Err(err) =
                    crate::egress::deprovision_egress(&identity.sandbox_id, &identity.if_name).await
                {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove egress");
                }
            }
            ResourceKind::Nat => {
                if let Err(err) =
                    crate::nat::deprovision_nat(&identity.sandbox_id, &identity.if_name).await
                {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove NAT");
                }
            }
            ResourceKind::DnsAttachment => {
                if let Err(err) = crate::nftables::NftClient::delete_chain_in_table(
                    &crate::nftables::NftClient::sandbox_table_name(
                        &identity.sandbox_id,
                        &identity.if_name,
                    ),
                    "prerouting",
                )
                .await
                {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove DNS attachment");
                }
            }
            ResourceKind::Bandwidth => {
                // Strip the "bw-" prefix to recover the interface name.
                // Use strip_prefix for exact matching rather than
                // trim_start_matches (which would strip multiple leading
                // occurrences of any character in "bw-").
                let if_name = receipt
                    .resource_name
                    .strip_prefix("bw-")
                    .unwrap_or(&receipt.resource_name);
                if let Err(err) =
                    crate::bandwidth::deprovision_bandwidth(&identity.sandbox_id, if_name).await
                {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "rollback: failed to remove bandwidth shaping");
                }
            }
            ResourceKind::Address | ResourceKind::Link | ResourceKind::EbpF => {
                // These are cleaned up as part of removing the parent device
                continue;
            }
        }
    }

    cleanup.finalize(start.elapsed());
    metrics::record_rollback_completed();
    info!(
        sandbox_id = %identity.sandbox_id,
        resources_removed = cleanup.resources_removed.len(),
        "network_rollback_completed"
    );

    cleanup
}

/// Full idempotent cleanup for a sandbox's network resources.
///
/// Cleanup order: routes -> addresses (via device deletion) -> veth/TAP -> namespace.
pub async fn cleanup(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
    provision_receipt: Option<&ProvisionReceipt>,
) -> CleanupReceipt {
    let start = Instant::now();
    let mut cleanup = CleanupReceipt::new(identity.sandbox_id.clone());

    info!(sandbox_id = %identity.sandbox_id, "network_cleanup_started");

    // 1. Remove routes
    if let Ok(receipts) = crate::route::deprovision_routes(identity, handle).await {
        for r in receipts {
            cleanup.push_removed(r);
        }
    }

    // 2. Remove devices based on backend class
    match identity.backend_class {
        crate::identity::BackendClass::MicroVm => {
            if let Ok(receipts) = crate::tap::deprovision_tap(identity, handle).await {
                for r in receipts {
                    cleanup.push_removed(r);
                }
            }
        }
        crate::identity::BackendClass::Container => {
            if let Ok(receipts) = crate::veth::deprovision_veth(identity, handle).await {
                for r in receipts {
                    cleanup.push_removed(r);
                }
            }
        }
    }

    // 3. Verify no leftover resources if we have a receipt
    if let Some(receipt) = provision_receipt {
        for resource in &receipt.resources {
            if resource.created {
                let exists =
                    check_resource_exists(handle, &resource.resource_name, resource.kind).await;
                if !exists {
                    cleanup.push_absent(resource.resource_name.clone());
                }
            }
        }
    }

    cleanup.finalize(start.elapsed());
    metrics::record_cleanup_completed();
    info!(
        sandbox_id = %identity.sandbox_id,
        resources_removed = cleanup.resources_removed.len(),
        resources_absent = cleanup.resources_absent.len(),
        "network_cleanup_completed"
    );

    cleanup
}

/// Detect stale network objects by comparing desired state with current reality.
///
/// Returns sets of resource names that exist but should not (orphans) and
/// resources that should exist but don't (stale).
#[cfg(target_os = "linux")]
pub async fn detect_stale(
    handle: &Handle,
    expected: &ProvisionReceipt,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut orphans = BTreeSet::new();
    let mut missing = BTreeSet::new();

    for receipt in &expected.resources {
        let exists = check_resource_exists(handle, &receipt.resource_name, receipt.kind).await;
        if receipt.created && !exists {
            missing.insert(receipt.resource_name.clone());
        }
    }

    // Check for orphaned links that match our naming pattern but aren't in expected
    let _ = list_pico_links(handle, &mut orphans, expected).await;

    (orphans, missing)
}

#[cfg(not(target_os = "linux"))]
pub async fn detect_stale(
    _handle: &Handle,
    _expected: &ProvisionReceipt,
) -> (BTreeSet<String>, BTreeSet<String>) {
    (BTreeSet::new(), BTreeSet::new())
}

#[cfg(target_os = "linux")]
async fn check_resource_exists(handle: &Handle, name: &str, _kind: ResourceKind) -> bool {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    matches!(links.next().await, Some(Ok(_)))
}

#[cfg(not(target_os = "linux"))]
async fn check_resource_exists(_handle: &Handle, _name: &str, _kind: ResourceKind) -> bool {
    false
}

#[cfg(target_os = "linux")]
async fn list_pico_links(
    handle: &Handle,
    orphans: &mut BTreeSet<String>,
    expected: &ProvisionReceipt,
) -> NetworkResult<()> {
    let expected_names: BTreeSet<&str> = expected
        .resources
        .iter()
        .map(|r| r.resource_name.as_str())
        .collect();

    let mut links = handle.link().get().execute();
    while let Some(Ok(link)) = links.next().await {
        for attr in &link.attributes {
            if let crate::netlink::packet::link::LinkAttribute::IfName(name) = attr {
                let name_str = name.as_str();
                if (name_str.starts_with("cvx")
                    || name_str.starts_with("hp-")
                    || name_str.starts_with("hpc"))
                    && !expected_names.contains(name_str)
                {
                    orphans.insert(name_str.to_string());
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "linux"))]
    use crate::identity::BackendClass;
    use crate::receipt::ResourceKind;
    use std::time::Duration;

    #[test]
    fn cleanup_receipt_tracks_removed_and_absent() {
        let mut receipt = CleanupReceipt::new("sbx_a".into());
        receipt.push_removed(ResourceReceipt {
            sandbox_id: "sbx_a".into(),
            resource_name: "tap0".into(),
            kind: ResourceKind::Tap,
            created: false,
            provision_latency: Duration::from_millis(5),
        });
        receipt.push_absent("ns_path".into());
        receipt.finalize(Duration::from_millis(10));

        assert!(receipt.completed);
        assert_eq!(receipt.resources_removed.len(), 1);
        assert_eq!(receipt.resources_absent.len(), 1);
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn detect_stale_on_non_linux_returns_empty() {
        let receipt = ProvisionReceipt::new("sbx".into(), BackendClass::MicroVm, 0);

        {
            let (conn, handle) = crate::netlink::new_connection().unwrap();
            tokio::spawn(conn);
            let result = detect_stale(&handle, &receipt).await;
            assert!(result.0.is_empty());
            assert!(result.1.is_empty());
        }
    }
}
