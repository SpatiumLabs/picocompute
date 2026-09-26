//! TAP device provisioning for microVM backends (Firecracker, QEMU).
//!
//! Creates a persistent TAP device via `/dev/net/tun` and configures
//! its link state and IP address using rtnetlink.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::os::fd::RawFd;
use std::time::Instant;

use tokio_stream::StreamExt;

use crate::metrics;
use crate::netlink::Handle;
use tracing::debug;

use crate::error::{NetworkAgentError, NetworkResult};
use crate::identity::SandboxNetworkIdentity;
use crate::metrics::val;
use crate::receipt::{ResourceKind, ResourceReceipt};

/// Provision a TAP device for a microVM sandbox.
///
/// On Linux, this opens `/dev/net/tun`, creates a persistent TAP interface,
/// assigns the host IP address, and brings the link up.
///
/// Returns the TAP file descriptor (for the VMM to attach) and a receipt.
#[cfg(target_os = "linux")]
pub async fn provision_tap(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<(RawFd, Vec<ResourceReceipt>)> {
    let start = Instant::now();
    let tap_name = identity.sandbox_if_name();

    metrics::record_setup_started(val::MICROVM, val::TAP);
    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        tap_name = %tap_name,
        host_ip = %identity.host_ip,
        "network_setup_started"
    );

    let result = provision_tap_inner(identity, handle).await;
    match result {
        Ok((fd, receipts)) => {
            let total = start.elapsed();
            metrics::record_setup_completed(val::MICROVM, val::TAP, total.as_secs_f64());
            metrics::record_object_count(val::TAP, receipts.len());
            metrics::record_interface_allocated(val::MICROVM);
            tracing::info!(
                sandbox_id = %identity.sandbox_id,
                tap_name = %tap_name,
                object_count = receipts.len(),
                duration_ms = total.as_millis(),
                "network_setup_completed"
            );
            Ok((fd, receipts))
        }
        Err(err) => {
            metrics::record_setup_not_completed(val::MICROVM, val::TAP, val::PROVISION_FAILURE);
            metrics::record_interface_allocation_incomplete(val::MICROVM);
            tracing::warn!(
                sandbox_id = %identity.sandbox_id,
                tap_name = %tap_name,
                error = %err,
                "network_setup_not_completed"
            );
            // Best-effort cleanup of any partially created resources
            if let Err(cleanup_err) = delete_link(handle, tap_name).await {
                debug!(sandbox_id = %identity.sandbox_id, tap_name = %tap_name, error = %cleanup_err, "cleanup after failure: TAP already absent");
            }
            Err(err)
        }
    }
}

#[cfg(target_os = "linux")]
async fn provision_tap_inner(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<(RawFd, Vec<ResourceReceipt>)> {
    let tap_name = identity.sandbox_if_name();
    let host_ip = identity.host_ip;
    let prefix_len = identity.prefix_len;

    let mut receipts = Vec::with_capacity(3);

    let tap_fd = create_tap_fd(tap_name).map_err(|source| NetworkAgentError::TapCreate {
        tap_name: tap_name.to_string(),
        source,
    })?;

    let tap_latency = Instant::now().elapsed();
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: tap_name.to_string(),
        kind: ResourceKind::Tap,
        created: true,
        provision_latency: tap_latency,
    });

    set_link_up(handle, tap_name).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: tap_name.to_string(),
        kind: ResourceKind::Link,
        created: true,
        provision_latency: tap_latency,
    });

    assign_address(handle, tap_name, host_ip, prefix_len).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: tap_name.to_string(),
        kind: ResourceKind::Address,
        created: true,
        provision_latency: tap_latency,
    });

    Ok((tap_fd, receipts))
}

/// Provision a TAP device (non-Linux stub -- returns UnsupportedPlatform).
#[cfg(not(target_os = "linux"))]
pub async fn provision_tap(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<(i32, Vec<ResourceReceipt>)> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

/// Deprovision a TAP device: bring link down and delete it.
#[cfg(target_os = "linux")]
pub async fn deprovision_tap(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let tap_name = identity.sandbox_if_name();

    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        tap_name = %tap_name,
        "network_cleanup_started"
    );

    let mut receipts = Vec::with_capacity(2);

    match delete_link(handle, tap_name).await {
        Ok(()) => {
            let latency = start.elapsed();
            metrics::record_cleanup_removed(val::TAP);
            tracing::info!(
                sandbox_id = %identity.sandbox_id,
                tap_name = %tap_name,
                duration_ms = latency.as_millis(),
                "network_cleanup_completed"
            );
            receipts.push(ResourceReceipt {
                sandbox_id: identity.sandbox_id.clone(),
                resource_name: tap_name.to_string(),
                kind: ResourceKind::Tap,
                created: false,
                provision_latency: latency,
            });
        }
        Err(err) => {
            debug!(sandbox_id = %identity.sandbox_id, tap_name = %tap_name, error = %err, "TAP already absent during cleanup");
            metrics::record_cleanup_absent(val::TAP);
        }
    }

    Ok(receipts)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub async fn deprovision_tap(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn create_tap_fd(name: &str) -> std::io::Result<RawFd> {
    use std::os::fd::IntoRawFd;

    let mut config = tun::Configuration::default();
    config.layer(tun::Layer::L2).tun_name(name).up();

    config.platform_config(|platform| {
        #[allow(deprecated)]
        platform.packet_information(false);
    });

    let mut device = tun::create(&config).map_err(std::io::Error::other)?;
    device.persist().map_err(std::io::Error::other)?;
    Ok(device.into_raw_fd())
}

#[cfg(target_os = "linux")]
async fn set_link_up(handle: &Handle, name: &str) -> NetworkResult<()> {
    use crate::netlink::LinkUnspec;

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::TapNotFound {
            tap_name: name.to_string(),
        });
    };

    let msg = LinkUnspec::new_with_index(link.header.index).up().build();

    handle
        .link()
        .set(msg)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::LinkUp {
            interface: name.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn assign_address(
    handle: &Handle,
    name: &str,
    addr: std::net::Ipv4Addr,
    prefix_len: u8,
) -> NetworkResult<()> {
    use std::net::IpAddr;

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::TapNotFound {
            tap_name: name.to_string(),
        });
    };

    let index = link.header.index;
    let ip_addr = IpAddr::V4(addr);

    handle
        .address()
        .add(index, ip_addr, prefix_len)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::AddressAssign {
            interface: name.to_string(),
            addr: addr.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn delete_link(handle: &Handle, name: &str) -> NetworkResult<()> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::TapNotFound {
            tap_name: name.to_string(),
        });
    };

    handle
        .link()
        .del(link.header.index)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::TapDelete {
            tap_name: name.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::{NetworkAgentError, provision_tap};
    use crate::identity::{BackendClass, SandboxNetworkIdentity};

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn provision_tap_returns_unsupported_on_non_linux() {
        let identity = SandboxNetworkIdentity::for_sandbox("test_sbx", BackendClass::MicroVm);
        // On non-Linux, this will return UnsupportedPlatform
        {
            let (_conn, handle) = crate::netlink::new_connection().unwrap();
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { provision_tap(&identity, &handle).await });
            assert!(matches!(
                result,
                Err(NetworkAgentError::UnsupportedPlatform)
            ));
        }
    }
}
