//! veth pair and network namespace provisioning for container/gVisor backends.
//!
//! Creates a veth pair with one peer in a new network namespace, assigns
//! addresses, and brings links up.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use tokio_stream::StreamExt;
use tracing::debug;

use crate::error::{NetworkAgentError, NetworkResult};
use crate::identity::SandboxNetworkIdentity;
use crate::metrics;
use crate::metrics::val;
use crate::netlink::Handle;
use crate::receipt::{ResourceKind, ResourceReceipt};

/// Provision a veth pair with network namespace for a container backend.
///
/// Creates a veth pair, moves one peer into a new network namespace, assigns
/// the guest and host IP addresses, and brings both links up.
#[cfg(target_os = "linux")]
pub async fn provision_veth(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<(RawFd, Vec<ResourceReceipt>)> {
    let start = Instant::now();

    metrics::record_setup_started(val::CONTAINER, val::VETH);
    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        sandbox_if = %identity.sandbox_if_name(),
        host_if = %identity.host_if_name(),
        "network_setup_started"
    );

    let result = provision_veth_inner(identity, handle).await;
    match result {
        Ok((fd, receipts)) => {
            let total = start.elapsed();
            metrics::record_setup_completed(val::CONTAINER, val::VETH, total.as_secs_f64());
            metrics::record_object_count(val::VETH, receipts.len());
            metrics::record_interface_allocated(val::CONTAINER);
            tracing::info!(
                sandbox_id = %identity.sandbox_id,
                object_count = receipts.len(),
                duration_ms = total.as_millis(),
                "network_setup_completed"
            );
            Ok((fd, receipts))
        }
        Err(err) => {
            metrics::record_setup_not_completed(val::CONTAINER, val::VETH, val::PROVISION_FAILURE);
            metrics::record_interface_allocation_incomplete(val::CONTAINER);
            tracing::warn!(
                sandbox_id = %identity.sandbox_id,
                error = %err,
                "network_setup_not_completed"
            );
            // Best-effort cleanup of partial resources
            if let Err(cleanup_err) = delete_link(handle, identity.host_if_name()).await {
                debug!(sandbox_id = %identity.sandbox_id, host_if = %identity.host_if_name(), error = %cleanup_err, "cleanup after failure: host veth already absent");
            }
            if let Err(cleanup_err) = delete_namespace(&identity.ns_path) {
                debug!(sandbox_id = %identity.sandbox_id, ns = %identity.ns_path, error = %cleanup_err, "cleanup after failure: namespace already absent");
            }
            Err(err)
        }
    }
}

#[cfg(target_os = "linux")]
async fn provision_veth_inner(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<(RawFd, Vec<ResourceReceipt>)> {
    let sandbox_if = identity.sandbox_if_name();
    let host_if = identity.host_if_name();
    let guest_ip = identity.guest_ip;
    let host_ip = identity.host_ip;
    let prefix_len = identity.prefix_len;

    let mut receipts = Vec::with_capacity(6);

    create_namespace(&identity.ns_path).map_err(|source| NetworkAgentError::NamespaceCreate {
        ns_name: identity.ns_path.clone(),
        source,
    })?;

    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: identity.ns_path.clone(),
        kind: ResourceKind::Namespace,
        created: true,
        provision_latency: Duration::ZERO,
    });

    create_veth_pair(handle, sandbox_if, host_if)
        .await
        .inspect_err(|_source| {
            // Clean up namespace before propagating error
            let _ = delete_namespace(&identity.ns_path);
        })?;

    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: format!("{sandbox_if}<->{host_if}"),
        kind: ResourceKind::Veth,
        created: true,
        provision_latency: Duration::ZERO,
    });

    move_if_to_namespace(handle, sandbox_if, &identity.ns_path).await?;
    assign_address_in_ns(&identity.ns_path, sandbox_if, guest_ip, prefix_len).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: sandbox_if.to_string(),
        kind: ResourceKind::Address,
        created: true,
        provision_latency: Duration::ZERO,
    });

    assign_host_address(handle, host_if, host_ip, prefix_len).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: host_if.to_string(),
        kind: ResourceKind::Address,
        created: true,
        provision_latency: Duration::ZERO,
    });

    set_link_up_in_ns(&identity.ns_path, sandbox_if).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: sandbox_if.to_string(),
        kind: ResourceKind::Link,
        created: true,
        provision_latency: Duration::ZERO,
    });

    set_link_up(handle, host_if).await?;
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: host_if.to_string(),
        kind: ResourceKind::Link,
        created: true,
        provision_latency: Duration::ZERO,
    });

    Ok((0, receipts))
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub async fn provision_veth(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<(i32, Vec<ResourceReceipt>)> {
    Err(NetworkAgentError::UnsupportedPlatform)
}
/// Deprovision a veth pair and namespace.
#[cfg(target_os = "linux")]
pub async fn deprovision_veth(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let host_if = identity.host_if_name();
    let _sandbox_if = identity.sandbox_if_name();

    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        host_if = %host_if,
        ns = %identity.ns_path,
        "network_cleanup_started"
    );

    let mut receipts = Vec::with_capacity(3);

    match delete_link(handle, host_if).await {
        Ok(()) => {
            let latency = start.elapsed();
            metrics::record_cleanup_removed(val::VETH);
            receipts.push(ResourceReceipt {
                sandbox_id: identity.sandbox_id.clone(),
                resource_name: host_if.to_string(),
                kind: ResourceKind::Veth,
                created: false,
                provision_latency: latency,
            });
        }
        Err(err) => {
            debug!(sandbox_id = %identity.sandbox_id, host_if = %host_if, error = %err, "host veth already absent during cleanup");
            metrics::record_cleanup_absent(val::VETH);
        }
    }

    match delete_namespace(&identity.ns_path) {
        Ok(()) => {
            receipts.push(ResourceReceipt {
                sandbox_id: identity.sandbox_id.clone(),
                resource_name: identity.ns_path.clone(),
                kind: ResourceKind::Namespace,
                created: false,
                provision_latency: start.elapsed(),
            });
            metrics::record_cleanup_removed(val::NAMESPACE);
        }
        Err(err) => {
            debug!(sandbox_id = %identity.sandbox_id, ns = %identity.ns_path, error = %err, "namespace already absent during cleanup");
            metrics::record_cleanup_absent(val::NAMESPACE);
        }
    }

    tracing::info!(
        sandbox_id = %identity.sandbox_id,
        duration_ms = start.elapsed().as_millis(),
        "network_cleanup_completed"
    );

    Ok(receipts)
}

#[cfg(not(target_os = "linux"))]
pub async fn deprovision_veth(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

// --- Linux-specific helpers ---

#[cfg(target_os = "linux")]
fn create_namespace(path: &str) -> std::io::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let ns_dir = "/var/run/netns";
    fs::create_dir_all(ns_dir)?;

    let file = fs::File::create(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    drop(file);

    use std::os::unix::io::AsFd;

    use rustix::mount::{UnmountFlags, mount_bind, unmount};
    use rustix::thread::{
        LinkNameSpaceType, UnshareFlags, move_into_link_name_space, unshare_unsafe,
    };

    let mount_path = std::ffi::CString::new(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let netns_path_cstr = std::ffi::CString::new("/proc/self/ns/net")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // Save the original network namespace fd so we can restore on failure
    let orig_ns = fs::File::open("/proc/self/ns/net")?;

    // Create a new network namespace for the current thread
    // SAFETY: Not using FILES flag, so no thread safety issue.
    unsafe { unshare_unsafe(UnshareFlags::NEWNET) }?;

    // Bind-mount the new namespace to the path for persistence
    let result = mount_bind(netns_path_cstr.as_c_str(), mount_path.as_c_str());

    if let Err(err) = result {
        // Restore original namespace before returning
        let _ = move_into_link_name_space(orig_ns.as_fd(), Some(LinkNameSpaceType::Network));
        return Err(err.into());
    }

    // Restore the original namespace -- the new namespace stays alive via the bind-mount
    if let Err(err) = move_into_link_name_space(orig_ns.as_fd(), Some(LinkNameSpaceType::Network)) {
        // The namespace was created and persisted, but we couldn't return to original.
        // Clean up the persisted namespace and return error.
        let _ = unmount(mount_path.as_c_str(), UnmountFlags::DETACH);
        let _ = fs::remove_file(path);
        return Err(err.into());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn delete_namespace(path: &str) -> std::io::Result<()> {
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn create_veth_pair(handle: &Handle, sandbox_if: &str, host_if: &str) -> NetworkResult<()> {
    use crate::netlink::LinkVeth;

    let msg = LinkVeth::new(sandbox_if, host_if).build();

    handle
        .link()
        .add(msg)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::VethCreate {
            veth_name: sandbox_if.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn move_if_to_namespace(handle: &Handle, if_name: &str, ns_path: &str) -> NetworkResult<()> {
    use std::fs;

    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::VethPeerSetup {
            veth_name: if_name.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("interface {if_name} not found"),
            ),
        });
    };

    let index = link.header.index;
    let ns_fd = fs::File::open(ns_path).map_err(NetworkAgentError::Io)?;
    let ns_fd = ns_fd.as_raw_fd();

    use crate::netlink::LinkUnspec;
    let msg = LinkUnspec::new_with_index(index).setns_by_fd(ns_fd).build();

    handle
        .link()
        .set(msg)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::VethPeerSetup {
            veth_name: if_name.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn assign_address_in_ns(
    _ns_path: &str,
    _if_name: &str,
    _addr: std::net::Ipv4Addr,
    _prefix_len: u8,
) -> NetworkResult<()> {
    use std::process::Command;

    let addr = format!("{_addr}/{_prefix_len}");
    let output = Command::new("ip")
        .args([
            "netns",
            "exec",
            crate::identity::SandboxNetworkIdentity::namespace_base_name(_ns_path),
        ])
        .args(["ip", "addr", "add", &addr, "dev", _if_name])
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(NetworkAgentError::AddressAssign {
            interface: _if_name.to_string(),
            addr: _addr.to_string(),
            source: std::io::Error::other(String::from_utf8_lossy(&o.stderr).to_string()),
        }),
        Err(e) => Err(NetworkAgentError::AddressAssign {
            interface: _if_name.to_string(),
            addr: _addr.to_string(),
            source: e,
        }),
    }
}

#[cfg(target_os = "linux")]
async fn assign_host_address(
    handle: &Handle,
    if_name: &str,
    addr: std::net::Ipv4Addr,
    prefix_len: u8,
) -> NetworkResult<()> {
    use std::net::IpAddr;

    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::VethPeerSetup {
            veth_name: if_name.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "host veth not found"),
        });
    };

    handle
        .address()
        .add(link.header.index, IpAddr::V4(addr), prefix_len)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::AddressAssign {
            interface: if_name.to_string(),
            addr: addr.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn set_link_up(handle: &Handle, name: &str) -> NetworkResult<()> {
    use crate::netlink::LinkUnspec;

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::VethPeerSetup {
            veth_name: name.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "link not found"),
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
async fn set_link_up_in_ns(ns_path: &str, if_name: &str) -> NetworkResult<()> {
    use std::process::Command;

    let ns_name = crate::identity::SandboxNetworkIdentity::namespace_base_name(ns_path);
    let output = Command::new("ip")
        .args(["netns", "exec", ns_name])
        .args(["ip", "link", "set", if_name, "up"])
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(NetworkAgentError::LinkUp {
            interface: if_name.to_string(),
            source: std::io::Error::other(String::from_utf8_lossy(&o.stderr).to_string()),
        }),
        Err(e) => Err(NetworkAgentError::LinkUp {
            interface: if_name.to_string(),
            source: e,
        }),
    }
}

#[cfg(target_os = "linux")]
async fn delete_link(handle: &Handle, name: &str) -> NetworkResult<()> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(Ok(link)) = links.next().await else {
        return Err(NetworkAgentError::VethPeerSetup {
            veth_name: name.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "link not found"),
        });
    };

    handle
        .link()
        .del(link.header.index)
        .execute()
        .await
        .map_err(|e| NetworkAgentError::VethPeerSetup {
            veth_name: name.to_string(),
            source: std::io::Error::other(e),
        })?;

    Ok(())
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::{NetworkAgentError, provision_veth};
    use crate::identity::{BackendClass, SandboxNetworkIdentity};

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn provision_veth_returns_unsupported_on_non_linux() {
        let identity = SandboxNetworkIdentity::for_sandbox("test_sbx", BackendClass::Container);

        {
            let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (conn, handle) = crate::netlink::new_connection().unwrap();
                tokio::spawn(conn);
                provision_veth(&identity, &handle).await
            });
            assert!(matches!(
                result,
                Err(NetworkAgentError::UnsupportedPlatform)
            ));
        }
    }
}
