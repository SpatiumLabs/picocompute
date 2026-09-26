//! Route provisioning for sandbox network namespaces.
//!
//! Installs default routes and host-uplink routes needed by the NAT/DNS policy path.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::time::Instant;
use tracing::{debug, warn};

use crate::error::{NetworkAgentError, NetworkResult};
use crate::identity::SandboxNetworkIdentity;
use crate::metrics;
use crate::metrics::val;
use crate::netlink::Handle;
use crate::receipt::{ResourceKind, ResourceReceipt};

/// Provision default route in a sandbox network namespace.
///
/// Adds a default route via the host-side veth peer so the sandbox
/// can reach the NAT/DNS policy path.
#[cfg(target_os = "linux")]
pub async fn provision_default_route(
    identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let sandbox_if = identity.sandbox_if_name();
    let host_ip = identity.host_ip;

    let mut receipts = Vec::with_capacity(1);

    install_route_in_ns(
        &identity.ns_path,
        sandbox_if,
        "default",
        host_ip,
    )
    .await
    .map_err(|source| {
        metrics::record_setup_not_completed("", "", val::ROUTE_ADD);
        warn!(sandbox_id = %identity.sandbox_id, error = %source, "network_setup_not_completed");
        source
    })?;

    let latency = start.elapsed();
    receipts.push(ResourceReceipt {
        sandbox_id: identity.sandbox_id.clone(),
        resource_name: format!("default-via-{host_ip}"),
        kind: ResourceKind::Route,
        created: true,
        provision_latency: latency,
    });

    metrics::record_object_count(val::ROUTE, receipts.len());

    Ok(receipts)
}

#[cfg(not(target_os = "linux"))]
pub async fn provision_default_route(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

/// Deprovision all routes for a sandbox (currently the default route).
#[cfg(target_os = "linux")]
pub async fn deprovision_routes(
    identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    let start = Instant::now();
    let host_ip = identity.host_ip;

    let mut receipts = Vec::with_capacity(1);

    match remove_route_in_ns(&identity.ns_path, "default", host_ip).await {
        Ok(()) => {
            receipts.push(ResourceReceipt {
                sandbox_id: identity.sandbox_id.clone(),
                resource_name: format!("default-via-{host_ip}"),
                kind: ResourceKind::Route,
                created: false,
                provision_latency: start.elapsed(),
            });
            metrics::record_cleanup_removed(val::ROUTE);
        }
        Err(err) => {
            debug!(sandbox_id = %identity.sandbox_id, error = %err, "route already absent during cleanup");
            metrics::record_cleanup_absent(val::ROUTE);
        }
    }

    Ok(receipts)
}

#[cfg(not(target_os = "linux"))]
pub async fn deprovision_routes(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
) -> NetworkResult<Vec<ResourceReceipt>> {
    Err(NetworkAgentError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
async fn install_route_in_ns(
    ns_path: &str,
    _if_name: &str,
    destination: &str,
    gateway: std::net::Ipv4Addr,
) -> NetworkResult<()> {
    use std::process::Command;

    let ns_name = crate::identity::SandboxNetworkIdentity::namespace_base_name(ns_path);
    let dest = if destination == "default" {
        "default".to_string()
    } else {
        destination.to_string()
    };

    let output = Command::new("ip")
        .args(["netns", "exec", ns_name])
        .args(["ip", "route", "add", &dest, "via", &gateway.to_string()])
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(NetworkAgentError::RouteAdd {
            interface: _if_name.to_string(),
            source: std::io::Error::other(String::from_utf8_lossy(&o.stderr).to_string()),
        }),
        Err(e) => Err(NetworkAgentError::RouteAdd {
            interface: _if_name.to_string(),
            source: e,
        }),
    }
}

#[cfg(target_os = "linux")]
async fn remove_route_in_ns(
    ns_path: &str,
    destination: &str,
    gateway: std::net::Ipv4Addr,
) -> NetworkResult<()> {
    use std::process::Command;

    let ns_name = crate::identity::SandboxNetworkIdentity::namespace_base_name(ns_path);
    let dest = if destination == "default" {
        "default".to_string()
    } else {
        destination.to_string()
    };

    let output = Command::new("ip")
        .args(["netns", "exec", ns_name])
        .args(["ip", "route", "del", &dest, "via", &gateway.to_string()])
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        _ => {
            debug!("route {dest} via {gateway} already absent in ns {ns_name}");
            Ok(())
        }
    }
}
