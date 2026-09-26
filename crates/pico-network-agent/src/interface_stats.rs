//! Per-sandbox interface byte/packet counter collection.
//!
//! Reads accumulated RX/TX byte and packet counters from rtnetlink
//! link stats where the backend supports them. Labels use sandbox_id,
//! if_name, and backend dimensions - all tenant-safe, hash-derived values.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use tokio_stream::StreamExt;
use tracing::debug;

use crate::identity::SandboxNetworkIdentity;
use crate::metrics::{self, SandboxScope};
use crate::netlink::Handle;

/// Read link-layer statistics for a sandbox interface and emit metrics.
///
/// Collects `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets` from
/// rtnetlink `IFLA_STATS64` or `IFLA_STATS`. If the interface does not
/// exist or the counters are unavailable (e.g., on non-Linux), the
/// function is a no-op.
///
/// `tenant_id` is used for label redaction when `shared_host_metric_redaction`
/// is enabled.
#[cfg(target_os = "linux")]
pub async fn collect_interface_stats(
    identity: &SandboxNetworkIdentity,
    handle: &Handle,
    tenant_id: Option<&str>,
) {
    let if_name = identity.if_name_for_stats();
    let sandbox_id = &identity.sandbox_id;
    let backend = identity.backend_class.as_str();

    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();

    let Some(Ok(link)) = links.next().await else {
        debug!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            "interface not found during stats collection"
        );
        return;
    };

    // Search link attributes for IFLA_STATS64 or IFLA_STATS
    let (rx_bytes, tx_bytes, rx_packets, tx_packets) = extract_link_stats(&link.attributes);

    metrics::record_interface_stats(
        SandboxScope {
            sandbox_id,
            tenant_id,
        },
        if_name,
        backend,
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
    );
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub async fn collect_interface_stats(
    _identity: &SandboxNetworkIdentity,
    _handle: &Handle,
    _tenant_id: Option<&str>,
) {
    // No-op on non-Linux — interface counters require rtnetlink.
}

/// Extract accumulated byte/packet counters from rtnetlink link attributes.
///
/// Prefers `IFLA_STATS64` (64-bit counters) over `IFLA_STATS` (32-bit)
/// to avoid overflow on high-traffic interfaces. Returns zero for all
/// counters if neither attribute is present.
#[cfg(target_os = "linux")]
fn extract_link_stats(
    attrs: &[rtnetlink::packet_route::link::LinkAttribute],
) -> (u64, u64, u64, u64) {
    use rtnetlink::packet_route::link::LinkAttribute;

    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut found = false;

    for attr in attrs {
        match attr {
            LinkAttribute::Stats64(stats) => {
                rx_bytes = stats.rx_bytes;
                tx_bytes = stats.tx_bytes;
                rx_packets = stats.rx_packets;
                tx_packets = stats.tx_packets;
                found = true;
            }
            LinkAttribute::Stats(stats) if !found => {
                // Fall back to 32-bit counters only if Stats64 was not found
                rx_bytes = u64::from(stats.rx_bytes);
                tx_bytes = u64::from(stats.tx_bytes);
                rx_packets = u64::from(stats.rx_packets);
                tx_packets = u64::from(stats.tx_packets);
                found = true;
            }
            _ => {}
        }
    }

    (rx_bytes, tx_bytes, rx_packets, tx_packets)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn extract_link_stats_empty_returns_zero() {
        let attrs: Vec<rtnetlink::packet_route::link::LinkAttribute> = vec![];
        let (rx_bytes, tx_bytes, rx_packets, tx_packets) = extract_link_stats(&attrs);
        assert_eq!(rx_bytes, 0);
        assert_eq!(tx_bytes, 0);
        assert_eq!(rx_packets, 0);
        assert_eq!(tx_packets, 0);
    }
}
