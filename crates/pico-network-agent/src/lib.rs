//! PicoCompute Network Agent -- per-sandbox TAP, veth, namespace, route, DNS proxy, and cleanup.
//!
//! The network-agent is the compute-host component responsible for creating
//! and destroying network objects on behalf of sandboxes. It implements the
//! bounded provisioning model defined by ADR-0005 and hosts the per-cell
//! DNS policy proxy for sandbox name resolution.
//!
//! # Architecture
//!
//! - **identity** -- deterministic resource naming from sandbox IDs (fnv1a64).
//! - **tap** -- TAP device provisioning for microVM backends.
//! - **veth** -- veth pair + netns provisioning for container backends.
//! - **route** -- default route installation for NAT/DNS policy path.
//! - **egress** -- nftables egress policy enforcement.
//! - **nat** -- SNAT/masquerade for outbound sandbox traffic.
//! - **nftables** -- typed client wrapping the `nft` CLI.
//! - **receipt** -- typed receipts for durable reconciliation.
//! - **cleanup** -- idempotent teardown, partial rollback, stale detection.
//! - **dns** -- policy-aware DNS proxy: hickory-based UDP/TCP server,
//!   domain/suffix allow-deny, upstream resolution, TTL-bounded cache,
//!   deterministic NXDOMAIN for denied queries, audit event emission.
//! - **dns_attachment** -- nftables prerouting redirect for sandbox DNS
//!   traffic to the proxy listener.
//! - **ebpf** -- eBPF XDP/TC classifier for hardware-accelerated sandbox
//!   network policy: anti-spoofing, deny-by-default, allow-list
//!   per sandbox, behind the `ebpf-networking` feature flag.
//! - **lifecycle** -- network lifecycle semantics for suspend, resume, and
//!   fork: policy epoch validation, identity independence, and
//!   port-forwarding inheritance blocking.
//! - **mirror_policy** -- package-mirror policy classes (PyPI/NPM/Go proxy)
//!   via DNS proxy plus lease model, with dynamic per-stage updates.
//! - **reconciliation** -- stale resource detection, safe cleanup, and
//!   host health assessment after host-agent restart.
//! - **error** -- `thiserror` error types.
//!
//! # Platform Support
//!
//! Provisioning modules are `#[cfg(target_os = "linux")]` gated. Non-Linux
//! platforms return `NetworkAgentError::UnsupportedPlatform`.

pub mod bandwidth;
pub mod cleanup;
pub mod dns;
pub mod dns_attachment;
pub mod ebpf;
pub mod egress;
pub mod error;
pub mod flow_telemetry;
pub mod identity;
pub mod interface_stats;
pub mod lifecycle;
pub mod metrics;
pub mod mirror_policy;
pub mod nat;
pub mod netlink;
pub mod nftables;
pub mod receipt;
pub mod reconciliation;
pub mod route;
pub mod tap;
pub mod veth;

use std::time::Instant;

use crate::netlink::Handle;
use tracing::warn;

use crate::bandwidth::{
    BandwidthLimit, deprovision_bandwidth, provision_bandwidth, update_bandwidth,
};
use crate::cleanup::{cleanup, rollback};
use crate::dns_attachment::{
    DnsAttachmentConfig, deprovision_dns_attachment, provision_dns_attachment,
};
use crate::egress::{EgressPolicy, deprovision_egress, provision_egress};
#[cfg(feature = "ebpf-networking")]
use crate::error::NetworkAgentError;
use crate::error::NetworkResult;
use crate::identity::{BackendClass, SandboxNetworkIdentity};
use crate::nat::{NatConfig, deprovision_nat, provision_nat};
use crate::receipt::{CleanupReceipt, ProvisionReceipt, ResourceReceipt};
use crate::route::provision_default_route;
use crate::tap::provision_tap;
use crate::veth::provision_veth;
#[cfg(feature = "ebpf-networking")]
use std::net::Ipv4Addr;

pub fn init_seccomp() {
    use pico_seccomp::{CapabilitySet, ComponentProfile};
    use tracing::info;

    info!("initializing seccomp and capability minimization for network-agent");

    let _ = pico_seccomp::init_profile_for_component_with_strictness(
        ComponentProfile::NetworkAgent,
        &CapabilitySet::network_agent(),
        true,
        false,
    );
}

/// Type alias for the netlink connection join handle.
pub type ConnectionHandle = tokio::task::JoinHandle<()>;

/// Optional policy attachments applied after TAP/veth/route.
///
/// Callers that only need base connectivity leave this at [`Default`].
#[derive(Debug, Clone, Default)]
pub struct ProvisionExtras {
    /// nftables egress policy installed after the sandbox interface exists.
    pub egress: Option<crate::egress::EgressPolicy>,
    /// SNAT/masquerade configuration installed after egress.
    pub nat: Option<crate::nat::NatConfig>,
    /// DNS prerouting redirect installed last so policy is in place before use.
    pub dns: Option<DnsAttachmentConfig>,
}

/// The NetworkAgent is the main entry point for provisioning and cleanup.
///
/// It abstracts over backend class (microVM vs container) to provision the
/// correct set of network objects from a single `SandboxNetworkIdentity`.
pub struct NetworkAgent;

impl NetworkAgent {
    /// Provision all required network objects for a sandbox.
    ///
    /// Returns a `ProvisionReceipt` containing receipts for every created
    /// resource, or an error. On partial failure, a rollback is performed
    /// before the error is returned.
    #[tracing::instrument(skip(identity, handle), fields(sandbox_id = %identity.sandbox_id, backend_class = ?identity.backend_class))]
    pub async fn provision(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
    ) -> NetworkResult<ProvisionReceipt> {
        let start = Instant::now();

        let total_attempted = match identity.backend_class {
            BackendClass::MicroVm => 4,   // tap, link_up, address, route
            BackendClass::Container => 9, // ns, veth, ns_move, guest_addr, host_addr, guest_up, host_up, route
        };

        let mut provision_receipt = ProvisionReceipt::new(
            identity.sandbox_id.clone(),
            identity.backend_class,
            total_attempted,
        );

        let backend_result = match identity.backend_class {
            BackendClass::MicroVm => {
                Self::provision_microvm(identity, handle, &mut provision_receipt).await
            }
            BackendClass::Container => {
                Self::provision_container(identity, handle, &mut provision_receipt).await
            }
        };

        match backend_result {
            Ok(()) => {
                // Add routes -- if route provisioning fails, roll back the backend resources
                match provision_default_route(identity, handle).await {
                    Ok(route_receipts) => {
                        for r in route_receipts {
                            provision_receipt.push(r);
                        }
                    }
                    Err(err) => {
                        warn!(sandbox_id = %identity.sandbox_id, error = %err, "route provisioning failed, rolling back");
                        rollback(identity, handle, &provision_receipt.resources).await;
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                warn!(sandbox_id = %identity.sandbox_id, error = %err, "backend provisioning failed, rolling back");
                rollback(identity, handle, &provision_receipt.resources).await;
                return Err(err);
            }
        }

        provision_receipt.finalize(start.elapsed());
        Ok(provision_receipt)
    }

    /// Ordered per-sandbox pipeline: TAP/veth/route, then egress, NAT, DNS.
    ///
    /// This is the only method sandboxd should call for host network creation.
    /// On any extra-step failure, already-created resources are rolled back.
    #[tracing::instrument(skip(identity, handle, extras), fields(sandbox_id = %identity.sandbox_id, backend_class = ?identity.backend_class))]
    pub async fn provision_all(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
        extras: &ProvisionExtras,
    ) -> NetworkResult<ProvisionReceipt> {
        let start = Instant::now();
        let mut provision_receipt = Self::provision(identity, handle).await?;

        if let Some(policy) = &extras.egress {
            match Self::provision_egress(policy).await {
                Ok(receipts) => {
                    provision_receipt.total_attempted += receipts.len();
                    for r in receipts {
                        provision_receipt.push(r);
                    }
                }
                Err(err) => {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "egress provisioning failed, rolling back");
                    rollback(identity, handle, &provision_receipt.resources).await;
                    return Err(err);
                }
            }
        }

        if let Some(config) = &extras.nat {
            match Self::provision_nat(config).await {
                Ok(receipts) => {
                    provision_receipt.total_attempted += receipts.len();
                    for r in receipts {
                        provision_receipt.push(r);
                    }
                }
                Err(err) => {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "NAT provisioning failed, rolling back");
                    rollback(identity, handle, &provision_receipt.resources).await;
                    return Err(err);
                }
            }
        }

        if let Some(config) = &extras.dns {
            match Self::provision_dns_attachment(config).await {
                Ok(receipts) => {
                    provision_receipt.total_attempted += receipts.len();
                    for r in receipts {
                        provision_receipt.push(r);
                    }
                }
                Err(err) => {
                    warn!(sandbox_id = %identity.sandbox_id, error = %err, "DNS attachment failed, rolling back");
                    rollback(identity, handle, &provision_receipt.resources).await;
                    return Err(err);
                }
            }
        }

        provision_receipt.finalize(start.elapsed());
        Ok(provision_receipt)
    }

    async fn provision_microvm(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
        provision_receipt: &mut ProvisionReceipt,
    ) -> NetworkResult<()> {
        let (tap_fd, tap_receipts) = provision_tap(identity, handle).await?;

        // TAP fd is intentionally dropped here -- the caller (runtime adapter)
        // is responsible for keeping the fd alive. The TAP device is persistent.
        let _ = tap_fd;

        for r in tap_receipts {
            provision_receipt.push(r);
        }

        Ok(())
    }

    async fn provision_container(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
        provision_receipt: &mut ProvisionReceipt,
    ) -> NetworkResult<()> {
        let (_ns_fd, veth_receipts) = provision_veth(identity, handle).await?;

        for r in veth_receipts {
            provision_receipt.push(r);
        }

        Ok(())
    }

    /// Clean up all network resources for a sandbox.
    ///
    /// Cleans up idempotently -- missing resources are silently noted.
    pub async fn deprovision(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
        provision_receipt: Option<&ProvisionReceipt>,
    ) -> CleanupReceipt {
        cleanup(identity, handle, provision_receipt).await
    }

    /// Provision egress policy for a sandbox.
    ///
    /// Creates the nftables table, forward chain, and installs rules
    /// from the given `EgressPolicy`. The caller must have validated
    /// the policy against applicable leases before calling this.
    ///
    /// Must be called after base networking (TAP/veth/route) is
    /// provisioned but before the sandbox network is considered ready.
    pub async fn provision_egress(policy: &EgressPolicy) -> NetworkResult<Vec<ResourceReceipt>> {
        provision_egress(policy).await
    }

    /// Provision NAT/masquerade rules for a sandbox.
    ///
    /// Creates a `snat` chain in the sandbox's nftables table and
    /// installs the SNAT masquerade rule.
    pub async fn provision_nat(config: &NatConfig) -> NetworkResult<Vec<ResourceReceipt>> {
        provision_nat(config).await
    }

    /// Deprovision NAT/masquerade rules for a sandbox.
    ///
    /// Flushes the `snat` chain. Idempotent.
    pub async fn deprovision_nat(
        sandbox_id: &str,
        if_name: &str,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        deprovision_nat(sandbox_id, if_name).await
    }

    /// Deprovision egress policy for a sandbox.
    ///
    /// Deletes the nftables table. Idempotent.
    pub async fn deprovision_egress(
        sandbox_id: &str,
        if_name: &str,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        deprovision_egress(sandbox_id, if_name).await
    }

    /// Provision DNS attachment for a sandbox.
    ///
    /// Installs nftables prerouting rules that redirect UDP/TCP port 53
    /// traffic from the sandbox interface to the DNS proxy listener.
    /// Must be called after base networking and before the sandbox
    /// network is considered ready.
    pub async fn provision_dns_attachment(
        config: &DnsAttachmentConfig,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        provision_dns_attachment(config).await
    }

    /// Deprovision DNS attachment for a sandbox.
    ///
    /// Removes the prerouting chain. Idempotent.
    pub async fn deprovision_dns_attachment(
        config: &DnsAttachmentConfig,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        deprovision_dns_attachment(config).await
    }

    /// Provision egress bandwidth shaping for a sandbox interface.
    ///
    /// Attaches an HTB qdisc with fq_codel leaf to the host-side
    /// sandbox interface. Must be called after base networking
    /// (TAP/veth/route) is provisioned.
    ///
    /// If `limit.limit_bps` is 0, this is a no-op (unlimited).
    pub async fn provision_bandwidth(
        limit: &BandwidthLimit,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        provision_bandwidth(limit).await
    }

    /// Update the bandwidth limit for an existing sandbox interface.
    ///
    /// Atomically replaces the existing qdisc with a new one at the
    /// updated rate. If `limit.limit_bps` is 0, shaping is removed.
    pub async fn update_bandwidth(limit: &BandwidthLimit) -> NetworkResult<Vec<ResourceReceipt>> {
        update_bandwidth(limit).await
    }

    /// Deprovision bandwidth shaping for a sandbox interface.
    ///
    /// Removes the root qdisc (all child classes and qdiscs).
    /// Idempotent.
    pub async fn deprovision_bandwidth(
        sandbox_id: &str,
        if_name: &str,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        deprovision_bandwidth(sandbox_id, if_name).await
    }

    /// Roll back a partial provisioning.
    ///
    /// Uses the receipts from provisioning to determine which resources were
    /// created and need to be cleaned up. Resources are removed in reverse
    /// creation order.
    pub async fn rollback(
        identity: &SandboxNetworkIdentity,
        handle: &Handle,
        receipts: &[ResourceReceipt],
    ) -> CleanupReceipt {
        rollback(identity, handle, receipts).await
    }

    /// Provision eBPF XDP network policy for a sandbox.
    ///
    /// Attaches an XDP program to the host-side interface with
    /// anti-spoofing and deny-by-default semantics. The allow-list
    /// is populated from the given CIDRs.
    #[cfg(feature = "ebpf-networking")]
    pub async fn provision_ebpf_policy(
        manager: &ebpf::EbpfManager,
        identity: &SandboxNetworkIdentity,
        host_ip: Ipv4Addr,
        allowed_cidrs: &[String],
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        let receipts = manager.attach(identity, host_ip)?;

        manager
            .policy_manager
            .insert_allowed_cidrs(&identity.sandbox_id, allowed_cidrs)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        Ok(receipts)
    }

    /// Provision eBPF-based NAT (TC program) for a sandbox.
    ///
    /// Attaches a TC egress program to the host-side sandbox interface
    /// that performs SNAT/masquerade on outbound traffic.
    #[cfg(feature = "ebpf-networking")]
    pub async fn provision_ebpf_nat(
        manager: &ebpf::EbpfManager,
        identity: &SandboxNetworkIdentity,
        host_ip: Ipv4Addr,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        let ifindex = manager
            .get_attachment_ifindex(&identity.sandbox_id)
            .ok_or_else(|| NetworkAgentError::EbpfMapError {
                detail: format!(
                    "no active eBPF attachment for sandbox {}",
                    identity.sandbox_id
                ),
            })?;

        manager.nat_manager.provision_nat(
            &identity.sandbox_id,
            &identity.host_if_name,
            host_ip,
            ifindex,
        )
    }

    /// Deprovision eBPF-based NAT for a sandbox.
    ///
    /// Detaches the TC egress NAT program and cleans up NAT map entries.
    ///
    /// `tenant_id` attributes the `network.nat.sessions` gauge, which is keyed
    /// by tenant rather than sandbox on shared hosts. `SandboxNetworkIdentity`
    /// has no tenant field, so the caller supplies it.
    #[cfg(feature = "ebpf-networking")]
    pub async fn deprovision_ebpf_nat(
        manager: &ebpf::EbpfManager,
        identity: &SandboxNetworkIdentity,
        tenant_id: Option<&str>,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        let ifindex = match manager.get_attachment_ifindex(&identity.sandbox_id) {
            Some(idx) => idx,
            None => {
                return Ok(Vec::new());
            }
        };

        manager.nat_manager.deprovision_nat(
            &identity.sandbox_id,
            tenant_id,
            &identity.host_if_name,
            ifindex,
        )
    }

    /// Apply lease-based egress CIDRs to the BPF allow map.
    ///
    /// Expands CIDRs to individual IPs and inserts them into ALLOW_MAP.
    #[cfg(feature = "ebpf-networking")]
    pub fn apply_ebpf_lease_cidrs(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        cidrs: &[String],
    ) -> NetworkResult<usize> {
        manager.lease_manager.apply_lease_cidrs(sandbox_id, cidrs)
    }

    /// Remove lease-based egress CIDRs from the BPF allow map.
    #[cfg(feature = "ebpf-networking")]
    pub fn remove_ebpf_lease_cidrs(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        cidrs: &[String],
    ) -> NetworkResult<usize> {
        manager.lease_manager.remove_lease_cidrs(sandbox_id, cidrs)
    }

    /// Atomically replace lease-based egress CIDRs in the BPF allow map.
    #[cfg(feature = "ebpf-networking")]
    pub fn replace_ebpf_lease_cidrs(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        old_cidrs: &[String],
        new_cidrs: &[String],
    ) -> NetworkResult<(usize, usize)> {
        manager
            .lease_manager
            .replace_lease_cidrs(sandbox_id, old_cidrs, new_cidrs)
    }

    /// Apply DNS-resolved IPs to the BPF allow map for a sandbox.
    ///
    /// Used by the DNS proxy to dynamically add allowed IPs when a domain
    /// is resolved and the policy permits it.
    #[cfg(feature = "ebpf-networking")]
    pub fn apply_ebpf_dns_ips(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        resolved_ips: &[Ipv4Addr],
    ) -> NetworkResult<usize> {
        manager
            .lease_manager
            .apply_dns_resolved_ips(sandbox_id, resolved_ips)
    }

    /// Remove DNS-resolved IPs from the BPF allow map.
    #[cfg(feature = "ebpf-networking")]
    pub fn remove_ebpf_dns_ips(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        resolved_ips: &[Ipv4Addr],
    ) -> NetworkResult<usize> {
        manager
            .lease_manager
            .remove_dns_resolved_ips(sandbox_id, resolved_ips)
    }

    /// Deprovision eBPF XDP network policy for a sandbox.
    ///
    /// Removes the XDP program and cleans up map entries.
    #[cfg(feature = "ebpf-networking")]
    pub async fn deprovision_ebpf_policy(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        if_name: &str,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        manager.detach(sandbox_id, if_name)
    }

    /// Update eBPF allow-list for a sandbox.
    ///
    /// Removes old allowed CIDRs from the map and inserts new ones.
    #[cfg(feature = "ebpf-networking")]
    pub async fn update_ebpf_policy(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        old_cidrs: &[String],
        new_cidrs: &[String],
    ) -> NetworkResult<()> {
        manager
            .policy_manager
            .remove_allowed_cidrs(sandbox_id, old_cidrs)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        manager
            .policy_manager
            .insert_allowed_cidrs(sandbox_id, new_cidrs)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        Ok(())
    }

    /// Update eBPF rate limits for an active sandbox without reloading the XDP program.
    ///
    /// Performs a single BPF map insert (upsert) to update the bandwidth,
    /// connection, PPS, and connection rate limits in the running eBPF program.
    #[cfg(feature = "ebpf-networking")]
    /// `tenant_id` attributes the two rate-limit gauges, which are keyed by
    /// tenant rather than sandbox on shared hosts.
    pub async fn update_ebpf_rate_limits(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
        bandwidth_bps: u64,
        max_conns: u32,
        max_pps: u32,
        max_conn_rate_per_sec: u32,
    ) -> NetworkResult<()> {
        manager.update_rate_limits(
            scope.sandbox_id,
            bandwidth_bps,
            max_conns,
            max_pps,
            max_conn_rate_per_sec,
        )?;
        metrics::record_ratelimit_configured(scope, bandwidth_bps);
        metrics::record_ratelimit_active_connections(scope, u64::from(max_conns));
        Ok(())
    }

    /// Collect and reset eBPF rate-limit drop counters for a sandbox.
    ///
    /// Call periodically (every 5-30s per active sandbox, or from the
    /// network agent's reconciliation/metrics loop) to export drop counters
    /// to OpenTelemetry. The counters are atomically read and reset to zero
    /// in the BPF map.
    #[cfg(feature = "ebpf-networking")]
    /// `scope` attributes the drop counters, which are keyed by tenant rather
    /// than sandbox on shared hosts.
    pub async fn collect_ebpf_rate_limit_drops(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
    ) -> NetworkResult<ebpf::RateLimitDrops> {
        let drops = manager.collect_rate_limit_drops(scope.sandbox_id)?;
        metrics::record_ratelimit_drops(
            scope,
            &metrics::RateLimitDrops {
                bw_drops: drops.bw_drops,
                pps_drops: drops.pps_drops,
                conn_drops: drops.conn_drops,
                conn_rate_drops: drops.conn_rate_drops,
                nat_drops: drops.nat_drops,
            },
        );
        Ok(drops)
    }

    /// Reconcile the eBPF connection count by scanning CONN_MAP for the sandbox's ifindex.
    ///
    /// Connection counting in the XDP hot path is approximate (conn_count is only
    /// incremented, never decremented). LRU eviction and connection teardown cause
    /// drift. Call this every 5-30s per active sandbox to correct the count.
    ///
    /// Iterates the full CONN_MAP (up to 65k entries), so avoid calling it on
    /// every packet or connection attempt. Suitable for periodic reconciliation
    /// loops, high-drop-rate events, or sandbox resume lifecycle hooks.
    #[cfg(feature = "ebpf-networking")]
    /// `scope` attributes the active-connection gauge, which is keyed by tenant
    /// rather than sandbox on shared hosts.
    pub async fn reconcile_ebpf_conn_count(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
    ) -> NetworkResult<u32> {
        let count = manager.reconcile_conn_count(scope.sandbox_id)?;
        metrics::record_active_connections(scope, u64::from(count));
        Ok(count)
    }

    /// Reconcile eBPF NAT entries and report the active count.
    ///
    /// Scans NAT_MAP for the sandbox's ifindex and reports the current count
    /// to the `network.nat.active_entries` gauge.
    #[cfg(feature = "ebpf-networking")]
    /// `scope` attributes the NAT active-entries gauge, which is keyed by tenant
    /// rather than sandbox on shared hosts.
    pub async fn reconcile_ebpf_nat_count(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
    ) -> NetworkResult<u32> {
        let ifindex = manager
            .get_attachment_ifindex(scope.sandbox_id)
            .ok_or_else(|| NetworkAgentError::EbpfMapError {
                detail: format!("no active eBPF attachment for sandbox {}", scope.sandbox_id),
            })?;
        let count = manager.conn_track_manager.nat_active_count(ifindex)?;
        metrics::record_nat_active_entries(scope, count as u64);
        Ok(count)
    }

    /// GC stale eBPF NAT entries older than the given idle duration.
    ///
    /// Only removes entries whose last_seen_ns is older than max_idle_secs.
    #[cfg(feature = "ebpf-networking")]
    pub async fn gc_ebpf_stale_nat_entries(
        manager: &ebpf::EbpfManager,
        sandbox_id: &str,
        max_idle_secs: u64,
    ) -> NetworkResult<usize> {
        let ifindex = manager.get_attachment_ifindex(sandbox_id).ok_or_else(|| {
            NetworkAgentError::EbpfMapError {
                detail: format!("no active eBPF attachment for sandbox {sandbox_id}"),
            }
        })?;
        manager
            .conn_track_manager
            .gc_stale_nat_entries(ifindex, max_idle_secs)
    }

    #[cfg(feature = "ebpf-networking")]
    /// `scope` attributes the flow counters and TCP gauges, which are keyed by
    /// tenant rather than sandbox on shared hosts.
    pub async fn collect_ebpf_flow_telemetry(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
    ) -> NetworkResult<(ebpf::FlowCounterEntry, ebpf::TcpStateCounts)> {
        let (counters, tcp_state) =
            crate::flow_telemetry::FlowTelemetryCollector::collect_per_sandbox(
                manager,
                scope.sandbox_id,
            )?;

        metrics::record_egress_counters(
            scope,
            &metrics::EgressCounters {
                egress_bytes: counters.egress_bytes,
                egress_packets: counters.egress_packets,
            },
        );
        metrics::record_tcp_state(
            scope,
            &metrics::TcpStateCounts {
                syn_sent: tcp_state.syn_sent,
                established: tcp_state.established,
                fin_wait: tcp_state.fin_wait,
                reset: tcp_state.reset,
                total: tcp_state.total,
            },
        );

        Ok((counters, tcp_state))
    }

    /// `scope` attributes the TCP gauges, which are keyed by tenant rather than
    /// sandbox on shared hosts.
    #[cfg(feature = "ebpf-networking")]
    pub async fn reconcile_ebpf_tcp_state_counts(
        manager: &ebpf::EbpfManager,
        scope: metrics::SandboxScope<'_>,
    ) -> NetworkResult<ebpf::TcpStateCounts> {
        let ifindex = manager
            .get_attachment_ifindex(scope.sandbox_id)
            .ok_or_else(|| NetworkAgentError::EbpfMapError {
                detail: format!("no active eBPF attachment for sandbox {}", scope.sandbox_id),
            })?;

        let counts = manager
            .flow_counter_manager
            .reconcile_tcp_state_counts(ifindex)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        metrics::record_tcp_state_counts(
            scope,
            &metrics::TcpStateCounts {
                syn_sent: counts.syn_sent,
                established: counts.established,
                fin_wait: counts.fin_wait,
                reset: counts.reset,
                total: counts.total,
            },
        );

        Ok(counts)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::NetworkAgent;
    use crate::error::NetworkAgentError;
    use crate::identity::{BackendClass, SandboxNetworkIdentity};

    #[tokio::test]
    async fn unsupported_platform_returns_error() {
        #[cfg(not(target_os = "linux"))]
        {
            let identity = SandboxNetworkIdentity::for_sandbox("test_sbx", BackendClass::MicroVm);
            let (conn, handle) = crate::netlink::new_connection().unwrap();
            tokio::spawn(conn);
            let result = NetworkAgent::provision(&identity, &handle).await;
            assert!(matches!(
                result,
                Err(NetworkAgentError::UnsupportedPlatform)
            ));
            let extras_result =
                NetworkAgent::provision_all(&identity, &handle, &crate::ProvisionExtras::default())
                    .await;
            assert!(matches!(
                extras_result,
                Err(NetworkAgentError::UnsupportedPlatform)
            ));
        }
    }

    #[test]
    fn identity_produces_deterministic_names() {
        let id1 = SandboxNetworkIdentity::for_sandbox("a", BackendClass::MicroVm);
        let id2 = SandboxNetworkIdentity::for_sandbox("a", BackendClass::MicroVm);
        assert_eq!(id1, id2);
    }

    #[test]
    fn microvm_and_container_have_different_identities() {
        let vm = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        let ct = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::Container);
        assert_ne!(vm.host_if_name, ct.host_if_name);
        assert_ne!(vm.backend_class, ct.backend_class);
    }
}
