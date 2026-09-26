pub mod conn_track;
pub mod flow_counters;
pub mod lease;
pub mod nat;
pub mod policy;

#[cfg(all(target_os = "linux", feature = "ebpf-networking"))]
mod linux;
#[cfg(not(all(target_os = "linux", feature = "ebpf-networking")))]
mod stub;

mod loader;

#[cfg(all(target_os = "linux", feature = "ebpf-networking"))]
pub use linux::EbpfProgram;
#[cfg(not(all(target_os = "linux", feature = "ebpf-networking")))]
pub use stub::EbpfProgram;

#[cfg(all(target_os = "linux", feature = "ebpf-networking"))]
pub use linux::{
    Conn5Tuple, ConnEntry, ConnRateState, FlowCounterEntry, FlowEvent, NatEntry, RateLimitDrops,
    SandboxEntry, TcpStateCounts, TokenBucket,
};
#[cfg(not(all(target_os = "linux", feature = "ebpf-networking")))]
pub use stub::{
    Conn5Tuple, ConnEntry, ConnRateState, FlowCounterEntry, FlowEvent, NatEntry, RateLimitDrops,
    SandboxEntry, TcpStateCounts, TokenBucket,
};

pub use conn_track::ConnTrackManager;
pub use flow_counters::FlowCounterManager;
pub use lease::EbpfLeaseManager;
pub use loader::EbpfLoader;
pub use nat::EbpfNatManager;
pub use policy::EbpfPolicyManager;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::error::{NetworkAgentError, NetworkResult};
use crate::identity::SandboxNetworkIdentity;

pub struct EbpfManager {
    active_programs: Arc<RwLock<HashMap<String, EbpfAttachment>>>,
    pub policy_manager: EbpfPolicyManager,
    pub nat_manager: EbpfNatManager,
    pub conn_track_manager: ConnTrackManager,
    pub lease_manager: EbpfLeaseManager,
    pub flow_counter_manager: FlowCounterManager,
}

#[expect(dead_code, reason = "fields accessed via HashMap access patterns")]
struct EbpfAttachment {
    sandbox_id: String,
    if_name: String,
    ifindex: u32,
}

impl EbpfManager {
    pub fn new() -> NetworkResult<Self> {
        let loader = EbpfLoader::new()?;
        let policy_manager = EbpfPolicyManager::new(loader.clone());
        let nat_manager = EbpfNatManager::new(loader.clone());
        let conn_track_manager = ConnTrackManager::new(loader.clone());
        let lease_manager = EbpfLeaseManager::new(loader.clone());
        let flow_counter_manager = FlowCounterManager::new(loader);

        Ok(Self {
            active_programs: Arc::new(RwLock::new(HashMap::new())),
            policy_manager,
            nat_manager,
            conn_track_manager,
            lease_manager,
            flow_counter_manager,
        })
    }

    pub fn attach(
        &self,
        identity: &SandboxNetworkIdentity,
        host_ip: Ipv4Addr,
    ) -> NetworkResult<Vec<crate::receipt::ResourceReceipt>> {
        use std::time::Instant;

        let start = Instant::now();
        let mut receipts = Vec::new();
        let host_if_name = identity.host_if_name().to_string();
        let sandbox_id = identity.sandbox_id.clone();

        debug!(
            sandbox_id = %sandbox_id,
            if_name = %host_if_name,
            host_ip = %host_ip,
            "attaching eBPF XDP and TC programs"
        );

        let ifindex = self
            .policy_manager
            .loader()
            .get_ifindex(&host_if_name)
            .map_err(|e| NetworkAgentError::EbpfAttachFailed {
                if_name: host_if_name.clone(),
                detail: e.to_string(),
            })?;

        {
            let mut programs = self.active_programs.write();
            if programs.contains_key(&sandbox_id) {
                return Err(NetworkAgentError::EbpfAttachFailed {
                    if_name: host_if_name.clone(),
                    detail: "eBPF program already attached for this sandbox".into(),
                });
            }

            self.policy_manager
                .loader()
                .attach_xdp(&host_if_name)
                .map_err(|e| NetworkAgentError::EbpfAttachFailed {
                    if_name: host_if_name.clone(),
                    detail: e.to_string(),
                })?;

            programs.insert(
                sandbox_id.clone(),
                EbpfAttachment {
                    sandbox_id: sandbox_id.clone(),
                    if_name: host_if_name.clone(),
                    ifindex,
                },
            );
        }

        let host_ip_be = u32::from_be_bytes(host_ip.octets());
        let guest_ip_be = u32::from_be_bytes(identity.guest_ip.octets());

        self.policy_manager
            .loader()
            .insert_sandbox_entry(ifindex, guest_ip_be, host_ip_be)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        let latency = start.elapsed();

        receipts.push(crate::receipt::ResourceReceipt {
            sandbox_id: sandbox_id.clone(),
            resource_name: format!("ebpf-xdp-{host_if_name}"),
            kind: crate::receipt::ResourceKind::EbpF,
            created: true,
            provision_latency: latency,
        });

        info!(
            sandbox_id = %sandbox_id,
            if_name = %host_if_name,
            ifindex = ifindex,
            latency_ms = latency.as_millis(),
            "eBPF XDP program attached"
        );

        Ok(receipts)
    }

    pub fn detach(
        &self,
        sandbox_id: &str,
        if_name: &str,
    ) -> NetworkResult<Vec<crate::receipt::ResourceReceipt>> {
        use std::time::Instant;

        let start = Instant::now();
        let mut receipts = Vec::new();

        debug!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            "detaching eBPF programs"
        );

        let ifindex = {
            let mut programs = self.active_programs.write();
            let removed = programs.remove(sandbox_id);
            if let Some(attachment) = removed {
                self.policy_manager
                    .loader()
                    .detach_xdp(if_name)
                    .map_err(|e| NetworkAgentError::EbpfDetachFailed {
                        if_name: if_name.to_string(),
                        detail: e.to_string(),
                    })?;
                Some(attachment.ifindex)
            } else {
                debug!(
                    sandbox_id = %sandbox_id,
                    "no active eBPF program found for detach"
                );
                None
            }
        };

        if let Some(real_ifindex) = ifindex {
            self.policy_manager
                .remove_sandbox(sandbox_id, real_ifindex)
                .map_err(|e| NetworkAgentError::EbpfMapError {
                    detail: e.to_string(),
                })?;
            let _ = self.policy_manager.loader().gc_connections(real_ifindex);
            let _ = self.policy_manager.loader().gc_nat_entries(real_ifindex);
            let _ = self.flow_counter_manager.cleanup(real_ifindex);
        }

        let latency = start.elapsed();

        receipts.push(crate::receipt::ResourceReceipt {
            sandbox_id: sandbox_id.to_string(),
            resource_name: format!("ebpf-xdp-{if_name}"),
            kind: crate::receipt::ResourceKind::EbpF,
            created: false,
            provision_latency: latency,
        });

        info!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            latency_ms = latency.as_millis(),
            "eBPF programs detached"
        );

        Ok(receipts)
    }

    pub fn update_rate_limits(
        &self,
        sandbox_id: &str,
        bandwidth_bps: u64,
        max_conns: u32,
        max_pps: u32,
        max_conn_rate_per_sec: u32,
    ) -> NetworkResult<()> {
        let programs = self.active_programs.read();
        let attachment =
            programs
                .get(sandbox_id)
                .ok_or_else(|| NetworkAgentError::EbpfMapError {
                    detail: format!("no active eBPF program for sandbox {sandbox_id}"),
                })?;

        self.policy_manager
            .update_rate_limits(
                sandbox_id,
                attachment.ifindex,
                bandwidth_bps,
                max_conns,
                max_pps,
                max_conn_rate_per_sec,
            )
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        info!(
            sandbox_id = %sandbox_id,
            bandwidth_bps = bandwidth_bps,
            max_conns = max_conns,
            max_pps = max_pps,
            max_conn_rate = max_conn_rate_per_sec,
            "eBPF rate limits updated"
        );

        Ok(())
    }

    pub fn collect_rate_limit_drops(&self, sandbox_id: &str) -> NetworkResult<RateLimitDrops> {
        let programs = self.active_programs.read();
        let attachment =
            programs
                .get(sandbox_id)
                .ok_or_else(|| NetworkAgentError::EbpfMapError {
                    detail: format!("no active eBPF program for sandbox {sandbox_id}"),
                })?;

        self.policy_manager
            .loader()
            .collect_rate_limit_drops(attachment.ifindex)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })
    }

    pub fn reconcile_conn_count(&self, sandbox_id: &str) -> NetworkResult<u32> {
        let programs = self.active_programs.read();
        let attachment =
            programs
                .get(sandbox_id)
                .ok_or_else(|| NetworkAgentError::EbpfMapError {
                    detail: format!("no active eBPF program for sandbox {sandbox_id}"),
                })?;

        self.policy_manager
            .reconcile_conn_count(sandbox_id, attachment.ifindex)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })
    }

    pub fn active_sandbox_count(&self) -> usize {
        self.active_programs.read().len()
    }

    pub fn get_attachment_ifindex(&self, sandbox_id: &str) -> Option<u32> {
        self.active_programs
            .read()
            .get(sandbox_id)
            .map(|a| a.ifindex)
    }

    pub fn get_attachment_ifname(&self, sandbox_id: &str) -> Option<String> {
        self.active_programs
            .read()
            .get(sandbox_id)
            .map(|a| a.if_name.clone())
    }

    pub fn collect_flow_telemetry(
        &self,
        sandbox_id: &str,
    ) -> NetworkResult<(FlowCounterEntry, TcpStateCounts)> {
        let programs = self.active_programs.read();
        let attachment =
            programs
                .get(sandbox_id)
                .ok_or_else(|| NetworkAgentError::EbpfMapError {
                    detail: format!("no active eBPF program for sandbox {sandbox_id}"),
                })?;

        let counters = self
            .flow_counter_manager
            .collect(attachment.ifindex)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        let tcp_state = self
            .flow_counter_manager
            .tcp_state_counts(attachment.ifindex)
            .map_err(|e| NetworkAgentError::EbpfMapError {
                detail: e.to_string(),
            })?;

        Ok((counters, tcp_state))
    }
}
