use std::sync::Arc;

use parking_lot::RwLock;

use super::EbpfProgram;
use super::RateLimitDrops;
use super::{FlowCounterEntry, TcpStateCounts};
use crate::error::NetworkResult;

#[derive(Clone)]
pub struct EbpfLoader {
    inner: Arc<RwLock<EbpfProgram>>,
}

impl EbpfLoader {
    pub fn new() -> NetworkResult<Self> {
        let program =
            EbpfProgram::load().map_err(|e| crate::error::NetworkAgentError::EbpfLoadFailed {
                detail: e.to_string(),
            })?;

        Ok(Self {
            inner: Arc::new(RwLock::new(program)),
        })
    }

    pub fn get_ifindex(&self, if_name: &str) -> Result<u32, String> {
        let program = self.inner.read();
        program.get_ifindex(if_name)
    }

    pub fn attach_xdp(&self, if_name: &str) -> Result<u32, String> {
        let mut program = self.inner.write();
        program.attach_xdp(if_name)
    }

    pub fn detach_xdp(&self, if_name: &str) -> Result<(), String> {
        let mut program = self.inner.write();
        program.detach_xdp(if_name)
    }

    pub fn attach_tc_nat(&self, if_name: &str) -> Result<(), String> {
        let mut program = self.inner.write();
        program.attach_tc_nat(if_name)
    }

    pub fn detach_tc_nat(&self, if_name: &str) -> Result<(), String> {
        let mut program = self.inner.write();
        program.detach_tc_nat(if_name)
    }

    pub fn insert_sandbox_entry(
        &self,
        ifindex: u32,
        guest_ip: u32,
        host_ip: u32,
    ) -> Result<(), String> {
        let mut program = self.inner.write();
        program.insert_sandbox_entry(ifindex, guest_ip, host_ip)
    }

    pub fn update_rate_limits(
        &self,
        ifindex: u32,
        bandwidth_bps: u64,
        max_conns: u32,
        max_pps: u32,
        max_conn_rate_per_sec: u32,
    ) -> Result<(), String> {
        let mut program = self.inner.write();
        program.update_rate_limits(
            ifindex,
            bandwidth_bps,
            max_conns,
            max_pps,
            max_conn_rate_per_sec,
        )
    }

    pub fn update_host_ip(&self, ifindex: u32, host_ip: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.update_host_ip(ifindex, host_ip)
    }

    pub fn remove_sandbox_entry(&self, ifindex: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.remove_sandbox_entry(ifindex)
    }

    pub fn collect_rate_limit_drops(&self, ifindex: u32) -> Result<RateLimitDrops, String> {
        let mut program = self.inner.write();
        program.collect_rate_limit_drops(ifindex)
    }

    pub fn reconcile_conn_count(&self, ifindex: u32) -> Result<u32, String> {
        let mut program = self.inner.write();
        program.reconcile_conn_count(ifindex)
    }

    pub fn gc_connections(&self, ifindex: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.gc_connections(ifindex)
    }

    pub fn gc_nat_entries(&self, ifindex: u32) -> Result<usize, String> {
        let mut program = self.inner.write();
        program.gc_nat_entries(ifindex)
    }

    pub fn gc_stale_nat_entries(&self, ifindex: u32, max_idle_ns: u64) -> Result<usize, String> {
        let mut program = self.inner.write();
        program.gc_stale_nat_entries(ifindex, max_idle_ns)
    }

    pub fn nat_entry_count(&self, ifindex: u32) -> Result<u32, String> {
        let program = self.inner.read();
        program.nat_entry_count(ifindex)
    }

    pub fn insert_allow_entry(&self, dst_ip: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.insert_allow_entry(dst_ip)
    }

    pub fn remove_allow_entry(&self, dst_ip: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.remove_allow_entry(dst_ip)
    }

    pub fn collect_flow_counters(&self, ifindex: u32) -> Result<FlowCounterEntry, String> {
        let mut program = self.inner.write();
        program.collect_flow_counters(ifindex)
    }

    pub fn collect_tcp_state_counts(&self, ifindex: u32) -> Result<TcpStateCounts, String> {
        let mut program = self.inner.write();
        program.collect_tcp_state_counts(ifindex)
    }

    pub fn gc_flow_counters(&self, ifindex: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.gc_flow_counters(ifindex)
    }

    pub fn gc_tcp_state_counts(&self, ifindex: u32) -> Result<(), String> {
        let mut program = self.inner.write();
        program.gc_tcp_state_counts(ifindex)
    }

    pub fn reconcile_tcp_state_counts(&self, ifindex: u32) -> Result<TcpStateCounts, String> {
        let mut program = self.inner.write();
        program.reconcile_tcp_state_counts(ifindex)
    }
}
