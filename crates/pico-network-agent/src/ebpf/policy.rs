use std::net::Ipv4Addr;

use tracing::debug;

use super::loader::EbpfLoader;

pub struct EbpfPolicyManager {
    loader: EbpfLoader,
}

impl EbpfPolicyManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }

    pub fn insert_sandbox(
        &self,
        sandbox_id: &str,
        guest_ip: Ipv4Addr,
        host_ip: Ipv4Addr,
        ifindex: u32,
    ) -> Result<(), String> {
        let guest_ip_be = u32::from_be_bytes(guest_ip.octets());
        let host_ip_be = u32::from_be_bytes(host_ip.octets());

        debug!(
            sandbox_id = %sandbox_id,
            ifindex = ifindex,
            guest_ip = %guest_ip,
            host_ip = %host_ip,
            "inserting eBPF sandbox entry"
        );

        self.loader
            .insert_sandbox_entry(ifindex, guest_ip_be, host_ip_be)
    }

    pub fn remove_sandbox(&self, sandbox_id: &str, ifindex: u32) -> Result<(), String> {
        debug!(
            sandbox_id = %sandbox_id,
            ifindex = ifindex,
            "removing eBPF sandbox entry"
        );

        self.loader.remove_sandbox_entry(ifindex)
    }

    pub fn update_rate_limits(
        &self,
        sandbox_id: &str,
        ifindex: u32,
        bandwidth_bps: u64,
        max_conns: u32,
        max_pps: u32,
        max_conn_rate_per_sec: u32,
    ) -> Result<(), String> {
        debug!(
            sandbox_id = %sandbox_id,
            ifindex = ifindex,
            bandwidth_bps = bandwidth_bps,
            max_conns = max_conns,
            max_pps = max_pps,
            max_conn_rate = max_conn_rate_per_sec,
            "updating eBPF rate limits"
        );

        self.loader.update_rate_limits(
            ifindex,
            bandwidth_bps,
            max_conns,
            max_pps,
            max_conn_rate_per_sec,
        )
    }

    pub fn reconcile_conn_count(&self, sandbox_id: &str, ifindex: u32) -> Result<u32, String> {
        let count = self.loader.reconcile_conn_count(ifindex)?;
        debug!(
            sandbox_id = %sandbox_id,
            ifindex = ifindex,
            actual_count = count,
            "reconciled eBPF connection count"
        );
        Ok(count)
    }

    pub fn insert_allowed_cidrs(
        &self,
        _sandbox_id: &str,
        allowed_cidrs: &[String],
    ) -> Result<(), String> {
        for cidr in allowed_cidrs {
            if let Some(addr) = parse_exact_ip(cidr) {
                let addr_be = u32::from_be_bytes(addr.octets());
                self.loader.insert_allow_entry(addr_be)?;
            }
        }
        Ok(())
    }

    pub fn remove_allowed_cidrs(
        &self,
        _sandbox_id: &str,
        allowed_cidrs: &[String],
    ) -> Result<(), String> {
        for cidr in allowed_cidrs {
            if let Some(addr) = parse_exact_ip(cidr) {
                let addr_be = u32::from_be_bytes(addr.octets());
                self.loader.remove_allow_entry(addr_be)?;
            }
        }
        Ok(())
    }
}

fn parse_exact_ip(cidr: &str) -> Option<Ipv4Addr> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix != 32 {
        return None;
    }
    Some(addr)
}
