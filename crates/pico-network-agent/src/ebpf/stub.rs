#[derive(Copy, Clone)]
pub struct SandboxEntry {}

#[derive(Copy, Clone)]
pub struct Conn5Tuple {}

#[derive(Copy, Clone)]
pub struct ConnEntry {}

#[derive(Copy, Clone)]
pub struct TokenBucket {}

#[derive(Copy, Clone)]
pub struct NatEntry {}

#[derive(Copy, Clone)]
pub struct ConnRateState {}

#[derive(Copy, Clone, Debug)]
pub struct FlowCounterEntry {
    pub egress_bytes: u64,
    pub egress_packets: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct TcpStateCounts {
    pub syn_sent: u32,
    pub established: u32,
    pub fin_wait: u32,
    pub reset: u32,
    pub total: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct FlowEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
    pub start_ns: u64,
    pub end_ns: u64,
    pub ifindex: u32,
    pub byte_count: u64,
    pub packet_count: u64,
}

#[derive(Copy, Clone, Default)]
pub struct RateLimitDrops {
    pub bw_drops: u64,
    pub pps_drops: u64,
    pub conn_drops: u64,
    pub conn_rate_drops: u64,
    pub nat_drops: u64,
}

impl RateLimitDrops {
    pub fn total_drops(&self) -> u64 {
        0
    }
}

pub struct EbpfProgram;

impl EbpfProgram {
    pub fn load() -> Result<Self, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn get_ifindex(&self, _if_name: &str) -> Result<u32, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn attach_xdp(&mut self, _if_name: &str) -> Result<u32, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn detach_xdp(&mut self, _if_name: &str) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn attach_tc_nat(&mut self, _if_name: &str) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn detach_tc_nat(&mut self, _if_name: &str) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn insert_sandbox_entry(
        &mut self,
        _ifindex: u32,
        _guest_ip: u32,
        _host_ip: u32,
    ) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn update_rate_limits(
        &mut self,
        _ifindex: u32,
        _bandwidth_bps: u64,
        _max_conns: u32,
        _max_pps: u32,
        _max_conn_rate_per_sec: u32,
    ) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn update_host_ip(&mut self, _ifindex: u32, _host_ip: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn remove_sandbox_entry(&mut self, _ifindex: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn collect_rate_limit_drops(&mut self, _ifindex: u32) -> Result<RateLimitDrops, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn reconcile_conn_count(&mut self, _ifindex: u32) -> Result<u32, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn gc_connections(&mut self, _ifindex: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn gc_nat_entries(&mut self, _ifindex: u32) -> Result<usize, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn gc_stale_nat_entries(
        &mut self,
        _ifindex: u32,
        _max_idle_ns: u64,
    ) -> Result<usize, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn nat_entry_count(&self, _ifindex: u32) -> Result<u32, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn insert_allow_entry(&mut self, _dst_ip: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn remove_allow_entry(&mut self, _dst_ip: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn collect_flow_counters(&mut self, _ifindex: u32) -> Result<FlowCounterEntry, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn collect_tcp_state_counts(&mut self, _ifindex: u32) -> Result<TcpStateCounts, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn gc_flow_counters(&mut self, _ifindex: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn gc_tcp_state_counts(&mut self, _ifindex: u32) -> Result<(), String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn reconcile_tcp_state_counts(&mut self, _ifindex: u32) -> Result<TcpStateCounts, String> {
        Err("eBPF networking not available on this platform".into())
    }

    pub fn iter_flow_events(&mut self) -> impl Iterator<Item = FlowEvent> {
        std::iter::empty()
    }
}
