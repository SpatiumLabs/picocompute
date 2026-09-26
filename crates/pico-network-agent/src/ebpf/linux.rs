use std::collections::HashMap;

use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf as AyaRingBuf};
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::xdp::XdpLinkId;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, Pod, include_bytes_aligned};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SandboxEntry {
    pub guest_ip: u32,
    pub host_ip: u32,
    pub bandwidth_bps: u64,
    pub max_conns: u32,
    pub max_pps: u32,
    pub max_conn_rate_per_sec: u32,
    pub conn_count: u32,
    pub byte_count: u64,
    pub pps_tokens: u32,
    pub last_ts_ns: u64,
    pub bw_drops: u64,
    pub pps_drops: u64,
    pub conn_drops: u64,
    pub conn_rate_drops: u64,
    pub nat_drops: u64,
}
unsafe impl Pod for SandboxEntry {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Conn5Tuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}
unsafe impl Pod for Conn5Tuple {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnEntry {
    pub last_seen_ns: u64,
    pub ifindex: u32,
    pub state: u8,
    pub _pad: [u8; 3],
    pub start_ns: u64,
    pub byte_count: u64,
    pub packet_count: u64,
}
unsafe impl Pod for ConnEntry {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
}
unsafe impl Pod for TokenBucket {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct NatEntry {
    pub original_src_ip: u32,
    pub original_src_port: u16,
    pub translated_src_ip: u32,
    pub translated_src_port: u16,
    pub last_seen_ns: u64,
    pub ifindex: u32,
}
unsafe impl Pod for NatEntry {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnRateState {
    pub conn_count: u32,
    pub window_start_ns: u64,
}
unsafe impl Pod for ConnRateState {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FlowCounterEntry {
    pub egress_bytes: u64,
    pub egress_packets: u64,
}
unsafe impl Pod for FlowCounterEntry {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TcpStateCounts {
    pub syn_sent: u32,
    pub established: u32,
    pub fin_wait: u32,
    pub reset: u32,
    pub total: u32,
}
unsafe impl Pod for TcpStateCounts {}

#[repr(C)]
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
unsafe impl Pod for FlowEvent {}

#[derive(Copy, Clone)]
pub struct RateLimitDrops {
    pub bw_drops: u64,
    pub pps_drops: u64,
    pub conn_drops: u64,
    pub conn_rate_drops: u64,
    pub nat_drops: u64,
}

impl RateLimitDrops {
    pub fn total_drops(&self) -> u64 {
        self.bw_drops
            .saturating_add(self.pps_drops)
            .saturating_add(self.conn_drops)
            .saturating_add(self.conn_rate_drops)
            .saturating_add(self.nat_drops)
    }
}

pub struct EbpfProgram {
    bpf: Ebpf,
    sandbox_map: BpfHashMap<MapData, u32, SandboxEntry>,
    allow_map: BpfHashMap<MapData, u32, u8>,
    conn_map: BpfHashMap<MapData, Conn5Tuple, ConnEntry>,
    #[expect(dead_code, reason = "reserved for future token bucket rate limiting")]
    token_map: BpfHashMap<MapData, u32, TokenBucket>,
    nat_map: BpfHashMap<MapData, Conn5Tuple, NatEntry>,
    #[expect(dead_code, reason = "reserved for future connection rate limiting")]
    rate_map: BpfHashMap<MapData, u32, ConnRateState>,
    #[expect(dead_code, reason = "NAT port allocation map accessed via TC program")]
    nat_port_map: BpfHashMap<MapData, u32, u16>,
    flow_counters_map: BpfHashMap<MapData, u32, FlowCounterEntry>,
    tcp_state_counts_map: BpfHashMap<MapData, u32, TcpStateCounts>,
    #[expect(dead_code, reason = "reserved for future flow event streaming")]
    flow_events_ringbuf: AyaRingBuf<MapData>,
    links: HashMap<String, XdpLinkId>,
    tc_links: HashMap<String, SchedClassifierLinkId>,
}

impl EbpfProgram {
    pub fn load() -> Result<Self, String> {
        let bpf_elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pico_xdp.bpf.o"));

        let mut bpf = Ebpf::load(bpf_elf).map_err(|e| format!("failed to load BPF ELF: {e}"))?;

        let _: &mut Xdp = bpf
            .program_mut("pico_xdp_egress")
            .ok_or_else(|| "BPF program 'pico_xdp_egress' not found".to_string())?
            .try_into()
            .map_err(|e| format!("program is not XDP: {e}"))?;

        let sandbox_map: BpfHashMap<MapData, u32, SandboxEntry> = BpfHashMap::try_from(
            bpf.take_map("SANDBOX_MAP")
                .ok_or_else(|| "SANDBOX_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load SANDBOX_MAP: {e}"))?;

        let allow_map: BpfHashMap<MapData, u32, u8> = BpfHashMap::try_from(
            bpf.take_map("ALLOW_MAP")
                .ok_or_else(|| "ALLOW_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load ALLOW_MAP: {e}"))?;

        let conn_map: BpfHashMap<MapData, Conn5Tuple, ConnEntry> = BpfHashMap::try_from(
            bpf.take_map("CONN_MAP")
                .ok_or_else(|| "CONN_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load CONN_MAP: {e}"))?;

        let token_map: BpfHashMap<MapData, u32, TokenBucket> = BpfHashMap::try_from(
            bpf.take_map("TOKEN_MAP")
                .ok_or_else(|| "TOKEN_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load TOKEN_MAP: {e}"))?;

        let nat_map: BpfHashMap<MapData, Conn5Tuple, NatEntry> = BpfHashMap::try_from(
            bpf.take_map("NAT_MAP")
                .ok_or_else(|| "NAT_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load NAT_MAP: {e}"))?;

        let rate_map: BpfHashMap<MapData, u32, ConnRateState> = BpfHashMap::try_from(
            bpf.take_map("RATE_MAP")
                .ok_or_else(|| "RATE_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load RATE_MAP: {e}"))?;

        let nat_port_map: BpfHashMap<MapData, u32, u16> = BpfHashMap::try_from(
            bpf.take_map("NAT_PORT_MAP")
                .ok_or_else(|| "NAT_PORT_MAP not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load NAT_PORT_MAP: {e}"))?;

        let flow_counters_map: BpfHashMap<MapData, u32, FlowCounterEntry> = BpfHashMap::try_from(
            bpf.take_map("FLOW_COUNTERS")
                .ok_or_else(|| "FLOW_COUNTERS not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load FLOW_COUNTERS: {e}"))?;

        let tcp_state_counts_map: BpfHashMap<MapData, u32, TcpStateCounts> = BpfHashMap::try_from(
            bpf.take_map("TCP_STATE_COUNTS")
                .ok_or_else(|| "TCP_STATE_COUNTS not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load TCP_STATE_COUNTS: {e}"))?;

        let flow_events_ringbuf: AyaRingBuf<MapData> = AyaRingBuf::try_from(
            bpf.take_map("FLOW_EVENTS")
                .ok_or_else(|| "FLOW_EVENTS not found in BPF object".to_string())?,
        )
        .map_err(|e| format!("failed to load FLOW_EVENTS: {e}"))?;

        Ok(Self {
            bpf,
            sandbox_map,
            allow_map,
            conn_map,
            token_map,
            nat_map,
            rate_map,
            nat_port_map,
            flow_counters_map,
            tcp_state_counts_map,
            flow_events_ringbuf,
            links: HashMap::new(),
            tc_links: HashMap::new(),
        })
    }

    pub fn get_ifindex(&self, if_name: &str) -> Result<u32, String> {
        nix::net::if_::if_nametoindex(if_name)
            .map_err(|e| format!("failed to get ifindex for {if_name}: {e}"))
    }

    pub fn attach_xdp(&mut self, if_name: &str) -> Result<u32, String> {
        let program: &mut Xdp = self
            .bpf
            .program_mut("pico_xdp_egress")
            .ok_or_else(|| "program not found".to_string())?
            .try_into()
            .map_err(|_| "program is not XDP".to_string())?;

        program
            .load()
            .map_err(|e| format!("failed to load XDP program: {e}"))?;

        let link_id = program
            .attach(if_name, XdpMode::default())
            .map_err(|e| format!("failed to attach XDP to {if_name}: {e}"))?;

        self.links.insert(if_name.to_string(), link_id);
        Ok(0)
    }

    pub fn detach_xdp(&mut self, if_name: &str) -> Result<(), String> {
        let link_id = self
            .links
            .remove(if_name)
            .ok_or_else(|| format!("no active XDP link for {if_name}"))?;

        let program: &mut Xdp = self
            .bpf
            .program_mut("pico_xdp_egress")
            .ok_or_else(|| "program not found".to_string())?
            .try_into()
            .map_err(|_| "program is not XDP".to_string())?;

        program
            .detach(link_id)
            .map_err(|e| format!("failed to detach XDP from {if_name}: {e}"))?;

        Ok(())
    }

    pub fn attach_tc_nat(&mut self, if_name: &str) -> Result<(), String> {
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("pico_tc_nat")
            .ok_or_else(|| "BPF program 'pico_tc_nat' not found".to_string())?
            .try_into()
            .map_err(|e| format!("program is not TC: {e}"))?;

        program
            .load()
            .map_err(|e| format!("failed to load TC NAT program: {e}"))?;

        let link_id = program
            .attach(if_name, TcAttachType::Egress)
            .map_err(|e| format!("failed to attach TC NAT to {if_name}: {e}"))?;

        self.tc_links.insert(if_name.to_string(), link_id);
        Ok(())
    }

    pub fn detach_tc_nat(&mut self, if_name: &str) -> Result<(), String> {
        let entry = self
            .tc_links
            .remove(if_name)
            .ok_or_else(|| format!("no active TC NAT link for {if_name}"))?;

        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("pico_tc_nat")
            .ok_or_else(|| "BPF program 'pico_tc_nat' not found".to_string())?
            .try_into()
            .map_err(|e| format!("program is not TC: {e}"))?;

        program
            .detach(entry)
            .map_err(|e| format!("failed to detach TC NAT from {if_name}: {e}"))?;

        Ok(())
    }

    pub fn insert_sandbox_entry(
        &mut self,
        ifindex: u32,
        guest_ip: u32,
        host_ip: u32,
    ) -> Result<(), String> {
        let entry = SandboxEntry {
            guest_ip,
            host_ip,
            bandwidth_bps: 0,
            max_conns: 0,
            max_pps: 0,
            max_conn_rate_per_sec: 0,
            conn_count: 0,
            byte_count: 0,
            pps_tokens: 0,
            last_ts_ns: 0,
            bw_drops: 0,
            pps_drops: 0,
            conn_drops: 0,
            conn_rate_drops: 0,
            nat_drops: 0,
        };
        self.sandbox_map
            .insert(ifindex, entry, 0)
            .map_err(|e| format!("failed to insert sandbox entry: {e}"))?;
        Ok(())
    }

    pub fn update_rate_limits(
        &mut self,
        ifindex: u32,
        bandwidth_bps: u64,
        max_conns: u32,
        max_pps: u32,
        max_conn_rate_per_sec: u32,
    ) -> Result<(), String> {
        let mut entry = self
            .sandbox_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get sandbox entry: {e}"))?;

        entry.bandwidth_bps = bandwidth_bps;
        entry.max_conns = max_conns;
        entry.max_pps = max_pps;
        entry.max_conn_rate_per_sec = max_conn_rate_per_sec;

        self.sandbox_map
            .insert(ifindex, entry, 0)
            .map_err(|e| format!("failed to update rate limits: {e}"))?;
        Ok(())
    }

    pub fn update_host_ip(&mut self, ifindex: u32, host_ip: u32) -> Result<(), String> {
        let mut entry = self
            .sandbox_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get sandbox entry: {e}"))?;

        entry.host_ip = host_ip;

        self.sandbox_map
            .insert(ifindex, entry, 0)
            .map_err(|e| format!("failed to update host IP: {e}"))?;
        Ok(())
    }

    pub fn remove_sandbox_entry(&mut self, ifindex: u32) -> Result<(), String> {
        self.sandbox_map
            .remove(&ifindex)
            .map_err(|e| format!("failed to remove sandbox entry: {e}"))?;
        Ok(())
    }

    pub fn collect_rate_limit_drops(&mut self, ifindex: u32) -> Result<RateLimitDrops, String> {
        let entry = self
            .sandbox_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get sandbox entry: {e}"))?;
        let drops = RateLimitDrops {
            bw_drops: entry.bw_drops,
            pps_drops: entry.pps_drops,
            conn_drops: entry.conn_drops,
            conn_rate_drops: entry.conn_rate_drops,
            nat_drops: entry.nat_drops,
        };
        let mut entry = entry;
        entry.bw_drops = 0;
        entry.pps_drops = 0;
        entry.conn_drops = 0;
        entry.conn_rate_drops = 0;
        entry.nat_drops = 0;
        self.sandbox_map
            .insert(ifindex, entry, 0)
            .map_err(|e| format!("failed to reset drop counters: {e}"))?;
        Ok(drops)
    }

    pub fn reconcile_conn_count(&mut self, ifindex: u32) -> Result<u32, String> {
        let count = self
            .conn_map
            .iter()
            .filter_map(|item| item.ok())
            .filter(|(_, entry)| entry.ifindex == ifindex)
            .count() as u32;

        let mut entry = self
            .sandbox_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get sandbox entry: {e}"))?;

        entry.conn_count = count;

        self.sandbox_map
            .insert(ifindex, entry, 0)
            .map_err(|e| format!("failed to reconcile conn_count: {e}"))?;

        Ok(count)
    }

    pub fn gc_connections(&mut self, ifindex: u32) -> Result<(), String> {
        let mut to_remove: Vec<Conn5Tuple> = Vec::new();
        for item in self.conn_map.iter() {
            let (tuple, entry) = item.map_err(|e| format!("failed to iterate CONN_MAP: {e}"))?;
            if entry.ifindex == ifindex {
                to_remove.push(tuple);
            }
        }
        for tuple in to_remove {
            self.conn_map
                .remove(&tuple)
                .map_err(|e| format!("failed to remove conn entry: {e}"))?;
        }
        Ok(())
    }

    pub fn gc_nat_entries(&mut self, ifindex: u32) -> Result<usize, String> {
        let mut to_remove: Vec<Conn5Tuple> = Vec::new();
        for item in self.nat_map.iter() {
            let (tuple, entry) = item.map_err(|e| format!("failed to iterate NAT_MAP: {e}"))?;
            if entry.ifindex == ifindex {
                to_remove.push(tuple);
            }
        }
        let count = to_remove.len();
        for tuple in to_remove {
            self.nat_map
                .remove(&tuple)
                .map_err(|e| format!("failed to remove NAT entry: {e}"))?;
        }
        Ok(count)
    }

    pub fn gc_stale_nat_entries(
        &mut self,
        ifindex: u32,
        max_idle_ns: u64,
    ) -> Result<usize, String> {
        let now_ns = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let mut to_remove: Vec<Conn5Tuple> = Vec::new();
        for item in self.nat_map.iter() {
            let (tuple, entry) = item.map_err(|e| format!("failed to iterate NAT_MAP: {e}"))?;
            if entry.ifindex == ifindex && now_ns.saturating_sub(entry.last_seen_ns) > max_idle_ns {
                to_remove.push(tuple);
            }
        }
        let count = to_remove.len();
        for tuple in to_remove {
            self.nat_map
                .remove(&tuple)
                .map_err(|e| format!("failed to remove stale NAT entry: {e}"))?;
        }
        Ok(count)
    }

    pub fn nat_entry_count(&self, ifindex: u32) -> Result<u32, String> {
        let count = self
            .nat_map
            .iter()
            .filter_map(|item| item.ok())
            .filter(|(_, entry)| entry.ifindex == ifindex)
            .count() as u32;
        Ok(count)
    }

    pub fn insert_allow_entry(&mut self, dst_ip: u32) -> Result<(), String> {
        self.allow_map
            .insert(dst_ip, 1u8, 0)
            .map_err(|e| format!("failed to insert allow entry: {e}"))?;
        Ok(())
    }

    pub fn remove_allow_entry(&mut self, dst_ip: u32) -> Result<(), String> {
        self.allow_map
            .remove(&dst_ip)
            .map_err(|e| format!("failed to remove allow entry: {e}"))?;
        Ok(())
    }

    pub fn collect_flow_counters(&mut self, ifindex: u32) -> Result<FlowCounterEntry, String> {
        let counter = self
            .flow_counters_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get flow counter: {e}"))?;

        self.flow_counters_map
            .remove(&ifindex)
            .map_err(|e| format!("failed to reset flow counter: {e}"))?;

        Ok(counter)
    }

    pub fn collect_tcp_state_counts(&mut self, ifindex: u32) -> Result<TcpStateCounts, String> {
        let counts = self
            .tcp_state_counts_map
            .get(&ifindex, 0)
            .map_err(|e| format!("failed to get tcp state counts: {e}"))?;

        Ok(counts)
    }

    pub fn gc_flow_counters(&mut self, ifindex: u32) -> Result<(), String> {
        self.flow_counters_map
            .remove(&ifindex)
            .map_err(|e| format!("failed to remove flow counter: {e}"))?;
        Ok(())
    }

    pub fn gc_tcp_state_counts(&mut self, ifindex: u32) -> Result<(), String> {
        self.tcp_state_counts_map
            .remove(&ifindex)
            .map_err(|e| format!("failed to remove tcp state counts: {e}"))?;
        Ok(())
    }

    pub fn reconcile_tcp_state_counts(&mut self, ifindex: u32) -> Result<TcpStateCounts, String> {
        // Scans CONN_MAP for this sandbox's connections. Non-TCP flows (UDP,
        // ICMP) use state 0/1 and land in syn_sent/established; the gauges
        // are "connection state counts" rather than strictly TCP-only.
        // For strict TCP-only counts, filter on the connection's proto field.
        let mut counts = TcpStateCounts {
            syn_sent: 0,
            established: 0,
            fin_wait: 0,
            reset: 0,
            total: 0,
        };

        for item in self.conn_map.iter() {
            let (_, entry) = item.map_err(|e| format!("failed to iterate CONN_MAP: {e}"))?;
            if entry.ifindex != ifindex {
                continue;
            }
            match entry.state {
                0 => counts.syn_sent = counts.syn_sent.saturating_add(1),
                1 => counts.established = counts.established.saturating_add(1),
                2 => counts.fin_wait = counts.fin_wait.saturating_add(1),
                3 => counts.reset = counts.reset.saturating_add(1),
                _ => {}
            }
            counts.total = counts.total.saturating_add(1);
        }

        self.tcp_state_counts_map
            .insert(ifindex, counts, 0)
            .map_err(|e| format!("failed to update tcp state counts: {e}"))?;

        Ok(counts)
    }
}
