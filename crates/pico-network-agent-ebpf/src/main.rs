#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, map, xdp};
use aya_ebpf::maps::{HashMap, LruHashMap, RingBuf};
use aya_ebpf::programs::{TcContext, XdpContext};
use core::mem;

#[repr(C)]
#[derive(Copy, Clone)]
struct EthHdr {
    dst_addr: [u8; 6],
    src_addr: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv4Hdr {
    version_ihl: u8,
    dscp_ecn: u8,
    total_len: u16,
    identification: u16,
    flags_frag_offset: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    doff_reserved: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
}

const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();
const IP_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>();
const TCP_HDR_LEN: usize = mem::size_of::<TcpHdr>();

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

const BW_INTERVAL_NS: u64 = 1_000_000_000;

#[repr(C)]
#[derive(Copy, Clone)]
struct SandboxEntry {
    guest_ip: u32,
    host_ip: u32,
    bandwidth_bps: u64,
    max_conns: u32,
    max_pps: u32,
    max_conn_rate_per_sec: u32,
    conn_count: u32,
    byte_count: u64,
    pps_tokens: u32,
    last_ts_ns: u64,
    bw_drops: u64,
    pps_drops: u64,
    conn_drops: u64,
    conn_rate_drops: u64,
    nat_drops: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Conn5Tuple {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ConnEntry {
    last_seen_ns: u64,
    ifindex: u32,
    state: u8,
    _pad: [u8; 3],
    start_ns: u64,
    byte_count: u64,
    packet_count: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TokenBucket {
    tokens: u64,
    last_refill_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NatEntry {
    original_src_ip: u32,
    original_src_port: u16,
    translated_src_ip: u32,
    translated_src_port: u16,
    last_seen_ns: u64,
    ifindex: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ConnRateState {
    conn_count: u32,
    window_start_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FlowCounterEntry {
    egress_bytes: u64,
    egress_packets: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpStateCounts {
    syn_sent: u32,
    established: u32,
    fin_wait: u32,
    reset: u32,
    total: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FlowEvent {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    _pad: [u8; 3],
    start_ns: u64,
    end_ns: u64,
    ifindex: u32,
    byte_count: u64,
    packet_count: u64,
}

const CONN_STATE_NEW: u8 = 0;
const CONN_STATE_ESTABLISHED: u8 = 1;
const CONN_STATE_CLOSING: u8 = 2;

const TCP_STATE_SYN_SENT: u8 = 0;
const TCP_STATE_ESTABLISHED: u8 = 1;
const TCP_STATE_FIN_WAIT: u8 = 2;
const TCP_STATE_RESET: u8 = 3;

#[map]
static SANDBOX_MAP: HashMap<u32, SandboxEntry> =
    HashMap::<u32, SandboxEntry>::with_max_entries(4096, 0);

#[map]
static ALLOW_MAP: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1048576, 0);

#[map]
static CONN_MAP: LruHashMap<Conn5Tuple, ConnEntry> =
    LruHashMap::<Conn5Tuple, ConnEntry>::with_max_entries(65536, 0);

#[map]
static TOKEN_MAP: HashMap<u32, TokenBucket> =
    HashMap::<u32, TokenBucket>::with_max_entries(4096, 0);

#[map]
static NAT_MAP: LruHashMap<Conn5Tuple, NatEntry> =
    LruHashMap::<Conn5Tuple, NatEntry>::with_max_entries(65536, 0);

#[map]
static RATE_MAP: HashMap<u32, ConnRateState> =
    HashMap::<u32, ConnRateState>::with_max_entries(4096, 0);

#[map]
static NAT_PORT_MAP: HashMap<u32, u16> = HashMap::<u32, u16>::with_max_entries(65536, 0);

// Persistent per-ifindex byte/packet counters, collected and reset periodically
// by userspace. Separate from SandboxEntry.byte_count which resets every 1s for
// bandwidth rate limiting.
#[map]
static FLOW_COUNTERS: HashMap<u32, FlowCounterEntry> =
    HashMap::<u32, FlowCounterEntry>::with_max_entries(4096, 0);

// Per-ifindex TCP connection state counts. These drift when CONN_MAP LRU evicts
// entries; userspace should periodically call reconcile_tcp_state_counts() to
// rescan CONN_MAP and correct the gauges.
#[map]
static TCP_STATE_COUNTS: HashMap<u32, TcpStateCounts> =
    HashMap::<u32, TcpStateCounts>::with_max_entries(4096, 0);

// Sampled flow event RingBuf. Events are written when a TCP connection reaches
// FIN_WAIT or RESET state. Userspace consumption is deferred to a dedicated
// async consumer task (tracked in follow-up).
#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

#[xdp]
pub fn pico_xdp_egress(ctx: XdpContext) -> u32 {
    match try_xdp_egress(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::PASS,
    }
}

fn try_xdp_egress(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = ctx.ingress_ifindex() as u32;

    let mut entry = unsafe { SANDBOX_MAP.get(&ifindex).ok_or(())?.clone() };

    if ctx.data() + ETH_HDR_LEN > ctx.data_end() {
        return Ok(xdp_action::PASS);
    }

    let eth: &EthHdr = unsafe { &*(ctx.data() as *const EthHdr) };
    if u16::from_be(eth.ether_type) != ETH_P_IP {
        return Ok(xdp_action::PASS);
    }

    let ip_offset = ETH_HDR_LEN;
    if ctx.data() + ip_offset + IP_HDR_LEN > ctx.data_end() {
        return Ok(xdp_action::PASS);
    }

    let ip: &Ipv4Hdr = unsafe { &*((ctx.data() + ip_offset) as *const Ipv4Hdr) };

    if ip.proto != IPPROTO_TCP && ip.proto != IPPROTO_UDP && ip.proto != IPPROTO_ICMP {
        return Ok(xdp_action::PASS);
    }

    let src_ip = u32::from_be_bytes(ip.src_addr);
    let dst_ip = u32::from_be_bytes(ip.dst_addr);

    if src_ip != entry.guest_ip {
        return Ok(xdp_action::DROP);
    }

    if dst_ip == 0 {
        return Ok(xdp_action::DROP);
    }

    // bpf_ktime_get_ns() is now called unconditionally (previously guarded by
    // rate-limit flags) because flow counters and TCP state tracking require
    // per-packet timestamps.
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    if entry.bandwidth_bps > 0 {
        if now_ns.saturating_sub(entry.last_ts_ns) >= BW_INTERVAL_NS {
            entry.byte_count = 0;
            entry.last_ts_ns = now_ns;
        }
        entry.byte_count = entry.byte_count.saturating_add(pkt_len);
        if entry.byte_count > entry.bandwidth_bps {
            entry.bw_drops = entry.bw_drops.saturating_add(1);
            unsafe {
                SANDBOX_MAP.insert(&ifindex, &entry, 0).ok();
            }
            return Ok(xdp_action::DROP);
        }
    }

    if entry.max_pps > 0 {
        let bucket = unsafe { TOKEN_MAP.get(&ifindex) };
        let refill_rate = entry.max_pps as u64;
        let (tokens, last_ns) = if let Some(tb) = bucket {
            let elapsed_ns = now_ns.saturating_sub(tb.last_refill_ns);
            let new_tokens = tb
                .tokens
                .saturating_add(elapsed_ns.saturating_mul(refill_rate) / BW_INTERVAL_NS);
            (new_tokens.min(refill_rate), tb.last_refill_ns)
        } else {
            (refill_rate, now_ns)
        };

        if tokens == 0 {
            entry.pps_drops = entry.pps_drops.saturating_add(1);
            unsafe {
                SANDBOX_MAP.insert(&ifindex, &entry, 0).ok();
            }
            return Ok(xdp_action::DROP);
        }

        let new_bucket = TokenBucket {
            tokens: tokens - 1,
            last_refill_ns: now_ns,
        };
        unsafe {
            TOKEN_MAP.insert(&ifindex, &new_bucket, 0).ok();
        }
    }

    if entry.max_conns > 0 && (ip.proto == IPPROTO_TCP || ip.proto == IPPROTO_UDP) {
        let src_port = parse_transport_port(ctx, ip, true);
        let dst_port = parse_transport_port(ctx, ip, false);

        let tuple = Conn5Tuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: ip.proto,
            _pad: [0u8; 3],
        };

        let existing = unsafe { CONN_MAP.get(&tuple) };

        if let Some(mut conn) = existing {
            conn.last_seen_ns = now_ns;
            conn.byte_count = conn.byte_count.saturating_add(pkt_len);
            conn.packet_count = conn.packet_count.saturating_add(1);

            if ip.proto == IPPROTO_TCP && conn.state == TCP_STATE_ESTABLISHED {
                let tcp_flags = parse_tcp_flags(ctx, ip);
                let old_state = conn.state;
                if tcp_flags & TCP_FLAG_RST != 0 {
                    conn.state = TCP_STATE_RESET;
                } else if tcp_flags & TCP_FLAG_FIN != 0 {
                    conn.state = TCP_STATE_FIN_WAIT;
                }
                if conn.state != old_state {
                    update_tcp_state_counts(ifindex, old_state, conn.state);
                    if conn.state == TCP_STATE_FIN_WAIT || conn.state == TCP_STATE_RESET {
                        emit_flow_event(&conn, &tuple, ifindex, now_ns);
                    }
                }
            } else if ip.proto == IPPROTO_TCP && conn.state == TCP_STATE_SYN_SENT {
                // Any subsequent packet after SYN transitions to ESTABLISHED.
                // This is intentionally approximate: it does not require a
                // matching SYN+ACK and will over-count ESTABLISHED under early
                // RST or mid-handshake patterns. Coarse telemetry is acceptable
                // for v1; reconcile_tcp_state_counts() provides ground truth.
                conn.state = TCP_STATE_ESTABLISHED;
                update_tcp_state_counts(ifindex, TCP_STATE_SYN_SENT, TCP_STATE_ESTABLISHED);
            } else if conn.state == CONN_STATE_NEW {
                conn.state = CONN_STATE_ESTABLISHED;
            }
            unsafe {
                CONN_MAP.insert(&tuple, &conn, 0).ok();
            }
        } else {
            if entry.max_conn_rate_per_sec > 0 {
                let rate_state = unsafe { RATE_MAP.get(&ifindex) };
                let max_rate = entry.max_conn_rate_per_sec;
                let (ok, new_rate) = check_conn_rate(rate_state, max_rate, now_ns);
                if !ok {
                    entry.conn_rate_drops = entry.conn_rate_drops.saturating_add(1);
                    unsafe {
                        SANDBOX_MAP.insert(&ifindex, &entry, 0).ok();
                    }
                    return Ok(xdp_action::DROP);
                }
                unsafe {
                    RATE_MAP.insert(&ifindex, &new_rate, 0).ok();
                }
            }

            if entry.conn_count >= entry.max_conns {
                entry.conn_drops = entry.conn_drops.saturating_add(1);
                unsafe {
                    SANDBOX_MAP.insert(&ifindex, &entry, 0).ok();
                }
                return Ok(xdp_action::DROP);
            }

            let initial_state = if ip.proto == IPPROTO_TCP {
                let tcp_flags = parse_tcp_flags(ctx, ip);
                if tcp_flags & TCP_FLAG_SYN != 0 {
                    let state = TCP_STATE_SYN_SENT;
                    update_tcp_state_init(ifindex, state);
                    state
                } else {
                    let state = TCP_STATE_ESTABLISHED;
                    update_tcp_state_init(ifindex, state);
                    state
                }
            } else {
                CONN_STATE_NEW
            };

            let conn = ConnEntry {
                last_seen_ns: now_ns,
                ifindex,
                state: initial_state,
                _pad: [0u8; 3],
                start_ns: now_ns,
                byte_count: pkt_len,
                packet_count: 1,
            };
            unsafe {
                CONN_MAP.insert(&tuple, &conn, 0).ok();
            }
            entry.conn_count = entry.conn_count.saturating_add(1);
        }
    }

    unsafe {
        SANDBOX_MAP.insert(&ifindex, &entry, 0).ok();
    }

    let allowed = unsafe { ALLOW_MAP.get(&dst_ip).is_some() };
    if allowed {
        update_flow_counters(ifindex, pkt_len);
        Ok(xdp_action::PASS)
    } else {
        Ok(xdp_action::DROP)
    }
}

fn check_conn_rate(
    current: Option<&ConnRateState>,
    max_rate: u32,
    now_ns: u64,
) -> (bool, ConnRateState) {
    if max_rate == 0 {
        return (
            true,
            ConnRateState {
                conn_count: 0,
                window_start_ns: now_ns,
            },
        );
    }

    match current {
        Some(state) => {
            if now_ns.saturating_sub(state.window_start_ns) >= BW_INTERVAL_NS {
                (
                    true,
                    ConnRateState {
                        conn_count: 1,
                        window_start_ns: now_ns,
                    },
                )
            } else if state.conn_count < max_rate {
                (
                    true,
                    ConnRateState {
                        conn_count: state.conn_count + 1,
                        window_start_ns: state.window_start_ns,
                    },
                )
            } else {
                (false, *state)
            }
        }
        None => (
            true,
            ConnRateState {
                conn_count: 1,
                window_start_ns: now_ns,
            },
        ),
    }
}

fn parse_transport_port(ctx: &XdpContext, ip: &Ipv4Hdr, is_src: bool) -> u16 {
    let ip_hdr_len = ((ip.version_ihl & 0x0F) as usize) * 4;
    let offset = ETH_HDR_LEN + ip_hdr_len + if is_src { 0 } else { 2 };

    if ctx.data() + offset + 2 > ctx.data_end() {
        return 0;
    }

    let ptr = (ctx.data() + offset) as *const u16;
    u16::from_be(unsafe { *ptr })
}

#[classifier]
pub fn pico_tc_nat(ctx: TcContext) -> i32 {
    match try_tc_nat(&ctx) {
        Ok(_) => TC_ACT_OK,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_nat(ctx: &TcContext) -> Result<(), ()> {
    let ifindex = ctx.ifindex();

    let entry = unsafe { SANDBOX_MAP.get(&ifindex).ok_or(())?.clone() };
    let host_ip = entry.host_ip;

    if entry.host_ip == 0 {
        return Ok(());
    }

    let ip_start = ETH_HDR_LEN;
    if ctx.len() < (ip_start + IP_HDR_LEN) as u32 {
        return Ok(());
    }

    let src_ip: u32 = u32::from_be(ctx.load(ip_start + 12).map_err(|_| ())?);
    let dst_ip: u32 = u32::from_be(ctx.load(ip_start + 16).map_err(|_| ())?);
    let proto: u8 = ctx.load(ip_start + 9).map_err(|_| ())?;

    if src_ip != entry.guest_ip {
        return Ok(());
    }

    if proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP {
        return Ok(());
    }

    let version_ihl: u8 = ctx.load(ip_start).map_err(|_| ())?;
    let ip_hdr_len = ((version_ihl & 0x0F) as usize) * 4;
    if ip_hdr_len < 20 || ip_hdr_len > 60 {
        return Ok(());
    }
    let transport_start = ip_start + ip_hdr_len;

    if ctx.len() < (transport_start + 4) as u32 {
        return Ok(());
    }

    if proto == IPPROTO_ICMP {
        return do_nat_inner(ctx, entry, ifindex, src_ip, dst_ip, 0, 0, proto, ip_start);
    }

    let src_port: u16 = u16::from_be(ctx.load(transport_start).map_err(|_| ())?);
    let dst_port: u16 = u16::from_be(ctx.load(transport_start + 2).map_err(|_| ())?);

    do_nat_inner(
        ctx,
        entry,
        ifindex,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        ip_start,
    )
}

fn do_nat_inner(
    ctx: &TcContext,
    entry: SandboxEntry,
    ifindex: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    ip_start: usize,
) -> Result<(), ()> {
    let host_ip = entry.host_ip;
    let tuple = Conn5Tuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        _pad: [0u8; 3],
    };

    let existing_nat = unsafe { NAT_MAP.get(&tuple) };
    let nat_port = if let Some(nat) = existing_nat {
        if proto != IPPROTO_ICMP {
            let mut updated = nat;
            updated.last_seen_ns = unsafe { bpf_ktime_get_ns() };
            unsafe {
                NAT_MAP.insert(&tuple, &updated, 0).ok();
            }
        }
        nat.translated_src_port
    } else {
        let port_key = (u64::from(ifindex) << 32) | u64::from(src_port);
        let assigned = allocate_nat_port(port_key, src_port);

        let nat_entry = NatEntry {
            original_src_ip: src_ip,
            original_src_port: src_port,
            translated_src_ip: host_ip,
            translated_src_port: assigned,
            last_seen_ns: unsafe { bpf_ktime_get_ns() },
            ifindex,
        };
        let inserted = unsafe { NAT_MAP.insert(&tuple, &nat_entry, 0) };
        if inserted.is_err() {
            let mut tally = entry;
            tally.nat_drops = tally.nat_drops.saturating_add(1);
            unsafe {
                SANDBOX_MAP.insert(&ifindex, &tally, 0).ok();
            }
            return Ok(());
        }
        assigned
    };

    if proto == IPPROTO_ICMP {
        ctx.store(ip_start + 12, &host_ip.to_be_bytes(), 0)
            .map_err(|_| ())?;
        ctx.l3_csum_replace(ip_start, src_ip as u64, host_ip as u64, 4)
            .map_err(|_| ())?;
        return Ok(());
    }

    let transport_start = ip_start + (((ctx.load::<u8>(ip_start).map_err(|_| ())? & 0x0F) as usize) * 4);

    ctx.store(ip_start + 12, &host_ip.to_be_bytes(), 0)
        .map_err(|_| ())?;
    ctx.store(transport_start, &nat_port.to_be_bytes(), 0)
        .map_err(|_| ())?;

    ctx.l3_csum_replace(ip_start, src_ip as u64, host_ip as u64, 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(transport_start, ip_start, src_ip as u64, host_ip as u64, 2)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(transport_start, ip_start, src_port as u64, nat_port as u64, 2)
        .map_err(|_| ())?;

    Ok(())
}

fn allocate_nat_port(port_key: u64, _fallback: u16) -> u16 {
    let key = (port_key ^ (port_key >> 16)) as u32;
    let existing = unsafe { NAT_PORT_MAP.get(&key) };
    if let Some(port) = existing {
        return port;
    }

    let base: u16 = 40000;
    let range: u16 = 25535;
    let hash = murmur_hash3(port_key) as u16;
    let port = base + (hash % range);
    unsafe {
        NAT_PORT_MAP.insert(&key, &port, 0).ok();
    }
    port
}

fn parse_tcp_flags(ctx: &XdpContext, ip: &Ipv4Hdr) -> u8 {
    let ip_hdr_len = ((ip.version_ihl & 0x0F) as usize) * 4;
    let tcp_offset = ETH_HDR_LEN + ip_hdr_len;

    if ctx.data() + tcp_offset + TCP_HDR_LEN > ctx.data_end() {
        return 0;
    }

    let tcp: &TcpHdr = unsafe { &*((ctx.data() + tcp_offset) as *const TcpHdr) };
    tcp.flags
}

fn update_tcp_state_init(ifindex: u32, state: u8) {
    let mut counts = unsafe { TCP_STATE_COUNTS.get(&ifindex) }
        .copied()
        .unwrap_or(TcpStateCounts {
            syn_sent: 0,
            established: 0,
            fin_wait: 0,
            reset: 0,
            total: 0,
        });

    match state {
        TCP_STATE_SYN_SENT => counts.syn_sent = counts.syn_sent.saturating_add(1),
        TCP_STATE_ESTABLISHED => counts.established = counts.established.saturating_add(1),
        _ => {}
    }
    counts.total = counts.total.saturating_add(1);

    unsafe {
        TCP_STATE_COUNTS.insert(&ifindex, &counts, 0).ok();
    }
}

fn update_tcp_state_counts(ifindex: u32, old_state: u8, new_state: u8) {
    let mut counts = unsafe { TCP_STATE_COUNTS.get(&ifindex) }
        .copied()
        .unwrap_or(TcpStateCounts {
            syn_sent: 0,
            established: 0,
            fin_wait: 0,
            reset: 0,
            total: 0,
        });

    match old_state {
        TCP_STATE_SYN_SENT => counts.syn_sent = counts.syn_sent.saturating_sub(1),
        TCP_STATE_ESTABLISHED => counts.established = counts.established.saturating_sub(1),
        TCP_STATE_FIN_WAIT => counts.fin_wait = counts.fin_wait.saturating_sub(1),
        TCP_STATE_RESET => counts.reset = counts.reset.saturating_sub(1),
        _ => {}
    }
    match new_state {
        TCP_STATE_SYN_SENT => counts.syn_sent = counts.syn_sent.saturating_add(1),
        TCP_STATE_ESTABLISHED => counts.established = counts.established.saturating_add(1),
        TCP_STATE_FIN_WAIT => counts.fin_wait = counts.fin_wait.saturating_add(1),
        TCP_STATE_RESET => counts.reset = counts.reset.saturating_add(1),
        _ => {}
    }

    unsafe {
        TCP_STATE_COUNTS.insert(&ifindex, &counts, 0).ok();
    }
}

fn update_flow_counters(ifindex: u32, pkt_len: u64) {
    let mut counter = unsafe { FLOW_COUNTERS.get(&ifindex) }
        .copied()
        .unwrap_or(FlowCounterEntry {
            egress_bytes: 0,
            egress_packets: 0,
        });

    counter.egress_bytes = counter.egress_bytes.saturating_add(pkt_len);
    counter.egress_packets = counter.egress_packets.saturating_add(1);

    unsafe {
        FLOW_COUNTERS.insert(&ifindex, &counter, 0).ok();
    }
}

fn emit_flow_event(conn: &ConnEntry, tuple: &Conn5Tuple, ifindex: u32, end_ns: u64) {
    let event = FlowEvent {
        src_ip: tuple.src_ip,
        dst_ip: tuple.dst_ip,
        src_port: tuple.src_port,
        dst_port: tuple.dst_port,
        proto: tuple.proto,
        _pad: [0u8; 3],
        start_ns: conn.start_ns,
        end_ns,
        ifindex,
        byte_count: conn.byte_count,
        packet_count: conn.packet_count,
    };

    unsafe {
        let _ = FLOW_EVENTS.output(&event, 0);
    }
}

fn murmur_hash3(key: u64) -> u32 {
    let mut h: u32 = key as u32 ^ 0x9E3779B9;
    h = h.wrapping_mul(0xCC9E2D51);
    h = (h << 15) | (h >> 17);
    h = h.wrapping_mul(0x1B873593);
    h ^= h >> 16;
    h
}

mod xdp_action {
    pub const ABORTED: u32 = 0;
    pub const DROP: u32 = 1;
    pub const PASS: u32 = 2;
    pub const TX: u32 = 3;
    pub const REDIRECT: u32 = 4;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
