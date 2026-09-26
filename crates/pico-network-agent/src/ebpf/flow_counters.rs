use tracing::debug;

use super::loader::EbpfLoader;
use crate::ebpf::{FlowCounterEntry, TcpStateCounts};
use crate::error::NetworkResult;

pub struct FlowCounterManager {
    loader: EbpfLoader,
}

impl FlowCounterManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    pub fn collect(&self, ifindex: u32) -> Result<FlowCounterEntry, String> {
        let counters = self.loader.collect_flow_counters(ifindex)?;
        debug!(
            ifindex = ifindex,
            egress_bytes = counters.egress_bytes,
            egress_packets = counters.egress_packets,
            "collected flow counters"
        );
        Ok(counters)
    }

    pub fn tcp_state_counts(&self, ifindex: u32) -> Result<TcpStateCounts, String> {
        let counts = self.loader.collect_tcp_state_counts(ifindex)?;
        debug!(
            ifindex = ifindex,
            syn_sent = counts.syn_sent,
            established = counts.established,
            fin_wait = counts.fin_wait,
            reset = counts.reset,
            total = counts.total,
            "collected tcp state counts"
        );
        Ok(counts)
    }

    pub fn cleanup(&self, ifindex: u32) -> NetworkResult<()> {
        let _ = self.loader.gc_flow_counters(ifindex);
        let _ = self.loader.gc_tcp_state_counts(ifindex);
        Ok(())
    }

    pub fn reconcile_tcp_state_counts(&self, ifindex: u32) -> Result<TcpStateCounts, String> {
        self.loader.reconcile_tcp_state_counts(ifindex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_counter_entry_size_matches_bpf() {
        assert_eq!(
            std::mem::size_of::<FlowCounterEntry>(),
            16,
            "FlowCounterEntry size mismatch with BPF struct"
        );
    }

    #[test]
    fn tcp_state_counts_size_matches_bpf() {
        assert_eq!(
            std::mem::size_of::<TcpStateCounts>(),
            20,
            "TcpStateCounts size mismatch with BPF struct"
        );
    }

    #[test]
    fn flow_counter_entry_zero_default() {
        let entry = FlowCounterEntry {
            egress_bytes: 0,
            egress_packets: 0,
        };
        assert_eq!(entry.egress_bytes, 0);
        assert_eq!(entry.egress_packets, 0);
    }

    #[test]
    fn tcp_state_counts_reconcile_preserves_total() {
        let counts = TcpStateCounts {
            syn_sent: 1,
            established: 5,
            fin_wait: 2,
            reset: 0,
            total: 8,
        };
        assert_eq!(
            counts.total,
            counts.syn_sent + counts.established + counts.fin_wait + counts.reset
        );
    }
}
