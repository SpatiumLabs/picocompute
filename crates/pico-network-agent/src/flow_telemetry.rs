use std::time::Instant;

use tracing::debug;

use crate::ebpf::{EbpfManager, FlowCounterEntry, TcpStateCounts};
use crate::error::NetworkResult;

pub struct FlowTelemetryCollector;

impl FlowTelemetryCollector {
    pub fn collect_per_sandbox(
        manager: &EbpfManager,
        sandbox_id: &str,
    ) -> NetworkResult<(FlowCounterEntry, TcpStateCounts)> {
        let start = Instant::now();
        let result = manager.collect_flow_telemetry(sandbox_id)?;

        debug!(
            sandbox_id = %sandbox_id,
            egress_bytes = result.0.egress_bytes,
            egress_packets = result.0.egress_packets,
            tcp_syn = result.1.syn_sent,
            tcp_est = result.1.established,
            tcp_fin = result.1.fin_wait,
            tcp_rst = result.1.reset,
            tcp_total = result.1.total,
            latency_us = start.elapsed().as_micros(),
            "flow telemetry collected"
        );

        Ok(result)
    }
}
