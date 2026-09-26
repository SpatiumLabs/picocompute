use std::time::Instant;

use tracing::debug;

use super::loader::EbpfLoader;
use crate::error::NetworkResult;

pub struct ConnTrackManager {
    loader: EbpfLoader,
}

impl ConnTrackManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    pub fn remove_all_connections(&self, ifindex: u32) -> NetworkResult<()> {
        debug!(ifindex = ifindex, "removing all connection tracking state");
        self.loader.gc_connections(ifindex).map_err(|e| {
            crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("connection GC failed: {e}"),
            }
        })
    }

    pub fn reconcile(&self, sandbox_id: &str, ifindex: u32) -> NetworkResult<u32> {
        let start = Instant::now();
        let count = self.loader.reconcile_conn_count(ifindex).map_err(|e| {
            crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("connection count reconciliation failed: {e}"),
            }
        })?;

        debug!(
            sandbox_id = %sandbox_id,
            ifindex = ifindex,
            conn_count = count,
            latency_us = start.elapsed().as_micros(),
            "reconciled connection count"
        );

        Ok(count)
    }

    pub fn nat_active_count(&self, ifindex: u32) -> NetworkResult<u32> {
        self.loader.nat_entry_count(ifindex).map_err(|e| {
            crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("NAT entry count query failed: {e}"),
            }
        })
    }

    pub fn remove_all_nat_entries(&self, ifindex: u32) -> NetworkResult<usize> {
        debug!(ifindex = ifindex, "removing all NAT entries");
        self.loader.gc_nat_entries(ifindex).map_err(|e| {
            crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("NAT GC failed: {e}"),
            }
        })
    }

    pub fn gc_stale_nat_entries(&self, ifindex: u32, max_idle_secs: u64) -> NetworkResult<usize> {
        let max_idle_ns = max_idle_secs.saturating_mul(1_000_000_000);
        let count = self
            .loader
            .gc_stale_nat_entries(ifindex, max_idle_ns)
            .map_err(|e| crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("stale NAT GC failed: {e}"),
            })?;

        debug!(
            ifindex = ifindex,
            removed = count,
            max_idle_secs = max_idle_secs,
            "GC'd stale NAT entries"
        );

        Ok(count)
    }

    pub fn total_nat_entries(&self) -> NetworkResult<u32> {
        let count = self.loader.nat_entry_count(0).map_err(|e| {
            crate::error::NetworkAgentError::EbpfMapError {
                detail: format!("total NAT entry count query failed: {e}"),
            }
        })?;
        Ok(count)
    }
}
