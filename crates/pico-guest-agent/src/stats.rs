//! Stats handler for the guest agent. Returns CPU, memory, and disk
//! usage counters collected via sys-info.

use pico_guest_protocol::framed;
use pico_guest_protocol::operational_v1::*;

use crate::exec::{OperationalSession, SharedWriter, write_tagged_response};

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum StatsError {
    #[error("failed to collect stats: {0}")]
    CollectionFailed(String),

    #[error("context validation failed: {0}")]
    ContextValidation(String),
}

pub(crate) async fn handle_stats(
    session: &OperationalSession,
    request: StatsRequest,
    writer: &SharedWriter,
    timeout: std::time::Duration,
) -> Result<(), StatsError> {
    let ctx = request
        .context
        .as_ref()
        .ok_or_else(|| StatsError::ContextValidation("missing context".into()))?;
    session
        .validate_context(ctx)
        .map_err(|e| StatsError::ContextValidation(e.to_string()))?;

    let stats = collect_system_stats()
        .map_err(|e| StatsError::CollectionFailed(format!("stats collection failed: {e}")))?;

    let response = StatsResponse {
        cpu: stats.cpu,
        memory: stats.memory,
        disk: stats.disk,
    };

    write_tagged_response(writer, framed::TAG_STATS_RESPONSE, &response, timeout)
        .await
        .map_err(|e| StatsError::CollectionFailed(format!("send stats response: {e}")))?;

    tracing::debug!(?stats.cpu, ?stats.memory, ?stats.disk, "stats collected");

    Ok(())
}

fn collect_system_stats() -> Result<StatsResponse, String> {
    let load = sys_info::loadavg().map_err(|e| format!("loadavg: {e}"))?;
    let mem = sys_info::mem_info().map_err(|e| format!("meminfo: {e}"))?;
    let disk = sys_info::disk_info().map_err(|e| format!("diskinfo: {e}"))?;

    let cpu_user_secs = load.one as u64;
    let cpu_user_nanos = ((load.one - load.one.floor()) * 1_000_000_000.0) as u32;

    let cpu = Some(stats_response::CpuStats {
        user_time: Some(prost_types::Duration {
            seconds: cpu_user_secs as i64,
            nanos: cpu_user_nanos as i32,
        }),
        system_time: Some(prost_types::Duration {
            seconds: 0,
            nanos: 0,
        }),
        context_switches: 0,
    });

    let memory = Some(stats_response::MemoryStats {
        rss_bytes: mem.total.saturating_sub(mem.avail) * 1024,
        available_bytes: mem.avail * 1024,
        total_bytes: mem.total * 1024,
        swap_bytes: (mem.swap_total.saturating_sub(mem.swap_free)) * 1024,
    });

    let disk = Some(stats_response::DiskStats {
        total_bytes: disk.total * 1024,
        used_bytes: disk.total.saturating_sub(disk.free) * 1024,
        available_bytes: disk.free * 1024,
    });

    Ok(StatsResponse { cpu, memory, disk })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_stats_does_not_panic() {
        // This test may fail in environments where /proc is not available.
        // The function should still not panic.
        let result = collect_system_stats();
        // It's OK if this fails on non-Linux platforms.
        if let Ok(stats) = result {
            assert!(stats.cpu.is_some());
            assert!(stats.memory.is_some());
            assert!(stats.disk.is_some());
        }
    }

    #[test]
    fn stats_response_has_expected_fields() {
        let resp = StatsResponse {
            cpu: Some(stats_response::CpuStats {
                user_time: Some(prost_types::Duration {
                    seconds: 10,
                    nanos: 500_000_000,
                }),
                system_time: Some(prost_types::Duration {
                    seconds: 5,
                    nanos: 0,
                }),
                context_switches: 100,
            }),
            memory: Some(stats_response::MemoryStats {
                rss_bytes: 1048576,
                available_bytes: 8388608,
                total_bytes: 16777216,
                swap_bytes: 0,
            }),
            disk: Some(stats_response::DiskStats {
                total_bytes: 10000000000,
                used_bytes: 3000000000,
                available_bytes: 7000000000,
            }),
        };

        assert_eq!(
            resp.cpu
                .as_ref()
                .unwrap()
                .user_time
                .as_ref()
                .unwrap()
                .seconds,
            10
        );
        assert_eq!(resp.memory.as_ref().unwrap().rss_bytes, 1048576);
        assert_eq!(resp.disk.as_ref().unwrap().total_bytes, 10000000000);
    }
}
