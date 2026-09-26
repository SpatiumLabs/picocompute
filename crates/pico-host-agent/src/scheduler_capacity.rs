//! Adapter from host-agent boot inventory to the shared scheduler capacity model.
//!
//! The host-agent detects OS totals once at boot (CPU count, memory and disk
//! totals). The cell scheduler needs allocated-vs-total vCPU, memory, disk,
//! network, and process slots plus in-flight create/restore pressure. This
//! module owns that translation so live inventory can populate packing
//! decisions instead of only boot-time totals.
//!
//! Totals come from [`crate::identity::HostCapacity::detect`]. Allocated
//! resources are summed from live sandbox entries at report time. Disk has no
//! per-sandbox request field, so each live sandbox accounts for the same
//! default the placement gate assumes per sandbox. Network allocation is not
//! tracked per sandbox yet and reports zero allocated against a fixed total.

use pico_core::{
    HostCapacity as SchedulerHostCapacity, HostHealth as SchedulerHostHealth,
    HostPressure as SchedulerHostPressure,
};

use crate::health::{HealthStatus, HostHealth as AgentHostHealth};
use crate::identity::HostCapacity as BootHostCapacity;

/// Total network bandwidth in Mbps advertised when no measured total exists.
///
/// Matches the control-plane fallback used before live reporting so existing
/// placements do not shift when the adapter lands.
pub const DEFAULT_TOTAL_NETWORK_MBPS: u64 = 10_000;

/// Maximum sandbox process slots advertised per host.
///
/// Matches the control-plane fallback. Each live sandbox consumes one slot.
pub const DEFAULT_MAX_PROCESS_SLOTS: u64 = 1000;

/// Disk in MB accounted per live sandbox.
///
/// `SandboxSpec` carries no disk field, so placement assumes 1 GiB per
/// sandbox. The host uses the same assumption when summing used disk.
pub const DEFAULT_DISK_MB_PER_SANDBOX: u64 = 1024;

/// Maximum concurrent sandbox creates the host accepts.
pub const MAX_CONCURRENT_CREATES: u32 = 8;

/// Maximum concurrent snapshot restores the host accepts.
pub const MAX_CONCURRENT_RESTORES: u32 = 8;

/// Allocated resources summed from live sandbox entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocatedResources {
    /// Sum of requested vCPUs across live sandboxes.
    pub vcpus: u64,
    /// Sum of requested memory in MB across live sandboxes.
    pub memory_mb: u64,
    /// Number of live sandboxes.
    pub sandbox_count: u64,
}

/// Builds scheduler capacity from boot totals plus live allocation.
///
/// `used_disk_mb` is `sandbox_count * DEFAULT_DISK_MB_PER_SANDBOX` because
/// per-sandbox disk requests are not tracked. Network allocation reports zero
/// until per-sandbox bandwidth accounting exists. Each sandbox consumes one
/// process slot.
pub fn scheduler_capacity(
    boot: &BootHostCapacity,
    allocated: AllocatedResources,
) -> SchedulerHostCapacity {
    SchedulerHostCapacity {
        total_vcpus: u64::from(boot.cpu_count),
        allocated_vcpus: allocated.vcpus,
        total_memory_mb: boot.memory_mb_total,
        allocated_memory_mb: allocated.memory_mb,
        total_disk_mb: boot.disk_mb_total,
        used_disk_mb: allocated
            .sandbox_count
            .saturating_mul(DEFAULT_DISK_MB_PER_SANDBOX),
        total_network_mbps: DEFAULT_TOTAL_NETWORK_MBPS,
        allocated_network_mbps: 0,
        max_process_slots: DEFAULT_MAX_PROCESS_SLOTS,
        used_process_slots: allocated.sandbox_count,
    }
}

/// Builds scheduler pressure from in-flight operation counts.
pub fn scheduler_pressure(
    in_flight_creates: u32,
    in_flight_restores: u32,
) -> SchedulerHostPressure {
    SchedulerHostPressure {
        in_flight_creates,
        in_flight_restores,
        max_concurrent_creates: MAX_CONCURRENT_CREATES,
        max_concurrent_restores: MAX_CONCURRENT_RESTORES,
    }
}

/// Maps agent health plus the drain flag onto scheduler health.
///
/// A draining host never admits, even when the last probe was ready. An
/// unsafe host maps to unavailable so placement fails closed.
pub fn scheduler_health(health: &AgentHostHealth, draining: bool) -> SchedulerHostHealth {
    if draining || health.status == HealthStatus::Draining {
        return SchedulerHostHealth::Draining;
    }
    match health.status {
        HealthStatus::Ready => SchedulerHostHealth::Healthy,
        HealthStatus::Degraded => SchedulerHostHealth::Degraded,
        HealthStatus::Draining => SchedulerHostHealth::Draining,
        HealthStatus::Unsafe => SchedulerHostHealth::Unavailable,
    }
}

/// Utilization in 0.0-1.0 for a used/total pair. Zero total reports zero.
pub fn utilization(used: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (used.min(total) as f64) / (total as f64)
}

/// Utilization breakdown for the capacity gauges.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapacityUtilization {
    /// Allocated vCPUs over total vCPUs.
    pub cpu: f64,
    /// Allocated memory over total memory.
    pub memory: f64,
    /// Used disk over total disk.
    pub disk: f64,
    /// Allocated network over total network.
    pub network: f64,
    /// Used process slots over max slots.
    pub process_slots: f64,
}

impl CapacityUtilization {
    /// Derives per-resource utilization from a scheduler capacity snapshot.
    pub fn from_capacity(capacity: &SchedulerHostCapacity) -> Self {
        Self {
            cpu: utilization(capacity.allocated_vcpus, capacity.total_vcpus),
            memory: utilization(capacity.allocated_memory_mb, capacity.total_memory_mb),
            disk: utilization(capacity.used_disk_mb, capacity.total_disk_mb),
            network: utilization(capacity.allocated_network_mbps, capacity.total_network_mbps),
            process_slots: utilization(capacity.used_process_slots, capacity.max_process_slots),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::health::HostHealth as AgentHostHealth;
    use crate::identity::HostCapacity as BootHostCapacity;

    fn boot() -> BootHostCapacity {
        BootHostCapacity {
            cpu_count: 64,
            memory_mb_total: 131_072,
            memory_mb_available: 65_536,
            disk_mb_total: 500_000,
            disk_mb_available: 400_000,
        }
    }

    #[test]
    fn capacity_maps_boot_totals_and_live_allocation() {
        let capacity = scheduler_capacity(
            &boot(),
            AllocatedResources {
                vcpus: 4,
                memory_mb: 1024,
                sandbox_count: 2,
            },
        );
        assert_eq!(capacity.total_vcpus, 64);
        assert_eq!(capacity.allocated_vcpus, 4);
        assert_eq!(capacity.total_memory_mb, 131_072);
        assert_eq!(capacity.allocated_memory_mb, 1024);
        assert_eq!(capacity.total_disk_mb, 500_000);
        assert_eq!(capacity.used_disk_mb, 2 * DEFAULT_DISK_MB_PER_SANDBOX);
        assert_eq!(capacity.total_network_mbps, DEFAULT_TOTAL_NETWORK_MBPS);
        assert_eq!(capacity.allocated_network_mbps, 0);
        assert_eq!(capacity.max_process_slots, DEFAULT_MAX_PROCESS_SLOTS);
        assert_eq!(capacity.used_process_slots, 2);
    }

    #[test]
    fn empty_host_reports_zero_allocated() {
        let capacity = scheduler_capacity(&boot(), AllocatedResources::default());
        assert_eq!(capacity.allocated_vcpus, 0);
        assert_eq!(capacity.allocated_memory_mb, 0);
        assert_eq!(capacity.used_disk_mb, 0);
        assert_eq!(capacity.used_process_slots, 0);
        assert!(capacity.can_fit(2, 512, 1024));
    }

    #[test]
    fn pressure_carries_configured_maxima() {
        let pressure = scheduler_pressure(3, 1);
        assert_eq!(pressure.in_flight_creates, 3);
        assert_eq!(pressure.in_flight_restores, 1);
        assert_eq!(pressure.max_concurrent_creates, MAX_CONCURRENT_CREATES);
        assert_eq!(pressure.max_concurrent_restores, MAX_CONCURRENT_RESTORES);
    }

    #[test]
    fn health_mapping_fails_closed() {
        let ready = AgentHostHealth::ready(0, vec![]);
        assert_eq!(
            scheduler_health(&ready, false),
            SchedulerHostHealth::Healthy
        );
        assert_eq!(
            scheduler_health(&ready, true),
            SchedulerHostHealth::Draining
        );
        let draining = AgentHostHealth::draining(1, vec![]);
        assert_eq!(
            scheduler_health(&draining, false),
            SchedulerHostHealth::Draining
        );
        let degraded = AgentHostHealth::degraded(1, vec![], "sandboxd behind".into());
        assert_eq!(
            scheduler_health(&degraded, false),
            SchedulerHostHealth::Degraded
        );
        let unsafe_state = AgentHostHealth::unsafe_state(1, vec![], "ambiguous objects".into());
        assert_eq!(
            scheduler_health(&unsafe_state, false),
            SchedulerHostHealth::Unavailable
        );
    }

    #[test]
    fn utilization_handles_zero_totals() {
        assert_eq!(utilization(5, 0), 0.0);
        assert_eq!(utilization(0, 10), 0.0);
        assert_eq!(utilization(5, 10), 0.5);
        assert_eq!(utilization(15, 10), 1.0);
    }
}
