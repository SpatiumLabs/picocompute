//! Host-level identity used for inventory reporting and structured logging.

use pico_core::RuntimeType;
use pico_core::{HostCapacity as SchedulerHostCapacity, HostPressure as SchedulerHostPressure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostIdentity {
    pub host_id: String,
    pub cell_id: String,
    pub region: String,
}

impl HostIdentity {
    pub fn new(host_id: String, cell_id: String, region: String) -> Self {
        Self {
            host_id,
            cell_id,
            region,
        }
    }

    pub fn from_env(default_region: &str) -> Self {
        let host_id = std::env::var("PICO_HOST_ID").unwrap_or_else(|_| default_host_id());
        let cell_id = std::env::var("PICO_CELL_ID").unwrap_or_else(|_| "default-cell".into());
        let region = std::env::var("PICO_REGION").unwrap_or_else(|_| default_region.into());
        Self {
            host_id,
            cell_id,
            region,
        }
    }

    pub(crate) fn default_host_id() -> String {
        default_host_id()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCapacity {
    pub cpu_count: u32,
    pub memory_mb_total: u64,
    pub memory_mb_available: u64,
    pub disk_mb_total: u64,
    pub disk_mb_available: u64,
}

impl HostCapacity {
    pub fn detect() -> Self {
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);

        let (mem_total_kb, mem_avail_kb) = detect_memory_kb();

        let (disk_total_mb, disk_avail_mb) = detect_disk_mb();

        Self {
            cpu_count,
            memory_mb_total: mem_total_kb / 1024,
            memory_mb_available: mem_avail_kb / 1024,
            disk_mb_total: disk_total_mb,
            disk_mb_available: disk_avail_mb,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostInventory {
    pub identity: HostIdentity,
    pub capacity: HostCapacity,
    pub supported_backends: Vec<RuntimeType>,
    pub agent_version: String,
    /// Scheduler capacity derived from boot totals plus live sandbox allocation.
    ///
    /// `None` only for reports produced before the first live snapshot.
    /// Deserializes as `None` for payloads from older agents.
    #[serde(default)]
    pub scheduler_capacity: Option<SchedulerHostCapacity>,
    /// In-flight create/restore pressure at report time.
    #[serde(default)]
    pub pressure: Option<SchedulerHostPressure>,
    /// Live sandbox count backing the scheduler capacity snapshot.
    #[serde(default)]
    pub current_sandboxes: u64,
}

impl HostInventory {
    /// Scheduler capacity when reported, else boot totals with zero allocated.
    ///
    /// The fallback keeps older control-plane readers placeable until the
    /// first live snapshot arrives. New code should prefer
    /// `scheduler_capacity` directly and treat the fallback as transitional.
    pub fn effective_scheduler_capacity(&self) -> SchedulerHostCapacity {
        if let Some(capacity) = self.scheduler_capacity {
            return capacity;
        }
        crate::scheduler_capacity::scheduler_capacity(
            &self.capacity,
            crate::scheduler_capacity::AllocatedResources::default(),
        )
    }

    /// Reported pressure or an idle default with configured maxima.
    pub fn effective_pressure(&self) -> SchedulerHostPressure {
        self.pressure
            .unwrap_or_else(|| crate::scheduler_capacity::scheduler_pressure(0, 0))
    }
}

fn default_host_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn detect_memory_kb() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let info = sys_info::mem_info();
        match info {
            Ok(info) => (info.total, info.avail),
            Err(_) => (0, 0),
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let total = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|b| b / 1024)
            .unwrap_or(0);

        let page_size = Command::new("sysctl")
            .args(["-n", "vm.pagesize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(4096);

        let free_pages = Command::new("sysctl")
            .args(["-n", "vm.page_free_count"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        (total, page_size * free_pages / 1024)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

fn detect_disk_mb() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let info = sys_info::disk_info();
        match info {
            Ok(info) => linux_disk_kb_to_mb(info.total, info.free),
            Err(_) => (0, 0),
        }
    }

    #[cfg(target_os = "macos")]
    {
        parse_df_output()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

#[cfg(target_os = "macos")]
fn parse_df_output() -> (u64, u64) {
    use std::process::Command;
    Command::new("df")
        .args(["-m", "/"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines().nth(1).and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    Some((parts[1].parse::<u64>().ok()?, parts[3].parse::<u64>().ok()?))
                } else {
                    None
                }
            })
        })
        .unwrap_or((10240, 10240))
}

#[cfg(target_os = "linux")]
fn linux_disk_kb_to_mb(total_kb: u64, free_kb: u64) -> (u64, u64) {
    (total_kb / 1024, free_kb / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests mutate process-global env vars, so they must not run
    // concurrently within the same test binary.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn host_identity_uses_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("PICO_HOST_ID", "test-host");
            std::env::set_var("PICO_CELL_ID", "test-cell");
            std::env::set_var("PICO_REGION", "test-region");
        }

        let identity = HostIdentity::from_env("default-region");
        assert_eq!(identity.host_id, "test-host");
        assert_eq!(identity.cell_id, "test-cell");
        assert_eq!(identity.region, "test-region");

        unsafe {
            std::env::remove_var("PICO_HOST_ID");
            std::env::remove_var("PICO_CELL_ID");
            std::env::remove_var("PICO_REGION");
        }
    }

    #[test]
    fn host_identity_falls_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("PICO_HOST_ID");
            std::env::remove_var("PICO_CELL_ID");
            std::env::remove_var("PICO_REGION");
        }
        let identity = HostIdentity::from_env("fallback-region");
        assert!(!identity.host_id.is_empty());
        assert_eq!(identity.cell_id, "default-cell");
        assert_eq!(identity.region, "fallback-region");
    }

    #[test]
    fn host_capacity_detects_cpu_count() {
        let capacity = HostCapacity::detect();
        assert!(capacity.cpu_count >= 1);
    }

    #[test]
    fn inventory_effective_capacity_prefers_live_snapshot() {
        let boot = HostCapacity {
            cpu_count: 8,
            memory_mb_total: 16384,
            memory_mb_available: 8192,
            disk_mb_total: 100_000,
            disk_mb_available: 90_000,
        };
        let live = crate::scheduler_capacity::scheduler_capacity(
            &boot,
            crate::scheduler_capacity::AllocatedResources {
                vcpus: 2,
                memory_mb: 512,
                sandbox_count: 1,
            },
        );
        let pressure = crate::scheduler_capacity::scheduler_pressure(1, 0);
        let inventory = HostInventory {
            identity: HostIdentity::new("h".into(), "c".into(), "r".into()),
            capacity: boot,
            supported_backends: vec![],
            agent_version: "test".into(),
            scheduler_capacity: Some(live),
            pressure: Some(pressure),
            current_sandboxes: 1,
        };
        assert_eq!(inventory.effective_scheduler_capacity().allocated_vcpus, 2);
        assert_eq!(inventory.effective_pressure().in_flight_creates, 1);
    }

    #[test]
    fn inventory_effective_capacity_falls_back_to_boot_totals() {
        let boot = HostCapacity {
            cpu_count: 4,
            memory_mb_total: 8192,
            memory_mb_available: 4096,
            disk_mb_total: 50_000,
            disk_mb_available: 40_000,
        };
        let inventory = HostInventory {
            identity: HostIdentity::new("h".into(), "c".into(), "r".into()),
            capacity: boot,
            supported_backends: vec![],
            agent_version: "test".into(),
            scheduler_capacity: None,
            pressure: None,
            current_sandboxes: 0,
        };
        let effective = inventory.effective_scheduler_capacity();
        assert_eq!(effective.total_vcpus, 4);
        assert_eq!(effective.allocated_vcpus, 0);
        assert_eq!(
            inventory.effective_pressure().max_concurrent_creates,
            crate::scheduler_capacity::MAX_CONCURRENT_CREATES
        );
    }

    #[test]
    fn inventory_deserializes_without_scheduler_fields() {
        // Payloads from older agents omit the scheduler snapshot.
        let json = serde_json::json!({
            "identity": {"host_id": "h", "cell_id": "c", "region": "r"},
            "capacity": {
                "cpu_count": 2,
                "memory_mb_total": 4096,
                "memory_mb_available": 2048,
                "disk_mb_total": 20000,
                "disk_mb_available": 15000
            },
            "supported_backends": [],
            "agent_version": "old"
        });
        let inventory: HostInventory = serde_json::from_value(json).unwrap();
        assert!(inventory.scheduler_capacity.is_none());
        assert!(inventory.pressure.is_none());
        assert_eq!(inventory.current_sandboxes, 0);
        assert_eq!(inventory.effective_scheduler_capacity().total_vcpus, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_units_convert_from_kb_to_mb() {
        assert_eq!(linux_disk_kb_to_mb(4 * 1024, 2 * 1024), (4, 2));
    }
}
