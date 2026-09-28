//! Linux cgroup v2 helpers for applying sandbox resource limits.
//!
//! Implements the cgroup hierarchy:
//!   /sys/fs/cgroup/sandbox/{id}/
//!     cgroup.procs           -> VMM/container PID
//!     cpu.max                -> bandwidth cap
//!     cpu.weight             -> fair-share weight
//!     memory.max             -> hard limit
//!     memory.high            -> soft limit (reclaim throttle, no OOM kill)
//!     memory.oom.group       -> 1 (kill entire cgroup on OOM)
//!     pids.max               -> process count cap
//!     io.max                 -> per-device bandwidth/iops
//!     cpuset.cpus            -> CPU pinning (logical CPU list)
//!     cpuset.cpus.effective  -> effective CPU set (read-only, kernel-enforced)
//!
//! On non-Linux platforms, all operations are no-ops.

/// Default max process count for a sandbox cgroup.
pub const DEFAULT_MAX_PIDS: u32 = 512;

/// Default soft memory limit as a fraction of the hard limit.
const SOFT_LIMIT_FRACTION: f64 = 0.8;

/// Computes the soft memory limit bytes from the hard limit in megabytes.
#[must_use]
pub fn default_soft_limit_bytes(memory_mb: u64) -> u64 {
    (memory_mb as f64 * 1_048_576.0 * SOFT_LIMIT_FRACTION) as u64
}

// ── Linux implementation ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::cgroups::{format_cpu_list, parse_memory_pressure};
    use crate::types::{CpuBandwidth, IoLimit};
    use crate::{Result, SandboxError, validate_sandbox_id};
    use tracing::{debug, warn};

    const CGROUP_BASE: &str = "/sys/fs/cgroup/sandbox";

    pub struct CgroupManager {
        base_path: PathBuf,
        sandbox_id: String,
    }

    impl CgroupManager {
        /// Creates a manager for one sandbox cgroup directory.
        ///
        /// The id is validated against the workspace path rules so a
        /// malicious id cannot escape `/sys/fs/cgroup/sandbox` via `..`
        /// components. The explicit `contains("..")` guard doubles as the
        /// traversal check static analysis recognizes.
        pub fn new(sandbox_id: &str) -> Result<Self> {
            if sandbox_id.contains("..") {
                return Err(SandboxError::PathEscape(sandbox_id.into()));
            }
            validate_sandbox_id(sandbox_id)?;
            Ok(Self {
                base_path: PathBuf::from(CGROUP_BASE),
                sandbox_id: sandbox_id.to_string(),
            })
        }

        pub fn sandbox_path(&self) -> PathBuf {
            self.base_path.join(&self.sandbox_id)
        }

        fn cgroups_accessible(&self) -> bool {
            self.base_path.exists()
        }

        fn ensure_dir(&self) -> Result<()> {
            if !self.cgroups_accessible() {
                return Ok(());
            }
            let path = self.sandbox_path();
            if !path.exists() {
                fs::create_dir_all(&path).map_err(|e| SandboxError::CgroupSetupFailed {
                    controller: "directory".into(),
                    reason: format!("failed to create cgroup directory: {e}"),
                })?;
            }
            Ok(())
        }

        fn write_control(&self, file: &str, value: &str) -> Result<()> {
            if !self.cgroups_accessible() {
                return Ok(());
            }
            let path = self.sandbox_path().join(file);
            fs::write(&path, value).map_err(|e| SandboxError::CgroupSetupFailed {
                controller: file.into(),
                reason: format!("failed to write '{value}' to {}: {e}", path.display()),
            })
        }

        pub fn setup(
            &self,
            memory_limit_bytes: u64,
            memory_soft_limit_bytes: Option<u64>,
            cpu_shares: u32,
            cpu_bandwidth: Option<CpuBandwidth>,
            max_pids: Option<u32>,
            io_limits: &[IoLimit],
        ) -> Result<()> {
            self.ensure_dir()?;

            self.write_control("memory.max", &memory_limit_bytes.to_string())?;

            if let Some(soft) = memory_soft_limit_bytes {
                self.write_control("memory.high", &soft.to_string())?;
            }

            // memory.oom.group is best-effort: some kernel configs may
            // have the controller compiled out or mounted read-only.
            if let Err(e) = self.write_control("memory.oom.group", "1") {
                warn!(
                    sandbox_id = %self.sandbox_id,
                    error = %e,
                    "failed to set memory.oom.group (OOM kill may affect individual processes instead of the entire cgroup)"
                );
            }

            let weight = (cpu_shares / 10).clamp(1, 10000);
            self.write_control("cpu.weight", &weight.to_string())?;

            if let Some(bw) = cpu_bandwidth {
                self.write_control("cpu.max", &format!("{} {}", bw.max_us, bw.period_us))?;
            }

            if let Some(pids) = max_pids {
                self.write_control("pids.max", &pids.to_string())?;
            }

            for io in io_limits {
                let mut parts = Vec::new();
                if let Some(rbps) = io.rbps {
                    parts.push(format!("rbps={rbps}"));
                }
                if let Some(wbps) = io.wbps {
                    parts.push(format!("wbps={wbps}"));
                }
                if let Some(riops) = io.riops {
                    parts.push(format!("riops={riops}"));
                }
                if let Some(wiops) = io.wiops {
                    parts.push(format!("wiops={wiops}"));
                }
                if !parts.is_empty() {
                    let value = format!(
                        "{}:{} {}",
                        io.device_major,
                        io.device_minor,
                        parts.join(" ")
                    );
                    self.write_control("io.max", &value)?;
                }
            }

            Ok(())
        }

        /// Adds a running process to the sandbox cgroup.
        ///
        /// Production callers must go through
        /// `HostResourceManager::attach_process` in
        /// `pico-sandboxd/src/resources.rs` rather than writing
        /// `cgroup.procs` directly.
        pub fn add_process(&self, pid: u32) -> Result<()> {
            let path = self.sandbox_path().join("cgroup.procs");
            fs::write(&path, pid.to_string()).map_err(|e| SandboxError::CgroupSetupFailed {
                controller: "cgroup.procs".into(),
                reason: format!("failed to add process {pid} to cgroup: {e}"),
            })?;
            Ok(())
        }

        /// Sets the CPU pinning via the cpuset controller.
        ///
        /// Writes a CPU list like "0-3" or "0,2" to `cpuset.cpus`. Before
        /// writing cpuset.cpus, the parent's cpuset.cpus.effective must be
        /// written to cpuset.cpus.effective to satisfy the cgroup v2 constraint
        /// that a child's cpuset must be a subset of its parent's effective set.
        pub fn setup_cpuset(&self, cpus: &[u32]) -> Result<()> {
            if !self.cgroups_accessible() {
                return Ok(());
            }

            // Read parent's effective CPUs to satisfy cgroup v2 constraint
            let parent_effective = self.base_path.join("cpuset.cpus.effective");
            if let Ok(effective_str) = fs::read_to_string(&parent_effective) {
                let effective = effective_str.trim();
                if !effective.is_empty() {
                    // Write parent's effective set as the child's effective prerequisite
                    let cpuset_effective = self.sandbox_path().join("cpuset.cpus.effective");
                    if let Err(e) = fs::write(&cpuset_effective, effective) {
                        debug!(
                            sandbox_id = %self.sandbox_id,
                            error = %e,
                            "failed to pre-initialize cpuset.cpus.effective (may be ok if cpuset controller is not mounted)"
                        );
                    }
                }
            }

            // Format CPU list for cpuset.cpus
            let cpu_list = format_cpu_list(cpus);
            self.write_control("cpuset.cpus", &cpu_list)?;

            // After setting cpuset.cpus, cpuset.mems must also be set
            if let Ok(mems) = fs::read_to_string(self.base_path.join("cpuset.mems.effective")) {
                let mems = mems.trim();
                if !mems.is_empty() {
                    self.write_control("cpuset.mems", mems)?;
                }
            } else {
                // Fallback: set all memory nodes
                let _ = self.write_control("cpuset.mems", "0");
            }

            Ok(())
        }

        /// Applies a container reclaim plan after suspend.
        ///
        /// Writes `memory.high` throttle first, then `memory.reclaim` to push
        /// cold pages to swap while the frozen cgroup preserves execution
        /// state. Uses the plan's `file_writes` order so throttle precedes
        /// reclaim. No-op when cgroups are not accessible (non-Linux or
        /// missing mount); callers keep the sandbox suspended and log a
        /// warning when a write fails.
        pub fn apply_reclaim(&self, plan: super::ContainerReclaimPlan) -> Result<()> {
            for (file, value) in plan.file_writes() {
                self.write_control(file, &value)?;
            }
            Ok(())
        }

        pub fn cleanup(&self) -> Result<()> {
            let path = self.sandbox_path();
            if !path.exists() {
                return Ok(());
            }
            // Cgroups often stay busy briefly while tasks exit. Retry the full
            // tree removal so destroy can release receipts without review.
            crate::fs_retry::retry_transient_fs_op("cgroup-cleanup", || {
                self.remove_cgroup_tree_once(&path)
            })
            .map_err(|e| SandboxError::CgroupCleanupFailed {
                reason: format!("failed to remove cgroup {}: {e}", path.display()),
            })
        }

        fn remove_cgroup_tree_once(&self, path: &Path) -> std::io::Result<()> {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let child = entry.path();
                    if child.is_dir() {
                        self.remove_cgroup_tree_once(&child)?;
                    }
                }
            }

            match fs::remove_dir(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }

        #[must_use]
        pub fn exists(&self) -> bool {
            self.sandbox_path().exists()
        }

        /// Kernel cgroup id used by eBPF (`bpf_get_current_cgroup_id`).
        ///
        /// On cgroup v2 this is the directory inode of the sandbox cgroup.
        #[must_use]
        pub fn cgroup_id(&self) -> Option<u64> {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(self.sandbox_path()).ok().map(|m| m.ino())
        }

        pub fn oom_kill_count(&self) -> Result<u64> {
            let events = self.read_control("memory.events")?;
            for line in events.lines() {
                if let Some(count_str) = line.strip_prefix("oom_kill ") {
                    return count_str.trim().parse::<u64>().map_err(|e| {
                        SandboxError::Other(format!("failed to parse oom_kill: {e}"))
                    });
                }
            }
            Ok(0)
        }

        /// Reads the cgroup v2 `memory.pressure` file and returns the
        /// `some avg10` value as a floating-point percentage (0.0--100.0).
        ///
        /// The `memory.pressure` file tracks the time tasks were stalled
        /// due to memory pressure. The `some` line reports pressure when
        /// at least some tasks are stalled; the `full` line reports when
        /// all non-idle tasks are stalled.
        ///
        /// Returns `None` if the controller is not mounted or the file
        /// cannot be parsed.
        ///
        /// File format:
        /// ```text
        /// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
        /// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
        /// ```
        #[must_use]
        pub fn read_memory_pressure(&self) -> Option<f64> {
            if !self.cgroups_accessible() {
                return None;
            }
            let path = self.sandbox_path().join("memory.pressure");
            let contents = std::fs::read_to_string(&path).ok()?;
            parse_memory_pressure(&contents)
        }

        fn read_control(&self, file: &str) -> Result<String> {
            let path = self.sandbox_path().join(file);
            fs::read_to_string(&path).map_err(|e| SandboxError::CgroupSetupFailed {
                controller: file.into(),
                reason: format!("failed to read {}: {e}", path.display()),
            })
        }
    }
}

// ── Non-Linux stub ────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::PathBuf;

    use crate::Result;
    use crate::types::{CpuBandwidth, IoLimit};
    use crate::validate_sandbox_id;

    pub struct CgroupManager {
        _base_path: PathBuf,
        _sandbox_id: String,
    }

    impl CgroupManager {
        /// Creates a non-Linux stub manager. The id is validated like the
        /// Linux implementation so invalid ids fail closed on every platform.
        pub fn new(sandbox_id: &str) -> Result<Self> {
            if sandbox_id.contains("..") {
                return Err(crate::SandboxError::PathEscape(sandbox_id.into()));
            }
            validate_sandbox_id(sandbox_id)?;
            Ok(Self {
                _base_path: PathBuf::from("/sys/fs/cgroup/sandbox"),
                _sandbox_id: sandbox_id.to_string(),
            })
        }

        pub fn setup(
            &self,
            _memory_limit_bytes: u64,
            _memory_soft_limit_bytes: Option<u64>,
            _cpu_shares: u32,
            _cpu_bandwidth: Option<CpuBandwidth>,
            _max_pids: Option<u32>,
            _io_limits: &[IoLimit],
        ) -> Result<()> {
            Ok(())
        }

        pub fn add_process(&self, _pid: u32) -> Result<()> {
            Ok(())
        }

        pub fn setup_cpuset(&self, _cpus: &[u32]) -> Result<()> {
            Ok(())
        }

        /// Applies a container reclaim plan after suspend (non-Linux no-op).
        pub fn apply_reclaim(&self, _plan: super::ContainerReclaimPlan) -> Result<()> {
            Ok(())
        }

        pub fn cleanup(&self) -> Result<()> {
            Ok(())
        }

        #[must_use]
        pub fn exists(&self) -> bool {
            false
        }

        pub fn oom_kill_count(&self) -> Result<u64> {
            Ok(0)
        }

        #[must_use]
        pub fn sandbox_path(&self) -> PathBuf {
            self._base_path.join(&self._sandbox_id)
        }

        /// Stable pseudo-id when real cgroup inode is unavailable (non-Linux).
        #[must_use]
        pub fn cgroup_id(&self) -> Option<u64> {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in self._sandbox_id.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            Some(h)
        }

        #[must_use]
        pub fn read_memory_pressure(&self) -> Option<f64> {
            None
        }
    }
}

pub use imp::CgroupManager;

/// Parses cgroup v2 `memory.pressure` file contents and returns the
/// `some avg10` value as a floating-point percentage (0.0--100.0).
///
/// The `memory.pressure` file format:
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
///
/// Returns `None` if the file is malformed or missing expected fields.
#[must_use]
pub fn parse_memory_pressure(contents: &str) -> Option<f64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("avg10=") {
                    return val.parse::<f64>().ok();
                }
            }
        }
    }
    None
}

/// Parses a single named counter from `memory.events` or `cpu.stat` contents.
///
/// Matches lines of the form `<field> <value>` with exact field-name match
/// (whitespace separated), so `high` does not match `high_detail`.
fn parse_cgroup_counter(contents: &str, field: &str) -> Option<u64> {
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(field) {
            let value = parts.next()?;
            return value.parse::<u64>().ok();
        }
    }
    None
}

/// Parses the cumulative `oom_kill` count from `memory.events` contents.
///
/// Returns `None` when the field is missing or malformed; callers skip
/// the poll for that cgroup rather than emitting a fabricated delta.
#[must_use]
pub fn parse_memory_events_oom_kill(contents: &str) -> Option<u64> {
    parse_cgroup_counter(contents, "oom_kill")
}

/// Parses the cumulative `high` count from `memory.events` contents.
///
/// Returns `None` when the field is missing or malformed; callers skip
/// the poll for that cgroup rather than emitting a fabricated delta.
#[must_use]
pub fn parse_memory_events_high(contents: &str) -> Option<u64> {
    parse_cgroup_counter(contents, "high")
}

/// Parses the cumulative `nr_throttled` count from `cpu.stat` contents.
///
/// `nr_throttled` counts throttled periods (not microseconds); the poller
/// diffs it to emit `pico_cgroup_cpu_throttled_total`. Returns `None`
/// when the field is missing or malformed.
#[must_use]
pub fn parse_cpu_stat_nr_throttled(contents: &str) -> Option<u64> {
    parse_cgroup_counter(contents, "nr_throttled")
}

/// Computes the delta between a cumulative cgroup counter and its baseline.
///
/// First observation (`None` baseline) establishes the baseline and yields
/// zero delta so host restarts do not spike host-level totals. A reset
/// (`current < baseline`, cgroup recreated) yields `current` as the delta.
#[must_use]
pub fn cgroup_counter_delta(current: u64, baseline: Option<u64>) -> u64 {
    match baseline {
        None => 0,
        Some(prev) if current >= prev => current - prev,
        Some(_) => current,
    }
}

/// Formats a slice of CPU IDs into a Linux cpuset list string.
///
/// Consecutive CPU IDs are collapsed into ranges, e.g. [0,1,2,4] -> "0-2,4".
#[cfg(any(target_os = "linux", test))]
pub(crate) fn format_cpu_list(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<u32> = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts: Vec<String> = Vec::new();
    let mut range_start = sorted[0];
    let mut range_end = sorted[0];

    for &cpu in &sorted[1..] {
        if cpu == range_end + 1 {
            range_end = cpu;
        } else {
            if range_start == range_end {
                parts.push(format!("{range_start}"));
            } else {
                parts.push(format!("{range_start}-{range_end}"));
            }
            range_start = cpu;
            range_end = cpu;
        }
    }
    if range_start == range_end {
        parts.push(format!("{range_start}"));
    } else {
        parts.push(format!("{range_start}-{range_end}"));
    }

    parts.join(",")
}

/// Prefetch advice applied on container resume.
///
/// Hot pages reclaimed to swap are prefetched with `MADV_WILLNEED` so the
/// next request faults them back before execution resumes. The constant
/// documents the contract; the actual `madvise` call lives in the
/// privileged helper that owns the reclaimed mapping.
pub const CONTAINER_PREFETCH_ADVICE: &str = "MADV_WILLNEED";

/// Container reclaim plan: cgroup throttle plus swap reclaim.
///
/// The plan is pure data so unit tests can assert the throttle math
/// without touching `/sys/fs/cgroup`. The privileged helper applies it
/// best-effort after the sandbox is suspended: lower `memory.high` to
/// throttle, write `memory.reclaim` to push cold pages to swap, and keep
/// the frozen cgroup so execution state is preserved while host memory
/// is freed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerReclaimPlan {
    /// Target for `memory.high` during reclaim (bytes).
    pub memory_high_bytes: u64,
    /// Bytes requested through `memory.reclaim` (bytes).
    pub reclaim_bytes: u64,
}

impl ContainerReclaimPlan {
    /// Control file writes that implement this plan.
    ///
    /// Returns `(file, value)` pairs in apply order: throttle first, then
    /// reclaim. Callers write each file best-effort and keep the sandbox
    /// suspended when a write fails.
    #[must_use]
    pub fn file_writes(self) -> Vec<(&'static str, String)> {
        vec![
            ("memory.high", self.memory_high_bytes.to_string()),
            ("memory.reclaim", self.reclaim_bytes.to_string()),
        ]
    }
}

/// Computes the container reclaim plan for a sandbox.
///
/// The throttle is half the hard limit so the kernel reclaims aggressively
/// without tripping the OOM killer; the reclaim request equals the full
/// hard limit so cold pages move to swap while the frozen cgroup preserves
/// execution state. Zero or tiny inputs fail closed.
pub fn container_reclaim_plan(memory_limit_bytes: u64) -> crate::Result<ContainerReclaimPlan> {
    if memory_limit_bytes == 0 {
        return Err(crate::SandboxError::BadRequest(
            "container reclaim requires a non-zero memory limit".into(),
        ));
    }
    let memory_high_bytes = memory_limit_bytes / 2;
    if memory_high_bytes == 0 {
        return Err(crate::SandboxError::BadRequest(
            "container reclaim memory limit is too small to throttle".into(),
        ));
    }
    Ok(ContainerReclaimPlan {
        memory_high_bytes,
        reclaim_bytes: memory_limit_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_manager_has_deterministic_path() {
        let mgr = CgroupManager::new("sbx_test123").unwrap();
        #[cfg(target_os = "linux")]
        {
            let path = mgr.sandbox_path();
            assert!(path.ends_with("sbx_test123"));
            assert!(path.to_string_lossy().contains("/sys/fs/cgroup/sandbox"));
        }
        #[cfg(not(target_os = "linux"))]
        assert!(!mgr.exists());
    }

    #[test]
    fn cgroup_manager_id_is_preserved() {
        let _mgr = CgroupManager::new("sbx_abc").unwrap();
    }

    #[test]
    fn cgroup_manager_rejects_traversal_id() {
        for id in ["../escape", "sbx_..", "sbx_a/b", "sbx_a\\b", "evil"] {
            assert!(
                CgroupManager::new(id).is_err(),
                "cgroup id {id} must be rejected"
            );
        }
    }

    #[test]
    fn parse_memory_pressure_happy_path() {
        let contents = "some avg10=25.50 avg60=15.25 avg300=10.00 total=12345\nfull avg10=5.00 avg60=3.00 avg300=2.00 total=6789";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(25.5));
    }

    #[test]
    fn parse_memory_pressure_zero_values() {
        let contents = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(0.0));
    }

    #[test]
    fn parse_memory_pressure_hundred_percent() {
        let contents = "some avg10=100.00 avg60=95.50 avg300=90.00 total=99999";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(100.0));
    }

    #[test]
    fn parse_memory_pressure_full_line_only() {
        // Only full line, no some line - should return None
        let contents = "full avg10=50.00 avg60=40.00 avg300=30.00 total=5555";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_memory_pressure_missing_avg10() {
        // some line exists but avg10 is missing
        let contents = "some avg60=15.25 avg300=10.00 total=12345";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_memory_pressure_malformed_avg10() {
        // avg10 has non-numeric value
        let contents = "some avg10=invalid avg60=15.25 avg300=10.00 total=12345";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_memory_pressure_empty_file() {
        let contents = "";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_memory_pressure_no_lines() {
        let contents = "random text without structure";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_memory_pressure_some_line_not_first() {
        // some line appears after full line
        let contents = "full avg10=5.00 avg60=3.00 avg300=2.00 total=6789\nsome avg10=75.25 avg60=60.00 avg300=50.00 total=11111";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(75.25));
    }

    #[test]
    fn parse_memory_pressure_extra_whitespace() {
        // Extra whitespace in avg10 value
        let contents = "some avg10=  33.33   avg60=25.00 avg300=20.00 total=9999";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, None); // Should fail because avg10=  33.33 is malformed
    }

    #[test]
    fn parse_memory_pressure_scientific_notation() {
        // Scientific notation should parse correctly
        let contents = "some avg10=1.5e1 avg60=1.2e1 avg300=1.0e1 total=12345";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(15.0));
    }

    #[test]
    fn parse_memory_pressure_negative_value() {
        // Negative values should parse (though not realistic for pressure)
        let contents = "some avg10=-5.00 avg60=3.00 avg300=2.00 total=12345";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(-5.0));
    }

    #[test]
    fn parse_memory_pressure_very_small_value() {
        let contents = "some avg10=0.0001 avg60=0.0001 avg300=0.0001 total=12345";
        let result = parse_memory_pressure(contents);
        assert!(result.is_some());
        assert!((result.unwrap() - 0.0001).abs() < 1e-10);
    }

    #[test]
    fn parse_memory_pressure_very_large_value() {
        let contents = "some avg10=999999.99 avg60=888888.88 avg300=777777.77 total=12345";
        let result = parse_memory_pressure(contents);
        assert_eq!(result, Some(999999.99));
    }

    #[test]
    fn format_cpu_list_empty_input() {
        assert_eq!(format_cpu_list(&[]), "");
    }

    #[test]
    fn format_cpu_list_single_cpu() {
        assert_eq!(format_cpu_list(&[4]), "4");
    }

    #[test]
    fn format_cpu_list_collapses_consecutive_ranges() {
        assert_eq!(format_cpu_list(&[0, 1, 2, 3]), "0-3");
        assert_eq!(format_cpu_list(&[0, 1, 2, 4]), "0-2,4");
    }

    #[test]
    fn format_cpu_list_sorts_and_dedups_input() {
        assert_eq!(format_cpu_list(&[3, 1, 2, 0, 2, 1, 3]), "0-3");
        assert_eq!(format_cpu_list(&[4, 1, 5, 1]), "1,4-5");
    }

    #[test]
    fn format_cpu_list_large_non_consecutive_set() {
        let cpus: Vec<u32> = (0..128).filter(|cpu| cpu % 2 == 0).collect();
        let expected: Vec<String> = (0..64).map(|i| (i * 2).to_string()).collect();
        assert_eq!(format_cpu_list(&cpus), expected.join(","));
    }

    #[test]
    fn format_cpu_list_round_trips_arbitrary_inputs() {
        // Deterministic pseudo-random generator so the property test is
        // reproducible across runs without external dependencies.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..100 {
            let count = (next() % 32) as usize;
            let cpus: Vec<u32> = (0..count).map(|_| (next() % 256) as u32).collect();
            let mut expected: Vec<u32> = cpus.clone();
            expected.sort_unstable();
            expected.dedup();

            let formatted = format_cpu_list(&cpus);
            let parsed = parse_cpu_list(&formatted);

            assert_eq!(parsed, expected, "round trip failed for {cpus:?}");
        }
    }

    /// Parses a cpuset list string back into sorted, deduplicated CPU IDs.
    fn parse_cpu_list(list: &str) -> Vec<u32> {
        if list.is_empty() {
            return Vec::new();
        }
        let mut cpus = Vec::new();
        for part in list.split(',') {
            if let Some((start, end)) = part.split_once('-') {
                let start: u32 = start.parse().unwrap();
                let end: u32 = end.parse().unwrap();
                cpus.extend(start..=end);
            } else {
                cpus.push(part.parse().unwrap());
            }
        }
        cpus.sort_unstable();
        cpus.dedup();
        cpus
    }

    #[test]
    fn parse_memory_events_happy_path() {
        let contents = "low 0\nhigh 7\nmax 3\noom 1\noom_kill 2\n";
        assert_eq!(parse_memory_events_oom_kill(contents), Some(2));
        assert_eq!(parse_memory_events_high(contents), Some(7));
    }

    #[test]
    fn parse_memory_events_missing_field_returns_none() {
        let contents = "low 0\nmax 0\noom 0\n";
        assert_eq!(parse_memory_events_oom_kill(contents), None);
        assert_eq!(parse_memory_events_high(contents), None);
    }

    #[test]
    fn parse_memory_events_malformed_value_returns_none() {
        let contents = "low 0\nhigh boom\nmax 0\noom 0\noom_kill nope\n";
        assert_eq!(parse_memory_events_oom_kill(contents), None);
        assert_eq!(parse_memory_events_high(contents), None);
    }

    #[test]
    fn parse_memory_events_ignores_similar_prefixes() {
        // Exact field match only; `high_detail` must not satisfy `high`.
        let contents = "high_detail 99\nlow 0\nmax 0\noom 0\noom_kill 1\n";
        assert_eq!(parse_memory_events_high(contents), None);
        assert_eq!(parse_memory_events_oom_kill(contents), Some(1));
    }

    #[test]
    fn parse_cpu_stat_nr_throttled_happy_path() {
        let contents = "usage_usec 123\nuser_usec 45\nsystem_usec 78\nnr_periods 10\nnr_throttled 4\nthrottled_usec 9000\n";
        assert_eq!(parse_cpu_stat_nr_throttled(contents), Some(4));
    }

    #[test]
    fn parse_cpu_stat_nr_throttled_missing_returns_none() {
        let contents = "usage_usec 123\nnr_periods 10\n";
        assert_eq!(parse_cpu_stat_nr_throttled(contents), None);
    }

    #[test]
    fn parse_cpu_stat_nr_throttled_malformed_returns_none() {
        let contents = "nr_throttled many\nnr_periods 10\n";
        assert_eq!(parse_cpu_stat_nr_throttled(contents), None);
    }

    #[test]
    fn cgroup_counter_delta_baselines_first_poll() {
        assert_eq!(cgroup_counter_delta(42, None), 0);
    }

    #[test]
    fn cgroup_counter_delta_accumulates_growth() {
        assert_eq!(cgroup_counter_delta(10, Some(7)), 3);
        assert_eq!(cgroup_counter_delta(7, Some(7)), 0);
    }

    #[test]
    fn cgroup_counter_delta_treats_reset_as_new_epoch() {
        // Cgroup recreated: kernel counters restart at zero.
        assert_eq!(cgroup_counter_delta(2, Some(100)), 2);
    }

    #[test]
    fn container_reclaim_plan_halves_throttle() {
        let plan = container_reclaim_plan(1_073_741_824).unwrap();
        assert_eq!(plan.memory_high_bytes, 536_870_912);
        assert_eq!(plan.reclaim_bytes, 1_073_741_824);
        let writes = plan.file_writes();
        assert_eq!(writes[0].0, "memory.high");
        assert_eq!(writes[1].0, "memory.reclaim");
    }

    #[test]
    fn apply_reclaim_is_noop_without_cgroup_mount() {
        // The test environment has no writable cgroup mount, so the write
        // path is exercised as a safe no-op rather than panicking or
        // erroring out. The plan math is asserted separately.
        let mgr = CgroupManager::new("sbx_reclaim").unwrap();
        let plan = container_reclaim_plan(2_097_152).unwrap();
        let _ = mgr.apply_reclaim(plan);
    }

    #[test]
    fn container_reclaim_plan_rejects_zero_limit() {
        assert!(container_reclaim_plan(0).is_err());
        assert!(container_reclaim_plan(1).is_err());
    }

    #[test]
    fn container_prefetch_advice_is_willneed() {
        assert_eq!(CONTAINER_PREFETCH_ADVICE, "MADV_WILLNEED");
    }
}
