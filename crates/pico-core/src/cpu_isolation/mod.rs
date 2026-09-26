//! CPU pinning and SMT sibling exclusion for cross-tenant isolation.
//!
//! Implements SC-IMPL-02 per the
//! [side-channel assessment](../../../docs/security/side-channel-assessment.md):
//!
//! - Detects CPU topology and SMT sibling groups from sysfs.
//! - Allocates non-overlapping CPU sets with SMT sibling exclusion.
//! - Applies `sched_setaffinity(2)` to VMM and sentry processes.
//! - Validates that cross-tenant sandboxes do not share physical cores.
//!
//! ## Platform support
//!
//! Full support on Linux x86_64/aarch64 via sysfs topology and
//! `sched_setaffinity(2)`. On non-Linux platforms all operations
//! are no-ops that report success so development workflows are
//! not blocked. Production hosts must be Linux.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// A non-empty set of logical CPU IDs assigned to one sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CpuSet {
    /// Logical CPU indices, guaranteed sorted and non-empty.
    cpus: Vec<u32>,
}

impl CpuSet {
    /// Creates a new CPU set. Returns `None` when `cpus` is empty.
    #[must_use]
    pub fn new(cpus: impl IntoIterator<Item = u32>) -> Option<Self> {
        let mut sorted: Vec<u32> = cpus.into_iter().collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        sorted.dedup();
        Some(Self { cpus: sorted })
    }

    /// Creates a CPU set from a range `[start, end)`.
    #[must_use]
    pub fn from_range(start: u32, end: u32) -> Option<Self> {
        if end <= start {
            return None;
        }
        Some(Self {
            cpus: (start..end).collect(),
        })
    }

    /// Number of logical CPUs in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cpus.len()
    }

    /// Returns true when the set is empty (should never happen after construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    /// Returns a slice of the sorted CPU indices.
    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.cpus
    }

    /// Validates that every CPU index in this set is within the host topology range.
    ///
    /// Returns an error listing any out-of-range CPU indices.
    pub fn validate_against_topology(&self, topology: &CpuTopology) -> Result<(), Vec<u32>> {
        let max_cpu = topology.total_logical_cpus.saturating_sub(1) as u32;
        let invalid: Vec<u32> = self
            .cpus
            .iter()
            .copied()
            .filter(|&cpu| cpu > max_cpu)
            .collect();
        if invalid.is_empty() {
            Ok(())
        } else {
            Err(invalid)
        }
    }

    /// Returns true when this set overlaps with another.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.cpus.iter().any(|cpu| other.cpus.contains(cpu))
    }

    /// Merge two CPU sets, returning a new combined set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let merged: BTreeSet<u32> = self.cpus.iter().chain(&other.cpus).copied().collect();
        Self {
            cpus: merged.into_iter().collect(),
        }
    }

    /// Returns the intersection of two CPU sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Vec<u32> {
        self.cpus
            .iter()
            .filter(|cpu| other.cpus.contains(cpu))
            .copied()
            .collect()
    }

    /// Format the CPU set as a hexadecimal affinity mask string (e.g. "ff,ff").
    #[must_use]
    pub fn to_hex_mask(&self) -> String {
        if self.cpus.is_empty() {
            return String::new();
        }
        let max_cpu = *self.cpus.iter().max().unwrap_or(&0) as usize;
        let num_bytes = (max_cpu / 8) + 1;
        let mut mask = vec![0u8; num_bytes];
        for cpu in &self.cpus {
            let byte_idx = (*cpu as usize) / 8;
            let bit_idx = (*cpu as usize) % 8;
            mask[byte_idx] |= 1u8 << bit_idx;
        }
        mask.iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl fmt::Display for CpuSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.cpus.iter().map(|c| c.to_string()).collect();
        write!(f, "{}", parts.join(","))
    }
}

/// A physical CPU core identified by its SMT sibling group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalCore {
    /// Physical core identifier (package-local or topology-local).
    pub core_id: u32,
    /// Logical CPU indices that are SMT siblings on this core.
    pub siblings: Vec<u32>,
}

impl PhysicalCore {
    /// Returns true when this core has SMT enabled (more than one sibling).
    #[must_use]
    pub fn has_smt(&self) -> bool {
        self.siblings.len() > 1
    }
}

/// Detected CPU topology for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTopology {
    /// Total number of logical CPUs.
    pub total_logical_cpus: usize,
    /// Physical cores with their SMT sibling groups.
    pub physical_cores: Vec<PhysicalCore>,
}

impl CpuTopology {
    /// Detects CPU topology from sysfs on Linux.
    ///
    /// Reads `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`
    /// to discover SMT sibling groups. Falls back to a single-core model
    /// on non-Linux or when sysfs is unavailable.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            match Self::detect_linux() {
                Ok(topology) => topology,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "failed to detect CPU topology from sysfs, using flat model"
                    );
                    Self::flat_fallback()
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::flat_fallback()
        }
    }

    /// Returns a fallback topology where each logical CPU is a separate physical core.
    #[must_use]
    fn flat_fallback() -> Self {
        let total = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let physical_cores: Vec<PhysicalCore> = (0..total)
            .map(|cpu| PhysicalCore {
                core_id: cpu as u32,
                siblings: vec![cpu as u32],
            })
            .collect();
        Self {
            total_logical_cpus: total,
            physical_cores,
        }
    }

    /// Returns a map from logical CPU index to its sibling group.
    #[must_use]
    pub fn smt_sibling_map(&self) -> HashMap<u32, Vec<u32>> {
        let mut map = HashMap::new();
        for core in &self.physical_cores {
            for cpu in &core.siblings {
                map.insert(*cpu, core.siblings.clone());
            }
        }
        map
    }

    /// Returns the sibling CPU indices for a given logical CPU.
    #[must_use]
    pub fn siblings_of(&self, cpu: u32) -> Vec<u32> {
        self.physical_cores
            .iter()
            .find(|core| core.siblings.contains(&cpu))
            .map(|core| core.siblings.clone())
            .unwrap_or_else(|| vec![cpu])
    }

    /// Validates that a set of allocated CPU sets has no SMT sibling sharing
    /// across different tenants (or different sandboxes if tenant info is absent).
    ///
    /// Returns a list of violations: for each pair of CPU sets that share
    /// a physical core, reports the shared siblings.
    #[must_use]
    pub fn validate_smt_exclusion<'a>(&self, allocations: &[&'a CpuSet]) -> Vec<SmtViolation<'a>> {
        let mut violations = Vec::new();
        let sibling_map = self.smt_sibling_map();

        for i in 0..allocations.len() {
            for j in (i + 1)..allocations.len() {
                let a = allocations[i];
                let b = allocations[j];

                // Check if any CPU in a has a sibling in b
                let mut shared_siblings: Vec<(u32, u32)> = Vec::new();
                for cpu_a in a.as_slice() {
                    if let Some(siblings_a) = sibling_map.get(cpu_a) {
                        for cpu_b in b.as_slice() {
                            if siblings_a.contains(cpu_b) {
                                shared_siblings.push((*cpu_a, *cpu_b));
                            }
                        }
                    }
                }

                if !shared_siblings.is_empty() {
                    violations.push(SmtViolation {
                        set_a: a,
                        set_b: b,
                        shared_siblings,
                    });
                }
            }
        }

        violations
    }

    #[cfg(target_os = "linux")]
    fn detect_linux() -> Result<Self, String> {
        let cpu_base = "/sys/devices/system/cpu";
        let mut logical_cpus: Vec<u32> = Vec::new();
        let mut seen_siblings: HashMap<Vec<u32>, u32> = HashMap::new();
        let mut next_core_id: u32 = 0;

        for entry in fs::read_dir(cpu_base).map_err(|e| format!("cannot read {cpu_base}: {e}"))? {
            let entry = entry.map_err(|e| format!("directory entry error: {e}"))?;
            let name_str = entry.file_name().to_string_lossy().into_owned();
            if !name_str.starts_with("cpu") {
                continue;
            }
            let cpu_id: u32 = name_str[3..]
                .parse()
                .map_err(|_| format!("invalid cpu dir: {name_str}"))?;

            let siblings_path = entry.path().join("topology/thread_siblings_list");
            let siblings_str = fs::read_to_string(&siblings_path)
                .map_err(|e| format!("cannot read {siblings_path:?}: {e}"))?;
            let siblings: Vec<u32> = parse_cpu_list(siblings_str.trim());
            if siblings.is_empty() {
                continue;
            }

            logical_cpus.push(cpu_id);
            seen_siblings.entry(siblings).or_insert_with(|| {
                let id = next_core_id;
                next_core_id += 1;
                id
            });
        }

        let mut physical_cores: Vec<PhysicalCore> = seen_siblings
            .into_iter()
            .map(|(siblings, core_id)| PhysicalCore { core_id, siblings })
            .collect();
        physical_cores.sort_by_key(|c| c.core_id);

        Ok(Self {
            total_logical_cpus: logical_cpus.len(),
            physical_cores,
        })
    }
}

/// A violation of SMT sibling exclusion between two CPU sets.
#[derive(Debug, Clone)]
pub struct SmtViolation<'a> {
    /// First CPU set involved in the violation.
    pub set_a: &'a CpuSet,
    /// Second CPU set involved in the violation.
    pub set_b: &'a CpuSet,
    /// Pairs of (cpu_from_a, cpu_from_b) that share a physical core.
    pub shared_siblings: Vec<(u32, u32)>,
}

impl fmt::Display for SmtViolation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pairs: Vec<String> = self
            .shared_siblings
            .iter()
            .map(|(a, b)| format!("cpu{a}↔cpu{b}"))
            .collect();
        write!(
            f,
            "SMT sibling sharing: [{}] ↔ [{}]: {}",
            self.set_a,
            self.set_b,
            pairs.join(", ")
        )
    }
}

/// CPU isolation policy for a host or cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CpuIsolationPolicy {
    /// No CPU pinning. All sandboxes share all CPUs.
    #[default]
    None,
    /// Per-sandbox CPU pinning with non-overlapping sets.
    DedicatedCores,
    /// Dedicated cores plus SMT sibling exclusion across sandboxes.
    DedicatedCoresWithSmtExclusion,
}

impl CpuIsolationPolicy {
    /// Returns true when CPU pinning is required.
    #[must_use]
    pub fn requires_pinning(&self) -> bool {
        matches!(
            self,
            Self::DedicatedCores | Self::DedicatedCoresWithSmtExclusion
        )
    }

    /// Returns true when SMT sibling exclusion is enforced.
    #[must_use]
    pub fn requires_smt_exclusion(&self) -> bool {
        matches!(self, Self::DedicatedCoresWithSmtExclusion)
    }
}

/// Manages CPU set allocation across sandboxes on a host.
///
/// Tracks allocated CPU sets and ensures:
/// - Non-overlapping CPU sets between sandboxes.
/// - SMT sibling exclusion when policy requires it.
/// - Rejection when the host cannot satisfy isolation requirements.
#[derive(Debug, Clone)]
pub struct CpuAllocator {
    /// The host's CPU topology.
    topology: CpuTopology,
    /// Current isolation policy.
    policy: CpuIsolationPolicy,
    /// Allocated CPU sets keyed by sandbox ID.
    allocations: HashMap<String, CpuSet>,
    /// Which tenant owns each sandbox (for cross-tenant validation).
    sandbox_tenants: HashMap<String, String>,
}

impl CpuAllocator {
    /// Creates a new CPU allocator for the given topology and policy.
    #[must_use]
    pub fn new(topology: CpuTopology, policy: CpuIsolationPolicy) -> Self {
        Self {
            topology,
            policy,
            allocations: HashMap::new(),
            sandbox_tenants: HashMap::new(),
        }
    }

    /// Returns the current isolation policy.
    #[must_use]
    pub fn policy(&self) -> CpuIsolationPolicy {
        self.policy
    }

    /// Returns the detected topology.
    #[must_use]
    pub fn topology(&self) -> &CpuTopology {
        &self.topology
    }

    /// Attempts to allocate a CPU set for a sandbox.
    ///
    /// When `cpu_set` is provided, validates that it does not overlap with
    /// existing allocations and satisfies SMT exclusion (when required).
    ///
    /// When `cpu_set` is `None` and pinning is required, auto-allocates
    /// from the pool of free CPUs respecting SMT siblings.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested CPU set overlaps with an existing
    /// allocation, violates SMT exclusion, or no suitable CPUs are available.
    pub fn allocate(
        &mut self,
        sandbox_id: &str,
        tenant_id: &str,
        cpu_set: Option<&CpuSet>,
        vcpu_count: u32,
    ) -> Result<CpuSet, CpuAllocationError> {
        if !self.policy.requires_pinning() {
            // No pinning: return all CPUs
            let all = CpuSet::from_range(0, self.topology.total_logical_cpus as u32)
                .unwrap_or_else(|| CpuSet::new([0]).unwrap());
            self.allocations.insert(sandbox_id.to_string(), all.clone());
            self.sandbox_tenants
                .insert(sandbox_id.to_string(), tenant_id.to_string());
            return Ok(all);
        }

        let allocated_set = match cpu_set {
            Some(set) => {
                // Validate every CPU index is within the host topology range
                if let Err(invalid_cpus) = set.validate_against_topology(&self.topology) {
                    return Err(CpuAllocationError::InvalidCpuIndices {
                        sandbox: sandbox_id.to_string(),
                        invalid_cpus,
                        max_valid: self.topology.total_logical_cpus.saturating_sub(1) as u32,
                    });
                }

                // Validate no overlap with existing allocations
                for (existing_id, existing_set) in &self.allocations {
                    if set.overlaps(existing_set) {
                        let existing_tenant = self
                            .sandbox_tenants
                            .get(existing_id)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        // Same tenant may share CPUs
                        if existing_tenant != tenant_id {
                            return Err(CpuAllocationError::Overlap {
                                sandbox: sandbox_id.to_string(),
                                existing: existing_id.clone(),
                                overlapping: set.intersection(existing_set),
                            });
                        }
                    }
                }

                // Validate SMT sibling exclusion against other-tenant allocations.
                // The overlap check above only catches direct CPU overlap, but
                // SMT siblings (e.g. cpu0 and cpu2 on the same physical core)
                // must also not be shared across tenants even when the CPU sets
                // appear non-overlapping. We filter to only different-tenant sets
                // and chain the new set into the validation list so it is checked
                // against every surviving allocation.
                if self.policy.requires_smt_exclusion() {
                    let all_allocations: Vec<&CpuSet> = self
                        .allocations
                        .iter()
                        .filter(|(id, _)| {
                            self.sandbox_tenants.get(*id).map(|t| t.as_str()) != Some(tenant_id)
                        })
                        .map(|(_, set)| set)
                        .chain(std::iter::once(set))
                        .collect();

                    let violations = self.topology.validate_smt_exclusion(&all_allocations);
                    if !violations.is_empty() {
                        let violation_msgs: Vec<String> =
                            violations.iter().map(|v| v.to_string()).collect();
                        return Err(CpuAllocationError::SmtExclusionViolation {
                            sandbox: sandbox_id.to_string(),
                            violations: violation_msgs,
                        });
                    }
                }

                set.clone()
            }
            None => {
                // Auto-allocate from free CPUs
                self.auto_allocate(sandbox_id, tenant_id, vcpu_count)?
            }
        };

        self.allocations
            .insert(sandbox_id.to_string(), allocated_set.clone());
        self.sandbox_tenants
            .insert(sandbox_id.to_string(), tenant_id.to_string());
        Ok(allocated_set)
    }

    /// Releases a sandbox's CPU allocation.
    pub fn release(&mut self, sandbox_id: &str) {
        self.allocations.remove(sandbox_id);
        self.sandbox_tenants.remove(sandbox_id);
    }

    /// Restores a previously persisted allocation.
    ///
    /// Used to rebuild allocator state from durable ledger receipts after a
    /// daemon restart. The supplied set is trusted as proven state, so no
    /// overlap or SMT exclusion checks run: revalidating against other
    /// restored allocations would spuriously reject the exact allocation
    /// that was valid before the restart.
    ///
    /// The set is still validated against the host topology so that a
    /// restart on a smaller host fails closed with
    /// [`CpuAllocationError::InvalidCpuIndices`] instead of silently
    /// recording CPUs this host does not have.
    pub fn restore(
        &mut self,
        sandbox_id: &str,
        tenant_id: &str,
        cpu_set: CpuSet,
    ) -> Result<(), CpuAllocationError> {
        if let Err(invalid_cpus) = cpu_set.validate_against_topology(&self.topology) {
            return Err(CpuAllocationError::InvalidCpuIndices {
                sandbox: sandbox_id.to_string(),
                invalid_cpus,
                max_valid: self.topology.total_logical_cpus.saturating_sub(1) as u32,
            });
        }
        self.allocations.insert(sandbox_id.to_string(), cpu_set);
        self.sandbox_tenants
            .insert(sandbox_id.to_string(), tenant_id.to_string());
        Ok(())
    }

    /// Returns the CPU set allocated to a sandbox, if any.
    #[must_use]
    pub fn get(&self, sandbox_id: &str) -> Option<&CpuSet> {
        self.allocations.get(sandbox_id)
    }

    /// Returns all current allocations.
    #[must_use]
    pub fn allocations(&self) -> &HashMap<String, CpuSet> {
        &self.allocations
    }

    /// Returns the number of free logical CPUs.
    #[must_use]
    pub fn free_cpu_count(&self) -> usize {
        let allocated: BTreeSet<u32> = self
            .allocations
            .values()
            .flat_map(|set| set.as_slice().iter())
            .copied()
            .collect();
        self.topology.total_logical_cpus - allocated.len()
    }

    /// Auto-allocate CPUs from the free pool with SMT exclusion.
    fn auto_allocate(
        &self,
        sandbox_id: &str,
        tenant_id: &str,
        vcpu_count: u32,
    ) -> Result<CpuSet, CpuAllocationError> {
        let _ = (sandbox_id, tenant_id);
        let target_count = vcpu_count.max(1) as usize;

        // Find all allocated CPUs
        let allocated: BTreeSet<u32> = self
            .allocations
            .values()
            .flat_map(|set| set.as_slice().iter())
            .copied()
            .collect();

        // Find available CPUs
        let available: Vec<u32> = (0..self.topology.total_logical_cpus as u32)
            .filter(|cpu| !allocated.contains(cpu))
            .collect();

        if available.len() < target_count {
            return Err(CpuAllocationError::NoCpusAvailable {
                sandbox: sandbox_id.to_string(),
            });
        }

        // If SMT exclusion is required, pick cores where no sibling is allocated
        if self.policy.requires_smt_exclusion() {
            let mut chosen: Vec<u32> = Vec::new();
            for &cpu in &available {
                if chosen.len() >= target_count {
                    break;
                }
                let siblings = self.topology.siblings_of(cpu);
                let any_sibling_allocated = siblings
                    .iter()
                    .any(|s| allocated.contains(s) || chosen.contains(s));
                if !any_sibling_allocated {
                    chosen.push(cpu);
                }
            }
            if chosen.len() >= target_count {
                return CpuSet::new(chosen).ok_or_else(|| CpuAllocationError::NoCpusAvailable {
                    sandbox: sandbox_id.to_string(),
                });
            }
            // Not enough isolated cores available
            return Err(CpuAllocationError::NoIsolatedCoresAvailable {
                sandbox: sandbox_id.to_string(),
            });
        }

        // Without SMT exclusion, pick the first `target_count` available CPUs
        CpuSet::new(available.into_iter().take(target_count)).ok_or_else(|| {
            CpuAllocationError::NoCpusAvailable {
                sandbox: sandbox_id.to_string(),
            }
        })
    }

    /// Validates that cross-tenant sandboxes do not share SMT siblings.
    ///
    /// Returns a list of violations. An empty list means all checks passed.
    #[must_use]
    pub fn validate_cross_tenant_smt(&self) -> Vec<SmtViolation<'_>> {
        if !self.policy.requires_smt_exclusion() {
            return Vec::new();
        }

        // Group allocations by tenant
        let mut tenant_sets: HashMap<&str, Vec<&CpuSet>> = HashMap::new();
        for (sandbox_id, cpu_set) in &self.allocations {
            if let Some(tenant) = self.sandbox_tenants.get(sandbox_id) {
                tenant_sets.entry(tenant).or_default().push(cpu_set);
            }
        }

        // Check cross-tenant pairs
        let mut violations = Vec::new();
        let tenant_ids: Vec<&str> = tenant_sets.keys().copied().collect();

        for i in 0..tenant_ids.len() {
            for j in (i + 1)..tenant_ids.len() {
                let tenant_a = tenant_ids[i];
                let tenant_b = tenant_ids[j];
                let sets_a = &tenant_sets[tenant_a];
                let sets_b = &tenant_sets[tenant_b];

                for set_a in sets_a {
                    for set_b in sets_b {
                        let combined: Vec<&CpuSet> = vec![set_a, set_b];
                        let mut v = self.topology.validate_smt_exclusion(&combined);
                        violations.append(&mut v);
                    }
                }
            }
        }

        violations
    }
}

/// Errors returned by CPU allocation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CpuAllocationError {
    /// The requested CPU set overlaps with another tenant's allocation.
    #[error(
        "CPU set for sandbox {sandbox} overlaps with existing sandbox {existing}: CPUs {overlapping:?}"
    )]
    Overlap {
        sandbox: String,
        existing: String,
        overlapping: Vec<u32>,
    },
    /// One or more CPU indices exceed the host topology range.
    #[error(
        "CPU set for sandbox {sandbox} contains invalid CPU indices {invalid_cpus:?} \
         (max valid is {max_valid})"
    )]
    InvalidCpuIndices {
        sandbox: String,
        invalid_cpus: Vec<u32>,
        max_valid: u32,
    },
    /// SMT sibling exclusion is violated.
    #[error("SMT sibling exclusion violated for sandbox {sandbox}: {violations:?}")]
    SmtExclusionViolation {
        sandbox: String,
        violations: Vec<String>,
    },
    /// No free CPUs available.
    #[error("no free CPUs available for sandbox {sandbox}")]
    NoCpusAvailable { sandbox: String },
    /// No isolated cores available (all free cores share SMT siblings with allocations).
    #[error(
        "no isolated cores available for sandbox {sandbox}: all free CPUs share SMT siblings with existing allocations"
    )]
    NoIsolatedCoresAvailable { sandbox: String },
}

// --- Linux `sched_setaffinity` helpers ---

/// Applies CPU affinity to a process by PID.
///
/// On Linux, calls `sched_setaffinity(2)` to pin the process to the
/// given CPU set. On non-Linux, this is a no-op that succeeds.
///
/// # Errors
///
/// Returns an error when the syscall fails (e.g., invalid PID or permission denied).
#[cfg(target_os = "linux")]
pub fn apply_cpu_affinity(pid: u32, cpu_set: &CpuSet) -> Result<(), String> {
    let total_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let bits_per_long = std::mem::size_of::<libc::c_ulong>() * 8;
    let num_longs = total_cpus.div_ceil(bits_per_long).max(16);
    let mut mask = vec![0u64; num_longs];

    for cpu in cpu_set.as_slice() {
        let long_idx = (*cpu as usize) / bits_per_long;
        let bit_idx = (*cpu as usize) % bits_per_long;
        if long_idx < mask.len() {
            mask[long_idx] |= 1u64 << bit_idx;
        }
    }

    let size = num_longs * std::mem::size_of::<libc::c_ulong>();
    let ret = unsafe {
        libc::sched_setaffinity(
            pid as libc::pid_t,
            size,
            mask.as_ptr() as *const libc::cpu_set_t,
        )
    };

    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        let msg =
            format!("sched_setaffinity failed for PID {pid} with CPU set {cpu_set}: errno={errno}");
        tracing::warn!("{msg}");
        return Err(msg);
    }

    tracing::debug!(
        pid = pid,
        cpu_set = %cpu_set,
        "applied CPU affinity"
    );
    Ok(())
}

/// Reads the current CPU affinity mask for a process.
///
/// Returns the set of logical CPUs the process is pinned to.
#[cfg(target_os = "linux")]
#[must_use]
pub fn read_cpu_affinity(pid: u32) -> Option<CpuSet> {
    let total_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let bits_per_long = std::mem::size_of::<libc::c_ulong>() * 8;
    let num_longs = total_cpus.div_ceil(bits_per_long).max(16);
    let mut mask = vec![0u64; num_longs];
    let size = num_longs * std::mem::size_of::<libc::c_ulong>();

    let ret = unsafe {
        libc::sched_getaffinity(
            pid as libc::pid_t,
            size,
            mask.as_mut_ptr() as *mut libc::cpu_set_t,
        )
    };

    if ret != 0 {
        return None;
    }

    let mut cpus = Vec::new();
    for (long_idx, &long_val) in mask.iter().enumerate() {
        for bit in 0..bits_per_long {
            if (long_val >> bit) & 1 == 1 {
                let cpu = (long_idx * bits_per_long + bit) as u32;
                if cpu < total_cpus as u32 {
                    cpus.push(cpu);
                }
            }
        }
    }

    CpuSet::new(cpus)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_cpu_affinity(_pid: u32, _cpu_set: &CpuSet) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn read_cpu_affinity(_pid: u32) -> Option<CpuSet> {
    None
}

// --- Helpers ---

/// Parses a CPU list string like "0-3" or "0,2,4-7" into a Vec<u32>.
///
/// This handles the format exposed by sysfs `thread_siblings_list`.
#[allow(dead_code)]
fn parse_cpu_list(input: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = part.find('-') {
            let start: Result<u32, _> = part[..pos].trim().parse();
            let end: Result<u32, _> = part[pos + 1..].trim().parse();
            if let (Ok(start), Ok(end)) = (start, end) {
                cpus.extend(start..=end);
            }
        } else if let Ok(cpu) = part.parse::<u32>() {
            cpus.push(cpu);
        }
    }
    cpus
}

#[cfg(test)]
mod tests;
