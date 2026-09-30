//! Latency-sensitive / best-effort service classes and the gated overcommit track.
//!
//! Step 1 of the CAP-168 measured-overcommit track. Host packing stays
//! no-overcommit by default: [`OvercommitPolicy`] is disabled unless a
//! config explicitly enables it, and every scheduling, cgroup, and reclaim
//! seam below is a no-op for latency-sensitive sandboxes and for any
//! request while the policy is disabled.
//!
//! ## Plumbing
//!
//! Tenant policy ([`crate::tenant::Tenant::default_service_class`]) resolves
//! through [`resolve_service_class`] into
//! [`crate::cell_scheduler::CellSchedulerRequest::service_class`]. The cell
//! scheduler admits best-effort sandboxes against overcommitted effective
//! capacity only when the policy is enabled, and echoes the class plus
//! [`crate::cell_scheduler::CellSchedulerResponse::overcommit_applied`] so
//! S-NOISY evidence can tell strict admits from overcommit admits.
//! Host application (cgroup weight/throttle via
//! [`crate::cgroups::CgroupManager::apply_class_controls`], scheduler policy
//! via [`apply_sched_policy_to_pid`]) consumes [`controls_for_class`].
//!
//! ## Memory sharing and reclaim
//!
//! [`BaseSharingMode`] names the read-only base mechanism whose measured
//! sharing backs [`OvercommitPolicy::be_shared_base_mb`]. Balloon and
//! idle-reclaim plans stay tied to the suspend memory profile
//! ([`crate::snapshot::SnapshotProfile`]): a `Filesystem` profile preserves
//! no guest memory, so there is nothing to balloon or reclaim.
//!
//! Nothing here sets a launch proven operating point. Sharing megabytes,
//! overcommit ratios, and scheduler policy effects must come from measured
//! P1/P2 reports per ADR-0012, never by inference; see
//! `docs/capacity/overcommit-spike-cap-168.md`.

use serde::{Deserialize, Serialize};

use crate::cell_scheduler::HostCapacity;
use crate::cgroups::{ContainerReclaimPlan, container_reclaim_plan};
use crate::error::{Result, SandboxError};
use crate::snapshot::SnapshotProfile;
use crate::tenant::Tenant;

/// Scheduling service class for one sandbox.
///
/// Orthogonal to [`crate::backend_selection::WorkloadClass`] (which sets the
/// isolation floor): the service class sets scheduling priority and
/// host-control treatment under pressure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceClass {
    /// Default. Strict no-overcommit fit, full cgroup weight, `SCHED_OTHER`.
    #[default]
    LatencySensitive,
    /// Preemptible under pressure. Eligible for overcommit packing, reduced
    /// cgroup weight and earlier memory-high throttle, `SCHED_IDLE`.
    BestEffort,
}

impl ServiceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencySensitive => "latency_sensitive",
            Self::BestEffort => "best_effort",
        }
    }

    /// True for the preemptible class.
    #[must_use]
    pub fn is_best_effort(self) -> bool {
        matches!(self, Self::BestEffort)
    }
}

/// Resolves the effective service class from tenant policy and an optional
/// per-request override.
///
/// `None` inherits the tenant default. An explicit `LatencySensitive`
/// narrowing is always allowed. An explicit `BestEffort` widening is
/// allowed only when the tenant opted into best-effort; otherwise it fails
/// closed so one request cannot silently demote its own priority below
/// what the tenant authorized.
pub fn resolve_service_class(
    explicit: Option<ServiceClass>,
    tenant: &Tenant,
) -> Result<ServiceClass> {
    match explicit {
        None => Ok(tenant.default_service_class),
        Some(ServiceClass::LatencySensitive) => Ok(ServiceClass::LatencySensitive),
        Some(ServiceClass::BestEffort) => {
            if tenant.default_service_class.is_best_effort() {
                Ok(ServiceClass::BestEffort)
            } else {
                Err(SandboxError::BadRequest(
                    "best-effort service class requires tenant best-effort opt-in".into(),
                ))
            }
        }
    }
}

/// Read-only base sharing mechanism backing the shared-base discount.
///
/// The mode names which mechanism a measured `be_shared_base_mb` value was
/// characterized under. A non-zero shared-base discount with
/// [`BaseSharingMode::None`] fails [`OvercommitPolicy::validate`] so a
/// config cannot claim sharing without naming the mechanism.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum BaseSharingMode {
    /// No base sharing. The shared-base discount must be zero.
    #[default]
    None,
    /// Page-cache-friendly shared mounts (same read-only base pages cached
    /// once per host).
    SharedPageCache,
    /// Guest read-only layers backed by host virtio-pmem with DAX.
    PmemDax,
}

impl BaseSharingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SharedPageCache => "shared_page_cache",
            Self::PmemDax => "pmem_dax",
        }
    }
}

/// Upper rail for any overcommit ratio.
///
/// A config rail against typos, not a measured safe point: raising packing
/// beyond measured evidence still requires a P1/P2 report per ADR-0012.
pub const MAX_OVERCOMMIT_RATIO: f64 = 8.0;

/// Upper rail for the shared-base discount in megabytes.
///
/// A config rail against unit typos (bytes vs megabytes), not a measured
/// safe point: 8 GiB already exceeds any plausible per-sandbox read-only
/// base, and any non-zero value still needs a P1/P2 report. Without a rail
/// a typo could push the effective request to zero, which the packing math
/// reads as unbounded for that dimension (see [`effective_memory_request`]).
pub const MAX_SHARED_BASE_MB: u64 = 8192;

/// Gated overcommit policy for best-effort packing.
///
/// Disabled by default: [`Self::default`] leaves every scheduling decision
/// identical to strict no-overcommit packing. Enabling the policy affects
/// only [`ServiceClass::BestEffort`] requests; latency-sensitive requests
/// always pack strict. Disk, network, and process slots are never
/// overcommitted (disk bytes are real; slots bound fd/process accounting).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct OvercommitPolicy {
    /// Master gate. False (default) disables every overcommit effect.
    pub enabled: bool,
    /// Multiplier on host vCPU totals for best-effort fit (>= 1.0).
    pub be_cpu_overcommit: f64,
    /// Multiplier on host memory totals for best-effort fit (>= 1.0).
    pub be_memory_overcommit: f64,
    /// Read-only base megabytes assumed shared per best-effort sandbox.
    /// Subtracted from the best-effort memory request. Must be zero unless
    /// [`Self::base_sharing`] names the mechanism, and the value must come
    /// from a measured P1/P2 report, never by inference.
    pub be_shared_base_mb: u64,
    /// Mechanism backing [`Self::be_shared_base_mb`].
    pub base_sharing: BaseSharingMode,
}

impl Default for OvercommitPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            be_cpu_overcommit: 1.0,
            be_memory_overcommit: 1.0,
            be_shared_base_mb: 0,
            base_sharing: BaseSharingMode::None,
        }
    }
}

impl OvercommitPolicy {
    /// Validates ratio ranges and the sharing-mechanism pairing.
    ///
    /// Fails closed on non-finite or out-of-range ratios and on a
    /// shared-base discount without a named mechanism.
    pub fn validate(&self) -> Result<()> {
        for (name, ratio) in [
            ("be_cpu_overcommit", self.be_cpu_overcommit),
            ("be_memory_overcommit", self.be_memory_overcommit),
        ] {
            if !ratio.is_finite() || ratio < 1.0 || ratio > MAX_OVERCOMMIT_RATIO {
                return Err(SandboxError::BadRequest(format!(
                    "{name} must be within [1.0, {MAX_OVERCOMMIT_RATIO}], got {ratio}"
                )));
            }
        }
        if self.be_shared_base_mb > 0 && self.base_sharing == BaseSharingMode::None {
            return Err(SandboxError::BadRequest(
                "be_shared_base_mb requires a base_sharing mechanism".into(),
            ));
        }
        if self.be_shared_base_mb > MAX_SHARED_BASE_MB {
            return Err(SandboxError::BadRequest(format!(
                "be_shared_base_mb must be within [0, {MAX_SHARED_BASE_MB}], got {}",
                self.be_shared_base_mb
            )));
        }
        Ok(())
    }

    /// True when no request class observes any policy effect.
    ///
    /// Either the gate is off, or every knob is at its identity value.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.enabled
            || (self.be_cpu_overcommit == 1.0
                && self.be_memory_overcommit == 1.0
                && self.be_shared_base_mb == 0)
    }
}

/// Scales one host total by an overcommit ratio, rounding down.
///
/// Floor (never ceiling): the scheduler must never promise a fractional
/// unit. Saturates instead of overflowing on huge totals.
fn scale_total(total: u64, ratio: f64) -> u64 {
    if ratio <= 1.0 {
        return total;
    }
    (total as f64 * ratio).floor().clamp(0.0, u64::MAX as f64) as u64
}

/// Effective host capacity for one request class under the policy.
///
/// Best-effort requests under an enabled policy see scaled vCPU and memory
/// totals; every other combination sees the base capacity unchanged, so
/// strict packing is byte-identical with the policy disabled. Allocated
/// counters are never rewritten, only totals.
#[must_use]
pub fn effective_capacity_for_class(
    base: &HostCapacity,
    class: ServiceClass,
    policy: &OvercommitPolicy,
) -> HostCapacity {
    if !class.is_best_effort() || !policy.enabled {
        return *base;
    }
    HostCapacity {
        total_vcpus: scale_total(base.total_vcpus, policy.be_cpu_overcommit),
        total_memory_mb: scale_total(base.total_memory_mb, policy.be_memory_overcommit),
        ..*base
    }
}

/// Effective memory request after the shared-base discount.
///
/// Only best-effort requests under an enabled policy with a named sharing
/// mechanism observe the discount; all other combinations request the full
/// shape. Saturates at zero instead of underflowing. Note the downstream
/// packing math reads a zero request as unbounded for that dimension
/// ([`HostCapacity::remaining_fit_count`] treats it as "no memory
/// needed"), so the discount must stay below any real request size: the
/// [`MAX_SHARED_BASE_MB`] rail plus P1-measured values keep a typo from
/// silently exempting best-effort sandboxes from memory accounting.
#[must_use]
pub fn effective_memory_request(
    memory_mb: u64,
    class: ServiceClass,
    policy: &OvercommitPolicy,
) -> u64 {
    if !class.is_best_effort() || !policy.enabled || policy.base_sharing == BaseSharingMode::None {
        return memory_mb;
    }
    memory_mb.saturating_sub(policy.be_shared_base_mb)
}

// ---- Host controls ----

/// cgroup v2 default CPU weight (proportional share baseline).
pub const LS_CPU_WEIGHT: u32 = 100;

/// Best-effort CPU weight: ~1/11 of contended CPU against default-weight
/// latency-sensitive siblings. Strong deprioritization without starvation.
pub const BE_CPU_WEIGHT: u32 = 10;

/// Latency-sensitive `memory.high` as a fraction of `memory.max`.
pub const LS_MEMORY_HIGH_FRACTION: f64 = 0.8;

/// Best-effort `memory.high` fraction: the kernel throttles and reclaims
/// best-effort pages earlier under host pressure.
pub const BE_MEMORY_HIGH_FRACTION: f64 = 0.5;

/// Linux scheduling policy applied to sandbox processes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SchedPolicy {
    /// Default time-sharing.
    #[default]
    Other,
    /// Batch time-sharing (second-class to `Other` under contention).
    Batch,
    /// Runs only when no runnable `Other`/`Batch` task wants the CPU.
    Idle,
}

impl SchedPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::Batch => "batch",
            Self::Idle => "idle",
        }
    }

    /// libc policy constant for this variant (Linux only).
    #[cfg(target_os = "linux")]
    fn to_libc(self) -> libc::c_int {
        match self {
            Self::Other => libc::SCHED_OTHER,
            Self::Batch => libc::SCHED_BATCH,
            Self::Idle => libc::SCHED_IDLE,
        }
    }
}

/// Host controls derived from one service class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ServiceClassControls {
    /// cgroup v2 `cpu.weight` value (1-10000).
    pub cpu_weight: u32,
    /// `memory.high` as a fraction of the sandbox hard limit.
    pub memory_high_fraction: f64,
    /// Linux scheduling policy for sandbox processes.
    pub sched_policy: SchedPolicy,
}

/// Maps a service class to its host controls.
///
/// Latency-sensitive keeps the production defaults (weight 100,
/// `memory.high` at 80% of max, `SCHED_OTHER`). Best-effort is
/// deprioritized on all three axes.
#[must_use]
pub fn controls_for_class(class: ServiceClass) -> ServiceClassControls {
    match class {
        ServiceClass::LatencySensitive => ServiceClassControls {
            cpu_weight: LS_CPU_WEIGHT,
            memory_high_fraction: LS_MEMORY_HIGH_FRACTION,
            sched_policy: SchedPolicy::Other,
        },
        ServiceClass::BestEffort => ServiceClassControls {
            cpu_weight: BE_CPU_WEIGHT,
            memory_high_fraction: BE_MEMORY_HIGH_FRACTION,
            sched_policy: SchedPolicy::Idle,
        },
    }
}

impl ServiceClassControls {
    /// `memory.high` in bytes for a sandbox hard limit.
    ///
    /// Truncates (never rounds up): the throttle must never exceed the
    /// configured fraction of the hard limit.
    #[must_use]
    pub fn memory_high_bytes(&self, memory_limit_bytes: u64) -> u64 {
        (memory_limit_bytes as f64 * self.memory_high_fraction) as u64
    }
}

/// Maps a service class to its Linux scheduling policy.
///
/// Latency-sensitive keeps `SCHED_OTHER`; best-effort runs `SCHED_IDLE`.
/// This is the policy half of [`controls_for_class`]; the cgroup
/// weight/throttle half applies via
/// [`crate::cgroups::CgroupManager::apply_class_controls`].
#[must_use]
pub fn sched_policy_for_class(class: ServiceClass) -> SchedPolicy {
    controls_for_class(class).sched_policy
}

/// Applies the service-class scheduling policy to one process.
///
/// Latency-sensitive is a no-op without a syscall: the production default
/// is already `SCHED_OTHER`, so the LS path stays byte-identical with the
/// pre-class behavior. Best-effort applies `SCHED_IDLE` via
/// [`apply_sched_policy_to_pid`], which rejects pid 0 and surfaces
/// permission-denied as a typed `Io` error so callers can tell a
/// restricted environment (missing `CAP_SYS_NICE`, warn and continue)
/// from a real control failure (fail closed).
pub fn apply_service_class_sched_policy(class: ServiceClass, pid: u32) -> Result<()> {
    if !class.is_best_effort() {
        if pid == 0 {
            return Err(SandboxError::BadRequest(
                "sched policy requires an explicit pid".into(),
            ));
        }
        return Ok(());
    }
    apply_sched_policy_to_pid(sched_policy_for_class(class), pid)
}

/// True when a sched-policy error is a restricted-environment denial.
///
/// Callers (VMM/sentry spawn) warn and continue on this path but fail
/// closed on any other control error, so a real misconfiguration never
/// demotes silently to a weaker policy.
#[must_use]
pub fn is_sched_permission_denied(err: &SandboxError) -> bool {
    matches!(
        err,
        SandboxError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// Applies a Linux scheduling policy to one process.
///
/// Priority is always zero: only real-time policies take a priority, and
/// this helper only applies non-real-time class policies, never setting
/// one. `pid == 0` is rejected: pid 0 carries process-group semantics in
/// `sched_setscheduler` and this helper only ever targets one explicit
/// process. On non-Linux platforms this is a validated no-op so
/// development workflows are not blocked; production hosts must be Linux.
pub fn apply_sched_policy_to_pid(policy: SchedPolicy, pid: u32) -> Result<()> {
    if pid == 0 {
        return Err(SandboxError::BadRequest(
            "sched policy requires an explicit pid".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::{self, ErrorKind};
        use std::mem;

        let param: libc::sched_param = unsafe { mem::zeroed() };
        // Safety: pid is non-zero (checked above); param is a zeroed
        // sched_param, valid for non-real-time policies.
        let ret = unsafe { libc::sched_setscheduler(pid as libc::pid_t, policy.to_libc(), &param) };
        if ret != 0 {
            let os = io::Error::last_os_error();
            if os.kind() == ErrorKind::PermissionDenied {
                // Restricted environments (e.g. CI containers without
                // CAP_SYS_NICE) deny the call even on self. Surface the
                // typed OS error with context so callers and tests can
                // tell a restricted environment from a real control
                // failure without string matching.
                return Err(SandboxError::Io(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("sched_setscheduler({policy:?}) denied for pid {pid}: {os}"),
                )));
            }
            return Err(SandboxError::CgroupSetupFailed {
                controller: "sched".into(),
                reason: format!("sched_setscheduler({policy:?}) failed for pid {pid}: {os}"),
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        Ok(())
    }
}

/// Core-scheduling (core sched) support on this host.
///
/// Core scheduling tags VMM threads with cookies so the kernel never
/// co-schedules mutually untrusted tasks on SMT siblings of one core.
/// It needs kernel >= 5.14 built with `CONFIG_SCHED_CORE`, plus host
/// enablement; this probe reports what the P1 runbook can rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreSchedSupport {
    Supported,
    Unsupported { reason: &'static str },
}

/// Probes core-scheduling support without side effects.
///
/// Reads (never creates) the caller's own core-sched cookie via
/// `prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET)`. A kernel without
/// `CONFIG_SCHED_CORE` rejects the option with `EINVAL`.
#[must_use]
pub fn probe_core_scheduling() -> CoreSchedSupport {
    #[cfg(target_os = "linux")]
    {
        use std::io;
        use std::process;

        // Safety: read-only GET of our own pid; out-pointer targets a
        // live stack slot for the duration of the call. The pointer-to-int
        // cast assumes a 64-bit Linux host (all production SKUs are
        // x86_64/aarch64); it would truncate on 32-bit Linux.
        let cookie: u64 = 0;
        let ret = unsafe {
            libc::prctl(
                libc::PR_SCHED_CORE,
                libc::PR_SCHED_CORE_GET,
                process::id() as libc::c_ulong,
                libc::PIDTYPE_PID as libc::c_ulong,
                &cookie as *const u64 as libc::c_ulong,
            )
        };
        if ret == 0 {
            return CoreSchedSupport::Supported;
        }
        let reason = match io::Error::last_os_error().raw_os_error() {
            Some(libc::EINVAL) => "kernel lacks CONFIG_SCHED_CORE",
            Some(libc::ENODEV) => "core scheduling disabled on this host",
            Some(libc::EPERM) | Some(libc::EACCES) => "core-sched query not permitted",
            _ => "core-sched probe failed",
        };
        CoreSchedSupport::Unsupported { reason }
    }
    #[cfg(not(target_os = "linux"))]
    {
        CoreSchedSupport::Unsupported {
            reason: "non-linux platform",
        }
    }
}

// ---- Balloon and idle reclaim ----

/// Guest memory balloon driver.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum BalloonDriver {
    /// virtio-balloon inflate/deflate against the guest free-page hint.
    #[default]
    VirtioBalloon,
}

impl BalloonDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VirtioBalloon => "virtio_balloon",
        }
    }
}

/// Balloon policy for best-effort idle reclaim.
///
/// Disabled by default. When enabled, the host may ask the guest balloon
/// to inflate up to `reclaim_fraction` of the reported free pages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BalloonPolicy {
    pub enabled: bool,
    /// Fraction of guest-reported free pages to reclaim (0, 1].
    pub reclaim_fraction: f64,
}

impl Default for BalloonPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            reclaim_fraction: 0.5,
        }
    }
}

impl BalloonPolicy {
    /// Validates the reclaim fraction range.
    pub fn validate(&self) -> Result<()> {
        if !self.reclaim_fraction.is_finite()
            || self.reclaim_fraction <= 0.0
            || self.reclaim_fraction > 1.0
        {
            return Err(SandboxError::BadRequest(format!(
                "balloon reclaim_fraction must be within (0.0, 1.0], got {}",
                self.reclaim_fraction
            )));
        }
        Ok(())
    }
}

/// Balloon inflate target derived from a guest free-page hint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BalloonTarget {
    pub driver: BalloonDriver,
    /// Bytes for the guest balloon to inflate.
    pub inflate_bytes: u64,
}

/// Computes the balloon inflate target, or `None` when no reclaim applies.
///
/// Fails closed (returns `None`, never an error): a disabled policy, a
/// zero limit, a zero free hint, or an out-of-range fraction each mean
/// there is nothing safe to reclaim. The fraction range is enforced here
/// rather than trusting callers to run [`BalloonPolicy::validate`] first,
/// so an unvalidated policy (e.g. an infinite fraction, which would
/// otherwise saturate to a full-guest balloon) yields no target. The
/// target truncates the fraction and clamps to the sandbox limit so the
/// balloon can never exceed the guest it lives in.
#[must_use]
pub fn balloon_target(
    memory_limit_bytes: u64,
    guest_free_hint_bytes: u64,
    policy: &BalloonPolicy,
) -> Option<BalloonTarget> {
    if !policy.enabled
        || memory_limit_bytes == 0
        || guest_free_hint_bytes == 0
        || !policy.reclaim_fraction.is_finite()
        || policy.reclaim_fraction <= 0.0
        || policy.reclaim_fraction > 1.0
    {
        return None;
    }
    let inflate = (guest_free_hint_bytes as f64 * policy.reclaim_fraction) as u64;
    let inflate = inflate.min(memory_limit_bytes);
    if inflate == 0 {
        return None;
    }
    Some(BalloonTarget {
        driver: BalloonDriver::VirtioBalloon,
        inflate_bytes: inflate,
    })
}

/// Idle-reclaim plan tied to the suspend memory profile.
///
/// A `Filesystem` profile preserves no guest memory (per ADR-0007 suspend
/// needs the `Memory` profile), so there is nothing to reclaim and this
/// returns `Ok(None)`. A `Memory` profile reuses the container
/// throttle-plus-`memory.reclaim` plan, which fails closed on zero or tiny
/// limits via [`container_reclaim_plan`].
pub fn idle_reclaim_plan(
    memory_limit_bytes: u64,
    profile: SnapshotProfile,
) -> Result<Option<ContainerReclaimPlan>> {
    if !profile.preserves_memory() {
        return Ok(None);
    }
    Ok(Some(container_reclaim_plan(memory_limit_bytes)?))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::process;

    use super::*;
    use crate::backend_selection::WorkloadClass;
    use crate::capacity::SandboxPackingShape;
    use crate::capacity::advertised_host_limit;
    use crate::identity::TenantId;
    use crate::runtime::RuntimeType;
    use crate::tenant::TenantStatus;

    fn tenant_with_default(default: ServiceClass) -> Tenant {
        Tenant {
            id: TenantId::generate(),
            name: "class-tenant".into(),
            status: TenantStatus::Active,
            allowed_runtimes: vec![RuntimeType::Firecracker],
            allowed_workload_classes: vec![WorkloadClass::PublicUntrusted],
            default_service_class: default,
            policy_epoch: Some(1),
        }
    }

    fn lab_host() -> HostCapacity {
        HostCapacity {
            total_vcpus: 64,
            allocated_vcpus: 0,
            total_memory_mb: 65536,
            allocated_memory_mb: 0,
            total_disk_mb: 500000,
            used_disk_mb: 0,
            total_network_mbps: 10000,
            allocated_network_mbps: 0,
            max_process_slots: 100,
            used_process_slots: 0,
        }
    }

    fn enabled_policy() -> OvercommitPolicy {
        OvercommitPolicy {
            enabled: true,
            be_cpu_overcommit: 2.0,
            be_memory_overcommit: 2.0,
            be_shared_base_mb: 128,
            base_sharing: BaseSharingMode::SharedPageCache,
        }
    }

    #[test]
    fn service_class_defaults_to_latency_sensitive() {
        assert_eq!(ServiceClass::default(), ServiceClass::LatencySensitive);
        assert!(!ServiceClass::LatencySensitive.is_best_effort());
        assert!(ServiceClass::BestEffort.is_best_effort());
        assert_eq!(ServiceClass::LatencySensitive.as_str(), "latency_sensitive");
        assert_eq!(ServiceClass::BestEffort.as_str(), "best_effort");
    }

    #[test]
    fn service_class_serde_roundtrip() {
        for class in [ServiceClass::LatencySensitive, ServiceClass::BestEffort] {
            let json = serde_json::to_string(&class).unwrap();
            assert_eq!(serde_json::from_str::<ServiceClass>(&json).unwrap(), class);
        }
        // Unknown class strings fail closed instead of mapping to a default.
        assert!(serde_json::from_str::<ServiceClass>("\"urgent\"").is_err());
    }

    #[test]
    fn resolve_inherits_tenant_default() {
        let tenant = tenant_with_default(ServiceClass::BestEffort);
        assert_eq!(
            resolve_service_class(None, &tenant).unwrap(),
            ServiceClass::BestEffort
        );
    }

    #[test]
    fn resolve_narrowing_to_ls_always_allowed() {
        let tenant = tenant_with_default(ServiceClass::BestEffort);
        assert_eq!(
            resolve_service_class(Some(ServiceClass::LatencySensitive), &tenant).unwrap(),
            ServiceClass::LatencySensitive
        );
    }

    #[test]
    fn resolve_widening_to_be_requires_tenant_opt_in() {
        let ls_tenant = tenant_with_default(ServiceClass::LatencySensitive);
        assert!(resolve_service_class(Some(ServiceClass::BestEffort), &ls_tenant).is_err());

        let be_tenant = tenant_with_default(ServiceClass::BestEffort);
        assert_eq!(
            resolve_service_class(Some(ServiceClass::BestEffort), &be_tenant).unwrap(),
            ServiceClass::BestEffort
        );
    }

    #[test]
    fn default_policy_is_noop_and_valid() {
        let policy = OvercommitPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.is_noop());
        policy.validate().unwrap();
    }

    #[test]
    fn policy_validation_rejects_bad_ratios() {
        for ratio in [0.5, f64::NAN, f64::INFINITY, MAX_OVERCOMMIT_RATIO + 0.5] {
            let policy = OvercommitPolicy {
                enabled: true,
                be_cpu_overcommit: ratio,
                ..OvercommitPolicy::default()
            };
            assert!(policy.validate().is_err(), "ratio {ratio} must fail");
        }
    }

    #[test]
    fn policy_validation_rejects_phantom_sharing() {
        let policy = OvercommitPolicy {
            enabled: true,
            be_shared_base_mb: 128,
            base_sharing: BaseSharingMode::None,
            ..OvercommitPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_validation_rejects_oversized_shared_base() {
        // Bytes-vs-megabytes typo guard: anything above the rail fails
        // even with a named mechanism.
        let policy = OvercommitPolicy {
            enabled: true,
            be_shared_base_mb: MAX_SHARED_BASE_MB + 1,
            base_sharing: BaseSharingMode::SharedPageCache,
            ..OvercommitPolicy::default()
        };
        assert!(policy.validate().is_err());
        let ok = OvercommitPolicy {
            enabled: true,
            be_shared_base_mb: MAX_SHARED_BASE_MB,
            base_sharing: BaseSharingMode::SharedPageCache,
            ..OvercommitPolicy::default()
        };
        ok.validate().unwrap();
    }

    #[test]
    fn ls_and_disabled_requests_see_strict_capacity() {
        let base = lab_host();
        let strict_shape = SandboxPackingShape::platform_default();

        // Disabled policy: best-effort sees strict capacity.
        let be_strict = effective_capacity_for_class(
            &base,
            ServiceClass::BestEffort,
            &OvercommitPolicy::default(),
        );
        assert_eq!(be_strict, base);

        // Enabled policy: latency-sensitive still sees strict capacity.
        let ls =
            effective_capacity_for_class(&base, ServiceClass::LatencySensitive, &enabled_policy());
        assert_eq!(ls, base);

        // Strict packing on the lab SKU is vCPU-bound at 32.
        let (limit, binding) = advertised_host_limit(&base, strict_shape);
        assert_eq!(
            (limit, binding),
            (32, crate::capacity::BindingResource::Vcpu)
        );
    }

    #[test]
    fn be_enabled_scales_vcpu_and_memory_only() {
        let base = lab_host();
        let effective =
            effective_capacity_for_class(&base, ServiceClass::BestEffort, &enabled_policy());
        assert_eq!(effective.total_vcpus, 128);
        assert_eq!(effective.total_memory_mb, 131072);
        // Disk, network, and slots are never overcommitted.
        assert_eq!(effective.total_disk_mb, base.total_disk_mb);
        assert_eq!(effective.total_network_mbps, base.total_network_mbps);
        assert_eq!(effective.max_process_slots, base.max_process_slots);
        // Allocated counters pass through untouched.
        assert_eq!(effective.allocated_vcpus, base.allocated_vcpus);
        assert_eq!(effective.allocated_memory_mb, base.allocated_memory_mb);
    }

    #[test]
    fn be_enabled_effective_fit_doubles_vcpu_packing() {
        // P0 model input for the CAP-168 spike report: with 2x CPU/memory
        // overcommit plus a 128 MiB shared-base discount, the default shape
        // packs 64 best-effort sandboxes on the lab SKU (vCPU-bound), while
        // strict packing stays at 32.
        let base = lab_host();
        let policy = enabled_policy();
        let shape = SandboxPackingShape::platform_default();
        let strict = base.remaining_fit_count(shape.vcpus, shape.memory_mb, shape.disk_mb);
        assert_eq!(strict, 32);

        let effective = effective_capacity_for_class(&base, ServiceClass::BestEffort, &policy);
        let memory_req =
            effective_memory_request(shape.memory_mb, ServiceClass::BestEffort, &policy);
        assert_eq!(memory_req, 384);
        let be_fit = effective.remaining_fit_count(shape.vcpus, memory_req, shape.disk_mb);
        assert_eq!(be_fit, 64);
    }

    #[test]
    fn shared_base_discount_only_applies_to_be_with_mechanism() {
        let policy = enabled_policy();
        // LS keeps the full request even under an enabled policy.
        assert_eq!(
            effective_memory_request(512, ServiceClass::LatencySensitive, &policy),
            512
        );
        // Disabled policy: no discount even for BE.
        assert_eq!(
            effective_memory_request(512, ServiceClass::BestEffort, &OvercommitPolicy::default()),
            512
        );
        // Saturates at zero instead of underflowing.
        assert_eq!(
            effective_memory_request(64, ServiceClass::BestEffort, &policy),
            0
        );
    }

    #[test]
    fn controls_map_ls_to_defaults_and_be_to_deprioritized() {
        let ls = controls_for_class(ServiceClass::LatencySensitive);
        assert_eq!(ls.cpu_weight, LS_CPU_WEIGHT);
        assert_eq!(ls.memory_high_fraction, LS_MEMORY_HIGH_FRACTION);
        assert_eq!(ls.sched_policy, SchedPolicy::Other);

        let be = controls_for_class(ServiceClass::BestEffort);
        assert_eq!(be.cpu_weight, BE_CPU_WEIGHT);
        assert_eq!(be.memory_high_fraction, BE_MEMORY_HIGH_FRACTION);
        assert_eq!(be.sched_policy, SchedPolicy::Idle);

        // memory.high truncates and never exceeds the fraction.
        let limit = 512 * 1024 * 1024u64;
        assert_eq!(be.memory_high_bytes(limit), limit / 2);
        assert_eq!(ls.memory_high_bytes(limit), (limit as f64 * 0.8) as u64);
    }

    #[test]
    fn sched_policy_rejects_pid_zero() {
        for policy in [SchedPolicy::Other, SchedPolicy::Batch, SchedPolicy::Idle] {
            assert!(apply_sched_policy_to_pid(policy, 0).is_err());
        }
    }

    #[test]
    fn sched_policy_applies_to_own_process() {
        // Applies SCHED_OTHER (the current default) to the test process and
        // round-trips SCHED_IDLE back to OTHER on Linux; validated no-op
        // elsewhere. Restricted environments that deny sched_setscheduler
        // (CI containers without CAP_SYS_NICE) skip with notice instead of
        // failing: the permission-denied path is typed, all other errors
        // still fail.
        let pid = process::id();
        if let Err(e) = apply_sched_policy_to_pid(SchedPolicy::Other, pid) {
            if is_permission_denied(&e) {
                eprintln!("SKIP: environment denies sched_setscheduler: {e}");
                return;
            }
            panic!("sched apply must succeed where permitted: {e}");
        }
        #[cfg(target_os = "linux")]
        {
            for policy in [SchedPolicy::Idle, SchedPolicy::Other] {
                if let Err(e) = apply_sched_policy_to_pid(policy, pid) {
                    if is_permission_denied(&e) {
                        eprintln!("SKIP: environment denies sched_setscheduler: {e}");
                        return;
                    }
                    panic!("sched round-trip must succeed where permitted: {e}");
                }
            }
        }
    }

    fn is_permission_denied(e: &SandboxError) -> bool {
        matches!(e, SandboxError::Io(io) if io.kind() == ErrorKind::PermissionDenied)
    }

    #[test]
    fn core_sched_probe_returns_a_valid_variant() {
        match probe_core_scheduling() {
            CoreSchedSupport::Supported => {}
            CoreSchedSupport::Unsupported { reason } => {
                assert!(!reason.is_empty());
            }
        }
    }

    #[test]
    fn idle_reclaim_requires_memory_profile() {
        let limit = 512 * 1024 * 1024u64;
        assert_eq!(
            idle_reclaim_plan(limit, SnapshotProfile::Filesystem).unwrap(),
            None
        );
        let plan = idle_reclaim_plan(limit, SnapshotProfile::Memory)
            .unwrap()
            .expect("memory profile must yield a plan");
        assert_eq!(plan.memory_high_bytes, limit / 2);
        assert_eq!(plan.reclaim_bytes, limit);
        assert!(idle_reclaim_plan(0, SnapshotProfile::Memory).is_err());
    }

    #[test]
    fn balloon_target_fails_closed_on_empty_inputs() {
        let policy = BalloonPolicy {
            enabled: true,
            ..BalloonPolicy::default()
        };
        assert_eq!(balloon_target(0, 1024, &policy), None);
        assert_eq!(balloon_target(1024, 0, &policy), None);
        assert_eq!(balloon_target(1024, 512, &BalloonPolicy::default()), None);
    }

    #[test]
    fn balloon_target_rejects_unvalidated_fractions() {
        // An unvalidated policy never yields a target: infinite fractions
        // would otherwise saturate to a full-guest balloon.
        for fraction in [f64::NAN, f64::INFINITY, -0.5, 0.0, 1.5] {
            let policy = BalloonPolicy {
                enabled: true,
                reclaim_fraction: fraction,
            };
            assert_eq!(
                balloon_target(4096, 2048, &policy),
                None,
                "fraction {fraction} must yield no target"
            );
        }
    }

    #[test]
    fn balloon_target_takes_fraction_and_clamps_to_limit() {
        let policy = BalloonPolicy {
            enabled: true,
            reclaim_fraction: 0.5,
        };
        policy.validate().unwrap();
        let target = balloon_target(4096, 2048, &policy).unwrap();
        assert_eq!(target.driver, BalloonDriver::VirtioBalloon);
        assert_eq!(target.inflate_bytes, 1024);
        // A huge hint can never inflate past the guest size.
        let clamped = balloon_target(1024, u64::MAX / 2, &policy).unwrap();
        assert_eq!(clamped.inflate_bytes, 1024);
        // A tiny hint truncates to zero reclaim instead of a 1-byte balloon.
        assert_eq!(balloon_target(4096, 1, &policy), None);
    }

    #[test]
    fn balloon_policy_validation_rejects_bad_fractions() {
        for fraction in [0.0, -0.5, 1.5, f64::NAN, f64::INFINITY] {
            let policy = BalloonPolicy {
                enabled: true,
                reclaim_fraction: fraction,
            };
            assert!(policy.validate().is_err(), "fraction {fraction} must fail");
        }
    }

    #[test]
    fn sched_policy_for_class_maps_ls_to_other_and_be_to_idle() {
        assert_eq!(
            sched_policy_for_class(ServiceClass::LatencySensitive),
            SchedPolicy::Other
        );
        assert_eq!(
            sched_policy_for_class(ServiceClass::BestEffort),
            SchedPolicy::Idle
        );
    }

    #[test]
    fn service_class_sched_policy_rejects_pid_zero_for_both_classes() {
        // Pid 0 carries process-group semantics; both classes fail closed.
        for class in [ServiceClass::LatencySensitive, ServiceClass::BestEffort] {
            assert!(
                apply_service_class_sched_policy(class, 0).is_err(),
                "class {class:?} must reject pid 0"
            );
        }
    }

    #[test]
    fn service_class_sched_policy_ls_is_noop_without_syscall() {
        // LS never touches sched_setscheduler (already SCHED_OTHER), so it
        // succeeds even where the syscall would be denied; BE goes through
        // the real path (success or typed permission-denied on restricted
        // hosts).
        let pid = process::id();
        assert!(pid != 0);
        apply_service_class_sched_policy(ServiceClass::LatencySensitive, pid)
            .expect("LS must be a validated no-op");
    }

    #[test]
    fn sched_permission_denied_distinguishes_restricted_env() {
        let denied = SandboxError::Io(std::io::Error::new(ErrorKind::PermissionDenied, "denied"));
        assert!(is_sched_permission_denied(&denied));
        let other = SandboxError::BadRequest("bad".into());
        assert!(!is_sched_permission_denied(&other));
        let setup = SandboxError::CgroupSetupFailed {
            controller: "sched".into(),
            reason: "fail".into(),
        };
        assert!(!is_sched_permission_denied(&setup));
    }
}
