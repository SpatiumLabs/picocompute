# PicoCompute Multi-Tenant Side-Channel and Covert-Channel Risk Assessment

**Status**: Proposed
**Date**: 2026-07-01
**Milestone**: M4 - Isolation Boundary Validation
**Risk model**: [PicoCompute threat model](threat-model.md)
**Normative posture**: [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Isolation boundary**: [Boundary validation suite](..../crates/pico-runtime/src/isolation)
**Production readiness**: [G-15 Side-channel and tenant-sharing posture](production-readiness.md)

## Purpose

This assessment evaluates side-channel and covert-channel risks when PicoCompute
runs multiple tenant workloads on shared hosts. It covers timing, resource
contention, cache behavior, observability, snapshot artifacts, and fork
behavior across all supported runtime backends.

The assessment produces:

- A risk inventory classified as must-fix, accepted with limits, or out-of-scope for v1.
- Accepted-risk register entries for risks accepted with operational controls.
- Concrete recommendations for scheduling, host sharing, metric redaction, and backend selection.
- Follow-up issues for every finding that requires implementation work.

## Scope

### In scope

- CPU cache timing, microarchitectural side channels, and sibling-thread leakage.
- Memory pressure, page-cache contention, and memory-bandwidth signals.
- Scheduler timing, CPU steal time, and noisy-neighbor observability.
- Disk I/O contention, image cache timing, and snapshot cache access patterns.
- Network bandwidth contention, interface stats, and DNS proxy timing.
- Observability labels, logs, metrics, error messages, and trace attributes.
- Snapshot size, restore timing, artifact metadata, and lineage information.
- Parent/child fork behavior and resource inheritance.
- Three production backends: Firecracker (microVM), gVisor (syscall-level container), QEMU (VM).

### Out of scope

- Provider infrastructure side channels (cloud hypervisor, physical network, power analysis).
- Application-layer covert channels within a single sandbox (tenant self-harm).
- Hardware vulnerabilities requiring physical access (e.g., DRAM row hammer at distance, EM emanations).
- Side channels exploitable only by the host platform operator (insider threat covered by RR-05 in the threat model).

## Methodology

This assessment combines:

1. **Design review**: Analysis of the PicoCompute codebase including runtime
   adapters, network agent, telemetry, snapshot system, and isolation
   boundary validation.
2. **Backend threat modeling**: Per-backend isolation boundary analysis
   using the Security Engineering framework from Ross Anderson.
3. **Observable signal audit**: Catalog of every metric, log field, trace
   attribute, error message, and metadata field exposed across sandbox
   boundaries.
4. **Existing control analysis**: Evaluation of current mitigations
   (cgroup v2, namespace isolation, seccomp, CPU pinning stubs, telemetry
   redaction).

This is a design-level assessment. Live timing/cache probes require
`live_boundary_tests: true` in the isolation boundary validation suite,
which is currently stubbed (all checks return `true` unconditionally).
See [SC-IMPL-01](#sc-impl-01-implement-live-side-channel-probes) for the
implementation follow-up.

## Backend Isolation Comparison

### Firecracker (MicroVM)

| Dimension | Assessment |
|---|---|
| Isolation boundary | Hardware VM (KVM). Guest and host run in separate ring-0 contexts with EPT/NPT page-table isolation. |
| CPU cache side channels | Mitigated by KVM page-table isolation on contemporary x86 and ARM. L1TF, MDS, and Spectre-v2 class vulnerabilities require host kernel and microcode mitigations. Cross-VM cache attacks are harder than cross-process but not impossible without cache partitioning. |
| Memory pressure | cgroup v2 `memory.max` and `memory.high` (80% fraction) bound per-VM memory. Host OOM killer prefers sandbox processes. Ballooning not used. |
| Scheduler timing | Firecracker VMM uses one vCPU thread per guest vCPU. KVM `kvm-clock` exposes host-visible timing. No `sched_setaffinity` pinning by default. |
| Network | virtio-net with per-sandbox TAP device in isolated netns. No shared bridge. Bandwidth contention possible at host physical NIC. |
| Cache and snapshot | Firecracker snapshot/resume uses KVM dirty-page tracking and memory-delta diff. Snapshot size and restore timing observable from host metrics. |

**Verdict**: Strongest isolation of the three backends. Microarchitectural
side channels are the primary residual concern and are covered by
[SC-01](#sc-01-cpu-cache-and-microarchitectural-side-channels).

### gVisor (Syscall-Level Container)

| Dimension | Assessment |
|---|---|
| Isolation boundary | Userspace application kernel (Sentry). No hardware VM boundary. Syscalls are intercepted and implemented in userspace. |
| CPU cache side channels | Same as any multi-process system. gVisor does not provide cache partitioning. Co-located sandboxes share L1/L2/L3 cache with host and each other. |
| Memory pressure | cgroup v2 limits apply. Page-cache and memory-bandwidth contention observable across sandboxes. |
| Scheduler timing | Standard Linux CFS scheduling. CPU steal time, scheduling latency, and context-switch rates are observable. |
| Network | Per-sandbox netns with veth pairs. Same host-NIC contention as Firecracker. |
| Cache and snapshot | No hardware VM snapshot support. Checkpoint/restore via CRIU is possible but not currently implemented for gVisor. |

**Verdict**: Weaker isolation than microVM backends. Syscall-mediated
boundary does not isolate microarchitectural state. gVisor is restricted
to the Trusted Fast-Path workload class per ADR-0006, which limits blast
radius but does not eliminate side channels. Co-located gVisor sandboxes
from different tenants must never share a host until dedicated CPU
partitioning is enforced.

### QEMU (Full VM)

| Dimension | Assessment |
|---|---|
| Isolation boundary | Hardware VM (KVM) with broader device model. |
| CPU cache side channels | Similar to Firecracker with KVM isolation. QEMU's broader device model (emulated devices, firmware) adds attack surface but does not fundamentally change cache side-channel posture. |
| Memory pressure | cgroup v2 limits apply. Memory overhead is higher than Firecracker (QEMU process + guest). |
| Scheduler timing | More vCPU threads and I/O threads than Firecracker. Timing signals richer but similar class of risk. |
| Network | virtio-net or e1000 with per-sandbox TAP. Same isolation model. |
| Cache and snapshot | QEMU migration and snapshot mechanisms expose timing and memory-footprint signals. |

**Verdict**: Cache-side-channel posture comparable to Firecracker on KVM.
Broader device model adds escape-surface risk (R-13) but is not a
meaningful side-channel differentiator. Used as compatibility VM fallback
per ADR-0006.

## Risk Analysis

### SC-01: CPU Cache and Microarchitectural Side Channels

**Risk class**: Covert channel (cross-sandbox) and side channel (sandbox-to-host inference).

**Description**: Shared CPU resources (L1/L2/L3 cache, TLB, branch predictor,
execution units) allow co-located workloads to observe each other's
activity through timing variations. Classic attack primitives include
Prime+Probe, Flush+Reload, and Evict+Time.

**Backend exposure**:

| Backend | L1/L2 isolation | L3 isolation | SMT/Hyper-Threading | Cache partitioning available |
|---|---|---|---|---|
| Firecracker | KVM EPT | No (shared L3 across VMs) | Yes (SMT siblings may cross VMs) | Intel CAT Arm MPAM (not configured) |
| gVisor | None (userspace boundary) | None | Yes (SMT siblings may cross sandboxes) | Intel CAT Arm MPAM (not configured) |
| QEMU | KVM EPT | No (shared L3) | Yes | Intel CAT Arm MPAM (not configured) |

**Current controls**:
- KVM EPT/NPT provides L1/L2 cache isolation for microVM backends (Firecracker, QEMU).
- gVisor restricted to Trusted Fast-Path workload class (not public untrusted).
- Dedicated tenancy required for cross-tenant shared-host placement until this assessment is approved.
- CPU pinning stubs in `side_channels.rs:151` (`check_cpu_pinning_isolation`) unconditionally return `true`.

**Current gaps**:
- No Intel Cache Allocation Technology (CAT) or Arm Memory Partitioning and Monitoring (MPAM) configuration.
- No SMT/SMT-sibling policy. Co-located sandbox vCPUs may share a physical core via SMT.
- No cache-way or memory-bandwidth partitioning.
- gVisor has no hardware cache isolation at any level.
- Live measurement stubs in `side_channels.rs` do not perform actual timing or cache analysis.

**Classification**: **Must-fix** for gVisor cross-tenant placement. **Accepted with limits** for microVM backends (Firecracker/QEMU) with dedicated core pinning and SMT sibling exclusion.

**Recommended controls**:
1. Enforce `sched_setaffinity` per-sandbox vCPU pinning with non-overlapping CPU sets for cross-tenant sandboxes (must-fix).
2. Disable SMT or enforce SMT-sibling exclusion per sandbox on shared hosts (must-fix for gVisor; recommended for microVM).
3. Configure Intel CAT Arm MPAM for L3 cache partitioning on shared hosts (v2).
4. Prohibit gVisor cross-tenant co-location on shared hosts until CPU pinning is enforced (must-fix).
5. Implement live cache-timing probes in `side_channels.rs` (see SC-IMPL-01).

**Follow-up issues**: SC-IMPL-01, SC-IMPL-02

### SC-02: Memory Pressure and Page-Cache Contention

**Risk class**: Side channel (resource-contention inference).

**Description**: Memory-bandwidth contention, page-cache eviction patterns,
and swap activity can reveal co-tenant workload characteristics
(memory-intensive vs idle, working-set size, allocation patterns).

**Backend exposure**:
- All backends share host physical memory and page cache.
- cgroup v2 `memory.max` provides hard per-sandbox limits.
- cgroup v2 `memory.high` at 80% fraction throttles allocation.
- No memory-bandwidth monitoring or throttling (no `memory.bandwidth` cgroup controller usage).

**Current controls**:
- `pico_cgroup_memory_high_events_total` metric tracks high-watermark events.
- `pico_cgroup_oom_events_total` metric tracks OOM kills.
- OOM group kill (`memory.oom.group`) kills all sandbox processes together.
- PID limit (`pids.max`, default 512) bounds process creation.

**Current gaps**:
- Memory-bandwidth contention not monitored or bounded.
- Page-cache eviction is a global host operation - aggressive page-cache use by one sandbox can evict another sandbox's hot pages.
- No memory-bandwidth reservation or NUMA-aware placement.
- Per-sandbox memory pressure not visible to tenant (no `memory.pressure` metric exposed).

**Classification**: **Accepted with limits** for v1. Memory-bandwidth partitioning is a v2 capability. Page-cache contention is partially mitigated by `memory.max` limits. Cross-tenant inference through memory pressure is low-bandwidth compared to cache timing.

**Recommended controls**:
1. Enable cgroup v2 `memory.pressure` metrics for host operators (v1). ✅ Implemented
2. Investigate `memory.bandwidth` cgroup controller for v2.

**Follow-up issues**: SC-IMPL-03 ✅

### SC-03: Scheduler Timing and Noisy-Neighbor Signals

**Risk class**: Side channel (CPU-usage inference).

**Description**: CPU scheduling latency, steal time, and context-switch
rates observable from within a sandbox can reveal co-tenant workload
patterns (compute-bound vs idle, periodic activity, batch-job timing).

**Backend exposure**:
- All backends share Linux CFS scheduler.
- Firecracker and QEMU guests observe steal time via `kvm-clock`.
- gVisor sandboxes observe scheduling latency directly via Linux scheduling.
- No `cpu.max` bandwidth limit on host-agent seccomp profile, but cgroup v2
  `cpu.max` can enforce bandwidth caps per sandbox.

**Current controls**:
- cgroup v2 `cpu.max` for bandwidth limiting.
- cgroup v2 `cpu.weight` for relative priority.
- `pico_cgroup_cpu_throttled_total` metric for throttle events.
- `sched_setaffinity` allowed in host-agent seccomp profile (not yet applied
  per sandbox).

**Current gaps**:
- No per-sandbox CPU pinning (`sched_setaffinity`) configured.
- No CPU quota isolation between tenants beyond cgroup bandwidth.
- CPU steal time and scheduling latency visible inside guest without rate-limiting.
- No `cpu.pressure` metric aggregation.

**Classification**: **Accepted with limits** for v1 microVM backends with CPU pinning. **Must-fix** for gVisor cross-tenant placement without pinning. Scheduling inference is lower risk than cache timing but can compound with other signals.

**Recommended controls**:
1. Enforce non-overlapping CPU pinning per sandbox via `sched_setaffinity` (covered by SC-01).
2. Rate-limit or virtualize `kvm-clock` steal-time reporting for untrusted guests (v2).
3. Enable cgroup v2 `cpu.pressure` for host monitoring.

**Follow-up issues**: SC-IMPL-02 (combined with SC-01)

### SC-04: Disk I/O, Image Cache, and Snapshot Cache Timing

**Risk class**: Side channel (storage-access inference).

**Description**: Disk I/O latency, image cache hit/miss patterns, and
snapshot restore timing can reveal co-tenant storage activity (image pulls,
snapshot restores, workspace writes). Image cache layers are shared
read-only between sandboxes using the same base image.

**Backend exposure**:
- Image layers are content-addressed and potentially shared across tenants
  using the same base image digests.
- Snapshot cache (`TieredCacheManager`, `CacheGarbageCollector`) exposes hit/miss
  timing through its tiered access pattern (hot/warm/cold).
- `pico_snapshot_cache_hits` and `pico_snapshot_cache_misses` metrics
  expose aggregate cache behavior per host.
- Disk I/O limits (`io.max`) bound per-sandbox throughput but do not
  eliminate timing correlation.

**Current controls**:
- Image layers are read-only and digest-verified at restore.
- cgroup v2 `io.max` limits per-sandbox I/O bandwidth and IOPS.
- Snapshot cache has LRU-based eviction (`EvictionEngine`) with freeze
  protection for referenced snapshots.
- Cache tiering separates hot/warm/cold tiers with per-tier capacity limits.

**Current gaps**:
- Shared base image layers create a timing channel: one tenant's image pull
  warms the cache, observably accelerating another tenant's boot.
- Snapshot cache hit/miss timing observable through `SnapshotRepository`
  access patterns and restore latency.
- `pico_snapshot_cache_hits`/`misses` metrics aggregate per host,
  potentially revealing cross-tenant cache activity patterns.
- No per-tenant cache isolation or cache-way partitioning for snapshot storage.

**Classification**: **Accepted with limits** for v1. Image and snapshot
cache timing is a low-bandwidth side channel with limited practical
exploitability. Shared read-only image layers are an intentional
performance optimization.

**Recommended controls**:
1. Rate-limit snapshot cache metrics to prevent high-frequency inference (v1).
2. Consider per-tenant cache partition quotas in v2.
3. Document image-layer sharing in tenant documentation as a known performance characteristic.

**Follow-up issues**: SC-IMPL-04

### SC-05: Network Timing and Bandwidth Contention

**Risk class**: Side channel (network-activity inference) and covert channel (inter-sandbox timing).

**Description**: Network interface statistics, bandwidth contention at the
host physical NIC, DNS proxy cache timing, and NAT session behavior can
reveal co-tenant network activity patterns.

**Backend exposure**:
- `network.interface.rx_bytes`/`tx_bytes` and `network.interface.rx_packets`/`tx_packets`
  metrics are per-sandbox (identifiable via interface name derived from sandbox_id).
- DNS proxy (`pico-network-agent/src/dns/`) maintains a per-host TTL-bounded
  cache. DNS query timing and cache hit/miss patterns observable.
- `network.nat.sessions` metric count per host.
- Host physical NIC bandwidth shared across all sandboxes.

**Current controls**:
- Per-sandbox Linux network namespaces prevent direct packet observation.
- Anti-spoofing rules validate source IP/MAC/interface.
- No sandbox-to-sandbox forwarding (including same-tenant peers).
- Default-deny egress. DNS-only initially.
- Interface names derived deterministically via `fnv1a64(sandbox_id)` but are
  only visible to operators, not to sandbox workloads.

**Current gaps**:
- DNS proxy cache timing: one tenant's DNS query can warm the cache,
  changing response time for another tenant's identical query.
- Bandwidth contention at host NIC is unshaped and observable via latency
  changes.
- Per-interface byte/packet counters exposed via metrics with sandbox_id
  correlation enabling activity inference.
- NAT session count and connection tracking are shared host resources.

**Classification**: **Accepted with limits** for v1. Network side channels
are a well-known class of risk in multi-tenant systems. Per-namespace
isolation and anti-spoofing provide strong preventive controls. DNS cache
timing is low-bandwidth. Bandwidth contention is a general shared-infrastructure
concern.

**Recommended controls**:
1. Add per-sandbox bandwidth shaping via tc or nftables rate limiting (v2).
2. Evaluate DNS cache partitioning per tenant in v2.
3. Document network-contention behavior in SLO definitions
   ([slo-error-budget-policy](../observability/slo-error-budget-policy.md#network-contention)).
4. Keep interface metric labels but consider adding per-tenant aggregation
   rather than per-sandbox granularity for cross-tenant hosts.

**Follow-up issues**: SC-IMPL-05

### SC-06: Observability Labels, Logs, Metrics, and Error Messages

**Risk class**: Information disclosure (observability-based inference).

**Description**: Structured logs, metrics, trace attributes, and error
messages may expose tenant-identifiable or sandbox-identifiable information
including backend type, lifecycle timing, resource limits, error reasons,
and sandbox metadata.

**Audit of exposed information**:

| Signal type | Fields exposed | Tenant isolation | Risk |
|---|---|---|---|
| Structured logs (`LogRecord`) | `sandbox_id`, `tenant_id`, `operation_id`, `backend`, `lifecycle_operation`, `outcome`, `reason`, `host_id`, `cell_id`, `region` | Not tenant-filtered by default | Medium: sandbox_id and tenant_id are SPI (security-personal information) |
| Traces (`trace_context.rs`) | `sandbox_id`, `operation_id`, `tenant_id`, `backend`, `lifecycle_operation`, `outcome`, `reason`, `host_id`, `cell_id`, `region` | debug_assert-guarded allowlist | Medium: attribute key allowlist prevents unbounded disclosure but lifetime/timing data persists |
| Host-agent metrics | Boot/create/prepare/destroy/fork/exec latency and counts, exec output bytes, cgroup events (OOM, memory_high, cpu_throttled), credential events, port-forward state, network health | Per-sandbox via sandbox_id label | High: per-sandbox lifecycle timing and resource-event counts reveal workload characteristics |
| Network-agent metrics | Interface rx/tx bytes and packets, egress allow/deny counts, NAT sessions, DNS proxy stats | Per-sandbox via interface identity | High: per-interface counters reveal network activity patterns (traffic volume, DNS query frequency, connection rates) |
| Snapshot metadata | Snapshot ID, tenant ID, sandbox ID, parent snapshot ID, lineage type, purpose, profile, backend type/version, CPU/memory shape, device model | Stored in snapshot repository (not telemetry) | Medium: metadata accessible to storage operators; backend and shape reveal infrastructure topology |
| Error messages | Guest output, command text, file paths, environment values, IP addresses, port numbers | `ProhibitedCategory` detection + `Redacted<T>` wrapper | Low: strong redaction controls exist but require ongoing vigilance |

**Current controls**:
- `ProhibitedCategory` enum with 12 categories (Credential, Command, RequestBody,
  ResponseBody, FileContent, Url, QueryString, HostPath, WorkspacePath, IpAddress,
  PortNumber, DependencyError, GuestOutput, EnvironmentValue).
- `Redacted<T>` serializes as `{"redacted":true}`.
- `credential_redaction_patterns` configurable per deployment (defaults: token,
  secret, password, api_key, private_key).
- Trace attribute allowlist (`debug_assert!` in `record_bounded_attr`) restricts
  span attributes to sandbox_id, operation_id, tenant_id, backend,
  lifecycle_operation, outcome, reason, host_id, cell_id, region.
- No tenant-supplied data in trace_context attributes.
- Dual-emission strategy: structured platform log (stable schema) + human-readable
  diagnostic event (ephemeral detail).

**Current gaps**:
- **Gap 1 (High)**: Per-sandbox metrics (boot/create/destroy/exec latency,
  cgroup events, network byte/packet counters) are labeled with `sandbox_id`,
  enabling precise per-tenant activity correlation. On shared hosts, this
  allows a tenant or operator to observe co-tenant activity patterns.
- **Gap 2 (Medium)**: Lifecycle timestamps appear in structured logs and
  traces. While aggregate, they reveal when a tenant created, booted,
  executed, suspended, or destroyed a sandbox.
- **Gap 3 (Medium)**: `pico_exec_output_bytes` reveals output volume
  per execution, which may correlate with tool type or data sensitivity.
- **Gap 4 (Low)**: Metric label cardinality from sandbox_id is bounded by
  active sandbox count, but per-sandbox granularity on shared hosts
  creates a cross-tenant observability channel.
- **Gap 5 (Low)**: `ProhibitedCategory::is_suspected_in` uses heuristic
  string matching. False negatives are possible for novel sensitive patterns.

**Classification**: **Must-fix** for Gap 1 (per-sandbox metric filtering
on shared hosts). **Accepted with limits** for gaps 2-4 with
recommendations below. Gap 5 is a continuous-improvement item.

**Recommended controls**:
1. Implement per-tenant metric aggregation or drop sandbox_id labels for
   cross-tenant shared-host deployments (must-fix, blocks shared-host beta).
2. Add a `shared_host_metric_redaction` configuration flag that replaces
   `sandbox_id` with `tenant_id` on multi-tenant hosts.
3. Bucket lifecycle timing metrics (p50/p95/p99) rather than exposing
   per-sandbox individual latencies on shared hosts.
4. Add `exec_output_bytes` to shared-host redaction scope.
5. Maintain `ProhibitedCategory` allowlist and run pattern-matching tests
   against representative workloads.

**Follow-up issues**: SC-IMPL-06

### SC-07: Snapshot Size, Restore Timing, and Artifact Metadata

**Risk class**: Side channel (snapshot-state inference).

**Description**: Snapshot artifact size, restore duration, and metadata
fields can reveal workload characteristics including memory footprint,
disk usage, execution duration, filesystem composition, and lineage
structure.

**Backend exposure**:
- `SnapshotMetadata` exposes: `id`, `tenant_id`, `sandbox_id`,
  `parent_snapshot_id`, `lineage_type`, `purpose`, `profile`, `state`,
  `version`, `operation_id`, `image_digest`, `rootfs_digest`, `kernel_version`,
  `guest_agent_version`, `protocol_version`, `backend` type/version,
  `cpu_shape` (vCPU count, topology), `memory_shape` (MiB allocation),
  `device_model`, `policy_epoch`, `excluded_mounts`, `encryption_key_id`,
  `integrity` digests.
- Memory segments include `start_address`, `size_bytes`, and blob digests.
- Filesystem references include `mount_point`, `fs_type`, and blob digests.
- Workspace layers include `layer_index` and parent references.
- `pico_snapshot_gc_*` metrics expose GC activity per host.
- Restore timing exposed via `pico_restore_latency_seconds` metric.

**Current controls**:
- Snapshot metadata is tenant-bound and stored in the snapshot repository
  (not broadcast via telemetry).
- Authenticated encryption protects blob content.
- Cross-backend restore is prohibited.
- Tenant/lineage binding prevents cross-tenant snapshot access.
- Credential exclusion manifest removes secrets from snapshot scope.
- GC reference counting prevents premature deletion of live snapshots.

**Current gaps**:
- **Gap 1 (Medium)**: Snapshot metadata is comprehensive and reveals
  infrastructure topology (backend type, CPU/memory shape, device model,
  kernel version, guest agent version, protocol version). This is accessible
  to storage operators and could aid targeted attacks.
- **Gap 2 (Low)**: Snapshot size (sum of blob sizes) reveals memory footprint
  and filesystem composition. Larger snapshots indicate more stateful or
  memory-intensive workloads.
- **Gap 3 (Low)**: Parent snapshot ID and lineage type expose sandbox
  genealogy (fork count, snapshot depth).
- **Gap 4 (Low)**: Restore latency metrics reveal snapshot size indirectly
  (larger snapshots = longer restore).
- **Gap 5 (Low)**: GC metrics (`pico_snapshot_gc_*`) reveal GC cycle
  timing and candidate counts.

**Classification**: **Accepted with limits** for v1. Snapshot metadata is
operator-visible but not tenant-visible. Operators already have broad host
access, making this an insider-risk concern covered by RR-05 in the threat
model.

**Recommended controls**:
1. Add access audit logging for snapshot metadata reads (v1).
2. Consider restricting snapshot metadata visibility in multi-tenant
   deployments (v2).
3. Rate-limit restore latency and GC metrics on shared hosts (v1).
4. Document snapshot metadata surface in operator runbooks.

**Follow-up issues**: SC-IMPL-07

### SC-08: Parent/Child Fork Behavior

**Risk class**: Covert channel (cross-generation state leakage).

**Description**: Forked sandboxes share parent filesystem state and
potentially reveal parent execution patterns through inherited artifacts,
timing behavior, and resource footprints.

**Backend exposure**:
- Fork creates a child sandbox from a parent snapshot.
- Child inherits parent filesystem state (workspace layers, mount points).
- Child receives fresh identity (new sandbox_id, new boot secret, new
  protocol session, new network namespace, new credentials).
- `ForkCredentialPolicy` controls credential exclusion from fork snapshots.
- Fork timing exposed via `pico_fork_latency_seconds` metric.

**Current controls**:
- Fresh identity after fork: new sandbox_id, boot secret, protocol session,
  network namespace, network identity, and credentials.
- `ForkCredentialPolicy` excludes credentials from fork snapshots.
- Credential revocation before snapshot capture.
- Parent/child lineage tracked in `SnapshotMetadata` (via `LineageGraph`).
- No shared writable state between parent and child post-fork.
- Child cannot access parent sandbox, network, or credentials.

**Current gaps**:
- **Gap 1 (Low)**: Child inherits parent filesystem state. Sensitive data
  written to filesystem by parent (not classified as credentials) persists
  in child workspace.
- **Gap 2 (Low)**: Fork timing and snapshot size reveal parent execution
  characteristics (how much state was accumulated before fork).
- **Gap 3 (Low)**: Lineage metadata reveals fork depth and genealogy.
- **Gap 4 (Low)**: Identical filesystem state across siblings creates
  a covert channel: multiple sibling sandboxes can observe and modify
  initially-identical state differently, and a later observer can correlate
  changes.

**Classification**: **Accepted with limits** for v1. Fork inheritance of
filesystem state is a documented design property (ADR-0007). Credential
exclusion and fresh identity provide strong preventive controls. The
filesystem-based covert channel is a niche concern.

**Recommended controls**:
1. Document fork filesystem inheritance in tenant documentation.
2. Consider workspace-diff snapshots (filesystem delta from parent) in v2
   to reduce child snapshot size and limit exposed parent state.
3. Add fork lineage depth limits to prevent genealogical analysis.

**Follow-up issues**: SC-IMPL-08

## Risk Classification Summary

### Must-Fix (blocks shared-host public beta)

| ID | Risk | Backend | Rationale |
|---|---|---|---|
| SC-01-gVisor | CPU cache side channels on gVisor without SMT/pinning controls | gVisor | No hardware isolation. Must not co-locate cross-tenant without CPU pinning and SMT exclusion. |
| SC-01-SMT | SMT sibling sharing across sandboxes | All | SMT siblings share L1 cache. Cross-tenant sandboxes must not share a physical core via SMT. |
| SC-06-Gap1 | Per-sandbox metric labels on shared hosts | All | sandbox_id labels on metrics expose per-tenant activity patterns to operators and co-tenant inference. |

### Accepted with Limits (operational controls required)

| ID | Risk | Control |
|---|---|---|
| SC-01-VM | L3 cache side channels on microVM backends | Non-overlapping CPU pinning + SMT exclusion. Intel CAT/MPAM for v2. |
| SC-02 | Memory pressure and page-cache contention | cgroup v2 memory.max limits. Memory-bandwidth monitoring for v2. |
| SC-03 | Scheduler timing and noisy-neighbor signals | CPU pinning (same as SC-01). Steal-time virtualization for v2. |
| SC-04 | Disk I/O and cache timing | io.max limits. Per-tenant cache partitions for v2. |
| SC-05 | Network timing and bandwidth contention | Per-namespace isolation. Bandwidth shaping for v2. |
| SC-06-Gap2-4 | Lifecycle timing, exec bytes, cardinality | Bucketed metrics on shared hosts. Shared-host redaction mode. |
| SC-07 | Snapshot metadata exposure | Operator access audit. Rate-limited metrics. |
| SC-08 | Fork behavior state inheritance | Documented design property. Workspace-diff for v2. |

### Out of Scope for v1

| ID | Risk | Rationale |
|---|---|---|
| SC-OUT-01 | Intel CAT Arm MPAM cache partitioning | Requires hardware enumeration, kernel policy, and per-workload configuration. v2 capability. |
| SC-OUT-02 | Memory-bandwidth reservation and monitoring | Requires `memory.bandwidth` cgroup controller or Intel MBA. v2 capability. |
| SC-OUT-03 | Per-tenant DNS proxy cache partitioning | Requires DNS proxy redesign. Low practical risk. v2 capability. |
| SC-OUT-04 | Virtualized kvm-clock steal-time reporting | Requires KVM modification or guest kernel cooperation. v2 investigation. |
| SC-OUT-05 | Workspace-diff snapshots | Requires snapshot format change. v2 capability. |
| SC-OUT-06 | Cloud-provider infrastructure side channels | Provider responsibility. Covered by deployment contract. |

## Accepted-Risk Register

These entries extend the residual-risk register in the [threat model](threat-model.md#residual-risk-register).

### RR-06a: Shared-hardware L3 cache timing on microVM backends

| Field | Value |
|---|---|
| Related risks | R-15 |
| Risk | Co-located microVM sandboxes on a shared host can observe each other's L3 cache access patterns through timing analysis, despite KVM EPT isolation. |
| Accepting profile | Firecracker and QEMU on shared hosts with non-overlapping CPU pinning and SMT sibling exclusion. |
| Compensating control | CPU pinning per sandbox with non-overlapping core sets. SMT sibling exclusion (no two sandboxes share a physical core). Intel CAT/MPAM in v2. |
| Owner | Security and Runtime |
| Review date | 2027-01-01 or before public-beta launch |
| Follow-up | SC-IMPL-01, SC-IMPL-02 |

### RR-06b: Shared-host metric and telemetry inference

| Field | Value |
|---|---|
| Related risks | R-15 |
| Risk | Per-sandbox metric labels on shared hosts enable co-tenant activity inference through lifecycle timing, resource events, and network counters. |
| Accepting profile | All backends on shared hosts with `shared_host_metric_redaction` enabled. |
| Compensating control | Per-tenant metric aggregation replacing sandbox_id labels. Bucketed lifecycle timing metrics. Rate-limited network interface metrics. |
| Owner | Security and Observability |
| Review date | 2027-01-01 or before public-beta launch |
| Follow-up | SC-IMPL-06 |

### RR-06c: Shared-host gVisor co-location

| Field | Value |
|---|---|
| Related risks | R-15 |
| Risk | gVisor sandboxes from different tenants co-located on the same host share L1/L2/L3 cache, memory bandwidth, and scheduling domains with no hardware isolation boundary. |
| Accepting profile | Not accepted for v1. gVisor cross-tenant co-location is prohibited until CPU pinning and SMT exclusion are enforced and gVisor cache-isolation posture is reviewed. |
| Compensating control | Dedicated tenancy for gVisor. Trusted Fast-Path workload class restricts blast radius. |
| Owner | Security and Runtime |
| Review date | 2027-01-01 |
| Follow-up | SC-IMPL-01, SC-IMPL-02 |

## Recommendations

### Scheduling

1. **CPU pinning (must-fix)**: Enforce non-overlapping `sched_setaffinity`
   CPU sets for cross-tenant sandboxes. Sandboxes from different tenants
   must not share any logical CPU.
2. **SMT sibling exclusion (must-fix)**: When SMT is enabled, sibling
   threads (e.g., cpu0 and cpu4 on a 4-core/8-thread system) must not be
   assigned to different tenants. The scheduling unit is the physical core.
3. **NUMA-aware placement (v2)**: Place sandbox memory and CPUs on the
   same NUMA node. Avoid cross-NUMA memory access that increases
   interconnect contention.

### Host Sharing

4. **Dedicated tenancy for gVisor (must-fix for v1)**: gVisor workloads
   from different tenants must not share a host. gVisor provides no
   hardware cache isolation. This restriction may be relaxed in v2 with
   CPU pinning and Intel CAT/MPAM.
5. **MicroVM co-location limit**: Cap the number of cross-tenant microVM
   sandboxes per host to limit cache-contention surface area.
6. **Workload-class mixing prohibition**: Do not mix Public Untrusted
   (Firecracker/QEMU) and Trusted Fast-Path (gVisor) workloads from
   different tenants on the same host.

### Metric Redaction

7. **Shared-host metric mode (must-fix)**: Implement a
   `shared_host_metric_redaction` flag that, when enabled on multi-tenant
   hosts:
   - Replaces `sandbox_id` labels with `tenant_id` on host-agent and
     network-agent metrics.
   - Buckets lifecycle timing metrics (p50/p95/p99 per tenant) instead of
     per-sandbox individual latencies.
   - Rate-limits network interface byte/packet counters (max 60s reporting
     interval).
   - Excludes per-sandbox cgroup event metrics from multi-tenant hosts.

### Backend Selection

8. **Shared-host backend policy (must-fix)**: Extend the backend selection
   engine to enforce that cross-tenant placement only occurs on hosts
   configured with CPU pinning and SMT sibling exclusion. Reject placement
   rather than silently weaken isolation.
9. **Isolation floor enforcement**: Maintain the current policy that
   Firecracker is the default for public untrusted workloads. gVisor
   requires explicit opt-in and dedicated tenancy.

## Follow-Up Implementation Issues

### SC-IMPL-01: Implement live side-channel probes in isolation boundary validation

**Priority**: High
**Description**: Replace the stub functions in `crates/pico-runtime/src/isolation/side_channels.rs`
with live measurement probes:
- `check_timing_observable_assertion`: Measure cache-line access timing
  variation using `rdtsc` or `clock_gettime` with CLOCK_MONOTONIC.
- `check_resource_side_channel_isolation`: Verify that resource usage
  from one sandbox is not observable from another via timing.
- `check_cpu_pinning_isolation`: Verify that `sched_setaffinity` is
  applied with non-overlapping CPU sets.
- `check_cache_observable_boundary`: Compare cache access latency from
  within and across sandbox boundaries.

Probes should run only when `live_boundary_tests: true` and require at
least two live sandboxes on the same host.

### SC-IMPL-02: Implement CPU pinning and SMT sibling exclusion

**Priority**: High
**Description**: Add per-sandbox CPU affinity configuration:
- Extend `SandboxConfig` or host-agent boot path to accept a CPU set.
- Apply `sched_setaffinity` to sandbox vCPU threads (Firecracker, QEMU)
  and gVisor sentry process.
- Enforce SMT sibling exclusion: when assigning CPUs, reserve sibling
  threads for the same sandbox or leave them unassigned.
- Reject placement on hosts that cannot satisfy the CPU isolation
  requirements for cross-tenant sandboxes.
- Update backend selection and placement engine to validate CPU isolation
  constraints.

### SC-IMPL-03: Enable cgroup v2 memory pressure metrics

**Priority**: Medium
**Status**: Implemented
**Description**: Enable `memory.pressure` cgroup v2 interface for per-sandbox
cgroups. Expose as a host-level gauge metric. This provides operators with
visibility into memory contention without exposing per-sandbox details to
tenants.

**Implementation**:
- `CgroupManager::read_memory_pressure` reads `memory.pressure` and returns
  the `some avg10` value (0.0--100.0) per sandbox.
- `pico_cgroup_memory_pressure` gauge is registered and updated every
  30 seconds via `HostAgent::spawn_memory_pressure_poller`. The gauge
  tracks the maximum pressure value across all active sandbox cgroups.
- The gauge is always host-level aggregate; it never exposes per-sandbox
  pressure to avoid cross-tenant inference.
- Operator documentation: [cgroup-metrics.md](../observability/cgroup-metrics.md)

### SC-IMPL-04: Rate-limit snapshot cache metrics on shared hosts

**Priority**: Medium
**Description**: Add rate-limiting to `pico_snapshot_cache_hits`,
`pico_snapshot_cache_misses`, and `pico_snapshot_eviction_*` metrics
when the host is configured for shared multi-tenancy. Consider aggregating
at per-tenant or per-cell granularity instead of per-host.

### SC-IMPL-05: Add per-sandbox network bandwidth shaping

**Priority**: Low
**Status**: Implemented
**Description**: Per-sandbox egress bandwidth limits via tc HTB qdisc
with fq_codel leaf. Attaches a rate-limiting qdisc to each sandbox's
host-side interface. Bounds the bandwidth-contention side channel and
provides fair-queueing across tenants. The configured bandwidth limit
is exposed as the `network.bandwidth.limit_configured` gauge.

### SC-IMPL-06: Implement shared-host metric redaction mode

**Priority**: High
**Description**: Implement `shared_host_metric_redaction` configuration flag:
- Replace `sandbox_id` labels with `tenant_id` on shared-host metrics.
- Bucket lifecycle timing metrics per tenant (p50/p95/p99).
- Rate-limit network interface byte/packet counters.
- Exclude per-sandbox cgroup event metrics.
- Maintain full per-sandbox granularity on dedicated-tenancy hosts.

### SC-IMPL-07: Add snapshot metadata access audit logging

**Priority**: Low
**Description**: Add structured audit events for snapshot metadata reads
and list operations. Integrate with durable audit delivery when
available.

### SC-IMPL-08: Add fork lineage depth limits

**Priority**: Low
**Description**: Add a configurable maximum fork depth (e.g., 10 levels)
to prevent genealogical analysis through lineage metadata. Default should
be conservative.

## Production Readiness Checklist Update

The assessment satisfies the evidence requirement for gate **G-15:
Side-channel and tenant-sharing posture** in the
[production readiness model](production-readiness.md#mandatory-gate-matrix).

Before a shared-host deployment profile can pass G-15:

- SC-IMPL-01 (live side-channel probes) is implemented and passing.
- SC-IMPL-02 (CPU pinning and SMT exclusion) is implemented and enforced.
- SC-IMPL-06 (shared-host metric redaction) is implemented and enabled.
- gVisor cross-tenant co-location is prohibited per RR-06c.
- All accepted-risk register entries (RR-06a, RR-06b, RR-06c) are
      recorded with owners and review dates.
- The candidate deployment profile matches the accepted-risk scope
      (backend, workload class, CPU pinning, metric redaction, gVisor policy).
- Security, Runtime, and Observability owners approve.

Until these conditions are met, cross-tenant shared-host placement remains
gated and dedicated tenancy is the required fallback.

## References

- [ADR-0006: Production security posture for sandbox isolation](../adr/0006-production-security-posture-for-sandbox-isolation.md)
- [ADR-0004: Default isolation backend strategy](../adr/0004-default-isolation-backend-strategy.md)
- [ADR-0005: Per-sandbox networking model](../adr/0005-per-sandbox-networking-model.md)
- [ADR-0007: Snapshot, resume, fork consistency model](../adr/0007-snapshot-resume-fork-consistency-model.md)
- [ADR-0009: Observability and reliability signals](../adr/0009-observability-and-reliability-signals.md)
- [Threat model](threat-model.md)
- [Production readiness model](production-readiness.md)
- [Isolation boundary validation suite](..../crates/pico-runtime/src/isolation)
- [Side-channel validation stubs](..../crates/pico-runtime/src/isolation/side_channels.rs)
- [Security Engineering, 3rd Ed (Anderson)](https://www.cl.cam.ac.uk/~rja14/book.html)
