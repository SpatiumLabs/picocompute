# Measured Overcommit Track: LS/BE Classes and Memory Sharing (P0 Spike)

**Date**: 2026-09-29 (P0 spike revision)
**Status**: Spike complete, track gated (P0 synthetic validation only)
**Issue**: CAP-168
**Strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Candidate revision**: `650f831`
**Profile**: Firecracker on `lab-64vcpu`, dedicated tenancy, `MIX-AGENT-V1`
**Default posture**: no-overcommit packing stays for launch

## Executive Summary

This report closes the spike half of CAP-168 and opens the gated
implementation track. LS/BE classification now flows from tenant policy
through the cell scheduler to cgroup/sched controls behind a policy gate
that defaults to disabled; SCHED_IDLE application, core-scheduling
probing, read-only base-sharing accounting, and balloon plus idle-reclaim
tied to the suspend memory profile all have executable Rust seams with P0
unit-test pins. Every overcommit effect is off unless a config explicitly
enables it, and latency-sensitive requests always pack strict.

**Overall verdict**: the classification plumbing, the scheduler gate, the
host-control mapping, and the reclaim math pass on synthetic P0 series for
the pinned lab profile. No LPOP is set, no
`docs/capacity/active-sandbox-defaults.md` number changes, and no
production-shaped host measurement exists yet: every
`proposed_lpop` is `none`, and every per-mechanism delta below is labeled
P0-model (unit-test-pinned) or DSec-reference (external input awaiting P1
confirmation). Promotion of any mechanism past the gate requires its P1
run through the S-RAMP-ACTIVE / S-SOAK-ACTIVE / S-NOISY / S-RAMP-EXEC
scenarios in section 5.

## How to Run the Evidence

```bash
cargo test -p pico-core --all-features --lib overcommit
cargo test -p pico-core --all-features --lib cell_scheduler
cargo test -p pico-core --all-features --lib capacity
cargo test -p pico-core --all-features --lib cgroups
cargo test -p pico-core --all-features --test placement_burst
cargo test -p pico-core --all-features --test control_plane_readiness
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Suite mapping:

| Validation area | Suite | Location |
|---|---|---|
| Service class, policy gate, controls, sched, reclaim math | 25 overcommit tests | `crates/pico-core/src/overcommit.rs` |
| Scheduler gate, overcommit bit, serde compat | cell_scheduler tests | `crates/pico-core/src/cell_scheduler/` |
| Packing model calibration | 69 capacity tests | `crates/pico-core/src/capacity/` |
| cgroup controls | 38 cgroups tests | `crates/pico-core/src/cgroups.rs` |
| Burst placement (class default) | placement_burst | `crates/pico-core/tests/placement_burst.rs` |
| Full create chain (class default) | control_plane_readiness | `crates/pico-core/tests/control_plane_readiness.rs` |

## 1. Candidate Profile

Pinned lab profile shared with the G-14 P0 evidence:

| Field | Value |
|---|---|
| Host SKU | `lab-64vcpu` (64 vCPU, 64 GiB, 500 GiB disk, 10 Gbps, 100 process slots) |
| Backend | Firecracker |
| Tenancy | dedicated |
| Default sandbox shape | 2 vCPU, 512 MiB, 1024 MiB disk, 512 PIDs |
| Strict advertised packing | **32** (vCPU-bound) |
| Overcommit policy | disabled (default) |

## 2. Mechanism Evaluations

Each mechanism below records four things: what was built in this
revision, the P0-model delta pinned by unit tests, the DSec reference
delta awaiting P1 confirmation, and the class-A invariants that gate it.

### 2.1 LS/BE classification from tenant policy through scheduler

Built (`pico_core::overcommit`, cell scheduler, create path):

- `ServiceClass::{LatencySensitive, BestEffort}` (default LS), resolved
  from `Tenant::default_service_class` via `resolve_service_class`.
  Explicit widening to best-effort without tenant opt-in fails closed.
- `CellSchedulerRequest.service_class` (serde-defaults to LS, so old
  payloads keep strict packing), threaded through `CreateRequest` and
  the API placement path at the LS default.
- `OvercommitPolicy` gate on `CellScheduler` (default disabled).
  Enabled, it scales host vCPU/memory totals for best-effort fit only;
  disk, network, and process slots are never overcommitted.
- `CellSchedulerResponse` echoes `service_class` and sets
  `overcommit_applied` only when a best-effort admit consumed budget
  beyond strict capacity, so S-NOISY can separate strict from
  overcommit admits. Invalid policies fail placement closed with
  `InvalidOvercommitPolicy` (not retryable).

P0-model delta (pinned by
`be_enabled_effective_fit_doubles_vcpu_packing`): with 2x CPU/memory
overcommit plus a 128 MiB shared-base discount, the default shape packs
**64 best-effort vs 32 strict** sandboxes on the lab SKU (vCPU-bound in
both cases). Strict packing is unchanged with the policy disabled
(pinned by `be_request_packs_strict_while_policy_disabled`).

DSec reference (not measured here): DSec 4.3 notes 90% of sandboxes sit
at <= 5% of requested CPU, which is the headroom an overcommit track
converts; 800 microVMs (3200 containers) per node stays a class-C design
target until an LPOP reaches it.

Class-A invariants: LS requests never consume overcommit budget (pinned
by `ls_request_never_consumes_overcommit_budget`); saturation still
sheds with typed `InsufficientCapacity`, never silent fallback; the
overcommit bit keeps admits auditable per-admit.

### 2.2 SCHED_IDLE plus core scheduling for SMT isolation

Built:

- `SchedPolicy::{Other, Batch, Idle}` with `apply_sched_policy_to_pid`
  over `sched_setscheduler(2)` on Linux (pid 0 refused; non-Linux is a
  validated no-op). Best-effort maps to `SCHED_IDLE`, latency-sensitive
  to `SCHED_OTHER` via `controls_for_class`.
- `probe_core_scheduling` reads the caller's own core-sched cookie via
  `prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET)` without side effects, so
  the P1 runbook can branch on kernel support (`CONFIG_SCHED_CORE`,
  kernel >= 5.14, host enablement).
- SMT sibling exclusion stays on the existing `cpu_isolation` path
  (topology detection, non-overlapping sets, `sched_setaffinity`);
  core-sched cookie *tagging* of VMM threads is not implemented in this
  revision (follow-up in section 6).

P0-model delta: the apply path round-trips `SCHED_IDLE` back to
`SCHED_OTHER` on the calling process on Linux (pinned by
`sched_policy_applies_to_own_process`); the probe returns a valid
`Supported`/`Unsupported` variant without side effects (pinned by
`core_sched_probe_returns_a_valid_variant`). No latency delta is
claimed at P0: scheduler-policy effects need contended-CPU measurement.

DSec reference (not measured here): DSec 8.4/8.5 reports SMT latency
inflation dropping from 45.2% to 17.3% with best-effort at SCHED_IDLE
plus core scheduling. Confirming or refuting that range on the lab SKU
is the S-NOISY P1 run in section 5.

Class-A invariants: policy application is per-explicit-pid only (no
process-group semantics); failures surface as typed control errors,
never silent demotion to a weaker policy.

### 2.3 Read-only base sharing (shared mounts, pmem/DAX)

Built:

- `BaseSharingMode::{None, SharedPageCache, PmemDax}` names the
  mechanism behind `OvercommitPolicy::be_shared_base_mb`, which is
  subtracted from the best-effort memory request via
  `effective_memory_request`.
- Fail-closed pairing: a non-zero shared-base discount with mode
  `None` fails policy validation, and the default discount is 0, so no
  config can claim sharing without naming the mechanism.
- The discount applies to best-effort requests under an enabled policy
  only; latency-sensitive requests always see the full shape.

P0-model delta (pinned by
`shared_base_discount_only_applies_to_be_with_mechanism` and the
packing test in 2.1): a 128 MiB discount turns the default 512 MiB
best-effort request into an effective 384 MiB request. The 128 MiB
figure is a placeholder knob, not a measurement: it exercises the
accounting path and must be replaced per-image from P1 data.

DSec reference (not measured here): DSec 5.2 reports -40% peak memory
with read-only layers on virtio-pmem plus DAX. The P1 run must measure
per-image shared-base megabytes on the lab SKU before any discount is
configured.

Class-A invariants: sharing accounting never changes the isolation
floor or backend selection; a misconfigured discount fails validation
instead of silently over-admitting.

### 2.4 Balloon plus idle-reclaim tied to the suspend memory profile

Built:

- `idle_reclaim_plan` reuses the container throttle-plus-
  `memory.reclaim` plan for the `Memory` snapshot profile and returns
  `None` for `Filesystem`: per ADR-0007, suspend needs the memory
  profile, so a filesystem-only snapshot preserves no guest memory to
  reclaim. Zero/tiny limits fail closed via `container_reclaim_plan`.
- `BalloonPolicy` (default disabled, fraction in (0, 1]) plus
  `balloon_target` pure math: inflate up to the fraction of the guest
  free-page hint, truncated and clamped to the sandbox limit, `None`
  when disabled or when either input is zero.

P0-model delta (pinned by `idle_reclaim_requires_memory_profile` and
`balloon_target_takes_fraction_and_clamps_to_limit`): throttle at half
the hard limit with full-limit reclaim write; balloon at 50% of the
free hint (e.g. 1024 B from a 2048 B hint in a 4096 B guest), never
past guest size, never a 1-byte balloon from a 1-byte hint.

DSec reference (not measured here): DSec 5.2 reports -21% integrated
memory with DAMON plus balloon free-page reporting. DAMON wiring and
guest-balloon actuation live behind the follow-ups in section 6; this
revision pins the plan math only.

Class-A invariants: reclaim applies to suspended (frozen) cgroups via
the existing `apply_reclaim` path with its written-count accounting;
profiles that preserve no memory yield no plan instead of a vacuous
one.

## 3. P0 Synthetic Packing Table

Model values from `SandboxPackingShape::platform_default` on the lab
SKU, pinned by unit tests (not measurements):

| Packing | vCPU bound | Memory bound | Admitted |
|---|---|---:|---:|
| Strict (both classes, gate off) | 32 | 128 | **32** |
| BE, 2x CPU/mem, 128 MiB shared base | 64 | 170 | **64** |
| LS, gate on | 32 | 128 | **32** |

Disk (488), process slots (100), and network never bind first on this
SKU/shape. The BE row is a model input to P1 design, not an operating
point: ratios and the shared-base knob need P1/P2 reports before any
config carries them.

## 4. Deliberately Unchanged

- `docs/capacity/active-sandbox-defaults.md`: no number changes (P1/P2
  reports only, never inference).
- Regional scheduler and `CellCapacity`: overcommit is host-level in
  this revision; cell-level BE pools are a follow-up.
- Scoring weights: placement scoring is untouched; class-aware scoring
  (e.g. BE bin-packing) is a follow-up.
- Host-guest protocol and sandboxd gRPC proto: no new RPCs, so the
  misuse-resistance checklist does not apply. SCHED_IDLE application to
  VMM/sentry pids and the tenant-registry wiring in admission need
  proto/route changes and are follow-ups.
- Launch posture: default policy disabled; preview stays inside the
  ADR-0012 headroom rule.

## 5. Gating Plan (per ADR-0012)

Warning zone caps the LPOP for every scenario below; saturation must
not break isolation, cleanup, or audit (class-A even if some creates
succeed). Each run uses a class mix (LS-only baseline, then LS+BE)
against one production-shaped host (P1) per backend.

| Scenario | Gate question | Pass bar for the mechanism |
|---|---|---|
| S-RAMP-ACTIVE | Does BE overcommit raise warning-max without moving saturation earlier for LS? | LS warning-max unchanged vs LS-only baseline; BE admits carry `overcommit_applied` |
| S-SOAK-ACTIVE | Does a warning-zone LS+BE mix hold 30-day SLO projection with no soak into saturation? | No `soak_left_warning_zone`; heartbeats fresh |
| S-NOISY | Do SCHED_IDLE + class controls + SMT exclusion hold LS p99 under a BE noisy neighbor? | LS exec p99 within diagnostic band; `isolation_held`; SMT inflation vs DSec 45.2% to 17.3% reference recorded |
| S-RAMP-EXEC | Does BE packing change exec-concurrency knee vs strict? | Exec LPOP reported separately; never copied from the active-count cap |

P1 runbook per mechanism: (1) characterize `be_shared_base_mb`
per image under `SharedPageCache` then `PmemDax`; (2) sweep
`be_cpu_overcommit`/`be_memory_overcommit` with LS SLOs green;
(3) run `probe_core_scheduling` on the SKU and, if supported, compare
cookie-tagged vs SMT-exclusion-only S-NOISY; (4) measure balloon +
idle-reclaim freed bytes vs the suspend memory profile. Only
mechanisms inside SLO plus class-A invariants graduate to
implementation follow-ups.

## 6. Findings

| Class | Code | Detail |
|---|---|---|
| C | `phase_cannot_set_lpop` | P0 spike: `proposed_lpop` is `none`; warning-max values are model inputs only |
| C | `saturation_not_reached` | No saturation knee exists at P0; knees need P1 runs |
| C | `core_sched_untagged` | Core-sched cookie tagging of VMM threads is unevaluated code, not a measurement; SMT story rests on `cpu_isolation` until the P1 probe comparison |
| C | `sharing_knob_unmeasured` | `be_shared_base_mb` default 0; any non-zero value needs a P1 report |

No class-A or class-B findings at P0: the gate defaults off, LS
behavior is byte-identical to strict packing, and every BE effect
requires explicit enablement plus validation.

## 7. Follow-up Issues

Implementation follow-ups open only for mechanisms inside SLO plus
class-A invariants after P1; until then they are blocked on evidence:

- P1 measurement runs (S-RAMP-ACTIVE / S-SOAK-ACTIVE / S-NOISY /
  S-RAMP-EXEC with LS+BE mix on the lab SKU).
- Tenant-registry wiring in admission (`resolve_service_class` at the
  API boundary) plus sandboxd proto/route changes for class delivery.
- SCHED_IDLE application to VMM/sentry pids and core-sched cookie
  tagging (needs kernel/host enablement from the P1 probe).
- Class-aware scoring (BE bin-packing) once packing evidence exists.
- Cell-level BE pools in the regional scheduler.

## 8. Acceptance Criteria Mapping

| CAP-168 accept | This revision |
|---|---|
| Spike report with per-mechanism memory/CPU/latency deltas on production-shaped host | P0 half done: per-mechanism sections with P0-model deltas, DSec references, and the P1 runbook that produces host deltas. Host deltas are open until P1 runs. |
| Follow-up implementation issues only for mechanisms inside SLO plus class-A invariants | Section 7 lists evidence-blocked follow-ups; none graduate before P1 SLO + class-A evidence. |
| Default no-overcommit posture stays for launch | Policy defaults disabled; LS byte-identical; defaults doc untouched. |
| No Fn/GPU | Untouched. |

## Appendix A: Test Run Output

```bash
cargo test -p pico-core --all-features --lib overcommit
# 25 passed
cargo test -p pico-core --all-features --lib cell_scheduler
# 85 passed
cargo test -p pico-core --all-features --lib capacity
# 69 passed
cargo test -p pico-core --all-features --lib cgroups
# 38 passed
cargo test -p pico-core --all-features --test placement_burst
# 2 passed
cargo test -p pico-core --all-features --test control_plane_readiness
# 46 passed
cargo clippy --workspace --all-targets --all-features -- -D warnings
# clean
```

## Appendix B: Reproducibility

```bash
# Full P0 evidence set used by this report
cargo test -p pico-core --all-features --lib overcommit
cargo test -p pico-core --all-features --lib cell_scheduler
cargo test -p pico-core --all-features --lib capacity
cargo test -p pico-core --all-features --lib cgroups
cargo test -p pico-core --all-features --test placement_burst
cargo test -p pico-core --all-features --test control_plane_readiness
cargo test -p pico-core --all-features --test backend_selection_property
# Clippy for the touched crates
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
