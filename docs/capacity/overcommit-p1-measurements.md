# Overcommit P1 Measurements: LS/BE Gating Evidence (Synthetic)

**Date**: 2026-09-29 (P1 synthetic revision)
**Status**: Gating harness complete, host runs open (P1 synthetic only)
**Strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Candidate revision**: `14a8771`
**Profile**: Firecracker on `lab-64vcpu`, dedicated tenancy, `MIX-AGENT-V1`
**Default posture**: no-overcommit packing stays for launch

## Executive Summary

This report provides the P1 gating harness and the first synthetic evidence
for the LS/BE overcommit track. A new pure-data module
(`pico_core::overcommit_p1`) evaluates the section 5 gating plan from the P0
spike report through the same `analyze_active_capacity` seam the load harness
feeds: LS baseline stability, the `overcommit_applied` bit contract, BE sweep
ordering, S-NOISY inflation against the external 45.2%/17.3% reference, the
core-scheduling branch, soak and noisy gates, exec-knee separation, and
balloon plus idle-reclaim bytes tied to the suspend profile.

**Overall verdict**: the gating harness passes on synthetic series for the
pinned lab profile (21 new gating tests green). No launch proven operating
point is set, no `docs/capacity/active-sandbox-defaults.md` number changes,
and no production-shaped host measurement exists yet: every `proposed_lpop`
is `none`, every per-mechanism delta below is labeled P1-synthetic
(scheduler simulation plus host-local probe) or external-reference (awaiting
host confirmation). No mechanism graduates to default-on in this revision.
Production-shaped host runs per backend (Firecracker first) remain the gate
for any graduation or defaults change.

## How to Run the Evidence

```bash
cargo test -p pico-core --all-features --lib overcommit_p1
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
| P1 gating verdicts, sweep, inflation, soak/noisy/exec, reclaim | 21 overcommit_p1 tests | `crates/pico-core/src/overcommit_p1.rs` |
| Service class, policy gate, controls, sched, reclaim math | 27 overcommit tests (22 module plus 5 gate matched by filter, 48 with P1) | `crates/pico-core/src/overcommit.rs` |
| Scheduler gate, overcommit bit, serde compat | 88 cell_scheduler tests | `crates/pico-core/src/cell_scheduler/` |
| Packing model calibration, zones, backend comparison | 69 capacity tests | `crates/pico-core/src/capacity/` |
| cgroup controls, reclaim plans | 38 cgroups tests | `crates/pico-core/src/cgroups.rs` |
| Burst placement (class default) | placement_burst | `crates/pico-core/tests/placement_burst.rs` |
| Full create chain (class default) | control_plane_readiness | `crates/pico-core/tests/control_plane_readiness.rs` |

## 1. Candidate Profile

Pinned lab profile shared with the P0 evidence:

| Field | Value |
|---|---|
| Host SKU | `lab-64vcpu` (64 vCPU, 64 GiB, 500 GiB disk, 10 Gbps, 100 process slots) |
| Backend | Firecracker (first; QEMU/gVisor repeat the same plan per backend) |
| Tenancy | dedicated |
| Default sandbox shape | 2 vCPU, 512 MiB, 1024 MiB disk, 512 PIDs |
| Strict advertised packing | **32** (vCPU-bound) |
| Overcommit policy | disabled (default) |
| Mix | `MIX-AGENT-V1` |
| Phase | P1 (one production-shaped host; input to cell tests, never an LPOP) |

Limitation: all zone numbers in this report come from synthetic
`analyze_active_capacity` series plus scheduler simulation on a developer
host (`arm64/Darwin` for this revision), not from a production-shaped host.
The developer host cannot set density, RPS, or SLO claims. Host runs on the
lab SKU remain open and must re-pin region, cell count, host image, kernel,
VMM, guest image, and config revision for the exact candidate.

## 2. Mechanism Evaluations

Each mechanism records four things: the P1 harness seam, the P1-synthetic
delta from that seam, the external reference awaiting host confirmation, and
the class-A invariants that gate it.

### 2.1 LS/BE classification and scheduler gate (S-RAMP-ACTIVE)

Harness (`pico_core::overcommit_p1`):

- `compare_ls_warning_max` requires the LS warning-max from the LS-only
  baseline ramp to equal the LS slice of the LS+BE mixed ramp exactly.
  Either side unmeasured fails closed.
- `verify_be_overcommit_bits` requires every BE admit beyond strict capacity
  to carry `overcommit_applied`, and forbids the bit on LS admits.
- `summarize_sweep` checks LS stability and isolation across the BE sweep;
  `sweep_mode_order_ok` enforces SharedPageCache-then-PmemDax table order.

P1-synthetic delta (pinned by `ls_baseline_match_passes_when_warning_max_equal`,
`be_bits_require_bit_beyond_strict_and_forbid_it_on_ls`,
`sweep_summary_tracks_ls_stability_and_isolation`):

- LS baseline warning-max **16** vs LS slice warning-max **16**: `ls_unchanged = true`.
- BE bit audit on a mixed ramp (1 BE beyond strict with bit, 1 BE within
  strict without bit, 1 LS without bit): `passes = true`, `be_beyond_strict = 1`.
- Sweep of 2 points (2.0x CPU/2.0x memory/128 MiB shared-base under
  SharedPageCache, then under PmemDax): LS stable at all points, all
  isolated, max mixed warning-max **52** (synthetic zone input, not an LPOP).
- Packing math unchanged from P0: default shape packs **64 BE vs 32 strict**
  on the lab SKU at 2x plus 128 MiB shared-base discount (vCPU-bound).

External reference: none beyond P0. The 90% at or below 5% requested CPU
headroom note stays a class-C design input until a host LPOP reaches it.

Class-A invariants: LS never consumes overcommit budget; saturation sheds
with typed `InsufficientCapacity`; the overcommit bit keeps admits auditable
per admit. A mixed ramp that moves the LS warning-max earlier fails the gate.

### 2.2 SCHED_IDLE plus core scheduling and SMT exclusion (S-NOISY)

Harness:

- `smt_inflation_pct` computes `(noisy - baseline)/baseline * 100`, fail
  closed on non-finite or non-positive baseline.
- `classify_smt_inflation` places the result against the 17.3%/45.2%
  reference band (descriptive, not a pass threshold).
- `core_sched_branch` maps `probe_core_scheduling` onto
  `cookie_tagged_vs_smt_exclusion` (when `Supported`) or
  `smt_exclusion_only` (when `Unsupported`).
- `check_noisy_holds` requires isolation findings absent
  (`isolation_broken`, `cross_tenant_placement`) plus a computable inflation
  number.

P1-synthetic delta (pinned by `smt_inflation_matches_reference_band`,
`noisy_holds_with_isolation_and_computable_inflation`):

- Baseline p99 100 ms to noisy 117.3 ms: inflation **17.3%**
  (`at_or_below_reference`, matches the mitigated reference).
- Baseline p99 100 ms to noisy 145.2 ms: inflation **45.2%**
  (`within_reference`, matches the unmitigated reference).
- S-NOISY synthetic report (8 active, dedicated tenancy, no cross-tenant):
  `isolation_held = true`, `passes = true` with SMT-exclusion-only branch.
- Host-local probe on this revision (`arm64/Darwin`, non-Linux):
  `Unsupported` with reason `non-linux platform`, so `core_branch =
  smt_exclusion_only`. The cookie-tagged comparison is open until a Linux lab
  SKU with kernel and host enablement reports `Supported`.

External reference (not measured here): SMT latency inflation dropping from
45.2% to 17.3% with BE at SCHED_IDLE plus core scheduling. Confirming or
refuting that range on the lab SKU is the host S-NOISY run.

Class-A invariants: policy application is per-explicit-pid only; failures
surface as typed control errors; cross-tenant placement on dedicated tenancy
fails the run even when latency looks green (pinned by
`noisy_fails_on_isolation_break_even_with_green_latency`).

### 2.3 Read-only base sharing (SharedPageCache/PmemDax)

Harness: `OvercommitPolicy::be_shared_base_mb` with `BaseSharingMode`,
validated fail-closed (non-zero discount with `None` fails; oversized values
fail at the `MAX_SHARED_BASE_MB` rail).

P1-synthetic delta (pinned by the sweep tests in 2.1 plus the P0 packing test):

- 128 MiB discount turns the default 512 MiB BE request into an effective
  384 MiB request. The 128 MiB figure stays a placeholder knob: it exercises
  the accounting path and must be replaced per image from host data.
- Sweep table order SharedPageCache-then-PmemDax passes
  (`sweep_mode_order_ok`); the reversed order fails as intended.

External reference (not measured here): -40% peak memory with read-only
layers on virtio-pmem plus DAX. The host run must characterize
`be_shared_base_mb` per image under SharedPageCache first, then under
PmemDax, before any discount is configured.

Class-A invariants: sharing accounting never changes the isolation floor or
backend selection; misconfigured discounts fail validation instead of
silently over-admitting.

### 2.4 Balloon plus idle-reclaim tied to the suspend profile (Memory/Filesystem)

Harness: `measure_reclaim_freed_bytes` combines `balloon_target` with
`idle_reclaim_plan` for both profiles. The Filesystem side must free zero.

P1-synthetic delta (pinned by `reclaim_ties_freed_bytes_to_memory_profile`):

- 512 MiB limit with 256 MiB free hint at 50% fraction: balloon frees
  **128 MiB**; Memory-profile idle-reclaim frees **512 MiB** (full-limit
  reclaim write with half-limit throttle); Filesystem-profile frees **0**.
- Zero limit with zero hint: all sides zero, Filesystem stays zero.

External reference (not measured here): -21% integrated memory with free-page
reporting. Actuation and free-page hint wiring stay behind follow-up work;
this revision pins the plan math plus the profile tie.

Class-A invariants: reclaim applies to suspended (frozen) cgroups via the
existing apply path with written-count accounting; profiles that preserve no
memory yield no plan instead of a vacuous one.

### 2.5 Exec concurrency (S-RAMP-EXEC)

Harness: `compare_exec_knees` requires both exec reports on the
exec-concurrency axis and flags a mixed exec knee that copies the
active-count cap.

P1-synthetic delta (pinned by
`exec_knees_stay_on_concurrency_axis_and_separate_from_active`):

- Strict exec knee **32** concurrent vs mixed LS+BE knee **16** concurrent
  (synthetic error-ratio knees); `both_on_exec_axis = true`,
  `separate_from_active_cap = true` against active warning-max 24.
- Copy case (both knees 24 against active 24): `separate_from_active_cap =
  false`, so the report cannot present a copy as a measurement.

External reference: none. Exec LPOP is unset until host S-RAMP-EXEC runs; it
must be reported separately and never copied from the active-count cap.

Class-A invariants: exec contention must not move boot/restore across latency
thresholds silently; saturation still sheds typed rejects.

## 3. P1 Synthetic Zone Tables

Model values from synthetic `analyze_active_capacity` series (not host
measurements). All phases are P1, so every `proposed_lpop` is `none`.

| Scenario | Input | Safe max | Warning max | Knee | Proposed LPOP |
|---|---|---:|---:|---:|---:|
| S-RAMP-ACTIVE LS-only baseline | 8/12/16 active, healthy | 16 | 16 | none | none |
| S-RAMP-ACTIVE LS+BE mixed (synthetic stable) | same steps plus BE bit audit | 16 | 16 | none | none |
| S-RAMP-ACTIVE LS moved earlier (negative) | saturation at 12 | 8 | 8 | 12 | none |
| S-SOAK-ACTIVE warning-zone mix | 16 active at pressure 16, fresh heartbeats | - | 16 | none | none |
| S-NOISY dedicated, no cross-tenant | 8 active, isolation held | 8 | 8 | none | none |
| S-RAMP-EXEC strict | 1/4/8/32 concurrent | - | 8 | 32 | none |
| S-RAMP-EXEC LS+BE | 1/4/8/16 concurrent | - | 8 | 16 | none |

Calibration on the synthetic stable ramp (advertised 32 vs measured warning
max 16) reports over-advertise class-A synthetically: the synthetic series
stops at 16 active without reaching the packing limit, so the gap is a
harness-range artifact, not a scheduler defect. Host ramps must fill to the
packing knee before calibration is meaningful.

## 4. Deliberately Unchanged

- `docs/capacity/active-sandbox-defaults.md`: no number changes. P1 reports
  keep `proposed_lpop = none` per `ValidationPhase::P1`, so there is no
  measured warning-max to promote. The file changes only from a future host
  report with measured knees, never by inference from synthetic tables.
- Regional scheduler and cell pools: overcommit stays host-level; cell-level
  BE pools remain follow-up work pending host evidence.
- Scoring weights: placement scoring untouched; class-aware scoring (BE
  bin-packing) remains follow-up work pending packing evidence.
- Host-guest protocol and sandboxd gRPC proto: no new RPCs, so the
  misuse-resistance checklist does not apply. New RPC or field work (class
  delivery, VMM controls) needs the checklist at that time.
- Launch posture: default policy disabled; preview stays inside the ADR-0012
  headroom rule.

## 5. Gating Evaluation (per ADR-0012)

Warning zone caps the LPOP for every scenario; saturation must not break
isolation, cleanup, or audit (class-A even if some creates succeed). Each
host run uses a class mix (LS-only baseline, then LS+BE) on one
production-shaped host per backend. Synthetic status below; host runs open.

| Scenario | Gate question | P1-synthetic status | Host gate for promotion |
|---|---|---|---|
| S-RAMP-ACTIVE | Does BE overcommit raise warning-max without moving saturation earlier for LS? | Pass (synthetic): LS warning-max 16 matches baseline; BE sweep LS-stable and isolated; every BE admit beyond strict carries the bit | LS warning-max unchanged vs LS-only baseline on the lab SKU; BE admits carry `overcommit_applied` |
| S-SOAK-ACTIVE | Does a warning-zone LS+BE mix hold the SLO projection with no soak into saturation? | Pass (synthetic): no `soak_left_warning_zone`; heartbeats fresh; no leak | No `soak_left_warning_zone` on a timed soak; heartbeats fresh |
| S-NOISY | Do SCHED_IDLE plus class controls plus SMT exclusion hold LS p99 under a BE neighbor? | Pass (synthetic): isolation held; inflation 17.3% recorded at/below reference; branch SMT-exclusion-only on this host | LS exec p99 within diagnostic band; `isolation_held`; inflation vs 45.2%/17.3% recorded; probe on the SKU plus cookie-tagged vs SMT-exclusion-only where supported |
| S-RAMP-EXEC | Does BE packing change the exec-concurrency knee vs strict? | Pass (synthetic): strict knee 32 vs mixed knee 16 on the concurrency axis, separate from active 24 | Exec LPOP reported separately; never copied from the active-count cap |

P1 runbook per mechanism (open for host runs): (1) characterize
`be_shared_base_mb` per image under SharedPageCache then PmemDax; (2) sweep
`be_cpu_overcommit`/`be_memory_overcommit` with LS SLOs green; (3) run the
core-scheduling probe on the SKU and, if supported, compare cookie-tagged vs
SMT-exclusion-only S-NOISY; (4) measure balloon plus idle-reclaim freed bytes
vs the suspend Memory/Filesystem profiles. Only mechanisms inside SLO plus
class-A invariants graduate to implementation follow-ups.

## 6. Findings

| Class | Code | Detail |
|---|---|---|
| C | `phase_cannot_set_lpop` | P1 synthetic: `proposed_lpop` is `none`; warning-max values are harness inputs only |
| C | `saturation_not_reached` | Synthetic stable ramps stop before the packing knee; knees need host runs |
| C | `core_sched_untagged` | Cookie tagging of VMM threads is unevaluated code, not a measurement; SMT story rests on exclusion until the host probe comparison |
| C | `sharing_knob_unmeasured` | `be_shared_base_mb` default 0; any non-zero value needs a host report |
| C | `synthetic_host_gap` | Developer host (`arm64/Darwin`) is not production-shaped; density, RPS, and SLO claims need the lab SKU |

No class-A or class-B findings on the synthetic series: the gate defaults
off, LS behavior matches strict packing, and every BE effect requires
explicit enablement plus validation.

## 7. Follow-up Work

Implementation follow-ups open only for mechanisms inside SLO plus class-A
invariants after host runs; until then they stay blocked on evidence:

- Host measurement runs (S-RAMP-ACTIVE/SOAK-ACTIVE/S-NOISY/S-RAMP-EXEC with
  LS+BE mix on the lab SKU, Firecracker first, then QEMU/gVisor).
- Tenant-registry wiring in admission plus sandboxd proto and route changes
  for class delivery.
- SCHED_IDLE application to VMM and sentry pids and core-scheduling cookie
  tagging (needs kernel and host enablement from the host probe).
- Class-aware scoring (BE bin-packing) once packing evidence exists.
- Cell-level BE pools in the regional scheduler.

## 8. Acceptance Mapping

| P1 task | This revision |
|---|---|
| S-RAMP-ACTIVE BE sweep with LS baseline stability and bit audit | Synthetic harness plus stable LS 16/16, bit audit pass, SharedPageCache-then-PmemDax order check; host sweep open |
| S-SOAK-ACTIVE at warning-zone LS+BE mix | Synthetic soak pass with no soak into saturation and fresh heartbeats; timed host soak open |
| S-NOISY with SCHED_IDLE plus class controls plus SMT exclusion | Synthetic noisy pass with 17.3% inflation recorded and probe branch mapped; host noisy run with SKU probe open |
| S-RAMP-EXEC knee for LS+BE vs strict | Synthetic strict 32 vs mixed 16 on the concurrency axis, separate from active; host exec ramp open |
| Balloon plus idle-reclaim vs suspend profile | Synthetic 128 MiB balloon plus 512 MiB Memory-profile reclaim vs 0 Filesystem; host freed-bytes measurement open |
| P1 report with per-mechanism deltas | This document with P1-synthetic deltas, external references, and gating verdicts |
| Defaults update only from this report | No number changes: P1 keeps `proposed_lpop = none`, so there is nothing to promote |
| Graduate only mechanisms inside SLO plus class-A | No graduations in this revision; all mechanisms stay gated pending host SLO plus class-A evidence |

## Appendix A: Test Run Output

```bash
cargo test -p pico-core --all-features --lib overcommit_p1
# 21 passed
cargo test -p pico-core --all-features --lib overcommit
# 48 passed (21 P1 gating plus 27 P0 overcommit matched by the filter)
cargo test -p pico-core --all-features --lib cell_scheduler
# 88 passed
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
# Full P1 evidence set used by this report
cargo test -p pico-core --all-features --lib overcommit_p1
cargo test -p pico-core --all-features --lib overcommit
cargo test -p pico-core --all-features --lib cell_scheduler
cargo test -p pico-core --all-features --lib capacity
cargo test -p pico-core --all-features --lib cgroups
cargo test -p pico-core --all-features --test placement_burst
cargo test -p pico-core --all-features --test control_plane_readiness
cargo test -p pico-core --all-features --test backend_selection_property
# Clippy for the workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
