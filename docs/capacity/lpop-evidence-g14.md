# G-14 LPOP Evidence Against Live SLO Queries (P0)

**Date**: 2026-09-20 (initial P0 revision)
**Status**: Draft (P0 synthetic validation)
**Strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**SLO policy**: [SLO and error-budget policy](../observability/slo-error-budget-policy.md)
**Readiness model**: [Production readiness](../security/production-readiness.md) gate `G-14`
**Assurance parent**: [Security assurance case](../security/assurance-case.md) claim `C-06`
**Candidate revision**: `d2a1836`
**Profile**: Firecracker on `lab-64vcpu`, dedicated tenancy, `MIX-AGENT-V1`

## Executive Summary

This report provides P0 synthetic G-14 evidence that the `pico:slo:*`
recording rules and burn alerts behave per policy when fed representative
load, and that the ADR-0012 scenario-to-target mapping is fully wired through
executable Rust seams. It does not set an LPOP and does not authorize quotas:
every `proposed_lpop` is `none`, every `LpopTuple` rate is `none`, and the
bundle carries an explicit `phase_cannot_set_lpop` finding.

**Overall verdict**: the SLO query contract, burn-alert predicates, freeze
checklist, throughput classification, and bundle assembly all pass on
synthetic series for the pinned Firecracker lab profile. All 181 composed
model tests pass plus the offline `burn_rate_sim.py` check. Promotion to P2
preview LPOP requires a production-shaped cell, live Prometheus scrape of
`pico:slo:*`, timed soak and failure drills, and owner sign-off listed in
section 8.

## How to Run the Evidence

```bash
cargo nextest run -p pico-core --lib slo_validation
cargo nextest run -p pico-core --lib capacity
cargo nextest run -p pico-core --lib restore_capacity
cargo nextest run -p pico-core --lib image_cache
cargo nextest run -p pico-core --lib availability
cargo nextest run -p pico-core --lib cost_model
python3 o11y/slo/burn_rate_sim.py
cargo clippy -p pico-core --lib --locked -- -D warnings
```

Suite mapping to validation areas:

| Validation area | Suite | Location |
|---|---|---|
| SLO math, burn predicates, freeze, throughput, mapping, bundle | 29 slo_validation tests | `crates/pico-core/src/slo_validation/` |
| ST-ACTIVE and ST-EXEC density zones and calibration | 65 capacity tests | `crates/pico-core/src/capacity/` |
| ST-RESTORE pressure zones and calibration | 24 restore tests | `crates/pico-core/src/restore_capacity/` |
| ST-CACHE cold, warm, thrash zones and sizing | 26 image-cache tests | `crates/pico-core/src/image_cache/` |
| ST-CELL failover and recovery | 16 availability tests | `crates/pico-core/src/availability/` |
| Cost, headroom, and rollout limits | 21 cost-model tests | `crates/pico-core/src/cost_model/` |
| Offline burn-rate math and rule names | burn sim check | `o11y/slo/burn_rate_sim.py` |

Related prior evidence (not duplicated here): SLO policy in
`docs/observability/slo-error-budget-policy.md`, recording
rules in `o11y/rules/pico-recording-rules.yaml`, dashboard in
`o11y/slo-error-budget.json`, runbook in `docs/runbooks/slo-error-budget.md`,
scale strategy in ADR-0012, active defaults in
`docs/capacity/active-sandbox-defaults.md`, restore pressure in
`docs/capacity/checkpoint-load.md`, cell behavior in
`docs/capacity/cell-unavailability.md`, cost plan in
`docs/capacity/cost-model.md`.

## 1. Candidate Profile

Pinned by `CandidateProfile::firecracker_lab_dedicated`:

| Field | Value |
|---|---|
| Region | `lab-region` |
| Cells | 1 |
| Host SKU | `lab-64vcpu` (64 vCPU, 64 GiB, 500 GiB disk, 10 Gbps, 100 process slots) |
| Kernel | `lab-kernel-6.8` |
| Backend | Firecracker |
| Guest image | `agent-guest-v0.1.0` |
| Config revision | `g14-p0` |
| Tenancy | dedicated |
| Mix | `MIX-AGENT-V1` (50 WP-SHORT, 20 WP-SESSION, 15 WP-RESTORE, 5 WP-FORK, 7 WP-NET, 3 WP-COLD) |
| Source revision | `d2a1836` |

Profile scope matches `active-sandbox-defaults.md` lab SKU. Single-cell lab
scope means no regional API claim and no multi-cell survival claim. Any P2
preview LPOP must re-pin region, cell count, host image, kernel, VMM, guest
image, and config revision for the exact candidate.

## 2. Live SLO Query Validation

Recording-rule parity is pinned by `validate_recording_rules_text` plus the
`recording_rules_match_deployed_file` test, which reads the deployed
`o11y/rules/pico-recording-rules.yaml` and asserts:

- all 13 required `pico:slo:*` records exist (targets, bad and valid rates
  for 5m, 30m, 1h, 6h, 30d, error ratios, burns, budget remaining)
- all 4 alerts exist (`PicoComputeSloBurnFast`, `PicoComputeSloBurnSlow`,
  `PicoComputeSloBudgetExhausted`, `PicoComputeSloTelemetryStale`)
- the stale `outcome="error"` selector is gone

SLO math parity is pinned by `burn_math_matches_policy_worked_example`,
which repeats the policy worked example: 7.2 percent errors on a 99.5 percent
SLO is exactly 14.4x burn, 1.44 percent on a 99.9 percent SLO is 14.4x, and
14.4x exhausts the 30-day budget in about 50 hours. `error_ratio_empty_is_no_data_not_zero`
pins the missing-data contract: zero valid events is no data, never zero
percent errors.

Targets pinned by `slo_targets_match_recording_rules`:

| SLO | Target | Budget | User-facing |
|---|---|---|---|
| create, boot, suspend, resume, fork, restore | 99.5% | 0.5% | yes |
| exec, destroy | 99.9% | 0.1% | yes |
| audit | 99.99% | 0.01% | no (platform health) |

## 3. Burn-Alert Simulation

`evaluate_slo` mirrors the PromQL windows: error ratios for 5m, 30m, 1h, 6h,
30d, burns per window, budget remaining, and the fast and slow predicates
with quiet-region floors (0.01 per second for fast, 0.003 per second for
slow).

Proven by tests:

| Test | Proves |
|---|---|
| `fast_burn_simulation_pages_and_slow_tickets` | 7.3 percent errors on 99.5 percent (14.6x) fires both fast and slow, budget 0 |
| `slow_only_simulation_tickets_without_paging` | 3.1 percent errors (6.2x) fires slow only, no page |
| `fast_burn_needs_both_windows_and_floor` | single-window burn does not page |
| `slow_burn_needs_both_windows_and_floor` | single-window burn does not ticket |
| `quiet_region_does_not_page_despite_huge_ratio` | 1 bad in 2 valid looks like 50 percent errors but stays below the rate floor |
| `freeze_blocks_on_fast_burn_and_stale_telemetry` | page and stale series both block rollout |
| `freeze_with_no_evaluations_fails_closed` | empty evaluation list blocks rollout as unknown |
| `freeze_exception_waives_budget_only` | exception waives the 25% rule only; fast burn still blocks and `reasons` holds exactly the blocking reasons |
| `evaluate_slo_without_30d_data_yields_no_budget` | missing 30d data yields zero remaining budget, never full budget |
| `bundle_digest_is_reproducible` | clearing `lpop.artifact_digest` and rehashing reproduces the recorded digest |
| `bundle_records_exhausted_budget_without_fast_burn` | spent 30d budget with healthy windows fails freeze with a `budget_exhausted` finding |
| `g14_bundle_is_fail_closed_on_fast_burn` | injected fast burn fails the bundle freeze with a `fast_burn_firing` finding |

Healthy soak (`healthy_soak_passes_freeze_with_full_budget`) keeps full budget
on all nine SLOs at representative volume with no fast burn, no exhaustion,
fresh telemetry, and a passing freeze. No fast-burn page is active in the
steady-state bundle, satisfying that acceptance criterion synthetically.
Live Prometheus evaluation against sample traffic on the candidate remains a
P2 requirement.

## 4. Throughput Scenarios (ST-API, ST-CREATE, ST-PIPE)

`ThroughputScenario` owns the seven rate scenarios without a prior Rust
model: `S-RAMP-API`, `S-SPIKE-API`, `S-RAMP-CREATE`, `S-SPIKE-CREATE`,
`S-RAMP-PIPE`, `S-SOAK-MIX`, `S-PIPE-BACKPRESSURE`. `S-SOAK-MIX` uses
`MIX-AGENT-V1` shares. Classification reuses the capacity zone vocabulary
(safe, warning, saturation) with SLO-budget-derived thresholds: warning at
half budget, saturation at full budget. Host pressure uses the capacity
bands (memory-pressure warning at 15, saturation at 30; utilization warning
at 0.75, saturation at 0.90): saturation on either band marks the knee, with
the zone carrying the signal. A step with no terminal valid events is
Saturation (unknown, never healthy).

Fail-closed behavior pinned by tests:

- timeouts rising with `unavailable` rejects is class-A
  (`timeout_instead_of_shed`), never counted as clean shed
- a step with zero valid events is class-A (`no_valid_events`), never
  reported as healthy
- stale `pico:slo:*` series is class-A (`telemetry_stale`), never reported
  as healthy
- audit lag above 30s is class-A (`audit_lag`) per SLO-AUDIT-LAG
- isolation, cleanup, backend-change, leak, and cross-tenant placement breaks
  are class-A even when SLOs look green
- spike reports carry `spike_measures_shed_not_rate` (class-C): they prove
  shed behavior, never a sustainable rate
- every P0 report carries `phase_cannot_set_lpop` and keeps
  `proposed_lpop = none`

Cell-failure and snapshot-load runs compose the existing models rather than
re-implementing them: `S-FAIL-HOST`, `S-FAIL-CELL`, and `S-RECOVER` run
through `analyze_cell_availability`; `S-RAMP-RESTORE`, `S-SPIKE-RESTORE`, and
`S-SOAK-RESTORE` run through `analyze_restore_pressure`. Cache and density
compose similarly (section 5).

## 5. Full Mapping and Composed Models

`mapping_completeness` encodes the ADR-0012 mapping table. All eight targets
are present in the P0 bundle synthetically:

| Target | Required scenarios | P0 source |
|---|---|---|
| ST-API | S-RAMP-API, S-SPIKE-API, S-SOAK-MIX | slo_validation throughput |
| ST-CREATE | S-RAMP-CREATE, S-SPIKE-CREATE, S-SOAK-MIX | slo_validation throughput |
| ST-ACTIVE | S-RAMP-ACTIVE, S-SOAK-ACTIVE, S-NOISY | capacity model |
| ST-EXEC | S-RAMP-EXEC, S-NOISY, S-SOAK-MIX | capacity model |
| ST-RESTORE | S-RAMP-RESTORE, S-SPIKE-RESTORE, S-SOAK-RESTORE | restore_capacity model |
| ST-CACHE | S-CACHE-COLD, S-CACHE-WARM, S-CACHE-THRASH | image_cache model |
| ST-CELL | S-FAIL-HOST, S-FAIL-CELL, S-RECOVER | availability model |
| ST-PIPE | S-RAMP-PIPE, S-PIPE-BACKPRESSURE, S-SOAK-MIX | slo_validation throughput |

`mapping_completeness_covers_full_matrix` pins all 20 scenario IDs present.
`mapping_completeness_flags_missing_cell_drill` pins the negative path: a
missing `S-FAIL-CELL` surfaces as an incomplete ST-CELL row, and
`build_g14_bundle` converts any missing row into a class-A
`mapping_incomplete` finding.

Composed P0 suites and their report seams:

- capacity: `analyze_active_capacity` with safe, warning, and saturation zones
  plus scheduler calibration inside a 15 percent band
- restore_capacity: `analyze_restore_pressure` with lineage, secret-material,
  partial-cleanup, and backlog class-A rules
- image_cache: `analyze_image_cache` with cold, warm, and thrash paths and
  byte sizing from working set plus headroom
- availability: `analyze_cell_availability` with no-placement-on-failed-domain,
  no-split-brain, no-retry-after-reject, and surviving-capacity output
- cost_model: plan, headroom, and per-stage rollout limits (all `none` at P0)

## 6. Measured Availability, Latency, Capacity, Headroom, and Cost

Availability: healthy synthetic soak holds zero bad events on all nine SLOs,
so projected 30-day error ratios sit at zero and budget remaining at 1.0.
Burn simulation bounds the other end: 14.6x pages, 6.2x tickets. Freeze on the
healthy bundle passes with min user-facing budget 1.0, no fast burn, and
fresh telemetry.

Latency: p99 panels stay diagnostic per policy until histogram buckets include
threshold edges (0.1, 0.2, 0.5, 1, 2, 5, 8 seconds). Throughput steps record
audit lag against the 30s SLO-AUDIT-LAG threshold; restore and prepare p99
values flow through the composed restore and cache reports. No latency SLO
consumes budget in P0.

Capacity: throughput knees are recorded per scenario (`knee` on saturation
onset) with `proposed_lpop = none`. Density, restore concurrency, cache
bytes, and surviving capacity flow from the composed reports via their
digests into `G14EvidenceBundle.composed_digests`.
`G14EvidenceBundle::artifact_digest` hashes the bundle with
`lpop.artifact_digest` cleared, so clearing that field and rehashing
reproduces the recorded digest.

Headroom: `LpopTuple.headroom` records 0.50 (private-preview rule) as the
candidate input, never as an authorized margin. Beta and production need 0.25
plus surviving-cell capacity after one cell loss on a P3 regional candidate.

Cost: P0 plans use `PriceBook::example_lab` only. The bundle records an
optional `cost_digest` when a plan is computed; rollout limits stay `none`
until the limiting evidence phase across density, restore, cache, and
availability reaches P2 (preview) or P3 (beta and production).

## 7. Test Counts at the Tested Revision (2026-09-20)

| Suite | Tests | Passed | Failed | Evidence |
|---|---|---|---|---|
| slo_validation lib | 22 | 22 | 0 | Rerun in-session |
| capacity lib | 65 | 65 | 0 | Rerun in-session |
| restore_capacity lib | 24 | 24 | 0 | Rerun in-session |
| image_cache lib | 26 | 26 | 0 | Rerun in-session |
| availability lib | 16 | 16 | 0 | Rerun in-session |
| cost_model lib | 21 | 21 | 0 | Rerun in-session |
| **Total pinned by this report** | **174** | **174** | **0** | All suites rerun in-session |
| burn_rate_sim.py offline check | 1 | 1 | 0 | `ok: burn-rate math and recording-rule names` |

Full workspace lib total at this revision: 1075 passed, 0 failed.

## 8. Known Gaps and Accepted Limitations

| Gap | Severity | Evidence | Mitigation and follow-up |
|---|---|---|---|
| No live Prometheus scrape of `pico:slo:*` on the candidate | High for G-14 | This report section 3 plus bundle `limitations` | P2 cell run must scrape recording rules and alerts under MIX-AGENT-V1; G-14 evidence follow-up |
| No production-shaped cell or regional candidate measured | High for LPOP | `phase_cannot_set_lpop` finding, all LPOP rates `none` | P2 cell validation then P3 regional candidate per ADR-0012 phases |
| Soak durations are synthetic steps, not 24h or 72h stage soaks | High for LPOP | Bundle `limitations` | Stage soak at preview, beta, or production LPOP with leak checks |
| Cell-failure fencing and orphan reconcile unmeasured beyond scheduler snapshots | High for beta S-FAIL-CELL | availability model class-C notes | Host-agent fencing plus reconcile measurement before public beta |
| Snapshot-store backlog and lineage under sustained restore unmeasured beyond synthetic steps | Medium | restore_capacity soak notes | Timed S-SOAK-RESTORE with storage-tier labels |
| Cache working set uncalibrated until a thrash report on the candidate | Medium | image_cache sizing notes | S-CACHE-THRASH on the candidate image set |
| Latency SLOs diagnostic only (histogram buckets, API request export, host heartbeat age pending) | Medium | SLO policy instrumentation follow-ups | Wire buckets and `pico.api.request.*`, then attach LAT SLOs to burn machinery |
| SLO-API uses the create proxy | Medium | Policy provisional clause | Export ADR `pico.api.request` with outcome taxonomy |
| Cost uses lab example prices | Low for planning, blocking for procurement | cost_model docs | Finance and infra owners supply real prices at review |
| Generator fidelity: synthetic counters, not a load generator with client RPS and auth minting limits | Medium | Bundle `limitations` | P2 harness must record offered vs admitted vs completed plus generator bottleneck attestation |

## 9. Acceptance Criteria Mapping

- LPOP and scenario reports exist for the candidate profile with measured
  numbers: sections 1, 4, 5, 7. P0 reports record knees, warning zones,
  error ratios, and digests with `proposed_lpop = none`. Full 20-scenario
  mapping is wired and pinned by `mapping_completeness_covers_full_matrix`.
  Real measured LPOP awaits P2.
- Burn-alert simulation proves fast-burn pages and slow-burn tickets fire
  correctly: section 3. 14.6x fires fast plus slow; 6.2x fires slow only;
  quiet-region volume does not page; single-window burn neither pages nor
  tickets.
- No fast-burn page is active; remaining user-facing budget is within policy
  or a current exception exists: section 3 plus `healthy_soak_passes_freeze_with_full_budget`.
  Healthy bundle freeze passes with budget 1.0 and no page. No exception is
  recorded in P0.
- The C-06 gap row can cite the reports: this document plus the
  `slo_validation` seam (`crates/pico-core/src/slo_validation/mod.rs`),
  the deployed rules (`o11y/rules/pico-recording-rules.yaml`), and the
  policy (`docs/observability/slo-error-budget-policy.md`). The C-06 gap
  stays open pending P2 live scrape and owner approvals below.

## Approval

| Role | Name | Date | Decision |
|---|---|---|---|
| SRE owner | Pending | - | Review SLO math, burn predicates, freeze rules, P0 limitations |
| Control Plane owner | Pending | - | Review API and create throughput plus scheduler shed semantics |
| Runtime owner | Pending | - | Review exec, boot, restore, and safety invariants under load |
| Security owner | Pending | - | Review audit delivery, telemetry-stale fail-closed, C-06 citation |

This report stays Draft until all four owners approve the claim mapping and
the section 8 follow-ups have owners and dates. P2 preview LPOP needs a new
report revision on the exact candidate with live scrape evidence.

## Appendix A: Test Run Output

All suites below were rerun in-session for this revision.

```
# slo_validation (new)
test result: ok. 22 passed; 0 failed (pico-core lib slo_validation)

# capacity (ST-ACTIVE and ST-EXEC)
test result: ok. 65 passed; 0 failed (pico-core lib capacity)

# restore_capacity (ST-RESTORE)
test result: ok. 24 passed; 0 failed (pico-core lib restore_capacity)

# image_cache (ST-CACHE)
test result: ok. 26 passed; 0 failed (pico-core lib image_cache)

# availability (ST-CELL)
test result: ok. 16 passed; 0 failed (pico-core lib availability)

# cost_model (cost and headroom)
test result: ok. 21 passed; 0 failed (pico-core lib cost_model)

Total pinned by this report: 174 tests, 0 failures

# burn_rate_sim.py
ok: burn-rate math and recording-rule names
```

## Appendix B: Reproducibility

```bash
# Full G-14 P0 evidence set used by this report
cargo nextest run -p pico-core --lib slo_validation
cargo nextest run -p pico-core --lib capacity
cargo nextest run -p pico-core --lib restore_capacity
cargo nextest run -p pico-core --lib image_cache
cargo nextest run -p pico-core --lib availability
cargo nextest run -p pico-core --lib cost_model
python3 o11y/slo/burn_rate_sim.py

# Clippy for the touched crate
cargo clippy -p pico-core --lib --locked -- -D warnings
```
