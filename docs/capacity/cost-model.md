# Cost and capacity plan

**Status**: P0 synthetic validation
**Normative strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Model**: `pico_core::cost_model`
**SLO policy**: [slo-error-budget-policy](../observability/slo-error-budget-policy.md)
**Dashboards**: `pico-scheduling-capacity`, `pico-snapshot-fork`,
`pico-image-cache`, `pico-slo-error-budget`

This plan is planning math over validation reports, not a launch proven
operating point. P0/P1 evidence never authorizes quotas: every rollout
limit in this file is `none` until P2 (preview) or P3 (beta/production).
Architecture 14.1 (10k RPS, 500k active, 50k creates/min) remains a
class-C design target until an LPOP reaches it.

## Inputs

| Input | Source | P0 status |
|---|---|---|
| Active density (`warning_max` per host) | `ActiveCapacityReport` | Synthetic, host scope |
| Sustainable concurrent restores per host | `RestorePressureReport` (ramp/soak only) | Synthetic |
| Cache bytes and warm hit rate | `ImageCacheReport` (thrash calibrates) | Uncalibrated lab default |
| Surviving cells/hosts after one loss | `CellAvailabilityReport` | Synthetic drill |
| Per-region demand (active, creates, execs, restores, audit, egress, snapshot bytes) | Caller | Assumption, not measured |
| Prices (host-hour, cell cache, snapshot storage, egress, audit) | Caller `PriceBook` | Lab example only |
| Workload mix | `MIX-AGENT-V1` default | Fixed shares |

`PriceBook::example_lab` is a lab-only example. Never use it for
procurement. Real prices come from finance/infra owners at review time.

## Outputs

| Output | Rule |
|---|---|
| Hosts per region | `ceil(target_active warning_max)` grown by stage headroom (50% preview, 25% beta/production) |
| Cells per region | At least the stage minimum (1/2/3), at most ~20 hosts per cell, grown until surviving hosts after one cell loss still cover pre-headroom demand |
| Cache sizing | Host-local and cell bytes from the image report; uncalibrated until a thrash report exists |
| Storage | `target_active x snapshot_bytes` per region plus cell cache; audit storage assumes 1 KiB/event over 30 days |
| Cost by workload class | Hosts plus storage allocated by mix share; egress to `WP-NET` (shared by mix share when `WP-NET` is absent); audit by mix share |
| Headroom and autoscaling | Target utilization is `1 - headroom`; add hosts when sustained active passes that line while keeping one-cell survival |
| Rollout limits | Each stage is sized from **that** stage's host plan (`warning_max x stage_hosts x (1 - stage headroom)`). Rate caps stay `none` while their axes are unmeasured. The current `PlanningInput.stage` only sizes `HostPlan`, not other stages' caps. |

## Lab worked example (unproven)

`PlanningInput::lab_p0_example` (Firecracker, `lab-64vcpu`, warning 32,
1,000 target active, preview stage):

| Output | Value |
|---|---|
| Hosts for active (pre-headroom) | 32 |
| Hosts per region (50% headroom) | 64 |
| Cells per region hosts per cell | 4 16 |
| Surviving hosts after one cell loss | 48 |
| Host-local cell cache | 5 GiB 20 GiB |
| Snapshot storage per region | ~244 GiB |
| Monthly hosts cost (example prices) | ~$70,080 |
| Confidence | Low |
| Rollout limits | `none` (P0 authorizes nothing) |

Production with the same density needs 43 hosts in 4 cells (25%
headroom) with 32 surviving hosts. These numbers move with the
sensitivity table below; they are not quotas.

## Sensitivity analysis (lab P0)

Swept by `default_sensitivity`. Host counts move with density and
demand; cost moves with all five variables.

| Variable | Low | Base | High | Hosts | Monthly cost direction |
|---|---|---|---|---|---|
| `warning_max_per_host` | 25.6 | 32 | 38.4 | 78 64 54 | Falls as density rises |
| `target_active` | 800 | 1000 | 1200 | 50 64 76 | Rises with demand |
| `snapshot_bytes_per_active` | 128 MiB | 256 MiB | 384 MiB | Unchanged | Rises (storage only) |
| `usd_per_host_hour` | $1.20 | $1.50 | $1.80 | Unchanged | Rises linearly |
| `egress_gb_per_month` | 500 | 1000 | 1500 | Unchanged | Rises (egress only) |

Density is the dominant variable: a 20% density miss moves the
footprint by ~25%. Do not publish quotas without P2+ density.

## Confidence and unknowns

P0 plans carry **Low** confidence. Standing unknowns (also in every
plan's `unknowns` list):

- Create throughput per host/cell (`S-RAMP-CREATE` not consumed).
- Exec concurrency per host (`S-RAMP-EXEC` LPOP not consumed; do not
  copy the active-count cap).
- Sustained restores/s per host (restore windows are untimed).
- Audit pipeline throughput and lag at LPOP (`ST-PIPE` not consumed;
  audit cost uses the demand assumption).
- Egress/DNS/port-forwarding capacity (`WP-NET` not load-validated).
- Cell packing (host-scope evidence only; the cell control plane knee
  is unproven until P2).
- Cache working set (uncalibrated until a thrash report exists).
- Audit event size (assumed 1 KiB; storage only, not correctness).

## Fail-closed rules

- P0/P1 evidence authorizes no rollout limit (`none` for every stage). The
  limiting (lowest) phase across density, restore, cache, and availability
  is what counts; P3 density with P0 restore still authorizes nothing.
- P2 across all four reports authorizes preview only; beta and production
  need P3 on all four.
- Each stage's `max_active` is computed from that stage's own host plan,
  not the caller's `PlanningInput.stage` fleet.
- `HostPlan.surviving_hosts_after_one_cell_loss` is proposed topology. A
  P2+ multi-cell drill whose `hosts_eligible_after_loss` is below
  pre-headroom demand sets `meets_one_cell_survival` false and emits
  `measured_survival_below_demand`.
- Exec-axis density reports size no hosts.
- Spike restore reports measure no sustainable concurrency (`report.scenario`).
- Cold/warm cache reports do not calibrate sizing (`report.scenario`).
- Non-production-eligible backends authorize no stage.
- Invalid prices clamp to zero with a class-A finding.
- Zero-region demand plans a 1-region equivalent, never zero hosts.

## How to fill this file from a real run

1. Run the harness to P2 (cell) or P3 (regional) under
   `MIX-AGENT-V1` for the exact deployment profile.
2. Feed the four reports into `MeasuredDensity::from_active_report`,
   `MeasuredRestore::from_restore_report`,
   `MeasuredImageCache::from_image_report`, and
   `MeasuredAvailability::from_availability_report`, plus reviewed
   demand and real prices.
3. Replace the worked example with `zones.warning_max`,
   surviving capacity, sizing, and cost from the JSON artifact. Record
   the plan digest.
4. Validate the plan against one full validation report, then compare
   the prediction with a second run via `compare_plans` and record
   `hosts_error_pct`.
5. Review assumptions with SRE and finance/infra owners before
   references the rollout limits.

## Follow-up gaps

- Load harness that drives live scenarios:

- Create/API/pipe throughput for rate-based sizing:

- Exec concurrency LPOP:
- Surviving-capacity evidence:

- Timed restore-rate evidence:

- Calibrated cache working set:

- Rollout checklist consumes these limits:
