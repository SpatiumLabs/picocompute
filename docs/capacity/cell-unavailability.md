# Cell unavailability and recovery

**Status**: P0 synthetic validation
**Normative strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Model**: `pico_core::availability`
**Dashboards**: `pico-scheduling-capacity`, `pico-host-health`,
`pico-control-plane`, `pico-cleanup-reconciliation`,
`pico-audit-telemetry`
**Alerts**: `PicoComputeHostQuarantined`, `PicoComputeCellCannotPlace`

These results are scheduler-snapshot drills, not a launch proven operating
point. P0/P1 must not set regional quotas. Surviving capacity after one
cell loss is a candidate input to, not a published LPOP.

## Existing sandbox behavior

Regional and cell schedulers decide **new** placement only. They do not
migrate, fence, or destroy running sandboxes.

| Domain state | New placement | Running sandboxes |
|---|---|---|
| `Healthy`/`Degraded` | Admit | Unchanged by `schedule` |
| `Draining`/`Unavailable`/`Quarantined`/`DisabledForPlacement` | Reject | Stay until they exit, an approved host drain, or host-agent fence |
| Host missing from inventory (60s TTL) | Host is not a candidate | Same as above; quarantine alert at 120s |

Degraded cell control path still admits. Total cell loss returns
`SchedulerError`; callers must shed, not retry. `should_throttle` is the
shed signal when some candidates remain but admission rate is below 0.15
or average headroom is below 0.10. Two-cell failover (one remaining) does
not throttle on admission rate (0.50 > 0.15) and must keep placing on the
survivor.

## Scenario results (P0)

| ID | Drill | P0 result |
|---|---|---|
| S-FAIL-CELL | Mark one cell `Unavailable` | New placements never select it. Survivor takes the load. Existing count on the failed cell is unchanged. |
| S-FAIL-HOST | Mark one host `Unavailable`, or expire inventory then quarantine | New placements skip the host. Existing count unchanged. Stale hosts vanish at 60s; `CapacityReportingStaleness` fires at 120s. Apply `HostHealth::with_quarantine` before `CellScheduler::schedule`. |
| S-RECOVER | Restore `Healthy` | Placements resume on the restored domain without rewriting host inventory by hand. Audit/telemetry backlog drain is not measured (class-C). |

Class-A failures in this model: placement onto the failed domain, split
brain, existing sandbox count changing without fence, admits with zero
eligible cells/hosts, retries after reject without honoring shed.

## Observability

| Channel | What to watch |
|---|---|
| Dashboard | `pico-scheduling-capacity` placement efficiency, quarantined hosts, GC orphans |
| Alert | `PicoComputeCellCannotPlace` (evaluated hosts, zero passed, 5m), `PicoComputeHostQuarantined` |
| Trace | `create` span `outcome=placement_failed` with no `host_agent_rpc` child |
| Audit | `placement_outcome` on both admit and reject (`no_cell_available`/`no_host_available`) |

P0 does not scrape Grafana. Named evidence must still appear on the report.

## How to fill this file from a real run

1. Run S-FAIL-HOST, S-FAIL-CELL, and S-RECOVER through the harness
   against a production-shaped cell (P2) under MIX-AGENT-V1.
2. Feed observations into `analyze_cell_availability`. Keep
   `proposed_lpop = none` until P2+ and only then as surviving-capacity
   input, never as a density quota.
3. Replace the table with artifact digest, surviving eligible cells/hosts,
   and class-A/B/C findings.
4. Never extrapolate one-cell loss to a regional LPOP.

## Follow-up gaps

- Load harness that drives live S-FAIL-*/S-RECOVER:

- Wire schedulers into API create admission:

- Host-agent fencing and orphan reconcile after cell/host loss remain
  unmeasured (class-C in P0). Needed before public-beta S-FAIL-CELL.
- `AlertStateManager` is not consulted inside `CellScheduler`; callers must
  apply `HostHealth::with_quarantine`.
- Failed `schedule` emits `placement_outcome`. Cell scheduler records
  evaluated/passed histograms on reject (empty inventory is audit-only,
  evaluated ~ 0).
- Total-loss path returns `Err` with no `BackpressureSignal`. Treat any
  `Err` as shed.
- Cost model consumes surviving capacity:
