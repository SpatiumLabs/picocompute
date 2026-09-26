# Scheduling and Capacity

**Owner**: SRE-PicoCompute
**Alert category**: `capacity_exhaustion`, `host_degradation`
**Severity**: Page when a cell cannot place; drain/quarantine for one host; ticket for efficiency drift
**Dashboards**: `pico-scheduling-capacity`, `pico-host-health`, `pico-control-plane`, `pico-cleanup-reconciliation`

## When to use

Creates fail with no host, insufficient capacity, all hosts draining, or
pressure saturation. Also use for stale capacity: hosts disappear from
placement before boot starts.

## Severity

| Condition | Level |
|---|---|
| Cell `NoHostsAvailable`/`InsufficientCapacity`/`AllHostsDraining`/`PressureSaturated` or `PicoComputeCellCannotPlace` | Page |
| One host missing from inventory (60s TTL) | Quarantine after 120s ([host-health](host-health.md)) |
| Placement efficiency low but creates still succeed | Ticket |
| >20% of hosts in a cell missing capacity reports | Page |

## First checks

1. `pico-scheduling-capacity` -> **Placement Latency**, **Active
   Sandbox Count per Host**, **Host Memory Pressure** (15 30 zone
   lines), **Hosts Quarantined**, and **Orphan Reconcile**.
2. **Placement Efficiency Ratio**:
   `passed_constraints/evaluated`. A collapse with high evaluated count is
   constraint/pressure. A collapse with low evaluated count is inventory
   loss (stale host-agent).
3. `pico-control-plane` **Admission & Auth Rates**: `create_failed` plus
   audit `placement_outcome`.
4. `pico-host-health` **Draining Hosts** (`pico_host_draining > 0`) and
   **Active Sandbox Count per Host**.
5. Distinguish:

   | Evidence | Cause |
   |---|---|
   | Evaluated ~ 0 | Host-agent/inventory stale ([host-health](host-health.md)) |
   | Evaluated high, passed ~ 0, draining table full | Intentional drain |
   | Evaluated high, passed ~ 0, cgroup pressure up | [host-quarantine](host-quarantine.md) `resource_pressure` |
   | Passed > 0 but boot `reason=resource` | Host accepted then failed allocation |

Active density zones use the same pressure series:

| Zone | Memory pressure | Utilization | Operator action |
|---|---|---|---|
| Safe | < 15 | < 0.75 | Normal placement |
| Warning (LPOP cap) | 15-30 | 0.75-0.90 | Shed toward warning-max; do not raise overcommit |
| Saturation | >= 30 | >= 0.90 | Stop new placement. Isolation/cleanup breaks are class-A |

P0 packing on the lab 64-vCPU SKU advertises **32** default-shape sandboxes
(vCPU-bound). The P0 packing fixture uses 100 process slots, which still
leaves vCPU as the binding resource; the host default is 1000 slots, so
vCPU binds there too. Measured zones:
[active-sandbox-defaults](../capacity/active-sandbox-defaults.md).

Cell/host unavailability: unavailable cells never receive new
placements; running sandboxes stay until fence or approved drain. Treat
`schedule` `Err` as shed. Do not retry. See
[cell-unavailability](../capacity/cell-unavailability.md).

Scheduler inventory TTL is **60s**. Quarantine staleness is **120s**. A host
can fail placement for a minute without a quarantine alert.

Do not SSH. Do not add capacity by starting extra VMMs on a packed host.

## Host capacity signals

`/rpc/v1/inventory` reports boot totals plus a live scheduler snapshot:
`total_vcpus`, `total_memory_mb`, and `total_disk_mb` come from boot
detection; `allocated_vcpus` and `allocated_memory_mb` sum live sandbox
requests; `used_disk_mb` is live count x 1024 MB per sandbox (the same
assumption the placement gate uses, since specs carry no disk field);
each sandbox uses one of 1000 process slots; network reports 10 Gbps total
with zero allocated until per-sandbox bandwidth accounting exists.
`/rpc/v1/stats` carries the same `capacity` and `pressure` plus per-resource
`utilization` in 0.0-1.0 and `in_flight_creates`/`in_flight_restores` from
the create/restore counters. Boot admission checks requested plus other
residents against totals, so a second sandbox fails closed when the live sum
no longer fits.

OTel gauges (Prometheus translates dots to underscores):

- `pico.host.cpu.capacity{state="total"|"allocated"}` - counts
- `pico.host.memory.capacity{state="total"|"allocated"}` - bytes
- `pico.host.sandbox.capacity{state="total"|"used"}` - process slots
- `pico.host.resource.utilization{resource="cpu"|"memory"|"disk"|"network"|"process_slots"}` - 0.0-1.0
- `pico.host.health{health_state="healthy"|"degraded"|"draining"|"disabled_for_placement"|"unavailable"|"quarantined"}` - 1.0 for the active state

All are host-level aggregates with bounded labels only. Host identity comes
from scrape/resource attributes, never from tenant or sandbox labels.

## Logs, traces, audit

**Logs**

```
{service_name="pico-api"} | json | reason=~"no_capacity|assignment_stale|host_degraded|host_draining|host_unsafe"
```

**Traces**

`create` span with `outcome=placement_failed`. No `host_agent_rpc` child
means the scheduler never assigned a host.

**Audit**

`placement_outcome` reasons include `best_score`, `only_candidate`,
`cache_hit`, `failure_domain_spread`, `no_cell_available`,
`no_host_available`. Rejection categories: `unavailable`, `draining`,
`disabled_for_placement`, `insufficient_capacity`, `unsupported_runtime`,
`pressure_saturated`.

## Mitigation

1. Cell full: stop new non-essential creates (admission shed, Control Plane
   approval). Do not pack draining hosts.
2. Stale inventory: follow [host-health](host-health.md). The host is already
   out of placement after 60s.
3. Pressure: allow natural drain. `POST /rpc/v1/drain` only with SRE
   approval, and only on the affected host.
4. Unsupported runtime: fail those creates; do not silently select a weaker
   backend.
5. Do not raise overcommit during an incident.

## Escalation

- Page SRE if a cell rejects creates for 10m.
- Page infra if the cell needs more hosts.
- Page Runtime if `unsupported_runtime` follows a backend rollout.
- Jump to [host-quarantine](host-quarantine.md) when quarantine gauges move.

## Rollback

1. Restore admission limits after passed-constraint count and create success
   recover for 15m.
2. Re-enable a drained host only when `pico_host_draining` is 0, health is
   `Healthy` or `Degraded`, and capacity reports are fresh (<60s). Full
   rebuild re-admit follows [host-rebuild](host-rebuild.md) with the 5m
   no-requarantine watch.
3. Never resolve quarantine to recover capacity.

## Related

- [host-health](host-health.md), [host-quarantine](host-quarantine.md),
  [host-rebuild](host-rebuild.md), [control-plane](control-plane.md)
- [active sandbox defaults](../capacity/active-sandbox-defaults.md),
  [cell unavailability](../capacity/cell-unavailability.md)
