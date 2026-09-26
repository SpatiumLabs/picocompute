# Cgroup v2 Memory Pressure and Event Metrics

**Status**: Implemented
**Related**: [SC-02 side-channel assessment](../security/side-channel-assessment.md#sc-02-memory-pressure-and-page-cache-contention)

## Overview

The host-agent polls the cgroup v2 `memory.pressure`, `memory.events`, and
`cpu.stat` interfaces for each active sandbox and exposes host-level
aggregate series. This provides operators with visibility into memory
contention, OOM kills, memory-high throttling, and CPU throttling without
exposing per-sandbox values to tenants.

## Metrics

| Instrument | Type | Description |
|---|---|---|
| `pico_cgroup_memory_pressure` | Gauge | Maximum `memory.pressure` `some avg10` value across all active sandbox cgroups. Range 0.0 (no pressure) to 100.0 (full stall). |
| `pico_cgroup_oom_events_total` | Counter | Summed delta of `memory.events` `oom_kill` across all sandboxes since the previous poll. |
| `pico_cgroup_memory_high_events_total` | Counter | Summed delta of `memory.events` `high` across all sandboxes since the previous poll. |
| `pico_cgroup_cpu_throttled_total` | Counter | Summed delta of `cpu.stat` `nr_throttled` across all sandboxes since the previous poll. |
| `pico_cgroup_memory_pressure_read_errors_total` | Counter | Count of `memory.pressure` read/parse failures per poll. |

All series are host-level aggregates - they never expose per-sandbox
values. This avoids the cross-tenant inference concern documented in SC-02.

## Polling

The host-agent reads `memory.pressure`, `memory.events`, and `cpu.stat` for
every active sandbox every 30 seconds. The gauge is set to the maximum
`some avg10` value observed. If no sandboxes are present or the cgroup v2
filesystem is not mounted, the gauge reads 0.0.

Event counters diff cumulative kernel counters against the previous poll:

- `oom_kill` from `memory.events` feeds `pico_cgroup_oom_events_total`.
- `high` from `memory.events` feeds
  `pico_cgroup_memory_high_events_total`.
- `nr_throttled` from `cpu.stat` feeds `pico_cgroup_cpu_throttled_total`.

The first observation of a cgroup establishes a baseline with zero delta,
so host restarts do not spike totals with pre-existing counts. A counter
reset (current below baseline after cgroup recreation) emits current as the
delta. Missing or malformed `memory.events`/`cpu.stat` reads are skipped
without emitting a delta; the previous baseline is kept so the next good
poll diffs correctly. Baselines for removed cgroups are pruned each poll.

## Interpreting the value

| Range | Meaning | Suggested action |
|---|---|---|
| **0--5** | Normal light contention | Healthy |
| **5--15** | Noticeable pressure | Investigate workload or limits |
| **15--30** | Elevated | Consider scaling or rebalancing |
| **30--50** | High pressure | Strong signal to act (drain, shed) |
| **>50** | Severe thrashing | Critical - risk of OOM or stalls |

 maps these onto density zones: <15 safe, 15-30 warning (LPOP cap),
>=30 saturation. See
[active-sandbox-defaults](../capacity/active-sandbox-defaults.md).

## Alerting guidance

| Alert | Condition | Severity | Action |
|---|---|---|---|
| `resource_pressure` | `pico_cgroup_memory_pressure > 30` for 5m | Warning | Consider scaling, rebalancing, or shedding load |
| `resource_pressure` | `pico_cgroup_memory_pressure > 50` for 2m | Critical | Stop placement on host, drain existing sandboxes - risk of OOM |

See [ADR-0009 alert categories](../adr/0009-observability-and-reliability-signals.md#alert-categories-and-operational-action)
for the `resource_pressure` alert classification.

## Implementation

- cgroup reading: `crates/pico-host-agent/src/cgroups.rs`
- metric registration: `crates/pico-host-agent/src/metrics.rs`
- polling loop: `HostAgent::spawn_memory_pressure_poller` in
  `crates/pico-host-agent/src/lib.rs`
