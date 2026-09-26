# Host Health

**Owner**: SRE-PicoCompute
**Alert category**: `host_degradation`, `resource_pressure`, `telemetry_delivery_failure`
**Severity**: Quarantine for stale/unavailable; drain for pressure; page if a cell is dark
**Dashboards**: `pico-host-health`, `pico-scheduling-capacity`, `pico-cleanup-reconciliation`

## When to use

Host-agent is down, capacity reports are stale, the host is draining, or
cgroup pressure (OOM, memory high, CPU throttle) is clustered on a host.

## Severity

| Condition | Level |
|---|---|
| Host missing from placement >60s, quarantine after 120s | Quarantine |
| >20% of cell hosts stale or draining | Page |
| Cgroup OOM/memory-high clustered on one host | Drain, then [host-quarantine](host-quarantine.md) |
| Single draining host with healthy cell capacity | Ticket |

## First checks

1. `pico-host-health` -> **Active Sandbox Count per Host**. A missing
   series is stale telemetry, not zero load.
2. **Draining Hosts** table: `pico_host_draining > 0`.
3. **Cgroup Event Rates**: `pico_cgroup_oom_events_total`,
   `pico_cgroup_memory_high_events_total`,
   `pico_cgroup_cpu_throttled_total`, `pico_cgroup_setup_errors_total`.
4. **Cgroup Memory Pressure by Host** and **Memory Pressure Read Errors**.
5. `pico-scheduling-capacity`: if evaluated hosts drop, inventory expired
   (60s). Confirm quarantine gauges only after 120s.
6. `pico-audit-telemetry`: exporter/outbox failure can look like a dead
   host. Check that first if many hosts vanish together.

Host-agent health vocabulary: `ready`, `degraded`, `draining`, `unsafe`.
Scheduler vocabulary: `healthy`, `degraded`, `draining`,
`disabled_for_placement`, `unavailable`, `quarantined`. Only `healthy` and
`degraded` admit new work.

Do not SSH yet. Do not `systemctl restart` host-agent as a first check.

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | host_id="<host>"
```

If the stream itself stops, the agent or the collector is down. Check
`pico-metrics-agent` and OTLP gateway freshness on
[audit-telemetry](audit-telemetry.md).

**Traces**

In-flight `host_agent_rpc` spans ending in error or missing children after
`create`. A total absence of new spans from one `host_id` is unavailability.

**Audit**

`host_disabled`, `cleanup_disposition`, `lifecycle_transition` on that host.
No new audit from a host while the outbox is healthy elsewhere means the
agent is not running.

## Mitigation

1. Stale one host: leave it out of placement. Do not force it back.
2. Stale many hosts: suspect the telemetry pipeline, not the fleet. Follow
   [audit-telemetry](audit-telemetry.md) before touching agents.
3. Pressure: stop new placement (already true if health is not
   `healthy`/`degraded`). Let sandboxes finish. Drain RPC only with approval
   per [host-rebuild](host-rebuild.md).
4. OOM cluster: treat as [host-quarantine](host-quarantine.md)
   `repeated_runtime_outcomes`/`resource_pressure`.
5. Approved restart of `pico-host-agent` is host mutation. After restart,
   wait for capacity to reappear on **Hosts Evaluated** within 2m.

## Escalation

- Page SRE if a cell cannot place and host series are missing.
- Page Observability if audit/metrics pipelines are also stale.
- Page Runtime if cgroup setup errors follow a kernel or runtime rollout.
- Infra if hardware pressure (memory/disk) is host-local and persistent.

## Rollback

1. After an approved drain: host stays draining until sandbox count is 0 or
   SRE un-drains via the control path. There is no un-drain in the public
   CLI. Full rebuild re-admit follows [host-rebuild](host-rebuild.md).
2. After an approved agent restart: confirm health `ready` or `degraded`,
   capacity <60s old, and no new quarantine alert within 5m.
3. Do not clear cgroup pressure with manual `echo` to cgroup files.

## Related

- [host-quarantine](host-quarantine.md)
- [scheduling-capacity](scheduling-capacity.md)
- [audit-telemetry](audit-telemetry.md)
- [host-rebuild](host-rebuild.md)
- [cgroup metrics](../observability/cgroup-metrics.md)
