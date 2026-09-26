# Host Quarantine

**Owner**: SRE-PicoCompute
**Alert category**: `host_quarantine`, `host_degradation`, `cleanup_drift`, `resource_pressure`
**Severity**: Page (critical) > Quarantine (warning) > Drain (info)
**Dashboards**: `pico-host-health`, `pico-scheduling-capacity`, `pico-cleanup-reconciliation`, `pico-lifecycle-operations`

## When to use

Any host is quarantined, quarantine alerts fire too fast, or unresolved
alerts sit past 30m. Also the drill path for boot non-ready that collapses
onto one host.

A quarantined host is excluded from scheduler placement. Existing workloads
stay until they exit or an approved drain.

## Alert conditions

| Alert | Severity | Trigger |
|---|---|---|
| PicoComputeHostQuarantined | warning | `pico_quarantine_hosts_quarantined > 0` for 1m |
| PicoComputeHostAlertFiringRateHigh | critical | `rate(pico_quarantine_alerts_fired_total[5m]) > 1` for 5m |
| PicoComputeHostUnresolvedAlerts | warning | `pico_quarantine_alerts_active > 5` for 30m |

All three link here (`o11y/rules/pico-recording-rules.yaml`).

In-process conditions (`AlertCondition`):

| Condition | Default severity | Threshold |
|---|---|---|
| `repeated_runtime_outcomes` | Page | 5 consecutive runtime failures |
| `cleanup_or_reconciliation_issue` | Quarantine | review/cleanup issue detected |
| `stale_resources` | Page | ambiguous leftovers |
| `capacity_reporting_staleness` | Quarantine | no capacity report for 120s |
| `resource_pressure` | Drain | CPU/memory/disk/slot >= 0.90 |

There is no quarantine dashboard JSON. Use host-health, scheduling-capacity,
and cleanup-reconciliation. Alerts auto-resolve when the condition is absent
for 120s. `acknowledge`/`resolve` exist on `AlertStateManager`; the approved
operator path is the ticket-gated helper in [Operator procedure](#operator-procedure-approved-helper) backed by `pico-core::operator`.

## First checks

1. Read alert labels: `host_id`, `cell_id`, `region`, `condition`,
   `severity`. Do not SSH.
2. `pico-host-health`: sandbox count, draining table, cgroup events.
3. `pico-scheduling-capacity`: is the host already out of
   **Hosts Evaluated vs Passed Constraints**?
4. `pico-lifecycle-operations`: `boot_not_ready`/exec `failed` /
   `timed_out` clustered on that host. Use `event` and `reason`, not
   `outcome="runtime_failed"` (that label is not implemented).
5. `pico-cleanup-reconciliation`: review-required, orphans, network
   health.
6. If many hosts fire at once, open the combined triage view in the runbook
   index before deciding audit vs runtime vs both, then suspect
   [audit-telemetry](audit-telemetry.md) or a bad rollout, not one kernel.

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | host_id="<host>"
{service_name="pico-host-agent"} | json | event="boot_not_ready"
```

Read-only host diagnostics (`journalctl -u pico-host-agent`, `dmesg`)
are allowed after telemetry, not before, and they are not mutation.

**Traces**

Failed `boot_sandbox`/`exec`/`destroy` on that `host_id`. Quarantine
itself is a host-health decision; it does not create a tenant trace.

**Audit**

`host_disabled`, `cleanup_disposition`, `runtime_outcome`,
`lifecycle_transition`. Keep evidence; do not delete local state to clear
the alert.

## Mitigation

### Repeated runtime outcomes (Page)

**Symptoms**: `boot_not_ready` with `reason=backend|protocol|timeout`,
cgroup OOM, guest handshake failures on one host.

**Mitigation**: Leave the host out of placement. If hardware or kernel is
suspected, approved drain then rebuild per [host-rebuild](host-rebuild.md)
with an infra ticket. If one image, follow
[image-cache](image-cache.md). If one backend, stop placing that backend.

**Escalation**: >2 hosts in the same cell in 30m: page SRE lead; consider
cell-level admission shed.

### Cleanup or reconciliation issue (Quarantine)

Follow [cleanup-reconciliation](cleanup-reconciliation.md). Default action
is stop deleting. Fenced cleanup is approved mutation only.

### Stale resources (Page)

Ambiguous ownership (fenced-out sandbox, expired lease, leftovers). Do not
`rm` cgroups or netns. Approved GC only with fencing-token evidence. If the
set spans hosts, page SRE lead.

### Capacity reporting staleness (Quarantine)

Inventory already dropped the host at 60s. Check [host-health](host-health.md)
and [audit-telemetry](audit-telemetry.md) before any restart. Approved
host-agent restart only; then wait 2m for capacity to reappear.

### Resource pressure (Drain)

Headroom <10%, placement evaluated high/passed low, `should_throttle`.
Prefer natural completion. `POST /rpc/v1/drain` on host-agent is mutation
(bearer-auth) and needs SRE approval. Do not raise overcommit.

## Operator procedure (approved helper)

Owner: SRE-PicoCompute with Runtime and Control Plane. This is the approved
in-process path for tabletop gap G-04. Validation lives in
`pico-core::operator`; the CLI in `pc operator ...` prints
ticket evidence but performs no in-process mutation except `drain`.

Acknowledge (keeps host out of placement, never clears a page without owner):

```
pc operator quarantine-ack --ticket INC-123 --host hst_01   --condition repeated_runtime_outcomes --owner sre-pico
```

Then call `AlertStateManager::acknowledge` in-process with the same ticket
and owner, and record both in the ticket. Owner is a team or person, never
blank.

Resolve (only when the condition is gone):

```
pc operator quarantine-resolve --ticket INC-123 --host hst_01   --condition stale_resources --condition-cleared
```

Without `--condition-cleared` the helper fails closed. Then call
`AlertStateManager::resolve` in-process only because the condition cleared
and the approved owner is re-admitting the host. Auto-resolve after 120s of
a cleared condition remains the default; manual resolve is the exception.

Drain (existing RPC with ticket evidence):

```
export PICO_HOST_TOKEN="<bearer-token>"
pc operator drain --host-url http://hst-01:8081 --ticket INC-123
pc operator drain-status --host-url http://hst-01:8081
```

Drain needs SRE on-call approval recorded in the ticket with sandbox count,
RPC time, and operator. Pass the bearer via `PICO_HOST_TOKEN` (exported)
rather than `--host-token` so the secret stays out of shell history and
process lists; the flag remains as an override. Watch `pico_host_draining`
and Active Sandbox Count per Host until the count reaches zero or the
approved window expires.

No undrain helper exists by design. A drained host returns only through the
re-admit gates below, never through an undrain RPC:

```
pc operator readmit-check --quarantine-gauge-zero --capacity-age-secs 12   --health ready --reconciliation-clean --watch-clean
```

Re-admit needs SRE on-call approval with quarantine gauge at 0, capacity age
under 60s, health `ready` or `degraded`, a clean reconciliation pass with
zero orphans and zero review-required, and a 5m watch with no new alert.
Any failing gate keeps the host quarantined and reopens the ticket.

Ledger inspect stays read-only; see
[cleanup-reconciliation](cleanup-reconciliation.md#operator-procedure-approved-helper)
for the allowlisted queries. Fenced cleanup needs fencing tokens; see the
same section.

## Escalation

- PicoComputeHostAlertFiringRateHigh: page SRE, then Observability if telemetry
  is the source.
- PicoComputeHostUnresolvedAlerts: page SRE if still true after the first
  mitigation pass.
- Never clear a page by acknowledging without a condition owner.

## Rollback

After the condition clears (or auto-resolves at 120s):

1. Host health is `healthy` or `degraded` (scheduler)/`ready` or
   `degraded` (host-agent).
2. Scheduler places again only in those states.
3. No new quarantine alert on that host within 5m.
4. `pico_quarantine_hosts_quarantined` returns to 0 for that host.

Do not call `AlertStateManager::resolve` just to restore capacity. Resolve
only when the condition is gone and an approved owner is re-admitting the
host.

## Host mutation

| Action | Approval |
|---|---|
| Read dashboards/logs/traces/audit | none |
| `journalctl`/`dmesg` | none (read-only, after telemetry) |
| `POST /rpc/v1/drain` | SRE on-call |
| Restart host-agent/sandboxd/metrics-agent | SRE on-call |
| Fenced cleanup/GC | SRE on-call + incident ticket |
| Rebuild host | SRE lead + infra (with Security for suspected escape) per [host-rebuild](host-rebuild.md) |

## Related

- Cell-wide combined triage view: [README](README.md#cell-wide-fire-with-audit-backlog---combined-triage-view)
- Drill rerun using that view: [cell-wide-fire-rerun-2026-09-21](drills/cell-wide-fire-rerun-2026-09-21.md)
- Operator rerun: [quarantine-fenced-cleanup-rerun-2026-09-21](drills/quarantine-fenced-cleanup-rerun-2026-09-21.md)
- Alert rules: `o11y/rules/pico-recording-rules.yaml`
- [host-health](host-health.md), [cleanup-reconciliation](cleanup-reconciliation.md),
  [lifecycle-operations](lifecycle-operations.md), [host-rebuild](host-rebuild.md)
- ADR-0009,
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
