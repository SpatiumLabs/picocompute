# Audit and Telemetry Pipeline

**Owner**: SRE-PicoCompute/Observability/Security
**Alert category**: `audit_delivery_failure`, `audit_integrity_gap`, `telemetry_delivery_failure`, `cardinality_overflow`
**Severity**: Page on audit loss, corruption, or required-signal staleness; ticket for lag under budget
**Dashboards**: `pico-audit-telemetry`, `pico-host-health`, `pico-slo-error-budget`

## When to use

Audit delivery rate/lag/outbox is wrong, hosts look dead because metrics
stopped, cardinality overflow, or a security-sensitive mutation was blocked
because audit could not be enqueued.

## Severity

| Condition | Level |
|---|---|
| Audit enqueue/delivery failure, dead-letter growth, sequence gap, corruption | Page SRE + Security |
| Required metrics/traces stale across a cell | Page Observability |
| Cardinality overflow/2,000-series cap hit | Page Observability; stop the rollout |
| Lag up, delivery still succeeding, mutations not blocked | Ticket |

## First checks

1. `pico-audit-telemetry` -> **Audit Delivery Rate**
   (`pico_audit_delivery_count`), **Audit Delivery Lag** p50/p95,
   **Audit Outbox Pending** (`pico_audit_outbox_pending`).
2. Are lifecycle dashboards empty while audit is healthy? Telemetry
   exporter/collector, not the fleet.
3. Are lifecycle dashboards healthy while audit is not? Fail closed on
   authoritative mutations; do not "fix" by disabling audit.
4. Cardinality: new label values on `pico_*` or `network_*` after a
   deploy.
5. Cell-wide fire with audit backlog: open the combined triage view in the
   runbook index plus `pico-scheduling-capacity` quarantine gauges and
   `pico-lifecycle-operations` plus `pico-cleanup-reconciliation`
   before deciding audit vs runtime vs both.

Do not purge the outbox. Do not replay dead-letters without Security.

## Logs, traces, audit

**Logs**

```
{service_name=~"pico-api|pico-host-agent"} | json | event=~"audit_.*"
```

**Traces**

Pipeline diagnostic spans only. Audit records themselves are not sampled
and are not traces.

**Audit**

`audit_delivery` events. Query gaps with `event_id`/HLC order. Dead-letter
table `audit_events_dead_letter` is evidence, not trash.

## Mitigation

1. Delivery failure: block affected security-sensitive mutations (already
   required by ADR-0009). Page Security. Do not acknowledge creates that
   lack durable enqueue.
2. Host outbox unavailable: host becomes `degraded` or `unsafe`. Leave it
   out of placement ([host-health](host-health.md)).
3. Telemetry stale: do not quarantine the whole cell until collector
   gateway health is checked. If only scrape is down, placement may still
   be valid.
4. Cardinality overflow: revert the instrumentation change. Do not raise
   the cap during the incident.

## Escalation

- Security owns integrity gaps and unauthorized replay.
- Observability owns exporter, collector, and cardinality.
- SRE owns host outbox disk and placement impact.

## Rollback

1. Restore the previous collector/exporter/instrumentation revision.
2. Confirm delivery rate, lag, and outbox pending return to baseline.
3. Replay dead-letters only with a reviewed disposition; never delete the
   source outbox row.

## Related

- Cell-wide combined triage view: [README](README.md#cell-wide-fire-with-audit-backlog---combined-triage-view)
- Drill rerun using that view: [cell-wide-fire-rerun-2026-09-21](drills/cell-wide-fire-rerun-2026-09-21.md)
- [host-health](host-health.md)
- [control-plane](control-plane.md)
- ADR-0009 audit and telemetry sections
- audit pipeline
