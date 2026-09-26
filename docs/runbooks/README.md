# Operational Runbooks

**Owner**: SRE-PicoCompute
**Contract**: [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
**Dashboards**: `o11y/*.json` (Grafana folder `PicoCompute`)

These runbooks are the operational response for PicoCompute lifecycle and
infrastructure failures. Dashboards and alerts are not enough; each failure
mode has a linked runbook with severity, first checks, mitigation,
escalation, and rollback.

## Coverage

| Failure mode | Runbook | Alert category |
|---|---|---|
| Create or schedule issues | [control-plane](control-plane.md), [scheduling-capacity](scheduling-capacity.md), [lifecycle-operations](lifecycle-operations.md) | `regional_lifecycle_failure`, `capacity_exhaustion` |
| Host-agent unavailable or stale capacity | [host-health](host-health.md), [scheduling-capacity](scheduling-capacity.md) | `host_degradation`, `telemetry_delivery_failure` |
| Boot non-ready (image, network, runtime, guest-agent) | [lifecycle-operations](lifecycle-operations.md), [image-cache](image-cache.md), [networking](networking.md), [runtime-backend](runtime-backend.md) | `regional_lifecycle_failure` |
| Exec timeout or stuck command | [lifecycle-operations](lifecycle-operations.md) | `regional_lifecycle_failure` |
| Snapshot restore or fork | [snapshot-fork](snapshot-fork.md) | `regional_lifecycle_failure`, `capacity_exhaustion` |
| Network policy and DNS | [networking](networking.md), [dns](dns.md) | `security_event`, `regional_lifecycle_failure` |
| Cleanup/reconciliation and host quarantine | [cleanup-reconciliation](cleanup-reconciliation.md), [host-quarantine](host-quarantine.md) | `cleanup_drift`, `host_quarantine`, `resource_pressure` |
| Host rebuild after quarantine or residual authority | [host-rebuild](host-rebuild.md) | `host_quarantine`, `cleanup_drift`, `resource_pressure` |
| Audit or telemetry pipeline | [audit-telemetry](audit-telemetry.md) | `audit_delivery_failure`, `audit_integrity_gap`, `telemetry_delivery_failure`, `cardinality_overflow` |
| SLO burn | [slo-error-budget](slo-error-budget.md) | `slo_burn` |

Numeric SLO targets, freeze rules, and burn alerts are
[slo-error-budget-policy](../observability/slo-error-budget-policy.md)
.
Use the SLO runbook only for first response, then jump to the owning failure mode.

## Required sections

Every runbook defines:

1. **Severity** - page, quarantine, drain, or ticket
2. **First checks** - dashboards and aggregate metrics before any host access
3. **Mitigation** - stop the blast radius without guessing
4. **Escalation** - when to page the next owner
5. **Rollback** - how to undo the mitigation

## Host mutation policy

Runbooks do **not** require direct host mutation. Diagnose from dashboards,
platform logs, traces, and audit events first.

| Class | Allowed without extra approval | Requires on-call SRE approval |
|---|---|---|
| Read telemetry | Grafana, Loki, Tempo, audit query | Protected tenant/sandbox pivot |
| Placement | Wait for scheduler exclusion (`Healthy`/`Degraded` only admit) | `pc operator drain` to the existing `POST /rpc/v1/drain` with ticket evidence |
| Quarantine | Let `AlertStateManager` auto-resolve after 120s of a cleared condition | Manual `acknowledge`/`resolve` via `pc operator quarantine-ack`/`quarantine-resolve` checks plus in-process call with ticket and owner |
| Process | None | Restart `pico-host-agent`, `sandboxd`, or `pico-metrics-agent` |
| Cleanup | None | Fenced cleanup via `pc operator fenced-cleanup` with ticket plus fencing tokens; ledger inspect via `pc operator ledger-inspect` (read-only queries only) |
| Rebuild | None | Cordon, drain, rebuild, re-admit per [host-rebuild](host-rebuild.md) (SRE lead and infra, with Security for suspected escape) |

**Prohibited without a reviewed incident ticket:**

- editing the sandboxd ledger by hand
- killing guest processes or VMMs outside drain/destroy
- deleting cgroups, netns, taps, or workspaces without fencing tokens
- replaying audit dead-letters without Security review
- attaching high-cardinality tenant or sandbox labels to metrics

SSH/`dmesg`/`journalctl` are read-only diagnostics. They are not first checks
and they are not a substitute for drain, quarantine, or fenced cleanup.

## Signal lookup

### Dashboards

Grafana folder `PicoCompute`. Filter every panel by `region` and `cell` before
acting. Dashboards do not expose tenant or sandbox dimensions.

| UID | File |
|---|---|
| `pico-control-plane` | `o11y/control-plane.json` |
| `pico-lifecycle-operations` | `o11y/lifecycle-operations.json` |
| `pico-scheduling-capacity` | `o11y/scheduling-capacity.json` |
| `pico-host-health` | `o11y/host-health.json` |
| `pico-runtime-backend` | `o11y/runtime-backend.json` |
| `pico-image-cache` | `o11y/image-cache.json` |
| `pico-networking` | `o11y/networking.json` |
| `pico-dns` | `o11y/dns.json` |
| `pico-snapshot-fork` | `o11y/snapshot-fork.json` |
| `pico-cleanup-reconciliation` | `o11y/cleanup-reconciliation.json` |
| `pico-audit-telemetry` | `o11y/audit-telemetry.json` |
| `pico-slo-error-budget` | `o11y/slo-error-budget.json` |

Metric names are OTel in the code and Prometheus in the dashboards. The full
mapping, which series each backend reads, and which series have no consumer at
all, is in [observability/metric-naming.md](../observability/metric-naming.md).

### Metrics vs ADR taxonomy

Dashboards and recording rules use Prometheus names. Boot and exec labels are
the **implemented** `event`/`reason` values, not ADR-0009 `outcome` strings.

| Signal | Implemented labels |
|---|---|
| Create | `pico_create_events_total{event="create_started\|create_completed\|create_failed"}` |
| Boot | `pico_boot_events_total{event="boot_start\|boot_ready\|boot_not_ready\|boot_cleanup", reason="image\|network\|resource\|backend\|protocol\|timeout\|cleanup"}` |
| Exec | `pico_exec_events_total{event="exec_started\|succeeded\|failed\|canceled\|timed_out\|not_completed"}` |
| Placement | `pico_placement_latency_seconds`, `pico_placement_hosts_evaluated`, `pico_placement_hosts_passed_constraints` |
| Quarantine | `pico_quarantine_hosts_quarantined`, `pico_quarantine_alerts_active`, `pico_quarantine_alerts_fired_total` |
| Image cache | `pico_image_prepare_latency_seconds` (`status`, `cache_result="unknown"`, `image_profile="unknown"`) live from the prepare path; `pico_image_cache_hits`/`misses`/`evictions` (`tier`) and verify/overlay histograms pending host image cache (BSD-184). Hit-filtered rules stay empty so `PicoComputeImageCacheHitRateLow` and `PicoComputeImagePrepareSaturated` cannot fire on fabricated ratios. |

Scheduler inventory drops a host after **60s** without a capacity report.
Quarantine `capacity_reporting_staleness` fires after **120s**.

### Logs

Platform logs use `target = "pico_platform_log"` and the `LogRecord` fields
in `pico-telemetry`. Query by `event`, then pivot on `operation_id`,
`trace_id`, `host_id`, `cell_id`, and `region`.

```
{service_name="pico-host-agent"} | json | event="boot_not_ready"
```

Diagnostic `tracing` events may include a `diagnostics` field. They are not
the terminal record. Terminal non-success operations emit ERROR platform logs.

Never search logs for commands, credentials, paths, or workload output. Those
fields are redacted at source.

### Traces

1. Copy `trace_id` from the platform log or audit event.
2. Open Tempo/Jaeger and search that W3C trace ID.
3. Implemented span names: `request`, `create`, `host_agent_rpc`,
   `create_sandbox`, `prepare_sandbox`, `boot_sandbox`, `exec`, `suspend`,
   `resume`, `restore_from_snapshot`, `destroy`, `prepare`, `boot`,
   `provision`, `build`.

Failed, timed-out, and rejected traces are the diagnostic path. Successful
traces may be sampled.

See [distributed tracing](../observability/distributed-tracing.md).

### Audit

Query the durable audit store (not logs) with `event_kind`, `operation_id`,
`trace_id`, `sandbox_id`, or `lease_id`. Relevant kinds:

| Kind | Use |
|---|---|
| `lifecycle_transition` | state changes |
| `placement_outcome` | schedule/create |
| `quota_rejection`/`policy_decision` | admission |
| `runtime_outcome` | prepare/start/stop |
| `network_enforcement` | DNS/egress/port-forward |
| `snapshot_operation` | restore/fork/integrity |
| `cleanup_disposition` | GC/quarantine/reconcile |
| `host_disabled` | placement disable |
| `audit_delivery` | pipeline health |

Audit events are unsampled. A gap, dead-letter, or sequence hole is itself an
incident ([audit-telemetry](audit-telemetry.md)).

## Severity

| Level | Meaning | Typical action |
|---|---|---|
| Page | User-visible or safety-critical now | Page SRE-PicoCompute; stop placement if a host or cell is unsafe |
| Quarantine | Host must not receive new work | Confirm scheduler exclusion; do not mutate the host |
| Drain | Host is over pressure or being emptied | Prefer natural drain; `POST /rpc/v1/drain` only with approval |
| Ticket | Elevated error rate, budget burn, or single-tenant impact | File to the owning team; watch SLO burn |

## Tenant notification

**Owner**: SRE-PicoCompute with Product and Security
**Applies to**: revoke, isolate, quarantine, drain, rebuild, and rollback cases with user-visible impact

Owner paging per each runbook Escalation section is not tenant notice.
Dashboards never carry tenant/sandbox dimensions by design, so tenant notice
uses a direct tenant channel, never metrics or dashboard links with tenant
identity.

### Triggers

Notify the affected tenant owner when any of these holds. Otherwise owner
paging plus the incident ticket is enough.

| Case | Notify tenant when | Owner-only when |
|---|---|---|
| Revoke credential/lease | Any lease for that tenant was revoked or rotated, or a broker denial blocks that tenant | Denial with no tenant impact beyond a rejected call |
| Isolate network namespace or revoke egress lease | That tenant loses an egress, DNS, or port-forward path, or a policy change blocks that tenant | Blocked probe with no admitted workload affected |
| Quarantine host | That tenant has sandboxes on the quarantined host and drain/rebuild may affect them | Placement exclusion with no admitted workload on the host |
| Drain host | That tenant has sandboxes on the draining host | Draining host with no tenant workload |
| Rebuild host | That tenant had sandboxes on the rebuilt host, or re-placement changes behavior | Rebuild of an empty host |
| Rollback digest/policy/rollout/restore | That tenant was on the rolled-back version, policy, or snapshot path | Rollback with no admitted workload on the affected path |

### Timing

- Initial tenant notice within 60m of confirmed user-visible impact.
- Update on mitigation change, rollback, re-admit, or at least every 4h
  during ongoing impact.
- Close notice with recovery confirmation and the re-admit checks that passed.
- Owner paging follows the owning runbook immediately and does not wait for
  tenant-notice timing.

### Template

Copy this template for each affected tenant. Send one notice per tenant with
only that tenant scope. Never include another tenant identity.

```
Subject: [PicoCompute] <revoke/isolate/quarantine/drain/rebuild/rollback> notice for <tenant> in <region>/<cell>
Incident: <incident-ticket>
Date: <YYYY-MM-DD> Revision: <source-revision>
Scope (this tenant only): <operation-id/lease-id/sandbox-count/snapshot-id where applicable>
User-visible impact: <what the tenant sees: failed create/boot/exec, lost network path, delayed placement>
Action taken: <revoked leases, isolated namespace, quarantined host, approved drain, rebuild, rollback to known-good>
Tenant action: <rotate downstream credential, retry with backoff, re-deploy pinned digest, no action>
Next update: <time or state-change trigger>
Contact: <owning team plus incident ticket>
Audit refs: <LeaseRevoked/network_enforcement/host_disabled/cleanup_disposition/snapshot_operation/lifecycle_transition event IDs>
```

### Prohibited content

Never include secrets, tokens, boot secrets, or lease bearer material.
Never include commands, arguments, paths, workload output, or raw errors.
Never include another tenant identity, sandbox identity from another tenant,
image registry credentials, or snapshot blob locations. Use typed reason
codes from the signal contract instead of raw strings.

### Audit record

Record each notice in the incident ticket with send time, recipient class,
template fields, and the underlying audit event IDs for the action taken.
Do not attach tenant/sandbox labels to metrics. Query the durable audit
store by `event_kind` with `operation_id`, `trace_id`, `sandbox_id`, or
`lease_id` for the recovery evidence. Dead-letter replay needs Security
review and never deletes the source outbox row.

Worked example using this template is in
[drills/tenant-notification-rerun-2026-09-21](drills/tenant-notification-rerun-2026-09-21.md).

## Cell-wide fire with audit backlog - combined triage view

**Owner**: Observability with SRE
**Applies to**: cell-wide quarantine fire plus audit outbox backlog (tabletop gap G-03, scenario 4)
**Dashboards in fixed order**: `pico-scheduling-capacity`, `pico-audit-telemetry`, `pico-lifecycle-operations`, `pico-cleanup-reconciliation`, `pico-host-health`

The owning runbooks correctly split audit-telemetry vs runtime. This section
is the joint pointer the facilitator opens first so both sides are read
together with one `region` plus `cell` filter. Filter every panel by `region`
and `cell` before acting. Dashboards never carry tenant or sandbox dimensions.

### When to use

Open this view when any of these hold:

- `PicoComputeHostAlertFiringRateHigh` is firing, or 2 or more hosts in one cell
  quarantine within 30m.
- `pico_quarantine_hosts_quarantined` is greater than 0 on more than one
  host while `pico_audit_outbox_pending` is climbing.
- `pico_gc_review_required` or `network_reconciliation_review_required`
  is active during a multi-host quarantine.
- Lifecycle dashboards look empty or cell-wide degraded at the same time as
  audit lag grows.

For a single bad host with healthy audit, stay on
[host-quarantine](host-quarantine.md) first checks instead.

### Panel order

Read top to bottom without skipping. Record the value at each step before
moving on.

| Order | Dashboard - panel | Signal and threshold |
|---|---|---|
| 1 - Quarantine scope | `pico-scheduling-capacity` - **Hosts Quarantined (S-FAIL-HOST)** | `pico_quarantine_hosts_quarantined` greater than 0 for 1m is warning (`PicoComputeHostQuarantined`); `rate(pico_quarantine_alerts_fired_total[5m])` greater than 1 for 5m is critical (`PicoComputeHostAlertFiringRateHigh`); `pico_quarantine_alerts_active` greater than 5 for 30m is warning (`PicoComputeHostUnresolvedAlerts`). Note alert labels `host_id`, `cell_id`, `region`, `condition`, `severity`. |
| 2 - Audit backlog | `pico-audit-telemetry` - **Audit Outbox Pending**, **Audit Delivery Lag (p50/p95)**, **Audit Delivery Rate** | `pico_audit_outbox_pending` orange at 100 and red at 1000; lag p50/p95 from `pico_audit_delivery_lag_bucket`; rate from `pico_audit_delivery_count`. Climbing pending plus rising lag means backlog. Flat pending with falling rate means delivery stall. Check `audit_delivery` events and the `audit_events_dead_letter` table next. |
| 3 - Lifecycle impact | `pico-lifecycle-operations` - **Operation Volume by Phase** | `pico_boot_events_total{event="boot_not_ready"}` split by `reason` (`image`, `network`, `resource`, `backend`, `protocol`, `timeout`, `cleanup`); `pico_create_events_total` and `pico_exec_events_total` for create plus exec impact. Clustered `boot_not_ready` on quarantined hosts points at runtime. Empty lifecycle panels with healthy hosts points at telemetry export, not the fleet. |
| 4 - Cleanup drift | `pico-cleanup-reconciliation` - **Orphans Detected vs Removed**, **GC Review Required**, **Network Review Required**, **Reconciliation Health State** | `pico_gc_orphans_detected` sustained plus `pico_gc_review_required` orange at 1 and red at 5; same bands for `network_reconciliation_review_required`. `requires_review` means stop deleting and keep the host quarantined per [cleanup-reconciliation](cleanup-reconciliation.md). |
| 5 - Placement plus health | `pico-scheduling-capacity` - **Hosts Evaluated vs Passed Constraints**, **Placement Efficiency Ratio**; `pico-host-health` - **Active Sandbox Count per Host**, **Draining Hosts** | Scheduler inventory drops a host after 60s without a capacity report; quarantine `capacity_reporting_staleness` fires after 120s. High evaluated with near-zero passed is constraint or pressure. Near-zero evaluated is inventory loss. Missing series is stale telemetry, not zero load. |

Log pivot after panels:

```
{service_name="pico-host-agent"} | json | event="boot_not_ready"
{service_name=~"pico-api|pico-host-agent"} | json | event=~"audit_.*"
```

Trace pivot: copy `trace_id` from the platform log or audit event, then
search that W3C trace ID. Audit records are unsampled; traces are diagnostic
only.

Audit pivot: query the durable audit store by `event_kind` (`host_disabled`,
`cleanup_disposition`, `lifecycle_transition`, `placement_outcome`,
`runtime_outcome`, `audit_delivery`) with `operation_id`, `trace_id`,
`host_id`, `cell_id`, or `region`.

### Decide audit vs runtime vs both

| What the panels show | Meaning | First action |
|---|---|---|
| Quarantine gauges up, outbox pending flat, lag flat, lifecycle degraded on those hosts | Runtime-led fire | Follow [host-quarantine](host-quarantine.md) mitigation; leave hosts out of placement; shed admission if 2 or more hosts in 30m page SRE lead |
| Quarantine gauges up, outbox pending climbing, lag rising, lifecycle panels thin or empty everywhere | Audit backlog with possible telemetry stall | Follow [audit-telemetry](audit-telemetry.md): block affected security-sensitive mutations, page SRE plus Security on loss or integrity gap, page Observability on stale pipeline; do not quarantine the whole cell until collector gateway health is checked |
| Quarantine gauges up, outbox climbing, lifecycle degraded on the same hosts, review-required active | Both sides active | Treat as combined incident: quarantine plus fail-closed audit gating together; page SRE lead; shed create admission at the API rather than mutating hosts; preserve `cleanup_disposition`, `host_disabled`, and `audit_delivery` evidence |
| Many hosts vanish at once with no quarantine condition and no lifecycle reason split | Telemetry export or collector failure, not a fleet fire | Follow [host-health](host-health.md) stale-many-hosts path plus [audit-telemetry](audit-telemetry.md); check `pico-metrics-agent` and OTLP gateway freshness before touching agents |

Do not purge the outbox. Do not replay dead-letters without Security review
and never delete the source outbox row. Do not delete cgroups, netns, or
workspaces. Do not resolve the quarantine alert to test cleanup. Do not
restart every host-agent.

### Admission shed

- SRE lead owns the cell-level admission-shed decision.
- Prefer rejecting new creates at the API over draining, restarting, or
  rebuilding hosts.
- `POST /rpc/v1/drain` stays SRE on-call approved per the host mutation
  policy. Rebuild stays SRE lead plus infra per [host-rebuild](host-rebuild.md).
- Restore admission only after quarantine gauges return to 0, outbox pending
  and lag return to baseline, and `boot_ready` holds 15m on the affected cell.

### Audit record

Record the combined-view readings in the incident ticket: timestamped values
for quarantined count, alerts active plus firing rate, outbox pending, lag
p50/p95, delivery rate, `boot_not_ready` by `reason`, orphans plus
review-required, and evaluated-vs-passed. Pin the underlying
`host_disabled`, `cleanup_disposition`, `lifecycle_transition`,
`placement_outcome`, and `audit_delivery` event IDs.

Worked example using this view is in
[drills/cell-wide-fire-rerun-2026-09-21](drills/cell-wide-fire-rerun-2026-09-21.md).

## Incident drills

The boot non-ready and host-quarantine drill is
[drills/boot-non-ready-and-quarantine.md](drills/boot-non-ready-and-quarantine.md).
The host rebuild exercise is
[drills/host-rebuild-exercise-2026-09-21.md](drills/host-rebuild-exercise-2026-09-21.md)
and walks the [host-rebuild](host-rebuild.md) cordon/drain/rebuild/re-admit
path with duration, approval evidence, and the 5m no-requarantine check.
The patch and rebuild emergency exercise is
[drills/patch-rebuild-emergency-2026-09-22.md](drills/patch-rebuild-emergency-2026-09-22.md)
and adds advisory triage, patch selection, boundary validation for the exact
profile, timing evidence, and no-reuse verification for the RR-01 escape
class on top of the same mechanical path.
The cell-wide fire rerun is
[drills/cell-wide-fire-rerun-2026-09-21](drills/cell-wide-fire-rerun-2026-09-21.md)
and replays the cell-wide fire plus audit backlog inject using the combined
triage view above.
The quarantine and fenced cleanup rerun is
[drills/quarantine-fenced-cleanup-rerun-2026-09-21](drills/quarantine-fenced-cleanup-rerun-2026-09-21.md)
and replays injects 2-3 with the ticket-gated operator helper for
acknowledge/resolve, fenced cleanup, ledger inspect, and drain/re-admit.
Update the owning runbook when a drill finding changes a check or mitigation.

## Related

- [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
- [ARCHITECTURE.md](..../ARCHITECTURE.md) section 13
- Alert rules: `o11y/rules/pico-recording-rules.yaml`
-: operational runbooks
-: dashboards
-: host quarantine alerts
- [SLO and error-budget policy](../observability/slo-error-budget-policy.md)
