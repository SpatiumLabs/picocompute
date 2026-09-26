# PicoCompute SLO and Error-Budget Policy

**Status**: Proposed
**Date**: 2026-09-04
**Owners**: SRE-PicoCompute (policy), Control Plane and Runtime (service), Observability (queries)
**Contract**: [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
**Runbook**: [slo-error-budget](../runbooks/slo-error-budget.md)
**Dashboard**: `pico-slo-error-budget` (`o11y/slo-error-budget.json`)
**Rules**: `o11y/rules/pico-recording-rules.yaml`

This document is the production contract for PicoCompute SLOs, SLIs, error
budgets, burn alerts, and rollout freeze. Architecture latency and
availability numbers in [ARCHITECTURE.md](..../ARCHITECTURE.md) section 14.1
are design targets, not this contract.

## Principles

1. An SLO is a commitment used for paging, freeze, and launch gates. It is
   looser than the architecture target until measured candidate behavior
   under load (G-14) justifies tightening.
2. Every SLO names a measurable SLI, a window, a target, an owner, and a
   dashboard query. Unmeasurable objectives stay out of the budget.
3. Availability SLIs count **terminal valid events** only. Start, progress,
   and retry events are never in the denominator.
4. Client-caused outcomes are excluded from availability: ADR-0009
   `rejected`, `conflict`, and `canceled`. Quota and policy denials are
   admission correctness, not platform unavailability.
5. Service-level SLOs aggregate away `host_id` and never use tenant,
   sandbox, or request identity as a dimension.
6. Latency SLIs are histogram success ratios at a threshold, not client
   quantiles. Histogram buckets must include every latency threshold below.
7. Missing required SLI series is a telemetry incident, not 100% success.

## Event mapping

Implemented host-agent counters use `event=` labels. ADR-0009 uses
`operation` and `outcome`. Until instrumentation converges, SLI queries use
the implemented labels. ADR values remain the semantic contract.

| Operation | Valid (denominator) | Bad (numerator) | Excluded |
|---|---|---|---|
| create | `create_completed`, `create_failed` | `create_failed` | `create_started` |
| boot | `boot_ready`, `boot_not_ready` | `boot_not_ready` | `boot_start`, `boot_cleanup` |
| exec | `succeeded`, `failed`, `timed_out`, `not_completed` | `failed`, `timed_out`, `not_completed` | `exec_started`, `canceled` |
| destroy | `destroy_completed`, `destroy_failed` | `destroy_failed` | `destroy_started` |
| suspend | `suspend_completed`, `suspend_failed`, `suspend_timed_out` | `suspend_failed`, `suspend_timed_out` | `suspend_started` |
| resume | `resume_completed`, `resume_failed`, `resume_timed_out` | `resume_failed`, `resume_timed_out` | `resume_started` |
| fork | `fork_completed`, `fork_failed` | `fork_failed` | `fork_started` |
| restore | `restore_completed`, `restore_failed`, `restore_partial_cleanup` | `restore_failed`, `restore_partial_cleanup` | `restore_started`, `restore_memory_restored` |
| audit | `delivered`, `dead_letter`, `dropped` | `dead_letter`, `dropped` | `retry` |

When `pico.api.request.count` exists with ADR `outcome`, API availability
replaces the create proxy. Do not treat `outcome="error"` as an SLI signal;
that label is not produced.

## Window and budget math

- Compliance window: 30-day rolling.
- Error budget: `1 - availability_target` of valid events in the window.
- Error ratio: `bad valid`.
- Budget remaining: `clamp_min(1 - error_ratio (1 - availability_target), 0)`.
- Burn rate: `error_ratio (1 - availability_target)`. Burn `1` spends the
  30-day budget exactly on schedule. Burn `14.4` spends it in about 50 hours.

Recording rules expose these as `pico:slo:*` with label `slo`.

## SLO catalog

All availability SLOs are regional. Cell splits are diagnostic, not the
commitment. Targets apply to private preview through production unless a
stage exception is recorded under [Exceptions](#exceptions).

### User-facing availability

| ID | SLO | Target | SLI (`slo` label) | Owner |
|---|---|---|---|---|
| SLO-API | Control-plane API availability | 99.9% | Intended: admitted API requests with `outcome` in `success`, `timeout`, `unavailable`, `failed`. **Provisional:** create terminal events (`slo="create"`) until `pico.api.request` is exported. | Control Plane |
| SLO-CREATE | Sandbox create success | 99.5% | `slo="create"` | Control Plane Runtime |
| SLO-BOOT | Sandbox boot ready | 99.5% | `slo="boot"` | Runtime |
| SLO-EXEC | Exec platform completion | 99.9% | `slo="exec"` | Runtime |
| SLO-DESTROY | Destroy success | 99.9% | `slo="destroy"` | Runtime |
| SLO-SUSPEND | Suspend success | 99.5% | `slo="suspend"` | Runtime |
| SLO-RESUME | Resume success | 99.5% | `slo="resume"` | Runtime |
| SLO-FORK | Fork success | 99.5% | `slo="fork"` | Runtime |
| SLO-RESTORE | Snapshot restore success | 99.5% | `slo="restore"` | Runtime Storage |

99.9% over 30 days is 43.2 minutes of equivalent full unavailability, or
about 1 bad event per 1,000 valid events. 99.5% is 3.6 hours 5 bad per
1,000. Architecture 99.99% API availability remains a design target.

Exec duration is caller-controlled. SLO-EXEC is completion of the platform
exec path, not command runtime.

### Latency (defined; budgeted after histogram buckets)

Latency SLIs are `share of terminal operations with duration <= T`.
Required histogram bucket edges include `0.1`, `0.2`, `0.5`, `1`, `2`, `5`,
and `8` seconds. Until `pico-telemetry` configures those edges, p99
panels are diagnostic only and do **not** consume error budget.

| ID | SLO | Target | Instrument | Owner |
|---|---|---|---|---|
| SLO-API-LAT | API admission latency | 99% <= 300ms | `pico.api.request.duration` (not yet exported) | Control Plane |
| SLO-BOOT-LAT | Boot latency | 99% <= 8s | `pico_boot_latency_seconds` | Runtime |
| SLO-FORK-LAT | Fork latency | 99% <= 500ms | `pico_fork_latency_seconds` | Runtime |
| SLO-RESTORE-LAT | Warm restore latency | 99% <= 1s | `pico_restore_latency_seconds` | Runtime |
| SLO-DESTROY-LAT | Destroy latency | 99% <= 2s | `pico_destroy_latency_seconds` | Runtime |

Architecture p50 restore < 200ms and fork < 100ms stay design targets.
gVisor vs microVM cold-start p50 targets are backend diagnostics, not
separate budgets.

### Platform health

| ID | SLO | Target | Current measurement | Owner |
|---|---|---|---|---|
| SLO-HOST | Host control-loop freshness | 99.9% of host-minutes with last capacity report age < 60s | Not yet a histogram. Scheduler TTL is 60s; quarantine `capacity_reporting_staleness` is 120s. Until `pico.host.health` freshness is exported, page from [host-quarantine](../runbooks/host-quarantine.md), not SLO burn. | SRE Runtime |
| SLO-RECONCILE | Reconciliation delay | 99% of GC passes finish in 60s and review-required does not grow for 30m | Diagnostic: `pico_gc_pass_duration_seconds`, `pico_gc_review_required`. Budgeted after a terminal reconcile counter with ADR `outcome`. | Runtime |
| SLO-AUDIT | Audit durable delivery | 99.99% of terminal deliveries are `delivered` | `slo="audit"` on `pico_audit_delivery_count` | Control Plane Security |
| SLO-AUDIT-LAG | Audit delivery lag | 99% of delivered events persist within 30s | `pico_audit_delivery_lag` once buckets include 30s | Control Plane |
| SLO-TELEMETRY | Required telemetry freshness | SLO recording series present within 120s | `PicoComputeSloTelemetryStale` on absent `pico:slo:valid:rate5m` | Observability |

Audit `retry` is in-flight. Dead-letter or drop is a bad event and a
security-sensitive mutation gate per ADR-0009.

## Error-budget policy

SRE-PicoCompute owns the budget. The subsystem owner of the burning `slo` label
owns the fix. Product may request budget spend; SRE may refuse.

### Rollout freeze

Freeze is regional unless the burn is global.

| Budget remaining (30d) or burn | Production change policy |
|---|---|
| Fast burn page (`PicoComputeSloBurnFast`) | Freeze non-incident rollouts in the region immediately. |
| Remaining < 25% | Freeze feature and capacity-expanding rollouts. Security patches, SLO-restoring fixes, and incident changes proceed. |
| Remaining = 0% or `PicoComputeSloBudgetExhausted` | Freeze all non-incident production changes until remaining > 10% or an exception is approved. |
| Slow burn ticket (`PicoComputeSloBurnSlow`) | No automatic freeze. Owning team files work; SRE reviews within one business day. |

 must record SLO status
before each production stage:

- no firing `PicoComputeSloBurnFast` or `PicoComputeSloBudgetExhausted` in the
  target region
- user-facing availability SLOs have remaining budget >= 25%, or a current
  exception
- `PicoComputeSloTelemetryStale` is not firing
- burn alerts are routed to SRE-PicoCompute with this policy linked

Private preview may ship with remaining < 25% if the review records the
burn cause and a cap on admitted tenants. Public beta and production may
not.

### Escalation

| Condition | Page | Escalate after |
|---|---|---|
| Fast burn on create, boot, exec, restore, or audit | SRE-PicoCompute | 15m to Control Plane or Runtime owner of `slo` |
| Fast burn on destroy, suspend, resume, or fork | SRE-PicoCompute | 30m if still burning |
| Budget exhausted | SRE-PicoCompute + service owner | Immediate freeze; incident commander if user-visible |
| Telemetry stale | Observability | 15m; treat user-facing SLOs as unknown, not healthy |
| Audit dead-letter or drop | SRE + Security | Follow [audit-telemetry](../runbooks/audit-telemetry.md) |

Do not page solely from a raw 30-day error-ratio graph. Page from the
multi-window alerts.

### Exceptions

Exceptions are fail-closed and cannot waive ADR-0006 isolation, audit
durability, or G-14 evidence for the candidate profile.

A budget-spend or freeze-bypass exception records:

- SLO IDs and regions
- remaining budget and current burn
- reason, compensating control, and rollback
- expiry (default 7 days)
- SRE-PicoCompute and the service owner
- Security when SLO-AUDIT or a security-sensitive path is involved

Expired exceptions restore the freeze. Spending budget on an experiment
during a page is not an exception; stop the experiment.

### Review cadence

SRE reviews remaining budget weekly and after every fast-burn page. Targets
change only through this document with SRE and the service owner. Tightening
after G-14 load evidence does not require a new ADR.

## Multi-window burn alerts

Alerts live in `o11y/rules/pico-recording-rules.yaml` group
`pico.slo.alerts`. Category: `slo_burn`.

| Alert | Windows | Threshold | Severity | `for` |
|---|---|---|---|---|
| `PicoComputeSloBurnFast` | 1h and 5m | burn > 14.4 | critical (page) | 2m |
| `PicoComputeSloBurnSlow` | 6h and 30m | burn > 6 | warning (ticket) | 15m |
| `PicoComputeSloBudgetExhausted` | 30d remaining <= 0 | n/a | critical (page) | 15m |
| `PicoComputeSloTelemetryStale` | absent `pico:slo:valid:rate5m` | n/a | warning | 15m |

Fast and slow alerts also require a minimum valid event rate so a single
failure in a quiet region does not page:

- fast: `pico:slo:valid:rate5m > 0.01` (about 36 valid events/hour)
- slow: `pico:slo:valid:rate30m > 0.003`

Worked example for a 99.5% SLO (0.5% budget):

| Burn | Error ratio | Time to exhaust 30d budget | Alert |
|---|---|---|---|
| 1 | 0.5% | 30 days | none |
| 6 | 3.0% | 5 days | slow if both 6h and 30m hold |
| 14.4 | 7.2% | ~50 hours | fast if both 1h and 5m hold |

For 99.9% (0.1% budget), the same multipliers apply: slow fires at 0.6%
errors, fast at 1.44% errors.

## Missing data

- Grafana panels use last-non-null. Empty is null, never 0% errors.
- `PicoComputeSloTelemetryStale` pages the telemetry path
  ([audit-telemetry](../runbooks/audit-telemetry.md)).
- While required series are absent, rollout treats SLO status as `blocked`
  for G-14, not `pass`.

## Network contention

Per [SC-05](../security/side-channel-assessment.md#sc-05-network-timing-and-bandwidth-contention),
noisy-neighbor and bandwidth contention are not excluded from these SLOs.
Contention that delays boot, restore, or exec completion burns the
corresponding lifecycle budget. SLOs stay service-level; they do not add
per-sandbox or per-tenant network dimensions.

## Dashboards

`pico-slo-error-budget` is the SLO status board. It must show:

- policy summary linking here
- 30-day error ratio vs target per `slo`
- budget remaining per `slo`
- 5m/1h fast burn and 30m/6h slow burn
- jump links to lifecycle, host-health, snapshot, and audit dashboards

Component dashboards remain diagnostic. They do not define targets.

## Production readiness

[G-14](../security/production-readiness.md) requires this policy, live
queries, burn-alert tests, and measured candidate behavior under
[ADR-0012](../adr/0012-production-scale-validation-strategy.md). consumes:

1. This document approved by SRE and engineering owners.
2. Recording rules and `slo_burn` alerts deployed for the candidate profile.
3. Dashboard `pico-slo-error-budget` populated (not null) in the target
   region.
4. Freeze checklist in [Rollout freeze](#rollout-freeze).

## Instrumentation follow-ups

These do not block adopting this policy for the signals that already exist.
They block tightening or adding the named SLO to the budget:

- Export ADR `pico.api.request.*` and stop using create as the API proxy.
- Align lifecycle counters to ADR `operation`/`outcome` without dropping
  `event=` until dashboards switch.
- Configure histogram buckets for latency SLOs, then attach
  SLO-*-LAT to the same burn machinery.
- Export host heartbeat age and reconcile terminal outcomes for SLO-HOST
  and SLO-RECONCILE.

## Test evidence

`python3 o11y/slo/burn_rate_sim.py` checks budget remaining, fast/slow
predicates, the quiet-region floor, and that recording rules no longer use
`outcome="error"`. Deployed `slo_burn` alerts still need a live Prometheus
evaluation against sample traffic before G-14 can pass.

## Approval

This policy remains `Proposed` until both roles approve the catalog, freeze
rules, and burn alerts:

- SRE owner
- Engineering owner (Control Plane and Runtime)

Changing a target, exclusion, or freeze threshold requires both signatures
again.
