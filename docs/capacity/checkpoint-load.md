# Snapshot restore pressure

**Status**: P0 synthetic validation
**Normative strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Model**: `pico_core::restore_capacity`
**Dashboards**: `pico-snapshot-fork`, `pico-image-cache`,
`pico-slo-error-budget`, `pico-lifecycle-operations`
**Alerts**: `PicoComputeRestoreSaturated`, `PicoComputeRestorePartialCleanup`,
`PicoComputeSloBurnFast`

These results are synthetic restore-pressure drills, not a launch proven
operating point. P0/P1 must not set regional quotas. Restore/s and
concurrent restore caps are candidate inputs to, not a published
LPOP.

## Zone model

| Zone | Meaning | LPOP |
|---|---|---|
| Safe | SLO-RESTORE holds and host/cache pressure stays below warning | Allowed |
| Warning | Elevated pressure, cache miss, or diagnostic p99; isolation and cleanup still hold | Cap (maximum LPOP) |
| Saturation | Knee: goodput stops rising, SLO miss, pressure saturation, scheduler reject, or class-A safety miss | Never |

Warning is the LPOP cap. The knee is not. Partial cleanup is a bad restore
event (class-A even if some restores succeed).

Thresholds encoded in `RestoreThresholds::default`:

| Signal | Warning | Saturation |
|---|---:|---:|
| SLO-RESTORE error ratio | 0.0025 | 0.005 (99.5%) |
| Restore p99 (diagnostic, class-B) | 1s (SLO-RESTORE-LAT) | n/a (does not saturate) |
| Exec p99 under restore (diagnostic, class-B) | 1s | n/a |
| `pico_cgroup_memory_pressure` (0-100) | 15 | 30 |
| CPU/disk/network/process-slot utilization (0-1) | 0.75 | 0.90 |
| Warm host-local hit rate | 0.80 | n/a (class-B if restores still succeed) |

Architecture p50 restore < 200ms stays a class-C design target.

Advertised vs measured concurrent-restore warning-max must stay inside a
15% relative error band. Over-advertise is class-A for production (wrong
admission math). Under-advertise is class-B efficiency.

## Lab host SKU used by scheduler tests

Matches [active-sandbox-defaults](active-sandbox-defaults.md):

| Resource | Total |
|---|---:|
| vCPU | 64 |
| Memory | 64 GiB |
| Disk | 500 GiB |
| Network | 10 Gbps |
| Process slots | 100 |
| Max concurrent creates/restores | 10/**5** |

The advertised restore concurrency cap is **5**, bound by
`HostPressure.max_concurrent_restores`. Restore/s is unset until P1.

## Recommended defaults by backend (unproven)

Until P1 host characterization runs, every production-eligible backend
inherits the same concurrent-restore cap. Do not treat these as measured
throughput.

| Backend | Host SKU | Safe (unproven) | Warning/LPOP cap (unproven) | Saturation |
|---|---|---:|---:|---|
| Firecracker | lab-64vcpu | <= 3 | 5 | first reject, restore error >= 0.5%, or pressure >= 30 |
| QEMU | lab-64vcpu | <= 3 | 5 | same (expect earlier knee) |
| gVisor | lab-64vcpu | <= 3 | 5 | same (expect earlier knee) |
| Remote Firecracker | n/a | n/a | n/a | not production-eligible |

Safe is a 40% haircut on advertised restore concurrency so preview stays
inside ADR-0012 private-preview headroom once a cell test exists. Cache
tier, snapshot size, and memory vs filesystem restore may bind first.

## Scenario results (P0)

| ID | Drill | P0 result |
|---|---|---|
| S-RAMP-RESTORE | Raise concurrent restores on `lab-64vcpu` | Scheduler rejects at 6. Safe <= 3, warning cap 5 when pressure stays in envelope. Report includes p50/p95/p99 by snapshot kind and storage tier. |
| S-SPIKE-RESTORE | 3x offered restore rate from one snapshot | Throughput caps via `unavailable` rejects. Timeouts with shed are class-A. |
| S-SOAK-RESTORE | Steady restore at warning density | Lineage mix-up, secret material, or snapshot-store backlog is class-A. |

Cache hit/miss is measured on every step. Warm host-local vs cold
regional-object-store comparison stays in warning on miss; it does not
saturate if restores succeed. Lazy memory restore is class-C untested
.

Class-A failures in this model: isolation/cleanup break, silent backend
change, leak, lineage mix-up, secrets in artifacts, partial cleanup,
timeouts instead of shed, snapshot-store backlog on soak, restore error
ratio at 0.5%.

## Observability

| Channel | What to watch |
|---|---|
| Dashboard | `pico-snapshot-fork` restore volume, p50/p95/p99 by `snapshot_type` and `cache_tier`, restore saturation; `pico-image-cache` hit/miss |
| Alert | `PicoComputeRestoreSaturated` (p99 > 1s while restores complete), `PicoComputeRestorePartialCleanup`, `PicoComputeSloBurnFast` |
| Trace | `restore_from_snapshot` |
| Audit | `snapshot_operation` on restore admit and reject |

P0 does not scrape Grafana. Named evidence must still appear on the report.
`snapshot_type` and `cache_tier` labels are not yet on live restore
histograms; panels stay empty until restore telemetry is labeled.

## How to fill this file from a real run

1. Run S-RAMP-RESTORE, S-SPIKE-RESTORE, and S-SOAK-RESTORE through the
    harness against one production-shaped host (P1) per backend,
   snapshot kind (filesystem, memory, lazy when available), and storage
   tier (host-local, cell cache, regional object store). Include a
   concurrent restore plus exec workload.
2. Feed observations into `analyze_restore_pressure`. P1 reports must keep
   `proposed_lpop = none`.
3. Replace the table rows with `zones.safe_max`, `zones.warning_max`,
   `zones.saturation_onset`, and `latency_by_kind_and_tier` from the JSON
   artifact. Record the report digest.
4. Repeat at P2 before any preview restore LPOP. Never extrapolate a host
   result to a region.

## Follow-up bottlenecks

Tracked as Linear issues from P0 (path and telemetry gaps, not
measured knees):

- Load harness that drives live S-RAMP-RESTORE/S-SPIKE-RESTORE
  S-SOAK-RESTORE:
- Host restore via sandboxd is fail-closed:

- Lazy memory restore prototype:
- Snapshot cache hit/miss lacks `tier` labels:

- Image/rootfs cache under load:
- Cost model consumes restore/s and storage bandwidth:
