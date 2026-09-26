# Active sandbox default limits

**Status**: Unproven packing defaults (P0)
**Normative strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Model**: `pico_core::capacity`
**Dashboards**: `pico-scheduling-capacity`, `pico-host-health`

These numbers are scheduler packing math and zone thresholds, not a launch
proven operating point. P0/P1 must not set regional quotas. Architecture
14.1 (500k active) remains a class-C design target until an LPOP reaches it.

## Zone model

| Zone | Meaning | LPOP |
|---|---|---|
| Safe | SLOs hold and host pressure stays below warning | Allowed |
| Warning | Elevated pressure or near-SLO; isolation and cleanup still hold | Cap (maximum LPOP) |
| Saturation | Knee: goodput stops rising, SLO miss, pressure saturation, or scheduler reject | Never |

Warning is the LPOP cap. The knee is not. Saturation must not break
isolation or cleanup (class-A even if some creates succeed).

Thresholds encoded in `DensityThresholds::default`:

| Signal | Warning | Saturation |
|---|---:|---:|
| `pico_cgroup_memory_pressure` (0-100) | 15 | 30 |
| CPU disk network process-slot utilization (0-1) | 0.75 | 0.90 |
| SLO-EXEC error ratio | 0.0005 | 0.001 (99.9%) |
| SLO-BOOT error ratio | 0.0025 | 0.005 (99.5%) |
| Exec p99 (diagnostic, class-B) | 1s | n/a (does not saturate) |

Advertised vs measured warning-max must stay inside a 15% relative error
band. Over-advertise is class-A for production (wrong admission math).
Under-advertise is class-B efficiency.

## Default sandbox shape

Matches `ResourceLimits::default` plus 1 GiB disk:

| Resource | Per sandbox |
|---|---:|
| vCPU | 2 |
| Memory | 512 MiB |
| Disk | 1024 MiB |
| PIDs | 512 |

## Lab host SKU used by scheduler tests

| Resource | Total |
|---|---:|
| vCPU | 64 |
| Memory | 64 GiB |
| Disk | 500 GiB |
| Network | 10 Gbps |
| Process slots | 100 |
| Max concurrent creates restores | 10 5 |

Advertised packing for the default shape on this SKU:

| Binding | Count |
|---|---:|
| vCPU (`64 2`) | **32** |
| Memory (`65536 512`) | 128 |
| Disk (`500000 1024`) | 488 |
| Process slots | 100 |

The advertised host limit is **32**, bound by vCPU. `max_process_slots = 100`
overstates density unless the per-sandbox vCPU request is lowered. Do not
raise process slots to chase architecture 500k.

Cell advertised limit is the minimum of summed host packing and
`CellCapacity::max_sandboxes`. Region is not inferred from one host.

## Recommended defaults by backend (unproven)

Until P1 host characterization runs, every production-eligible backend
inherits the same packing cap. Do not treat these as measured density.

| Backend | Host SKU | Safe (unproven) | Warning LPOP cap (unproven) | Saturation |
|---|---|---:|---:|---|
| Firecracker | lab-64vcpu | <= 24 (75% of 32) | 32 | first reject or pressure >= 30 |
| QEMU | lab-64vcpu | <= 24 | 32 | same (expect earlier knee) |
| gVisor | lab-64vcpu | <= 24 | 32 | same (expect earlier knee) |
| Remote Firecracker | n/a | n/a | n/a | not production-eligible |

Safe is a 25% headroom haircut on advertised packing so preview stays inside
the ADR-0012 private-preview rule (>= 50% unused cell capacity vs the knee
once a cell test exists). It is still unproven: cgroup, fd, and exec
contention may bind first.

Exec concurrency LPOP is unset. S-RAMP-EXEC must measure it; do not copy
the active-count cap.

## How to fill this file from a real run

1. Run S-RAMP-ACTIVE, S-SOAK-ACTIVE, S-NOISY, and S-RAMP-EXEC through the
    harness against one production-shaped host (P1) per backend.
2. Feed observations into `analyze_active_capacity`. P1 reports must keep
   `proposed_lpop = none`.
3. Replace the table rows with `zones.safe_max`, `zones.warning_max`, and
   `zones.saturation_onset` from the JSON artifact. Record the report
   digest.
4. Repeat at P2 before any preview LPOP. Never extrapolate a host result
   to a region.

## Follow-up bottlenecks

Tracked as Linear issues from P0 (packing and integration gaps,
not measured knees):

- Load harness that drives live S-RAMP-ACTIVE S-SOAK-ACTIVE S-NOISY /
  S-RAMP-EXEC:
- Wire schedulers into API create admission:

- Unify host-agent and scheduler `HostCapacity`:

- Record cgroup OOM memory-high CPU-throttle events:

- Cost model consumes these reports:
- Cell/host loss surviving capacity: [cell-unavailability](cell-unavailability.md)

- Snapshot restore pressure: [checkpoint-load](checkpoint-load.md)

- Image/rootfs cache: [image-cache](image-cache.md)
