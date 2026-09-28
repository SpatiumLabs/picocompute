# Image and rootfs cache

**Status**: P0 synthetic validation
**Normative strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Model**: `pico_core::image_cache`
**Dashboards**: `pico-image-cache`, `pico-lifecycle-operations`,
`pico-slo-error-budget`
**Alerts**: `PicoComputeImageCacheHitRateLow`, `PicoComputeImagePrepareSaturated`,
`PicoComputeSloBurnFast`

These results are synthetic image-cache drills, not a launch proven
operating point. P0/P1 must not set regional quotas. Cache bytes and
expected hit rate are candidate inputs to, not a published LPOP.

## Zone model

| Zone | Meaning | LPOP |
|---|---|---|
| Safe | SLO-BOOT holds, supply-chain checks hold, and host pressure stays below warning | Allowed |
| Warning | Elevated miss/eviction, diagnostic p99, or disk pressure; isolation and cleanup still hold | Cap (maximum LPOP) |
| Saturation | Knee: goodput stops rising, SLO miss, pressure saturation, scheduler reject, or class-A supply-chain miss | Never |

Warning is the LPOP cap. The knee is not. Unsigned, unpinned, or unverified
images served from cache are class-A even if boots succeed.

Thresholds encoded in `ImageCacheThresholds::default`:

| Signal | Warning | Saturation |
|---|---:|---:|
| SLO-BOOT error ratio | 0.0025 | 0.005 (99.5%) |
| Warm prepare p99 (diagnostic, class-B) | 1s | n/a (does not saturate) |
| Signature verify p99 (diagnostic, class-B) | 50ms | n/a |
| Rootfs overlay p99 (diagnostic, class-B) | 500ms | n/a |
| `pico_cgroup_memory_pressure` (0-100) | 15 | 30 |
| CPU/disk/network/process-slot utilization (0-1) | 0.75 | 0.90 |
| Warm host-local hit rate (S-CACHE-WARM) | 0.90 | n/a (class-B if boots still succeed) |

Cold miss on S-CACHE-COLD is expected and stays Safe when boots succeed or
fail closed with `reason=image`/verification deny. Prepare latency is
reported; it does not have to match warm LPOP.

Advertised vs recommended cache bytes is calibrated only on
S-CACHE-THRASH, using the last working set that still fit (no
evictions). Overflow probes do not raise recommended size. Cold/warm
reports emit the unproven lab default and do not calibrate. Under-size
is class-A for production (working set will thrash). Over-size is
class-B efficiency.

## Lab host SKU used by P0

Matches [active-sandbox-defaults](active-sandbox-defaults.md):

| Resource | Total |
|---|---:|
| vCPU | 64 |
| Memory | 64 GiB |
| Disk | 500 GiB |
| Network | 10 Gbps |
| Typical image | 512 MiB |
| Host-local working set | 8 images |
| Cache headroom | 25% |

## Recommended cache sizing (unproven)

`recommend_cache_bytes(working_set, typical_image, 0.25)`:

| Tier | Working set | Formula | Recommended |
|---|---:|---|---:|
| Host-local | 8 images | 8 x 512 MiB x 1.25 | **5 GiB** |
| Cell | 32 images | 32 x 512 MiB x 1.25 | **20 GiB** |

Until P1 host characterization runs, every production-eligible backend
inherits the same sizing. Do not treat these as measured hit-rate curves.

| Backend | Host SKU | Host-local (unproven) | Cell (unproven) | Saturation |
|---|---|---:|---:|---|
| Firecracker | lab-64vcpu | 5 GiB | 20 GiB | boot error >= 0.5%, disk util >= 0.90, or class-A supply-chain miss |
| QEMU | lab-64vcpu | 5 GiB | 20 GiB | same |
| gVisor | lab-64vcpu | 5 GiB | 20 GiB | same |
| Remote Firecracker | n/a | n/a | n/a | not production-eligible |

## Scenario results (P0)

| ID | Drill | P0 result |
|---|---|---|
| S-CACHE-COLD | WP-COLD against empty host/cell cache | Miss stays Safe. Report includes prepare/verify/overlay p50/p95/p99 by image profile and host SKU. Unsigned or unpinned pull is class-A. |
| S-CACHE-WARM | Repeat boots of the candidate image | Host-local hit stays Safe. Hit rate below 0.90 is class-B. Warm prepare p99 > 1s is class-B diagnostic. |
| S-CACHE-THRASH | Working set larger than cache | Eviction is Warning. Wrong digest, skipped verification, or tenant-layer leak is class-A. |

Concurrent prepares of the same digest that do not single-flight are
class-B (`prepare_not_single_flight`).

Class-A failures in this model: isolation/cleanup break, silent backend
change, leak, secrets in cached layers, unsigned/unpinned/unverified
served, wrong digest, verification skipped, tenant layer leak, timeouts
instead of shed, boot error ratio at 0.5%.

## Observability

| Channel | What to watch |
|---|---|
| Dashboard | `pico-image-cache` image hit/miss/eviction, prepare latency by `cache_result`, verify and overlay p99; `pico-lifecycle-operations` `boot_not_ready{reason="image"}` |
| Alert | `PicoComputeImageCacheHitRateLow` (warm hit rate < 0.80), `PicoComputeImagePrepareSaturated` (warm prepare p99 > 1s while prepares complete), `PicoComputeSloBurnFast` |
| Trace | `prepare_sandbox`, `image_prepare` |
| Audit | `image_verification` on admit, deny, and eviction |

P0 does not scrape Grafana. Named evidence must still appear on the report.
`pico_image_prepare_latency_seconds` is live from the host-agent prepare path.
Eager prepares report `cache_result="unknown"`; on-demand prepares
(CAP-165, `PICO_IMAGE_ON_DEMAND=1`) report real `hit`/`miss`/`evicted`
outcomes from the verification gate, so the **Image Prepare Latency by
cache_result** panel and `pico:image_prepare:latency:*` rules populate by
outcome. `pico_image_cache_hits`/`misses`/`evictions` (by `tier`),
`pico_image_verify_latency_seconds`, and `pico_image_overlay_latency_seconds`
are emitted by the on-demand path. Do not compute hit rates from the
`unknown` prepare series; use the `tier`-labeled counters.

## How to fill this file from a real run

1. Run S-CACHE-COLD, S-CACHE-WARM, and S-CACHE-THRASH through the
   harness against one production-shaped host (P1) per backend, image
   profile (minimal, agent, session), and cache tier (host-local, cell
   cache). Include concurrent prepare of one digest and a disk-pressure
   eviction pass.
2. Feed observations into `analyze_image_cache`. P1 reports must keep
   `proposed_lpop = none`.
3. Replace the table rows with `zones.safe_max`, `zones.warning_max`,
   `zones.saturation_onset`, `latency_by_profile_and_tier`, and `sizing`
   from the JSON artifact. Record the report digest.
4. Repeat at P2 before any preview cache working-set LPOP. Never
   extrapolate a host result to a region.

## Follow-up bottlenecks

Tracked as Linear issues from P0 (path and telemetry gaps, not
measured knees):

- Load harness that drives live S-CACHE-COLD/S-CACHE-WARM/S-CACHE-THRASH:

- Host image fetch, verify, cache, overlay, and eviction:
  BSD-184
- `cache_result` labels on image prepare histograms:

- Cost model consumes cache size vs hit rate vs prepare latency:

- Image pipeline readiness review:
