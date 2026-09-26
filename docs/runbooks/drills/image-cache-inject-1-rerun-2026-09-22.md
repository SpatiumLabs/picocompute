# Image-Cache Inject 1 Rerun - 2026-09-22

**Owner**: Image Pipeline with Observability
**Date**: 2026-09-22
**Source revision (base)**: `ad5d26151dcb052ae6c03204067ea783a79e01a8`
**Change under test**: live `pico_image_prepare_latency_seconds` emission from the host-agent prepare path (branch change under review; absent from the base revision, which is cited as the stable anchor)
**Procedure**: boot non-ready drill inject replay (tabletop)
**Prior record**: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) inject 1, gap row 1
**Drill inject**: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) inject 1
**Ticket**: synthetic tabletop replay, no production host mutation

Tabletop only. No host mutation, no drain RPC, no image rebuild, no layer
copy, no signature bypass, and no cache deletion was performed. This rerun
replays the image non-ready inject against the updated signals: live
`pico_image_prepare_latency_seconds` with `unknown` cache labels plus the
explicit fallback path for the still-empty hit/miss/eviction and
verify/overlay panels.

## Participants

- Image Pipeline owner as facilitator and image-signal owner
- Observability owner for dashboard, recording-rule, and alert evidence
- SRE owner for quarantine, mitigation, and incident ticket
- Control-plane owner for promotion pinning and rollback
- Security owner for verification and supply-chain decisions

## Candidate profile

| Field | Value |
|---|---|
| Date | 2026-09-22 |
| Source revision (base) | `ad5d26151dcb052ae6c03204067ea783a79e01a8` |
| Change under test | `pico_image_prepare_latency_seconds` emission (branch change; see header) |
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Region/cell | `region_test`/`cel_east` |
| Backend | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop-only profiles |
| Host profile | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Network | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway |
| Credential mode | Short-lived scoped leases with revoke-first destroy |
| Telemetry | `o11y/rules/pico-recording-rules.yaml` plus `PicoCompute` Grafana folder; durable audit outbox as authoritative record |

Evidence commands rerun for this revision:

- `scripts/validate-o11y-dashboards.sh` - pass, all dashboards and runbook links resolve
- `cargo nextest run -p pico-host-agent --lib metrics` - 17 passed, including 6 new image-prepare label tests
- `cargo nextest run -p pico-host-agent --lib boot` - 16 passed
- `cargo clippy -p pico-telemetry -p pico-host-agent --all-targets --locked -- -D warnings` - clean

## Scenario replayed

Facilitator states: after digest promotion `sha256:dead...`, cell `cel_east`
shows `pico_boot_events_total{event="boot_not_ready",reason="image"}`
rising. Other reasons are flat. Placement efficiency is normal.

Same mitigation and escalation as the prior record: stop promotion, pin last
known-good digest from the control plane, no host pull, no signature bypass.
Escalation to Image Pipeline, Security only on verification failure.

## Signal walk with updated signals

All panels were filtered by `region_test` plus `cel_east` first. Values below
are facilitator-stated inject values for the tabletop walk.

| Order | Panel or signal | Rerun reading |
|---|---|---|
| 1 - Reason split | `pico-lifecycle-operations` - `boot_not_ready` by `reason` | `reason="image"` rising after the `sha256:dead...` promotion; `network`, `backend`, `protocol` flat; placement efficiency normal. Image cause confirmed before any host access. |
| 2 - Prepare volume | `pico-image-cache` - **Prepare Volume** (`pico_prepare_events_total`) | Prepare failures track the promotion window; successes fall. Uses the long-live prepare event series, unchanged by this change. |
| 3 - Prepare latency (live) | `pico-image-cache` - **Prepare Latency** (`pico_prepare_latency_seconds`) | p50/p95/p99 move with the failing promotion window. Existing series, unchanged. |
| 4 - Image prepare by cache_result (new live series) | `pico-image-cache` - **Image Prepare Latency by cache_result** (`pico_image_prepare_latency_seconds{cache_result="unknown",image_profile="unknown"}`) | Populated from the real prepare path on every prepare completion and failure. The `unknown` labels are honest: no cache lookup ran, so no hit/miss claim is made. Unfiltered recording rules `pico:image_prepare:latency:p50:rate5m`, `:p95`, and `:p99` now populate; the hit-filtered rule `pico:image_prepare:latency:p99:hit:rate5m` stays empty. |
| 5 - Hit/miss/eviction (honestly empty) | `pico-image-cache` - **Image Cache Hit Rate**, **Image Cache Misses**, **Image Eviction Activity** | No series. `pico_image_cache_hits`, `misses`, and `evictions` are not emitted until host image-cache work lands. Emitting misses-only would force the hit-rate ratio to zero and fire `PicoComputeImageCacheHitRateLow` on a fabrication, so absence is the correct signal. The runbook marks these panels empty-with-fallback, not healthy. |
| 6 - Verify/overlay (honestly empty) | `pico-image-cache` - **Signature Verify Latency**, **Overlay Creation Latency** | No series. Verify and overlay stages do not exist outside the future cache path, so no histograms are emitted. Recording rules `pico:image_verify:latency:p99:rate5m` and `pico:image_overlay:latency:p99:rate5m` stay empty. |
| 7 - Logs | `{service_name="pico-host-agent"} \| json \| event="boot_not_ready" \| reason="image"`; `operation="image_prepare"` | `outcome=image_unavailable` on the failing prepares; no credential, path, or workload output in the query. |
| 8 - Traces | `prepare_sandbox` and image prepare spans, `backend` attribute only | Prepare spans bracket the failing window; no tenant or sandbox dimensions. |
| 9 - Audit | Image verification, promotion, rejection, revocation events | Promotion of `sha256:dead...` present; a verification miss is treated as a supply-chain incident, not cache tuning. |

Alert behavior confirmed: `PicoComputeImageCacheHitRateLow` stays silent because
the hits-plus-misses volume guard sees zero traffic (no fabricated misses).
`PicoComputeImagePrepareSaturated` stays silent because the hit-filtered p99 rule
and the hits-volume guard both see zero hits. Silence here means
not-enough-data, not healthy, and the runbook says so explicitly.

## Decision reached

Image cause confirmed on telemetry before any host access. The team stopped
the failing promotion, pinned the last known-good digest from the control
plane, refused host pulls, layer copies, cache deletions, and signature
bypass, and paged Image Pipeline. Security joins only on verification
mismatch. The new `unknown`-labeled prepare series was cited in order (step
4); the empty hit/miss/eviction and verify/overlay panels were read as
empty-with-fallback per the runbook (steps 5-6), not as zero misses or zero
latency.

## Gap closure assessment for inject 1

- Live metric series: `pico_image_prepare_latency_seconds` with bounded
  `status`, `cache_result="unknown"`, `image_profile="unknown"` labels is
  registered, emitted on every prepare completion and failure, unit-tested
  for allowlist rejection of digests/IDs/tags in status, cache labels, and
  profile plus redaction behavior, and validated by clippy plus nextest. The
  **Image Prepare Latency by cache_result** panel and the unfiltered
  `pico:image_prepare:latency:*` rules now populate.
- Explicit fallback doc: [image-cache](../image-cache.md) first checks now
  separate live panels (prepare volume, prepare latency, image prepare by
  cache_result) from honestly-empty panels (hit rate, misses, evictions,
  verify, overlay) with the prepare-event/log/trace/audit fallback path and
  expiry on host image-cache work (BSD-184). The runbook index metrics table
  and the capacity model observability section carry the same split.
- Drill rerun: this record replays inject 1 against the updated signals and
  cites each panel reading in order, including the empty-with-fallback reads.
- Remaining work: real `hit`/`miss`/`evicted` outcomes, real `minimal`/`agent`/
  `session` profiles, `tier` labels, hit/miss/eviction counters, and
  verify/overlay histograms land with the host image cache. On arrival the
  `unknown` default retires, the hit-filtered rules and both image-cache
  alerts become evaluable, and this rerun pattern repeats with a warm-cache
  scenario. No fabricated ratios are used as an interim.

## Related

- Drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) inject 1
- Runbook: [image-cache](../image-cache.md) first checks and fallback
- Runbook index: [README](../README.md) metrics vs ADR taxonomy
- Capacity model: [image-cache](../../capacity/image-cache.md) observability
- Dashboard: `o11y/image-cache.json` panels 10 (live) and 7-9, 11-12 (pending)
- Recording rules: `o11y/rules/pico-recording-rules.yaml` groups `pico.image.cache` and `pico.image.cache.alerts`
