# Image Prepare and Cache

**Owner**: Image Pipeline/SRE-PicoCompute
**Alert category**: `regional_lifecycle_failure`, `security_event`
**Severity**: Page when boots fail `reason=image` after a promotion; ticket for cache miss/latency only
**Dashboards**: `pico-image-cache`, `pico-lifecycle-operations`, `pico-snapshot-fork`

## When to use

Boot is `boot_not_ready` with `reason=image`, image prepare fails or is slow,
or snapshot cache miss/eviction is starving restore/boot.

## Severity

| Condition | Level |
|---|---|
| `boot_not_ready{reason="image"}` after an image promotion | Page Image Pipeline |
| Verification/rejection of a digest (supply chain) | Page Security + Image Pipeline |
| Cache hit rate drop with boots still ready | Ticket |
| Prepare p99 high, success rate intact | Ticket |

## First checks

1. `pico-lifecycle-operations`: `boot_not_ready` with `reason="image"`.
   Platform log `outcome=image_unavailable` (or verification failed in audit).
2. `pico-image-cache` -> **Prepare Volume** (`pico_prepare_events_total`)
   and **Prepare Latency**. Then **Image Prepare Latency by cache_result**
   (`pico_image_prepare_latency_seconds`; eager prepares report
   `cache_result="unknown"`, on-demand prepares report real
   `hit`/`miss`/`evicted`).
3. **Image Cache Hit Rate**, **Image Cache Misses**, **Image Eviction
   Activity**, **Signature Verify Latency**, and **Overlay Creation Latency**
   populate when the on-demand path is enabled (`PICO_IMAGE_ON_DEMAND=1`,
   CAP-165). On eager-only hosts those panels stay empty. Do not read an
   empty panel as healthy. Fall back to prepare events, platform logs,
   traces, and audit below until then.
4. **Snapshot Cache Hit Rate**, **Cache Misses**, **Eviction Activity**,
   **Snapshot Reference Churn** (restore path, not image layers).
5. Correlate with [snapshot-fork](snapshot-fork.md) if restore/fork moved
   at the same time.
6. Confirm the digest is not revoked. Do not re-pull an unpinned tag.

Do not rebuild images on the host. Do not copy layers by hand onto a host.

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | event="boot_not_ready" | reason="image"
{service_name=~"pico-host-agent|pico-image"} | json | operation="image_prepare"
```

**Traces**

`prepare_sandbox` and image `build`/prepare spans. Attribute `backend` only.

**Audit**

Image verification, promotion, rejection, and revocation events. Treat a
verification miss as a supply-chain incident, not a cache tuning problem.

## Mitigation

1. Stop promoting the failing digest. Pin hosts to the last known-good
   digest via the image control plane, not by host mutation.
2. Verification failure: fail closed. Do not bypass signature or digest
   checks.
3. Cache eviction storm: stop additional snapshot load; follow
   [snapshot-fork](snapshot-fork.md). Do not delete cache files on disk.
4. Single-host prepare failures with cluster-wide success: that host is
   [host-health](host-health.md)/quarantine, not an image bug.

## Escalation

- Page Image Pipeline when prepare or `reason=image` tracks a promotion.
- Page Security on verification, signature, or revocation mismatches.
- Page SRE if prepare latency burns the create/boot SLO without a digest
  change (host disk or network).

## Rollback

1. Revert to the previous promoted digest.
2. Confirm `prepare` success and `boot_ready` recover for 15m.
3. Leave cache contents alone; let the cache refill on demand.

## Related

- [lifecycle-operations](lifecycle-operations.md)
- [snapshot-fork](snapshot-fork.md)
- ADR-0008 guest image format
- [Image cache capacity model](../capacity/image-cache.md)
