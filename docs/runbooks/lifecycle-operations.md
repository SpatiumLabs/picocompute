# Lifecycle Operations

**Owner**: SRE-PicoCompute
**Alert category**: `regional_lifecycle_failure`
**Severity**: Page when a region or cell fails create, boot, or exec; ticket for a single-host blip
**Dashboards**: `pico-lifecycle-operations`, `pico-slo-error-budget`, `pico-control-plane`

## When to use

Create does not reach ready, boot finishes `boot_not_ready`, exec times out, or
a sandbox stays in a transitory state past its deadline.

## Severity

| Condition | Level |
|---|---|
| Create/boot/exec error rate elevated in one region or cell for 5m | Page |
| Clustered `boot_not_ready` on one host (see [host-quarantine](host-quarantine.md)) | Quarantine/Page |
| Isolated tenant or image failures | Ticket |
| Exec `timed_out`/`not_completed` without create/boot impact | Ticket unless SLO burn is page-level |

## First checks

1. `pico-lifecycle-operations` -> **Operation Volume by Phase**. Split
   `pico_create_events_total`, `pico_boot_events_total`, and
   `pico_exec_events_total` by `event` and `reason`.
2. Confirm it is not an SLO-only view: `pico-slo-error-budget` burn by
   `operation`.
3. If create fails before boot, open [control-plane](control-plane.md) and
   [scheduling-capacity](scheduling-capacity.md).
4. If boot fails after placement, split `boot_not_ready` by `reason`:

   | `reason` | Owning runbook |
   |---|---|
   | `image` | [image-cache](image-cache.md) |
   | `network` | [networking](networking.md) |
   | `resource` | [scheduling-capacity](scheduling-capacity.md) |
   | `backend` | [runtime-backend](runtime-backend.md) |
   | `protocol` | [runtime-backend](runtime-backend.md) (guest handshake) |
   | `timeout` | this runbook, then the slowest phase in the trace |
   | `cleanup` | [cleanup-reconciliation](cleanup-reconciliation.md) |

5. For exec: `event="timed_out"` vs `failed` vs `not_completed`. Rising
   duration on **Exec Duration** without `timed_out` is saturation, not a hung
   guest.

Do not SSH. Do not restart host-agent. Do not destroy sandboxes from the host.

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | event="boot_not_ready"
{service_name="pico-host-agent"} | json | event=~"exec_.*|timed_out|not_completed"
```

Platform log `outcome` for boot maps `reason` to ADR reasons
(`image_unavailable`, `network_setup_failed`, `no_capacity`,
`runtime_start_failed`, `protocol_error`, `deadline_exceeded`,
`cleanup_incomplete`). Metric `reason` stays `image`/`network`/`backend`/...

**Traces**

Root: `request` -> `create` -> `create_sandbox`/`prepare_sandbox` /
`boot_sandbox`/`exec`. Pivot from `trace_id` on the terminal log.

**Audit**

- `lifecycle_transition` for the sandbox state
- `runtime_outcome` for prepare/start
- `placement_outcome` if create never reached the host

## Mitigation

1. If one host: confirm it is already excluded (`HostHealth` not
   `Healthy`/`Degraded`, or quarantine gauge > 0). Do not drain yet.
2. If one image: stop promoting that digest; page Image Pipeline. Existing
   ready sandboxes stay up.
3. If one backend: disable new placement onto that backend via the scheduler
   constraint path (control-plane change, not host mutation).
4. If regional: shed create admission at the API (approval: control-plane
   on-call). Prefer rejecting new creates over mutating hosts.
5. Stuck exec: treat the command as failed at the API; do not kill the guest.
   Destroy only through the control-plane destroy path if the sandbox is
   `is_stuck` past timeout.

## Escalation

- Page Runtime if `reason` is `backend` or `protocol` on more than one host
  in 15m.
- Page Networking if `reason=network` is cell-wide.
- Page Image Pipeline if `reason=image` follows a promotion.
- Page SRE lead if two cells in the same region burn create/boot together.
- Jump to [host-quarantine](host-quarantine.md) when
  `pico_quarantine_hosts_quarantined > 0`.

## Rollback

1. Re-enable admission or backend placement only after `boot_ready` /
   `create_completed`/exec `succeeded` return to the pre-incident baseline
   for 15m on the affected cell.
2. Do not manually resolve quarantine to force placement. Let the condition
   clear, or follow [host-quarantine](host-quarantine.md).
3. If API admission was shed, restore the previous admission limit and watch
   p95 on **Boot & Prepare Latency**.

## Related

- [control-plane](control-plane.md), [runtime-backend](runtime-backend.md),
  [image-cache](image-cache.md), [host-quarantine](host-quarantine.md)
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
