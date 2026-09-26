# Runtime Backend and Guest Agent

**Owner**: Runtime/SRE-PicoCompute
**Alert category**: `regional_lifecycle_failure`
**Severity**: Page when a backend or guest handshake fails across hosts; quarantine one bad host
**Dashboards**: `pico-runtime-backend`, `pico-lifecycle-operations`, `pico-host-health`

## When to use

Boot is `boot_not_ready` with `reason=backend` (VMM/runtime start) or
`reason=protocol` (guest-agent transport, auth, or handshake). Also suspend,
resume, quiesce, or resume-notify failures.

## Severity

| Condition | Level |
|---|---|
| `backend` or `protocol` on many hosts in one cell | Page Runtime |
| Same reasons on one host, other hosts healthy | Quarantine ([host-quarantine](host-quarantine.md)) |
| Resume/quiesce latency only, boots still ready | Ticket |
| `pico_network_health_state` unsafe on the host | Quarantine |

## First checks

1. `pico-lifecycle-operations` **Operation Volume by Phase**:
   `pico_boot_events_total{event="boot_not_ready",reason="backend|protocol"}`.
2. Filter `backend` template (`firecracker`, `qemu`, `gvisor`).
3. `pico-runtime-backend` -> **Network Health State**
   (`pico_network_health_state`: 0 ready, 1 degraded, 2 unsafe).
4. **Suspend/Resume/Quiesce** latency and **Resume Notify Events**.
   Notify outcomes: `resume_notify_accepted`, `resume_notify_stale_epoch`,
   `resume_notify_session_mismatch`, `resume_notify_resources_unavailable`,
   `resume_notify_failed`.
5. `pico-host-health` cgroup OOM/setup errors on the same host.

Guest handshake: retryable timeout is `Timeout`; terminal
proof/version/identity rejection is `Protocol`. Default boot budget is 60s.

Do not attach to the VMM. Do not restart `sandboxd` without approval.

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | event="boot_not_ready" | reason=~"backend|protocol"
```

Platform `outcome` is `runtime_start_failed` or `protocol_error`.

**Traces**

`boot_sandbox` -> runtime adapter `boot` -> guest protocol. Handshake
failures end before `ready`. Span attribute `backend` is bounded.

**Audit**

`runtime_outcome` for start/stop/suspend/resume. `lifecycle_transition` to a
non-ready state.

## Mitigation

1. One host: leave quarantined/out of placement. Do not pick a weaker
   backend for new work.
2. One backend cell-wide: stop placing that backend (control-plane
   constraint). Keep other backends.
3. Protocol/version skew after a guest-agent rollout: halt the rollout.
   Do not mix protocol versions on new boots.
4. Resume notify `stale_epoch`/`session_mismatch`: fail the resume; do
   not reuse the old session. Destroy through control plane if stuck.
5. Approved `sandboxd` restart is host mutation and drops in-memory guest
   sessions. Expect quarantine until reconciliation.

## Escalation

- Page Runtime if two hosts fail `backend`/`protocol` within 15m.
- Page SRE lead if the only healthy backend in the cell is also failing.
- Jump to [networking](networking.md) if health state is unsafe but boot
  reason is `network`, not `backend`.

## Rollback

1. Revert the runtime or guest-agent rollout that coincides with the start
   of `boot_not_ready`.
2. Re-enable backend placement after `boot_ready` baseline holds 15m on the
   affected cell and backend.
3. Do not resolve quarantine to test a fix.

## Related

- [lifecycle-operations](lifecycle-operations.md)
- [host-quarantine](host-quarantine.md)
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
