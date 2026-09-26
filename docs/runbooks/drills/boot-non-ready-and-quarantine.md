# Drill: Boot Non-Ready and Host Quarantine

**Owner**: SRE-PicoCompute
**Runbooks**: [lifecycle-operations](../lifecycle-operations.md),
[runtime-backend](../runtime-backend.md),
[image-cache](../image-cache.md),
[networking](../networking.md),
[host-quarantine](../host-quarantine.md),
[cleanup-reconciliation](../cleanup-reconciliation.md)
**Alert category**: `regional_lifecycle_failure`, `host_quarantine`, `cleanup_drift`

Tabletop by default. A live drill that drains or restarts a host needs SRE
lead approval and is out of scope for the first pass.

## Objectives

1. Split `boot_not_ready` by `reason` (`image`, `network`, `backend`,
   `protocol`) without SSHing.
2. Follow quarantine first checks for a single bad host, then for cell-wide
   fire.
3. Refuse unapproved host mutation (no un-fenced cleanup, no ledger edits).
4. Record findings back into the owning runbook.

## Participants

SRE (facilitator), Runtime, Networking, Image Pipeline, Observability,
Control Plane. Security joins if inject 4 is used.

## Preconditions

- Grafana folder `PicoCompute` loads all dashboards.
- Loki/Tempo (or equivalent) can filter `event="boot_not_ready"`.
- Alert rules in `o11y/rules/pico-recording-rules.yaml` are provisioned
  in the drill environment, or the facilitator injects the alert payload.
- No production host mutation.

## Inject 1: Image non-ready (15m)

Facilitator states: after digest promotion `sha256:dead...`, cell `cel_east`
shows `pico_boot_events_total{event="boot_not_ready",reason="image"}`
rising. Other reasons are flat. Placement efficiency is normal.

**Expect**

- First checks on `pico-lifecycle-operations`, then
  [image-cache](../image-cache.md).
- Mitigation: stop promotion, pin last known-good digest from control
  plane. No host pull, no signature bypass.
- Escalation: Image Pipeline. Security only if verification failed.

## Inject 2: Protocol non-ready on one host (15m)

Facilitator states: host `hst_01` has consecutive `reason=protocol` boots.
`pico_quarantine_hosts_quarantined=1`. Other hosts `boot_ready`.
`PicoComputeHostQuarantined` is firing.

**Expect**

- [lifecycle-operations](../lifecycle-operations.md) reason table ->
  [runtime-backend](../runtime-backend.md) ->
  [host-quarantine](../host-quarantine.md) `repeated_runtime_outcomes`.
- First checks use `event`/`reason`, not `outcome="runtime_failed"`.
- Mitigation: leave quarantined. No `POST /rpc/v1/drain` without approval.
- No `pico-cli quarantine resolve` (not shipped). Auto-resolve is 120s
  after the condition clears.

## Inject 3: Cleanup review-required (15m)

Facilitator states: same host now has `pico_gc_review_required` and
`network_reconciliation_review_required`. Orphans detected, none removed.

**Expect**

- [cleanup-reconciliation](../cleanup-reconciliation.md): stop deleting.
- `requires_review` is not "retry rm".
- Fenced cleanup only with a ticket and fencing tokens.
- Rollback: host stays quarantined until a later reconciliation pass is
  clean.

## Inject 4 (optional): Cell-wide fire (10m)

Facilitator states: `PicoComputeHostAlertFiringRateHigh` and three hosts in
`cel_east` quarantined. Audit outbox pending is also climbing.

**Expect**

- Do not restart every host-agent.
- Split [audit-telemetry](../audit-telemetry.md) vs runtime.
- Page SRE lead; shed admission rather than mutate hosts.

## Pass criteria

- Reason split for image vs protocol vs network vs backend
- Telemetry before SSH
- No unapproved drain, restart, GC, or ledger edit
- Quarantine rollback does not use a fake CLI
- At least one runbook patch filed from a finding (or an explicit
      "no change" note)

## Candidate profile and revision (2026-09-21)

Tabletop only. No host mutation was performed. The facilitator host cannot
run a live backend walk (Darwin arm64, no `/dev/kvm`, no VMM binaries), so
all injects below use the documented signals and the current code paths.

| Field | Value |
|---|---|
| Date | 2026-09-21 |
| Source revision | `ad4377d3c8ba3bd5ee51cbb1db5b58f61ef64521` |
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Backends | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop-only profiles |
| Host profile | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Network | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway |
| Credential mode | Short-lived scoped leases with revoke-first destroy |
| Snapshot mode | Sandboxd-owned `Restore` and `Fork` RPC path with fresh authority on restore/fork |
| Telemetry | `o11y/rules/pico-recording-rules.yaml` plus `PicoCompute` Grafana folder; durable audit outbox as authoritative record |

Evidence commands rerun for this revision:

- `scripts/validate-o11y-dashboards.sh` - pass, all dashboards and runbook links resolve
- `cargo nextest run -p pico-core --lib host_quarantine availability` - 59 passed
- `cargo nextest run -p pico-core --test control_plane_readiness destroy_revokes_all_sandbox_leases` - pass
- `cargo nextest run -p pico-host-agent --test secrets_integration` - 5 passed

## Drill results (2026-09-21)

| Date | Inject | Outcome | Signals checked |
|---|---|---|---|
| 2026-09-21 | 1 - Image non-ready | Pass with gaps | `pico_boot_events_total{event="boot_not_ready",reason="image"}` split on `pico-lifecycle-operations`; `pico_prepare_events_total` and prepare latency on `pico-image-cache`; platform log `outcome=image_unavailable`; audit promotion and verification events |
| 2026-09-21 | 2 - Protocol non-ready on one host | Pass with gaps | `pico_boot_events_total{event="boot_not_ready",reason="protocol"}` clustered on `hst_01`; `pico_quarantine_hosts_quarantined=1`; `PicoComputeHostQuarantined` firing after 1m; `repeated_runtime_outcomes` condition; `pico-host-health` and `pico-scheduling-capacity` exclusion |
| 2026-09-21 | 3 - Cleanup review-required | Pass with gaps | `pico_gc_review_required` and `network_reconciliation_review_required`; orphans detected with zero removed; `cleanup_disposition` audit as authoritative record; quarantine condition `cleanup_or_reconciliation_issue` |
| 2026-09-21 | 4 - Cell-wide fire with audit backlog | Pass with gaps | `PicoComputeHostAlertFiringRateHigh` with three hosts quarantined in `cel_east`; `pico_audit_outbox_pending` climbing; split of `pico-audit-telemetry` vs runtime per host-quarantine first checks; admission shed path |
| 2026-09-22 | 1 - Image non-ready (rerun) | Pass | Replay against updated signals: `pico_image_prepare_latency_seconds{cache_result="unknown",image_profile="unknown"}` live on **Image Prepare Latency by cache_result**; hit/miss/eviction and verify/overlay panels read as empty-with-fallback per [image-cache](../image-cache.md); `boot_not_ready{reason="image"}` split, prepare events, `outcome=image_unavailable` logs, prepare traces, promotion/verification audit. See [image-cache-inject-1-rerun-2026-09-22](image-cache-inject-1-rerun-2026-09-22.md). Hit-filtered rules and both image-cache alerts honestly silent (no fabricated ratios). |

What the team did right:

- Split by `event`/`reason` before any host access on every inject.
- Left the single bad host quarantined and refused `POST /rpc/v1/drain`, un-fenced GC, ledger edits, and signature bypass without approval.
- Used `cleanup_disposition` and `host_disabled` audit events as the recovery record, not log text.
- Correctly refused the fake `pico-cli quarantine resolve` path and waited for the 120s auto-resolve condition.

Gaps found (owners in Findings log):

- Image-cache hit/miss/eviction panels are not emitted until host image cache work lands, so inject 1 relies on prepare events, logs, and traces until then. Update 2026-09-22: partially closed. `pico_image_prepare_latency_seconds` with `unknown` cache labels is now live from the prepare path and cited in the [2026-09-22 inject-1 rerun](image-cache-inject-1-rerun-2026-09-22.md); hit/miss/eviction and verify/overlay panels remain honestly empty with a documented fallback and expiry on host image-cache work (BSD-184). No fabricated ratios.
- Manual quarantine acknowledge/resolve and fenced cleanup have no shipped CLI. The in-process `AlertStateManager` API exists and is unit-tested, but the operator path needs a ticket plus fencing-token evidence and has no un-drain helper in the public CLI.
- Tenant notification has no template, owner, or timing in the runbooks. Escalation pages owners correctly but does not define tenant notice.
- Host rebuild is approval-only (SRE lead plus infra) with no tested step-by-step rebuild procedure in the runbooks. The patch/rebuild exercise for unknown VMM/kernel/firmware/hardware escape remains separate backlog work.
- The G-13 link in Related pointed at a non-existent `..../security/production-readiness.md` path. Fixed in this change.

Runbook patch in this change: fix the Related production-readiness link. No other runbook check text changed; the remaining gaps above are recorded as follow-ups instead of silent edits.

## Findings log

| Inject | What broke in the runbook | Follow-up |
|---|---|---|
| 1 | Image-cache hit/miss/eviction signals missing on current build; first checks fall back to prepare events/logs/traces | Image Pipeline and Observability: emit host image-cache metrics or document the fallback panels and expiry. Resolved 2026-09-22: live `unknown`-labeled image prepare latency plus explicit empty-with-fallback doc in [image-cache](../image-cache.md); rerun [image-cache-inject-1-rerun-2026-09-22](image-cache-inject-1-rerun-2026-09-22.md). Full hit/miss/eviction/verify/overlay awaits host image-cache work. |
| 2 | No shipped CLI for manual quarantine acknowledge/resolve; no un-drain helper in public CLI | SRE and Runtime: document the approved in-process acknowledge/resolve and drain/undrain operator path with approval evidence |
| 3 | Fenced cleanup path is ticket plus fencing tokens with no shipped CLI helper | SRE, Runtime, and Networking: define the fenced cleanup operator procedure or ship the minimal approved helper |
| 4 | Cell-wide fire plus audit backlog has no combined triage view; tenant notification path is undefined | Observability and SRE: keep the audit-vs-runtime split and add a tenant-notification section with owner and timing; SRE lead owns the admission-shed decision |

Facilitator files findings as comments on or a follow-up issue and
patches the runbook in the same change when the check is wrong.

## Related

- [README](../README.md) host mutation policy
- test plan: tabletop + this drill
- G-13 in [production-readiness](../../security/production-readiness.md)
- Incident tabletop record: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md)
