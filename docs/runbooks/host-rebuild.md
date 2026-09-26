# Host Rebuild

**Owner**: SRE-PicoCompute with Runtime and Release
**Alert category**: `host_quarantine`, `cleanup_drift`, `resource_pressure`
**Severity**: Quarantine by default; page when drift is cell-wide or a suspected escape needs emergency handling
**Dashboards**: `pico-host-health`, `pico-scheduling-capacity`, `pico-cleanup-reconciliation`, `pico-lifecycle-operations`

## When to use

Rebuild is the last step after quarantine, cordon, drain, revoke, and fenced
cleanup have been tried or ruled out. Use this runbook when one of these holds:

- Cleanup reconciliation leaves review-required or stale leftovers that
  survived the retry budget on one host, and the owning runbook says to
  rebuild only with a reviewed ticket.
- Leftovers span hosts or cells, or ownership is ambiguous after host loss
  with expired leases and a partitioned capacity report.
- A suspected VMM, KVM, kernel, firmware, or hardware escape requires
  the host to return only from a known-good build, not from local repair.
- Host-agent, `sandboxd`, or network state cannot reach a clean
  reconciliation pass and the host cannot safely admit again.

Do not rebuild for a single GC pass that removes its own orphans, for
pressure alone without residual authority, or for image-only failures that
resolve by pinning a known-good digest. Those paths stay in
[cleanup-reconciliation](cleanup-reconciliation.md),
[host-health](host-health.md), [scheduling-capacity](scheduling-capacity.md),
and [image-cache](image-cache.md).

## Severity

| Condition | Level |
|---|---|
| One host needs rebuild after a clean quarantine with no tenant impact | Quarantine |
| Rebuild host carried tenant sandboxes, or re-placement changes behavior | Quarantine with tenant notice per [README](README.md#tenant-notification) |
| Review-required or stale resources on more than one host in 30m | Page SRE lead |
| Suspected VMM or kernel escape, or cell-wide admission shed | Page SRE lead and Security |

## Preconditions

- Incident ticket exists with host, cell, region, reason, and candidate
  source revision. No rebuild without a reviewed ticket.
- The host is already quarantined or excluded from placement. Confirm
  `pico_quarantine_hosts_quarantined > 0` for the host or scheduler
  exclusion in **Hosts Evaluated vs Passed Constraints** before any drain.
- Cell has headroom to lose the host for the full drain plus rebuild window.
  If more than 20 percent of cell hosts are stale or draining, page SRE lead
  and shed admission first per [scheduling-capacity](scheduling-capacity.md).
- Tenant notice channel is ready when the host carried tenant sandboxes.
  Owner paging per Escalation below is not tenant notice.
- Audit outbox is healthy enough to record the sequence. If
  `pico_audit_outbox_pending` climbs with dead-letter growth, treat that
  as a parallel incident per [audit-telemetry](audit-telemetry.md) and block
  security-sensitive mutation while delivery fails.

## Approval gates

| Step | Approval required | Evidence in ticket |
|---|---|---|
| Cordon (scheduler exclusion) | SRE on-call | Host, reason, exclusion source, time |
| Drain RPC (`POST /rpc/v1/drain`) | SRE on-call | Sandbox count, natural-drain wait, RPC time, operator |
| Restart host-agent, `sandboxd`, or metrics-agent | SRE on-call | Component, reason, pre-restart health |
| Fenced cleanup or GC before rebuild | SRE on-call and incident ticket with fencing-token evidence | Tokens, receipts, reconciliation pass result |
| Rebuild host image | SRE lead and infra | Ticket review, approved build, digest, time window |
| Rebuild for suspected escape | SRE lead and infra and Security | Advisory or integrity signal, quarantine scope, patch source |
| Re-admit host to placement | SRE on-call | Re-admit checks below with timestamps and the 5m watch |

Read telemetry is unapproved. `journalctl` and `dmesg` are read-only and
follow telemetry, never precede it. Every mutation row above needs its
approval before the command runs. Silence is not approval.

## First checks

1. `pico-host-health` -> **Active Sandbox Count per Host** and
   **Draining Hosts**. A missing series is stale telemetry, not zero load.
2. `pico-scheduling-capacity` -> placement exclusion for the host and
   remaining cell headroom. Inventory drops a host after 60s without a
   capacity report; quarantine staleness fires after 120s.
3. `pico-cleanup-reconciliation` -> **GC Review Required**,
   **Orphans Detected vs Removed**, **Network Review Required**, and
   reconciliation health. A clean pass is zero orphans and zero
   review-required.
4. `pico-lifecycle-operations` -> `boot_not_ready` by `reason` and exec
   `failed` or `timed_out` clustered on the host.
5. Quarantine gauges: `pico_quarantine_hosts_quarantined` and alert
   condition (`repeated_runtime_outcomes`, `cleanup_or_reconciliation_issue`,
   `stale_resources`, `capacity_reporting_staleness`, `resource_pressure`).

**Logs**

```
{service_name="pico-host-agent"} | json | host_id="<host>"
{service_name=~"pico-host-agent|pico-network-agent|pico-sandboxd"} | json | event=~"gc_.*|reconcil.*|cleanup.*"
```

**Traces**

In-flight `host_agent_rpc` with `create`, `boot_sandbox`, `exec`, `destroy`,
and reconciliation spans on that `host_id`. Absence of new spans with a
healthy outbox elsewhere means the agent is not running.

**Audit**

`host_disabled`, `cleanup_disposition`, `runtime_outcome`,
`lifecycle_transition`, `placement_outcome`, `LeaseRevoked`,
`network_enforcement`, `snapshot_operation`. Preserve these records. Never
edit the `sandboxd` ledger by hand, never delete local state to clear an
alert, and never replay dead-letters as deletes.

## Mitigation

Cordon/drain/rebuild/re-admit in order. Do not skip quarantine confirm and
do not rebuild without a reviewed ticket.

### 0. Confirm quarantine and open the ticket

1. Confirm the host cannot admit: scheduler health is not `Healthy` or
   `Degraded`, or the quarantine gauge is nonzero for the host.
2. Open or update the incident ticket with host, cell, region, trigger
   (orphan class, span, or suspected escape signal), sandbox count, and
   source revision.
3. Page per [Escalation](#escalation). Notify affected tenant owners per
   [README](README.md#tenant-notification) when the host carried tenant
   sandboxes or re-placement changes behavior.

### 1. Cordon

Cordon is scheduler exclusion, not host mutation.

1. Exclude the host from placement through the control-plane scheduler path.
   Do not fix fencing on the host.
2. Confirm exclusion on `pico-scheduling-capacity`: the host leaves
   **Hosts Evaluated vs Passed Constraints** while peers stay stable.
3. Record cordon time and source in the ticket. Cordon needs SRE on-call
   approval when done by hand rather than by automatic quarantine.

Rollback: if exclusion does not take effect or peers also drop, stop. Suspect
telemetry, inventory, or a bad rollout per [host-health](host-health.md) and
[host-quarantine](host-quarantine.md). Do not proceed to drain.

### 2. Drain

Prefer natural completion. Drain RPC is mutation with bearer auth and needs
SRE on-call approval.

1. Record sandbox count and let running sandboxes finish where the incident
   allows it.
2. Only with approval, run `pc operator drain` to the existing
   `POST /rpc/v1/drain` on the host-agent for the affected host, then
   `pc operator drain-status` for the watch.
3. Watch `pico_host_draining > 0` and **Active Sandbox Count per Host**
   until the count reaches zero or the approved window expires.
4. Record drain start, approval, sandbox count at start, and drain end in the
   ticket. There is no un-drain helper by design; re-admit follows
   [step 7](#7-re-admit) only with `pc operator readmit-check`.

Rollback: if the count does not fall, if new placement still lands on the
host, or if cell headroom collapses, stop the drain. Keep the host cordoned
and quarantined, shed admission per
[scheduling-capacity](scheduling-capacity.md), and page SRE lead. Do not
raise overcommit and do not kill guests outside drain or destroy.

### 3. Revoke and isolate

1. Confirm all sandbox leases for destroyed sandboxes are revoked with
   operation identity. Foreign-sandbox leases survive per the destroy-path
   contract.
2. Revoke live leases bound to the host where the credential owner requires
   it, rotate downstream credentials, and revoke egress leases with mapping
   removal through the control-plane path. Do not flush NAT by hand.
3. Isolate suspect network namespaces per [networking](networking.md) and
   quarantine suspect snapshot artifacts per
   [snapshot-fork](snapshot-fork.md). Never reuse a sandbox identity,
   network address, or path before absence is proven.

Rollback: if revocation audit (`LeaseRevoked`, `network_enforcement`) does
not appear, or if audit delivery is failing, stop. Block further
security-sensitive mutation until delivery recovers per
[audit-telemetry](audit-telemetry.md).

### 4. Freeze evidence

1. Keep `host_disabled`, `cleanup_disposition`, `placement_outcome`,
   `runtime_outcome`, `lifecycle_transition`, and revocation audit events
   for the full cordon/drain/revoke window.
2. Preserve the quarantined blob, orphan receipts, and fencing tokens for
   review instead of deleting them.
3. Record audit event IDs in the ticket. Log text is not the recovery record.

### 5. Rebuild

Rebuild returns the host from the approved build pipeline, never from local
repair or hand copies. Do not rebuild images on the host and do not copy
layers by hand onto a host per [image-cache](image-cache.md).

1. Confirm rebuild approval in the ticket: SRE lead and infra, with Security
   added for suspected escape.
2. Rebuild the host from the approved host image and pinned release
   artifacts through the infra pipeline. Record build, digest, and window.
3. For suspected escape, include the approved patch source in the ticket and
   keep the host out of placement until verification passes. Patch selection
   and advisory intake details stay with the vulnerability response path;
   this runbook records only the build that was applied and its approval.
4. Do not reclassify `requires-review`, `confirmed-owned`, or `safe-to-remove`
   from the host during rebuild.

Rollback: if the pipeline cannot produce a pinned build, if digests do not
match promotion, or if verification fails, keep the host quarantined and out
of placement. Page Release and Image Pipeline. Do not admit best-effort
state and do not restore from a suspect snapshot.

### 6. Verify

1. Confirm host-agent health `ready` or `degraded` and scheduler health
   `healthy` or `degraded`. Only those states admit new work.
2. Confirm capacity reports are fresh (under 60s) and the host reappears in
   **Hosts Evaluated**.
3. Run another reconciliation pass: zero orphans and zero review-required on
   the host, with network reconciliation healthy.
4. Confirm `boot_ready` baseline can place test workload per the owning
   lifecycle path before tenant work returns. Record each check with
   timestamps.

Rollback: any failed check keeps the host out of placement. Keep it
quarantined, file the failure back into the ticket, and return to the owning
runbook. Do not resolve the quarantine alert to test verification.

### 7. Re-admit

Re-admit needs SRE on-call approval with all checks below recorded.

1. Confirm `pico_quarantine_hosts_quarantined` is 0 for the host.
2. Confirm capacity age under 60s and health in an admitting state.
3. Confirm the clean reconciliation pass from step 6 with zero orphans and
   zero review-required.
4. Watch for 5m with no new quarantine alert on that host before closing
   re-admit. Any new alert returns the host to quarantine and reopens the
   ticket.
5. Record re-admit time, approver, and the 5m watch window in the ticket.

### 8. Close

1. Send tenant close notice with recovery confirmation and the re-admit
   checks that passed, per [README](README.md#tenant-notification).
2. Record in the ticket: cordon/drain/rebuild/re-admit times, approvals,
   sandbox counts, verification results, the 5m watch outcome, tenant
   notices sent, and audit event IDs.
3. File follow-ups for slow paths, manual interventions, or missing signals
   instead of silent edits.

## Escalation

- Page SRE if review-required lasts more than 1h on one host.
- Page SRE lead if resources span hosts or cells, if cell headroom cannot
  cover the rebuild window, or before any rebuild approval.
- Page infra for the rebuild itself and for persistent hardware pressure.
- Page Security for suspected VMM, kernel, firmware, or hardware escape, for
  verification mismatch, and for dead-letter replay.
- Page Networking when only network reconciliation stays unhealthy.
- Page Runtime when cgroup setup errors follow a kernel or runtime rollout.
- Page Observability when audit or metrics pipelines also go stale.
- Never clear a page by acknowledging without a condition owner.

## Rollback

| Phase | Abort and keep quarantined when |
|---|---|
| Cordon | Exclusion does not take effect, or peers also drop |
| Drain | Count does not fall, new placement still lands, or headroom collapses |
| Revoke | Revocation audit is missing, or audit delivery fails |
| Rebuild | No pinned build, digest mismatch, or verification failure |
| Verify or re-admit | Any health, capacity, orphan, review-required, or quarantine check fails, or a new alert fires in the 5m watch |

After an approved fenced cleanup that made things worse, stop and keep the
host quarantined. After a failed rebuild, keep the host out of placement and
do not admit best-effort state. Do not call `AlertStateManager::resolve`
just to restore capacity. Resolve only when the condition is gone and the
approved owner re-admits the host.

## Tenant notification

Tenant notice follows [README](README.md#tenant-notification). Notify the
affected tenant owner when the rebuilt host carried that tenant sandboxes or
when re-placement changes behavior. Rebuild of an empty host is owner-only.
Each notice uses the per-tenant template with scope, user-visible impact,
action taken, tenant action, next update, contact, and audit refs, and the
ticket records send time with the underlying audit event IDs. Never include
secrets, commands, paths, workload output, raw errors, another tenant
identity, registry credentials, or snapshot blob locations.

## Audit record

The ticket must hold the full sequence: quarantine evidence, cordon source
and time, drain approval with sandbox counts and window, revocation IDs,
frozen evidence IDs, rebuild approval with build and digest, verification
results, re-admit approval with the 5m watch outcome, tenant notices, and
the durable audit event IDs for each step. Query the durable audit store by
`event_kind` with `operation_id`, `trace_id`, `sandbox_id`, or `lease_id`.
Dead-letter replay needs Security review and never deletes the source outbox
row.

## Host mutation

| Action | Approval |
|---|---|
| Read dashboards, logs, traces, audit | none |
| `journalctl` and `dmesg` | none (read-only, after telemetry) |
| Scheduler exclusion (cordon) | SRE on-call when manual |
| `POST /rpc/v1/drain` | SRE on-call |
| Restart host-agent, `sandboxd`, or metrics-agent | SRE on-call |
| Fenced cleanup or GC | SRE on-call and incident ticket with fencing-token evidence |
| Rebuild host | SRE lead and infra, with Security for suspected escape |
| Re-admit host | SRE on-call with recorded checks and 5m watch |

Prohibited without a reviewed incident ticket: editing the `sandboxd` ledger
by hand, killing guests outside drain or destroy, deleting cgroups, netns,
taps, or workspaces without fencing tokens, replaying audit dead-letters
without Security review, and attaching high-cardinality tenant or sandbox
labels to metrics.

## Coordination with the residual-risk emergency exercise

The residual-risk register keeps an emergency drain, revoke, rebuild, and
patch capability for unknown VMM, kernel, firmware, or hardware escape with
its own dated exercise record
([patch-rebuild-emergency-2026-09-22](drills/patch-rebuild-emergency-2026-09-22.md)).
That exercise owns advisory intake, patch selection, boundary validation for
the exact profile, and time-to-drain plus
time-to-rebuild SLO evidence. This runbook owns the mechanical
cordon/drain/rebuild/re-admit path used by any rebuild, including that
emergency. A rebuild done here cites the approved build and keeps the host
out of placement until verification passes, but does not duplicate patch
triage or the full boundary suite. When both run together, record timings
once and reference the shared ticket from both records.

## Related

- [README](README.md) host mutation policy and tenant notification
- [host-quarantine](host-quarantine.md), [host-health](host-health.md),
  [cleanup-reconciliation](cleanup-reconciliation.md),
  [scheduling-capacity](scheduling-capacity.md),
  [lifecycle-operations](lifecycle-operations.md)
- [networking](networking.md), [snapshot-fork](snapshot-fork.md),
  [audit-telemetry](audit-telemetry.md), [image-cache](image-cache.md)
- Alert rules: `o11y/rules/pico-recording-rules.yaml`
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
- Exercise: [host-rebuild-exercise-2026-09-21](drills/host-rebuild-exercise-2026-09-21.md)
- Emergency exercise: [patch-rebuild-emergency-2026-09-22](drills/patch-rebuild-emergency-2026-09-22.md)
