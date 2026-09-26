# Host Rebuild Exercise - 2026-09-21

**Owner**: SRE-PicoCompute with Runtime and Release
**Date**: 2026-09-21
**Source revision**: `c6b8d8150e3704957fd6a5b9a25cb871f612cfe7`
**Procedure**: [host-rebuild](../host-rebuild.md) cordon/drain/rebuild/re-admit path
**Prior record**: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4, gap G-02
**Ticket**: `INC-2026-09-21-04` (synthetic tabletop ticket)

Tabletop only. No host mutation, no drain RPC, no restart, no GC, no rebuild,
and no ledger edit was performed. All steps below were walked against the
current runbooks, alert rules, dashboards, and unit-tested code paths. Live
windows are estimates for planning, not measured live rebuild timings.

## Participants

- SRE owner as facilitator and rebuild approval owner
- Runtime owner for host, VMM, guest, and cleanup behavior
- Release and infra owners for the approved build pipeline
- Security owner for escape triage and evidence preservation
- Networking owner for namespace and egress lease scope
- Control-plane owner for scheduler exclusion, leases, and fencing
- Observability owner for telemetry, audit integrity, and tenant notice check

## Candidate profile

| Field | Value |
|---|---|
| Date | 2026-09-21 |
| Source revision | `c6b8d8150e3704957fd6a5b9a25cb871f612cfe7` |
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Region/cell/host | `region_test`/`cel_east`/`hst_01` with two peer hosts for headroom |
| Backend | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop-only profiles |
| Host image | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Guest image | Pinned digest `sha256:good...` |
| Network policy | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway, no ambient peer path |
| Credential mode | Short-lived scoped leases, mediation preferred, revoke-first destroy with `LeaseRevoked` audit |
| Snapshot mode | Sandboxd-owned `Restore` and `Fork` RPC path; tampered/stale/cross-tenant artifacts fail closed |
| Audit | Durable transactional outbox, `audit_delivery` events, dead-letter table as evidence |
| Telemetry | `o11y/rules/pico-recording-rules.yaml` plus `PicoCompute` Grafana folder |

Evidence commands rerun for this revision:

- `scripts/validate-o11y-dashboards.sh` - pass, all dashboards and runbook links resolve
- `cargo nextest run -p pico-core --lib host_quarantine availability` - 59 passed
- `cargo nextest run -p pico-core --test control_plane_readiness destroy_revokes_all_sandbox_leases` - pass

## Scenario replayed

From the prior tabletop scenario 4 (Tree 4, R-19/R-20/R-09/R-14):

- Initial: tenant `tnt_d` sandbox `sbx_21` on `hst_01` is destroyed through
  the control-plane path. Leases, routes, mappings, cgroups, netns, and
  workspace receipts are expected to reach absence with delayed reuse.
- Adversarial action: an operator attempts un-fenced `rm` of cgroups, netns,
  and workspaces to clear orphans quickly during on-call pressure.
- Independent failure: host loss on `hst_01` leaves unclassified orphan
  resources with expired leases and a partitioned capacity report.

The prior record walked rebuild only as a reviewed ticket without duration,
approval evidence, or re-admit checks. This exercise walks the merged
cordon/drain/rebuild/re-admit procedure step by step for that same host.

## Steps walked with duration

Total tabletop walk: 75m. Times below are facilitator timestamps for the
walk. Estimated live windows are planning estimates for a real rebuild of an
empty or drained host, not measured in this tabletop.

| Step | Tabletop walk | Estimated live window | What was checked |
|---|---|---|---|
| 0 - Quarantine confirm and ticket | 10m (09:00-09:10) | 5m | `pico_quarantine_hosts_quarantined` for `stale_resources`, scheduler exclusion, ticket `INC-2026-09-21-04` opened |
| 1 - Cordon | 5m (09:10-09:15) | 2m | Control-plane exclusion, **Hosts Evaluated vs Passed Constraints** drop for `hst_01`, SRE on-call approval recorded |
| 2 - Drain decision | 15m (09:15-09:30) | 15-30m natural, 5m with RPC | Sandbox count from `pico-host-health`, `pico_host_draining`, natural completion preferred, RPC approval path reviewed without calling it |
| 3 - Revoke and isolate | 10m (09:30-09:40) | 5m | Destroy revoke-all with operation identity, egress lease revoke with mapping removal, no NAT flush, no identity or address reuse before absence proof |
| 4 - Evidence freeze | 5m (09:40-09:45) | 2m | `host_disabled`, `cleanup_disposition`, `placement_outcome`, `LeaseRevoked`, `network_enforcement` IDs pinned in ticket |
| 5 - Rebuild walk | 15m (09:45-10:00) | 20-40m | Approved build pipeline path, no host-side image rebuild, no hand copy, digest and window recorded |
| 6 - Verify walk | 5m (10:00-10:05) | 10m | Health `ready` or `degraded`, capacity age under 60s, zero orphans with zero review-required, `boot_ready` baseline |
| 7 - Re-admit with 5m watch | 5m (10:05-10:10) | 5m watch plus checks | Quarantine gauge 0, clean reconciliation pass, 5m with no new alert, SRE on-call approval |
| 8 - Tenant notice and close | 5m (10:10-10:15) | Within 60m of confirmed impact | Rebuild notice for `tnt_d` filled and checked, ticket close fields reviewed |

No step relied on cooperation from the destroyed workload or the lost host
agent. Placement decisions used control-plane authority and fencing epochs.
The facilitator stopped the walk twice to refuse shortcut proposals: once
for un-fenced `rm` during drain discussion, and once for resolving the
quarantine alert to test verification. Both refusals match the merged
procedure rollback rules.

## Approval evidence

Synthetic tabletop approvals recorded in `INC-2026-09-21-04`:

- 09:10 - SRE on-call approved cordon for `hst_01` with reason
  `stale_resources` and scheduler exclusion source.
- 09:15 - SRE on-call approved drain plan: natural completion preferred,
  RPC held as fallback with sandbox count attached. RPC was not called.
- 09:30 - SRE on-call approved fenced review scope with fencing-token
  evidence requirement. No cleanup was executed live.
- 09:45 - SRE lead and infra approved rebuild walk with approved build
  reference and pinned digest placeholder. Security reviewed escape triage
  and agreed no separate emergency advisory applied to this host.
- 10:05 - SRE on-call approved re-admit pending the checks below, with the
  5m watch as a hard gate.

Each approval names the approver role, time, and scope. Silence was never
treated as approval. A live rebuild would need the same roles with real
signatures in the ticket before each mutation.

## Re-admit checks

Walked against the merged procedure with tabletop signal review:

- [x] Host health `ready` or `degraded` on host-agent and `healthy` or
  `degraded` on scheduler. Only those states admit new work.
- [x] Capacity reports fresh, age under 60s, host present in
  **Hosts Evaluated**.
- [x] Reconciliation pass shows zero orphans and zero review-required on
  `hst_01`, with network reconciliation healthy.
- [x] `pico_quarantine_hosts_quarantined` is 0 for `hst_01`.
- [x] 5m watch with no new quarantine alert on `hst_01`. The watch was
  walked as a timer review of the alert rules (`PicoComputeHostQuarantined`
  after 1m, unresolved alerts after 30m) with the agreement that any new
  alert returns the host to quarantine and reopens the ticket.
- [x] `boot_ready` baseline holds before tenant work returns.

Result: pass as tabletop. The 5m no-requarantine check is the gate that was
missing from the prior scenario 4 walk and is now recorded with timestamps
(10:05-10:10) and approver.

## Tenant notification check (rebuild row)

The prior tenant rerun exercised the revoke plus isolate rows. This exercise
covers the rebuild row for `tnt_d`, which had sandboxes on the rebuilt host.

Filled notice (synthetic example for `tnt_d` only):

```
Subject: [PicoCompute] rebuild notice for tnt_d in region_test/cel_east
Incident: INC-2026-09-21-04
Date: 2026-09-21 Revision: c6b8d8150e3704957fd6a5b9a25cb871f612cfe7
Scope (this tenant only): sandbox sbx_21 on hst_01, destroyed through control-plane path with delayed reuse
User-visible impact: sbx_21 stays destroyed; re-placement may delay new creates during cordon/drain/rebuild
Action taken: quarantined hst_01, cordoned from placement, approved drain plan, revoked leases with operation identity, rebuilt from approved build
Tenant action: retry new creates with backoff during rebuild window; rotate downstream credential derived from revoked leases
Next update: on mitigation change or within 4h during ongoing impact; close notice follows re-admit checks
Contact: SRE-PicoCompute via INC-2026-09-21-04
Audit refs: host_disabled for hst_01 exclusion; cleanup_disposition for quarantine disposition; LeaseRevoked with operation identity
```

Redaction check passed: no secret, token, boot secret, command, path,
workload output, raw error, other-tenant identity, registry credential, or
blob location in the notice. Only `tnt_d` scope is included. No
tenant/sandbox labels were attached to metrics. Timing target (initial
notice within 60m of confirmed user-visible impact) was reviewed as met for
tabletop, with owner paging immediate per the owning runbooks.

## Audit record for this exercise

- Ticket `INC-2026-09-21-04` holds cordon/drain/rebuild/re-admit times,
  approvals above, sandbox counts, verification results, the 5m watch
  outcome, the tenant notice above, and the underlying audit event IDs.
- Recovery evidence stays in the durable audit store keyed by `event_kind`
  with `host_id=hst_01` and the destroying operation identity for `sbx_21`.
- Dead-letter replay, if needed, requires Security review and preserves the
  source outbox row. The ledger was never edited by hand.

## Gap closure assessment for G-02

- Merged procedure: [host-rebuild](../host-rebuild.md) publishes
  cordon/drain/rebuild/re-admit steps with approval gates and rollback
  criteria, linked from the runbook index and the quarantine, health,
  cleanup, and capacity runbooks.
- Dated exercise: this record is dated 2026-09-21 with a 75m tabletop
  duration table, approval evidence with roles and timestamps, and a 5m
  no-requarantine re-admit check.
- Remaining scope: live drain, rebuild, and re-admit timings stay estimates
  until a staging rebuild measures them. No new procedure change is needed
  for closure; the follow-up is to record measured timings when a staging
  host rebuilds and reference the same ticket pattern.

## Coordination with the residual-risk emergency exercise

This exercise does not duplicate the residual-risk emergency exercise for
unknown VMM, kernel, firmware, or hardware escape. That backlog owns
advisory intake, patch selection, boundary validation for the exact profile,
and time-to-drain plus time-to-rebuild SLO evidence. This record covers the
mechanical rebuild path any host follows, cites the approved build without
re-triaging patch selection, and notes that a suspected escape would add
Security approval and keep the host out of placement until verification
passes. When that emergency runs, it can reference ticket
`INC-2026-09-21-04` as the mechanical path and add only advisory, patch, and
boundary evidence.

## Related

- Procedure: [host-rebuild](../host-rebuild.md)
- Runbook index: [README](../README.md)
- Prior scenarios: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4
- Drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md)
- Tenant template: [runbook index](../README.md#tenant-notification) and
  [tenant-notification-rerun-2026-09-21](tenant-notification-rerun-2026-09-21.md)
- Runbooks: host-quarantine, host-health, cleanup-reconciliation,
  scheduling-capacity, lifecycle-operations, networking, snapshot-fork,
  audit-telemetry, image-cache
