# Cleanup and Reconciliation

**Owner**: SRE-PicoCompute/Runtime/Networking
**Alert category**: `cleanup_drift`, `host_quarantine`
**Severity**: Quarantine when review is required; page when drift is cell-wide or stale resources persist
**Dashboards**: `pico-cleanup-reconciliation`, `pico-host-health`, `pico-networking`

## When to use

GC finds orphans, cleanup fails, reconciliation marks `requires_review`,
network rollback is incomplete, or quarantine condition
`cleanup_or_reconciliation_issue`/`stale_resources` is active.

## Severity

| Condition | Level |
|---|---|
| `pico_gc_review_required` or `network_reconciliation_review_required` | Quarantine |
| `pico_gc_orphans_detected` sustained >15m, or cleanup_failed rising | Page |
| Review required on >1 host in 30m | Page SRE lead |
| Single pass with orphans that are then removed | Ticket |

Destroy/GC already retries transient `EBUSY`/non-empty directories.
`requires_review` means a human decision is still required: fencing
conflict, unknown resource class, unparsable receipt, non-directory path,
or leftovers that survived the retry budget.

## First checks

1. `pico-cleanup-reconciliation` -> **GC Pass Duration**, **Orphans
   Detected vs Removed**.
2. **GC Review Required** and **GC Cleanup Failed** stats.
3. **Network Reconciliation Passes**, **Stale Objects & Cleaned**,
   **Reconciliation Health State**, **Network Rollback Completions**,
   **Network Review Required**.
4. `pico-host-health` draining and cgroup setup errors on the same host.
5. Quarantine gauges: `pico_quarantine_hosts_quarantined` and alert
   condition `cleanup_or_reconciliation_issue` or `stale_resources`.

Do not delete cgroups, netns, or workspaces. Do not run un-fenced GC.

## Logs, traces, audit

**Logs**

```
{service_name=~"pico-host-agent|pico-network-agent|pico-sandboxd"} | json | event=~"gc_.*|reconcil.*|cleanup.*"
```

**Traces**

Reconciliation and destroy spans. Ambiguous live resources should quarantine
rather than continue the delete.

**Audit**

`cleanup_disposition` is authoritative: cleanup, quarantine, or reviewed
disposition. `host_disabled` if the host was taken out of placement.
Preserve these records; do not replay them as deletes.

## Mitigation

1. Stop unsafe deletion. The correct default is quarantine, not cleanup.
2. Confirm the host cannot admit (`can_admit` is false). If it still admits,
   page SRE; do not fix fencing on the host.
3. Fenced cleanup uses the approved helper in [Operator procedure](#operator-procedure-approved-helper) with an incident ticket plus fencing-token evidence. `gc --force-stale` is not shipped as a `pico-cli` command. Any equivalent host RPC is mutation and needs the same ticket plus fencing-token evidence.
4. If receipts belong to live sandboxes, leave them. Mismatched fencing
   tokens are a control-plane bug, not a local rm.
5. Network `requires-review`/`confirmed-owned`/`safe-to-remove` must
   stay in that classification. Do not reclassify from the host.

## Operator procedure (approved helper)

Owner: SRE-PicoCompute with Runtime and Networking. This is the approved
in-process path for tabletop gap G-04. Validation lives in
`pico-core::operator`; the CLI prints ticket evidence and performs no
deletion itself.

Fenced cleanup (ticket plus fencing tokens, SRE on-call approval):

```
pc operator fenced-cleanup --ticket INC-123 --fencing-token 42.7,43.0
```

Tokens are `epoch.sequence` from control-plane authority. At least one
token is required; the helper fails closed without it. Record tokens,
receipts, and the reconciliation result in the ticket. If tokens mismatch
live leases, stop: that is a control-plane bug, not a local rm. Never run
un-fenced GC and never use a force-stale flag (not shipped by design).

Ledger inspect (read-only, ticket required):

```
pc operator ledger-inspect --ticket INC-123 --query sandbox-status --sandbox-id sbx_21
pc operator ledger-inspect --ticket INC-123 --query list-receipts --sandbox-id sbx_21
pc operator ledger-inspect --ticket INC-123 --query gc-stats
pc operator ledger-inspect --ticket INC-123 --query findings
```

Allowed queries only: `sandbox-status`, `list-sandboxes`, `list-receipts`,
`gc-stats`, `findings`. These map to the read-only ledger paths
(`sandbox_status`, `list_sandbox_statuses`, `list_receipts`, GC stats,
reconciliation findings). Ledger edits by hand remain prohibited. There is
no ledger write, delete, or edit flag in the helper.

Post-cleanup gate: another reconciliation pass must show zero orphans and
zero review-required before re-admit. Then follow the re-admit checklist in
[host-quarantine](host-quarantine.md#operator-procedure-approved-helper)
with SRE on-call approval and the 5m watch. Do not resolve the quarantine
alert to test cleanup.

## Escalation

- Page SRE if review-required lasts >1h on one host.
- Page SRE lead if resources appear to span hosts or cells.
- Page Networking if only network reconciliation is unhealthy.
- Continue at [host-quarantine](host-quarantine.md).

## Rollback

1. After an **approved** fenced cleanup: another reconciliation pass must
   show zero orphans and zero review-required before anyone re-admits the
   host.
2. Do not resolve the quarantine alert to test cleanup.
3. If cleanup made things worse, stop. Leave the host quarantined and
   rebuild only with a reviewed ticket per [host-rebuild](host-rebuild.md).

## Related

- [host-quarantine](host-quarantine.md)
- [networking](networking.md)
- [host-health](host-health.md)
- [host-rebuild](host-rebuild.md)
- Drill: [boot-non-ready-and-quarantine](drills/boot-non-ready-and-quarantine.md)
- Operator rerun: [quarantine-fenced-cleanup-rerun-2026-09-21](drills/quarantine-fenced-cleanup-rerun-2026-09-21.md)
