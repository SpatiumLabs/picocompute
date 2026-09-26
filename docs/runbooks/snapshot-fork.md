# Snapshot Restore and Fork

**Owner**: Runtime/SRE-PicoCompute
**Alert category**: `regional_lifecycle_failure`, `capacity_exhaustion`
**Severity**: Page when restore/fork fails cell-wide; ticket while restore remains fail-closed
**Dashboards**: `pico-snapshot-fork`, `pico-image-cache`, `pico-lifecycle-operations`

## When to use

Snapshot restore, resume, or fork fails or is slow. Also CoW workspace
failures and snapshot GC skipping or deleting unexpectedly.

## Current implementation note

`restore_from_snapshot` runs through the sandboxd-owned `Restore` RPC:
host-agent prepares the target sandbox and admits the command,
sandboxd validates tenant binding, lineage, compatibility, integrity, and
exclusion from trusted metadata before staging state. Filesystem restores
leave the sandbox ready to boot; memory restores leave it for resume. Fork
runs through the `Fork` RPC with independent child authority. Treat
`restore_failed` as expected for rejected snapshots (tampered, stale,
cross-tenant); page on `restore_partial_cleanup` or failing valid
snapshots after a release.

This runbook still applies to resume, quiesce, cache, CoW, and GC, and to
restore/fork once those paths emit success.

## Severity

| Condition | Level |
|---|---|
| Restore/fork errors after a release that claims the path is live | Page Runtime |
| `PicoComputeRestoreSaturated` (restore p99 > 1s while restores complete) | Ticket until live restore; page Runtime after the path is enabled |
| `PicoComputeRestorePartialCleanup` | Page Runtime; treat as a bad restore |
| Resume/quiesce failures clustered on one host | Quarantine |
| Cache miss/eviction with boots still succeeding | Ticket |
| Snapshot GC deleting ref-held artifacts | Page Runtime |

## First checks

1. `pico-snapshot-fork` -> **Fork Volume**/**Resume & Restore Volume**,
   **Restore Latency by Snapshot Type/Cache Tier**, and **Restore
   Saturation**.
2. Events: `pico_restore_events_total` (`restore_started`,
   `restore_completed`, `restore_failed`, `restore_memory_restored`,
   `restore_partial_cleanup`) and `pico_fork_events_total`.
3. **CoW Workspace Activity** (`started`/`completed`/`failed`) and **Shared
   vs Private Bytes**.
4. **Snapshot GC Candidates/Activity** (`gc_deleted`, `gc_skipped_ref`,
   `gc_skipped_retention`).
5. `pico-image-cache` hit/miss/eviction. Restore SLO depends on cache.
6. Compatibility failures belong here, not in [image-cache](image-cache.md):
   backend/CPU/resource-shape mismatch, integrity mismatch, blob missing.

Do not copy snapshot blobs onto a host. Do not delete snapshot objects to
"make GC catch up".

## Logs, traces, audit

**Logs**

```
{service_name="pico-host-agent"} | json | event=~"restore_.*|fork_.*|quiesce_.*|resume_.*"
```

**Traces**

`restore_from_snapshot`, `resume`, `suspend`, runtime `prepare`/`boot`.
Fork views may be stubs.

**Audit**

`snapshot_operation` for create/restore/fork/integrity.
`snapshot_metadata_access` for metadata reads. `lifecycle_transition` for
the resulting state. Integrity mismatch is a security-relevant event.

## Mitigation

1. Restore saturation (`PicoComputeRestoreSaturated`): stop additional restore
   admission; shed with `unavailable`. Do not raise
   `max_concurrent_restores` without a new report.
2. Fail-closed restore: do not bypass sandboxd. Route workload to cold
   boot if product allows.
3. Integrity or missing blob: stop using that snapshot ID. Page Storage
   and Security. Do not restore "best effort".
4. Incompatible shape: fail the request; do not place onto a different
   backend to make it fit.
5. Partial restore (`restore_partial_cleanup`): leave the host for
   [cleanup-reconciliation](cleanup-reconciliation.md). Do not reuse the
   workspace.
6. Fork failure: the child must not inherit leases, credentials, or port
   forwards. Destroy the child through control plane if it exists.

## Escalation

- Page Runtime if restore/fork was enabled and is failing.
- Page Security on integrity mismatch or unexpected metadata access.
- Page SRE if CoW/GC pressure fills host disk ([host-health](host-health.md)).

## Rollback

1. Disable restore/fork admission if a new release broke the path.
2. Revert the snapshot-manager or sandboxd rollout.
3. Confirm resume/boot success and that GC `skipped_ref` still protects
   live snapshots.

## Related

- [image-cache](image-cache.md)
- [lifecycle-operations](lifecycle-operations.md)
- [cleanup-reconciliation](cleanup-reconciliation.md)
- ADR-0007 snapshot/resume/fork consistency
