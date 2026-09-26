# Snapshot Restore sandboxd RPC Design

**Status**: Draft
**Date**: 2026-09-20
**Related**: assurance claim C-04, ADR-0007, ADR-0011, ADR-0002, G-10
**Prior**: `crates/pico-core/src/snapshot/restore.rs` validation hardening with `request_tenant` binding and exclusion gates

## Goal

Replace the fail-closed `HostAgent::restore_from_snapshot` stub (`crates/pico-host-agent/src/lib.rs:2128`) with a sandboxd-owned `Restore` RPC that implements the ADR-0007 restore contract end to end: fence, validate from trusted metadata, verify integrity, restore state via the runtime adapter, issue fresh authority, notify the guest, and persist a ledger outcome.

Host-agent keeps admission, fencing token issue, observation mirror, and port proxy. sandboxd owns the guest session, runtime handle, workspace, network attach, secrets inject, and ledger. This matches ADR-0011 sole RuntimeBackend ownership and the Interface 1 single-service model in `docs/design/sandboxd-host-rpc-design-twice.md`.

Non-goals for v1 wire: lazy memory loading, cross-backend restore, crash-consistent fallback, same-sandbox session reattach across daemon restart.

## Ownership map

| Concern | Owner | Notes |
|---|---|---|
| Admission, fencing token, policy epoch check, deadline | host-agent | Builds `CommandMeta`, validates tenant scope before RPC |
| Durable snapshot identity, lineage, retention | snapshot manager plus regional metadata store | sandboxd loads via `SnapshotRepository`; never trusts host-passed metadata alone |
| Operation fence, exec drain, step persistence, retry, rollback | sandboxd supervisor | Reuses `begin` plus `operation_gate` pattern from `suspend` and `resume` |
| Blob locate, integrity, decrypt, exclusion scan | sandboxd via `RestoreOrchestrator` | Core validation landed in the first slice; sandboxd reuses it verbatim |
| Workspace flush, freeze, COW branch, storage receipts | workspace implementation under sandboxd | ADR-0011 section 3; receipts in ledger |
| Backend pause, memory plus device restore | runtime adapter via `BackendRestoreContext` | `restore_snapshot` requires at least two blob paths for Firecracker today |
| Guest quiesce receipt check, `ResumeNotify` | guest agent via sandboxd-owned session | Host never dials guest directly |
| Network rebuild, DNS reattach | `NetworkAttachManager` plus `DnsAttachManager` | Ingress disabled by default; no flow inherit |
| Credential revoke plus reissue | `SecretsCoordinator` plus lease manager | No lease, credential, or port inherit; fork never inherits unless policy permits |

## Proto sketch

Wire truth remains `crates/pico-sandboxd-proto/proto/pico/sandboxd/v1/sandboxd.proto`. Sketch only.

```protobuf
// Shared host capability evidence for snapshot restore and fork.
// Adding a field touches HostShape once, not every Restore/Fork layer.
message HostShape {
  string backend_type = 1;
  string backend_version = 2;
  string protocol_version = 3;
  string cpu_arch = 4;
  uint32 memory_mb = 5;
  uint32 vcpus = 6;
  string machine_type = 7;
  uint64 disk_mb = 8;
}

message RestoreRequest {
  CommandMeta meta = 1;
  // Snapshot to restore from. Must be Ready and user-restorable.
  string snapshot_id = 2;
  // Tenant requesting restore. Must match snapshot tenant.
  // Redundant with HostResourceSpec tenant but explicit for audit.
  string request_tenant_id = 3;
  // True when caller needs memory profile. False is filesystem restore.
  bool requires_memory = 4;
  // Runtime family the host selected. Must match snapshot backend family.
  RuntimeType runtime_type = 5;
  // Host capability evidence for compatibility checks.
  HostShape host = 6;
}

message ForkRequest {
  CommandMeta meta = 1;
  string parent_snapshot_id = 2;
  string request_tenant_id = 3;
  string child_sandbox_id = 4;
  bool requires_memory = 5;
  RuntimeType runtime_type = 6;
  // Same host capability shape as RestoreRequest.
  HostShape host = 7;
}

service Sandboxd {
  // ... existing RPCs ...
  rpc Restore(RestoreRequest) returns (Outcome);
  rpc Fork(ForkRequest) returns (Outcome);
}
```

`Outcome.kind` uses `OPERATION_KIND_RESTORE` and `OPERATION_KIND_FORK` enums. `reason_code` uses `OUTCOME_REASON_COMPLETED`, `OUTCOME_REASON_BACKEND_FAILURE`, plus `OUTCOME_REASON_RESTORE_REJECTED` for typed compat failures. `observed_state` uses `SandboxState` enum. `resources` carries workspace, network, cgroup, and guest session receipts. `observed_state` is the post-restore state, typically `Running` or `Failed`.

Fork v1 can be a thin wrapper over restore plus `ForkManager` lineage record and independent authority. If scope must shrink, land `Restore` first and keep `Fork` as a host-orchestrated `Restore` plus `fork_workspace` call. This doc specifies both so lineage binding is pinned once.

## Supervisor sequence

`SandboxSupervisor::restore(ctx, req, backend, snapshot_store)` runs under the per-sandbox `operation_gate` with ledger `begin` for idempotent replay, mirroring `prepare` at `crates/pico-sandboxd/src/supervisor/mod.rs:228` and `resume` at line 995.

1. Admit: `command_context` validates `CommandMeta` shape. Supervisor checks fencing token freshness and policy epoch staleness before side effects, returning `StaleFencingToken` or `StalePolicyEpoch` as gRPC `FailedPrecondition`.
2. Fence: install operation fence rejecting new execs with typed `snapshot_in_progress` or busy outcome. Wait for admitted execs to drain within deadline. Timeout aborts with `TimedOut` and clears the fence.
3. Validate: build `RestoreContext` from `req` plus host caps. Call `RestoreOrchestrator::validate_restore`. This now pins tenant binding, purpose gate, lineage self-parent guard, backend plus CPU plus memory plus device plus protocol compat, policy epoch match, schema downgrade guard, production integrity gate, key resolvability, metadata digest, and exclusion receipts. Any failure maps to a typed `Outcome` with `Failed` plus audit `DENIED` or `FAILED`.
4. Resolve: `resolve_blobs` via injected `BlobLocator`. Paths must stay under the snapshot store root; reject traversal with `InvalidArgument`.
5. Verify plus decrypt: `verify_blob_integrity` pre-KMS, then `decrypt_blob_set` via injected `KeyResolver`. AEAD AAD binds blob plus tenant plus snapshot plus epoch plus key id, so cross-tenant or cross-epoch blob reuse fails closed.
6. Workspace: create COW root via injected `CowWorkspaceManager`. Populate layers from decrypted blob paths. On copy failure, delete the partial workspace and return `PartialCleanup` with deterministic remaining identities.
7. Backend restore: for `requires_memory`, call `backend.restore_snapshot` with memory blob paths. For filesystem, the workspace point plus a clean boot is the restore. Never substitute profiles.
8. Fresh authority: generate new boot id, new protocol session via `establish_guest_session`, new network namespace plus TAP plus DNS attach with ingress disabled, new cgroup plus workspace receipts, new fencing binding. Revoke pre-snapshot leases and credentials. Reissue only with a valid current lease via `SecretsCoordinator`. Reset port exposure; child fork gets a new sandbox id, workspace id, network identity, quota, and audit chain.
9. Notify: send `ResumeNotify` with current sandbox, boot, policy, mount, network, and lineage identity. Memory restore fails if the guest rejects. Filesystem restore records `guest_notified=false` without failing when the agent is not yet reachable, matching `crates/pico-host-agent/src/restore.rs:127` behavior.
10. Persist: `persist_outcome` with observed state plus receipts. Emit `snapshot_operation` audit with operation, outcome, snapshot id, and parent id for fork. Bump observation generation so host proxy invalidates stale port targets.

Implementation status: steps 1 and 3 through 7 plus 10 (minus
audit emission) are implemented in
`crates/pico-sandboxd/src/supervisor/restore.rs`. Deferred to follow-ups:
the exec-drain fence in step 2 (the per-sandbox `operation_gate` serializes
instead), inline fresh authority in step 8 (restore invalidates the stale
guest session and stages data; the subsequent boot or resume issues fresh
authority), `ResumeNotify` in step 9 (waits on guest-client support), and
durable `snapshot_operation` audit in step 10 (metrics plus ledger outcomes
only). All four are tracked as G-10 report section 8 gaps.

Quiesce note: restore verifies that capture quiesced by requiring Ready state, integrity digest, and exclusion receipts. The full guest-signed quiesce receipt from ADR-0007 section Consistency Guarantee step 4 travels at capture time through sandboxd exec drain plus guest hooks; restore does not re-quiesce a stopped source. If a future snapshot carries an explicit `quiesce_receipt` field, step 3 verifies its signature and policy epoch as well.

## Error mapping

| Snapshot failure | gRPC code | Outcome status plus reason |
|---|---|---|
| `SnapshotNotFound`, `BlobMissing` | `NotFound` | `Failed` plus `restore_rejected` |
| `TenantMismatch`, `LineageInvalid`, `CredentialExclusionInvalid`, `CredentialMaterialDetected`, `PolicyIncompatible` | `InvalidArgument` | `Failed` plus `restore_rejected` |
| `PolicyEpochIncompatible`, stale fencing | `FailedPrecondition` | `Failed` plus `restore_rejected` |
| `BlobIntegrityMismatch`, `IntegrityFailed`, `IntegrityRequired` | `DataLoss` or `FailedPrecondition` | `Failed` plus `restore_rejected`; page Security on mismatch |
| `KeyUnavailable` | `FailedPrecondition` | `Failed` plus `restore_rejected` |
| `ForkDepthExceeded` | `ResourceExhausted` | `Failed` plus `restore_rejected` |
| Exec drain timeout, deadline exceeded | `DeadlineExceeded` | `TimedOut` |
| Partial workspace plus cleanup failure | `Internal` with `RequiresReview` outcome | `RequiresReview` plus `PartialCleanup` |

All compat failures identify the mismatched dimension without exposing secret metadata, per `crates/pico-core/src/snapshot/error.rs:1`.

## Convert plus client plus service

- `crates/pico-sandboxd-proto/proto/pico/sandboxd/v1/sandboxd.proto`: `RestoreRequest`, `ForkRequest`, and service methods with shared `HostShape` and typed enums. Regenerate via `crates/pico-sandboxd-proto/build.rs`.
- `crates/pico-sandboxd/src/grpc/convert.rs`: shared `HostShape` validation plus typed enum mapping (`RuntimeType`, `OperationKind`, `OutcomeStatus`, `OutcomeReason`, `SandboxState`, `NonReadyReason`). Validate string lengths against `ID_MAX_LEN`, reject empty `snapshot_id` and `request_tenant_id`, reject unknown/unspecified `runtime_type`, require `host` shape with non-zero memory/vcpus and non-empty backend/version/protocol/arch/machine (disk_mb 0 means unspecified for older clients).
- `crates/pico-sandboxd/src/grpc/service.rs`: add `restore` and `fork` handlers using `run_with_meta`. Follow `prepare` validation style: require `meta`, require `snapshot_id`, map supervisor errors via `supervisor_error_to_status`.
- `crates/pico-host-agent/src/sandboxd_client.rs`: add `restore` and `fork` methods taking `CommandMetaParts` plus a new `RestoreParts` struct mirroring `HostResourceParts`. Reuse `outcome_from_proto` and `status_to_error`.
- `crates/pico-host-agent/src/lib.rs:2128`: replace the fail-closed stub with admission plus `sandboxd.restore` call. Keep fail-closed when sandboxd is unreachable; route to cold boot only when product allows.
- `crates/pico-sandboxd-proto/src/status.rs`: extend `operation_kind` with `restore` and `fork`, extend reason codes if needed.

## Snapshot store plumbing

Supervisor today has no `SnapshotRepository`, `BlobLocator`, `CowWorkspaceManager`, or `KeyResolver`. Options:

- Preferred: new `SnapshotRestoreService` struct holding `Arc<dyn SnapshotRepository>`, `Arc<dyn BlobLocator>`, `Arc<dyn CowWorkspaceManager>`, and optional `Arc<dyn KeyResolver>`, injected via `SandboxSupervisor::with_snapshot_restore`. Keeps supervisor lean and testable with in-memory doubles.
- Alternative: pass stores per-RPC from host. Rejected: host-passed paths reintroduce TOCTOU and trust bypass.

Blob paths cross the process boundary as filesystem paths under a shared store root because host-agent and sandboxd share the host. Validate containment on every resolve. Future helper peel can move the store behind a socket without changing the RPC shape.

## Misuse-resistance and tests

Per `docs/robustness/misuse-resistance-checklist.md` and AGENTS.md protocol rules, add at least one robustness test per vector when the RPC lands:

- Oversized and truncated `snapshot_id`, `request_tenant_id`, `runtime_type`; empty meta; bad fencing token format; deadline in the past.
- Wrong tenant, stale policy epoch, tampered blob, stale metadata digest (reuse `crates/pico-core/tests/snapshot_restore_negative.rs` fixtures through the gRPC layer).
- Self-parent lineage, `Runtime` purpose restore, `requires_memory` on filesystem snapshot.
- Path traversal in `blob_ref`; oversized host shape values.
- Idempotent replay with same `operation_id` returns prior `Outcome` without a second workspace.
- Concurrent restore with same `operation_id` yields single winner.
- Fork depth exceed, fork credential inherit denied by default, fork child has independent workspace plus no port or lease inherit.
- Audit ordering: validation failure emits `DENIED` before blob I/O; integrity failure emits `FAILED` with snapshot id.

New suites: `crates/pico-sandboxd/tests/restore.rs` for service plus supervisor, plus client round-trip in `crates/pico-host-agent/src/sandboxd_client.rs` tests. Existing core negative tests remain the compat oracle.

## Observability and audit

- Tracing span `sandboxd.restore` with `snapshot_id`, `sandbox_id`, `operation_id`, `tenant`, `purpose`, `profile`, and phase latencies. Reuse `RestorePhase::as_str` from `crates/pico-core/src/snapshot/restore_executor.rs:47`.
- Metrics: `restore_started`, `restore_completed`, `restore_failed`, `restore_partial_cleanup`, `fork_completed`, plus phase latency histograms. Wire into `pico-snapshot-fork` dashboard and runbook `docs/runbooks/snapshot-fork.md`.
- Audit: `snapshot_operation` for restore plus fork with outcome, plus `snapshot_metadata_access` for metadata reads, plus `lifecycle_transition` for the resulting state. Integrity mismatch is security-relevant and pages Security.

## Rollout

1. Proto plus convert plus status kinds, with round-trip tests.
2. Supervisor `restore` with in-memory stores plus MockBackend, covering the four negative paths through gRPC.
3. Client plus host-agent wiring behind an admission flag; runbook records the path as live.
4. Fork handler plus depth plus independent workspace tests.
5. G-10 readiness report in `docs/robustness/snapshot-readiness-report.md` linking retention, deletion, restore, and fork evidence for assurance claim C-04.

## Open questions

1. Where does the production `SnapshotRepository` live: sandboxd-local SQLite, shared host directory, or regional metadata service proxied over UDS?
2. Does sandboxd hold KMS credentials for `KeyResolver`, or does host-agent unwrap per-restore and pass a short-lived key handle?
3. Should `RestoreRequest` carry full host shape fields or a compact capability token issued at prepare time?
4. Is fork a separate RPC or a `RestoreRequest` with `purpose=fork` plus `child_sandbox_id`?
5. What retention and GC evidence format does Storage want cited in the G-10 report?
