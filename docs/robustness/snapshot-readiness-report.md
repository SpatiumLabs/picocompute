# Snapshot Production Readiness Report

**Date**: 2026-09-20 (initial revision)
**Status**: Draft
**Strategy**: [ADR-0007](../adr/0007-snapshot-resume-fork-consistency-model.md)
**Posture**: [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Readiness model**: [Production readiness](../security/production-readiness.md) gate `G-10`
**Assurance parent**: [Security assurance case](../security/assurance-case.md) claim `C-04`

## Executive Summary

This report validates PicoCompute snapshot behavior as an integrated subsystem
for production rollout. Validation composes capture exclusion, encryption
and integrity, tenant and lineage binding, the sandboxd-owned restore and
fork path, retention and deletion evidence, and fresh-authority semantics
through automated suites, instead of re-testing each snapshot module in
isolation.

**Overall verdict**: the snapshot subsystem meets the G-10 evidence bar at
Draft status. Restore and fork execute through the sandboxd `Restore` and
`Fork` RPCs with typed rejection of tampered, stale, cross-tenant, and
exclusion-violating artifacts. Retention, deletion, revocation, and
lineage-aware garbage collection are pinned by tests. All 620 integrated
validation tests pass. Known boundaries are pinned by tests and listed in
section 8. Promotion past Draft requires the Storage, Runtime, and Security
owner approvals recorded in Approval, plus closure of the accepted
limitations there.

## How to Run the Evidence

```bash
cargo nextest run -p pico-core --lib snapshot
cargo nextest run -p pico-core --test credential_snapshot_exclusion
cargo nextest run -p pico-core --test snapshot_restore_negative
cargo nextest run -p pico-core --test snapshot_encryption_robustness
cargo nextest run -p pico-sandboxd --lib
cargo nextest run -p pico-sandboxd --test supervisor
cargo nextest run -p pico-sandboxd-proto
cargo nextest run -p pico-host-agent --lib sandboxd_client
cargo nextest run -p pico-host-agent --test restore_acceptance
cargo clippy -p pico-core --lib -p pico-sandboxd --lib -p pico-host-agent --lib -p pico-sandboxd-proto --lib --locked -- -D warnings
```

Suite mapping to validation areas:

| Validation area | Suite | Location |
|---|---|---|
| Snapshot metadata, compat, lineage, integrity units | 419 core lib snapshot tests | `crates/pico-core/src/snapshot/` |
| Credential exclusion and fork policy | 34 exclusion tests | `crates/pico-core/tests/credential_snapshot_exclusion.rs` |
| Negative restore rejections | 5 negative tests | `crates/pico-core/tests/snapshot_restore_negative.rs` |
| Encryption and integrity misuse vectors | 13 robustness tests | `crates/pico-core/tests/snapshot_encryption_robustness.rs` |
| Supervisor restore plus fork execution | 10 restore tests inside 79 sandboxd lib tests | `crates/pico-sandboxd/src/supervisor/restore.rs` |
| Supervisor lifecycle integration | 17 integration tests | `crates/pico-sandboxd/tests/supervisor.rs` |
| Wire round-trip and status codes | 18 proto tests | `crates/pico-sandboxd-proto/` |
| Restore plus fork client round-trip | 33 client tests | `crates/pico-host-agent/src/sandboxd_client.rs` |
| Host-agent end-to-end restore | 2 acceptance tests | `crates/pico-host-agent/tests/restore_acceptance.rs` |
| Design record | RPC design doc | `docs/design/snapshot-restore-sandboxd-rpc.md` |

Related prior evidence (not duplicated here): control-plane readiness in
`docs/control-plane/prod-readiness-report.md`, backend readiness in
`docs/robustness/backend-prod-readiness-report.md`, protocol readiness in
`docs/robustness/guest-agent-proto-prod-readiness-report.md`, threat model
in `docs/security/threat-model.md`, runbook in `docs/runbooks/snapshot-fork.md`.

## 1. Capture Contract: Quiesce and Exclusion

Capture follows ADR-0007: cooperative quiescence, exclusion of secret and
runtime state, and Ready publication only after every blob, digest,
compatibility field, and lineage reference is durable.

What this report pins:

- Exclusion receipts are enforced at restore time, not only at capture.
  `RestoreOrchestrator::validate_restore` calls
  `validate_credential_exclusion` and `scan_for_credential_material` for
  every v2 snapshot and every snapshot carrying a credential policy
  (`crates/pico-core/src/snapshot/restore.rs`). A missing `secret`
  mount class or a secret mount present in filesystem refs fails closed
  with `CredentialExclusionInvalid` or `CredentialMaterialDetected`.
- The 34 exclusion tests pin ephemeral secret mounts, exclusion receipts,
  restore refresh policy, fork inheritance default-deny, misplaced
  credential fixtures, and audit redaction.
- Quiesce cooperation is attested by Ready state plus the integrity digest
  plus exclusion receipts. The full guest-signed quiesce receipt from
  ADR-0007 travels at capture time; restore verifies its consequences
  rather than re-quiescing a stopped source. Section 8 records the
  explicit receipt field as a follow-up.

## 2. Encryption, Integrity, and Tenant Binding

- Authenticated encryption is AES-256-GCM with AAD binding blob, tenant,
  snapshot, policy epoch, and key id
  (`crates/pico-core/src/snapshot/encryption.rs`). The blob digest
  covers stored ciphertext so integrity is verified pre-KMS; a mismatch
  never reaches key resolution.
- Metadata digest covers every immutable field and is verified before any
  blob I/O. Schema v2 without an integrity block is rejected, and
  production mode rejects `integrity_required: false`.
- Tenant binding is enforced twice: the explicit `request_tenant` check in
  `validate_restore` (`TenantMismatch` before blob I/O) and the AEAD AAD
  binding at decryption. Cross-tenant blob reuse fails at both layers.
- Policy epoch is historical evidence, not restored authority. A snapshot
  epoch different from the current epoch is rejected with
  `PolicyEpochIncompatible`.
- The 13 encryption robustness tests pin round-trip, wrong key, tampered
  and truncated ciphertext, cross-tenant AAD, wrong epoch AAD, pre-KMS
  ordering, metadata digest mismatch, stale key-ref digest, and atomic
  multi-blob failure.

## 3. Restore Path: sandboxd-Owned Execution

`HostAgent::restore_from_snapshot`
(`crates/pico-host-agent/src/lib.rs`) prepares the target sandbox from
the caller spec, admits the command with fencing and policy epoch, and
issues the sandboxd `Restore` RPC. It never touches blobs, backends, or
guest sessions directly, per ADR-0011.

`SandboxSupervisor::restore`
(`crates/pico-sandboxd/src/supervisor/restore.rs`) runs under the
per-sandbox operation gate with ledger fencing, idempotent replay on
`operation_id`, and deadline enforcement:

1. Loads snapshot stores (fail-closed while unconfigured).
2. Requires a prepared runtime handle.
3. Runs `prepare_restore`: tenant, purpose, lineage, compatibility,
   integrity, exclusion, resolve, verify, decrypt.
4. Restores backend memory state when required, else rejects a memory
   require without memory blobs.
5. Stages the COW filesystem; partial failure cleans up and surfaces
   review state instead of a half-built workspace.
6. Invalidates the stale guest session and boot id.
7. Persists `Preparing` (boot next) for filesystem restores or
   `Suspended` (resume next) for memory restores. Validation failures
   persist `Failed` with `RestoreRejected`.

Restore telemetry uses the existing `restore_started`, `restore_completed`,
`restore_failed`, `restore_memory_restored`, and `restore_partial_cleanup`
emitters, now wired to the live path. The runbook
(`docs/runbooks/snapshot-fork.md`) records the path as live.

## 4. Fork: Independent Authority With Lineage Binding

`SandboxSupervisor::fork` shares the staging pipeline with an additional
purpose gate: only fork-purpose snapshots branch children. Every child
receives an independent workspace; no leases, credentials, DNS cache,
flows, or port exposure are inherited by construction (the path never
touches secrets or network managers). The parent snapshot id is preserved
in the outcome message and audit trail. Fork depth is enforced at the
workspace COW level by `ForkManager` with `ForkDepthExceeded` typing; the
supervisor path mints independent roots, so shared-base fork lineage
stays a follow-up (section 8).

Pinned by supervisor fork tests (success with fork purpose, rejection of
base purpose) plus fork depth and independent-workspace units in
`crates/pico-core/src/snapshot/cow/fork/`.

## 5. Retention, Deletion, and Garbage Collection

- Lifecycle: `Staging` to `Ready` to `Revoked`, with `Deleting` and
  `Deleted` rejected at restore as not found. Revocation is allowed only
  from `Ready` and is permanent.
- Retention: `RetentionPolicy` defaults to a 24-hour minimum
  (`crates/pico-core/src/snapshot/cache_tiering/policy.rs`).
  Collection skips snapshots inside retention, referenced snapshots,
  snapshots with live descendants in the `LineageGraph`, and terminal
  states. Dry-run mode never deletes.
- Deletion evidence: `GcOutcome` distinguishes `Deleted`,
  `SkippedReferenced`, `SkippedRetention`, `SkippedTerminalState`, and
  `SkippedIntegrityFail`, with `GcRunStats` counting each class.
  `gc_deleted`, `gc_skipped_ref`, and `gc_skipped_retention` metrics feed
  the `pico-snapshot-fork` dashboard.
- COW layer safety: `GcStore` reference-counts shared base layers with
  crash-safe JSON persistence and rebuild-from-metadata on disagreement,
  so shared data is never deleted while any live workspace references it.

## 6. Compatibility Matrix

Every restore validates from trusted metadata before blob attach:
schema version, Ready state, tenant, purpose, lineage self-parent guard,
backend family and version, CPU architecture and features, memory and
vCPU shape, device model, protocol version, cross-backend runtime match,
policy epoch, key resolvability, metadata digest, and exclusion manifest.
Cross-backend restore is always rejected. Cross-version restore is
accepted only on exact version match today; approved version ranges with
conformance evidence remain a follow-up.

## 7. Test Counts at the Tested Revision (2026-09-20)

| Suite | Tests | Passed | Failed | Evidence |
|---|---|---|---|---|
| Core lib snapshot (`--lib snapshot`) | 419 | 419 | 0 | Rerun in-session |
| Credential exclusion | 34 | 34 | 0 | Rerun in-session |
| Negative restore | 5 | 5 | 0 | Rerun in-session |
| Encryption robustness | 13 | 13 | 0 | Rerun in-session |
| sandboxd lib (includes 10 restore) | 79 | 79 | 0 | Rerun in-session |
| sandboxd supervisor integration | 17 | 17 | 0 | Rerun in-session |
| sandboxd proto | 18 | 18 | 0 | Rerun in-session |
| Host-agent client | 33 | 33 | 0 | Rerun in-session |
| Host-agent restore acceptance | 2 | 2 | 0 | Rerun in-session |
| **Total pinned by this report** | **620** | **620** | **0** | All suites rerun in-session |

## 8. Known Gaps and Accepted Limitations

| Gap | Severity | Evidence | Mitigation and follow-up |
|---|---|---|---|
| Guest-signed quiesce receipt is not a distinct metadata field; Ready plus digest plus exclusion is the proxy | Medium | This report section 1 | Add an explicit receipt field with signature and epoch verification at capture and restore |
| Production KMS wiring for sandboxd `KeyResolver` is not configured; `server::run` leaves stores uninstalled | High for encrypted restores | Fail-closed `SnapshotRestore` error while unconfigured | Storage decision on repository location plus KMS credential owner (design doc open questions 1-2) |
| Snapshot store location (local dir vs regional service) is undecided | Medium | Design doc | Storage owner decision; host-passed paths are rejected by design |
| Inline `ResumeNotify` from sandboxd waits on guest-client support | Medium | `GuestConnection` has no notify method | Phase 2b: add notify to guest client; boot and resume issue authority today |
| Memory-profile restore has no live VMM evidence; MockBackend returns `Unsupported` | Medium | Rejection pinned, no success bundle | Live Firecracker or QEMU memory restore bundle per supported backend |
| Cross-version restore allows exact match only | Low | Compat units | Backend compatibility policy with approved ranges plus conformance |
| Application-copied secrets in workspace or memory escape classification | High for data classes | ADR-0007 tenant-state clause | RR-03; data classification plus tenant notice, not a restore bug |
| Supervisor fork mints independent roots instead of `ForkManager` shared-base children; RPC-level depth and shared lineage are unenforced | Medium | This report section 4 | Route supervisor fork through `ForkManager` or record per-lineage depth at staging |
| Restore plus fork emit metrics and ledger outcomes but no durable `snapshot_operation` audit event | Medium | Design doc observability section | Wire an audit sink into the supervisor restore path or extend the ledger audit trail |

## 9. Acceptance Criteria Mapping

- Live restore succeeds for the supported snapshot format and rejects
  tampered, stale, and cross-tenant artifacts with typed errors:
  sections 2, 3, 7. Negative tests pin `BlobIntegrityMismatch`,
  `IntegrityFailed`, `TenantMismatch`, and `PolicyEpochIncompatible`.
  End-to-end acceptance pins success plus cross-tenant rejection through
  the RPC.
- Fork issues independent authority while preserving lineage binding:
  section 4. Purpose gate, independent workspace, parent state
  preservation, and lineage-preserving outcome pinned. Workspace-level
  depth limits are pinned by COW units; RPC-level shared-base lineage
  stays a section 8 follow-up.
- Readiness report links test runs, open risks, and accepted limitations,
  and is approved by storage, runtime, and security owners: this report
  with section 7 runs, section 8 risks, and Approval below.
- C-04 gap rows can cite the path and the report: sections 3, 4,
  5, and 7 provide the cited evidence.

## Approval

| Role | Name | Date | Decision |
|---|---|---|---|
| Storage owner | Pending | - | Review retention, deletion, revocation, store location, KMS wiring |
| Runtime owner | Pending | - | Review restore plus fork execution, backend contract, authority invalidation |
| Security owner | Pending | - | Review exclusion, integrity, tenant binding, quiesce proxy, RR-03 |

This report stays Draft until all three owners approve the claim mapping
and the section 8 follow-ups have owners and dates.

## Appendix A: Test Run Output

All suites below were rerun in-session for this revision.

```
# Core lib snapshot
test result: ok. 419 passed; 0 failed (pico-core lib snapshot)

# Credential exclusion
test result: ok. 34 passed; 0 failed (pico-core credential_snapshot_exclusion)

# Negative restore
test result: ok. 5 passed; 0 failed (pico-core snapshot_restore_negative)

# Encryption robustness
test result: ok. 13 passed; 0 failed (pico-core snapshot_encryption_robustness)

# sandboxd lib (includes supervisor restore plus fork execution)
test result: ok. 79 passed; 0 failed (pico-sandboxd lib)

# sandboxd supervisor integration
test result: ok. 17 passed; 0 failed (pico-sandboxd supervisor)

# sandboxd proto
test result: ok. 18 passed; 0 failed (pico-sandboxd-proto)

# Host-agent client
test result: ok. 33 passed; 0 failed (pico-host-agent sandboxd_client)

# Host-agent restore acceptance
test result: ok. 2 passed; 0 failed (pico-host-agent restore_acceptance)

Total pinned by this report: 620 tests, 0 failures
```

## Appendix B: Reproducibility

```bash
# Full snapshot evidence set used by this report
cargo nextest run -p pico-core --lib snapshot
cargo nextest run -p pico-core --test credential_snapshot_exclusion
cargo nextest run -p pico-core --test snapshot_restore_negative
cargo nextest run -p pico-core --test snapshot_encryption_robustness
cargo nextest run -p pico-sandboxd --lib
cargo nextest run -p pico-sandboxd --test supervisor
cargo nextest run -p pico-sandboxd-proto
cargo nextest run -p pico-host-agent --lib sandboxd_client
cargo nextest run -p pico-host-agent --test restore_acceptance

# Clippy for the touched crates
cargo clippy -p pico-core --lib -p pico-sandboxd --lib -p pico-host-agent --lib -p pico-sandboxd-proto --lib --locked -- -D warnings
```
