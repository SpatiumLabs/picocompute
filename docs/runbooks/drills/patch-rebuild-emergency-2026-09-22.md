# Patch and Rebuild Emergency Exercise - 2026-09-22

**Owner**: SRE-PicoCompute with Runtime, Security, and Release
**Date**: 2026-09-22
**Source revision**: `0e06e42078175cb1dedac8bcabfb4025faac9a9c` (base; exercise-module walk verified against the branch head, re-confirm revision at merge)
**Procedure**: [host-rebuild](../host-rebuild.md) cordon/drain/rebuild/re-admit path plus the threat-model tabletop review procedure
**Prior records**: [host-rebuild-exercise-2026-09-21](host-rebuild-exercise-2026-09-21.md) (mechanical path), [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4, gap G-02
**Ticket**: `INC-2026-09-22-RR01` (synthetic exercise ticket)
**Advisory**: `SYNTH-ADV-2026-09-22-01` (simulated critical host advisory, KVM/VMM escape class; not a real CVE)

Tabletop walk plus simulated live steps. No production host mutation, no
drain RPC against a live host, no restart, no GC deletion, no ledger edit,
and no real host rebuild was performed. Advisory intake, patch selection,
boundary validation for the exact profile, and timing evidence are exercised
here; the mechanical cordon/drain/rebuild/re-admit path is owned by
[host-rebuild](../host-rebuild.md) and its 2026-09-21 exercise record. Live
windows below are planning estimates plus simulated-model fixtures, not
measured production rebuild timings.

## Participants

- SRE owner as facilitator, ticket owner, and drain/re-admit approval owner
- Runtime owner for host, VMM, guest, and cleanup behavior
- Security owner for advisory triage, escape scope, and evidence preservation
- Release and infra owners for the approved build pipeline and pinned digest
- Networking owner for namespace isolation and egress lease scope
- Control-plane owner for scheduler exclusion, leases, and fencing
- Observability owner for telemetry, audit integrity, and tenant notice check

## Candidate profile

| Field | Value |
|---|---|
| Date | 2026-09-22 |
| Source revision | `0e06e42078175cb1dedac8bcabfb4025faac9a9c` (base; re-confirm at merge - the exercise module is branch-new) |
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Region/cell/host | `region_test`/`cel_east`/`hst_01` with two peer hosts for headroom |
| Backend | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop profiles |
| Host image | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Guest image | Pinned digest `sha256:good...` |
| Patched build | Approved pipeline build `build-2026-09-22`, digest `sha256:good` (simulated patch for `SYNTH-ADV-2026-09-22-01`) |
| Network policy | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway, no ambient peer path |
| Credential mode | Short-lived scoped leases, mediation preferred, revoke-first destroy with `LeaseRevoked` audit |
| Snapshot mode | Sandboxd-owned `Restore` and `Fork` RPC path; tampered/stale/cross-tenant artifacts fail closed |
| Audit | Durable transactional outbox, `audit_delivery` events, dead-letter table as evidence |
| Telemetry | `o11y/rules/pico-recording-rules.yaml` plus `PicoCompute` Grafana folder |

Evidence commands rerun for this revision:

- `scripts/validate-o11y-dashboards.sh` - pass, all dashboards and runbook links resolve
- `cargo nextest run -p pico-core --lib emergency_rebuild` - 13 passed (ordered sequence, timings, no-reuse guard, evidence completeness)
- `cargo nextest run -p pico-core --lib operator host_quarantine availability` - 74 passed
- `cargo nextest run -p pico-core --test control_plane_readiness destroy_revokes_all_sandbox_leases` - pass
- `cargo nextest run -p pico-host-agent --lib draining_rejects_new_prepare destroy_revokes_all_known_credential_leases` - 2 passed
- `cargo nextest run -p pico-runtime --test isolation` - 28 passed (boundary suite for the exercise profile)
- `cargo nextest run -p pico-cli --bins` - 27 passed (drain bearer and ticket evidence, health shape rejection, prohibited-command rejection)
- `cargo clippy -p pico-core --lib --locked -- -D warnings` - pass (the workspace `--all-targets` run carries a pre-existing feature-gate import failure in the `secrets_broker` test on the base revision, unrelated to this exercise)

## Scenario replayed

Simulated critical host advisory in the unknown VMM/kernel/firmware/hardware
escape class (residual risk RR-01):

- Initial: tenant `tnt_d` sandbox `sbx_21` runs on `hst_01` in `cel_east`
  with network address `10.0.0.21` and two live credential leases.
- Advisory inject: `SYNTH-ADV-2026-09-22-01` reports a suspected KVM escape
  affecting the running host kernel/VMM combination. Security triages the
  advisory as in-scope for `hst_01` and opens `INC-2026-09-22-RR01`.
- Independent failure: during drain, `hst_01` stops reporting capacity
  (partitioned report) while one sandbox holds an expired lease with
  unclassified orphan receipts.
- Adversarial pressure: an operator proposes reusing sandbox identity
  `sbx_21` and address `10.0.0.21` for the replacement workload before
  cleanup confirms absence, and proposes resolving the quarantine alert to
  test verification faster.

## Steps walked with duration

Total tabletop walk: 80m. Times below are facilitator timestamps for the
walk. Estimated live windows are planning estimates for a real emergency
rebuild, not measured in this exercise. Simulated-model fixtures come from
the `EmergencyExercise` unit walk (`pico-core::emergency_rebuild`) and
are labeled as fixtures.

| Step | Tabletop walk | Estimated live window | What was checked |
|---|---|---|---|
| 0 - Advisory triage and ticket | 10m (09:00-09:10) | 10m | Advisory scope confirmed for `hst_01`, ticket `INC-2026-09-22-RR01` opened, Security paged for suspected escape |
| 1 - Cordon | 5m (09:10-09:15) | 2m | Control-plane exclusion, **Hosts Evaluated vs Passed Constraints** drop for `hst_01`, SRE on-call approval recorded (fixture: elapsed 2s) |
| 2 - Drain | 15m (09:15-09:30) | 15-30m natural, 5m with RPC | Sandbox count from `pico-host-health`, `pico_host_draining`, natural completion preferred, RPC approval path reviewed without calling it; `draining_rejects_new_prepare` unit holds (fixture: elapsed 12s, time-to-drain 10s) |
| 3 - Revoke and isolate | 10m (09:30-09:40) | 5m | Destroy revoke-all with operation identity, egress lease revoke with mapping removal, no NAT flush; `sbx_21` and `10.0.0.21` retired with reuse blocked before absence proof |
| 4 - Evidence freeze | 5m (09:40-09:45) | 2m | `host_disabled`, `cleanup_disposition`, `placement_outcome`, `LeaseRevoked`, `network_enforcement` IDs pinned in ticket (fixture: elapsed 19s) |
| 5 - Rebuild | 10m (09:45-09:55) | 20-40m | Approved pipeline build `build-2026-09-22` with pinned digest, no host-side image rebuild, no hand copy (fixture: elapsed 49s, time-to-rebuild 37s) |
| 6 - Boundary validation | 10m (09:55-10:05) | 10m | Isolation boundary suite rerun for the exact profile: 28 passed; failed suite would keep the host out of placement |
| 7 - Re-admit with 5m watch | 5m (10:05-10:10) | 5m watch plus checks | Quarantine gauge 0, clean reconciliation pass, 5m with no new alert, SRE on-call approval |
| 8 - Tenant notice and close | 10m (10:10-10:20) | Within 60m of confirmed impact | Emergency notice for `tnt_d` filled and checked, ticket close fields reviewed, evidence completeness confirmed with zero missing kinds |

No step relied on cooperation from the suspected workload or the affected
host agent. Placement decisions used control-plane authority and fencing
epochs. The facilitator stopped the walk twice to refuse shortcut proposals:
once for identity/address reuse before absence proof, and once for resolving
the quarantine alert to test verification. Both refusals match the merged
procedure rollback rules and the `ReuseBeforeAbsence` gate in the exercise
module.

## Approval evidence

Synthetic exercise approvals recorded in `INC-2026-09-22-RR01`:

- 09:00 - Security triaged `SYNTH-ADV-2026-09-22-01` as in-scope for
  `hst_01` and paged SRE lead plus infra for a suspected escape.
- 09:10 - SRE on-call approved cordon for `hst_01` with reason
  `stale_resources` and scheduler exclusion source.
- 09:15 - SRE on-call approved drain plan: natural completion preferred,
  RPC held as fallback with sandbox count attached. RPC was not called.
- 09:30 - SRE on-call approved fenced review scope with fencing-token
  evidence requirement. No cleanup was executed live.
- 09:45 - SRE lead and infra approved rebuild with build
  `build-2026-09-22` and pinned digest, with Security approval for the
  suspected escape and the advisory source recorded.
- 10:05 - SRE on-call approved re-admit pending the checks below, with the
  5m watch as a hard gate.

Each approval names the approver role, time, and scope. Silence was never
treated as approval. A live emergency rebuild would need the same roles with
real signatures in the ticket before each mutation.

## Re-admit checks

Walked against the merged procedure with tabletop signal review:

- [x] Host health `ready` or `degraded` on host-agent and `healthy` or
  `degraded` on scheduler. Only those states admit new work.
- [x] Capacity reports fresh, age under 60s, host present in
  **Hosts Evaluated**.
- [x] Reconciliation pass shows zero orphans and zero review-required on
  `hst_01`, with network reconciliation healthy.
- [x] `pico_quarantine_hosts_quarantined` is 0 for `hst_01`.
- [x] 5m watch with no new quarantine alert on `hst_01`. Any new alert
  returns the host to quarantine and reopens the ticket.
- [x] `boot_ready` baseline holds before tenant work returns.
- [x] Isolation boundary suite passes for the exact profile
  (`firecracker-linux-kvm-2026-09-22` in the simulated record, `MockBackend`
  profile in unit evidence).

Result: pass as tabletop plus simulated live. The shared `validate_readmit`
gate rejects each failing input in units, and the exercise module reuses
that gate so the drill and the code cannot drift apart.

## Tenant notification check (emergency row)

The prior rebuild exercise covered the mechanical rebuild row. This exercise
covers the emergency row for `tnt_d`, which had sandboxes on the affected
host during a suspected escape.

Filled notice (synthetic example for `tnt_d` only):

```
Subject: [PicoCompute] rebuild notice for tnt_d in region_test/cel_east
Incident: INC-2026-09-22-RR01
Date: 2026-09-22 Revision: 0e06e42078175cb1dedac8bcabfb4025faac9a9c
Scope (this tenant only): sandbox sbx_21 on hst_01, drained and destroyed through control-plane path with delayed reuse
User-visible impact: sbx_21 stays destroyed; re-placement may delay new creates during cordon/drain/rebuild; patched VMM profile on return
Action taken: quarantined hst_01, cordoned from placement, approved drain plan, revoked leases with operation identity, rebuilt from approved build build-2026-09-22
Tenant action: retry new creates with backoff during rebuild window; rotate downstream credential derived from revoked leases
Next update: on mitigation change or within 4h during ongoing impact; close notice follows re-admit checks
Contact: SRE-PicoCompute via INC-2026-09-22-RR01
Audit refs: host_disabled for hst_01 exclusion; cleanup_disposition for quarantine disposition; LeaseRevoked with operation identity; placement_outcome for rebuild
```

Redaction check passed: no secret, token, boot secret, command, path,
workload output, raw error, other-tenant identity, registry credential, or
blob location in the notice. Only `tnt_d` scope is included. No
tenant/sandbox labels were attached to metrics. Timing target (initial
notice within 60m of confirmed user-visible impact) was reviewed as met for
tabletop, with owner paging immediate per the owning runbooks.

## Audit record for this exercise

- Ticket `INC-2026-09-22-RR01` holds advisory triage, cordon/drain/rebuild
  times, approvals above, sandbox counts, patch build and digest,
  verification results, the 5m watch outcome, the tenant notice above, and
  the underlying audit event IDs.
- Recovery evidence stays in the durable audit store keyed by `event_kind`
  with `host_id=hst_01` and the destroying operation identity for `sbx_21`.
  Required kinds for close: `host_disabled`, `LeaseRevoked`,
  `placement_outcome`, plus the approved build record and a passing
  boundary suite for the exact profile. The exercise module reports zero
  missing kinds for this run.
- Dead-letter replay, if needed, requires Security review and preserves the
  source outbox row. The ledger was never edited by hand.

## No-reuse verification

`sandbox identity sbx_21` and network address `10.0.0.21` were retired at
revoke time. A reuse check before absence proof fails closed
(`ReuseBeforeAbsence`), and the facilitator refused the early-reuse proposal
on that basis. Absence was proven through the reconciliation pass (zero
orphans, zero review-required, network reconciliation healthy) before either
value became reusable. The unit gate covers retire, proof, and refusal.

## Boundary validation

The rebuilt host returns to service only for the exact profile the suite
validated. `cargo nextest run -p pico-runtime --test isolation` passes
28 checks (filesystem, process, network, resource, credential, backend,
data-sharing, and side-channel categories with mock-path enforcement plus
live-mode execution coverage). The exercise module additionally requires a
named exact profile and a passing result before the verify stage can
complete; a failed suite blocks verify, re-admit, and close.

## Timing evidence

| Metric | Simulated-model fixture | Estimated live window | Source |
|---|---|---|---|
| Time-to-drain (cordon to drain complete) | 10s | 15-30m natural, 5m with RPC | `EmergencyExercise::time_to_drain_secs` unit walk plus host-rebuild planning estimates |
| Time-to-rebuild (drain complete to rebuild) | 37s | 20-40m | `EmergencyExercise::time_to_rebuild_secs` unit walk plus host-rebuild planning estimates |
| Tabletop walk | 80m | n/a | Facilitator timestamps above |
| Evidence-preservation completeness | Zero missing kinds | n/a | `EmergencyExercise::missing_evidence` for this run |

Fixtures prove the measurement path (ordered monotonic timestamps with
audit IDs per stage), not host speed. Live drain, rebuild, and re-admit
timings stay estimates until a staging rebuild measures them.

## Gap closure assessment for RR-01

- Advisory intake and patch selection: this record triages a simulated
  critical host advisory, scopes it to `hst_01`, and cites the approved
  pipeline build with pinned digest plus Security approval. Real advisory
  intake stays with the vulnerability response path; this exercise proves
  the handoff shape.
- Drain, revoke, and rebuild sequence: walked in order with ticket-gated
  approvals and audit IDs per stage, backed by unit-tested gates
  (`pico-core::emergency_rebuild`, `pico-core::operator`,
  host-agent drain and destroy-revoke paths).
- Boundary validation for the exact profile: 28 isolation checks pass, and
  verify requires the named profile plus a passing suite.
- No-reuse: identity and address reuse before absence proof is refused in
  the walk and in units.
- Timings: measurement path is unit-proven with fixtures; live SLO evidence
  awaits a staging rebuild.
- Remaining scope: live drain, rebuild, and re-admit timings on a staging
  host; real patch-pipeline promotion evidence for a genuine advisory. No
  procedure change is needed for those; record measured timings against the
  same ticket pattern when a staging host rebuilds.

## Coordination with the mechanical rebuild exercise

The 2026-09-21 host rebuild exercise owns the mechanical
cordon/drain/rebuild/re-admit path any host follows. This record does not
duplicate it: it adds advisory triage, patch selection, boundary validation
for the exact profile, timing evidence, and the no-reuse verification the
residual-risk register requires. When both run together, record timings once
and reference the shared ticket pattern from both records.

## Related

- Procedure: [host-rebuild](../host-rebuild.md)
- Runbook index: [README](../README.md)
- Mechanical exercise: [host-rebuild-exercise-2026-09-21](host-rebuild-exercise-2026-09-21.md)
- Prior scenarios: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4
- Drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md)
- Tenant template: [runbook index](../README.md#tenant-notification) and
  [tenant-notification-rerun-2026-09-21](tenant-notification-rerun-2026-09-21.md)
- Code: `crates/pico-core/src/emergency_rebuild.rs`, `crates/pico-core/src/operator.rs`
- Runbooks: host-quarantine, host-health, cleanup-reconciliation,
  scheduling-capacity, lifecycle-operations, networking, snapshot-fork,
  audit-telemetry, image-cache
