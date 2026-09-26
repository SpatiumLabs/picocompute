# Incident Tabletop Record - 2026-09-21

**Owner**: SRE-PicoCompute
**Facilitator**: Security owner
**Date**: 2026-09-21
**Source revision**: `ad4377d3c8ba3bd5ee51cbb1db5b58f61ef64521`
**Procedure**: threat-model tabletop review procedure plus readiness review procedure
**Companion drill**: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md)

Tabletop only. No host mutation, no drain RPC, no restart, no GC, and no
ledger edit was performed. All recovery steps below were walked against the
current runbooks, alert rules, dashboards, and unit-tested code paths.

## Candidate profile

| Field | Value |
|---|---|
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Tenant sharing | Dedicated tenancy only; shared-host public profile remains blocked |
| Region/cell/host | `region_test`/`cel_east`/`hst_01` plus two peer hosts for cell-wide injects |
| Backend | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop-only profiles |
| Host image | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Guest image | Pinned digest `sha256:good...`; promotion candidate `sha256:dead...` for scenario 1 |
| Network policy | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway, no ambient peer path |
| Credential mode | Short-lived scoped leases, mediation preferred, revoke-first destroy with `LeaseRevoked` audit |
| Snapshot mode | Sandboxd-owned `Restore` and `Fork` RPC path; tampered/stale/cross-tenant artifacts fail closed |
| Audit | Durable transactional outbox, `audit_delivery` events, dead-letter table as evidence |

## Participants

- Security owner as facilitator and risk-record owner
- Runtime owner for host, VMM, guest, and cleanup behavior
- Networking owner for DNS, egress, exposure, and data-plane recovery
- Control-plane owner for identity, policy, scheduling, and lifecycle state
- Observability owner for telemetry, audit integrity, and evidence gaps
- SRE owner for availability, quarantine, rebuild, rollback, and incidents
- Image Pipeline and Storage owners joined for scenarios 1 and 3

## Preparation inputs reviewed

- Posture, risk, readiness, and signal contracts plus side-channel assessment
- Control-plane, backend, protocol, snapshot, and scale validation reports
- Runbook index plus lifecycle-operations, runtime-backend, image-cache, networking, host-quarantine, cleanup-reconciliation, audit-telemetry, and slo-error-budget runbooks
- `o11y/rules/pico-recording-rules.yaml` and the `PicoCompute` Grafana folder
- Residual-risk register RR-01 through RR-08
- Validation for this revision: `scripts/validate-o11y-dashboards.sh` pass; `host_quarantine` and `availability` units pass; destroy-path lease-revoke test passes; secrets revoke audit tests pass

Missing/expired/inexact evidence marked before the exercise:

- Shared-host placement has no approved profile; dedicated tenancy is the fallback
- Image-cache hit/miss/eviction panels are not emitted until host image-cache work lands
- Manual quarantine acknowledge/resolve, fenced cleanup, and un-drain have no shipped CLI helper
- Tenant notification has no template, owner, or timing in the runbooks
- Host rebuild is approval-only with no tested step-by-step rebuild procedure

One scenario was selected from each risk tree per the readiness review
procedure. Each scenario injects one adversarial action plus one independent
failure.

## Scenario 1 - Create-to-ready boundary failure (Tree 1, R-03/R-04/R-05)

Initial state: tenant `tnt_a` creates sandboxes in `cel_east` on the pinned
digest `sha256:good...` with policy epoch `p42`, fresh operation IDs, healthy
hosts, and normal placement efficiency.

- Adversarial action: a compromised promotion pipeline promotes revoked digest
  `sha256:dead...` with stale backend eligibility metadata that favors a
  weaker profile.
- Independent failure: `hst_01` stops reporting capacity, so inventory is
  stale (dropped at 60s, quarantine condition at 120s) during the promotion.

Preventive checks walked in order with owners:

- Admission and policy binding (Control-plane): reject the revoked digest by
  digest and provenance check; do not admit without current policy epoch.
- Scheduler constraints (Control-plane and Runtime): deterministic
  workload-class to floor mapping with no silent fallback; stale host is
  excluded from placement.
- Ordered prepare barrier (Runtime): readiness only after namespaces, mounts,
  network, cgroups, identity, and policy receipts are complete.
- Guest handshake binding (Runtime and Security): fresh boot secret with
  tenant/sandbox/boot/lineage binding; version policy rejects skew.

Detection signals and maximum expected delays:

- `pico_boot_events_total{event="boot_not_ready",reason="image"}` rising
  on `pico-lifecycle-operations` - immediate on next boot batch.
- `pico_prepare_events_total` failure plus platform log
  `outcome=image_unavailable` - immediate.
- Promotion and verification audit events - immediate; a verification miss is
  a supply-chain incident.
- `PicoComputeHostQuarantined` for `hst_01` after 1m of
  `pico_quarantine_hosts_quarantined > 0`; inventory already dropped the
  host at 60s.
- `PicoComputeSloBurnFast` on `boot` if error ratio exceeds 14.4x on 1h and 5m
  windows - 2m sustained.

Recovery steps executed as tabletop:

- Revoke: revoke the bad promotion in the image control plane; stop further
  placement of `sha256:dead...`.
- Isolate: keep `hst_01` out of placement; do not SSH as a first check.
- Quarantine: confirm `AlertStateManager` quarantine for capacity staleness;
  leave quarantined.
- Drain: no drain RPC without SRE approval; prefer natural completion.
- Rebuild: no rebuild in this scenario; host re-admit only after capacity
  reports are fresh and no quarantine alert fires for 5m.
- Rollback: pin back to `sha256:good...` from the control plane; confirm
  `boot_ready` baseline holds 15m before closing.
- Notification: page Image Pipeline on promotion-linked `reason=image`;
  page Security on verification mismatch; tenant notice is a gap (see G-01).
- Evidence preservation: keep promotion, verification, `placement_outcome`,
  `runtime_outcome`, and `host_disabled` audit events; do not delete local
  state to clear the alert.

No step relies on cooperation from the promoted image or the stale host
agent. Placement decisions use control-plane authority and fencing epochs.

## Scenario 2 - Tool execution exceeds delegated authority (Tree 2, R-10/R-11/R-12/R-15)

Initial state: tenant `tnt_b` workload uses mediated credential access with
lease `lse_01` bound to operation `op_77`, policy epoch `p42`, and an egress
allowlist limited to `svc_api` with a short expiry.

- Adversarial action: poisoned context induces a legitimate agent to call a
  tool against the wrong tenant resource and an unauthorized egress
  destination outside the allowlist.
- Independent failure: audit outbox pending climbs during the incident, so
  `pico_audit_delivery_count` lags and dead-letter risk rises.

Preventive checks walked in order with owners:

- Explicit target identity and scoped policy (Control-plane and Product):
  tool contract carries tenant/sandbox/operation/lease identity; mediation
  denies out-of-scope targets.
- Short-lived scoped tokens with protected delivery (Security and
  Control-plane): broker denies stale policy epoch and overbroad scope.
- Default-deny egress with policy DNS and anti-spoofing (Networking):
  namespace isolation plus lease-bound gateway; protected destinations stay
  denied.
- Source redaction with bounded schemas (Observability): raw secrets and
  workload output never enter logs/metrics/traces.

Detection signals and maximum expected delays:

- `network_enforcement` deny audit plus egress deny counters - immediate.
- Broker denial audit and `pico_credential_denied_total` rate - immediate.
- `pico_audit_outbox_pending` climbing plus delivery lag p50/p95 on
  `pico-audit-telemetry` - minutes; treat as incident if dead-letter grows.
- Tool-use audit target-mismatch review - minutes to hours depending on
  review cadence; automated deny is the primary signal.

Recovery steps executed as tabletop:

- Revoke: revoke `lse_01` and all leases for the affected sandbox; rotate
  downstream credentials; destroy-path revoke-all covers the destroy case.
- Isolate: isolate the sandbox network namespace; revoke the egress lease and
  remove the mapping; do not flush NAT by hand.
- Quarantine: quarantine the host only if runtime outcomes cluster there;
  otherwise keep the blast radius at sandbox and lease scope.
- Drain: no host drain in this scenario unless host health degrades.
- Rebuild: no host rebuild in this scenario.
- Rollback: revert the bad context or policy change from the control plane;
  confirm deny rate returns to baseline before re-enabling the affected tool.
- Notification: notify the tenant owner with scope, lifetime, and rotation
  guidance; page Security on protected-destination allows. Tenant-notice
  template is a gap (see G-01).
- Evidence preservation: keep broker, `LeaseRevoked`, `network_enforcement`,
  and `audit_delivery` events; block security-sensitive mutations while audit
  delivery is failing; replay dead-letters only with Security review and never
  delete the source outbox row.

No step relies on cooperation from the suspected workload. Revocation and
isolation use host-agent and control-plane authority with fencing.

## Scenario 3 - Snapshot/restore/fork leaks authority (Tree 3, R-11/R-16/R-17/R-18)

Initial state: tenant `tnt_c` snapshot `snap_09` with signed tenant/lineage
metadata, exclusion receipt for secret mounts, and encrypted integrity-protected
blob. Target host is healthy on the same backend and CPU shape.

- Adversarial action: restore is requested from a tampered blob with a
  cross-tenant lineage claim plus a captured pre-snapshot credential.
- Independent failure: resume notify returns `stale_epoch` and
  `session_mismatch` for the target sandbox during the same window.

Preventive checks walked in order with owners:

- Quiesce, revoke, zeroize, detach, and exclusion receipt at capture
  (Runtime and Security): fail-closed capture; artifact scan before use.
- Signed tenant/lineage metadata with collision-resistant IDs (Storage and
  Runtime): restore validates binding from trusted metadata.
- Authenticated encryption with exact compatibility gate (Runtime and
  Storage): integrity mismatch and CPU/backend/shape mismatch fail closed.
- Fresh authority on restore/fork (Runtime): new boot, protocol, network,
  lease, and credential authority; child never inherits parent leases,
  credentials, or port forwards.

Detection signals and maximum expected delays:

- `pico_restore_events_total{event="restore_failed"}` plus
  `snapshot_operation` integrity rejection - immediate.
- `resume_notify_stale_epoch` and `resume_notify_session_mismatch` on
  `pico-runtime-backend` - immediate; fail the resume and do not reuse the
  old session.
- `PicoComputeRestorePartialCleanup` page if partial cleanup occurs - immediate;
  treat as a failed restore.
- Snapshot metadata access audit for unexpected reads - minutes.

Recovery steps executed as tabletop:

- Revoke: revoke captured credentials; stop using the suspect snapshot ID.
- Isolate: do not reuse the workspace; leave the host for
  cleanup-reconciliation if partial cleanup occurred.
- Quarantine: quarantine the artifact and cache entry; quarantine the host
  only if resume failures cluster there.
- Drain: no host drain unless host health requires it.
- Rebuild: rebuild clean state from a trusted ancestor snapshot or cold boot
  if product allows; do not restore best effort.
- Rollback: disable restore/fork admission if a new release broke the path;
  revert the snapshot-manager or sandboxd rollout; confirm GC `skipped_ref`
  still protects live snapshots.
- Notification: page Storage and Security on integrity mismatch; notify the
  tenant owner without exposing another tenant identity. Template is a gap.
- Evidence preservation: keep `snapshot_operation`, `snapshot_metadata_access`,
  `lifecycle_transition`, and integrity-mismatch audit events; preserve the
  quarantined blob for review instead of deleting it.

No step relies on cooperation from the restored guest. Validation uses trusted
metadata and sandboxd authority before staging state.

## Scenario 4 - Destroy/reconciliation leaves residual authority (Tree 4, R-19/R-20/R-09/R-14)

Initial state: tenant `tnt_d` sandbox `sbx_21` on `hst_01` is destroyed
through the control-plane path. Leases, routes, mappings, cgroups, netns, and
workspace receipts are expected to reach absence with delayed reuse.

- Adversarial action: an operator attempts un-fenced `rm` of cgroups, netns,
  and workspaces to clear orphans quickly during on-call pressure.
- Independent failure: host loss on `hst_01` leaves unclassified orphan
  resources with expired leases and a partitioned capacity report.

Preventive checks walked in order with owners:

- Revoke-first destroy with receipt ledger (Runtime and Networking): revoke
  leases before removal; absence proof before identity/address/path reuse.
- Fencing with operation identity and idempotent steps (Control-plane and
  Runtime): stale retry converges to one outcome; mismatched fencing tokens
  are a control-plane bug, not a local `rm`.
- Quarantine on ambiguity (SRE and Runtime): ambiguous live resources
  quarantine rather than continue deletion.
- Durable audit outbox with ordering and integrity alerts (Observability and
  Security): gaps, dead-letters, and sequence holes are incidents.

Detection signals and maximum expected delays:

- `pico_gc_orphans_detected` sustained plus `pico_gc_review_required`
  and `network_reconciliation_review_required` - minutes; single pass with
  removal is a ticket, sustained drift is a page.
- `pico_quarantine_hosts_quarantined` for `cleanup_or_reconciliation_issue`
  or `stale_resources` - 1m to page; unresolved alerts page after 30m of
  `pico_quarantine_alerts_active > 5`.
- `cleanup_disposition` quarantine dispositions plus `host_disabled` - immediate.
- `PicoComputeHostAlertFiringRateHigh` if the pattern spreads - 5m sustained.

Recovery steps executed as tabletop:

- Revoke: confirm all sandbox leases are revoked with operation identity;
  foreign-sandbox leases survive per the destroy-path contract.
- Isolate: confirm the host cannot admit (`can_admit` false); do not fix
  fencing on the host.
- Quarantine: leave the host quarantined; `requires_review` is not retry `rm`.
- Drain: approved drain only with SRE approval if remaining sandboxes must
  be emptied; prefer natural completion.
- Rebuild: rebuild the host only with a reviewed ticket if leftovers survive
  the retry budget or span hosts/cells; SRE lead plus infra approval.
- Rollback: after approved fenced cleanup, require another reconciliation
  pass with zero orphans and zero review-required before re-admit; if cleanup
  made things worse, stop and keep the host quarantined.
- Notification: page SRE on review-required over 1h and SRE lead on
  cross-host spread; notify affected tenant owners of delayed reuse. Template
  is a gap.
- Evidence preservation: preserve `cleanup_disposition`, `host_disabled`,
  and `lifecycle_transition` records; never replay audit dead-letters as
  deletes; never edit the sandboxd ledger by hand.

No step relies on cooperation from the destroyed workload or the lost host
agent. Reconciliation uses authoritative control-plane state and fencing
tokens.

## Detection and recovery coverage

| Required path | Where it was exercised | Result |
|---|---|---|
| Revoke | Scenarios 1-4: promotion revoke, lease revoke and rotate, snapshot ID stop-use, destroy revoke-all | Pass; unit-tested revoke-all with operation identity |
| Isolate | Scenarios 1-4: placement exclusion, namespace isolation, artifact quarantine, admit-off | Pass |
| Quarantine | Scenarios 1-4: single-host, cell-wide, artifact, and cleanup quarantine | Pass; 120s auto-resolve verified in units |
| Drain | Scenarios 1 and 4 walked with approval gate; scenarios 2-3 correctly skipped drain | Pass as tabletop; live drain needs SRE approval and was not executed |
| Rebuild | Scenarios 3-4 walked as reviewed-ticket rebuild | Gap; no tested step-by-step rebuild procedure (see G-02) |
| Rollback | Scenarios 1-4: digest pin-back, policy revert, rollout revert, clean reconciliation pass | Pass as tabletop |
| Notification | All scenarios: owner paging works; tenant notice missing | Gap (see G-01) |
| Evidence preservation | All scenarios: durable outbox, dead-letter handling, no ledger edit, no outbox purge | Pass with triage friction (see G-03) |

## Gaps with owners

| ID | Gap | Risk | Owner | Blocking profile | Follow-up description | Evidence required for closure |
|---|---|---|---|---|---|---|
| G-01 | Tenant notification has no template, owner, or timing in the runbooks | R-10/R-11/R-14/R-20 | SRE with Product and Security | Any profile that notifies tenants of revoke/isolate/rebuild/rollback | Add a tenant-notification section to the runbook index with owner, triggers, template, timing, and audit record | Merged runbook section plus a tabletop rerun that uses the template |
| G-02 | Host rebuild is approval-only with no tested step-by-step rebuild procedure | R-13/R-19/R-20 and RR-01 | SRE with Runtime and Release | Launch tier recovery for host loss or VMM escape | Publish and exercise the cordon/drain/rebuild/re-admit procedure with rollback criteria | Dated rebuild exercise record with duration, approval evidence, and re-admit checks |
| G-03 | Cell-wide fire plus audit backlog has no combined triage view | R-09/R-20 | Observability with SRE | Launch tier incident triage | Document the joint audit-vs-runtime triage panel set or dashboard link used in scenario 4 | Merged runbook pointer plus drill rerun that uses the combined view |
| G-04 | Manual quarantine acknowledge/resolve, fenced cleanup, and un-drain have no shipped CLI helper | R-08/R-19/R-20 | SRE with Runtime and Control Plane | Operator response for quarantine and cleanup | Define the approved in-process operator procedure with ticket and fencing-token evidence, or ship the minimal approved helper | Merged procedure plus unit or integration test for the approved path |
| G-05 | Image-cache hit/miss/eviction panels are not emitted on the current build | R-03/R-20 | Image Pipeline with Observability | Image-linked boot triage | Emit the host image-cache metrics or document the fallback prepare-event/log/trace path with expiry | Live metric series or explicit fallback doc plus drill rerun |

## Exit criteria assessment

- Every critical and high risk in trees 1-4 was walked against an enforced
  control with a named owner and current evidence link. Prevention is enforced
  in code where claimed; detection and recovery do not substitute for missing
  prevention.
- Residual risks RR-01 through RR-08 keep exact scope, compensating controls,
  `not_accepted` status for public shared-host use, and review triggers. No
  silent acceptance was recorded.
- Audit and telemetry gaps are visible and fail closed: security-sensitive
  mutations block while audit delivery fails, and dead-letter replay needs
  Security review.
- Recovery reaches a known state without premature reuse: absence proof,
  fencing epochs, fresh authority on restore/fork, and clean reconciliation
  passes gate re-admit.
- Missing evidence blocks the affected profile: shared-host placement,
  tenant notification, rebuild procedure, and image-cache signals stay
  blocking until the follow-ups above close.
- Owners recorded: Security (facilitator), Runtime, Networking,
  Control-plane, Observability, and SRE reviewed the scenarios and gaps.

## Related

- [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) drill results for 2026-09-21
- Runbook index: [README](../README.md)
- Threat-model tabletop review procedure and risk trees
- Readiness review procedure and gate matrix
- Assurance claim C-06 detect/respond/recover evidence set
