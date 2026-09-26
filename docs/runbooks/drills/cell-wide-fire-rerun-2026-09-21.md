# Cell-Wide Fire Rerun - 2026-09-21

**Owner**: Observability with SRE
**Date**: 2026-09-21
**Source revision**: `32fdcb210dbb7996933a06c8840996cbb486ab81`
**Procedure**: threat-model tabletop review procedure, scenario rerun
**Combined view**: [runbook index combined triage view](../README.md#cell-wide-fire-with-audit-backlog---combined-triage-view)
**Prior record**: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4, gap G-03
**Drill inject**: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) inject 4
**Ticket**: `INC-2026-09-21-03` (synthetic tabletop ticket)

Tabletop only. No host mutation, no drain RPC, no restart, no GC, no rebuild,
no outbox purge, and no ledger edit was performed. This rerun replays the
cell-wide fire plus audit backlog inject using the merged combined triage view
instead of manually correlating across dashboards.

## Participants

- Observability owner as facilitator and view owner
- SRE owner for quarantine, admission shed, and incident ticket
- SRE lead for the cell-level admission-shed decision
- Runtime owner for host, VMM, guest, and cleanup behavior
- Networking owner for namespace and egress lease scope
- Control-plane owner for scheduler exclusion, leases, and fencing
- Security owner for audit integrity and evidence preservation

## Candidate profile

| Field | Value |
|---|---|
| Date | 2026-09-21 |
| Source revision | `32fdcb210dbb7996933a06c8840996cbb486ab81` |
| Workload class | Internal test, dedicated tenancy fallback, no shared-host placement |
| Region/cell/host | `region_test`/`cel_east`/`hst_01` plus two peer hosts for cell-wide injects |
| Backend | `MockBackend` for unit evidence; Firecracker/QEMU preview and gVisor trusted fast path as tabletop-only profiles |
| Host profile | Facilitator host Darwin arm64; production candidate is Linux KVM per live-boot evidence procedure |
| Network | Default-deny per-sandbox namespace, policy DNS, lease-bound gateway |
| Credential mode | Short-lived scoped leases with revoke-first destroy |
| Snapshot mode | Sandboxd-owned `Restore` and `Fork` RPC path with fresh authority on restore plus fork |
| Audit | Durable transactional outbox, `audit_delivery` events, dead-letter table as evidence |
| Telemetry | `o11y/rules/pico-recording-rules.yaml` plus `PicoCompute` Grafana folder |

Evidence commands rerun for this revision:

- `scripts/validate-o11y-dashboards.sh` - pass, all dashboards and runbook links resolve
- `cargo nextest run -p pico-core --lib host_quarantine availability` - 59 passed
- `cargo nextest run -p pico-core --test control_plane_readiness destroy_revokes_all_sandbox_leases` - pass

## Scenario replayed

From the prior tabletop scenario 4 (Tree 4, R-19/R-20/R-09/R-14) plus the
boot drill inject 4 cell-wide fire:

- Initial: tenant `tnt_d` sandbox `sbx_21` on `hst_01` is destroyed through
  the control-plane path. Leases, routes, mappings, cgroups, netns, and
  workspace receipts are expected to reach absence with delayed reuse.
- Adversarial action: an operator attempts un-fenced `rm` of cgroups, netns,
  and workspaces to clear orphans quickly during on-call pressure.
- Independent failure: host loss on `hst_01` leaves unclassified orphan
  resources with expired leases and a partitioned capacity report.
- Cell-wide extension for this rerun: three hosts in `cel_east` quarantine
  within one window while `pico_audit_outbox_pending` climbs and delivery
  lag p50/p95 rises. `PicoComputeHostAlertFiringRateHigh` fires.

The prior record walked recovery correctly but split audit-telemetry vs
runtime across separate dashboards with manual correlation. This rerun walks
the same recovery using the combined view panel order.

## Combined-view walk

All panels were filtered by `region_test` plus `cel_east` first. Values below
are facilitator-stated inject values for the tabletop walk, read in the
merged view order.

| Order | Panel read in the view | Rerun reading |
|---|---|---|
| 1 - Quarantine scope | `pico-scheduling-capacity` - **Hosts Quarantined (S-FAIL-HOST)** | 3 hosts quarantined in `cel_east`; `pico_quarantine_hosts_quarantined` greater than 0 for more than 1m so `PicoComputeHostQuarantined` fires; firing rate greater than 1 per second over 5m so `PicoComputeHostAlertFiringRateHigh` fires; `pico_quarantine_alerts_active` at 4 and rising. Alert labels carry `host_id`, `cell_id`, `region`, `condition`, `severity`. Conditions present: `stale_resources` plus `cleanup_or_reconciliation_issue`. |
| 2 - Audit backlog | `pico-audit-telemetry` - **Audit Outbox Pending**, **Audit Delivery Lag (p50/p95)**, **Audit Delivery Rate** | `pico_audit_outbox_pending` climbing through 100 toward 1000; lag p50 rising with p95 wider; delivery rate flat while pending climbs, so backlog not stall. `audit_delivery` events show enqueue succeeding with delivery behind. No dead-letter growth yet, so treat as backlog under pressure, not loss. |
| 3 - Lifecycle impact | `pico-lifecycle-operations` - **Operation Volume by Phase** | `pico_boot_events_total{event="boot_not_ready"}` clustered on the three quarantined hosts; `pico_gc_orphans_detected` path uses `reason="cleanup"` on `hst_01`; creates show `create_failed` with `no_host_available` on the affected cell; exec stays near baseline. Pattern matches runtime-led degradation on quarantined hosts, not a fleet-wide image or network cause. |
| 4 - Cleanup drift | `pico-cleanup-reconciliation` - **Orphans Detected vs Removed**, **GC Review Required**, **Network Review Required**, **Reconciliation Health State** | Orphans detected sustained with zero removed on `hst_01`; `pico_gc_review_required` at 2 and `network_reconciliation_review_required` at 1, so both orange. Health state degraded. Dispositions are quarantine, not removal. |
| 5 - Placement plus health | `pico-scheduling-capacity` - **Hosts Evaluated vs Passed Constraints**, **Placement Efficiency Ratio**; `pico-host-health` - **Active Sandbox Count per Host**, **Draining Hosts** | Evaluated stays high with passed near zero on the three hosts, so constraint exclusion not inventory loss. Efficiency ratio collapsed on `cel_east`. Sandbox counts still present on quarantined hosts; draining table empty because no drain RPC was approved. Missing series was checked and ruled out: series are present, so this is placement exclusion, not stale telemetry. |

Log plus trace plus audit pivots walked after the panels:

- Logs: `{service_name="pico-host-agent"} | json | event="boot_not_ready"` for the reason split; `{service_name=~"pico-api|pico-host-agent"} | json | event=~"audit_.*"` for the backlog window.
- Traces: failed `boot_sandbox` plus `destroy` spans on the quarantined `host_id` values; no tenant trace for quarantine itself.
- Audit: `host_disabled` for the three exclusions, `cleanup_disposition` for quarantine dispositions, `lifecycle_transition` for `sbx_21`, `placement_outcome` with `no_host_available`, plus `audit_delivery` for the lag window. No sequence hole and no dead-letter replay in this rerun.

## Decision reached with the view

Both sides active per the view decision table: quarantine gauges up plus
outbox climbing plus lifecycle degraded on the same hosts plus
review-required active.

- The facilitator did not restart every host-agent.
- The team did not quarantine the whole cell on telemetry alone and did not
  blame one kernel.
- SRE lead decided cell-level create admission shed at the API instead of
  host mutation. `POST /rpc/v1/drain` was held as approved-only fallback and
  was not called. Fenced cleanup was held to ticket plus fencing-token
  evidence and was not executed live.
- Security confirmed fail-closed gating for security-sensitive mutations
  while delivery lagged, with no dead-letter replay in this walk.

The prior gap was manual correlation across dashboards. In this rerun the
facilitator read steps 1 through 5 in one order without switching context,
and the decision above cites that order.

## Recovery steps confirmed

Recovery from the prior record still holds, now keyed to the view:

- Revoke: confirm all sandbox leases are revoked with operation identity;
  foreign-sandbox leases survive per the destroy-path contract.
- Isolate: confirm the hosts cannot admit (`can_admit` false); do not fix
  fencing on the host.
- Quarantine: leave the three hosts quarantined; `requires_review` is not
  retry `rm`.
- Drain: approved drain only with SRE approval if remaining sandboxes must be
  emptied; prefer natural completion.
- Rebuild: rebuild only with a reviewed ticket if leftovers survive the retry
  budget or span hosts plus cells; SRE lead plus infra approval.
- Rollback: after approved fenced cleanup, require another reconciliation
  pass with zero orphans and zero review-required before re-admit; if cleanup
  made things worse, stop and keep the hosts quarantined.
- Notification: page SRE on review-required over 1h and SRE lead on
  cross-host spread; tenant notice follows the runbook index template for
  affected tenants only.
- Evidence preservation: preserve `cleanup_disposition`, `host_disabled`,
  and `lifecycle_transition` records; never replay audit dead-letters as
  deletes; never edit the sandboxd ledger by hand; never purge the outbox.

No step relies on cooperation from the destroyed workload or the lost host
agent. Reconciliation uses authoritative control-plane state and fencing
tokens.

## Audit record for this rerun

- Incident ticket `INC-2026-09-21-03` holds the timestamped combined-view
  readings above, the SRE lead admission-shed decision, sandbox counts, and
  the underlying audit event IDs.
- Recovery evidence stays in the durable audit store keyed by `event_kind`
  with `cell_id=cel_east` and the destroying operation identity for `sbx_21`.
- Dead-letter replay, if needed, requires Security review and preserves the
  source outbox row. The ledger was never edited by hand.

## Gap closure assessment for G-03

- Merged pointer: the runbook index publishes the combined triage view with
  fixed panel order plus thresholds plus the audit-vs-runtime decision table,
  linked from host-quarantine and audit-telemetry first checks and related
  sections.
- Panel coverage: outbox pending, delivery lag p50/p95 plus rate, quarantine
  gauges plus firing rate plus active alerts, lifecycle volume plus
  `boot_not_ready` by `reason`, cleanup orphans plus review-required plus
  health state, and placement evaluated-vs-passed plus sandbox counts are all
  read in one procedure.
- Drill rerun: this record replays the cell-wide inject using that view and
  cites panel readings in view order with the both-sides-active decision and
  the SRE lead admission-shed outcome.
- Remaining work: live timings stay estimates until a staging cell-wide
  exercise measures them. No new procedure change is needed for closure; the
  follow-up is to attach measured timings to the same ticket pattern when a
  staging drill runs.

## Related

- Combined view: [runbook index](../README.md#cell-wide-fire-with-audit-backlog---combined-triage-view)
- Prior scenarios: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4
- Drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) inject 4
- Runbooks: host-quarantine, audit-telemetry, lifecycle-operations,
  cleanup-reconciliation, scheduling-capacity, host-health, host-rebuild
