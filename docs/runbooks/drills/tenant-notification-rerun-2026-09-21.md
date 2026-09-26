# Tenant Notification Rerun - 2026-09-21

**Owner**: SRE-PicoCompute with Product and Security
**Date**: 2026-09-21
**Source revision**: `ad4377d3c8ba3bd5ee51cbb1db5b58f61ef64521`
**Procedure**: threat-model tabletop review procedure, scenario rerun
**Template**: [runbook index tenant notification](../README.md#tenant-notification)
**Prior record**: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 2, gap G-01

Tabletop only. No host mutation, no drain RPC, and no live tenant send was
performed. This rerun replays scenario 2 with the merged notification
template filled for one affected tenant.

## Participants

- Security owner as facilitator
- Control-plane owner for lease and policy scope
- Networking owner for egress lease scope
- Observability owner for audit refs and redaction check
- SRE owner for timing and incident ticket

## Scenario replayed

From the prior tabletop scenario 2 (Tree 2, R-10/R-11/R-12/R-15):

- Initial: tenant `tnt_b` workload uses mediated access with lease `lse_01`
  bound to operation `op_77`, policy epoch `p42`, and an egress allowlist
  limited to `svc_api` with short expiry.
- Adversarial action: poisoned context induces a legitimate agent to call a
  tool against the wrong tenant resource and an unauthorized egress
  destination outside the allowlist.
- Independent failure: audit outbox pending climbs, so delivery lags and
  dead-letter risk rises.

Preventive checks from the prior record still hold: explicit target identity
with mediation deny, short-lived scoped tokens with broker deny on stale
epoch or overbroad scope, default-deny egress with policy DNS plus
lease-bound gateway, and source-side redaction with bounded schemas.

Detection from the prior record still holds: `network_enforcement` deny audit
plus egress deny counters (immediate), broker denial audit with
`pico_credential_denied_total` (immediate), `pico_audit_outbox_pending`
with delivery lag p50/p95 (minutes), and tool-use target-mismatch review
(minutes to hours, with automated deny as primary).

Recovery from the prior record still holds: revoke `lse_01` plus all leases
for the affected sandbox with rotation, isolate the namespace with egress
lease revoke and mapping removal, keep blast radius at sandbox and lease
scope, revert the bad context or policy change from the control plane, and
preserve broker plus `LeaseRevoked` plus `network_enforcement` plus
`audit_delivery` events with fail-closed mutation gating.

## Filled template (synthetic example for `tnt_b` only)

```
Subject: [PicoCompute] revoke/isolate notice for tnt_b in region_test/cel_east
Incident: INC-2026-09-21-02
Date: 2026-09-21 Revision: ad4377d3c8ba3bd5ee51cbb1db5b58f61ef64521
Scope (this tenant only): lease lse_01, operation op_77, policy epoch p42, egress allowlist svc_api
User-visible impact: mediated tool calls with lse_01 fail closed; unauthorized egress outside svc_api stays denied
Action taken: revoked lse_01 plus all leases for the affected sandbox; revoked the egress lease and removed the mapping; reverted the bad context change from the control plane
Tenant action: rotate downstream credential derived from lse_01; retry admitted calls with backoff; no secret material to return
Next update: on mitigation change or within 4h during ongoing impact; close notice follows recovery confirmation
Contact: SRE-PicoCompute via INC-2026-09-21-02
Audit refs: LeaseRevoked for lse_01 with operation identity; network_enforcement deny for the out-of-scope destination; audit_delivery for outbox lag window
```

Redaction check passed: no secret, token, boot secret, command, path,
workload output, raw error, other-tenant identity, registry credential, or
blob location in the notice. Only `tnt_b` scope is included. No
tenant/sandbox labels were attached to metrics.

## Timing check

- Owner paging: immediate per networking and audit-telemetry runbooks, with
  Security paged on protected-destination allows and SRE plus Security paged
  on audit loss or integrity gap.
- Initial tenant notice target: within 60m of confirmed user-visible impact
  for `tnt_b`. Met as tabletop; the filled notice above is ready to send on
  confirmation.
- Update trigger: mitigation change (revoke complete, egress mapping removed,
  context reverted) or 4h elapsed.
- Close trigger: deny rate back to baseline plus delivery lag back to baseline
  plus dead-letter disposition recorded.

## Audit record for this rerun

- Incident ticket `INC-2026-09-21-02` holds send time, recipient class
  (`tnt_b` owner), template fields above, and the underlying audit refs.
- Recovery evidence stays in the durable audit store keyed by `event_kind`
  with `operation_id=op_77` and `lease_id=lse_01`.
- Dead-letter replay, if needed, requires Security review and preserves the
  source outbox row.

## Gap closure assessment for G-01

- Trigger coverage: revoke, isolate, quarantine, drain, rebuild, and rollback
  notice cases are defined in the runbook index table. This rerun exercised
  the revoke plus isolate rows.
- Owner and timing: SRE-PicoCompute with Product and Security owns the path;
  initial/update/close timing is defined and was checked above.
- Template use: the filled notice above cites the merged template and passes
  the prohibited-content check.
- Remaining work: repeat this rerun pattern for drain/rebuild/rollback rows
  during those exercises; no new template change is needed for closure.

## Related

- Template: [runbook index](../README.md#tenant-notification)
- Prior scenarios: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md)
- Drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md)
- Runbooks: networking, audit-telemetry, lifecycle-operations
