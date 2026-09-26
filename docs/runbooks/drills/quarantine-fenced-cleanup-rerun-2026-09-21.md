# Quarantine and Fenced Cleanup Rerun - 2026-09-21

**Owner**: SRE-PicoCompute with Runtime and Control Plane
**Date**: 2026-09-21
**Source revision**: `d088cef4b4e02e1c5feaab096854b090ac0114d3` (base; helper walk verified against the PR head, re-confirm revision at merge)
**Procedure**: threat-model tabletop review procedure, scenario rerun
**Runbooks**: [host-quarantine](../host-quarantine.md#operator-procedure-approved-helper), [cleanup-reconciliation](../cleanup-reconciliation.md#operator-procedure-approved-helper)
**Prior records**: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md) injects 2-3, [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md) scenario 4, gap G-04

Tabletop only. No host mutation, no drain RPC, no GC deletion, and no
ledger edit was performed. This rerun replays injects 2-3 with the merged
operator helper offline plus the unit-tested gates in
`pico-core::operator`.

## Participants

- SRE owner as facilitator and ticket owner
- Runtime owner for quarantine, GC, and ledger behavior
- Control-plane owner for fencing tokens and scheduler exclusion
- Networking owner for reconciliation classification
- Observability owner for quarantine gauges and audit refs

## Scenario replayed

From the boot drill inject 2 (protocol non-ready on one host) and inject 3
(cleanup review-required), plus tabletop scenario 4 (destroy leaves residual
authority):

- Initial: host `hst_01` in `cel_east` with healthy peers; tenant `tnt_d`
  sandbox `sbx_21` destroyed through the control-plane path.
- Inject 2 signals: `pico_boot_events_total{event="boot_not_ready",reason="protocol"}`
  clustered on `hst_01`; `pico_quarantine_hosts_quarantined=1`;
  `PicoComputeHostQuarantined` firing; condition `repeated_runtime_outcomes`.
- Inject 3 signals: `pico_gc_review_required` and
  `network_reconciliation_review_required` active; orphans detected with zero
  removed; `cleanup_disposition` audit as authoritative record; condition
  `cleanup_or_reconciliation_issue`.
- Scenario 4 pressure: an operator attempts un-fenced `rm` under on-call
  pressure while `hst_01` holds unclassified orphans with expired leases.

Preventive checks from the prior records still hold: telemetry before SSH,
leave the single bad host quarantined, stop deleting on `requires_review`,
and refuse un-fenced GC plus ledger edits plus signature bypass without
approval.

## Helper walk (offline, ticket INC-2026-09-21-04)

Acknowledge keeps the host out of placement with an owner:

```
pc operator quarantine-ack --ticket INC-2026-09-21-04 --host hst_01 \
  --condition repeated_runtime_outcomes --owner sre-pico
```

Output records ticket, host, condition, and owner for the in-process
`AlertStateManager::acknowledge` call. A blank owner fails closed and was
verified in units.

Resolve requires a cleared condition:

```
pc operator quarantine-resolve --ticket INC-2026-09-21-04 --host hst_01 \
  --condition cleanup_or_reconciliation_issue --condition-cleared
```

Without `--condition-cleared` the helper fails closed. Manual resolve is
only for the cleared case with the approved owner re-admitting the host.
Auto-resolve after 120s remains the default.

Fenced cleanup requires fencing-token evidence:

```
pc operator fenced-cleanup --ticket INC-2026-09-21-04 --fencing-token 42.7,43.0
```

Tokens are `epoch.sequence` from control-plane authority. Empty or
unparsable tokens fail closed. Mismatched tokens stop the cleanup and page
control-plane instead of running a local rm. `gc --force-stale` is not
shipped and has no flag in the helper.

Ledger inspect stays read-only:

```
pc operator ledger-inspect --ticket INC-2026-09-21-04 --query sandbox-status --sandbox-id sbx_21
pc operator ledger-inspect --ticket INC-2026-09-21-04 --query list-receipts --sandbox-id sbx_21
pc operator ledger-inspect --ticket INC-2026-09-21-04 --query gc-stats
pc operator ledger-inspect --ticket INC-2026-09-21-04 --query findings
```

Write-like queries (`edit`, `delete`, `rm`, `gc --force-stale`) fail closed
in units. Ledger edits by hand remain prohibited.

Drain uses the existing RPC with ticket evidence (not executed here):

```
export PICO_HOST_TOKEN="<bearer-token>"
pc operator drain --host-url http://hst-01:8081 --ticket INC-2026-09-21-04
pc operator drain-status --host-url http://hst-01:8081
```

Drain needs SRE on-call approval with sandbox count, RPC time, and operator
recorded. No undrain flag exists; the parser rejects `undrain` in units.

Re-admit requires every gate:

```
pc operator readmit-check --quarantine-gauge-zero --capacity-age-secs 12 \
  --health ready --reconciliation-clean --watch-clean
```

Gates: gauge at 0, capacity age under 60s, health `ready` or `degraded`,
clean reconciliation pass with zero orphans and zero review-required, and a
5m watch with no new alert. Each failing gate was verified to block in units.

## Evidence commands for this revision

- `cargo nextest run -p pico-core --lib operator host_quarantine availability` - 74 passed
- `cargo nextest run -p pico-cli --bins` - 27 passed (includes drain bearer test, health shape rejection, prohibited-command rejection, and explicit-health requirement)
- `cargo nextest run -p pico-core --lib host_quarantine availability` - 59 passed (existing quarantine behavior unchanged)

## Audit record for this rerun

- Incident ticket `INC-2026-09-21-04` holds host, cell, region, trigger,
  sandbox count, fencing tokens `42.7,43.0`, helper outputs above, and the
  underlying `host_disabled`, `cleanup_disposition`, `runtime_outcome`, and
  `lifecycle_transition` event IDs.
- Recovery evidence stays in the durable audit store. Log text is not the
  recovery record.
- Dead-letter replay, if needed, requires Security review and preserves the
  source outbox row.

## Gap closure assessment for G-04

- Acknowledge/resolve: approved in-process path with ticket plus owner plus
  cleared-condition gates is merged in host-quarantine with helper commands
  and unit coverage. Inject 2 can close.
- Fenced GC: ticket plus fencing-token gate with no force flag is merged in
  cleanup-reconciliation with helper commands and unit coverage. Inject 3
  can close.
- Ledger inspect: read-only allowlist with prohibited-write rejection is
  merged with unit coverage. Inject 3 can close.
- Drain/undrain: drain wraps the existing RPC with ticket evidence and bearer
  auth coverage; no undrain exists by design with parser rejection coverage
  and re-admit gates. Injects 2-3 can close.
- Remaining work: live drain still needs SRE approval per call; live fenced
  cleanup still needs per-call SRE on-call approval with receipts and a clean
  follow-up pass.

## Related

- Procedures: [host-quarantine](../host-quarantine.md#operator-procedure-approved-helper), [cleanup-reconciliation](../cleanup-reconciliation.md#operator-procedure-approved-helper), [host-rebuild](../host-rebuild.md)
- Prior drill: [boot-non-ready-and-quarantine](boot-non-ready-and-quarantine.md)
- Prior tabletop: [incident-tabletop-2026-09-21](incident-tabletop-2026-09-21.md)
- Code: `crates/pico-core/src/operator.rs`, `crates/pico-cli/src/operator.rs`
