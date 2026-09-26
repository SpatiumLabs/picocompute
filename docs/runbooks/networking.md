# Networking

**Owner**: Networking/SRE-PicoCompute
**Alert category**: `regional_lifecycle_failure`, `security_event`, `cleanup_drift`
**Severity**: Page for cell-wide setup/enforcement failure; quarantine one unsafe host; ticket for NAT/session drift
**Dashboards**: `pico-networking`, `pico-dns`, `pico-cleanup-reconciliation`, `pico-host-health`

## When to use

Boot is `boot_not_ready` with `reason=network`, network setup does not
complete, egress deny/allow is wrong, NAT/port-forward misbehaves, or
suspend/resume/fork network ops fail.

## Severity

| Condition | Level |
|---|---|
| `network_setup_not_completed` or boot `reason=network` cell-wide | Page Networking |
| Egress allow to a protected destination, or deny storm on legitimate traffic | Page Security |
| One host `pico_network_health_state=2` (unsafe) | Quarantine |
| Cleanup/rollback incomplete | Quarantine ([cleanup-reconciliation](cleanup-reconciliation.md)) |

## First checks

1. `pico-lifecycle-operations`: `boot_not_ready{reason="network"}`.
   Platform `outcome=network_setup_failed`.
2. `pico-networking` -> **Network Setup Volume**
   (`network_setup_completed` vs `network_setup_not_completed`) and **Setup
   Latency**.
3. **Cleanup Volume** (`network_cleanup_completed`, `network_cleanup_absent`).
4. **Egress Allowed vs Denied**, **Active NAT Sessions**.
5. **Suspend/Resume Network Ops** and **Fork Network Ops**
   (`network_fork_failed`, `network_fork_port_inheritance_blocked`).
6. **Bandwidth Limits Active**.
7. If DNS volume/deny is the story, continue to [dns](dns.md).

Do not `ip netns`, `iptables`, or `tc` on the host. Do not "fix" NAT by
flushing tables.

## Logs, traces, audit

**Logs**

```
{service_name=~"pico-host-agent|pico-network-agent"} | json | event=~"network.*|boot_not_ready"
```

Setup-not-completed reasons include `provision_failure` and `route_add`.

**Traces**

`NetworkAgent::provision` span `provision` under `prepare_sandbox` /
`boot_sandbox`.

**Audit**

`network_enforcement` for DNS, egress, and port-forward.
`cleanup_disposition` when setup rolls back.

## Mitigation

1. Cell-wide setup failure: stop new creates that need network (admission
   shed). Do not provision by hand.
2. Policy deny that is correct: do not punch holes. Point the tenant at
   policy.
3. Policy deny that is a bad rollout: revert the network policy epoch from
   the control plane.
4. Unsafe host: leave quarantined. Reconciliation will `requires_review`
   rather than guess ([cleanup-reconciliation](cleanup-reconciliation.md)).
5. Fork port inheritance blocked: expected when the child must not inherit
   exposure. Fail the fork; do not copy forwards.

## Escalation

- Page Networking if setup fails on more than one host in 15m.
- Page Security on protected-destination allows or unexpected expose.
- Page SRE if cleanup/rollback leaves orphans.

## Rollback

1. Revert the last network policy or CNI/agent rollout.
2. Confirm `network_setup_completed` and `boot_ready` recover for 15m.
3. Do not mark rollback complete until **Cleanup Volume** matches setup
   and [cleanup-reconciliation](cleanup-reconciliation.md) review-required
   is 0 on the host.

## Related

- [networking readiness report](../robustness/network-prod-readiness-report.md)
- [dns](dns.md)
- [cleanup-reconciliation](cleanup-reconciliation.md)
- [lifecycle-operations](lifecycle-operations.md)
- ADR-0005 per-sandbox networking
