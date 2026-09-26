# Control Plane

**Owner**: SRE-PicoCompute/Control Plane
**Alert category**: `regional_lifecycle_failure`
**Severity**: Page when admission fails region-wide; ticket for credential or policy spikes with successful creates
**Dashboards**: `pico-control-plane`, `pico-lifecycle-operations`, `pico-scheduling-capacity`

## When to use

Sandbox create is rejected at admission, policy, quota, or credential issue,
before or instead of a host boot failure.

## Severity

| Condition | Level |
|---|---|
| `create_failed` elevated and placement/boot are healthy | Page Control Plane |
| Credential deny rate up with creates still succeeding | Ticket Security/Control Plane |
| Quota rejections only | Ticket (expected under tenant pressure) |
| Policy deny storm across tenants | Page Security |

## First checks

1. `pico-control-plane` -> **Admission & Auth Rates**.
   `pico_create_events_total` by `event`. `create_failed` without matching
   `boot_not_ready` is this runbook.
2. **Admission Latency** p95/p99. Latency without failures is API/scheduler
   saturation: continue to [scheduling-capacity](scheduling-capacity.md).
3. **Credential Issue Success Rate**:
   `issued/(issued + denied)`. A drop with stable creates is broker/policy,
   not lifecycle.
4. Confirm scheduling is not the cause: **Hosts Evaluated vs Passed
   Constraints** on `pico-scheduling-capacity`.

Do not restart API replicas as a first action. Do not mutate hosts.

## Logs, traces, audit

**Logs**

```
{service_name="pico-api"} | json | outcome=~"policy_rejected|quota_rejected|placement_failed"
```

**Traces**

Span `request` then `create` on `PolicyEnforcingAgent`. If the trace never
reaches `host_agent_rpc`, the host is innocent.

**Audit**

- `policy_decision`/`policy_change`
- `quota_rejection`
- `placement_outcome`
- `credential_issuance`/`credential_denied`/`credential_revoked`
- `lease_*` if create died on lease invalid/expired/revoked

## Mitigation

1. Policy deny: stop rolling policy or bundle changes. Revert the last policy
   epoch from control-plane config, not from hosts.
2. Quota: do not raise quotas during an incident unless Product/Control Plane
   approve. Shed new creates if the quota service is wrong-open or wrong-closed.
3. Credential deny: revoke is working as designed if Security is rotating.
   If issue fails, fail closed; do not inject ambient credentials.
4. API errors with empty audit: treat as [audit-telemetry](audit-telemetry.md).
   Authoritative mutations must not be acknowledged without audit enqueue.

## Escalation

- Page Control Plane if create fails in more than one cell and traces stop
  before `host_agent_rpc`.
- Page Security for cross-tenant policy deny or credential anomalies.
- Page SRE if admission latency is high **and** placement efficiency has
  collapsed (capacity, not API).

## Rollback

1. Revert the last policy/quota/admission config change.
2. Confirm `create_completed` recovers and credential success rate returns
   to baseline for 15m.
3. Leave host drain/quarantine untouched unless a host runbook also fired.

## Related

- [lifecycle-operations](lifecycle-operations.md)
- [scheduling-capacity](scheduling-capacity.md)
- [audit-telemetry](audit-telemetry.md)
