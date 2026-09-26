# DNS

**Owner**: Networking/SRE-PicoCompute
**Alert category**: `security_event`, `regional_lifecycle_failure`
**Severity**: Page for wrong allow/deny or resolver failure; ticket for cache hit-rate drift
**Dashboards**: `pico-dns`, `pico-networking`, `pico-lifecycle-operations`

## When to use

Sandbox DNS allow/deny/fail is wrong, resolution latency is high, or policy
actions do not match the intended default-deny posture.

## Severity

| Condition | Level |
|---|---|
| `network_dns_failed` cell-wide, or resolution p99 collapse | Page Networking |
| Unexpected `allow_rule`/`default_allow` to a blocked class | Page Security |
| Deny increase that matches a policy rollout | Ticket (confirm intended) |
| Cache hit ratio drop, failures not up | Ticket |

## First checks

1. `pico-dns` -> **DNS Query Volume** (`network_dns_queries_total`).
2. **DNS Allowed/Denied/Failed**: `network_dns_allowed`,
   `network_dns_denied`, `network_dns_failed`.
3. **DNS Policy Actions** (`allow_rule`, `deny_rule`, `default_allow`,
   `default_deny`, `platform_internal`, `unsupported_qtype`, `no_policy`,
   `ipv6_unsupported`).
4. **DNS Resolution Latency** and **DNS Cache Hit Ratio**.
5. **DNS Registered Sandboxes**. A drop with live sandboxes is agent/registry
   loss, not tenant traffic.
6. `pico-networking` egress deny/allow to see whether DNS or forwarding
   is the broken layer.

Do not change host stub resolvers. Do not flush the DNS cache on the host.

## Logs, traces, audit

**Logs**

```
{service_name="pico-network-agent"} | json | event=~"dns.*"
```

Queries do not include raw QNAME in metrics. Do not add domain labels.

**Traces**

Network `provision` and DNS policy spans on the request that triggered
resolution. Pivot `trace_id` from `network_enforcement` audit.

**Audit**

`network_enforcement` for each policy decision. This is the source of truth
for allow/deny, not the cache hit ratio.

## Mitigation

1. Wrong allow: revert the DNS policy epoch. Keep default-deny. Do not
   "temporarily allow" from the host.
2. Resolver failure: fail closed (deny/fail). Shed creates if guests cannot
   reach required platform names (`platform_internal`).
3. `ipv6_unsupported`/`unsupported_qtype`: expected denials. Do not enable
   IPv6 on the host to silence them.
4. `no_policy`: treat as a control-plane bug. Do not invent a host-local
   default.

## Escalation

- Page Security if an allow appears for a protected or default-deny class.
- Page Networking if `network_dns_failed` is cell-wide.
- Page Control Plane if registered sandbox count diverges from host sandbox
  count.

## Rollback

1. Revert the DNS policy or network-agent rollout.
2. Confirm allowed/denied ratios and p95 latency match the pre-incident
   baseline for 15m.
3. Do not rebuild the cache; it refills on the next queries.

## Related

- [networking](networking.md)
- ADR-0005 per-sandbox networking
