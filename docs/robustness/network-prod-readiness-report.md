# Per-Sandbox Networking Production Readiness Report

**Date**: 2026-09-23
**Status**: Draft (pending Networking, Runtime, Platform, and SRE owner review)
**Strategy**: [ADR-0005](../adr/0005-per-sandbox-networking-model.md)
**Posture**: [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Readiness model**: [Production readiness](../security/production-readiness.md) gate `G-07`
**Assurance parent**: [Security assurance case](../security/assurance-case.md) claim `C-03`

## Executive Summary

This report validates PicoCompute per-sandbox networking as an integrated
subsystem before production rollout. Validation composes the networking ADR,
TAP and veth identity, egress and NAT policy, DNS policy, lease-bound port
forwarding, the HTTP edge proxy, suspend/resume/fork decisions, cleanup and
reconciliation, and tenant-safe metrics through the existing automated
suites.

**Overall verdict**: the networking subsystem meets the G-07 evidence bar
that can be executed without a privileged Linux host, with the exceptions in
section 10. On 2026-09-23 the evidence suites passed: 237 network-agent
tests, 5 sandboxd network tests, 22 host-agent port-forward tests, and 16
edge tests (280 total). `cargo clippy -p pico-network-agent --lib --tests --locked -- -D warnings`
is clean. MicroVM and container identities are distinct and fit Linux
interface-name limits. Egress defaults to deny, including protected internal
ranges. DNS policy is first-match and blocks platform-internal names. Port
forwarding and the edge proxy require a valid lease when lease checks are
on. Resume rejects a stale or unset policy epoch and a mismatched network
identity. Fork allocates a new identity and blocks port inheritance. Cleanup
reconciliation fails closed on ambiguous ownership.

This report is not launch approval. ADR-0005 remains Proposed. Live
namespace, TAP, nftables, and NAT attachment on a Linux host is outside this
run. IPv6 stays disabled until the ADR's equivalent controls exist. Owner
sign-off is recorded as pending in Approval.

## How to Run the Evidence

```bash
cargo nextest run -p pico-network-agent --lib --tests
cargo nextest run -p pico-sandboxd --test network
cargo nextest run -p pico-host-agent --lib port_forward port_proxy port_target_cache
cargo nextest run -p pico-edge --lib
cargo clippy -p pico-network-agent --lib --tests --locked -- -D warnings
```

Suite mapping to validation areas:

| Validation area | Suite | Location |
|---|---|---|
| Networking model and ownership | ADR-0005 | `docs/adr/0005-per-sandbox-networking-model.md` |
| TAP, veth, and route identity | network-agent lib | `crates/pico-network-agent/src/identity.rs`, `tap.rs`, `veth.rs`, `route.rs` |
| Egress, NAT, bandwidth | egress integration plus lib | `crates/pico-network-agent/tests/egress_integration.rs` |
| DNS policy | lib plus property tests | `crates/pico-network-agent/src/dns/`, `tests/policy_property.rs` |
| eBPF policy mirror | eBPF integration | `crates/pico-network-agent/tests/ebpf_integration.rs` |
| Cleanup and reconciliation | reconciliation integration | `crates/pico-network-agent/tests/reconciliation_integration.rs` |
| sandboxd prepare/cleanup ownership | sandboxd network tests | `crates/pico-sandboxd/tests/network.rs` |
| Suspend, resume, fork decisions | lifecycle lib tests | `crates/pico-network-agent/src/lifecycle.rs` |
| Lease-bound port forwarding | host-agent lib | `crates/pico-host-agent/src/port_forward.rs`, `port_proxy.rs`, `port_target_cache.rs` |
| HTTP edge proxy (Pingora) | edge lib | `crates/pico-edge/src/proxy.rs` |
| Metrics and dashboards | lib plus dashboard JSON | `crates/pico-network-agent/src/metrics.rs`, `o11y/networking.json`, `o11y/dns.json` |
| Operator response | runbooks | `docs/runbooks/networking.md`, `docs/runbooks/dns.md`, `docs/runbooks/cleanup-reconciliation.md` |

Related prior evidence (not duplicated here): backend readiness in
`docs/robustness/backend-prod-readiness-report.md`, control-plane readiness
in `docs/control-plane/prod-readiness-report.md`, snapshot readiness in
`docs/robustness/snapshot-readiness-report.md`, threat model in
`docs/security/threat-model.md`.

## 1. Ownership Boundaries

ADR-0005 assigns one owner to each networking decision:

| Concern | Owner |
|---|---|
| Admission, desired policy, logical identity | Regional control plane |
| Lease issuance and revocation | Regional access lease manager |
| Workflow ordering and durable receipts | `sandboxd` |
| Namespace, TAP, veth, route, nftables, NAT | `network-agent` |
| Backend attachment of a pre-created device | Runtime adapter |
| DNS answer policy | DNS policy proxy |
| Ingress admission | Port-forward gateway, then `pico-edge` for HTTP |
| Counters and local health | `network-agent` metrics |

`pico-edge` is the HTTP and WebSocket proxy in front of host-agent
port-forward listeners. It is a production candidate for programmable proxy
behavior: lease checks, host routing, rate and connection limits, and
`NetworkEnforcement` audit events. It does not replace Linux namespaces,
nftables, DNS policy, reconciliation, or snapshot handling.

Pingora graceful reload, request-body limits, and WebSocket drain behavior
are provided by the Pingora server lifecycle (`crates/pico-edge/src/proxy.rs`
documents the contract). This suite does not drive a live reload or a
WebSocket upgrade. Those remain open limitations in section 10.

## 2. Network Setup for Supported Backends

ADR-0005 requires two attachment shapes under one identity contract:

| Backend class | Objects |
|---|---|
| MicroVM (Firecracker, QEMU) | Dedicated namespace, TAP, host uplink, guest and host addresses, route |
| Container (gVisor and other container backends) | Dedicated namespace, veth pair, addresses, route |

`SandboxNetworkIdentity::for_sandbox` derives both shapes from the sandbox
id. The same id is stable across calls. A different id, or the same id with
a different backend class, produces a different host interface and namespace
path. Resource names are hash-derived and do not embed the tenant or sandbox
string.

Interface names must be at most 15 characters (Linux `IFNAMSIZ`). The
microVM host peer was `hp-` plus the 13-character TAP name (16 characters),
which `bandwidth::validate_if_name` rejects. The host peer is now `hp-` plus
the same 10 hex digits (`hp-{hex}`, 13 characters). The TAP name (`cvx{hex}`)
is unchanged, including the pinned live-boot vector in
`identity::tests::pinned_vector_for_external_tap_provisioning`.
Reconciliation builds expected link and namespace names from
`SandboxNetworkIdentity` so the cleanup set cannot drift from the
provisioner.

On non-Linux hosts, `NetworkAgent::provision` and `provision_all` return
`UnsupportedPlatform` (`lib.rs` tests). TAP and veth provisioning functions
return the same error. This run does not claim a live Linux namespace was
created.

sandboxd records the ownership boundary:

| Test | Proves |
|---|---|
| `network_disabled_prepare_has_no_tap_receipt` | Network-off prepare does not invent a TAP receipt |
| `network_enabled_records_tap_receipt_on_prepare` | Enabled prepare records the TAP receipt |
| `network_provision_failure_fails_prepare_closed` | A provision error fails prepare |
| `failed_backend_prepare_releases_network_receipts` | A failed backend prepare releases network receipts |
| `empty_cleanup_does_not_mark_tap_released` | Cleanup does not claim a TAP release it did not perform |

## 3. Egress Policy and NAT

Default egress is deny. Compiling a policy with no CIDRs produces a deny-all
ruleset. RFC1918, CGNAT (`100.64.0.0/10`), link-local, loopback, and
multicast ranges are denied unless an egress lease grants an exception
(`egress_policy_internal_networks_are_protected_by_default`,
`egress_policy_lease_internal_network_exception`). A policy with no lease
carries no lease id. Revoke removes the egress rules. Re-applying the same
policy is idempotent. Distinct sandboxes receive distinct nftables table
names.

NAT masquerade rules are compiled into the same per-sandbox table and bind
sandbox and tenant identity in the rule comment. Bandwidth limits reject an
oversized interface name, treat a zero rate as an unlimited no-op, and
deprovision idempotently.

The eBPF suite mirrors the same allow list and default deny. It does not
load a program into the kernel in this suite (`ebpf_integration.rs`).

## 4. DNS Policy

`DnsPolicy::evaluate` is first-match. Exact rules do not match subdomains.
Suffix rules match the name and its subdomains. Unmatched names use the
policy default. Record-type filters are honored. `is_denied_ipv4` blocks
internal answers. Platform-internal suffixes are classified before resolve
(`dns/resolver.rs`). Cache entries are scoped by sandbox id and policy
epoch: a different sandbox cannot read them, an epoch change invalidates
them, and `remove_sandbox` drops them.

The DNS server answers IPv6 sources with `NXDOMAIN` and the
`ipv6_unsupported` metric (`dns/server.rs`). The resolver drops `AAAA`
answers. That is the ADR rule for a family whose equivalent controls are
not implemented. It is not dual-stack support.

Property tests in `tests/policy_property.rs` cover CIDR parsing, first-match
evaluation, internal-range denial, and pattern semantics without panics.

## 5. Port Forwarding Requires a Lease

`PortForwardManager::expose` validates a signed lease blob or a store lease
before it binds a listener (`port_forward.rs`). The documented failures are
`Unauthorized` for an invalid, expired, revoked, or out-of-scope lease.

| Test | Proves |
|---|---|
| `expose_accepts_signed_lease_blob` | A signed blob is sufficient authority |
| `expose_creates_endpoint_with_valid_lease` | A valid in-scope lease binds an endpoint |
| `expose_rejects_out_of_scope_port` | A port outside the lease scope is rejected |
| `expose_rejects_revoked_lease` | A revoked lease is rejected |
| `revoke_closes_endpoint` | Revoke closes the listener |
| `list_filters_by_sandbox` | Listing does not cross sandboxes |

`cleanup_expired` drops endpoints whose lease time has passed and emits the
expired audit reason. The proxy path resets a connection when the target
cannot be resolved, and a generation mismatch fails closed
(`port_proxy.rs`, `port_target_cache.rs`). A host boot id change resets the
generation floor so a restarted host cannot serve a stale route.

`pico-edge` repeats the lease check on the HTTP path. With
`require_lease`, a missing lease is `NotFound` and a revoked lease is
denied. Allow and deny both emit `AuditEventKind::NetworkEnforcement` with
lease, sandbox, and tenant identifiers when the request supplied them
(`lease_validation_with_valid_lease`, `lease_validation_with_revoked_lease`,
`emit_proxy_audit_allow`, `emit_proxy_audit_denied`). Rate and connection
limits deny before proxying. Routing is host-header exact match with a
configured default upstream.

When `require_lease` is false and no lease header is present, the edge
proxy allows the request. Production configuration must keep lease checks
required. The host-agent expose path has no equivalent bypass.

## 6. Suspend, Resume, and Fork

ADR-0005 behavior, implemented in `lifecycle.rs`:

| Operation | Required behavior | What the code does |
|---|---|---|
| Suspend | Drop flows, remove egress/NAT/DNS artifacts, keep the namespace for same-host resume | `suspend_network` deprovisions DNS, NAT, and egress best-effort and returns a receipt. Base TAP/veth state is left in place. |
| Resume | Revalidate the current policy epoch and the same logical identity. Do not restore the old policy blob. | `validate_resume` calls `validate_policy_epoch`, then requires both the request identity and the suspend-receipt identity to equal `SandboxNetworkIdentity::for_sandbox` for that sandbox. `resume_network` records metrics around that result. `resources_rebuilt` stays false. The caller must provision egress, NAT, and DNS from the current policy. |
| Fork | New identity, new addresses, no inherited exposure | `derive_child_network_identity` rejects epoch `0`, a child id equal to the parent, and `SandboxNetworkIdentity::conflicts_with` against the parent (interface names, addresses, MAC, namespace). `fork_network` then provisions the child and sets `port_forwarding_blocked`. |

Tests call `validate_resume` and `derive_child_network_identity`. A pair of
matching forged identities is rejected because it is not the derived
identity. `fork_network` itself still calls
`NetworkAgent::provision`, which returns `UnsupportedPlatform` off Linux and
needs `CAP_NET_ADMIN` on Linux. The identity decision is what this suite
pins.

A resumed sandbox does not inherit the suspend receipt's egress CIDRs. The
receipt records them for audit. Resume does not copy them into the new
receipt.

## 7. Cleanup and Reconciliation

Reconciliation classifies observed objects against identities derived for
the known sandbox set.

| Test | Proves |
|---|---|
| `cleanup_receipt_is_idempotent_when_resources_absent` | A second cleanup of missing objects succeeds |
| `cleanup_receipt_is_idempotent_when_resources_removed` | A second cleanup after removal succeeds |
| `known_sandbox_ids_empty_means_all_are_stale` | An empty known set does not adopt strangers |
| `reconciliation_report_unsafe_when_review_required` | Ambiguous ownership is unsafe, not deleted |
| `reconciliation_report_degraded_when_stale_but_no_review` | Stale-but-owned objects degrade health |
| `reconciliation_report_ready_when_no_stale_objects` | A clean pass is ready |
| `microvm_provision_receipt_tracks_tap_link_address` | MicroVM receipts name the TAP and address |
| `container_provision_receipt_tracks_veth_ns_addresses` | Container receipts name the veth and namespace |
| `partial_provisioning_rollback_tracks_partial_state` | Partial provision is visible to rollback |
| `detect_stale_on_non_linux_returns_empty` | Host enumeration is a no-op off Linux |
| `microvm_and_container_identities_are_distinct` | The two backend classes do not share a host peer |

Health is a gauge: `0` ready, `1` degraded, `2` unsafe. The runbook
`docs/runbooks/networking.md` quarantines a host at
`pico_network_health_state=2` and points cleanup drift at
`docs/runbooks/cleanup-reconciliation.md`. Operators are told not to flush
nftables or netns by hand.

## 8. Metrics, Audit, and Dashboards

Network metrics are registered for setup, cleanup, egress allow/deny, NAT
sessions, interface counters, reconciliation health, and
suspend/resume/fork outcomes (`metrics.rs`). Interface stats labels are
`sandbox_id` or, when `shared_host_metric_redaction` is enabled, `tenant_id`,
plus `if_name` and `backend`. Interface names are hash-derived. The
redaction flag defaults off (`metric_redaction_default_disabled`). Shared-host
placement is already prohibited by the side-channel assessment, so the
default label is acceptable for dedicated tenancy. Enabling redaction is
required before any shared-host profile.

Dashboards in `o11y/networking.json` graph setup volume, setup latency,
cleanup volume, NAT sessions, egress allow versus deny, interface counters,
suspend/resume, fork, and bandwidth. Legends use interface, region, and
cell. They do not display a tenant string. DNS and cleanup dashboards are
`o11y/dns.json` and `o11y/cleanup-reconciliation.json`. CI validates the
JSON via `scripts/validate-o11y-dashboards.sh`.

Audit events for DNS, egress, and port-forward use `network_enforcement`.
The edge proxy emits the same kind for allow, deny, rate-limit, and
connection-limit decisions. Sampling is not applied to those audit events.

## 9. IPv6

ADR-0005 disables IPv6 when the equivalent control set is missing. The
current control set is IPv4:

- DNS answers an IPv6 source with `NXDOMAIN` and `ipv6_unsupported`.
- The resolver discards IPv6 answers.
- Bandwidth shaping classifies both `ip` and `ipv6` into the same class so
  an IPv6 packet cannot skip the IPv4 shaper on a host where the filter is
  installed.
- Guest addresses allocated by `SandboxNetworkIdentity` are IPv4 in
  `172.16.0.0/12`.

There is no IPv6 guest address, IPv6 nftables family, or AAAA allow path.
Dual-stack sandboxes are deferred. IPv4 policy is not treated as covering
IPv6.

## 10. Open Limitations

| Limitation | Why it remains open |
|---|---|
| ADR-0005 is Proposed | Owner approval of the model is a separate review. This report does not accept the ADR. |
| No live Linux netns/TAP/nftables walk in this run | Provisioning returns `UnsupportedPlatform` off Linux. Creating devices needs `CAP_NET_ADMIN` on Linux. |
| `fork_network` host provision is not executed here | The function calls `NetworkAgent::provision` after the identity decision. The decision is tested. Device creation is not. |
| `resume_network` does not install current policy | The caller must provision egress, NAT, and DNS after validation. `resources_rebuilt` stays false until that caller does the work. |
| Suspend deprovision is best-effort | A DNS, NAT, or egress teardown error is logged and suspend still returns a receipt. |
| IPv6 guest networking is disabled | Section 9. |
| Edge lease bypass when `require_lease` is false | Host-agent expose has no bypass. Production edge config must require leases. |
| Pingora reload, body limits, and WebSocket drain are untested here | The proxy documents Pingora's native behavior. The suite covers lease, audit, rate, and connection limits. |
| Shared-host metric redaction defaults off | Dedicated tenancy is the approved placement posture. Turn redaction on before any shared-host profile. |
| Owner approval | Section 11. |

## 11. Approval

Promotion past Draft requires all four approvals. Until they are recorded,
G-07 stays short of `pass` and this report is evidence, not a rollout
decision.

| Owner | Scope | Decision | Date |
|---|---|---|---|
| Networking | ADR-0005 model, network-agent, DNS, reconciliation | Pending | |
| Runtime | Backend attachment, sandboxd prepare/cleanup, resume/fork caller | Pending | |
| Platform | `pico-edge` lease-required production config, port-forward gateway | Pending | |
| SRE | Dashboards, runbooks, quarantine on unsafe network health | Pending | |
