# ADR-0005: Per-Sandbox Networking Model

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Networking Model ADR
**Readiness Report**: [Networking readiness report](../robustness/network-prod-readiness-report.md)
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0004](0004-default-isolation-backend-strategy.md),

## Context

PicoCompute needs one networking model before network-agent and runtime integration
work expands. The model must isolate each sandbox while supporting:

- Firecracker and the QEMU backend networking for KVM-based VMs
- gVisor and other container-backed sandbox networking
- policy-controlled DNS and egress
- optional, lease-controlled ingress
- suspend, resume, fork, destroy, and host relocation
- restart-safe cleanup and reconciliation
- per-sandbox metrics, flow logs, and audit evidence

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
makes the regional control plane authoritative for lifecycle and access
decisions. [ADR-0002](0002-host-runtime-lifecycle-orchestration.md)
makes `network-agent` the bounded owner of host networking mechanics while
`sandboxd` persists resource receipts and cleanup progress.
[ADR-0004](0004-default-isolation-backend-strategy.md)
requires PicoCompute-owned TAP networking for production VM backends and forbids
host-network passthrough for gVisor.

 provides time-bound access leases for port forwarding and egress
exceptions. Network enforcement must consume those decisions without making
independent authorization choices or treating network locality as trust.

The current TAP and TCP proxy helpers are prototypes. They do not provide the
target production isolation, policy, lease validation, durable ownership, or
reconciliation model defined by this ADR.

## Decision

PicoCompute selects **PicoCompute-managed, per-sandbox Linux network namespaces with
routed layer-3 connectivity and nftables enforcement**.

- MicroVM backends use a dedicated namespace containing a TAP device and an
  uplink veth to the host namespace.
- Container-backed sandboxes use a dedicated namespace and veth attachment.
- Each sandbox receives an independent logical network identity.
- Host forwarding is routed. Sandboxes do not share a tenant-visible layer-2
  bridge or broadcast domain.
- nftables enforces anti-spoofing, ingress and egress policy, NAT, accounting,
  and deny-by-default behavior.
- DNS and externally reachable ingress pass through policy-aware PicoCompute
  services rather than directly exposing host or control-plane endpoints.

Linux bridges may be used inside an implementation-specific namespace only
when a backend requires layer-2 attachment between devices. They must not
create a shared cross-sandbox tenant network.

### Per-Sandbox Network Objects

The control plane allocates a logical network identity before host
preparation. `network-agent` derives deterministic local resource names from
the sandbox and operation identities and returns typed receipts to
`sandboxd`.

| Backend class | Required per-sandbox objects |
|---|---|
| Firecracker and the QEMU backend | Logical network identity, dedicated network namespace, TAP device, namespace uplink veth, host-side veth, guest and uplink addresses, routes, nftables policy and counters, DNS proxy attachment |
| gVisor and container-backed | Logical network identity, dedicated network namespace, sandbox-side veth, host-side veth, addresses, routes, nftables policy and counters, DNS proxy attachment |
| Every backend | Policy decision and epoch binding, deterministic resource receipts, audit correlation, metrics identity, cleanup state |

For a microVM, the VMM joins the sandbox network namespace and attaches only
the pre-created TAP device. The namespace routes guest traffic through its
uplink veth. Runtime adapters do not create routes, firewall rules, NAT, DNS
configuration, or externally reachable listeners.

For a container-backed sandbox, the sandbox process or isolated userspace
network stack receives the namespace-side interface. Host networking is
forbidden. A gVisor netstack integration may adapt the attachment mechanics,
but it must preserve the same policy, identity, accounting, and cleanup
contract.

Resource names are deterministic but are not authorization credentials.
Interface names, MAC addresses, IP addresses, namespace paths, and host
placement must never be treated as proof of tenant or sandbox identity.

### Routed Isolation

Each sandbox is a separate routing domain. The host forwards packets between
the sandbox uplink and approved PicoCompute egress services or external
destinations.

The routed model provides:

- no cross-sandbox broadcast or neighbor discovery
- no tenant-visible shared bridge
- source validation at the sandbox-facing interface
- per-sandbox routes and counters
- deterministic attribution before NAT
- independent teardown without modifying another sandbox's link

The host rejects packets whose source address, source MAC where applicable,
or ingress interface does not match the sandbox's assigned network identity.
Forwarding between sandbox interfaces is denied by default, including
same-tenant peers.

### Control-Plane and Compute-Plane Responsibilities

| Concern | Authority |
|---|---|
| Network admission and desired policy | Regional policy engine and network policy controller |
| Logical network identity allocation | Regional network policy controller and metadata store |
| Host-local address and route allocation | Cell controller |
| Access lease issuance and revocation | Regional access lease manager |
| Host command admission and fencing | `host-agent` |
| Workflow ordering and durable receipts | `sandboxd` |
| Namespace, TAP, veth, route, nftables, and NAT mechanics | `network-agent` |
| Backend attachment | Selected runtime adapter |
| Domain policy and answer validation | DNS policy proxy |
| Ingress connection admission | Port-forward gateway |
| Counters, flow export, and local health | `metrics-agent` and `network-agent` |

The control plane produces versioned network intent. At minimum, the intent
binds:

- tenant ID and sandbox ID
- logical network identity
- assignment fencing token
- policy decision ID and policy epoch
- allowed protocols, destinations, and ports
- DNS policy revision
- denied platform and tenant destination classes
- egress exception lease references and expiry, when present
- ingress exposure lease references and expiry, when present
- an absolute operation deadline

`host-agent` rejects stale assignment or policy context before admitting a
network mutation. `sandboxd` serializes the operation and records intent
before side effects. `network-agent` applies only the supplied bounded intent
and returns receipts for every created or updated resource.

### Security Defaults

Every sandbox starts with these defaults:

- no ingress
- no direct host or public listener exposure
- no trust based on IP address, subnet, cell, host, or network locality
- no forwarding to another sandbox
- no access to host, control-plane, metadata, link-local, or platform-internal
  destinations
- no unrestricted Internet egress
- no direct DNS resolver access outside the assigned DNS policy proxy
- no IPv6 unless equivalent identity, filtering, DNS, logging, and cleanup
  enforcement is active

The deny set includes host addresses, control-plane networks, cloud metadata
services, link-local ranges, loopback ranges, multicast, and tenant peer
ranges. A current control-plane policy may authorize a specific protected
destination, but network placement alone never authorizes it.

Policy is installed before the sandbox interface is made usable by the
runtime. If policy application, identity validation, or audit correlation
fails, network preparation fails and the sandbox cannot become `Running`.

### Egress and NAT

Fresh network intent permits only traffic to the assigned policy-aware DNS
proxy. Baseline egress requires a current control-plane policy that scopes
protocols, destination classes, CIDRs or resolved addresses, and ports.

An egress exception requires an active `EgressException` access lease. The
lease must match:

- tenant and sandbox
- requested protocol, destination, and port scope
- current policy epoch
- policy decision
- expiry and revocation state

The network policy controller decides whether egress is allowed. The access
lease manager authorizes a bounded exception. `network-agent` compiles both
into nftables state and rejects missing, stale, expired, revoked, or
wrong-scope leases.

Filtering and attribution occur before source NAT. NAT is a connectivity
mechanism, not an authorization boundary. The egress path retains enough
connection tracking and policy metadata to attribute allowed and denied
flows to the tenant, sandbox, network identity, policy decision, and lease
where applicable.

Policy and lease updates are applied as atomic nftables transactions. A
failed replacement leaves the previous valid restrictive ruleset active. On
lease expiry or revocation, new matching flows are denied and established
flows authorized only by that lease are terminated.

### DNS Policy

DNS is an authorization boundary. Sandboxes send DNS traffic only to the
assigned PicoCompute DNS policy proxy.

The proxy:

- validates tenant, sandbox, network identity, and current policy epoch
- applies allowed and denied domain, suffix, and record-type rules
- rejects answers that resolve to denied platform, host, metadata, link-local,
  or tenant-peer addresses
- binds allowed answers to the requesting sandbox and policy revision
- limits cached authorization to the lesser of DNS TTL and policy validity
- emits allow and deny evidence without logging payloads or secret material

Direct UDP or TCP DNS, DNS over TLS, and known external resolver paths are
denied unless a current policy explicitly authorizes them. Domain approval
does not override denied destination classes. Policy updates invalidate
affected cached decisions and remove related egress permissions.

### Port Forwarding and Ingress

Port forwarding is controlled ingress through an authenticated PicoCompute
gateway. Tenants never receive a raw host address or an arbitrary listener
bound directly by a sandbox host process.

An exposure requires:

- an explicit control-plane request
- a policy decision
- an active `PortForward` access lease
- tenant, sandbox, guest port, protocol, and exposure scope
- an expiry and revocation path
- audit correlation

The port-forward gateway validates the lease when provisioning the exposure
and again when accepting a connection. It routes an accepted connection to
the sandbox through an authenticated internal path. `network-agent` installs
only the narrow forwarding state needed for that gateway path.

Lease expiry, revocation, sandbox suspension, policy epoch change, or destroy
removes the exposure, rejects new connections, and terminates active
connections whose authority no longer exists. Waking a suspended sandbox does
not bypass lease validation or create a new exposure implicitly.

### IPv4 and IPv6

IPv4 and IPv6 use equivalent default-deny controls. Enabling IPv6 requires:

- assigned and source-validated addresses
- nftables rules for every protected boundary
- DNS answer policy for AAAA records
- equivalent platform, metadata, link-local, multicast, and peer deny sets
- per-sandbox metrics, flow logs, and cleanup

If any equivalent IPv6 control is unavailable, IPv6 is disabled in the
namespace and guest. IPv4 policy must not be bypassable through IPv4-mapped,
translated, tunneled, or dual-stack paths.

### Suspend, Resume, Fork, and Relocation

The logical network identity belongs to the sandbox record, not to a host
interface or address.

| Operation | Required behavior |
|---|---|
| Suspend | Disable local ingress and lease-backed egress artifacts, block new flows, remove transient connection state, and persist retained local resource receipts; lease revocation remains a control-plane action |
| Resume on the same host | Rebuild policy from the current epoch, use the same logical network identity, and validate all local resources before enabling the guest interface |
| Resume after relocation | Preserve the logical network identity, allocate new host-local addresses and resources, install current policy, and discard old host connection state |
| Fork | Allocate a new logical network identity, namespace, addresses, interfaces, policy artifacts, leases, DNS state, NAT state, and connection tracking for the child |
| Destroy | Require control-plane exposure and exception revocation, block traffic, remove all local network resources, and release addresses only after absence is proven |

A resumed sandbox does not inherit expired leases, established flows, DNS
authorization cache entries, or port-forward listeners. A fork never inherits
the source sandbox's network identity, MAC address, IP address, leases, NAT
state, DNS cache, flow state, or externally visible exposure.

 may refine operation sequencing and user-visible semantics, but it
must preserve these identity and authorization invariants.

### Cleanup and Reconciliation

Network creation and deletion are idempotent. `sandboxd` records planned
resource identities before calling `network-agent`, then records typed
receipts and cleanup progress.

Normal destroy cleanup proceeds in this order:

1. Confirm control-plane revocation and disable local port-forward and
   egress-exception enforcement artifacts.
2. Install a terminal deny rule for the sandbox identity.
3. Stop or detach the runtime from the sandbox interface.
4. Remove NAT, filter, counter, route, and DNS attachment state.
5. Delete TAP and veth devices.
6. Delete the network namespace.
7. Release host-local and control-plane address allocations.
8. Prove absence before reporting network cleanup complete.

`network-agent` reconciliation compares desired intent and persisted receipts
with:

- network namespaces
- TAP and veth devices and peer identities
- addresses, routes, and neighbor state
- nftables tables, chains, sets, maps, rules, and counters
- NAT and connection tracking state
- DNS proxy attachments
- port-forward gateway registrations
- address allocation records

Proven incomplete resources are adopted or cleaned through the recorded
operation. Proven stale and unused resources are removed. Ambiguous ownership
is quarantined, reported as `requires_review`, and causes the host to degrade
or drain. An ambiguous live interface, namespace, rule, or listener is never
deleted solely because its name resembles a PicoCompute resource.

### Failure Behavior

Networking fails closed:

- A missing or stale policy blocks network readiness.
- A failed nftables transaction does not expose a partially updated policy.
- Loss of the DNS policy proxy blocks new DNS authorization.
- Loss of lease revocation state blocks new lease-governed connections and
  expires existing authority at its bounded deadline.
- A port-forward gateway that cannot validate a lease rejects the connection.
- Reconciliation uncertainty quarantines resources instead of guessing.
- The sandbox cannot become `Running` until identity, policy, DNS path,
  accounting, and audit correlation are verified.

Host health reports network-agent availability, policy revision lag, DNS
proxy reachability, revocation propagation health, cleanup backlog, and
ambiguous resource findings.

### Metrics, Flow Logs, and Audit

Network telemetry is keyed by logical network identity and correlated with
tenant and sandbox identity.

Required metrics include:

- bytes and packets allowed and denied by direction and reason
- active and rejected egress flows
- DNS requests allowed, denied, failed, and invalidated
- active, accepted, rejected, expired, and revoked port-forward connections
- lease revocation propagation latency
- policy application and reconciliation latency
- namespace, interface, route, nftables, NAT, and cleanup failures
- orphan, drift, quarantine, and address allocation counts

Flow logs record metadata, not packet payloads. Required correlation fields
include:

- tenant ID, sandbox ID, and logical network identity
- operation ID and assignment fencing token
- policy decision ID and policy epoch
- lease ID when applicable
- direction, protocol, source and destination class, ports, action, and reason
- host, cell, interface identity, bytes, packets, and timestamps

Security-relevant denies, lease decisions, policy changes, exposure changes,
and cleanup anomalies emit durable audit events. Sampling may reduce
high-volume allowed-flow telemetry, but it must not discard required audit
events or evidence needed to investigate policy bypass and cross-tenant
access.

### Integration and Fallback Profiles

#### Approved CNI Integration

CNI may be used as a provisioning adapter in Kubernetes or other approved
environments. It is not the authority for PicoCompute network policy or
lifecycle.

An approved CNI integration must:

- create the same isolated namespace, TAP or veth, routing, and identity model
- accept deterministic operation and resource identities
- return inspectable resource receipts
- support idempotent add, check, delete, and garbage-collection behavior
- leave policy, lease, audit, and reconciliation authority with PicoCompute
- prevent unreviewed plugin chains from weakening deny rules

If the CNI environment cannot satisfy the PicoCompute contract, placement fails
or uses an explicitly requested limited profile. PicoCompute does not silently
accept the cluster network's trust or policy model.

#### Proxy-Only Limited Profile

Proxy-only networking is an explicit limited capability profile for
environments where general layer-3 attachment is unavailable or intentionally
disabled. All permitted traffic traverses approved application proxies.

This profile:

- has no transparent arbitrary TCP or UDP compatibility
- has no direct inbound listener
- exposes only declared proxy protocols and destinations
- uses the same policy, lease, identity, audit, and revocation requirements
- is selected by control-plane policy, never as an automatic fallback

#### OVS Evaluation Trigger

Open vSwitch is deferred. A separate ADR may evaluate it when PicoCompute has
measured requirements for multi-host overlays, high-density switching,
hardware offload, advanced service chaining, or flow telemetry that the
routed nftables model cannot meet.

OVS must not be introduced as an implementation-local substitution because
doing so changes the policy compiler, resource model, operational surface,
failure modes, reconciliation logic, and production evidence.

## Consequences

### Positive

- Every sandbox has an independent kernel routing domain and deterministic
  resource ownership.
- MicroVM and container-backed sandboxes share one policy and lifecycle model.
- Routed isolation prevents tenant-visible layer-2 adjacency.
- nftables provides one host enforcement path for filtering, NAT, counters,
  and atomic policy replacement.
- Policy and leases remain control-plane decisions with explicit compute-plane
  enforcement points.
- Network identity survives host relocation without reusing host artifacts.
- Cleanup and reconciliation can prove ownership through receipts rather than
  naming conventions.
- CNI remains available for integration without becoming PicoCompute's authority.

### Negative

- A namespace and veth per sandbox consume kernel objects and require host
  scale validation.
- MicroVM networking adds namespace routing and TAP management.
- Domain-based egress requires coordinated DNS and network policy state.
- Lease revocation must propagate to nftables and ingress gateways quickly.
- Dual-stack support doubles policy, testing, telemetry, and cleanup work.
- The design requires a privileged, narrowly scoped network-agent and robust
  reconciliation before production use.
- Proxy-only environments have reduced workload compatibility.

## Rejected Alternatives

### OVS Bridge with Per-Sandbox Ports

Every sandbox would attach to an Open vSwitch bridge, with OpenFlow rules and
connection tracking providing isolation and policy.

**Rejected as the primary model**: OVS adds a switch database, controller and
flow lifecycle, OpenFlow policy compiler, additional upgrade compatibility,
and a broader reconciliation surface before PicoCompute has requirements that
justify them. The routed namespace and nftables model meets the initial
isolation, NAT, policy, and accounting needs with fewer moving parts.

### CNI-Only Integration

Runtime adapters would call CNI plugins and treat the resulting network as the
complete networking model.

**Rejected**: CNI defines attachment mechanics, not PicoCompute's lifecycle
authority, access lease semantics, zero-trust policy model, durable receipts,
audit contract, or ambiguous-resource handling. Approved CNI integration
remains an adapter to the PicoCompute contract.

### Proxy-Only Networking for All Sandboxes

All ingress and egress would traverse application proxies, with no general
layer-3 networking.

**Rejected as the universal model**: It provides strong mediation but breaks
arbitrary TCP and UDP workloads, package managers, developer tools, and
protocols without proxy support. It remains a useful explicit limited
profile.

### Shared Host Bridge

TAP and veth devices would attach directly to a shared Linux bridge with
firewall rules separating tenants.

**Rejected**: A shared layer-2 domain increases spoofing, broadcast,
neighbor-discovery, lateral-movement, and reconciliation risk. Routed
per-sandbox namespaces make isolation structural and keep policy boundaries
explicit.

### Direct Host Port Listeners

Each host would bind externally reachable ports and proxy them directly to a
sandbox.

**Rejected**: Raw host listeners expose host identity and availability,
complicate relocation, and can accept traffic without a centrally enforced
lease. PicoCompute ingress must use an authenticated gateway with validation and
revocation.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Implement deterministic namespace, TAP, veth, address, route, and backend attachment provisioning |
| | Implement nftables egress policy, anti-spoofing, NAT, lease-backed exceptions, and atomic updates |
| | Implement the DNS policy proxy, answer validation, cache invalidation, and audit evidence |
| | Implement authenticated gateway-based port forwarding and lease revocation |
| | Define detailed suspend, resume, relocation, and fork network sequencing |
| | Implement receipt-based network cleanup, reconciliation, quarantine, and host health reporting |
| | Implement per-sandbox counters, flow logs, metrics, and dashboards |
| | Supplies the completed access lease model consumed by egress exception and port-forward enforcement |

## References

- [Firecracker jailer network namespace support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
- [Firecracker production host networking and filtering](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [nftables manual](https://www.netfilter.org/projects/nftables/manpage.html)
- [CNI specification](https://github.com/containernetworking/cni/blob/main/SPEC.md)
- [Open vSwitch connection tracking](https://docs.openvswitch.org/en/latest/tutorials/ovs-conntrack)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Linux veth devices](https://man7.org/linux/man-pages/man4/veth.4.html)

## Required Review

The ADR remains `Proposed` until both roles approve:

- Networking owner
- Security owner
