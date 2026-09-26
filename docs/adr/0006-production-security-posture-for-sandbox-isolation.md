# ADR-0006: Production Security Posture for Sandbox Isolation

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Security Posture ADR
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0003](0003-host-guest-agent-protocol-contract.md),
[ADR-0004](0004-default-isolation-backend-strategy.md),
[ADR-0005](0005-per-sandbox-networking-model.md)

## Context

PicoCompute runs autonomous agent workloads that may combine untrusted code,
tool access, credentials, network access, persistent workspaces, snapshots,
and forks. A workload can be malicious at admission, become compromised
during execution, or misuse a legitimate capability. The production posture
must therefore assume hostile guest behavior and prevent a tenant workload
from turning one granted capability into ambient access to the host, platform,
another tenant, or a later sandbox generation.

The preceding ADRs establish:

- regional control-plane ownership and compute-plane enforcement
- bounded host runtime orchestration and narrow privileged helpers
- an authenticated, bounded host/guest protocol
- Firecracker as the default public backend with QEMU as the only public
  fallback
- per-sandbox routed networking with deny-by-default enforcement

Those decisions define important boundaries but do not yet state the complete
production security posture, the controls that are mandatory across those
boundaries, or the evidence required before a workload class may launch.

This ADR defines the minimum production baseline. It does not claim that a
microVM eliminates risk, that one control can compensate for a missing
boundary, or that a passing functional test establishes security. Defense in
depth, fail-closed behavior, independent evidence, and explicit residual-risk
acceptance are all required.

The detailed assets, actors, trust boundaries, abuse cases, risk trees, FMEA,
control mapping, and residual-risk register are maintained in the
[PicoCompute threat model](../security/threat-model.md). That model elaborates
this posture and cannot lower the isolation floors, hard invariants, or launch
gates defined here.

## Decision

PicoCompute adopts a **workload-class-based security posture with a microVM-first
public default, minimized host runtime, brokered credentials, default-deny
networking, snapshot secret exclusion, and evidence-gated production
eligibility**.

Production eligibility is the intersection of:

1. an approved workload class and isolation floor
2. a production-approved backend and exact runtime profile
3. host, image, protocol, network, credential, and snapshot controls
4. current validation evidence for that complete profile
5. accepted residual risk and required owner approval

No component may infer eligibility from backend availability, tenant demand,
latency targets, or the presence of a single control. Missing or stale
evidence makes the profile ineligible.

### Workload Security Classes

| Workload class | Examples | Isolation floor | Placement and failure behavior |
|---|---|---|---|
| Public untrusted | Unknown code provenance, Internet-facing tools, public API execution, cross-tenant service | Firecracker microVM; QEMU is the only fallback | Preserve a hardware virtualization boundary. Reject placement when no approved VM backend passes every gate. |
| Trusted fast path | Tenant-owned code with explicit platform and tenant approval for a lower isolation floor | gVisor with approved compatibility profile; Firecracker and the QEMU backend remain valid stronger alternatives | Admission requires an explicit, revocable policy grant. Never infer trust from account age, image ownership, latency requirements, or prior successful runs. |
| Compatibility VM | Workload requiring a broader device model, guest kernel behavior, firmware path, or image format | QEMU with a minimized, pinned machine profile | Reject placement when the approved compatibility profile is unavailable. Do not substitute a container backend. |
| Dedicated tenancy | Workload or fleet whose residual risk is not approved for shared-host placement | Approved VM backend on hosts and supporting resources dedicated to the approved tenant or trust domain | Maintain the normal sandbox controls. Dedicated placement reduces cross-tenant exposure but does not waive host hardening, credential, network, or validation requirements. |
| Platform service | Control plane, cell controller, host agent, `sandboxd`, privileged helpers, policy services, secrets broker | Separate platform service boundary | Platform services are never scheduled as tenant sandbox workloads and never share tenant workload credentials or writable state. |

Shared-host cross-tenant placement is not production-eligible until
 produces an approved
side-channel and covert-channel assessment for the exact host, CPU,
virtualization, scheduling, and workload profile. Until then, public
multi-tenant execution uses dedicated tenancy or another placement model whose
accepted risk does not depend on unapproved shared-host isolation.

### Host Runtime Minimization

The production host is part of the security boundary. Its workload-facing
surface must contain only the components and interfaces required to prepare,
run, observe, and destroy the selected sandbox profile.

Every production VM runtime profile requires:

- Firecracker started through the jailer, or constraints proven at least as
  restrictive; QEMU uses an equivalent dedicated launcher and confinement
  profile
- a dedicated unprivileged runtime UID and GID per sandbox or another
  approved identity allocation that prevents cross-sandbox file and process
  access
- separate PID, mount, network, IPC, and UTS namespaces where applicable,
  with no host namespace sharing
- `no_new_privs`, an approved seccomp profile, and removal of all Linux
  capabilities not required by the bounded runtime operation
- cgroup v2 CPU, memory, PID, I/O, and applicable device or BPF controls, with
  limits installed before untrusted execution starts
- a minimal, pinned virtual device model with no unused host devices,
  passthrough devices, host filesystem exports, or debug interfaces
- a read-only runtime binary and verified host artifact set sourced through
  the approved build and release pipeline
- a private jail, chroot, or equivalent filesystem view containing only the
  runtime, immutable guest artifacts, declared writable runtime state, and
  explicitly attached resources
- per-sandbox TAP, vsock, API socket, console, snapshot, and filesystem
  resources with ownership enforced by kernel credentials and permissions
- narrow privileged helpers for network, mount, cgroup, device, and snapshot
  operations; helpers accept typed bounded intent and do not accept arbitrary
  shell commands
- no tenant-visible Docker socket, container runtime socket, KVM management
  socket, Firecracker API socket, QMP socket, host agent socket, control-plane
  credential, or privileged helper socket

Host services must use mutual authentication or kernel peer credentials on
local interfaces, validate sandbox and operation identity, reject stale
fencing and policy epochs, and enforce deadlines and bounded request sizes.
Runtime adapters and helpers receive only the capabilities and resource paths
needed for the current operation.

Production hosts use a minimal package and service set, verified boot or an
equivalent measured immutable host-image process, prompt security patching,
restricted administrative access, centralized audit collection, and a
documented rebuild path. A host with uncertain ownership, stale security
state, failed attestation, ambiguous resources, or incomplete cleanup is
quarantined and cannot accept new public workloads.

### Guest and Image Posture

Guest images are trusted platform artifacts running untrusted tenant code.
Every production image must:

- be immutable at its base layer and identified by digest
- include signed provenance, an SBOM, vulnerability results, and approved
  kernel, init, guest-agent, and package versions
- use a minimal kernel configuration and userspace package set for its
  declared capability profile
- run tenant processes as a non-root identity by default
- omit compilers, debuggers, package managers, shells, kernel modules, and
  administrative tools unless the workload profile explicitly requires them
- expose no host filesystems, host devices, platform sockets, or ambient
  credentials
- mount writable workspace, runtime temporary state, and secret locations as
  distinct classes with explicit persistence and snapshot behavior
- pass boot, protocol authentication, policy application, mount, network, and
  secret-absence validation before production eligibility

Tenant code may be root inside a guest only when the workload contract
requires it. Guest root never changes the host isolation floor and does not
grant host devices, platform credentials, privileged network paths, or host
filesystem access.

### Credential and Capability Delivery

Credentials are temporary capabilities, not sandbox configuration. PicoCompute
prefers mediated operations in which the sandbox requests an approved action
and a platform service uses the credential without disclosing it to the
workload. When direct credential use is required, PicoCompute issues a narrow,
short-lived token bound to:

- tenant and sandbox identity
- workload and tool identity where available
- operation and policy decision
- allowed service, resource, method, and scope
- current boot, policy epoch, and lease
- issue, expiry, and revocation time

Any raw secret delivered to untrusted workload code is considered disclosed
to that workload. Isolation reduces the scope of disclosure but cannot make
the workload forget a value it has observed. Such delivery therefore requires
an explicit policy decision, the shortest practical lifetime, narrow scope,
and revocation that does not depend on guest cooperation.

Credentials must not appear in:

- image layers, manifests, kernels, initrds, or base snapshots
- environment variables, command-line arguments, process titles, or API
  request URLs when a protected file descriptor or mount can be used
- persistent workspaces, writable image layers, caches, or forkable data
- logs, metrics labels, traces, audit payloads, diagnostic bundles, or console
  output
- core dumps, crash dumps, memory diagnostics, or support exports
- runtime snapshots, session snapshots, fork snapshots, or snapshot metadata

Directly delivered secrets use a non-persistent mount or protected local
channel, restrictive ownership and mode, bounded lifetime, and explicit
zeroization where technically possible. The secrets broker remains
authoritative for issuance and revocation. Guests do not receive cloud
instance credentials, control-plane credentials, host identities, or a
general-purpose credential relay.

### Snapshot, Resume, and Fork Security

Snapshots serialize guest and runtime state that may contain tenant data,
tokens, session material, process memory, network state, and protocol
credentials. Snapshot creation and restore are therefore security-sensitive
operations, not storage optimizations.

Before a snapshot containing runtime memory:

1. Admission verifies the snapshot type, tenant, policy, backend, and
   destination data-classification policy.
2. New exec, network exposure, and credential issuance are blocked.
3. Active work is drained or canceled according to the operation contract.
4. Access leases and directly delivered credentials are revoked.
5. The guest invalidates protocol sessions and zeroizes boot and runtime
   secrets through the authenticated quiesce protocol.
6. Non-persistent secret and temporary mounts are detached or proven excluded.
7. The snapshot agent verifies the exclusion manifest before capture.
8. Capture proceeds only when the quiesce receipt, exclusion evidence, and
   current policy epoch agree.

Snapshot artifacts require authenticated encryption, integrity metadata,
tenant and lineage binding, least-privilege storage access, retention and
deletion policy, and access audit events. Snapshot caches are treated as
sensitive tenant data and may not be shared across tenants without an
explicit content-addressed, immutable, secret-free base-artifact contract.

Resume and fork require:

- complete integrity, provenance, backend, image, CPU, device, protocol,
  tenant, lineage, and policy compatibility validation
- a fresh boot identity and host/guest authentication secret
- a new protocol session and operation namespace
- current network policy and fresh host-local network resources
- revalidation or replacement of every access lease
- fresh credentials issued only after the restored guest has authenticated
  and completed readiness validation
- a new sandbox, network, policy, and credential identity for every fork

An expired, revoked, or pre-snapshot credential, lease, session, network flow,
port exposure, DNS authorization, or protocol proof is never valid after
resume or fork.

### Network and Data-Plane Restrictions

[ADR-0005](0005-per-sandbox-networking-model.md) is the normative network
model. The production security posture requires:

- no ingress and no externally reachable listener by default
- no egress except current policy-authorized destinations
- egress exceptions and port forwarding only through active, scoped access
  leases
- DNS only through the assigned policy-aware proxy, with answer validation
  against protected destination classes
- no host, control-plane, cell-control, metadata, link-local, loopback,
  platform-internal, or tenant-peer access by default
- no sandbox-to-sandbox forwarding, including same-tenant peers, without an
  explicit workload policy and separately authenticated service path
- no shared tenant-visible layer-2 network, host networking, raw host port
  exposure, or trust based on IP address or placement
- source validation, anti-spoofing, filtering, accounting, and policy
  enforcement before NAT
- policy installed before the guest interface becomes usable
- equivalent IPv4 and IPv6 enforcement, or IPv6 disabled

Policy updates, lease revocation, suspension, restore, fork, destroy, and host
relocation rebuild or remove network authority without relying on the guest.
Failure to install, validate, or audit the required network policy prevents
the sandbox from becoming `Running`.

### Hard Security Invariants

The following outcomes must be impossible within an approved production
profile, not merely difficult or unlikely:

1. A public untrusted workload starts through gVisor, a standard container
   runtime, or another boundary below the approved VM isolation floor.
2. A runtime adapter, scheduler, host agent, or capacity fallback silently
   substitutes a weaker backend.
3. A tenant workload joins a host, platform service, or another sandbox's PID,
   mount, network, IPC, cgroup, or user namespace.
4. A guest opens a host runtime, container runtime, VMM management,
   control-plane, privileged helper, or secrets broker administrative socket.
5. Two tenants share writable image, workspace, runtime, snapshot, cache, or
   temporary state.
6. A sandbox reaches host, metadata, control-plane, platform-internal, or
   another sandbox destination through ambient network access.
7. A sandbox receives a platform-wide, host-wide, control-plane, or
   non-expiring credential.
8. A credential or authenticated session remains valid because it was
   captured in a snapshot, restored from an earlier boot, or inherited by a
   fork.
9. A sandbox becomes `Running` before backend, host, cgroup, namespace,
   network, protocol, image, and policy controls are installed and validated.
10. A failed or partial destroy releases an identity or address for reuse
    before the old resources are proven absent or quarantined.
11. A backend, host image, guest image, runtime version, or security profile
    enters public production without current evidence for the exact deployed
    combination.
12. A shared-host cross-tenant placement proceeds before the assessment
    and residual-risk approval cover that placement profile.

Implementation work that cannot enforce one of these invariants must block the
affected production profile or return to architecture review. Documentation,
operator procedure, monitoring, or best effort detection cannot substitute
for preventive enforcement where the architecture can prevent the outcome.

### Risk, Control, and Residual Risk

| Risk | Required preventive and detective controls | Residual risk and disposition |
|---|---|---|
| Guest escape through VMM, KVM, guest device, or host kernel vulnerability | VM isolation floor, minimized device model, jailer or equivalent confinement, dedicated identity, namespaces, seccomp, capability removal, patching, boundary tests, host quarantine | Zero-day vulnerabilities and hardware defects remain possible. Security owner accepts the exact runtime and host profile; incident response must support rapid drain, revoke, rebuild, and patch. |
| Host compromise through runtime or privileged helper | Narrow typed helpers, no shell interface, peer authentication, bounded intent, immutable artifacts, least privilege, audit, separate platform credentials | A successful host compromise has high blast radius. Hosts are treated as security domains, credentials are scoped, and dedicated tenancy is required when shared-host risk is not approved. |
| Credential theft or confused-deputy use | Mediation first, short-lived scoped tokens, policy and boot binding, non-persistent delivery, revocation, no telemetry persistence | Workload-visible secrets can be exfiltrated during their valid lifetime. Policy owners approve direct delivery and downstream services enforce scope and expiry. |
| Lateral movement and platform service access | Per-sandbox network namespace, default-deny policy, protected destination deny sets, policy DNS, authenticated gateways, no peer forwarding | Approved egress can reach a compromised external service and application-layer protocols can be abused. Destination policy and service authorization remain required. |
| Snapshot or fork leaks credentials or tenant state | Quiesce, revocation, zeroization, excluded mounts, exclusion verification, encryption, tenant and lineage binding, fresh identities | Application memory may contain tenant data or workload-copied secrets that PicoCompute cannot identify reliably. Data classification, retention, and explicit snapshot policy govern this residual risk. |
| CPU, memory, PID, I/O, disk, network, or control-plane exhaustion | cgroup v2 limits, quotas, bounded protocol and API requests, deadlines, rate limits, accounting, cleanup, capacity isolation | Shared kernel and hardware resources allow contention within configured limits. Capacity policy, admission control, and determine acceptable shared-host exposure. |
| Compromised host or guest artifact supply chain | Signed provenance, digest pinning, SBOM, vulnerability policy, reproducible or verified builds, immutable distribution, admission verification | Build systems and signing authorities remain high-value targets. Separate duties, key protection, audit, and incident response are required. |
| Control-plane compromise or authorization error | Authenticated APIs, policy-as-data, scoped leases, fencing, optimistic concurrency, audit, compute-plane validation | The control plane can authorize harmful actions within its authority. Administrative separation, review, detection, and recovery are required; compute-plane checks cannot correct an authorized but malicious policy. |
| Side channels and covert channels across shared hardware | assessment, placement controls, CPU and memory scheduling policy, hardware and kernel mitigations, dedicated tenancy fallback | Complete elimination is not assumed. Any accepted shared-host profile records measured leakage assumptions, affected data classes, compensating controls, and explicit owner acceptance. |

Residual risk is a versioned production artifact. Acceptance identifies the
workload class, backend, host and guest profiles, hardware scope, evidence
revision, expiration or review date, accepting owners, and operational
mitigations. Acceptance for one profile does not authorize another profile or
survive a material architecture, hardware, runtime, kernel, or threat change.

### Mandatory Production Launch Gates

Every enabled workload class and exact deployment profile must pass all
applicable gates. A gate is blocking, produces retained evidence, names an
owner, and has an expiration or revalidation trigger.

| Gate | Minimum evidence | Blocking owner |
|---|---|---|
| Threat and risk model | Approved [PicoCompute threat model](../security/threat-model.md) covering trust boundaries, assets, adversaries, abuse cases, security objectives, hard invariants, and residual risk from | Security |
| Backend and host hardening | Verified launcher, identity, namespaces, seccomp, capabilities, devices, mounts, sockets, host image, patch policy, and administrative access controls from and | Runtime and Security |
| Resource containment | cgroup v2 CPU, memory, PID, I/O, disk, network, and failure tests from | Runtime |
| Image and supply chain | Signed provenance, digest verification, SBOM, vulnerability policy, minimal image review, secret scan, and boot validation | Runtime and Security |
| Protocol abuse resistance | Authentication, downgrade, replay, malformed input, bounds, deadlines, stream, reconnect, snapshot, and fork tests for ADR-0003 | Runtime and Security |
| Network isolation | Anti-spoofing, protected destination denial, DNS enforcement, lease expiry and revocation, peer isolation, IPv6 parity, lifecycle, and cleanup tests for ADR-0005 | Networking and Security |
| Credential safety | Broker authorization, scope, lifetime, revocation, telemetry exclusion, delivery-channel, and confused-deputy tests from | Security and Control Plane |
| Snapshot credential exclusion | Quiesce, revocation, zeroization, mount exclusion, artifact scanning, restore, and fork tests from | Runtime and Security |
| Isolation boundary validation | Guest escape, namespace, device, filesystem, socket, cross-tenant state, backend downgrade, and host exposure suite from | Security |
| Cleanup and reconciliation | Crash, retry, restart, partial failure, orphan, quarantine, identity reuse, and absence-proof tests | Runtime, Networking, and Control Plane |
| Vulnerability response | Inventory, advisory intake, severity policy, patch and rebuild SLOs, emergency drain, credential revocation, rollback, and incident exercise | Security and Operations |
| Side-channel assessment | Approved assessment for the host, CPU, scheduler, backend, tenant-sharing, and data-classification profile, or enforced dedicated tenancy | Security and Runtime |
| Production readiness | SLOs, capacity evidence, monitoring, alerts, runbooks, rollback, ownership, and launch checklist from | Control Plane and Operations |
| Security assurance | Traceable claims, evidence, residual risks, exceptions, and approval record from | Security |

Evidence must cover the deployed backend version, host kernel and image,
hardware class, guest image, guest-agent version, network profile, credential
mode, snapshot mode, and workload class. A security-relevant change invalidates
affected evidence until impact analysis and required revalidation complete.

Temporary exceptions are fail-closed by default. An exception requires a
named owner, exact scope, reason, compensating controls, expiration, audit
record, and rollback plan. Exceptions cannot lower the public untrusted
isolation floor, permit ambient platform credentials, bypass tenant
separation, or waive evidence for a hard invariant.

## Consequences

### Positive

- Public untrusted execution has a concrete VM isolation floor and cannot
  silently degrade to a container boundary.
- Host, guest, network, credential, and snapshot controls form one reviewable
  production profile instead of independent best-effort features.
- Hard invariants distinguish preventive requirements from monitoring and
  operational mitigations.
- Credentials and snapshots receive explicit lifecycle semantics across boot,
  suspend, restore, fork, and destroy.
- Production launch depends on evidence for the exact deployed combination.
- Residual risk and shared-host placement require explicit ownership rather
  than implicit acceptance.

### Negative

- Public multi-tenant capacity may require dedicated tenancy until
  approves a shared-host profile.
- Multiple blocking evidence gates increase launch lead time and require
  coordinated ownership across platform teams.
- Brokered credentials and default-deny networking may require workload and
  tool integration changes.
- Snapshot creation is more expensive because it requires quiesce, revocation,
  exclusion evidence, encryption, and restore validation.
- Host minimization and profile-specific validation reduce configuration
  flexibility and increase release-management work.
- Some workloads will be rejected when their capability or compatibility
  requirements cannot satisfy the approved security profile.

## Rejected Alternatives

### Container-First Public Posture

Public workloads would use a standard container or gVisor by default, with a
microVM selected only for high-risk requests.

**Rejected**: Unknown code provenance and autonomous tool use make reliable
pre-execution risk classification insufficient. The public default retains a
hardware virtualization boundary, while gVisor remains an explicit trusted
fast path.

### Backend Choice as the Complete Security Posture

Selecting Firecracker would be treated as sufficient production isolation.

**Rejected**: A VMM boundary does not minimize host privileges, restrict
network access, protect credentials, exclude secrets from snapshots, verify
images, contain resource exhaustion, or provide current validation evidence.
The complete deployed profile is the security unit.

### Tenant-Declared Trust

Tenants would label workloads as trusted to gain the gVisor fast path.

**Rejected**: Tenant intent alone cannot authorize a lower platform isolation
floor. Trusted fast-path admission requires both tenant and platform policy,
compatibility evidence, revocation, and audit.

### Long-Lived Credentials Inside the Guest

Credentials would be injected at boot and reused across the sandbox lifetime,
snapshot, resume, and fork.

**Rejected**: Persistent credentials turn guest compromise and snapshot access
into durable authority. Credentials are short-lived, scoped, revocable, and
reissued after lifecycle transitions.

### Monitoring Instead of Preventive Isolation

Runtime monitoring, anomaly detection, and audit alerts would detect boundary
violations after they occur.

**Rejected**: Detection is necessary but cannot replace controls for backend
downgrade, namespace sharing, cross-tenant writable state, platform socket
access, credential persistence, or readiness ordering. Those outcomes must be
prevented.

### Shared-Host Multi-Tenancy Before Side-Channel Review

MicroVM boundaries would be considered sufficient for cross-tenant placement
on shared hardware without a dedicated side-channel assessment.

**Rejected**: Hardware and shared-resource channels are outside the VMM's
logical device boundary. must assess and approve the exact profile, or
placement uses dedicated tenancy.

### Snapshot Encryption Without Secret Exclusion

Encrypted snapshots would be allowed to contain live credentials because
storage access is controlled.

**Rejected**: Encryption protects storage media but does not prevent restored
or forked guests from reusing captured authority. Credentials and sessions
must be revoked, zeroized, excluded, and replaced.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Define the detailed threat model, abuse cases, security objectives, and risk register |
| | Convert the mandatory gates into the production readiness model and rollout checklist |
| | Implement and validate seccomp and Linux capability minimization profiles |
| | Harden runtime processes, identities, namespaces, filesystems, devices, sockets, and host services |
| | Implement cgroup v2 resource controls and exhaustion tests |
| | Implement mediated and short-lived runtime credential delivery through the secrets broker |
| | Prove credential revocation, zeroization, and exclusion across snapshot, resume, and fork |
| | Build the production isolation boundary validation suite |
| | Assess shared-host side-channel and covert-channel risks and define eligible placement profiles |
| 89 | Build the traceable security assurance case and residual-risk approval record: [assurance case](../security/assurance-case.md) |

## References

- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Firecracker design and security barriers](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Firecracker snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [Firecracker MMDS snapshot considerations](https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-user-guide.md)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [Linux control group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

## Required Review

The ADR remains `Proposed` until all roles approve the
production posture, hard invariants, launch gates, and residual-risk model:

- Security owner
- Runtime owner
- Networking owner
- Control-plane owner
