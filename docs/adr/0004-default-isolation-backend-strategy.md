# ADR-0004: Default Isolation Backend Strategy

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Backend Selection ADR
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0003](0003-host-guest-agent-protocol-contract.md)

## Context

PicoCompute needs one backend selection strategy before runtime implementation
expands across Firecracker, gVisor, QEMU, Cloud Hypervisor, and Kata
Containers. The strategy must balance:

- isolation strength for public multi-tenant execution
- startup and restore latency
- Linux application and device compatibility
- snapshot, resume, and fork support
- network and image integration
- host/guest protocol compatibility
- operational and security review cost

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
makes the control plane authoritative for lifecycle and access decisions.
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md)
keeps backend adapters bounded to runtime mechanics.
[ADR-0003](0003-host-guest-agent-protocol-contract.md)
defines one protocol over backend-specific local transports.

Backend choice is therefore a control-plane policy decision. It is not an
adapter preference, a host-local retry decision, or a tenant-controlled
escape hatch.

The current repository already uses Firecracker as the default runtime type
and has Firecracker and QEMU backend adapter prototypes. gVisor, Cloud Hypervisor,
and Kata Containers require additional adapter or evaluation work. This ADR
defines the target production policy without declaring those prototypes
production-ready.

## Decision

PicoCompute selects **Firecracker as the default backend for untrusted public
multi-tenant workloads**, **gVisor as an explicit trusted fast path**, and
**QEMU as the compatibility VM and public-workload fallback**.

Cloud Hypervisor and Kata Containers remain evaluation-only. They are not
eligible for production selection until their evaluation issues are accepted,
their adapters implement the PicoCompute lifecycle contract, and their required
conformance profiles pass.

### Workload Classes and Backend Order

| Workload class | Eligibility | Preferred backend | Permitted fallback order | Failure behavior |
|---|---|---|---|---|
| Public untrusted | Internet-facing or cross-tenant code, unknown provenance, or strong isolation required | Firecracker | QEMU | Reject placement when neither backend passes every gate. gVisor is never an automatic fallback. |
| Trusted fast path | Explicit tenant and platform policy approval for a lower isolation floor and gVisor compatibility | gVisor | Firecracker, then QEMU | Recompute and audit the selection. Never weaken below the approved isolation floor. |
| Compatibility VM | Workload requires a broader VM device model, guest kernel behavior, firmware path, or image format unavailable in Firecracker | QEMU | None automatically | Reject placement. A different backend requires a new request or policy decision proving compatibility. |
| Kubernetes-integrated | Deployment environment uses Kubernetes | Apply the underlying workload class | Apply the underlying workload class | Kubernetes integration does not change the isolation floor or make Kata production-eligible. |

Public untrusted workloads always retain a hardware virtualization boundary.
The QEMU fallback has a broader device and operational surface than
Firecracker, but it does not lower the workload to a syscall-mediated
container boundary.

Trusted fast-path eligibility is an explicit policy grant, not a default
inferred from low resource usage, latency sensitivity, image format, or
backend availability. Removing that grant immediately removes gVisor from
future placement and restore candidates.

### Selection and Fallback Semantics

The backend selection policy implemented by
 evaluates ordered candidates
before host assignment. The resulting decision records:

- workload class and isolation floor
- selected backend and fallback rank
- policy and tenant configuration revisions
- required capability set
- image, kernel, rootfs, and snapshot compatibility evidence
- host/guest protocol compatibility evidence
- conformance profile and backend health revision
- a stable reason code and rejected-candidate reasons

Fallback is a new control-plane selection decision. Runtime adapters,
`sandboxd`, host agents, and schedulers must not silently start another
backend when the selected backend fails.

When the selected backend becomes unavailable before boot:

1. The current attempt stops before starting another runtime.
2. Partial resources are cleaned through the normal idempotent workflow.
3. The control plane reruns selection against the permitted fallback order.
4. The old and new decisions are persisted and emitted as audit events.
5. Placement restarts only after the replacement backend passes every gate.

Backend fallback is not live migration. It does not preserve in-memory state
or reuse backend-specific runtime artifacts.

### Hard Selection Gates

A backend is eligible only when every gate passes:

1. **Tenant policy**: The tenant is allowed to use the backend and workload
   class.
2. **Isolation floor**: The backend meets or exceeds the class's required
   boundary. Public untrusted selection requires a microVM or VM boundary.
3. **Capabilities**: The backend declares support for every required
   lifecycle, device, network, snapshot, and guest capability.
4. **Image compatibility**: Signed image metadata identifies compatible
   kernel, rootfs, firmware, architecture, and backend artifacts.
5. **Snapshot compatibility**: Restore metadata matches the backend family,
   runtime version policy, CPU template, device model, image digest, and guest
   protocol requirements.
6. **Protocol compatibility**: The backend provides an approved local
   transport and the image can negotiate all required
   [ADR-0003](0003-host-guest-agent-protocol-contract.md) capabilities.
7. **Host support**: The target cell and host expose the required CPU
   virtualization, devices, kernel features, network integration, and backend
   version.
8. **Health and capacity**: The backend and its helpers are healthy and the
   host has capacity for the requested resources.
9. **Conformance status**: The backend has a passing, non-expired conformance
   result for the selected production profile.

No gate is advisory. If no backend passes, selection returns a typed rejection
with candidate-specific reasons. The scheduler may score only hosts that
support the already selected backend; it must not select or substitute a
backend through placement scoring.

### Backend Capability and Risk Matrix

Latency entries are relative architecture expectations, not production SLO
evidence. Each production backend must publish measured cold boot, warm
restore, memory overhead, and lifecycle latency through its conformance
report before launch.

| Backend | Isolation boundary | Expected boot latency | Snapshot posture | Networking | Image format | Host/guest protocol | Operational risk |
|---|---|---|---|---|---|---|---|
| Firecracker | KVM microVM with minimized device model | Low for a VM; primary warm-restore path | Full microVM snapshots supported; restore is backend, version, CPU, device, and artifact constrained | Pre-created TAP with PicoCompute-owned routing and policy | Signed guest kernel plus ext4 rootfs and declared data drives | virtio-vsock through the per-VM Unix socket mapping | Medium: KVM, jailer, guest kernel, TAP, artifact, and snapshot compatibility must be managed |
| gVisor | Userspace application kernel with syscall mediation | Lowest expected cold-start class for compatible workloads | Process checkpoint/restore exists but requires PicoCompute compatibility and lifecycle validation | gVisor netstack or approved CNI integration; host-network passthrough is forbidden for production isolation | Verified OCI image or bundle compatible with supported gVisor syscalls and features | Permission-controlled per-sandbox Unix domain socket | Medium: syscall, filesystem, networking, accelerator, and checkpoint compatibility vary by workload |
| QEMU | KVM VM with broad machine and device model | Higher than Firecracker by default; optimization requires measurement | Mature VM snapshot and migration primitives; PicoCompute restore remains version and machine-model constrained | TAP/virtio-net through PicoCompute-owned network setup | Signed kernel, firmware where required, and raw or qcow2-compatible disk artifacts | virtio-vsock; virtio-serial only as a compatibility transport | High: broad device surface, configuration space, patching, and tuning increase operational burden |
| Cloud Hypervisor | KVM microVM with a modern virtio-focused device model | Expected low to medium; must be measured by | Snapshot/restore exists, but cross-version support is not guaranteed | TAP/virtio-net subject to validation | Kernel, firmware where required, and compatible disk artifacts subject to | vsock or another ADR-0003-compliant local transport, pending validation | High until evaluation proves lifecycle, upgrade, snapshot, and security readiness |
| Kata Containers | VM-isolated container through CRI/containerd integration | Depends on Kata, hypervisor, image, and Kubernetes stack; must be measured by | Feasibility and lifecycle mapping are pending | Kubernetes CNI plus Kata runtime integration | OCI image plus Kata guest kernel, image, and hypervisor artifacts | ADR-0003-compatible transport requires integration validation | High: adds CRI, containerd, Kata, hypervisor, guest-agent, and Kubernetes version coupling |

### Per-Backend Production Requirements

#### Firecracker

Firecracker is the first production-quality backend path. It must provide:

- jailer-based process isolation and dedicated runtime identities
- approved KVM, seccomp, cgroup, namespace, device, and filesystem controls
- signed guest kernel and rootfs artifacts
- deterministic TAP and vsock resource identities
- full snapshot compatibility metadata and restore validation
- guest readiness through ADR-0003 before reporting `Running`
- passing public-untrusted conformance and isolation profiles

#### gVisor

gVisor is eligible only for trusted fast-path workloads. It must provide:

- an explicit tenant and workload policy grant
- verified syscall, filesystem, network, accelerator, and image compatibility
- netstack or another approved isolated network mode
- no host-network passthrough in production
- checkpoint/restore support only when the requested capability has passed
  PicoCompute conformance
- a permission-controlled Unix domain socket transport for ADR-0003
- passing trusted-fast-path conformance and isolation profiles

#### QEMU

QEMU is the public-workload fallback and compatibility VM. It must provide:

- a pinned machine type, CPU model or template, firmware policy, and device set
- minimized devices and privileges for the selected workload profile
- signed and verified guest artifacts
- PicoCompute-owned TAP and virtio networking
- virtio-vsock by default, with virtio-serial used only when compatibility
  requires it
- snapshot metadata bound to the QEMU version, machine type, CPU, devices,
  image, and protocol capabilities
- passing public-untrusted or compatibility conformance profiles as applicable

#### Cloud Hypervisor and Kata Containers

Cloud Hypervisor and Kata Containers remain disabled in production policy.
 and
 must produce measured
evaluations and explicit implement, defer, or reject recommendations.

An accepted evaluation is not enough to enable selection. Each backend still
requires:

- a production adapter with bounded operations
- declared capability and compatibility metadata
- an approved ADR-0003 transport
- backend-specific image and snapshot policy
- security and operational review
- passing conformance for every enabled workload profile

### Snapshot and Restore Rules

Snapshots are bound to the backend that created them. Required metadata
includes:

- backend family and exact runtime version or approved compatibility range
- architecture, CPU vendor, model or template, and required CPU features
- machine and device model
- kernel, firmware, rootfs, and image digests
- snapshot format version and lineage
- guest-agent protocol versions and required capabilities
- network and identity resources that must be regenerated

Cross-backend restore is prohibited. A Firecracker snapshot cannot fall back
to QEMU, and a gVisor checkpoint cannot restore through Firecracker.
Cross-version restore is allowed only when the backend's compatibility policy
and PicoCompute conformance evidence explicitly cover that version pair.

When no compatible restore target exists, the request fails. The control
plane may offer a separately requested cold boot from durable workspace state,
but it must not represent that operation as snapshot resume.

### Kubernetes-Integrated Deployments

Kubernetes is a deployment and orchestration environment, not an isolation
class. PicoCompute applies the same workload classification and backend gates
whether its control-plane or execution components run on bare hosts or
Kubernetes nodes.

- Public untrusted workloads require Firecracker or QEMU.
- Trusted fast-path workloads may use an approved gVisor runtime integration.
- Kata Containers is not a public-untrusted production path until,
  adapter implementation, and conformance approval are complete.
- If a Kubernetes environment cannot expose an eligible backend, placement is
  rejected rather than downgraded to a standard container runtime.

### Backend Conformance

 provides the shared
conformance suite. Every enabled backend and workload profile must report:

- prepare, boot, readiness, exec, suspend, resume, fork, destroy, and cleanup
- declared unsupported capabilities without silent skips
- guest protocol negotiation, authentication, bounds, and reconnect behavior
- idempotency, deadlines, cancellation, restart reconciliation, and cleanup
- resource accounting, cgroup enforcement, and process-tree containment
- network attachment, identity, policy, and teardown
- image, kernel, rootfs, architecture, and feature compatibility
- snapshot capture, restore, lineage, version, and secret-exclusion behavior
- isolation boundary tests and profile-specific security assertions
- latency, resource usage, diagnostics, and typed error behavior

Production eligibility requires a passing result for the exact backend
version, host profile, guest artifact profile, and workload class. Unsupported
capabilities remain selectable only when the workload does not require them.

## Consequences

### Positive

- Public multi-tenant workloads have a clear hardware-isolation default.
- The fallback preserves the VM isolation floor instead of silently moving to
  a weaker boundary.
- gVisor can provide a lower-latency path without becoming an implicit public
  default.
- QEMU provides a deliberate compatibility path while its broader
  operational surface remains visible.
- Backend choice is deterministic, auditable, and separated from scheduler
  scoring and adapter behavior.
- Snapshot and image compatibility become explicit selection evidence.
- Evaluation backends cannot enter production through configuration alone.

### Negative

- Public capacity must support at least one production VM backend, and robust
  fallback requires both Firecracker and QEMU capacity.
- Maintaining two public-workload VM paths increases patching, conformance,
  image, snapshot, and operational work.
- Trusted fast-path admission requires policy and compatibility evidence.
- Cross-backend restore is unavailable.
- Kubernetes environments without an approved VM backend cannot run public
  untrusted workloads.

## Rejected Alternatives

### gVisor as the Default

All workloads would prefer gVisor, with a microVM fallback for incompatible or
high-risk workloads.

**Rejected**: Compatibility and isolation classification would become part of
the exception path for the public default. PicoCompute's public multi-tenant
posture requires a hardware virtualization boundary by default, while gVisor
remains valuable for explicitly trusted and compatible workloads.

### Cloud Hypervisor as the Default

Cloud Hypervisor would become the primary microVM backend with Firecracker as
fallback.

**Rejected**: PicoCompute does not yet have measured Cloud Hypervisor lifecycle,
snapshot, upgrade, protocol, or operational evidence. Its snapshot/restore
compatibility is not guaranteed across versions. must evaluate it
without delaying the Firecracker production path.

### Workload-Policy-Only Selection

No backend would be privileged as the default. Policy and current host
availability would choose any backend that claimed the required capabilities.

**Rejected**: This permits fleet configuration and availability to redefine
the security posture. Capability labels alone do not capture isolation,
operational maturity, or conformance evidence. Workload policy constrains the
ordered strategy but does not replace it.

### Firecracker with gVisor as Public Fallback

Public untrusted workloads would use gVisor when Firecracker capacity or
health was unavailable.

**Rejected**: This is a silent isolation downgrade from hardware
virtualization to syscall mediation. Public placement must fail closed or use
QEMU.

### Kata as the Kubernetes Default

Kubernetes-integrated deployments would select Kata independently of workload
class.

**Rejected**: Deployment environment does not define trust level. Kata adds
integration and version coupling that has not yet evaluated, and it
must pass the same lifecycle, protocol, snapshot, and isolation gates as any
other backend.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Define the production security posture and controls using this backend isolation floor |
| | Implement deterministic, auditable backend selection and typed rejection reasons |
| | Complete the Firecracker production adapter and public-untrusted profile |
| | Implement the policy-gated gVisor trusted fast path |
| | Complete the QEMU compatibility and public fallback adapter |
| | Measure and review Cloud Hypervisor fit |
| | Validate Kata Containers and Kubernetes integration fit |
| | Build profile-aware backend conformance and production-readiness evidence |

## References

- [Firecracker overview](https://github.com/firecracker-microvm/firecracker)
- [Firecracker snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [Firecracker getting started and image requirements](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security)
- [gVisor checkpoint and restore](https://gvisor.dev/docs/user_guide/checkpoint_restore)
- [gVisor networking guide](https://gvisor.dev/docs/architecture_guide/networking)
- [QEMU system emulation](https://qemu.readthedocs.io/en/master/system)
- [Cloud Hypervisor project and compatibility policy](https://github.com/cloud-hypervisor/cloud-hypervisor)
- [Kata Containers project](https://github.com/kata-containers/kata-containers)

## Required Review

The ADR remains `Proposed` and remains in review until the public
workload default is approved:

- Security owner
