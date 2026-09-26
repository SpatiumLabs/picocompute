# ADR-0007: Snapshot, Resume, and Fork Consistency Model

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Snapshot Semantics ADR
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0003](0003-host-guest-agent-protocol-contract.md),
[ADR-0004](0004-default-isolation-backend-strategy.md),
[ADR-0005](0005-per-sandbox-networking-model.md),
[ADR-0006](0006-production-security-posture-for-sandbox-isolation.md)

## Context

PicoCompute needs one consistency contract for preserving and branching sandbox
state. Without that contract, backend snapshot features can expose different
behavior for:

- active exec operations and output streams
- filesystem and process state
- sandbox, boot, protocol, and operation identity
- current policy and access leases
- credentials and non-persistent mounts
- network identities, connections, DNS state, and port exposure
- restore compatibility and parent/child lineage

The runtime backends do not provide an interchangeable semantic surface. The
Firecracker and QEMU backends can capture VM memory and device state
through backend-specific snapshot mechanisms, while gVisor uses a different
checkpoint model. Both backends rely on KVM for hardware-accelerated
virtualization on Linux. Filesystem copy-on-write can branch a workspace
without preserving process memory. Backend-native artifacts also have strict
and evolving version, CPU, machine, device, and image compatibility
constraints.

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
makes the regional metadata store authoritative and treats fork as creation of
a new sandbox without changing the source lifecycle state.
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md)
assigns orchestration to `host-agent` and `sandboxd`, with bounded capture and
restore mechanics owned by `snapshot-agent` and runtime adapters.
[ADR-0003](0003-host-guest-agent-protocol-contract.md)
requires cooperative quiescence and fresh authentication after restore or
fork.
[ADR-0004](0004-default-isolation-backend-strategy.md)
prohibits cross-backend restore.
[ADR-0005](0005-per-sandbox-networking-model.md)
requires current network policy and fresh host-local network state.
[ADR-0006](0006-production-security-posture-for-sandbox-isolation.md)
requires credential revocation, secret exclusion, integrity validation, and
fresh authority after restore or fork.

This ADR defines the user-visible guarantees that those components implement.
It does not define the snapshot metadata storage schema, blob format, public
API wire schema, backend-specific capture commands, or storage tiering policy.

## Decision

PicoCompute adopts a **filesystem-first portable consistency contract with
cooperative quiescence, fail-closed capture, and capability-gated memory
preservation**.

The portable v1 guarantee is a consistent immutable workspace point plus the
metadata needed to create or resume a sandbox safely. Memory and runtime
device state may be included only when the selected backend and deployment
profile declare and prove the required capability. Backend-native details are
not exposed as the user-facing consistency model.

Snapshot creation never silently falls back to a weaker consistency level.
If the requested profile cannot quiesce, exclude prohibited state, or satisfy
its compatibility requirements, the operation fails and the sandbox returns
to its pre-operation behavior.

### User-Visible Snapshot Purposes

Snapshot purpose describes why an artifact exists. It is separate from the
state profile that describes what the artifact preserves.

| Purpose | User-visible guarantee | Reuse and identity |
|---|---|---|
| Base snapshot | Immutable, platform-produced warm-start point derived from a verified image and initialization sequence. It contains no tenant session, active exec, credential, lease, or live network authority. | May create many new sandboxes when tenant and policy rules allow. Every restore receives a new sandbox and boot identity. |
| Runtime snapshot | Internal backend-bound capture artifact used to implement another snapshot purpose. It records runtime and device evidence but is not a standalone portable API contract. | Never restored directly by callers and never interpreted by another backend family. |
| Session snapshot | Immutable recovery point for one sandbox workspace and, for lifecycle suspend/resume, its process memory and runtime device state. | Memory-backed resume preserves the sandbox identity and lineage but creates a new boot, protocol session, operation namespace, and runtime authority. Filesystem-only recovery uses a boot path rather than lifecycle resume. |
| Fork snapshot | Immutable branching point from which one or more child sandboxes receive independent writable state. | Every child receives a new sandbox, workspace, network, policy, boot, protocol session, operation, quota, and credential identity. |

Base, session, and fork snapshots may reference one or more runtime snapshot
artifacts internally. Callers depend on the declared state profile and
purpose, not the backend artifact layout.

### State Profiles

PicoCompute exposes semantic state profiles rather than backend-specific modes.

| Profile | Preserved state | Guarantee |
|---|---|---|
| `filesystem` | Immutable image references, the committed workspace point, declared persistent mounts, and snapshot metadata | Portable v1 baseline. Restore performs a clean boot or warm base restore and does not preserve running processes, open file descriptors, process memory, or in-flight execs. It is not a `Suspended -> Resuming` lifecycle transition. |
| `memory` | Everything in `filesystem`, plus backend runtime state, guest memory, and declared restorable device state | Capability-gated extension. Restore may continue guest processes from the capture point, but host protocol, credentials, network authority, and excluded mounts are always regenerated. |

The `memory` profile is eligible only when:

- the selected backend declares snapshot and restore support for the exact
  runtime profile
- the guest protocol supports quiesce, session invalidation, and resume
  notification
- secret exclusion and snapshot integrity evidence pass
- metadata can reject incompatible hosts without loading snapshot blobs
- the backend profile has current conformance evidence for capture, restore,
  cleanup, and identity refresh

A request for `memory` fails with a typed unsupported or incompatible outcome
when any condition is missing. PicoCompute does not substitute `filesystem`
without an explicit new request.

Lifecycle suspend and resume require the `memory` profile because
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
defines `Suspended` as preserving VM memory and device state. A backend that
cannot satisfy the `memory` profile rejects suspend. It does not transition
the sandbox to `Suspended`, `Stopped`, or a filesystem-only recovery state as
a fallback.

### Consistency Guarantee

A successful snapshot represents one immutable logical cut taken after:

1. The control plane admits the operation with tenant, sandbox, purpose,
   profile, policy, deadline, and idempotency identity.
2. `sandboxd` installs an operation fence that rejects new execs and other
   conflicting mutations.
3. Active exec operations reach a terminal state before the deadline.
4. The guest completes required application hooks, flushes guest-visible
   persistent state, invalidates runtime authority, and returns a signed or
   authenticated quiesce receipt.
5. Non-persistent mounts and prohibited state are detached or proven excluded.
6. The workspace implementation flushes and freezes the required filesystems,
   then creates an immutable copy-on-write point or equivalent atomic storage
   commit.
7. For the `memory` profile, the runtime is paused only after the workspace
   point is fixed while the required filesystems remain frozen, and the
   backend captures memory and restorable device state against that exact
   workspace reference.
8. `snapshot-agent` verifies artifact completeness and exclusion evidence.
9. The snapshot manager commits ready metadata only after every required blob,
   digest, compatibility field, and lineage reference is durable.

The workspace point and any memory artifact belong to the same snapshot
operation and must not be combined with artifacts from different attempts.

PicoCompute guarantees platform-level consistency, not automatic transactional
consistency for arbitrary applications. An application receives
application-consistent semantics only when its registered quiesce hooks
complete successfully. Without such hooks, PicoCompute guarantees that admitted
execs have drained, persistent filesystems have been flushed and frozen, and
the captured runtime is not concurrently mutating the workspace.

### Active Exec and Stream Behavior

Snapshot, suspend, and fork use the same default exec policy:

- after the operation fence is installed, new exec requests fail with a typed
  `snapshot_in_progress` or equivalent busy outcome
- already admitted execs continue within their original deadlines
- the snapshot operation waits for those execs and their supervised process
  trees to reach a terminal state
- output remains available through the normal bounded stream and replay
  contract while the exec drains
- PicoCompute does not automatically cancel an exec to make snapshot creation
  succeed
- if any exec remains active at the snapshot deadline, capture fails with a
  typed busy or timeout outcome

After failed capture, PicoCompute thaws filesystems, clears the operation fence,
restores admissible network behavior, and permits normal work only after
cleanup proves that no partial capture resource remains attached. If quiesce
already invalidated the protocol session or boot secret, the source receives
fresh authentication and an explicit abort/recovery notification before work
is admitted again. Existing execs are not reported as failed merely because
the snapshot attempt failed.

A caller that requires cancellation must issue an explicit cancel operation
and observe its terminal outcome before retrying the snapshot. This keeps exec
cancellation auditable and prevents snapshot requests from changing workload
behavior implicitly.

### Cooperative Quiescence and Failure Policy

Cooperative quiescence is mandatory for every session and fork snapshot and
for any base snapshot produced from a running guest.

The quiesce protocol must:

- stop guest admission of new host operations
- report active operation state and refuse readiness while required work is
  active
- execute bounded application quiesce hooks when configured
- flush persistent guest filesystems and workspace-visible state
- revoke or invalidate access leases and directly delivered credentials
- invalidate the current host/guest protocol session and zeroize its boot
  secret
- detach or prove exclusion of secret and temporary mounts
- return the captured policy epoch, mount manifest, persistent volume set,
  guest boot ID, and required compatibility evidence

Quiesce has an absolute deadline inherited from the lifecycle operation.
Busy, timeout, unsupported, guest crash, hook failure, exclusion failure, or
receipt mismatch aborts capture.

PicoCompute does not create a forced or crash-consistent fallback snapshot after
cooperative quiescence fails. Supporting an explicit crash-consistent profile
would require a separate architecture decision, API contract, data-safety
warning, and conformance profile.

### Included and Excluded State

The snapshot manifest classifies every attached state source. Unclassified
mounts or devices make capture ineligible.

| State class | Snapshot behavior |
|---|---|
| Verified base image, kernel, init, firmware, and rootfs | Referenced by immutable digest, not copied as mutable tenant state |
| Persistent workspace and declared persistent data mounts | Included as immutable references or copy-on-write layers |
| Guest memory and restorable device state | Included only for the `memory` profile |
| Application logs in declared persistent storage | Included according to the mount policy |
| `/run/pico/secrets` and direct credential channels | Excluded, revoked, detached, and proven absent |
| `/run/pico/tmp`, ephemeral mounts, scratch disks, and host staging paths | Excluded and recreated empty or reported unavailable |
| Host/guest protocol sessions, boot secrets, operation handles, and stream connections | Excluded and invalidated |
| Access leases, bearer tokens, runtime credentials, and secret broker state | Excluded and reauthorized after readiness |
| Network namespaces, TAP/veth devices, host addresses, NAT, connection tracking, DNS cache, active flows, and port exposure | Excluded and rebuilt from current policy |
| Host process identities, pidfds, cgroups, sockets, and helper receipts | Excluded as runtime authority; new host-local resources are created |
| Metrics exporters, trace connections, and telemetry transport buffers | Excluded; correlation identity is reconstructed from durable metadata |

If a workload copies a secret into its persistent workspace or ordinary
application memory, PicoCompute cannot reliably identify or erase that copy.
Such data is tenant state governed by data classification, retention, and
snapshot policy. Snapshot exclusion prevents platform-issued authority from
remaining valid; it does not make an untrusted workload forget data it has
already observed.

### Atomic Publication and Failure Recovery

A snapshot is externally restorable only after its metadata state is
`ready`. The implementation may use staging states, but callers must observe
one of two outcomes:

- a complete immutable snapshot with all required metadata and blobs
- no restorable snapshot for that operation

Metadata publication occurs after blob durability and integrity evidence.
Idempotent retries with the same operation identity return the existing ready
snapshot, continue the same incomplete operation, or return its persisted
terminal failure. They never create a second logical snapshot.

Partial blobs, temporary workspace layers, paused runtimes, and staging
metadata remain owned by the failed operation until cleanup proves absence or
quarantines ambiguous resources. They are not eligible for restore, fork,
cache promotion, or garbage-collection reference counting as live snapshots.

For a successful fork snapshot, the immutable branching point is committed
before a child writable layer is published. A child boot failure does not
modify or roll back the source sandbox or the committed fork point.

### Source Disposition After Capture

The operation that requested capture determines what happens to the source
after ready metadata is committed:

| Operation | Source disposition |
|---|---|
| Standalone snapshot of a running sandbox | Thaw persistent filesystems, resume the runtime when paused, establish fresh guest authentication when quiesce invalidated it, release the operation fence, and return the source to `Running` |
| Suspend | Require the `memory` profile, keep the runtime stopped, and report `Suspended` only after the ready snapshot and required local receipts are durable |
| Fork | Return the source to its pre-fork lifecycle state after the immutable fork point is ready; child preparation proceeds independently |
| Base snapshot generation | Follow the image-builder contract, which may terminate the disposable builder after capture; the base snapshot itself contains no builder authority |

A source returning to `Running` receives an explicit quiesce-release
notification. It does not receive `ResumeNotify` because its sandbox and boot
state were not restored from an artifact. If the protocol session or boot
secret was invalidated, it first authenticates with fresh per-boot material,
then receives the release notification and current policy context.

No operation reports success while the source is unexpectedly paused, frozen,
fenced, or unable to authenticate. Failure to restore the required source
disposition is a lifecycle failure with persisted cleanup and reconciliation
state, not a successful snapshot with a warning.

### Restore Compatibility

Compatibility validation occurs from trusted metadata before snapshot blobs
are attached to a runtime. Blob integrity and authenticated encryption are
then verified before guest execution.

Every restore validates:

- snapshot metadata schema and state profile
- tenant ownership and authorized base-snapshot sharing policy
- snapshot lineage, retention, revocation, and deletion state
- encryption key reference, authenticated metadata, and blob digests
- backend family and exact version or an explicitly approved version range
- architecture, CPU vendor, CPU template, and required CPU features
- machine type, device model, device configuration, and snapshot format
- image, rootfs, kernel, init, firmware, and guest-agent artifact digests
- guest protocol bootstrap compatibility, operational version range, and
  required capabilities
- vCPU, memory, workspace, persistent mount, and device shape constraints
- workload class, isolation floor, data classification, and current tenant
  policy
- exclusion manifest and proof that prohibited state is not restorable

Cross-backend restore is always rejected. Cross-version restore is accepted
only when the backend compatibility policy and PicoCompute conformance evidence
cover the exact source and target pair.

The snapshot policy epoch is historical evidence, not restored authority.
Resume and fork are admitted against the current policy epoch. A changed
policy is allowed only when the current decision still permits the snapshot
purpose, backend, workload class, data handling, mounts, and requested
capabilities. A stale command epoch, revoked snapshot, weakened isolation
floor, prohibited data class, missing exclusion evidence, or incompatible
current policy is rejected.

Compatibility failures are typed and identify the mismatched dimension
without exposing secret metadata. At minimum, implementations distinguish:

- `snapshot_not_ready`
- `snapshot_revoked`
- `tenant_mismatch`
- `integrity_failed`
- `key_unavailable`
- `backend_incompatible`
- `runtime_version_incompatible`
- `cpu_incompatible`
- `device_model_incompatible`
- `image_incompatible`
- `protocol_incompatible`
- `resource_shape_incompatible`
- `policy_incompatible`
- `excluded_state_invalid`
- `lineage_invalid`

When a snapshot cannot be restored, PicoCompute may offer a separately requested
cold boot from an independently durable workspace. That operation is not
reported as resume and does not imply process-memory recovery.

### Resume Semantics

Lifecycle resume applies only to a compatible `memory` session snapshot. It
preserves:

- tenant and sandbox identity
- durable sandbox metadata and audit history
- workspace identity and committed contents
- snapshot and workspace lineage
- logical network identity, subject to current policy

Resume always replaces:

- boot ID and per-boot authentication secret
- host/guest protocol session and operation namespace
- host assignment and fencing token as applicable
- host-local runtime, process, cgroup, socket, mount, and helper identities
- network namespace, interfaces, host-local addresses, routes, DNS
  authorization, NAT, connection tracking, and exposure state
- access leases and runtime credentials

The restored guest cannot become `Running` until:

1. integrity and compatibility checks pass
2. the runtime restores the declared state profile
3. current network policy is installed with ingress disabled by default
4. the guest authenticates with a fresh boot secret
5. protocol version and capabilities are renegotiated
6. `ResumeNotify` supplies current sandbox, boot, policy, mount, network, and
   lineage identity
7. non-persistent resources are recreated or explicitly reported unavailable
8. health, exclusion, and audit-correlation checks pass

An expired or pre-snapshot lease, credential, session, flow, DNS answer, or
port exposure never becomes valid because the sandbox resumed.

### Fork Semantics

Fork is creation of a child sandbox from an immutable fork snapshot. The
source remains in its existing lifecycle state except for the bounded
operation fence and quiesce interval.

Every child receives:

- a new sandbox ID and lifecycle record
- a new workspace identity and writable copy-on-write layer
- a new logical network identity and host-local network resources
- a new policy record admitted at the current policy epoch
- a new boot ID, protocol secret, session, and operation namespace
- independent quota, accounting, audit, retention, and cleanup ownership
- no credentials, leases, DNS cache, active network flows, port exposure, or
  secret mounts inherited from the source

The child policy may be equal to or more restrictive than the currently
authorized source policy. Any requested capability increase is a new
authorization decision and is not granted by lineage.

For a `filesystem` fork, the child starts through the normal boot or base
restore path from the committed workspace point. Source processes, memory,
open files, and exec operations do not exist in the child.

For a capability-gated `memory` fork, guest memory may be restored into the
child only after all embedded platform authority is invalidated. The child
must receive `ResumeNotify` with a fork reason and fresh child identity before
workload execution is released. Applications that cannot tolerate identity
change after memory restore are ineligible for memory fork and must use the
`filesystem` profile.

Lineage records:

- source sandbox ID
- source snapshot ID
- child sandbox ID
- parent workspace or layer reference
- fork operation ID
- snapshot purpose and state profile
- creation time and policy decision

Parent and child may be destroyed in any order. Shared immutable ancestors
remain retained while referenced by any live snapshot, sandbox, warm pool, or
child lineage. Writes, quotas, credentials, policies, and cleanup progress are
independent after fork.

### Lazy Restore

Lazy memory loading is an implementation optimization and must preserve the
same `memory` profile semantics.

- metadata, compatibility, integrity roots, identity refresh, and current
  policy validation complete before guest execution
- every page is authenticated before use
- missing or corrupt pages fail the restore rather than returning zero or
  stale data
- admission limits bound page-fault concurrency, storage bandwidth, and host
  memory pressure
- eager restore remains the fallback only when it was already requested or
  transparently preserves the same `memory` semantics

Lazy restore does not weaken readiness, exclusion, lineage, or compatibility
requirements.

### Ownership and Implementation Boundaries

| Concern | Authority |
|---|---|
| Snapshot/fork admission, tenant authorization, current policy, purpose, profile, and idempotency | Regional control plane |
| Durable snapshot identity, ready state, lineage, retention, and compatibility metadata | Snapshot manager and regional metadata store |
| Host command admission, fencing, deadlines, and aggregate lifecycle reporting | `host-agent` |
| Operation fence, exec draining, step persistence, retry, rollback, and local receipts | `sandboxd` |
| Guest quiesce hooks, flush, session invalidation, exclusion receipt, and resume notification | Guest agent |
| Workspace flush, freeze, immutable point, COW branch, and storage receipts | Workspace/storage implementation |
| Snapshot blob capture, restore, integrity evidence, staging, and local cleanup | `snapshot-agent` |
| Backend pause, memory/device capture, restore, and capability evidence | Runtime adapter |
| Current network resources and policy rebuild | `network-agent` |
| Credential revocation and post-readiness reissuance | Access lease manager and secrets broker |

No runtime adapter or snapshot storage component may choose the snapshot
purpose, lower the requested state profile, admit a restore, reuse authority,
or publish a child independently.

## Consequences

### Positive

- Callers receive one consistency model across backend implementations.
- Filesystem snapshots and COW fork can ship before memory restore without
  changing the portable contract.
- Memory preservation remains available where backend evidence supports it.
- Failed quiescence cannot silently create a weaker or unsafe artifact.
- Active exec behavior is explicit and does not hide cancellation inside a
  snapshot request.
- Restore compatibility and identity refresh are fail-closed and auditable.
- Parent and child authority, networking, storage, quota, and cleanup are
  independent after fork.
- Lazy restore can improve latency without redefining correctness.

### Negative

- Snapshot latency includes exec draining, quiesce, flush, exclusion checks,
  integrity work, and metadata publication.
- Long-running execs can prevent snapshot or fork until they finish or are
  explicitly canceled.
- The portable baseline does not preserve process memory.
- Memory restore and memory fork require narrow backend, CPU, device, image,
  and protocol compatibility.
- Application-consistent capture may require workload-specific quiesce hooks.
- Rebuilding credentials and networking can make resumed applications
  reconnect to external services.

## Rejected Alternatives

### Memory and Filesystem as the Default

Every session snapshot and fork would capture process memory and runtime
device state by default.

**Rejected**: It would make the baseline contract dependent on backend,
runtime version, CPU, device, image, and guest behavior before filesystem
restore and COW fork are available. Memory remains an explicit,
capability-gated profile.

### Forced Checkpoint Fallback

PicoCompute would attempt cooperative quiescence, then force a crash-consistent
capture when the guest is busy or unresponsive.

**Rejected**: Silent fallback changes data-safety and application semantics,
can capture live credentials or inconsistent workspace state, and makes a
successful response ambiguous. Capture fails closed instead.

### Automatic Exec Cancellation

Snapshot and fork would cancel active execs automatically to meet the capture
deadline.

**Rejected**: A storage operation should not implicitly terminate workload
operations. Cancellation remains explicit, independently authorized, and
auditable.

### Backend-Native Modes in the Public API

Callers would request Firecracker, QEMU, or gVisor snapshot variants directly.

**Rejected**: Backend names and artifact formats would become permanent API
contracts, prevent policy-controlled backend evolution, and produce different
identity and safety semantics for the same user intent.

### Restore Captured Network and Credentials

Resume would preserve live connections, leases, credentials, and protocol
sessions to make restoration transparent.

**Rejected**: Those artifacts are host-local or time-bound authority. Reuse
would bypass current policy, revocation, identity, and network placement
checks.

### Cross-Backend Restore

PicoCompute would translate or reinterpret snapshot artifacts across compatible
backend families.

**Rejected**: Runtime memory, device state, CPU assumptions, and checkpoint
formats are backend-specific. A cold boot from durable workspace state is a
separate operation, not cross-backend resume.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Define durable snapshot metadata, compatibility fields, lifecycle state, lineage, and migration rules |
| | Implement operation fencing, cooperative quiesce, flush, exclusion receipts, and failed-quiesce recovery |
| | Implement fresh authentication, identity rebinding, and mandatory `ResumeNotify` |
| | Implement persisted suspend and resume orchestration |
| | Implement base and filesystem restore with compatibility validation |
| | Prototype workspace copy-on-write branching |
| | Implement production filesystem COW fork, lineage, quota, and cleanup |
| | Implement capability-gated memory snapshot restore |
| | Implement authenticated encryption, integrity, tenant binding, and restore rejection |
| | Evaluate lazy memory loading without changing `memory` profile semantics |
| | Implement lineage-aware snapshot cache tiering, retention, and garbage collection |
| | Implement the network teardown and rebuild sequence required by this ADR |

## References

- [Firecracker snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [Firecracker snapshot versioning](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/versioning.md)
- [gVisor checkpoint and restore](https://gvisor.dev/docs/user_guide/checkpoint_restore)
- [QEMU migration compatibility](https://www.qemu.org/docs/master/devel/migration/compatibility.html)
- [Linux `fsfreeze`](https://man7.org/linux/man-pages/man8/fsfreeze.8.html)

## Required Review

The ADR remains `Proposed` until all roles approve the
consistency contract, exclusion rules, compatibility gates, and fork
semantics:

- Runtime owner
- Security owner
- Networking owner
- Storage owner
