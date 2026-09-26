# ADR-0002: Host Runtime Lifecycle Orchestration

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Host Runtime ADRs and Boundaries
**Depends on**: [ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
**Refined by**: [ADR-0011](0011-sandboxd-process-boundary-and-host-ingress.md)

> **Status note (2026-08)**: The concrete host-agent/sandboxd OS process
> boundary, sole `RuntimeBackend` and guest-session ownership, gRPC-over-UDS
> transport, restart semantics, and the intentional ingress-on-host residual
> are defined by
> [ADR-0011](0011-sandboxd-process-boundary-and-host-ingress.md). Where this
> ADR describes the unprivileged-helper end state, ADR-0011 section 7 records
> the interim privileged-sandboxd posture for the process-split milestone.

## Context

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md) makes the
regional metadata store authoritative for sandbox lifecycle state. Cell and
host components execute bounded decisions, report observed state, and
reconcile local resources toward control-plane intent.

The host runtime still needs one ownership model for:

- lifecycle coordination on an assigned host
- supervision of runtime processes and open streams
- backend-specific operations
- image, network, snapshot, and metrics helpers
- restart-safe local state
- partial operation recovery and orphan handling
- privileged host operations
- lifecycle and host health reporting

The current implementation combines these concerns in an in-memory
`HostAgent`. It calls runtime adapters directly, loses sandbox and operation
state on restart, and invokes some host networking operations through shell
commands and `sudo`. That shape is useful for a single-process prototype but
cannot provide restart-safe cleanup, strict privilege boundaries, or a stable
contract for independently implemented host components.

This ADR defines the target host-runtime architecture. It does not make local
state authoritative over the regional lifecycle record and does not prescribe
the external cell-to-host transport.

## Decision

PicoCompute selects **`host-agent` as the host lifecycle coordinator with
`sandboxd` as the durable local supervisor**.

The command path is:

```text
cell controller
    -> host-agent
        -> sandboxd
            -> runtime adapter
            -> network-agent
            -> image-agent
            -> snapshot-agent
            -> privileged helper

sandboxd -> metrics-agent
host-agent -> cell controller
```

`host-agent` owns host-level command admission and orchestration. `sandboxd`
owns per-sandbox serialization, runtime and stream supervision, the local
observed-state ledger, and restart reconciliation. Runtime adapters and helper
agents perform bounded operations and return typed receipts. They do not own
lifecycle policy or control-plane state.

### Authority Boundaries

| Concern | Authority |
|---|---|
| Desired lifecycle state | Regional metadata store, as defined by ADR-0001 |
| Cell and host assignment | Cell controller |
| Host command admission | `host-agent` |
| Per-sandbox operation serialization | `sandboxd` |
| Local observed state and resource ledger | `sandboxd` |
| Backend-specific mechanics | Selected runtime adapter |
| Network resource mechanics | `network-agent` |
| Image materialization mechanics | `image-agent` |
| Snapshot storage and restore mechanics | `snapshot-agent` |
| Telemetry collection and export | `metrics-agent` |
| Aggregate host lifecycle and health reporting | `host-agent` |

No host component may reinterpret a desired lifecycle state, select a new
host, weaken a policy decision, or destroy a healthy sandbox without a valid
control-plane command.

### Component Responsibility Matrix

| Component | Owns | Must not own |
|---|---|---|
| `host-agent` | Cell RPC surface, host identity, command admission, fencing and policy-epoch checks, host capacity, lifecycle workflow coordination, aggregate health, observed-state reporting | Runtime process handles, durable per-sandbox resource state, backend internals, regional lifecycle truth |
| `sandboxd` | Per-sandbox command queue, operation cancellation and deadlines, process and VM supervision, stream handles, local SQLite ledger, resource receipts, restart and orphan reconciliation, cleanup progress | Scheduling, policy decisions, backend selection policy, regional lifecycle truth |
| Runtime adapter | Backend capability discovery, prepare, boot, transport attachment, suspend, resume, destroy, stats, health, and diagnostic capture for one backend | Cross-component lifecycle workflow, durable orchestration state, direct control-plane reporting |
| `network-agent` | TAP/veth, namespaces, routes, firewall state, network identity attachment, and idempotent network cleanup | Sandbox lifecycle decisions, access policy decisions, process supervision |
| `image-agent` | Image fetch, verification, cache materialization, overlay preparation, and image resource cleanup | Runtime boot decisions, lifecycle reporting, snapshot lineage |
| `snapshot-agent` | Quiesced snapshot capture, restore, snapshot compatibility evidence, local snapshot resources, and snapshot cleanup | Deciding when suspend, resume, or fork is allowed |
| `metrics-agent` | Scraping local metrics, exporting logs and traces, host telemetry transport, and telemetry pipeline health | Lifecycle state transitions, cleanup decisions, command admission |

All helper responses use typed outcomes and include the deterministic resource
identity needed to retry or inspect the operation.

### Lifecycle Operation Ownership

| Operation | `host-agent` coordination | `sandboxd` supervision | Bounded executor | Reported result |
|---|---|---|---|---|
| Boot | Validate assignment, fencing token, policy epoch, limits, and requested backend; sequence preparation | Serialize the operation, persist steps, supervise runtime, enforce deadline, roll back partial work | `image-agent`, `network-agent`, runtime adapter, privileged helpers | `host-agent` reports `Booting`, then `Running` only after guest readiness |
| Exec | Validate access lease, policy, lifecycle precondition, and resource limits | Own command handle, streams, backpressure, timeout, cancellation, signals, and process-tree cleanup | Runtime adapter and guest transport | `host-agent` reports operation outcome; sandbox remains `Running` |
| Suspend | Validate desired state and reject stale commands | Block new execs, drain or cancel active work, persist quiesce and suspend progress | Guest transport, `snapshot-agent`, runtime adapter | `host-agent` reports `Suspending`, then `Suspended` |
| Resume | Validate snapshot, backend, image, assignment, and current policy epoch | Serialize restore, restore non-persistent attachments, supervise post-resume readiness | `snapshot-agent`, `network-agent`, runtime adapter, guest transport | `host-agent` reports `Resuming`, then `Running` after health validation |
| Fork | Validate source, target assignment, policy, and idempotency | Quiesce source when required and persist child resource receipts without changing source lifecycle state | `snapshot-agent`, `image-agent`, runtime adapter | `host-agent` reports the child through the normal create-to-`Running` path |
| Destroy | Validate fenced desired state and make retries idempotent | Cancel work, supervise ordered cleanup, persist each released resource, retain failures for retry | Runtime adapter and all resource helpers | `host-agent` reports `Destroying`, then `Destroyed` only after cleanup completes |
| Cleanup | Coordinate control-plane intent and host health response | Own rollback, restart continuation, orphan classification, quarantine, and garbage-collection ledger | Resource owner for each receipt | `host-agent` reports cleanup outcome and health degradation |

Only `host-agent` communicates aggregate lifecycle observations to the cell
controller. `sandboxd`, adapters, and helper agents expose local status to
`host-agent`; they do not report lifecycle state independently.

### Internal Command Envelope

Every state-changing command from `host-agent` to `sandboxd` includes:

```rust
struct HostRuntimeCommand<T> {
    sandbox_id: SandboxId,
    operation_id: OperationId,
    assignment_fencing_token: FencingToken,
    policy_epoch: u64,
    deadline: Timestamp,
    payload: T,
}
```

The envelope has these semantics:

- `sandbox_id` selects the per-sandbox serialized operation queue.
- `operation_id` is the idempotency identity. Replays return the persisted
  terminal outcome or continue the persisted incomplete operation.
- `assignment_fencing_token` must not be older than the greatest token stored
  for the sandbox. Stale commands are rejected before side effects.
- `policy_epoch` is checked by `host-agent` before admission and revalidated
  for policy-sensitive resume, fork, exec, and network attachment work.
- `deadline` is absolute. `sandboxd` persists it and applies it across retries
  and child operations instead of resetting timeouts after restart.
- The terminal outcome is typed as succeeded, failed, canceled, timed out, or
  requires review. It includes reason codes and resource receipts, not secrets.

Read-only inspection commands may omit a policy epoch when they cannot cause a
side effect. Every helper request derives an idempotency identity from the
operation ID, step name, and deterministic resource name.

### Local State Persistence

`sandboxd` stores its local observed-state and cleanup ledger at:

```text
/var/lib/pico/sandboxd/state.db
```

The store is SQLite configured with:

- WAL journal mode
- `synchronous=FULL`
- foreign key enforcement
- versioned, forward-only schema migrations
- one writer owned by the `sandboxd` process
- bounded read transactions for inspection and health reporting

The ledger is not a second lifecycle authority. It records what the current
host has observed or created so that supervision and cleanup can survive
process and host restarts.

The minimum logical records are:

| Record | Required content |
|---|---|
| Sandbox | Sandbox ID, assignment fencing token, policy epoch, backend identity, observed state, host boot ID, timestamps |
| Operation | Operation ID, kind, deadline, current step, terminal outcome, retry count, cancellation state |
| Resource receipt | Resource class, deterministic name, owner component, external identity, creation state, cleanup state |
| Process identity | PID or pidfd metadata, process start time, host boot ID, executable identity, cgroup identity |
| Reconciliation finding | Evidence, classification, action, review reason, first and last observed timestamps |

The ledger must never contain:

- access leases or signing material
- credentials, private keys, or secret mount contents
- command stdin, stdout, or stderr
- user file contents
- snapshot payloads
- bearer tokens or control-plane credentials

### Durable Operation Ordering

Lifecycle steps follow this ordering:

1. Validate the command and fencing token.
2. Commit the operation intent and planned deterministic resource identity.
3. Invoke one idempotent adapter or helper operation.
4. Commit the returned resource receipt and observed outcome.
5. Advance to the next step or persist a terminal result.
6. Let `host-agent` report the resulting observation to the cell controller.

Persisting intent before each side effect ensures a restart knows what may
have been attempted. A crash can still occur after a helper creates a resource
but before `sandboxd` stores the receipt. Deterministic names and idempotent
helper inspection allow reconciliation to discover and adopt or clean that
resource without guessing.

Cleanup uses the same model. Each resource is marked cleanup-pending before
the delete call and cleanup-complete only after the owning adapter or helper
proves absence.

### Restart and Orphan Reconciliation

`sandboxd` runs reconciliation before accepting new mutating operations after
startup. `host-agent` reports the host as degraded or draining until this pass
has classified all incomplete operations and discovered resources.

Process identity is reconstructed from the tuple:

```text
PID + process start time + host boot ID
```

PID alone is never sufficient because it can be reused. pidfds are used for
live supervision when the kernel supports them, but persisted recovery still
uses stable identity evidence because pidfds do not survive process restart.

Reconciliation compares the ledger with:

- runtime backend inventory and process identity
- cgroup hierarchy and process trees
- mounts, overlays, and workspace directories
- TAP/veth devices, namespaces, routes, and firewall state
- vsock and Unix domain sockets
- image cache and temporary materialization
- snapshot staging and restore resources

Findings are classified as:

| Classification | Required action |
|---|---|
| Proven expected | Reattach supervision and continue the persisted operation |
| Proven incomplete | Resume the recorded rollback or cleanup operation |
| Proven stale and not live | Clean through the owning adapter or helper |
| Ambiguous ownership | Quarantine, record `requires_review`, degrade and drain the host |
| Live but absent from ledger | Quarantine, do not signal or destroy, degrade and drain the host |

An ambiguous or live orphan is destroyed only after `host-agent` receives a
new control-plane directive with a fencing token newer than any locally known
token. Autonomous destructive garbage collection is prohibited.

#### Restart Scenarios

| Scenario | Behavior |
|---|---|
| `host-agent` restart | `sandboxd` continues supervision. The new `host-agent` queries local state, revalidates assignment fencing, and resumes reporting without restarting healthy sandboxes. |
| `sandboxd` restart | Reopen the WAL database, reconcile process and resource identities, rebuild stream and cancellation state where possible, and classify unrecoverable streams explicitly. |
| Host reboot | Detect the new host boot ID, treat old process identities as dead, inspect durable resources, resume safe cleanup, and await fresh fenced intent before boot or destructive ambiguous cleanup. |
| Partial boot | Continue a proven idempotent step or run rollback in reverse resource order from persisted intents and receipts. |
| Partial destroy | Resume cleanup from the first resource not proven absent. Do not report `Destroyed` while any required receipt remains. |
| Stale fencing token | Reject before side effects and return the greatest locally known token. |
| Ambiguous orphan | Quarantine, emit a review finding, degrade and drain the host, and wait for fenced operator or control-plane direction. |
| Control-plane outage | Preserve and supervise healthy workloads, enforce existing local deadlines and revocations available locally, reject new lifecycle mutations, and perform only previously authorized rollback or cleanup. |

### Privilege Boundaries

`host-agent` and `sandboxd` run as separate unprivileged service identities.
They do not execute `sudo`, invoke shell pipelines for host mutation, or hold
broad Linux capabilities.

Privileged resource operations are exposed through narrow typed helper RPCs:

- helpers listen on permission-controlled Unix domain sockets
- helpers authenticate callers with Unix peer credentials
- request schemas enumerate allowed operations and validate every identifier
- each helper owns one resource class where practical
- helper operations are deterministic and idempotent
- every request includes operation and sandbox correlation identities
- helpers return typed receipts suitable for ledger persistence

Capability examples:

| Helper responsibility | Maximum expected privilege |
|---|---|
| Network device and namespace setup | `CAP_NET_ADMIN` in the required namespace scope |
| Cgroup placement and limits | Delegated cgroup subtree, without general root filesystem access |
| Mount and overlay setup | `CAP_SYS_ADMIN` isolated to a dedicated mount helper and namespace |
| Runtime launch | Backend-specific device access and capabilities only |

Backend processes run under dedicated identities with cgroup limits,
namespaces, seccomp profiles, no-new-privileges, and only the device access
required by the selected backend. Helper compromise must not grant access to
control-plane credentials or unrelated tenant workspaces.

### Host Health Aggregation

`host-agent` is the sole host health reporter to the cell controller. It
combines:

- `sandboxd` reconciliation and supervision health
- adapter readiness and backend capacity
- helper-agent health
- cleanup backlog and orphan classifications
- resource pressure and telemetry pipeline health

The reported states are:

| State | Meaning |
|---|---|
| `ready` | New assignments may be admitted and all required components are healthy |
| `degraded` | Existing workloads can continue, but one or more capabilities are impaired |
| `draining` | No new assignments; existing workloads are being preserved or removed safely |
| `unsafe` | Host isolation or ownership cannot be proven; scheduler placement and mutating lifecycle work are blocked |

`metrics-agent` transports evidence but does not choose the health state.

## Consequences

### Positive

- Host lifecycle policy has one coordinator while process and resource
  supervision survive coordinator restarts.
- A single-writer ledger provides atomic operation and receipt updates without
  creating a second control-plane database.
- Runtime backends remain replaceable because adapters own mechanics, not
  orchestration.
- Partial work and cleanup are restart-safe and auditable.
- Privileged operations become narrow, typed, and independently hardenable.
- Ambiguous ownership fails closed by draining the host instead of deleting
  resources speculatively.

### Negative

- The host runtime gains an additional long-running process and local database.
- SQLite migrations and corruption recovery become operational concerns.
- Typed helper RPCs require more implementation work than direct shell
  commands.
- Cross-process calls add latency and require versioned internal protocols.
- Some stream state cannot be reconstructed after `sandboxd` restart and must
  fail with an explicit outcome.

## Rejected Alternatives

### `sandboxd` as Lifecycle Policy Owner

In this model, `host-agent` would be an RPC facade while `sandboxd` interpreted
control-plane intent and coordinated all lifecycle workflows.

**Rejected**: It combines durable supervision with scheduling and policy
authority, makes the host RPC boundary thin but semantically unstable, and
conflicts with ADR-0001's control-plane ownership. `sandboxd` must be able to
continue supervision without independently deciding desired lifecycle state.

### Per-Backend Lifecycle Ownership

Each runtime adapter would own its complete prepare, boot, exec, suspend,
resume, fork, destroy, and cleanup workflow.

**Rejected**: Image, network, snapshot, policy, reporting, and cleanup ordering
would diverge by backend. Shared lifecycle correctness would become difficult
to test, and adapters would accumulate control-plane semantics.

### Current In-Memory Host Monolith

`HostAgent` would continue to store sandbox entries and task handles in memory
and call runtime and host operations directly.

**Rejected**: It cannot recover after restart, cannot prove cleanup completion,
has no durable idempotency outcomes, and requires broad process privileges.

### Atomic Per-Sandbox Manifests

Each sandbox would persist its local state in fsynced JSON or binary manifest
files.

**Rejected**: Per-sandbox files simplify inspection but make atomic updates
across operation, resource, and cleanup records difficult. Fleet-wide orphan
queries, migrations, and transactional idempotency are better served by a
single local SQLite database.

### Append-Only Local Journal

All host operations would be reconstructed from an append-only event stream.

**Rejected**: Replay, indexing, snapshots, and compaction add complexity
without improving the host's authority model. The requirement is a durable
observed-state and cleanup ledger, not local event sourcing.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Implement the host RPC surface, command admission, capacity, and health aggregation |
| | Define bounded runtime adapter operations, capabilities, typed outcomes, and conformance tests |
| | Implement `sandboxd`, per-sandbox serialization, the SQLite ledger, and restart recovery |
| | Implement the persisted boot workflow and partial boot rollback |
| | Implement supervised exec streams, cancellation, timeout, and process cleanup |
| | Implement persisted suspend and resume orchestration |
| | Implement cleanup continuation, orphan classification, quarantine, and host drain behavior |

## Required Review

The ADR remains `Proposed` until each role signs off:

- Runtime owner
- Security owner
- Networking owner
- Observability owner
