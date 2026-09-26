# ADR-0001: Control-Plane Ownership and Lifecycle State Model

**Status**: Proposed
**Date**: 2026-06-09
**Milestone**: M0 - Control Plane ADRs and API Contract
## Context

PicoCompute currently runs a single-process, single-host control plane where
lifecycle state is held in process memory with no persistence, no
multi-node coordination, and a flat `SandboxState` enum whose variants
are set directly by runtime adapters without transition guards.

The platform is evolving toward a regional, multi-cell architecture where:

- A **regional API** accepts sandbox lifecycle requests.
- A **regional metadata store** persists sandbox records, policies, and
  audit events.
- One or more **cells** per region each contain multiple hosts and a cell
  controller.
- **Host agents** execute runtime operations and enforce bounded
  decisions.
- **Network and compute-plane** components enforce access at the edge.

Before implementation work spreads across these components, we need one
authoritative model for sandbox lifecycle ownership, state transitions,
reconciliation, and zero-trust access control.

### Zero-Trust Alignment

*Zero Trust Networks* separates the control plane
from the data plane: the control plane authenticates and authorizes
access, then dynamically configures the data plane for a specific client
and resource path. PicoCompute follows the same architectural separation
but uses the term **compute plane** in place of *data plane* to reflect
that PicoCompute's downstream components do more than forward data -- they
execute sandbox workloads, manage VM lifecycles, enforce access leases,
and orchestrate host-local resources. The compute plane encompasses the
cell controller, host agent, runtime adapters, network proxy, and all
components that carry out control-plane decisions on execution hosts.

- **Control plane** (regional API, metadata store, scheduler): makes
  lifecycle and access decisions.
- **Compute plane** (cell controller, host agent, runtime, network): executes
  decisions within bounded scope and enforces authorization at every
  access point.

## Decision

We select **regional metadata owner with cell-level enforcement** for
lifecycle state ownership, combined with a **control-plane-owned access
lease model with compute-plane enforcement** for zero-trust authorization.

### Ownership Model

| Concern | Owner | Scope |
|---|---|---|
| Lifecycle truth | Regional metadata store | Durable, one record per sandbox |
| Lifecycle initiation | Regional API | Accepts and validates lifecycle requests |
| Scheduling decisions | Regional scheduler | Assigns sandboxes to cells |
| Lifecycle execution | Cell controller + host agent | Prepares, starts, stops, suspends, resumes within the assigned cell |
| State observation | Cell controller | Reports observed state back to the regional store |
| Access authorization | Regional policy engine | Issues time-bound, cryptographically signed leases |
| Access enforcement | Host agent, network proxy, SSH tunnel | Validates leases before allowing access |
| Reconciliation | Cell controller | Drives local state toward the regional desired state |

The regional metadata store is the **single source of truth**. No
component below the regional control plane may independently decide the
lifecycle of a sandbox. Cell-level components report observed state but
do not own lifecycle authority.

### Canonical State Machine

The lifecycle state machine has 12 states. Five are transitory
(prefixed with an arrow in diagrams below); seven are durable.

```
                         (reject)
                           xx
  ┌────────┐ accept ┌──────────┐ assign ┌───────────┐
  │ Pending ├──────────►│ Scheduled ├──────────►│ Preparing │
  └────────┘ └──────────┘ └─────┬─────┘
                                                      │
                                                      ▼
                                               ┌───────────┐
                                               │ Booting │
                                               └─────┬─────┘
                                                     │
                                                     ▼
   ┌──────────┐ start ┌──────────┐ ┌──────────┐
   │ Stopped │◄──────────┤ Running │◄─────────┤ Ready │
   └─────┬─────┘ stop └────┬────┬──┘ started └──────────┘
         │ │ │
         │ suspend │ │ resume ┌──────────┐
         │ │ └───────────►│ Resuming │
         │ ▼ └────┬─────┘
         │ ┌───────────┐ │
         │ │ Suspending│◄─────────────────┘
         │ └─────┬─────┘
         │ │
         │ ▼
         │ ┌───────────┐
         │ │ Suspended │
         │ └───────────┘
         │
         ▼
   ┌──────────┐ cleanup ┌───────────┐
   │ Destroyed │◄──────────┤ Destroying │
   └──────────┘ └─────┬─────┘
                                 ▲
   ┌──────────┐ quarantine │
   │ Failed ├─────────────────┘
   └──────────┘ (any non-terminal state can transition to Failed)
```

#### State Definitions

| State | Type | Meaning |
|---|---|---|
| `Pending` | Durable | Request received, not yet accepted by the scheduler |
| `Scheduled` | Durable | Accepted and assigned to a cell |
| `Preparing` | Transitory | Cell controller is allocating resources (workspace, IP, cgroup) |
| `Booting` | Transitory | Host agent is starting the VM |
| `Running` | Durable | VM is operational and accepting exec requests |
| `Suspending` | Transitory | VM is being paused; memory is being saved |
| `Suspended` | Durable | VM is paused; memory and device state are preserved |
| `Resuming` | Transitory | VM is being restored from suspend |
| `Stopped` | Durable | VM has been cleanly shut down; workspace is preserved |
| `Destroying` | Transitory | Resources are being released |
| `Destroyed` | Durable | Terminal state; all resources released; no further transitions |
| `Failed` | Durable | An unrecoverable error occurred; carries an error code and message |

The five transitory states (`Preparing`, `Booting`, `Suspending`,
`Resuming`, `Destroying`) must resolve into a durable state within a
configured timeout or be escalated to `Failed`.

The current `Executing` and `Idle` variants are removed as lifecycle
states. The `Running` state captures the full operational window.
Activity detection becomes an **observed attribute** on the sandbox
record rather than a lifecycle state transition, avoiding state-model
churn on every exec or keepalive call. `Requested` is renamed to
`Pending` for clarity and to avoid confusion with HTTP request
semantics.

#### Transition Table

Each transition names the component authorized to initiate it and the
component that commits the resulting state.

| From | To | Initiated by | Committed by | Precondition |
|---|---|---|---|---|
| `Pending` | `Scheduled` | Regional scheduler | Regional metadata store | Cell has capacity |
| `Pending` | `Failed` | Regional API | Regional metadata store | Quota exhausted or policy denied |
| `Scheduled` | `Preparing` | Cell controller | Cell controller → regional store | Scheduled to this cell |
| `Preparing` | `Booting` | Cell controller | Cell controller → regional store | Resources allocated |
| `Preparing` | `Failed` | Cell controller | Cell controller → regional store | Resource allocation error |
| `Booting` | `Running` | Host agent | Host agent → cell controller → regional store | Guest agent ready |
| `Booting` | `Failed` | Host agent | Host agent → cell controller → regional store | Boot error or timeout |
| `Running` | `Suspending` | Regional API | Regional metadata store (desired state) | Sandbox is in `Running` |
| `Suspending` | `Suspended` | Host agent | Host agent → cell controller → regional store | VM paused successfully |
| `Suspending` | `Failed` | Host agent | Host agent → cell controller → regional store | Suspend error or timeout |
| `Suspended` | `Resuming` | Regional API | Regional metadata store (desired state) | Sandbox is in `Suspended` |
| `Resuming` | `Running` | Host agent | Host agent → cell controller → regional store | VM resumed successfully |
| `Resuming` | `Failed` | Host agent | Host agent → cell controller → regional store | Resume error or timeout |
| `Running` | `Stopped` | Regional API | Host agent → cell controller → regional store | Stop requested |
| `Stopped` | `Running` | Regional API | Regional metadata store (desired state) | Restart requested; cell must re-prepare |
| `Stopped` | `Destroying` | Regional API | Regional metadata store (desired state) | Destroy requested |
| `Suspended` | `Destroying` | Regional API | Regional metadata store (desired state) | Destroy requested; host resumes then destroys |
| `Failed` | `Destroying` | Regional API | Regional metadata store (desired state) | Explicit destroy after failure |
| `Destroying` | `Destroyed` | Host agent | Host agent → cell controller → regional store | All resources released |
| `Destroying` | `Failed` | Host agent | Host agent → cell controller → regional store | Cleanup error; requires operator attention |
| Any | `Destroying` | Regional API (force) | Regional metadata store (desired state) | Administrative force-destroy |
| Any | `Failed` | Any component | Depends on detecting component | Unrecoverable error with error code |

**Fork transition**: Fork is treated as a shorthand for "create a new
sandbox from this one's workspace and configuration." The new sandbox
follows the normal `Pending →... → Running` path. The source sandbox
is not state-changed by the fork operation. Fork durability is
guaranteed by the same idempotency mechanism as Create.

### Idempotency Model

Every lifecycle-initiation request carries an **idempotency key**
(`Idempotency-Key` header). The regional API stores the key with the
result for a configurable retention window (default 24 hours).
Retransmission of the same key returns the stored result without
re-executing the operation.

| Operation | Idempotency guarantee |
|---|---|
| Create | Same key returns the existing `SandboxInfo` even if the sandbox was already created |
| Exec | Same key returns the previous `ExecResponse`; exec is at-most-once per key |
| Suspend | If already `Suspended`, returns success immediately; if `Suspending`, waits for resolution then returns |
| Resume | If already `Running`, returns success immediately; if `Resuming`, waits for resolution then returns |
| Fork | Same as Create semantics for the new sandbox |
| Destroy | If already `Destroyed`, returns success immediately; if `Destroying`, waits for resolution then returns |

Idempotency keys are scoped to the tenant. Two different tenants may use
the same key without collision. Keys must be at most 256 bytes and only
contain ASCII alphanumeric characters plus hyphens and underscores.

### Retry and Conflict Behavior

**Optimistic concurrency**: Every write to the metadata store includes
the expected `version` (monotonic counter) from the last read. A write
that encounters a version mismatch receives a `409 Conflict` with the
current record. The caller must re-read and re-evaluate before retrying.

**Retry policy for internal callers** (scheduler, cell controller, host
agent):

- Exponential backoff with jitter: initial delay 100 ms, multiplier 2.0,
  max delay 30 s, max attempts 5.
- Only retry on `409 Conflict`, `503 Unavailable`, and network errors.
- Do not retry on `400 Bad Request`, `403 Forbidden`, `404 Not Found`,
  or `422 Unprocessable Entity`.

**Transitory-state timeout**: If a sandbox remains in a transitory state
longer than the configured timeout (default 300 s for boot, 120 s for
suspend/resume, 60 s for destroy), the cell controller escalates the
state to `Failed` with reason `transitory_state_timeout`.

### Reconciliation Semantics

The cell controller runs a reconciliation loop that compares the
**desired state** in the regional metadata store with the **observed
state** reported by host agents within the cell.

```
desired state (regional store) observed state (host agent)
         │ │
         └─────── reconcile ──────────────┘
                      │
                      ▼
              cell controller action
```

Reconciliation rules:

| Desired state | Observed state | Action |
|---|---|---|
| `Running` | Missing from cell | Prepare + boot on an available host |
| `Stopped` | `Running` | Send stop command to host agent |
| `Suspended` | `Running` | Send suspend command to host agent |
| `Destroying` | Any non-destroyed | Send destroy command to host agent |
| `Destroyed` | Any | Confirm cleanup; mark as fully destroyed in regional store |
| `Running` | `Failed` | Evaluate error; if recoverable, re-prepare; if not, set desired to `Failed` |
| Any | `Destroyed` | Set observed state to `Destroyed` in regional store |

Reconciliation runs on a configurable interval (default 30 s) per cell.
A cell controller that cannot reach the regional store continues to
manage local sandboxes but cannot initiate new lifecycle transitions
until connectivity is restored.

### Failure State Model

`Failed` carries structured error information:

```rust
struct FailureInfo {
    code: FailureCode, // machine-readable error category
    message: String, // human-readable description
    component: ComponentId, // which component detected the failure
    retryable: bool, // whether the operation can be retried
    occurred_at: Timestamp, // when the failure was detected
}
```

Failure codes:

| Code | Retryable | Meaning |
|---|---|---|
| `boot_timeout` | Yes | Guest agent did not respond within boot timeout |
| `resource_exhausted` | Yes | Insufficient CPU, memory, or disk on host |
| `network_unreachable` | Yes | Guest network stack failed to initialize |
| `suspend_failed` | Yes | VM suspend operation returned an error |
| `resume_failed` | Yes | VM resume operation returned an error |
| `workspace_corrupted` | No | Workspace filesystem is corrupted |
| `image_pull_failed` | Yes | Root filesystem image could not be fetched |
| `quota_exceeded` | No | Tenant quota exceeded at scheduling time |
| `policy_denied` | No | Policy engine rejected the request |
| `internal_error` | No | Unexpected internal error; requires investigation |

Only `Destroying` or `Destroyed` sandboxes are eligible for automatic
garbage collection. `Failed` sandboxes require explicit operator action
(destroy or retry) to prevent resource leaks from unrecoverable
failures.

### Audit Event Ordering

Every lifecycle state transition produces an audit event written to the
regional event log. Events carry a **hybrid logical clock (HLC)**
timestamp that provides causal ordering without requiring wall-clock
synchronization across cells.

```
sandbox_id, from_state, to_state, initiated_by, committed_by, hlc_timestamp, idempotency_key, failure_info?
```

Events are written atomically with the state transition in the metadata
store. The event log is append-only, immutable, and serves as the
durable record for all lifecycle actions.

### Access Authorization and Revocation Model

The control plane issues time-bound, cryptographically signed **access
leases** that authorize a specific principal to interact with a specific
sandbox. The compute plane enforces leases at every access point.

#### Lease Issuance

1. Client authenticates to the regional API (bearer token, mTLS, or
   workload identity).
2. API verifies the principal's identity and checks the policy engine
   for authorization to the requested sandbox and action.
3. If authorized, the API issues a signed lease containing:
   - `principal_id`: authenticated identity
   - `sandbox_id`: target sandbox
   - `action`: `exec`, `file_read`, `file_write`, `ssh`, `task_start`
   - `issued_at`: issuance timestamp
   - `expires_at`: expiration timestamp (default 5 minutes)
   - `signature`: Ed25519 signature over the above fields

4. The client includes the lease in subsequent compute-plane requests.

#### Lease Enforcement

Every compute-plane access point (host agent exec, file handler, SSH
proxy, task spawner, network proxy) validates the lease before allowing
the operation:

1. Verify the Ed25519 signature against the control plane's public key.
2. Verify `expires_at > now` using a trusted time source.
3. Verify `sandbox_id` matches the target sandbox.
4. Verify `action` matches the requested operation.
5. Verify the lease has not been revoked (check revocation list).

#### Lease Revocation

When authorization context changes (tenant suspension, policy update,
security incident), the control plane actively revokes active leases:

1. The policy engine publishes a revocation event containing the
   affected `(principal_id, sandbox_id, action)` tuples.
2. The revocation propagates to all cell controllers within the
   revocation latency target (default 10 seconds).
3. Cell controllers push the revocation list update to host agents in
   their cell.
4. Host agents reject any request carrying a revoked lease with
   `403 Forbidden` and reason `lease_revoked`.
5. Active connections (e.g., SSH tunnels, SSE streams) are terminated
   when their lease is revoked.

For time-critical revocations, the host agent can query the regional
lease status endpoint synchronously before allowing particularly
sensitive operations.

#### Lease Renewal

Clients with long-running operations (SSH sessions, task streams) must
renew their lease before expiry. The renewal request follows the same
authorization path as initial issuance: if the principal's authorization
has been revoked, renewal fails and the client must cease operations.

### Control-Plane versus Compute-Plane Responsibilities

| Function | Control Plane | Compute Plane |
|---|---|---|
| Accept sandbox lifecycle requests | Yes | No |
| Decide which cell hosts a sandbox | Yes | No |
| Persist lifecycle state | Yes | Reports observed state |
| Authenticate clients | Yes | Validates issued credentials |
| Authorize access (policy decisions) | Yes | No |
| Issue access leases | Yes | No |
| Revoke access leases | Yes | Propagates revocations |
| Enforce access leases | No | Yes (at every access point) |
| Allocate host resources (CPU, memory, disk) | No | Yes (cell controller on hosts) |
| Start/stop/suspend/resume VMs | No | Yes (host agent via runtime adapter) |
| Execute commands in sandbox | No | Yes (host agent via guest agent) |
| Manage workspace files | No | Yes (host agent) |
| Expose sandbox ports | No | Yes (host agent port proxy) |
| Report observed state | No | Yes |
| Drive reconciliation | No | Yes (cell controller loop) |
| Emit audit events | Yes (durable write) | Reports transition events |

### Write Ordering for State and Audit Events

State transitions and audit events are written in a single atomic
operation to the regional metadata store:

1. Validate the transition against the current state and version.
2. Write the new state record with incremented version.
3. Write the audit event with HLC timestamp.
4. Publish the state-change notification to cell controllers.

If any step fails, the entire operation is rolled back. This guarantees
that no state transition exists without a corresponding audit event, and
vice versa.

### Component Authority Matrix

Which component is permitted to transition a sandbox into each state:

| State | Regional API | Regional Scheduler | Cell Controller | Host Agent |
|---|---|---|---|---|
| `Pending` | Yes (create) | No | No | No |
| `Scheduled` | No | Yes | No | No |
| `Preparing` | No | No | Yes | No |
| `Booting` | No | No | Yes | Yes (commits) |
| `Running` | No | No | No | Yes |
| `Suspending` | No | No | No | Yes |
| `Suspended` | No | No | No | Yes |
| `Resuming` | No | No | No | Yes |
| `Stopped` | No | No | No | Yes |
| `Destroying` | Yes (initiate) | No | Yes (force) | Yes (commits) |
| `Destroyed` | No | No | No | Yes |
| `Failed` | Yes (quota/policy) | Yes (no capacity) | Yes | Yes |

## Consequences

### Positive

- **Single source of truth**: The regional metadata store eliminates
  ambiguity about which component owns lifecycle state. Every component
  queries one authoritative source.
- **Clear reconciliation contract**: Cell controllers reconcile against
  a well-defined desired state, minimizing state drift between the
  control plane and execution hosts.
- **Zero-trust enforcement**: Leases are validated at every access point
  without requiring the control plane to be on the request path. Policy
  changes propagate through revocation, not through synchronous checks.
- **Durable audit trail**: Every state transition is written atomically
  with an audit event, providing an append-only record for compliance
  and debugging.
- **Composable with existing code**: The `SandboxState` enum already
  exists and is used across all crates. The refined state machine
  reduces the number of states (from 15 to 12) and removes the
  `Executing`/`Idle` churn, simplifying adapter implementations.

### Negative

- **Regional store is a hard dependency**: If the regional metadata
  store is unavailable, no new lifecycle transitions can be initiated.
  Existing sandboxes continue to operate on their current leases.
- **Reconciliation adds latency**: State changes initiated through the
  control plane take one reconciliation interval (default 30 s) to
  propagate to host agents if push notifications fail. This is mitigated
  by the notification channel for the common happy path.
- **Lease model adds per-request overhead**: Every compute-plane request
  carries a lease that must be validated. Signature verification is
  fast (Ed25519) but adds a non-zero cost.
- **Migration from current flat model**: The state enum changes require
  updating all runtime adapters and the `RuntimeAdapter` trait to
  understand the new state set.

## Rejected Alternatives

### Cell-Owned Lifecycle State with Regional Projection

Each cell's metadata store would own lifecycle truth for its sandboxes,
with the regional store maintaining a read-only projection.

**Rejection rationale**: Creates ambiguity about authority when a cell
is unreachable. The regional API cannot authoritatively answer "what is
the state of sandbox X?" without querying the owning cell. Multi-cell
failover requires complex state transfer. Does not align with the
zero-trust model where the control plane makes decisions and the data
plane executes them.

### Event-Sourced Lifecycle Log with Materialized State

All lifecycle events are written to an append-only log. Current state is
materialized by replaying the event stream.

**Rejection rationale**: Event sourcing solves write-ordering but adds
significant complexity for a problem that does not require it. Sandbox
lifecycle state has a small, well-defined set of transitions that are
adequately modeled as a state machine with atomic writes. Event replay
on restart would add latency to recovery, and the benefit of temporal
queries (e.g., "what was the state at time T?") does not justify the
operational burden for PicoCompute's lifecycle domain.

### Control-Plane-Owned Access Lease Model WITHOUT Cell Ownership

The access lease model is not rejected - it is adopted as complementary.
This option was presented as an alternative to the lifecycle ownership
decision, but access authorization and lifecycle ownership are
orthogonal concerns. The ADR selects **both** regional metadata
ownership and control-plane lease management because they address
different layers of the zero-trust architecture.

### Continuing with the Current Flat State Model

Keeping the existing 15-variant `SandboxState` enum without transition
guards and using direct mutation by runtime adapters.

**Rejection rationale**: The current model has no notion of authority,
no idempotency guarantees, no reconciliation, and no durable state. It
works for a single-process architecture but cannot extend to multi-cell
deployments. The `Executing` and `Idle` variants cause unnecessary state
churn that complicates scheduling and reconciliation. The lack of
transition guards means any adapter can set any state at any time, which
is incompatible with a distributed control plane.

## Follow-Up Implementation Issues

This ADR unblocks the following work items. Each must be implemented
consistent with the decisions above.

| Issue | Title | Relationship to this ADR |
|---|---|---|
| | Define public sandbox lifecycle API | API routes and request/response types must reflect the canonical state machine defined here |
| | Implement sandbox metadata state machine | Implements the state transition table, optimistic concurrency, and transitory-state timeouts |
| | Define secure time and identity binding model | HLC timestamps and principal identity used in audit events and lease issuance |
| | Build tenant quota and policy engine | Policy engine authorizes lease issuance; quota checks gate the `Pending → Scheduled` transition |
| | Implement zero-trust access lease manager | Lease issuance, validation, renewal, and revocation as defined in the access authorization model |
| | Build regional scheduler | Implements `Pending → Scheduled` transition with cell selection |
| | Build cell scheduler | Reconciliation loop and cell-to-regional state reporting |
| | Emit lifecycle audit events | Atomic audit event writes with HLC timestamps as defined in audit event ordering |
