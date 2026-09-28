# PicoCompute Architecture

PicoCompute is a cloud compute layer for secure, stateful, observable agent sandboxes.

It is designed for AI agent platforms, developer automation systems, and tool-running workloads. These workloads need isolated compute, controlled network access, scoped credentials, fast startup, state preservation, forking, and reliable cleanup.

This document describes PicoCompute as a system, covering its functions, boundaries, operating behavior, and the architectural decisions shaping the implementation.

---

## 1. Architectural Framing

PicoCompute is a complex system, not a single service.

The core architectural question is:

> How do we safely create, run, observe, preserve, fork, and destroy large numbers of agent sandboxes across a distributed compute fleet?

PicoCompute maps these functions to concrete forms:

| Function | Form |
|---|---|
| Accept sandbox lifecycle requests | Public Platform API |
| Authorize and constrain workloads | Tenant Policy Engine + Access Lease Manager |
| Place sandboxes across infrastructure | Regional Scheduler + Cell Scheduler |
| Execute sandbox lifecycle locally | `host-agent` + `sandboxd` |
| Isolate workloads | Firecracker, gVisor, QEMU, Cloud Hypervisor, Kata |
| Communicate with the guest | Versioned Host/Guest Protocol |
| Provide network access safely | `network-agent` + DNS proxy + NAT/egress gateway |
| Build trusted runtime images | Guest Image Pipeline |
| Preserve and branch state | `snapshot-agent` + metadata + COW workspace |
| Observe and operate the platform | Metrics, logs, traces, audit events, dashboards, runbooks |
| Validate production readiness | Load harness, SLOs, security assurance, rollout checklist |

The architecture is defined by a set of decisions:

- who owns lifecycle state
- what isolation backend is default
- how host and guest communicate
- how policy becomes data-plane enforcement
- how credentials are delivered and excluded from snapshots
- how snapshot, resume, and fork preserve correctness
- how readiness evidence gates rollout

---

## 2. System Context

```text
+-------------------------+
| Client/Agent Platform |
+-----------+-------------+
            |
            | Sandbox lifecycle API
            v
+-------------------------+
| Public Platform API |
+-----------+-------------+
            |
            | admitted lifecycle operation
            v
+-----------------------------------------------------------+
| Regional Control Plane |
| |
| - API Gateway |
| - AuthN/AuthZ |
| - Tenant Policy Engine |
| - Access Lease Manager |
| - Runtime Orchestrator |
| - Regional Scheduler |
| - Image Resolver |
| - Snapshot Manager |
| - Network Policy Controller |
| - Audit/Event Bus |
+----------------------+------------------------------------+
                       |
                       | scheduled assignment
                       v
+-----------------------------------------------------------+
| Cell Control Plane |
| |
| - Placement Manager |
| - Host Inventory |
| - Capacity Manager |
| - Warm Pool Manager |
| - Snapshot Cache Index |
| - Failure Detector |
+----------------------+------------------------------------+
                       |
                       | host assignment
                       v
+-----------------------------------------------------------+
| Compute Host |
| |
| - host-agent |
| - sandboxd |
| - runtime adapters |
| - network-agent |
| - image-agent |
| - snapshot-agent |
| - metrics-agent |
+----------------------+------------------------------------+
                       |
                       | backend-specific execution
                       v
+-----------------------------------------------------------+
| Sandbox Backends |
| |
| - Firecracker |
| - gVisor |
| - QEMU |
| - Cloud Hypervisor |
| - Kata Containers |
+-----------------------------------------------------------+
```

### External actors

| Actor | Role |
|---|---|
| Agent platform | Creates sandboxes, runs tools, streams output, requests network exposure, suspends/resumes/forks work. |
| Developer/operator | Manages images, policies, dashboards, runbooks, and rollout gates. |
| Tenant admin | Defines tenant policy, quotas, workload classes, and allowed capabilities. |
| SRE/security reviewer | Reviews SLOs, audit events, readiness evidence, and accepted risks. |

### External systems

| System | Purpose |
|---|---|
| Artifact registry | Stores rootfs, kernel, init, guest-agent, image manifests, SBOMs, and signatures. |
| Snapshot storage | Stores encrypted snapshot blobs and lineage metadata. |
| Secrets broker | Issues scoped, short-lived credentials. |
| Observability backend | Stores metrics, logs, traces, dashboards, and alerts. |
| Audit/event store | Stores durable lifecycle, policy, lease, and enforcement events. |
| Network egress gateway | Enforces outbound connectivity and attribution. |
| DNS policy resolver | Enforces domain resolution policy. |

---

## 3. Architectural Principles

### 3.1 Lifecycle before backend breadth

PicoCompute builds one production-quality lifecycle path before expanding backend support.

The first production path should prove:

1. create
2. prepare
3. boot
4. handshake
5. ready
6. exec
7. suspend
8. resume
9. fork
10. destroy
11. cleanup
12. audit
13. observe

Backend expansion is only safe after the lifecycle contract is stable.

### 3.2 Policy decisions must become enforcement artifacts

A control-plane policy decision is not enough; it must be enforceable in the data plane.

| Decision | Enforcement artifact |
|---|---|
| Egress allowed | egress policy rule + audit event |
| Port exposure allowed | time-bounded access lease |
| Credential access allowed | scoped secret issuance |
| Snapshot restore allowed | metadata compatibility check |
| Backend allowed | scheduler/runtime backend selection |
| Workload admitted | quota reservation + lifecycle state |

### 3.3 READY is a validated state

A sandbox is not READY just because a VM or process started.

READY requires:

- runtime backend started successfully
- network setup completed
- image artifact verified
- guest-agent handshake completed
- sandbox ID matched
- image ID matched
- protocol version negotiated
- required capabilities present
- policy epoch valid
- telemetry and audit correlation established

The host reports `Running` only after the runtime adapter's explicit
`wait_ready` operation succeeds. Backend process start and transport
attachment leave the sandbox in `Booting`.

### 3.4 Network locality is not trust

PicoCompute does not trust a request because it comes from an internal network.

Every protected action must be scoped by:

- tenant identity
- sandbox identity
- operation identity
- policy decision
- lease or capability
- expiry/revocation state
- audit trail

### 3.5 Secrets are never ambient

Credentials must not be baked into images, persisted in workspaces, written to logs, or captured in snapshots.

Secrets are:

- issued just-in-time
- scoped by tenant, sandbox, operation, tool, and policy
- mounted through non-persistent paths
- revoked on policy change, lease expiry, destroy, resume, or fork
- excluded from snapshot artifacts

### 3.6 Evidence gates production

Production rollout depends on evidence, not intent.

Required evidence includes:

- ADRs
- conformance tests
- boundary validation
- image validation reports
- snapshot restore tests
- load validation reports
- SLO dashboards
- audit pipeline checks
- operational runbooks
- [security assurance case](docs/security/assurance-case.md)
- rollout checklist

---

## 4. Logical Architecture

```text
+--------------------------------------------------------------------------------+
| API + Regional Control Plane |
| |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | API Gateway | | AuthN/AuthZ | | Tenant Policy | | Access Leases | |
| +------+------+ +-------+--------+ +--------+-------+ +---------+---------+ |
| | | | | |
| v v v v |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | Lifecycle | | Runtime | | Image Resolver | | Snapshot Manager | |
| | State | | Orchestrator | | | | | |
| +------+------+ +-------+--------+ +--------+-------+ +---------+---------+ |
| | | | | |
| +-----------------+--------------------+--------------------+ |
| | |
| v |
| +------------------+ |
| | Regional | |
| | Scheduler | |
| +--------+---------+ |
+----------------------------------|---------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------------+
| Cell Control Plane |
| |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | Placement | | Host Inventory | | Capacity | | Snapshot Cache | |
| | Manager | | | | Manager | | Index | |
| +------+------+ +-------+--------+ +--------+-------+ +---------+---------+ |
| | | | | |
| +-----------------+--------------------+--------------------+ |
| | |
| v |
| host assignment |
+----------------------------------|---------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------------+
| Compute Host |
| |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | host-agent | | sandboxd | | image-agent | | network-agent | |
| +------+------+ +-------+--------+ +--------+-------+ +---------+---------+ |
| | | | | |
| v v v v |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | Runtime | | guest-agent | | snapshot-agent | | metrics-agent | |
| | Adapters | | protocol | | | | | |
| +------+------+ +----------------+ +----------------+ +-------------------+ |
| | |
| v |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
| | Firecracker | | gVisor | | QEMU | | Kata/CloudHV | |
| +-------------+ +----------------+ +----------------+ +-------------------+ |
+--------------------------------------------------------------------------------+
```

---

## 5. Control Plane

The Control Plane owns global intent, authorization, scheduling, state, and auditability.

### 5.1 Responsibilities

- expose public lifecycle API
- authenticate and authorize requests
- evaluate tenant policy
- enforce quotas
- issue access leases
- select backend policy
- schedule region/cell/host placement
- maintain lifecycle state
- coordinate image and snapshot metadata
- emit durable audit events
- enforce production readiness gates

Readiness is validated by the integrated control-plane suite
(`crates/pico-core/tests/control_plane_readiness.rs`) and recorded in
[the control-plane readiness report](docs/control-plane/prod-readiness-report.md).

### 5.1a Create admission placement

`CreateSandbox` admits through policy, quota, then two-stage placement:
`RegionalScheduler` selects the cell, `CellScheduler` selects the host.
Host-agent capacity reports feed a per-cell `HostInventory` with a 60s
stale TTL, and the admit path expires stale hosts before snapshotting.
Cell aggregates (totals, runtime union, mean pressure, most conservative
timing hint) refresh from live hosts on every report so regional math
tracks reported capacity. `InsufficientCapacity` and `PressureSaturated`
fail closed as retryable throttled errors carrying `Retry-After`, with
quota released and no silent backend fallback. Draining and unsupported
runtimes reject without a retry hint. A `None` runtime resolves once to
the configured default before scheduling and is pinned on success so
downstream hosts cannot switch families under pressure. Both schedulers
share one filter-score-select engine: constraints evaluate once per
candidate through a single check function, scores compute once per
survivor with breakdowns reused for observability, and rejection
classification derives typed errors from those single-pass rejections.
Each scheduler instance hardens bursts locally without cross-instance
coordination: an opt-in power-of-k winner policy samples `k` eligible
candidates and picks the best of the sample so concurrent bursts diverge
instead of herding onto one stale-snapshot winner, and an in-flight
overlay folds that instance's recent placements back into the snapshot
before filtering and scoring. Overlay entries expire on a TTL matched to
inventory staleness and release early when an assignment settles: every
host capacity report funnels through the placement gate, which drops the
overlay entries the fresh snapshot supersedes so production never
double-counts placements against refreshed snapshots. The winner policy
plus overlay state ride the placement spans, responses, and audit events.
The host keeps final admission authority: boot revalidates assignment,
fencing, policy epoch, and live capacity, and rejects stale estimates
with typed errors.

### 5.2 Lifecycle API

Expected operations:

- `CreateSandbox`
- `GetStatus`
- `Exec`
- `Signal`
- `AttachStream`
- `PutFile`
- `GetFile`
- `ExposePort`
- `UpdatePolicy`
- `Suspend`
- `Resume`
- `PauseJob`
- `ResumeJob`
- `Fork`
- `Destroy`

`PauseJob` and `ResumeJob` are job-scoped bulk signals. The control plane
sends one envelope per job; the host fans out to one fenced `Suspend` or
`Resume` per member sandbox with shared fencing, policy-epoch, and
deadline handling. Jobs are single-tenant: a mixed-tenant member set or a
tenant mismatch fails the whole signal before any side effect. Bulk
outcomes return `207` when any member fails, so a status-only caller
cannot mistake a partial application for success. See
[worker-container topology](docs/design/worker-container-topology.md).

### 5.3 Lifecycle state

```text
REQUESTED
  -> SCHEDULED
  -> PREPARING
  -> BOOTING
  -> READY
  -> EXECUTING
  -> IDLE
  -> SUSPENDING
  -> SUSPENDED
  -> RESUMING
  -> READY
  -> FORKING
  -> READY(parent) + READY(child)
  -> DESTROYING
  -> DESTROYED
```

Every state transition records:

- sandbox ID
- tenant ID
- operation ID
- previous state
- next state
- actor
- policy epoch
- timestamp
- trace ID
- audit event ID

### 5.4 Access leases

Access leases convert approved policy decisions into bounded capabilities.
Admission (`policy + quota + issue`) is the control-plane interface. Edge
and host are adapters on the enforce seam: they verify a signed lease blob
without sharing the issuer's in-memory store.

`PolicyEnforcingAgent` is wired on API boot. It maps `PolicyAction` to
`LeaseAction`, issues the lease, and overwrites client-supplied
`credential_request` tenant/lease fields so callers cannot smuggle identity.

Lease-backed actions include:

- port forwarding
- egress exceptions
- credential retrieval
- protected data-plane operations

Example lease shape:

```yaml
lease_id: string
tenant_id: string
sandbox_id: string
operation_id: string
policy_decision_id: string
scope: string
issued_at: timestamp
expires_at: timestamp
revoked_at: timestamp | null
signature: ed25519
```

### 5.5 Secrets broker integration

Credentials are never ambient. They are issued just-in-time through a
secrets broker, scoped by tenant, sandbox, operation, and policy, and
delivered to the guest through a non-persistent tmpfs mount.

#### Flow

```text
Control Plane Host Agent Guest Agent
     | | |
     |-- policy decision --------->| |
     |-- access lease ------------>| |
     | |-- validate lease --------->|
     | |-- fetch credentials ------>|
     | | (secrets broker) |
     | | |
     | |-- InjectSecrets RPC ------>|
     | | |-- mount tmpfs
     | | |-- write credentials
     | |<-- InjectSecretsResponse --|
     | | |
     | |-- revoke lease on -------->|
     | | destroy/suspend |
```

#### Components

| Component | Responsibility |
|---|---|
| `SecretsBroker` trait | Abstract interface for credential fetching (in `pico-core`) |
| `HttpSecretsBroker` | HTTP/JSON implementation (feature-gated behind `secrets-http`) |
| `MockSecretsBroker` | In-memory implementation for testing |
| `SecretsCoordinator` | Host-side orchestrator: validates lease, fetches credentials, injects into guest, emits audit events |
| Guest `secrets` module | Mounts tmpfs at `/run/pico/secrets`, writes credential files, validates names |

#### Mount contract

| Path | Type | Snapshot | Permissions |
|---|---|---|---|
| `/run/pico/secrets` | tmpfs | excluded | mode=500 (read-only to root) |

The tmpfs is mounted once by the guest's `/init`, before the guest agent
starts, and credential files are written with mode 0400 (owner read-only).
Init owns it because the guest agent runs under a seccomp profile that cannot
permit `mount(2)`, and widening that profile would also widen it for every
process the agent spawns on the Exec path. Init is unfiltered and already owns
the other filesystem mounts (`/proc`, `/dev`, `/sys`).

Boot fails if the secrets tmpfs cannot be mounted, so credentials can never
land on the root filesystem where a snapshot could capture them. On quiesce
the guest agent unlinks the credential files; the tmpfs itself stays mounted
because init created it and the agent cannot detach it, and its contents are
already gone once the files are removed.

The guest agent verifies the mount before every injection and fails closed if
the path is missing or is not a tmpfs.

#### Credential name validation

Guest-side validation rejects:

- empty names
- names exceeding 255 bytes
- names containing `/` (path traversal)
- reserved names (`.` and `..`)
- names with characters outside `[a-zA-Z0-9_.-]`

#### Lifecycle integration

- **Boot**: credentials injected after guest handshake if policy allows
- **Resume**: credentials refreshed with new lease validation
- **Fork**: child receives fresh credentials; parent credentials not inherited
- **Destroy**: lease revoked, tmpfs unmounted, audit event emitted

---

## 6. Host Runtime

The Host Runtime owns local execution.

The host-runtime ownership model is defined by
[ADR-0002](docs/adr/0002-host-runtime-lifecycle-orchestration.md). The concrete
OS process boundary between `host-agent` and `sandboxd`, sole `RuntimeBackend`
and guest-session ownership, and the host ingress split are defined by
[ADR-0011](docs/adr/0011-sandboxd-process-boundary-and-host-ingress.md):

```text
cell controller
    -> host-agent
        -> sandboxd
            -> runtime adapter
            -> image-agent
            -> network-agent
            -> snapshot-agent
            -> privileged helper

sandboxd -> metrics-agent
host-agent -> cell controller
```

The regional metadata store remains authoritative for desired lifecycle state.
Host-local persistence records observations, operations, and resource receipts
for supervision and cleanup; it does not become a second lifecycle authority.

### 6.1 host-agent

`host-agent` is the host-level lifecycle coordinator.

Responsibilities:

- receive scheduled assignments
- serve an authenticated host RPC surface, bound to loopback by default unless
  explicitly configured otherwise
- validate assignment fencing tokens, policy epochs, deadlines, and operation IDs
- coordinate image preparation
- coordinate network preparation
- coordinate runtime backend operations
- coordinate snapshot operations
- coordinate guest-agent readiness and protocol operations through `sandboxd`
- emit lifecycle telemetry
- aggregate ready, degraded, draining, and unsafe host health
- report capacity and observed lifecycle state to the cell controller

`host-agent` does not own runtime process handles or durable per-sandbox
resource state. It delegates supervised execution to `sandboxd` over a
permission-checked Unix domain socket (`Sandboxd` gRPC service, shared runtime
token plus Unix peer-credential allowlist).

Its sandbox registry is an observation cache, never an authority: entries are
rebuilt from `ListSandboxes` after a host-agent restart (rehydrate,
insert-only, `Destroyed` rows skipped) and kept current through the `Watch`
stream plus a periodic full `ListSandboxes` reconcile, guarded by per-sandbox
generation and the sandboxd `host_boot_id`. The observation adapter owns the
merge policy: stale generations are ignored, a new host boot resets the
ordering space. The sandboxd observation identity includes the host boot and
process incarnation, so a daemon-only restart resets generations safely.
Omitted SSH fields preserve previously observed metadata. Desired state lives on
`SandboxMetadata` and advances only through `commit(from, to, token)`.
After prepare, both desired and observed stay `Preparing` until boot;
`Preparing -> Pending` is not a legal path. A pre-upgrade ledger still
observed as `Pending` rehydrates as `Preparing` so `boot_sandbox` can
admit it. `Stopped` is a host-local
desired state after `stop` of a `Running` sandbox (for a later purge);
the ledger already shows those sandboxes `Destroyed`, and the reconcile
prunes every other ledger-destroyed entry so ghosts never resurface in
list output. The public lifecycle contract is explicit: `stop` accepts
`Running` and is idempotent on `Stopped`, `purge` accepts only `Stopped`,
and `destroy` is the force-teardown path for any non-terminal state. A
`purge` request for a live sandbox is rejected before any destructive RPC.
The port proxy resolves guest-port targets exclusively through
`GetPortTarget` and fails closed when the target is unknown or the generation
is stale.

Aggregate host health has two surfaces: `health` for local liveness, and the
sandboxd-aware `health_with_gc`, which reports `ready` only when sandboxd is
reachable, `ready_for_work`, and `reconcile_complete`, and reports `degraded`
while sandboxd is down or carries review-required findings.

The boot RPC carries a `BootCommand` containing sandbox and operation
identity, assigned host and cell, assignment fencing token, policy epoch, and
timeout. Admission validates assignment ownership, stale fencing and policy
context, host capacity, and required runtime capabilities before any boot side
effect. Terminal `BootReport` values are either `ready` or `not_ready`; failed
reports use the stable image, network, resource, backend, protocol, timeout,
and cleanup reason taxonomy.

### 6.2 sandboxd

`sandboxd` is the durable local supervisor.

Responsibilities:

- serialize mutating operations per sandbox
- supervise sandbox processes or VMMs
- persist observed state, operation progress, and resource receipts in a
  single-writer SQLite WAL database
- handle operation cancellation
- supervise streams
- enforce local deadlines
- supervise backend boot, guest transport attachment, and readiness as one
  durable operation
- clean up failed preparation and boot attempts before recording terminal
  ownership
- materialize host resources (workspace directories, cgroup v2 limits and
  cpuset, CPU pinning allocation) during prepare and tear them down during
  destroy, recorded as durable workspace, cgroup, and cpu resource receipts
- coordinate destroy cleanup
- reconcile processes and resources after process or host restart
- quarantine ambiguous or live orphans and require newly fenced direction

#### Host resource ownership

`HostResourceManager` inside `sandboxd` is the sole writer of host workspace
lifecycle (`ensure`/`delete`), cgroup hierarchy lifecycle
(`setup`/`setup_cpuset`/`cleanup`/`add_process`), and CPU pinning allocation
(`allocate`/`release`/`restore`). Supervisor prepare/destroy, process cgroup
attach, and garbage-collector orphan cleanup all go through that manager so
ledger receipts stay authoritative.

Intentionally outside the mutation path (read-only or non-lifecycle):

- cgroup identity and pressure/stats file reads (host-agent observability, eBPF)
- host-agent path resolution for file/task I/O against an already materialized
  workspace (no production `ensure`/`delete`)
- runtime adapters applying `sched_setaffinity` from a `cpu_set` allocated by
  `HostResourceManager` (affinity only; never allocation)
- soft `stop` on host-agent, which stops the runtime adapter only and leaves
  workspace/cgroup/CPU until destroy/purge

Idle reaper expiry always calls the full host-agent destroy path so host
resources are never released by a bare `RuntimeBackend::destroy` call.

`sandboxd` continues supervision across `host-agent` restarts but does not
interpret desired lifecycle policy. During a control-plane outage it preserves
healthy workloads, rejects new lifecycle mutations, and performs only
previously authorized rollback or cleanup.

The implementation lives in `crates/pico-sandboxd` as a separate OS
process. It provides:

- the `sandboxd` binary serving the `Sandboxd` gRPC service over a
  permission-checked Unix domain socket (default
  `/var/run/pico/sandboxd.sock`) with token metadata and a peer-credential
  allowlist; the socket is bound only after startup reconciliation completes,
  so `ready_for_work` and `reconcile_complete` hold for the entire serving
  window
- a typed command envelope with operation identity, fencing, policy epoch, and
  an absolute deadline
- terminal outcome reasons that `host-agent` can report without parsing error
  strings
- per-sandbox operation serialization and in-memory ownership of live runtime,
  process, stream, cancellation, and pidfd handles
- a single-writer SQLite WAL ledger for sandbox observations, operations,
  resource receipts, process identity, and reconciliation findings
- startup reconciliation that marks interrupted operations and unrecoverable
  streams as requiring review

Restart semantics follow the sole-runtime-owner rule:

- runtime handles are process-local and are never re-adopted after a restart;
  a `host-agent` restart therefore never drops VMM supervision
- guest exec and file RPCs fail closed before ledger registration when no
  guest session exists, keeping restart review findings accurate
- a `Destroy` retried after a mid-destroy restart resumes host cleanup from
  ledger receipts when durable evidence proves destroy intent: observed state
  `Destroying` or `Destroyed`, or `Failed` when the ledger's latest operation
  for the sandbox is destroy (partial cleanup or a restarted-away interrupt).
  Any other state refuses teardown without a runtime handle and stays
  quarantined for operator review

### 6.3 RuntimeBackend interface

All backends implement the same lifecycle contract.

```rust
#[async_trait]
trait RuntimeBackend {
    fn metadata(&self) -> BackendMetadata;
    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox>;
    async fn boot(&self) -> BackendResult<>;
    async fn attach_transport(&self) -> BackendResult<GuestTransport>;
    async fn wait_ready(&self, transport: &GuestTransport) -> BackendResult<>;
    async fn exec(&self, request: ExecRequest) -> BackendResult<ExecResponse>;
    async fn suspend(&self) -> BackendResult<>;
    async fn resume(&self) -> BackendResult<>;
    async fn fork(&self, target: &SandboxConfig) -> BackendResult<ForkResult>;
    async fn destroy(&self) -> BackendResult<CleanupReport>;
    async fn cleanup(&self) -> BackendResult<CleanupReport>;
    async fn state(&self) -> BackendResult<SandboxState>;
    async fn stats(&self) -> BackendResult<BackendStats>;
    async fn health(&self) -> BackendResult<BackendHealth>;
    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle>;
}
```

The interface keeps higher-level lifecycle code independent from
backend-specific details. Adapters return typed, idempotent outcomes and
resource identities to `sandboxd`; they do not own lifecycle coordination,
durable orchestration state, or control-plane reporting.

`BackendMetadata` exposes a stable backend identity, version, and explicit
capability set. Selection and conformance code matches required capabilities
before side effects begin. `BackendError` distinguishes image, network,
resource, backend, protocol, timeout, cleanup, incomplete setup, partial
cleanup, stale state, unsupported capability, invalid state, and unclassified
backend failure outcomes.

The host agent stores runtime trait objects and does not branch on concrete
backend types. Port exposure ownership is part of the interface so adapters
can declare host-proxied, backend-managed, or unsupported guest ports.
`pico-runtime::mock` implements the full contract and supports deterministic
failure injection. The shared conformance runner exercises required operations
and optional suspend, resume, and fork hooks according to declared
capabilities.

### 6.4 Privileged helpers

`host-agent` and `sandboxd` run without root privileges. Host mutations such as
network setup, cgroup management, mounts, and backend launch are exposed
through narrow typed helper RPCs over permission-controlled Unix domain
sockets. Helpers validate Unix peer credentials and receive only the
capabilities required for their resource class.

Backend processes run under dedicated identities, cgroups, namespaces, and
seccomp profiles. Direct shell and `sudo` based host mutation is not part of
the production architecture.

---

## 7. Isolation Backends

PicoCompute supports multiple backends, but not all backends have the same
security posture. The normative workload mapping, fallback rules, compatibility
gates, and conformance requirements are defined by
[ADR-0004](docs/adr/0004-default-isolation-backend-strategy.md).

| Backend | Role | Production posture |
|---|---|---|
| Firecracker | default microVM backend | default for public multi-tenant |
| gVisor | fast syscall-mediated sandbox | explicit opt-in for trusted workloads |
| QEMU | compatibility VM backend | public fallback and compatibility path |
| Cloud Hypervisor | modern microVM candidate | evaluation-only pending |
| Kata Containers | Kubernetes-native isolation candidate | evaluation-only pending |

Public untrusted workloads select Firecracker, with QEMU as the only
permitted fallback. Trusted fast-path workloads may select gVisor only through
an explicit tenant and workload policy grant, then fall back to Firecracker
and QEMU. Compatibility workloads select QEMU and fail closed when its
requirements cannot be met.

Kubernetes is a deployment environment, not a workload trust class. The same
selection policy applies on Kubernetes-integrated deployments. Kata is not a
public-untrusted production path until its evaluation, adapter, security
review, and conformance gates pass.

### 7.1 Backend conformance

Every backend must pass conformance tests for:

- prepare
- boot
- guest-agent transport
- exec
- suspend
- resume
- fork, where supported
- destroy
- cleanup
- stats
- health
- isolation expectations
- network attachment
- image compatibility
- snapshot compatibility

Unsupported capabilities are declared and reported, never silently skipped.
Production eligibility is scoped to the exact backend version, host profile,
guest artifact profile, and workload class covered by the conformance result.

### 7.2 Backend selection policy

Backend selection is a control-plane decision made before host assignment.
Every candidate must pass:

- tenant policy
- workload class and isolation floor
- required lifecycle, network, device, and snapshot capabilities
- signed image, kernel, rootfs, firmware, and architecture compatibility
- backend and version-specific snapshot compatibility
- host/guest protocol transport, version, and capability compatibility
- cell and host support
- backend health and capacity
- a current passing conformance profile

The persisted decision includes the selected backend, fallback rank, reason
code, rejected candidates, policy revision, and compatibility evidence. A
runtime adapter, host agent, or scheduler must not substitute another backend.
Fallback reruns the control-plane policy and creates a new audit record.

Cross-backend snapshot restore is prohibited. If no compatible backend is
available, restore fails rather than falling back to a cold boot or a weaker
isolation boundary.

---

## 8. Host/Guest Protocol

The guest-agent protocol is the contract between host runtime and sandbox
guest. Its format, transport, authentication, compatibility, deadline, retry,
and stream semantics are defined by
[ADR-0003](docs/adr/0003-host-guest-agent-protocol-contract.md).

### 8.1 Transport

PicoCompute uses tonic gRPC with Protocol Buffers `proto3` over a
backend-provided local byte stream:

- Firecracker virtio-vsock through its per-VM Unix socket mapping
- QEMU `AF_VSOCK`, with virtio-serial as a compatibility fallback
- permission-controlled Unix domain sockets for gVisor and container runtimes
- TCP loopback only for local development and tests

The host initiates every production connection. The control protocol is never
exposed through the sandbox network.

### 8.2 Protocol properties

The stable bootstrap service authenticates each connection with a fresh
per-sandbox, per-boot 256-bit secret and HMAC-SHA256 mutual
challenge-response. Successful negotiation binds sandbox, image, boot,
protocol, capability, policy, and session identity to the connection.

Operational packages use major-version names such as `pico.guest.v1`.
Hosts and newly built guest agents support the current and immediately
previous major, negotiate the highest overlapping minor, and enable only the
intersection of advertised capabilities.

Every operational request carries a unique request ID, stable operation ID for
side-effecting retries, sandbox ID, authenticated session ID, policy epoch,
negotiated protocol version, and absolute deadline. Application failures use
typed outcomes; gRPC statuses are reserved for transport, authentication,
negotiation, overload before admission, and malformed requests.

Protocol resource bounds include:

- 1 MiB maximum encoded protobuf message
- 64 KiB maximum stream payload frame
- 1 MiB replay buffer per output stream
- bounded queues and concurrent operations
- compression disabled by default

Streams use monotonic sequence IDs, cumulative acknowledgements, bounded
backpressure, and explicit replay through `AttachStream`. A stream disconnect
does not cancel its operation.

### 8.3 RPC surface

```text
Ping
Exec
Signal
Cancel
AttachStream
Quiesce
PrepareSnapshot
ResumeNotify
MountWorkspace
PutFile
GetFile
Stats
Health
Shutdown
```

Protocol robustness and misuse-resistance are validated by the
[protocol robustness test suite](docs/robustness). Every RPC is tested
against malformed, stale, replayed, reflected, oversized, and
identity-misbound messages. New RPCs must pass the
[misuse-resistance checklist](docs/robustness/misuse-resistance-checklist.md)
before merge.

### 8.4 Readiness handshake

A sandbox reaches READY only after guest-agent handshake proves:

- guest-agent version
- protocol version
- image ID
- sandbox ID
- boot ID
- capability set
- policy metadata
- transport compatibility
- possession of the per-boot authentication secret
- a connection-bound session ID

Snapshot restore and fork invalidate all existing connections, sessions, and
boot secrets. The host reconnects, authenticates with fresh boot credentials,
renegotiates the protocol, and completes `ResumeNotify` before READY.

---

## 9. Per-Sandbox Networking

PicoCompute networking follows zero-trust principles. The normative topology,
enforcement boundaries, lifecycle rules, and fallback profiles are defined by
[ADR-0005](docs/adr/0005-per-sandbox-networking-model.md).

### 9.1 Defaults

- no ingress by default
- no direct host or public listener exposure
- routed isolation with no shared tenant layer-2 network
- egress only through current policy
- egress exceptions require an active access lease
- DNS only through the policy-aware DNS proxy
- platform-internal networks denied by default
- no trust based on network location
- port forwarding requires explicit lease
- IPv6 disabled unless it has equivalent enforcement
- resume, relocation, and fork rebuild current network policy

### 9.2 Network path

```text
MicroVM: guest -> TAP -> sandbox network namespace
Container: process -> veth -> sandbox network namespace

sandbox namespace
  -> host-facing veth
  -> nftables policy, anti-spoofing, and accounting
  -> DNS proxy
  -> NAT/egress gateway
  -> external network
```

Every sandbox has an independent logical network identity and Linux network
namespace. MicroVMs receive a pre-created TAP and namespace uplink veth.
Container-backed sandboxes receive a namespace-side veth. The host routes
traffic without creating a tenant-visible shared bridge or broadcast domain.

The regional control plane owns network admission, policy decisions, logical
identity, and access leases. `host-agent` admits fenced commands, `sandboxd`
persists resource receipts and cleanup progress, and `network-agent` owns
bounded namespace, TAP, veth, route, nftables, NAT, and teardown mechanics.
Runtime adapters attach pre-created devices but do not create policy or
externally reachable listeners.

### 9.3 Egress

Fresh network intent permits only the assigned policy-aware DNS proxy.
Baseline egress is granted by current control-plane policy. Exceptions require
an active `EgressException` lease matching the tenant, sandbox, destination
scope, policy decision, epoch, and expiry.

nftables validates source identity, denies sandbox-to-sandbox forwarding,
filters protected destination classes, records counters, and applies NAT only
after authorization and attribution. Lease revocation denies new flows and
terminates flows whose authority no longer exists.

Egress decisions are recorded with:

- tenant ID
- sandbox ID
- logical network identity
- operation ID
- policy decision ID
- policy epoch
- lease ID, when applicable
- destination policy
- action
- timestamp

### 9.4 DNS

DNS is an authorization boundary.

The DNS proxy enforces:

- allowed domains
- denied domains
- suffix rules
- answer addresses and record types
- internal platform domain restrictions
- policy epoch updates
- cache invalidation
- audit event emission

Direct external resolver paths are denied unless explicitly authorized.
Approved names cannot resolve to host, control-plane, metadata, link-local, or
tenant-peer destinations.

### 9.5 Port forwarding

Port forwarding is controlled ingress through an authenticated PicoCompute
gateway. Tenants do not receive a raw host address or an arbitrary host
listener.

It requires:

- explicit API request
- policy approval
- access lease
- expiry
- revocation behavior
- audit event
- no raw host port exposure to tenants

The gateway validates the lease when provisioning an exposure and accepting a
connection. Expiry, revocation, policy epoch change, suspension, or destroy
removes the exposure and terminates connections whose authority no longer
exists.

### 9.6 Lifecycle and reconciliation

Suspend blocks new flows and deactivates lease-backed exposure. Resume keeps
the logical network identity but reconstructs current policy before enabling
the guest interface; host-local addresses may change after relocation. Fork
always receives new identity, addresses, leases, policy artifacts, DNS state,
NAT state, and connection tracking.

`network-agent` and `sandboxd` reconcile deterministic receipts against
namespaces, devices, routes, nftables state, DNS attachments, ingress
registrations, and address allocations. Proven stale resources are cleaned.
Ambiguous live resources are quarantined and drain or degrade the host rather
than being deleted by naming convention.

### 9.7 Integration profiles

Approved CNI plugins may provision the same PicoCompute topology in Kubernetes or
other integrated environments, but PicoCompute retains policy, lease, lifecycle,
audit, and reconciliation authority.

Proxy-only networking is an explicit limited profile for workloads that do
not require transparent layer-3 compatibility. It is never an automatic
fallback. Open vSwitch is deferred until measured overlay, density, offload,
or service-chaining requirements justify a separate architecture decision.

---

## 10. Guest Image Pipeline

PicoCompute images are trusted release graphs, not ad hoc root filesystems. The
normative artifact, compatibility, verification, and promotion contract is
defined by
[ADR-0008](docs/adr/0008-guest-image-format-and-build-pipeline.md).

### 10.1 Image bundle

A PicoCompute Guest Image Bundle is an OCI image index consumed by digest. It
references per-architecture, backend-compatible variants and their immutable:

- PicoCompute JSON manifest
- ext4 rootfs for Firecracker and QEMU, or OCI filesystem for gVisor
- kernel, optional initrd, and optional firmware
- guest-agent artifact
- backend, protocol, mount, and snapshot compatibility metadata

All rootfs renderings originate from one normalized filesystem tree. The
kernel, init, rootfs, and guest agent form one tested variant and are never
substituted independently at boot.

### 10.2 Manifest sketch

```yaml
schema_version: "1.0"
image_id: pico-guest-standard
platform:
  os: linux
  architecture: x86_64
artifacts:
  rootfs:
    format: ext4
    digest: sha256:...
  kernel:
    format: linux-vmlinux
    digest: sha256:...
  guest_agent:
    digest: sha256:...
protocol:
  bootstrap: pico.guest.bootstrap.v1
  supported:
    - major: 1
      min_minor: 0
      max_minor: 0
compatibility:
  profile_id: firecracker-x86_64-v1
  backends:
    - family: firecracker
      tested_versions: [...]
mount_contract:
  version: "1.0"
snapshot:
  filesystem: true
  memory: false
  excluded_mount_classes:
    - secret
    - runtime_tmp
```

Compatibility is a bounded allowlist backed by conformance evidence. The
scheduler uses verified metadata for placement, and the host rechecks the
root bundle, selected variant, component digests, production promotion,
supply-chain evidence, and local compatibility before caching or booting.

### 10.3 Build and promotion

The pipeline:

1. resolves every source, package, toolchain, and base input by digest
2. builds kernel, init, guest-agent, and normalized rootfs components
3. renders deterministic ext4 and OCI variants
4. assembles PicoCompute manifests and the root OCI index
5. generates SPDX 3.0.1 SBOMs, SLSA v1.2 in-toto provenance, vulnerability
   and secret-scan results
6. validates schema, filesystem, backend boot, authenticated readiness, mount,
   and compatibility behavior
7. signs and promotes the same immutable digest through `built`, `validated`,
   `candidate`, and `production`

Supply-chain and promotion evidence is attached as OCI referrers. Promotion
adds signed evidence and never rebuilds or rewrites the bundle. Mutable tags
are discovery aliases, not production identity.

### 10.4 Mount classes

| Path | Class | Snapshot behavior |
|---|---|---|
| `/` | immutable base + overlay | base tracked |
| `/workspace` | persistent workspace | included or COW |
| `/run/pico/tmp` | runtime temporary | excluded |
| `/run/pico/secrets` | tmpfs credentials | excluded |
| `/var/log/pico` | guest logs | policy-dependent |

### 10.5 Validation

Image validation checks:

- OCI graph, manifest schema, descriptor size, and digest integrity
- reproducible rootfs, kernel, init, guest-agent, and variant outputs
- filesystem policy and absence of secrets or host identity
- guest-agent protocol compatibility
- backend, runtime, host, CPU, machine, and device compatibility
- mount paths, permissions, persistence, and snapshot exclusions
- signatures, provenance, SBOM, vulnerability, validation, and promotion
  evidence
- boot-to-authenticated-handshake tests for every declared backend profile

Warm snapshots are separately signed, backend-bound OCI artifacts. They
reference the exact source bundle and variant digests and cannot broaden image
compatibility.

---

## 11. Snapshot, Resume, and Fork

PicoCompute supports stateful workloads through snapshots and copy-on-write
branching. The normative consistency, exclusion, restore, and fork contract is
defined by
[ADR-0007](docs/adr/0007-snapshot-resume-fork-consistency-model.md).

The portable v1 guarantee is filesystem-first. Memory and runtime device state
are preserved only through an explicit state profile supported by the exact
backend and deployment combination. Backend-native modes remain internal
implementation details.

### 11.1 Snapshot types

Snapshot purpose is separate from the state profile:

| Purpose | Contract |
|---|---|
| Base snapshot | Immutable, verified warm-start point without tenant session, credential, lease, or network authority |
| Runtime snapshot | Internal backend-bound artifact used to implement another snapshot purpose |
| Session snapshot | Immutable recovery point for one sandbox and its declared state profile |
| Fork snapshot | Immutable branching point for independent child sandboxes |

| State profile | Preserved state |
|---|---|
| `filesystem` | Image references, committed workspace point, declared persistent mounts, and metadata |
| `memory` | `filesystem` state plus compatible guest memory and restorable runtime device state |

The `filesystem` profile does not preserve running processes, open file
descriptors, process memory, or active exec operations. The `memory` profile
is rejected rather than downgraded when backend, protocol, exclusion, or
conformance capabilities are unavailable. Lifecycle suspend/resume requires
the `memory` profile because `Suspended` preserves VM memory and device state.
A filesystem-only restore follows a boot path and is not reported as resume.

### 11.2 Snapshot metadata

Snapshot metadata includes:

- snapshot ID
- tenant ID
- sandbox ID
- snapshot purpose and state profile
- snapshot lifecycle state
- parent snapshot ID
- lineage type
- image ID
- rootfs digest
- kernel version
- guest-agent version
- protocol version
- backend type/version
- CPU/memory shape
- device model
- policy epoch
- excluded mounts
- encryption key reference
- integrity digest

Metadata is published as ready only after all required blobs, digests,
compatibility fields, exclusion evidence, and lineage references are durable.
Partial artifacts are not restorable.

### 11.3 Quiescence and active execs

Snapshot, suspend, and fork install an operation fence before capture:

- new exec requests receive a typed busy outcome
- already admitted execs continue within their original deadlines
- capture waits for active execs and supervised process trees to terminate
- output remains available through the bounded stream replay contract
- snapshot creation never cancels an exec implicitly
- a busy or timed-out guest causes capture to fail without a weaker fallback

After exec drain, the guest runs configured quiesce hooks, flushes persistent
state, invalidates protocol and credential authority, and proves secret and
temporary mount exclusion. The workspace is frozen only for the bounded
immutable commit. Any failure thaws the workspace, clears the operation fence,
and restores normal operation after cleanup. If quiesce already invalidated
the protocol session, the source reauthenticates and completes explicit
recovery notification before work is admitted again.

PicoCompute provides application-consistent capture only when application
quiesce hooks succeed. Otherwise the guarantee is a PicoCompute-coordinated point
with drained execs and flushed, frozen persistent filesystems.

After a standalone snapshot or fork, the source is thawed, unfenced,
reauthenticated when required, and returned to its pre-operation lifecycle
state. Suspend keeps the source stopped and reports `Suspended` only after the
snapshot is durable. A disposable base-snapshot builder may terminate after
capture according to the image-builder contract.

### 11.4 Included and excluded state

Included state:

- immutable image and artifact digest references
- persistent workspace and declared persistent data mounts
- guest memory and restorable devices only for the `memory` profile
- policy-approved persistent application logs

Excluded and regenerated state:

- secret and temporary mounts
- runtime credentials, access leases, tokens, and secret broker state
- host/guest protocol sessions, boot secrets, operation handles, and streams
- network namespaces, interfaces, host addresses, DNS cache, NAT, flows,
  connection tracking, and port exposure
- host-local process, cgroup, mount, socket, and helper identities

Secrets copied by a workload into ordinary persistent data remain tenant data.
PicoCompute excludes platform-issued authority but cannot make an untrusted
workload forget data it has already observed.

### 11.5 Restore validation

Before restore, PicoCompute validates:

- tenant identity
- snapshot readiness, lineage, retention, and revocation
- encryption key availability and artifact integrity
- image compatibility
- backend compatibility
- kernel compatibility
- guest-agent compatibility
- protocol compatibility
- architecture, CPU template and required features
- machine, device, memory, and persistent mount shape
- current workload class, isolation floor, and policy
- excluded-state rules

Cross-backend restore is prohibited. Cross-version restore requires explicit
backend compatibility policy and PicoCompute conformance evidence. A policy epoch
stored in a snapshot is historical evidence, not restored authority; resume
and fork require a new decision at the current epoch.

### 11.6 Resume semantics

Lifecycle resume applies only to a compatible `memory` session snapshot. It
preserves the sandbox ID, durable lifecycle history, workspace identity,
logical network identity, and lineage. It replaces:

- boot identity and protocol authentication
- host assignment and fencing as applicable
- runtime, process, cgroup, socket, mount, and helper identities
- host-local network resources, DNS authorization, NAT, flows, and exposure
- access leases and runtime credentials

The sandbox becomes READY only after integrity and compatibility validation,
runtime restore, current network policy installation, fresh guest
authentication, protocol renegotiation, mandatory `ResumeNotify`,
non-persistent resource refresh, and health validation.

### 11.7 Fork semantics

A fork creates a child sandbox with:

- independent sandbox ID
- independent policy state
- independent network identity
- independent writable workspace layer
- lineage reference to parent
- refreshed or unavailable credentials
- no accidental port-forward inheritance

Fork quiesces the source only for the bounded consistency operation and does
not change its lifecycle state. A filesystem fork starts the child from a new
writable COW layer without source processes or memory. A memory fork is
capability-gated and must rebind all child identity before execution resumes.
Parent and child can be destroyed independently while shared immutable
ancestors remain retained until no live reference exists.

### 11.8 Lazy restore

Lazy restore is an optimization path.

Expected behavior:

- restore minimal state
- start sandbox before full memory load
- fetch pages on demand
- prefetch hot pages
- enforce bandwidth and concurrency limits
- authenticate every page before use
- preserve the same readiness, exclusion, lineage, and compatibility contract
- use eager restore only when it preserves the requested `memory` semantics

### 11.9 Job preemption with backend-specific reclaim

A job-scoped pause/resume signal reclaims preemptible capacity without
weakening the suspend contract. The host fans one job envelope out to one
fenced `Suspend` or `Resume` per member sandbox. Containers reclaim
through cgroup plus swap pressure with `MADV_WILLNEED` prefetch on resume;
microVMs reclaim through snapshot plus terminate plus on-demand restore on
the same backend family. Resume always refreshes policy epoch, network,
credentials, session, and `ResumeNotify`, and passes the full
restore-validation gate list. The rollout owner runs outside the
preemptible pool. See
[worker-container topology](docs/design/worker-container-topology.md).

---

## 12. Security Architecture

Security is a first-class architecture track. The normative workload mapping,
hard invariants, residual-risk model, and production gates are defined by
[ADR-0006](docs/adr/0006-production-security-posture-for-sandbox-isolation.md).
The detailed assets, actors, trust boundaries, abuse cases, risk trees,
failure modes, controls, and review procedure are maintained in the
[PicoCompute threat model](docs/security/threat-model.md).
The operational gate states, evidence contract, stage thresholds, and owner
matrix are maintained in the
[PicoCompute production readiness model](docs/security/production-readiness.md).

### 12.1 Security assumptions

PicoCompute assumes:

- workloads may be malicious or compromised
- tenants must be isolated
- internal services are protected resources
- network location is not trust
- credentials are temporary capabilities
- host compromise is high impact
- snapshots may contain sensitive runtime state
- audit integrity matters

### 12.2 Default production posture

| Workload class | Production isolation floor |
|---|---|
| Public untrusted | Firecracker microVM, with QEMU as the only fallback |
| Trusted fast path | gVisor only through explicit tenant and platform approval |
| Compatibility VM | Minimized and pinned QEMU profile |
| Dedicated tenancy | Approved VM backend on resources dedicated to the accepted trust domain |
| Platform service | Separate platform boundary; never a tenant sandbox workload |

Public workloads never fall back to a standard container boundary. Shared-host
cross-tenant placement requires an approved side-channel and
covert-channel assessment for the exact host, hardware, runtime, scheduler,
and workload profile. Until then, placement uses dedicated tenancy.

Every production profile combines:

- dedicated runtime identities and namespaces
- jailer or equivalent VMM confinement
- seccomp, capability minimization, and `no_new_privs`
- cgroup v2 CPU, memory, PID, I/O, and applicable device controls
- minimal devices, mounts, sockets, host services, and immutable artifacts
- signed minimal guest images with provenance and vulnerability evidence
- brokered, short-lived, scoped, and revocable credentials
- snapshot quiesce, credential revocation and exclusion, encryption, and
  fresh post-restore identities
- ADR-0005 default-deny networking and protected destination restrictions
- current validation evidence for the exact deployed combination

### 12.3 Hard invariants

The architecture prevents, rather than merely detects:

- silent downgrade below the approved workload isolation floor
- host, platform, or cross-sandbox namespace and management-socket access
- cross-tenant writable image, workspace, runtime, cache, or snapshot state
- ambient host, metadata, control-plane, platform-internal, or peer networking
- platform-wide, host-wide, control-plane, or non-expiring guest credentials
- credential, lease, session, flow, or exposure inheritance after restore or
  fork
- `Running` before backend, host, cgroup, namespace, network, protocol, image,
  and policy controls are installed and validated
- identity or address reuse before failed cleanup is proven absent or
  quarantined
- public production without current evidence for the exact backend, host,
  guest, network, credential, snapshot, hardware, and workload profile
- shared-host cross-tenant placement before approval

If a profile cannot enforce an invariant, the affected workload is rejected or
the profile returns to architecture review.

### 12.4 Trust boundaries

```text
Client -> Public API
Public API -> Control Plane
Control Plane -> Cell Control Plane
Cell Control Plane -> host-agent
host-agent -> sandboxd
sandboxd -> runtime backend
sandboxd -> image-agent
sandboxd -> network-agent
sandboxd -> snapshot-agent
sandboxd -> privileged helper
runtime backend -> guest-agent
sandbox -> network data plane
sandbox -> secrets broker
sandbox -> snapshot storage
host -> image registry
```

### 12.5 Residual risk

The production posture reduces but does not eliminate VMM, KVM, host-kernel,
hardware, supply-chain, control-plane, approved-egress, application-memory,
and side-channel risk.

Residual-risk acceptance is versioned and limited to an exact workload class,
backend, host and guest profile, hardware scope, evidence revision, and review
period. Material changes invalidate affected acceptance. Unapproved
shared-host risk requires dedicated tenancy, and directly delivered workload
credentials are treated as disclosed for their valid lifetime.

### 12.6 Security launch gates

Production readiness requires:

- approved risk and threat model
- backend, host runtime, seccomp, capability, namespace, device, and artifact
  hardening evidence
- cgroup v2 resource containment tests
- signed image provenance, SBOM, vulnerability policy, and boot validation
- host/guest protocol abuse and lifecycle validation
- network isolation, DNS, lease revocation, IPv6 parity, and cleanup tests
- secrets broker authorization, scope, lifetime, and telemetry-exclusion tests
- snapshot quiesce, credential revocation, exclusion, restore, and fork tests
- isolation boundary validation, including downgrade and cross-tenant checks
- crash, retry, reconciliation, quarantine, and absence-proof validation
- vulnerability response, emergency drain, rebuild, and incident exercises
- side-channel assessment or enforced dedicated tenancy
- production readiness, security assurance, residual-risk, and owner approval

Every gate is blocking, retains evidence, names an owner, and is revalidated
after relevant runtime, kernel, image, hardware, network, credential, snapshot,
or policy changes.

The production readiness model applies these gates to exact deployment
profiles and defines the private-preview, public limited-beta, and production
thresholds.

---

## 13. Observability and Reliability

PicoCompute must be observable as an integrated system. The normative telemetry,
audit, correlation, cardinality, redaction, dashboard, and alert contract is
defined by
[ADR-0009](docs/adr/0009-observability-and-reliability-signals.md).

### 13.1 Signal model

PicoCompute uses an OpenTelemetry-first operational model:

- OpenTelemetry APIs and OTLP export for metrics, traces, and platform logs
- W3C Trace Context across trusted internal lifecycle boundaries
- structured JSON logs with source-side allowlist redaction
- a separate durable audit plane for security and authoritative decisions
- validation reports, SLO dashboards, alert events, and
  [operational runbooks](docs/runbooks/README.md) derived from stable
  signal contracts

Metrics provide bounded aggregate behavior. Traces explain one distributed
operation. Logs provide local diagnostics. Audit events provide immutable,
unsampled security and control evidence. Operational telemetry may be sampled
or delayed, but audit durability cannot depend on that path.

### 13.2 Implementation: pico-telemetry crate

Observability infrastructure is standardized in `crates/pico-telemetry` with:

- **Log:** `tracing-subscriber` with pretty (dev) or JSON (prod) output,
  configured via `TelemetrySettings::log`.
- **Metrics:** OpenTelemetry SDK with OTLP gRPC export via `opentelemetry-otlp`.
  Each consuming crate defines metrics in a centralized `metrics.rs` module
  using `LazyLock<..>` statics backed by `pico_telemetry::metrics::Counter`,
  `Histogram`, and `Gauge` wrappers.
- **Tracing:** `tracing-opentelemetry` bridge for span export to OTLP.

```rust
let driver = pico_telemetry::init(TelemetryConfig {
    settings: &TelemetrySettings {... },
})?;
tokio::spawn(driver);
```

Called once at process startup in each binary's `main`.

#### Current metric names

| Name | Type | Labels | Crate |
|------|------|--------|-------|
| `network.setup.started` | Counter | `backend`, `kind` | network-agent |
| `network.setup.completed` | Counter | `backend`, `kind` | network-agent |
| `network.setup.not_completed` | Counter | `reason` | network-agent |
| `network.setup.duration_seconds` | Histogram | - | network-agent |
| `network.objects.count` | Gauge | `kind` | network-agent |
| `network.cleanup.removed` | Counter | `kind` | network-agent |
| `network.cleanup.absent` | Counter | `kind` | network-agent |
| `network.cleanup.completed` | Counter | - | network-agent |
| `network.rollback.completed` | Counter | - | network-agent |
| `pico_boot_events_total` | Counter | `event`, `reason` | host-agent |
| `pico_boot_latency_seconds` | Histogram | `status` | host-agent |
| `pico.host.cpu.capacity` | Gauge | `state` | host-agent |
| `pico.host.memory.capacity` | Gauge | `state` | host-agent |
| `pico.host.sandbox.capacity` | Gauge | `state` | host-agent |
| `pico.host.resource.utilization` | Gauge | `resource` | host-agent |
| `pico.host.health` | Gauge | `health_state` | host-agent |
| `pico_placement_latency_seconds` | Histogram | - | core |
| `pico_placement_hosts_evaluated` | Histogram | - | core |
| `pico_placement_hosts_passed_constraints` | Histogram | - | core |

### 13.3 Shared taxonomy and correlation

All signals share versioned bounded values for:

- lifecycle operation and phase
- terminal outcome and typed reason
- service, region, cell, backend, workload class, and lifecycle state
- host health, resource, cache, network, and snapshot classes

Protected traces, platform logs, and audit records may include tenant,
sandbox, operation, request, trace, policy-decision, and lease identity.
Metrics never include those unbounded identifiers.

Trace context is diagnostic input, never authority. Public trace headers are
validated as untrusted input, tenant data is not propagated through baggage,
and authenticated typed request fields remain authoritative for operation and
authorization identity.

### 13.4 Metric and cardinality rules

Required metric families cover:

- API availability, request count, and latency
- lifecycle operation and phase count, outcome, and latency
- scheduling latency, capacity, and placement outcomes
- host health, resource pressure, capacity, and heartbeat freshness
- runtime, guest readiness, and image preparation
- network setup, policy decisions, traffic, DNS, and port exposure
- snapshot capture, restore, fork, compatibility, and cache behavior
- cleanup backlog, orphan findings, drift, and reconciliation
- audit delivery, backlog, dead letters, integrity, and lag
- telemetry export, queue use, freshness, sampling, redaction, and overflow

Metric attributes are bounded enums and controlled deployment identities.
Tenant, sandbox, request, operation, trace, lease, policy-decision, path,
domain, address, command, error-string, and user-provided values are
prohibited. `host_id` appears only on host-scoped health, capacity, pressure,
and diagnostic instruments.

Each metric instrument has a hard limit of 2,000 active attribute
combinations per collection cycle. Overflow aggregates under
`otel.metric.overflow=true`, increments the PicoCompute overflow counter, raises
an alert, and blocks readiness approval until corrected.

### 13.5 Trace and log boundaries

Distributed traces cover API admission, policy, quota, regional and cell
scheduling, host orchestration, image and network preparation, runtime
adapters, guest protocol calls, snapshots, cleanup, metadata commit, and
audit enqueue.

Tail sampling retains every failed, slow, security-relevant, audit-pipeline,
and unsafe-host trace plus a configurable baseline of successful traces.
Sampling never applies to audit events.

Platform services emit structured JSON records with service and deployment
identity, trace context, authorized operation correlation, canonical outcome,
and redaction markers. The lifecycle coordinator emits one terminal error
record for each non-success operation. Platform logs, guest platform logs,
guest console output, and workload output use separate streams and access
policies.

Secrets, commands, arguments, environment data, user payloads, file contents,
raw output, full URLs, query strings, arbitrary headers, and raw dependency
errors are prohibited from telemetry. Source-side allowlists are mandatory;
collector redaction is a secondary safeguard.

### 13.6 Durable audit plane

Audit events include lifecycle, policy, quota, placement, lease, runtime,
network, credential, image, snapshot, cleanup, quarantine, operator,
telemetry-redaction, and readiness decisions.

Authoritative control-plane state and audit records commit atomically.
Compute-plane security-sensitive mutations durably enqueue audit evidence
before reporting success. Delivery is at-least-once with immutable event IDs,
consumer deduplication, HLC and per-operation ordering evidence, retries, and
durable dead-letter handling.

Audit queue pressure, delivery gaps, unexplained sequence gaps, or dropped
events are readiness failures. They can block security-sensitive mutations,
degrade or quarantine a host, and trigger SRE and Security pages.

#### Audit schema (v2)

The audit event schema is versioned at `pico_core::identity::AUDIT_SCHEMA_VERSION`.
v1 established lifecycle, lease, policy, quota, placement, runtime,
and host-disabled event kinds. v2 adds:

- `LeaseEnforced`: data-plane lease validation and enforcement
- `NetworkEnforcement`: egress, DNS, and port-forward enforcement decisions
- `CredentialIssuance`: credential issue, denial, and revocation
- `SnapshotOperation`: snapshot create, restore, fork, and integrity
- `CleanupDisposition`: cleanup, quarantine, and reconciliation outcomes
- `AuditDelivery`: audit pipeline delivery and disposition events

V2 also adds top-level correlation fields (`producer`, `request_id`, `action`,
`outcome`, `reason`, `policy_decision_id`, `lease_id`) with `#[serde(default)]`
for forward/backward compatibility. V1 events deserialize safely under v2;
new fields default to `None`.

#### Query model

Consumers query audit events via `AuditEventQuery` `query_events` with
filters on: tenant ID, sandbox ID, operation ID, policy decision ID, lease ID,
event kind, HLC wall-time range, and recorded-at time range. Cursor-based
pagination uses the `id` (BIGSERIAL) primary key.

#### Retention model

| Tier | Duration | Purpose |
|------|----------|---------|
| Hot | 30 days | Active querying in `pico.audit_events` |
| Cold | 365 days | Compliance and audit trail in the same table |
| Dead-letter | 90 days | Delivery exhaustion records in `pico.audit_events_dead_letter` |

`AuditRetentionConfig` generates batched expiration SQL for background cleanup.

#### Pipeline health

`pico_telemetry` metrics (`pico.audit.delivery.count`,
`pico.audit.delivery.lag`, `pico.audit.outbox.pending`) provide
visibility into delivery health, end-to-end lag, and backlog.

#### Redaction

`redact_event` strips secrets, raw user content, URLs, and credential
patterns from audit event details and reason fields before persistence.
Schema design prohibits these from appearing; redaction provides
defense-in-depth.

#### Delivery guarantees

- `PostgresAuditSink`: batch insert with exponential-backoff retry
  (configurable `max_retries`), dead-letter table (`audit_events_dead_letter`)
  on exhaustion, and idempotent `ON CONFLICT (event_id) DO NOTHING`.
- `ChannelAuditSink`: bounded channel with `ChannelFull` error for
  hold-for-review by the producer.
- Indexes on `sandbox_id`, `tenant_id`, `trace_id`, `event_kind`,
  `operation_id`, `policy_decision_id`, `lease_id`, `hlc_wall_time_ms`,
  and `recorded_at` support fast query filtering.

### 13.7 Production-readiness signals

| Area | Objective signals | Diagnostic and durable evidence |
|---|---|---|
| API | availability, count, latency, and burn | admission traces, terminal logs, policy audit |
| Lifecycle | operation and phase success and latency | end-to-end traces, lifecycle audit |
| Scheduling | placement latency, rejection, and capacity | scheduler spans and placement audit |
| Hosts | health, pressure, heartbeat, and capacity | health logs, drain and quarantine audit |
| Runtime and guest | prepare, boot, handshake, and exec outcomes | adapter and protocol traces, runtime audit |
| Networking | setup, policy, DNS, traffic, lease, and cleanup outcomes | network traces, flow metadata, enforcement audit |
| Images | prepare, cache, verification, and rejection | image traces and verification audit |
| Snapshots | capture, restore, fork, compatibility, and exclusion | snapshot traces and integrity audit |
| Cleanup | pending age, drift, orphan, and ambiguity | reconciliation traces and disposition audit |
| Audit | enqueue, lag, backlog, dead letter, and integrity | audit delivery and disposition records |
| Telemetry | export, lag, queue, sampling, redaction, and overflow | exporter diagnostics and readiness decisions |

Dashboard dimensions are limited to deployment, region, cell, service,
operation, phase, outcome, reason, backend, workload class, health state,
resource class, network class, snapshot profile, and cache result.

Alert categories cover SLO burn, regional lifecycle failure, capacity
exhaustion, host degradation or quarantine, cleanup drift, resource pressure,
audit delivery or integrity failure, telemetry loss, cardinality overflow,
and security events. Every alert identifies an owner, severity, dashboard,
and runbook category. Lifecycle failure runbooks live in
[docs/runbooks](docs/runbooks/README.md) and must not require unapproved
host mutation.

---

## 14. Scale and Production Readiness

PicoCompute is designed around explicit scale targets, but production limits must be validated.

### 14.1 Design targets

| Target | Goal |
|---|---:|
| External API traffic | 10k RPS |
| Active sandboxes | 500k |
| Sandbox creations | 50k/min region-wide |
| Warm snapshot restore | p50 < 200ms |
| Warm snapshot restore | p99 < 1000ms |
| gVisor cold start | p50 < 500ms |
| microVM cold start | p50 < 1500ms |
| Fork | p50 < 100ms |
| Destroy | p99 < 2s |
| Control plane availability | 99.99% |

These are architecture targets, not production guarantees until validation is complete.
Production SLOs, SLIs, error budgets, burn alerts, and rollout freeze are
[slo-error-budget-policy](docs/observability/slo-error-budget-policy.md).
The scale validation strategy, launch proven operating point, scenario
catalog, and class-A/B/C failure rules are
[ADR-0012](docs/adr/0012-production-scale-validation-strategy.md).

### 14.2 Validation areas

Scale validation covers the ADR-0012 target axes:

- API request rate
- sandbox creation rate
- active sandbox count
- exec concurrency
- cell unavailability behavior
- host pressure behavior
- snapshot restore pressure
- image cache behavior
- audit/observability pipeline throughput

Phased evidence runs from local/CI smoke through host characterization,
cell validation, regional candidate, and the G-14 evidence bundle.
Launch quotas must stay at or below the measured launch proven operating
point for the exact deployment profile.

### 14.3 Capacity model

 classifies measured active-sandbox and exec density into
safe, warning, and saturation zones and compares scheduler advertised
packing with measured admits. Zone thresholds and unproven packing
defaults live in
[active-sandbox-defaults](docs/capacity/active-sandbox-defaults.md).
Warning is the LPOP cap; P0/P1 reports must not set regional quotas.

 classifies S-FAIL-HOST, S-FAIL-CELL, and S-RECOVER drills.
Unavailable cells and hosts stop receiving new placements; running
sandboxes are unchanged by the scheduler. Backpressure is shed
(`should_throttle` or `schedule` `Err`), not retry. Recovery report:
[cell-unavailability](docs/capacity/cell-unavailability.md).

 classifies S-RAMP-RESTORE, S-SPIKE-RESTORE, and S-SOAK-RESTORE
observations into safe, warning, and saturation zones and records restore
p50/p95/p99 by snapshot kind and storage tier plus cache hit/miss.
Partial cleanup is a bad restore. P0/P1 reports must not set regional
quotas. Restore pressure defaults:
[checkpoint-load](docs/capacity/checkpoint-load.md).

 classifies S-CACHE-COLD, S-CACHE-WARM, and S-CACHE-THRASH
observations into safe, warning, and saturation zones and records
prepare/verify/overlay p50/p95/p99 by image profile, cache tier, and
host SKU plus hit/miss/eviction. Unsigned, unpinned, or unverified
images served from cache are class-A. P0/P1 reports must not set
regional quotas. Image cache defaults:
[image-cache](docs/capacity/image-cache.md).

The capacity model converts ADR-0012 validation outputs into:

- host count
- cell size
- region capacity
- cache sizing
- storage estimates
- cost by workload class
- headroom policy
- rollout limits

`pico_core::cost_model` plans from the four P0 reports plus caller
demand and a pluggable price book. P0/P1 evidence authorizes no rollout
limit; P2 authorizes preview only; beta and production need P3.
Sensitivity analysis, confidence, and unknowns live in
[cost-model](docs/capacity/cost-model.md).

### 14.4 Rollout checklist

Production rollout requires evidence for:

- control-plane readiness
- host-runtime readiness
- backend readiness
- guest-protocol readiness
- [networking readiness](docs/robustness/network-prod-readiness-report.md)
- [image-pipeline readiness](docs/robustness/image-prod-readiness-report.md)
- snapshot/fork readiness
- security assurance
- observability and SLO readiness, including current burn and remaining
  budget from [slo-error-budget-policy](docs/observability/slo-error-budget-policy.md)
- scale validation per [ADR-0012](docs/adr/0012-production-scale-validation-strategy.md)
- cost/capacity planning
- rollback and incident response

The [production readiness model](docs/security/production-readiness.md)
defines the gate contract and stage thresholds. consumes its approved
gate records as the final staged-rollout checklist.

---

## 15. Implementation Phases

### Phase 0: Architecture decisions

- lifecycle ownership ADR
- public lifecycle API
- metadata state machine
- host runtime ADR
- backend strategy ADR
- protocol ADR
- security posture ADR
- telemetry ADR
- scale validation ADR ([ADR-0012](docs/adr/0012-production-scale-validation-strategy.md))

### Phase 1: MVP runtime path

- host-agent skeleton
- sandboxd supervisor
- RuntimeBackend interface
- Firecracker adapter
- minimal image
- guest-agent handshake
- boot lifecycle
- exec lifecycle
- destroy cleanup

### Phase 2: Zero-trust data plane

- access lease manager
- per-sandbox networking
- egress and DNS policy
- controlled port forwarding
- secrets broker integration
- audit pipeline

### Phase 3: Snapshot and fork

- snapshot metadata
- quiesce/resume protocol
- base restore
- COW workspace branching
- memory restore
- snapshot integrity
- cache tiering

### Phase 4: Backend expansion

- gVisor adapter
- QEMU adapter
- Cloud Hypervisor evaluation
- Kata evaluation
- backend conformance suite

### Phase 5: Production readiness

- boundary validation
- side-channel/covert-channel assessment
- service dashboards
- SLOs
- runbooks
- load validation
- capacity model
- rollout checklist

---

## 16. Repository Layout

```text
picocompute
├── crates
│ ├── pico-api # Public Platform API (REST/gRPC gateway)
│ ├── pico-cli # CLI tooling (pc)
│ ├── pico-core # Shared domain types, errors, and utilities
│ ├── pico-edge # Edge-routed session proxy
│ ├── pico-guest-agent # Guest-side agent (runs inside sandbox)
│ ├── pico-guest-protocol # Versioned host/guest RPC protocol (protobuf)
│ │ └── proto # Protocol buffer definitions
│ ├── pico-host-agent # Host-side lifecycle supervisor per cell
│ ├── pico-image # Guest image build pipeline (rootfs + kernel)
│ ├── pico-network-agent # Per-sandbox DNS proxy + NAT/egress gateway
│ ├── pico-runtime # Sandbox runtime abstraction (Firecracker, gVisor, QEMU, Kata)
│ ├── pico-runtime-hardening # Runtime hardening: namespaces, eBPF syscall audit + anomaly detection
│ │ # Lifecycle: register_sandbox_audit(id, cgroup, sandbox_type_key(image, workload),...)
│ ├── pico-sandboxd # Sandbox lifecycle daemon (create, start, stop, destroy)
│ ├── pico-sandboxd-proto # host-agent <-> sandboxd gRPC proto (Interface 1)
│ │ └── proto # pico.sandboxd.v1 definitions
│ ├── pico-seccomp # Seccomp profile compiler and policies
│ │ └── profiles # Compiled seccomp profiles
│ └── pico-telemetry # Standardized metrics, logs, traces, audit events
├── docs
│ ├── adr # Architecture Decision Records (0001-0011)
│ ├── design # Design notes (sandboxd process split, RPC)
│ ├── api
│ │ └── v2 # OpenAPI spec, examples, and test fixtures
│ ├── observability
│ │ └── distributed-tracing.md
│ ├── runbooks # Lifecycle failure runbooks and incident drills
│ ├── robustness # Misuse-resistance checklist and prod-readiness reports
│ └── security # Threat model, production readiness, assurance case, privileged helpers
├── o11y # Grafana dashboards and Prometheus recording/alert rules
├── infra
│ └── templates # Cloud-init templates for compute hosts
├──.github
│ ├── workflows # CI: test, audit, semgrep, release-cli
│ └── actions # Reusable composite actions (install-linux-deps)
├──.agents
│ ├── prompts # Agent prompt templates
│ └── skills # Agent skill definitions
├── scripts # Build, lint, smoke-test, and asset upload scripts
├── assets # Static assets (icons, etc.)
├── AGENTS.md # Agent coding conventions
├── ARCHITECTURE.md # This document
├── README.md # Project overview and quickstart
├── Cargo.toml # Workspace manifest
├── Cargo.lock
├── rust-toolchain.toml # Pinned Rust toolchain
├── mise.toml # mise-en-place tool configuration
└── LICENSE
```

---

## 17. Open Questions

- Should lazy restore be a v1 feature or a post-v1 optimization?
- What is the right cell size and failure-domain boundary? ADR-0012 treats
  this as a output from measured LPOPs, not an architecture constant.
- What side-channel/covert-channel risks are acceptable for first launch?

---

## 18. Related Documents

- `docs/adr/` - Architecture Decision Records (all 12 ADRs)
- `docs/api/v2/openapi.yaml` - Platform API specification
- `docs/security/threat-model.md` - Security threat model
- `docs/security/production-readiness.md` - Production security posture
- `docs/security/assurance-case.md` - Security assurance case
- `docs/robustness/misuse-resistance-checklist.md` - Protocol misuse-resistance checklist
- `docs/runbooks/README.md` - Operational runbooks for lifecycle failures
- `docs/observability/distributed-tracing.md` - Distributed tracing design
- `README.md` - Project overview and quickstart
- `AGENTS.md` - Agent coding conventions
