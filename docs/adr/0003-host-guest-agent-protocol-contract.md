# ADR-0003: Host/Guest Agent Protocol Contract

**Status**: Accepted (pending final architecture and security owner approval)
**Date**: 2026-06-11
**Updated**: 2026-06-24
**Milestone**: M0 - Host Guest Protocol ADR
**Readiness Report**: [Readiness Report](../robustness/guest-agent-proto-prod-readiness-report.md)
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md)

## Context

PicoCompute needs a stable contract between the host runtime and the guest agent.
The two sides evolve on different schedules:

- host software is rolled out across cells and execution hosts
- guest-agent versions are embedded in signed images and warm snapshots
- runtime backends expose different local transport mechanisms
- active operations and streams may outlive one connection
- snapshot restore invalidates live transport connections and runtime secrets

The current prototype sends unframed JSON over guest TCP. It has no protocol
version negotiation, authenticated session binding, bounded message size,
stream backpressure, operation deduplication, or restore-safe reconnect
contract. It is suitable for local development but not for a production trust
boundary.

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md)
requires the host agent to prove guest readiness before reporting a sandbox as
`Running`.
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md)
assigns guest transport supervision, operation deadlines, cancellation, and
stream handles to `sandboxd`. This ADR defines the protocol those components
must implement.

## Decision

PicoCompute selects **Protocol Buffers using `proto3` with tonic gRPC over a
backend-provided local byte stream**.

The protocol is host initiated. The host opens the transport, authenticates a
per-sandbox session, negotiates a protocol version and capability set, and then
invokes operational RPCs. The guest agent never exposes the control protocol
through the sandbox network in production.

Concrete `.proto` schemas, generated Rust bindings, compatibility fixtures,
and RPC implementations are owned by
. This ADR owns the protocol
rules those schemas and implementations must satisfy.

### Protocol and Schema Ownership

The canonical source is the checked-in `proto3` schema. Generated code is not
hand edited.

Schema ownership follows these rules:

- `pico.guest.bootstrap.v1` owns the stable pre-negotiation handshake.
- `pico.guest.v{major}` owns operational RPCs for one protocol major.
- the guest-protocol maintainers review schema evolution
- Runtime and Security owners review changes to authentication, transport,
  identity binding, size limits, streaming, or compatibility policy
- every schema change includes compatibility fixtures before release

Protobuf Editions are not selected for the initial schema because the current
Rust generator stack documents proto2 and proto3 support while Editions
support remains incomplete.

### Transport Mapping

The gRPC service runs over one authenticated HTTP/2 connection carried by the
backend transport.

| Backend | Production transport | Host endpoint | Guest endpoint |
|---|---|---|---|
| Firecracker | virtio-vsock | Firecracker per-VM Unix socket mapping | `AF_VSOCK` listener on the reserved PicoCompute port |
| QEMU | virtio-vsock | host `AF_VSOCK` connection to the assigned guest CID | `AF_VSOCK` listener on the reserved PicoCompute port |
| QEMU fallback | virtio-serial byte stream | backend-owned character device | backend-owned virtio-serial port |
| gVisor or container | Unix domain socket | permission-controlled per-sandbox socket | socket mounted only into the sandbox runtime namespace |
| Local development and tests | TCP loopback | explicitly configured loopback address | explicitly configured loopback listener |

Transport requirements:

- the runtime adapter returns an already scoped `GuestTransport` to `sandboxd`
- each endpoint is dedicated to one sandbox
- the host initiates every production connection
- TCP is disabled in production configuration and is never readiness evidence
- transport selection is not exposed to tenants
- transport loss never changes lifecycle state by itself
- reconnect always creates a new authenticated protocol session

The QEMU virtio-serial path is a compatibility fallback only. Backends that
support vsock must use vsock.

### Stable Bootstrap Service

`pico.guest.bootstrap.v1` is the only service available before negotiation.
It remains additive and backward compatible across operational protocol
majors. An implementation that cannot serve this bootstrap contract is
incompatible with PicoCompute.

The bootstrap exchange carries:

- host and guest supported protocol major and minor ranges
- host and guest capability identifiers
- sandbox ID
- image ID and image manifest digest
- guest-agent build version and artifact digest
- guest boot ID
- host nonce and guest nonce
- guest authentication proof and host authentication proof
- selected protocol version and capability set
- connection-bound session ID

Identity values supplied by the guest are claims, not authority. The host
validates them against the scheduled sandbox, verified image manifest, backend
configuration, and locally assigned identity before readiness can succeed.

### Per-Boot Session Authentication

Every sandbox boot receives a fresh 256-bit authentication secret. The secret:

- is generated by the host from a cryptographically secure random source
- is unique to one sandbox boot
- is delivered through a protected backend bootstrap channel
- is never included in the image, workspace, logs, command environment,
  protocol messages, or snapshot payload
- is stored only for the active boot and zeroized when invalidated

The exact bootstrap delivery mechanism is backend specific and is implemented
with the guest-agent handshake work in
. Kernel command lines,
guest-network metadata services, and persistent disk files are not acceptable
delivery channels.

Authentication uses HMAC-SHA256 mutual challenge-response:

1. The host opens the scoped transport and sends `HostHello` with its nonce,
   expected identities, supported versions, and capabilities.
2. The guest responds with `GuestHello`, its nonce and identity claims, and an
   HMAC proof over the complete hello transcript with a guest role label.
3. The host validates the proof and identity claims, selects the highest
   compatible version and capability intersection, generates a random session
   ID, and returns an HMAC proof over the transcript and selection with a host
   role label.
4. The guest validates the host proof before enabling operational services for
   that connection.

Both proofs use a domain-separated transcript that includes:

- protocol name and bootstrap version
- role label
- sandbox ID, image ID, and boot ID
- host and guest nonces
- both advertised version ranges
- both advertised capability sets
- selected version and capability set
- session ID for the host proof

Proof comparison is constant time. Nonces are at least 256 random bits and
must never repeat for the same boot secret. A failed proof, identity mismatch,
or replay closes the connection and produces no operational session.

The session ID is at least 128 random bits. Every operational request carries
it and the guest accepts it only on the HTTP/2 connection that completed the
handshake. A reconnect must repeat authentication and receives a new session
ID.

This mechanism authenticates possession of the per-boot secret and binds the
connection to expected identities. It is not hardware attestation and does not
replace image signature, artifact digest, or backend integrity validation.

### Version Negotiation

Operational packages use major-version names such as `pico.guest.v1`.
Within a major, each implementation advertises a supported inclusive minor
range.

Negotiation selects:

1. the highest major supported by both sides
2. the highest minor in the overlapping range for that major
3. the intersection of capabilities valid for the selected version

If there is no overlapping major and minor range, authentication may complete
but operational negotiation fails. The host must not mark the sandbox ready.

Host releases and newly built guest agents must support:

- the current protocol major
- the immediately previous protocol major

Images may contain an older guest that supports only the previous major. A
host may remove support for that major only after the next major is released,
the image and snapshot inventory proves the older major is no longer needed,
and the deprecation has completed.

Capabilities are stable identifiers with documented request and response
semantics. A capability is enabled only when both peers advertise it.
Required capabilities are supplied by the host according to the requested
lifecycle operation and image profile. Missing required capabilities fail
readiness or reject the operation with a typed unsupported outcome.

### Compatibility Rules

Schema evolution within a major is additive:

- never reuse protobuf field numbers
- reserve deleted field numbers and names
- never reuse deleted enum numbers
- include an unspecified zero value for every enum
- do not change a field's wire type or established meaning
- do not add required behavior to an existing optional field
- add new RPCs and fields behind negotiated capabilities
- tolerate unknown fields
- reject unknown enum values when acting on them could change behavior
- preserve typed outcomes that older peers already understand

A breaking semantic or wire change requires a new operational major package.
The stable bootstrap service cannot be changed incompatibly.

#### Old Host and New Guest

| Host support | Guest support | Result |
|---|---|---|
| Previous major only | Current and previous major | Negotiate previous major |
| Older minor range | Newer overlapping minor range | Negotiate highest overlapping minor |
| Previous major only | Current major only | Incompatible; readiness fails |

The new guest ignores unknown fields from the old host, advertises only
capabilities it can honor under the negotiated version, and uses the old
major's established semantics.

#### New Host and Old Guest

| Host support | Guest support | Result |
|---|---|---|
| Current and previous major | Previous major only | Negotiate previous major |
| Newer minor range | Older overlapping minor range | Negotiate highest overlapping minor |
| Current major only | Previous major only | Incompatible; readiness fails |

The new host omits fields and capabilities unavailable in the selected
version. It must not infer support from guest-agent build version alone.

### Request Identity and Context

Every operational request includes a `RequestContext` with:

- `request_id`: unique identity for one transmission attempt
- `operation_id`: stable identity for one logical side-effecting operation
- `sandbox_id`: expected sandbox identity
- `session_id`: authenticated connection session
- `policy_epoch`: policy version admitted by the host
- `protocol_version`: negotiated major and minor
- `deadline`: absolute host deadline for audit and persistence

`request_id` changes for every retry. `operation_id` remains unchanged across
retries, reconnects, and status queries for the same logical operation.
Read-only requests may omit `operation_id` when they have no deduplication
requirement.

The guest rejects a request before side effects when its sandbox ID, session
ID, policy epoch, or protocol version does not match the authenticated
session. Request and operation IDs are opaque identifiers and are safe to log.

### Deadline Semantics

The host owns the absolute operation deadline and persists it according to
ADR-0002. For each attempt:

1. the host calculates the remaining budget from the original deadline
2. the host refuses to send an attempt with no remaining budget
3. the host sets the gRPC deadline to the remaining budget
4. the guest converts the received budget to a local monotonic deadline
5. every child action uses the same or an earlier deadline

The absolute timestamp in `RequestContext` is evidence and correlation data.
The guest does not extend work because of wall-clock skew. If the context
timestamp and gRPC budget disagree, both peers enforce the earlier deadline.

A retry never resets or extends the original operation deadline.

### Cancellation Semantics

gRPC cancellation stops waiting for the current call and asks the handler to
stop work associated only with that call. It is not durable operation
cancellation.

The explicit `Cancel` RPC targets an `operation_id` and is:

- idempotent
- valid from a newly authenticated session after reconnect
- acknowledged with a typed accepted, already-terminal, or unknown outcome
- propagated to the supervised process tree or lifecycle operation where
  supported

The terminal operation outcome distinguishes succeeded, failed, canceled,
timed out, unsupported, and requires review. Cancellation races resolve to the
first persisted terminal outcome.

### Retry and Deduplication Semantics

Automatic gRPC retries are disabled for mutating RPCs. `sandboxd` owns retry
decisions.

| Request class | Retry rule |
|---|---|
| Read-only request | Retry only for transport unavailability while budget remains |
| Side-effecting request not yet accepted | Retry with a new request ID and the original operation ID |
| Side-effecting request with unknown acceptance | Query operation status or resend with the original operation ID |
| Typed application failure | Do not retry unless that outcome explicitly declares itself retryable |
| Authentication or negotiation failure | Do not retry without a new transport and bootstrap attempt |
| Deadline exhausted | Do not retry |

The guest deduplicates side-effecting requests by sandbox ID and operation ID.
A duplicate returns the persisted or cached terminal outcome, continues the
same in-progress operation, or reports its current status. It must never start
a second operation.

The host ledger remains the durable source for operation retry state. The
guest retains enough per-boot operation identity and terminal outcome state to
deduplicate reconnects. Protocol schema work must define bounded retention and
an explicit operation-status query.

### Error Model

Application and lifecycle failures use typed protobuf outcomes. Examples
include invalid state, unsupported capability, busy, canceled, timed out,
history lost, output limit exceeded, and guest operation failure.

gRPC status codes are reserved for failures where a typed application response
cannot be trusted or produced:

- malformed or oversized request
- unauthenticated session
- permission or identity mismatch
- protocol negotiation failure
- transport unavailability
- server overload before operation admission

Once a side-effecting request is admitted, the guest records its operation ID
and returns or later exposes a typed outcome. A disconnected caller treats the
result as unknown and resolves it through operation status instead of assuming
failure.

### Message and Resource Bounds

All peers enforce these defaults:

| Resource | Limit |
|---|---:|
| Encoded protobuf message | 1 MiB |
| Stream payload per frame | 64 KiB |
| Replay buffer per output stream | 1 MiB |
| Compression | Disabled |

The 1 MiB message limit includes protobuf envelope and payload. File transfer,
stdio, and other larger data use streaming frames. Implementations configure
matching inbound and outbound gRPC limits and reject oversized data before
allocation where possible.

Compression is disabled by default to avoid decompression amplification,
unbounded CPU use, and inconsistent per-backend behavior. A future capability
may add a bounded compression mode after separate security and performance
review.

Every connection and operation also has bounded:

- concurrent RPC count
- active operation count
- stream count
- queued frame count
- aggregate buffered bytes

Concrete concurrency defaults are deployment configuration, but exceeding a
bound must produce backpressure or a typed resource-exhausted result, never
unbounded allocation.

### Stream Behavior

Exec output, stdin, file transfer, and future byte streams use explicit
application frames carried by gRPC streaming RPCs.

Each direction and logical stream has an independent sequence space:

- sequence IDs start at 1 and increase by one
- acknowledgements are cumulative through the highest contiguous sequence
- duplicate frames are ignored after validation
- a gap pauses delivery and requires replay or fails with a typed stream error
- end-of-stream and close are explicit frames

`AttachStream` identifies the operation and stream and supplies the last
acknowledged sequence. The guest replays later frames when they remain in the
bounded replay buffer.

If the requested sequence has been evicted, the guest returns a typed
`history_lost` outcome with the earliest available sequence. It never silently
skips bytes.

The replay buffer keeps at most 1 MiB per output stream. Acknowledged frames
are released promptly. When the host is slow:

- gRPC flow control and bounded application queues stop accepting new frames
- process output uses operating-system pipe backpressure
- file and stdin senders wait for capacity
- a source that cannot be paused terminates with a typed
  `output_limit_exceeded` outcome instead of dropping data

A stream disconnect does not by itself cancel its operation. The guest
continues the operation within its deadline and bounded buffers. The host may
reattach or explicitly cancel by operation ID.

### Connection Loss, Snapshot, and Restore

All live protocol connections and sessions are invalid after snapshot restore
or fork. Neither peer assumes an HTTP/2, vsock, Unix socket, or virtio-serial
connection survives.

Before a cooperative snapshot:

1. the host stops admitting new operations
2. the guest drains or rejects active operations according to quiesce policy
3. the guest invalidates the protocol session and zeroizes the boot secret
4. the guest confirms quiescence
5. the runtime captures the snapshot

After restore or fork:

1. the host provides a fresh per-boot secret through the protected bootstrap
   channel
2. the host opens a new transport
3. both peers repeat authentication and version negotiation
4. the host invokes `ResumeNotify` with fresh sandbox, policy, and lineage
   identity
5. the guest refreshes non-restorable resources
6. readiness succeeds only after `ResumeNotify` and health validation

The restored guest rejects the previous session ID, boot secret, policy epoch,
and operation authority. A child created by fork receives an independent
sandbox ID, boot secret, session, and operation namespace.

### Security Boundary

The guest and workload are untrusted. Host implementations treat every guest
field, frame, error, and stream transition as adversarial input.

Required controls include:

- per-sandbox transport endpoints
- authenticated connection-bound sessions
- identity and policy binding on every request
- constant-time authentication proof comparison
- strict message, frame, queue, and concurrency limits
- no guest-provided host paths
- no long-lived secret in images or snapshots
- no protocol listener on the guest network in production
- no lifecycle transition based only on guest claims

The HMAC exchange protects against endpoint confusion, replay across boots,
and unauthenticated use of a scoped transport. It does not make a compromised
guest trustworthy and does not grant the guest lifecycle authority.

## Consequences

### Positive

- Protobuf provides a mature, language-neutral, evolvable schema format.
- gRPC supplies standard streaming, deadlines, cancellation signaling, flow
  control, and status handling over any compatible byte stream.
- One protocol contract works across Firecracker, QEMU,
  gVisor, and
  container backends.
- Current and previous major support permits independent host and image
  rollouts.
- Per-boot authentication and connection binding prevent transport endpoint
  identity from becoming the only trust signal.
- Explicit bounds and replay semantics make streams testable under slow
  readers, reconnects, and adversarial input.
- Restore always creates fresh identity and session state.

### Negative

- tonic and HTTP/2 add code size and protocol complexity inside minimal guest
  images.
- Supporting two protocol majors increases host and guest test matrices.
- The bootstrap secret delivery channel requires backend-specific integration.
- Application-level stream sequencing and replay remain necessary even though
  gRPC provides connection-level flow control.
- Operation deduplication requires bounded guest state and durable host state.

## Rejected Alternatives

### gRPC over the Guest Network

The guest agent would listen on the sandbox TCP network and use standard gRPC
transport.

**Rejected**: It expands the network attack surface, couples readiness to
network configuration, complicates firewall policy, and risks exposing the
control protocol to tenant workloads or adjacent services. TCP remains
available only on loopback for local development and tests.

### Protobuf over Custom Framing

Protobuf messages would use a PicoCompute-owned length-delimited frame protocol
over vsock or Unix sockets.

**Rejected**: PicoCompute would need to design and maintain multiplexing, flow
control, stream lifecycle, deadlines, cancellation signaling, status mapping,
and reconnect behavior already available in gRPC. Custom application stream
frames are still used where replay semantics are required, but not as the RPC
transport.

### Cap'n Proto RPC

Cap'n Proto would provide schema and RPC support over the backend transports.

**Rejected**: It introduces a second ecosystem not otherwise used by PicoCompute,
has less alignment with the existing Rust dependency set, and adds security
review and operational expertise costs without a demonstrated requirement for
zero-copy message access.

### Unframed JSON over TCP

The current prototype format would be extended with more fields and timeouts.

**Rejected**: It has no intrinsic framing, weak schema evolution, no bounded
stream contract, no standard flow control, and uses the guest network. It
cannot safely support binary file and stdio streams or independent host and
image upgrades.

### Custom Binary Protocol

PicoCompute would define its own wire encoding and RPC state machine.

**Rejected**: The implementation and audit burden is disproportionate to the
requirements. A custom encoding would create compatibility, tooling, fuzzing,
and multi-language costs without a proven performance need.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Define bootstrap and operational `proto3` schemas, generate Rust bindings, and add compatibility fixtures |
| | Implement protected secret delivery, authenticated handshake, version negotiation, and readiness validation |
| | Implement operation deduplication, command RPCs, bounded streams, acknowledgements, and replay |
| | Implement quiesce, session invalidation, and pre-snapshot secret zeroization |
| | Implement post-restore authentication and mandatory `ResumeNotify` |
| | Implement bounded file, stats, health, mount, and shutdown RPCs |
| | Validate malformed input, replay, reflection, version downgrade, bounds, deadlines, and stream misuse |
| | Validate protocol readiness across supported backends and version combinations |

## References

- [Protocol Buffers proto3 language guide](https://protobuf.dev/programming-guides/proto3)
- [Protocol Buffers schema best practices](https://protobuf.dev/best-practices/dos-donts)
- [gRPC deadlines](https://grpc.io/docs/guides/deadlines)
- [gRPC flow control](https://grpc.io/docs/guides/flow-control)
- [Firecracker virtio-vsock design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
- [Firecracker snapshot transport behavior](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [prost Rust Protocol Buffers implementation](https://github.com/tokio-rs/prost)
- [prost Editions support tracking](https://github.com/tokio-rs/prost/issues/1031)

## Required Review

Protocol validation evidence is complete per
[Readiness Report](../robustness/guest-agent-proto-prod-readiness-report.md).
Final approval pending:

- Runtime owner
- Security owner

Once both roles approve, the ADR status is final and may close.
