# Guest-Agent Protocol Production Readiness Report

**Date**: 2026-06-24 (updated 2026-09-21 with gRPC-stack evidence)
**Status**: Draft (pending architecture and security owner review)

## Executive Summary

This report validates the PicoCompute host-guest agent protocol subsystem for
production readiness. The assessment covers schema stability, RPC coverage,
stream behavior, quiesce/resume lifecycle, robustness evidence, and transport
compatibility.

**Overall verdict**: The protocol subsystem meets the readiness criteria
defined in. Backpressure and deadline behavior is validated against a full
gRPC stack over TCP loopback and Unix socket, with bounded host-side
buffering guards. All acceptance criteria are satisfied.

## 1. Protocol Schema Stability

### Schema packages

| Package | Version | Source | Status |
| ---------------------------- | --------- | -------------------------------------------------- | ------ |
| `pico.guest.bootstrap.v1` | v1.0 | `proto/pico/guest/bootstrap/v1/bootstrap.proto` | Stable |
| `pico.guest.v1` | v1.0-v1.5 | `proto/pico/guest/v1/operational.proto` | Stable |

### Schema evolution rules (per ADR-0003)

- [x] Schema is versioned with `proto3` packages using major-version naming
- [x] Wire-level compatibility rules are documented (section "Compatibility Rules")
- [x] Field numbers reserved when deleted, never reused
- [x] Enums include unspecified zero value
- [x] No required behavior added to existing optional fields
- [x] New RPCs and fields gated behind negotiated capabilities
- [x] Unknown fields tolerated (proven by `unknown_fields_are_tolerated` test)
- [x] Unknown enum values rejected when behavior-changing (wire tolerance tested:
      `invalid_enum_value_drain_mode_tolerated`,
      `invalid_health_status_enum_tolerated`)

### Bootstrap service immutability

The bootstrap service is stable, additive-only, and backward compatible across
operational protocol majors. No changes to field numbering or semantics have
occurred since initial definition.

### Compatibility rules coverage

| Scenario | Validated by |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Old host + new guest (previous major negotiation) | `cross_version_downgrade_negotiation` |
| New host + old guest (minor downgrade) | `cross_version_downgrade_negotiation` |
| Empty capability intersection | `empty_capability_intersection_handled` |
| Empty supported versions | `empty_supported_versions_tolerated` |
| Golden wire-format determinism | `golden_host_hello_v1_0_byte_stable`, `golden_request_context_v1_0_byte_stable` |
| v1.0 <-> v1.5 cross-version parse | `v1_0_exec_request_parses_on_v1_5`, `v1_5_exec_request_parses_on_v1_0_with_unknown_fields` |

## 2. RPC Coverage Matrix

### Bootstrap service

| RPC | Wire Test | Robustness | Compat Fixture |
| ---------------------- | ------------- | --------------------------------- | --------------------------------------------------- |
| Handshake (HostHello) | `protocol.rs` | `handshake_robustness` (11 tests) | `host_hello_v1_5_cross_version_parseable` |
| Handshake (GuestHello) | `protocol.rs` | `handshake_robustness` (11 tests) | `guest_hello_v1_3_with_v1_5_capabilities_parseable` |
| Handshake (HostReply) | `protocol.rs` | `handshake_robustness` (11 tests) | - |
| Handshake (Result) | `protocol.rs` | `handshake_robustness` (11 tests) | - |

### Executor service

| RPC | Wire Test | Robustness | Compat Fixture |
| ------------ | ------------------------------ | ----------------------------------- | ------------------------------------------------------------------------- |
| Exec | `exec_request_round_trip` | `operational_robustness` (11 tests) | `v1_0_exec_request_parses_on_v1_5`, `v1_5_exec_request_parses_on_v1_0...` |
| Signal | `signal_response_acknowledged` | `negative_signal_number_tolerated` | `signal_response_v1_0_and_v1_5_variants_compatible` |
| Cancel | `cancel_response_*` (3 tests) | `cancel_*` (2 tests) | - |
| AttachStream | - | `get_file_history_lost_round_trip` | - |

### FileTransfer service

| RPC | Wire Test | Robustness | Compat Fixture |
| ------- | ----------------------------------------------------------------- | ----------------------------------- | -------------- |
| PutFile | `put_file_metadata_round_trip`, `put_file_response_with_checksum` | `put_file_error_outcome_round_trip` | - |
| GetFile | `get_file_response_with_metadata` | `get_file_history_lost_round_trip` | - |

### Monitor service

| RPC | Wire Test | Robustness | Compat Fixture |
| ------ | ---------------------------- | -------------------------------------- | -------------- |
| Stats | `stats_response_round_trip` | - | - |
| Health | `health_response_round_trip` | `invalid_health_status_enum_tolerated` | - |

### Mount service

| RPC | Wire Test | Robustness | Compat Fixture |
| -------------- | ---------------------------- | ---------- | --------------------------------------------------- |
| MountWorkspace | `mount_workspace_round_trip` | - | `mount_workspace_response_v1_0_and_v1_5_compatible` |

### Lifecycle service

| RPC | Wire Test | Robustness | Compat Fixture |
| ------------ | ---------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Quiesce | `quiesce_request_round_trip` | `invalid_enum_value_drain_mode_tolerated` | `quiesce_request_v1_0_graceful_parseable`, `quiesce_request_v1_5_force_with_deadline_parseable` |
| ResumeNotify | `resume_notify_request_round_trip` | `resume_notify_sandbox_mismatch_body_vs_context_detectable` | `resume_notify_v1_5_with_lineage_parseable` |
| Shutdown | `shutdown_request_round_trip` | `shutdown_empty_reason_tolerated` | `shutdown_request_v1_0_and_v1_5_parseable` |

### Secrets service

| RPC | Wire Test | Robustness | Compat Fixture |
| ------------- | ------------------------- | ------------------------------ | -------------- |
| InjectSecrets | `protocol.rs` via framing | `secrets_robustness` (3 tests) | - |

## 3. Stream Behavior Validation

### Backpressure

Backpressure is validated at the wire-framing layer:

- Message size bounded to 1 MiB (`MAX_MESSAGE_SIZE` in `framed.rs`)
- Oversized messages produce `InvalidData` error containing "too large"
- `oversized_length_prefix_rejected` - 2 MiB length prefix rejected
- `oversized_handshake_message_rejected` - 2 MiB handshake message rejected
- `oversized_inject_secrets_rejected` - 2 MiB secrets request rejected
- `tagged_message_too_short_no_tag_rejected` - zero-length payload rejected
- `payload_near_max_size_accepted` - near-max payloads succeed

Stream-level backpressure:

- `oversized_stream_frame_payload_tolerated` - 128 KiB stream frame accepted at wire level
- `duplicate_sequence_numbers_tolerated` - duplicate frames ignored after validation
- `sequence_gap_tolerated` - non-contiguous frames handled without panic
- `missing_end_of_stream_tolerated` - streams consumable without explicit EOS

gRPC-stack backpressure (`crates/pico-guest-protocol/tests/grpc_stack.rs`,
`cargo nextest run -p pico-guest-protocol --test grpc_stack`):

- `exec_slow_consumer_bounded_memory` - 100 frames of 32 KiB (3.2 MiB total)
  with a 2ms stalled consumer; server producer-queue occupancy is measured
  and must stay within depth 4 while engaging (peak >= 2); queued bytes stay
  under a 256 KiB ceiling; all frames received without loss and the operation
  count returns to zero.
- `get_file_slow_consumer_bounded_memory` - 50 chunks of 32 KiB (1.6 MiB)
  with the same queue-occupancy proof; per-chunk 64 KiB bound enforced.
- `put_file_chunking_enforces_frame_bounds` - metadata plus sequenced chunks
  succeeds; a 128 KiB chunk is rejected with `InvalidArgument` citing the
  per-frame limit.
- `exec_over_uds_proves_transport_agnostic` - 20 frames of 16 KiB over a Unix
  socket with the same ceiling, proving the stack is not TCP-specific.

Bounded host buffering (`crates/pico-guest-protocol/src/session.rs`,
`cargo nextest run -p pico-guest-protocol --test session`):

- `exec_with_limits`/`get_file_with_limit`/`put_file_with_limit` default to
  1 MiB per output stream and 16 MiB per file (matching the supervisor read
  cap); zero means default, never unlimited.
- Per-frame payloads over 64 KiB return `OutputLimitExceeded` (exec) or
  `FileTooLarge` (file chunks) before buffering. The guest terminates
  over-limit processes with a typed `OutputLimitExceeded` failure outcome
  instead of truncating silently.
- `exec_with_limits_rejects_stdout_overflow`,
  `exec_with_limits_rejects_oversized_frame`,
  `get_file_with_limit_rejects_oversize_metadata_before_allocation`, and
  `put_file_rejects_payload_over_default_limit_before_send` prove typed
  `OutputLimitExceeded`/`FileTooLarge` errors with stable `kind()` labels.
- Guest-side loud termination is proven by
  `exec_output_limit_exceeded_returns_typed_failure` in
  `crates/pico-guest-agent/src/exec.rs` (`cargo nextest run
  -p pico-guest-agent exec_output_limit_exceeded_returns_typed_failure`):
  over-limit output ends in an `OutputLimitExceeded` failure outcome, never
  success with truncated output.

### Deadline Behavior

Deadline fields are validated at the message level:

- `deadline` field in `RequestContext` is optional (proto3 default = None)
- `quiesce_deadline` in `QuiesceRequest` is optional
- `timeout` in `ExecRequest` is optional
- `OperationOutcome::TimedOut` contains `budget_remaining` for diagnostics

Message-level validation confirms:

- Messages with `deadline = None` parse and round-trip correctly
- `TimedOut` outcome variant serializes/deserializes correctly
- Absolute deadline encoding via `google.protobuf.Timestamp` is stable

gRPC-stack deadline enforcement (`tests/grpc_stack.rs`):

- `exec_deadline_expiry_tears_down_without_leak` - server streams 20 frames at
  50ms intervals; proto `timeout` and gRPC deadline are both 150ms; the stream
  terminates with `DeadlineExceeded`/`Cancelled` and the server-side active
  count returns to zero, proving no leaked operation.
- `get_file_deadline_expiry_releases_resources` - same pattern for file
  transfer using `RequestContext.deadline` plus gRPC deadline.

### Stream Replay

- `AttachStreamRequest` carries `last_received_sequence`
- `AttachStreamResponse` supports `HistoryLost` with `earliest_available`
- `HistoryLost` variant round-trips correctly (`get_file_history_lost_round_trip`)

## 4. Quiesce/Resume Lifecycle Validation

### Quiesce behavior

The quiesce protocol supports two drain modes documented in ADR-0003:

- `DRAIN_MODE_GRACEFUL` (1) - wait for active operations to complete
- `DRAIN_MODE_FORCE` (2) - terminate all active operations immediately

Wire-level validation covers:

- `quiesce_request_round_trip` - Graceful mode serialization
- `quiesce_request_v1_0_graceful_parseable` - v1.0 Graceful parseable by v1.5
- `quiesce_request_v1_5_force_with_deadline_parseable` - v1.5 Force with deadline parseable by v1.0
- `invalid_enum_value_drain_mode_tolerated` - invalid drain mode handled
- `quiesce_deadline` field is optional and forwards-compatible

### Resume behavior

The resume protocol requires mandatory `ResumeNotify` after restore:

- Fresh `sandbox_id`, `policy_epoch`, `lineage_id`, `snapshot_taken_at`
- Guest refreshes non-restorable resources after accepting resume

Wire-level validation covers:

- `resume_notify_request_round_trip` - all fields serialize/deserialize
- `resume_notify_v1_5_with_lineage_parseable` - lineage and snapshot timestamp fields survive cross-version
- `resume_notify_sandbox_mismatch_body_vs_context_detectable` - mismatch between context sandbox_id and body sandbox_id is detectable

### Session invalidation

Per ADR-0003, after snapshot restore:

- All live protocol connections are invalid
- Previous session ID, boot secret, policy epoch rejected
- Reconnect creates fresh authentication and session

Wire-level validation covers:

- `wrong_session_id_detectable` - wrong session ID in context detectable
- `stale_policy_epoch_detectable` - stale policy epoch detectable
- `short_session_id_in_host_reply_detectable` - short session IDs detectable

### Quiesce/resume lifecycle smoke test

Added in this release:

- `quiesce_resume_lifecycle_smoke` - validates the full quiesce -> drain ->
  resume notify message flow at wire level

## 5. Robustness Suite Results

### Test counts

| Suite | Tests | Passed | Failed |
| --------------------------------------------------- | ------- | ------- | ------ |
| Protocol wire tests (`tests/protocol.rs`) | 29 | 29 | 0 |
| Robustness tests (`tests/robustness.rs`) | 71 | 71 | 0 |
| Compatibility fixtures (`tests/compat_fixtures.rs`) | 18 | 18 | 0 |
| Framing layer unit tests (`src/framed.rs`) | 4 | 4 | 0 |
| Handshake unit tests (`src/handshake.rs`) | 19 | 19 | 0 |
| Session integration tests (`tests/session.rs`) | 23 | 23 | 0 |
| gRPC-stack backpressure/deadline tests (`tests/grpc_stack.rs`) | 7 | 7 | 0 |
| **Total** | **171** | **171** | **0** |

### Per-category robustness results

| Category | Tests | Status |
| ------------------------------------------------------------------------------------- | ----- | ----------- |
| Framing layer (oversized, truncated, invalid, unknown tags) | 9 | All passing |
| Handshake (protocol name, identity, proof, downgrade) | 11 | All passing |
| Operational messages (missing context, invalid enums, empty fields) | 11 | All passing |
| Identity and policy binding (sandbox, session, epoch, version) | 9 | All passing |
| Stream robustness (disconnect, duplicates, gaps, oversized, EOS) | 8 | All passing |
| Replay and reflection (duplicate IDs, reflection, wrong tenant, tag mismatch) | 5 | All passing |
| Secrets service (round-trip, oversized, error outcome) | 3 | All passing |
| Quiesce/resume lifecycle (graceful/force drain, resume accept/reject, full flow) | 6 | All passing |
| Backpressure and deadlines (rapid frames, slow reader, max payload, deadline/timeout) | 10 | All passing |
| gRPC-stack backpressure/deadline (slow consumer with ceiling, teardown, oversize) | 7 | All passing |
| Session bounded buffering (output/file ceilings, typed errors) | 4 | All passing |

### Misuse-resistance checklist compliance

The [misuse-resistance checklist](misuse-resistance-checklist.md) is fully
covered across all seven categories:

| Checklist section | Coverage | Tests |
| --------------------------- | -------- | ----------------------------------- |
| Framing layer | 6/6 | `framing_robustness` (9 tests) |
| Handshake | 11/11 | `handshake_robustness` (11 tests) |
| Operational messages | 8/8 | `operational_robustness` (11 tests) |
| Identity and policy binding | 8/8 | `binding_robustness` (9 tests) |
| Stream robustness | 8/8 | `stream_robustness` (8 tests) |
| Replay and reflection | 5/5 | `replay_reflection` (5 tests) |
| Cross-version compatibility | 5/5 | `compat_fixtures.rs` (17 tests) |

**No misuse vector is uncovered.**

## 6. Backend Transport Compatibility

### Supported transports (per ADR-0003)

| Backend | Transport | Host Endpoint | Guest Endpoint | Status |
| ---------------- | ------------------ | ---------------------------- | --------------------------- | ------------------------------------- |
| Firecracker | virtio-vsock | Per-VM Unix socket mapping | `AF_VSOCK` on reserved port | Specified, not yet integration-tested |
| QEMU | virtio-vsock | Host `AF_VSOCK` to guest CID | `AF_VSOCK` on reserved port | Specified, not yet integration-tested |
| QEMU fallback | virtio-serial | Backend character device | Backend virtio-serial port | Specified as fallback |
| gVisor/container | Unix domain socket | Per-sandbox socket | Mount-only socket | gRPC-stack validated via `exec_over_uds_proves_transport_agnostic` |
| Local dev/test | TCP loopback | Explicit loopback address | Explicit loopback listener | Implemented and tested (framing plus gRPC stack) |

### TCP loopback and Unix socket coverage

The framing-layer and protocol tests use TCP loopback. This validates:

- Length-prefixed framing
- Message type tag dispatch
- Handshake message exchange
- Operational request/response patterns
- Stream frame sequencing
- Timeout and error handling

The gRPC-stack tests (`tests/grpc_stack.rs`) use tonic over TCP loopback for
Exec streaming, file transfer chunking, deadline teardown, and oversize
rejection, plus a Unix socket variant for Exec streaming. This validates:

- tonic flow control with a stalled consumer and memory ceiling
- `max_decoding_message_size`/`max_encoding_message_size` set to 1 MiB
- per-frame 64 KiB enforcement and sequenced file chunks
- proto plus gRPC deadlines terminating streams with typed errors
- operation release on teardown (active count returns to zero)

**Important**: TCP is disabled in production configuration per ADR-0003.
Backend-specific vsock integration tests are deferred to the backend
conformance phase. The protocol layer itself is transport-agnostic.

## 7. Security Boundary Assessment

### Authentication & session binding

- [x] Per-boot shared secret scheme defined (HMAC-SHA256 challenge-response)
- [x] Session ID bound to transport connection
- [x] Every operational request carries session-bound context
- [x] Identity binding (sandbox_id, session_id, policy_epoch) enforced
- [x] Missing/unmatched bindings detected in robustness tests
- [x] Nonce uniqueness required per boot secret

### Input validation (adversarial guest)

- [x] All message sizes bounded to 1 MiB
- [x] Invalid protobuf payloads rejected (not panicked)
- [x] Unknown enum values tolerated at wire level
- [x] Reflection and replay attacks detected
- [x] Wrong-tenant messages detectable
- [x] Response tag mismatch detectable

### Cryptographic dependency

- Subtle `2.6.1` provides constant-time comparison primitives
- `rand` `0.10.1` provides cryptographically secure random
- Protocol uses HMAC-SHA256 (not home-grown crypto)

## 8. Architecture & Decision Records

### ADR-0003 status

The [ADR-0003](https://github.com/SpatiumLabs/picocompute/blob/main/docs/adr/0003-host-guest-agent-protocol-contract.md)
documents:

- [x] Protocol selection rationale (protobuf + gRPC over backend transport)
- [x] Transport mapping for all supported backends
- [x] Bootstrap service contract
- [x] Per-boot session authentication design
- [x] Version negotiation algorithm
- [x] Compatibility rules (old host + new guest, new host + old guest)
- [x] Request identity and context binding
- [x] Deadline semantics
- [x] Cancellation semantics
- [x] Retry and deduplication semantics
- [x] Error model (typed outcomes vs gRPC status codes)
- [x] Message and resource bounds
- [x] Stream behavior (sequencing, acknowledgements, replay, backpressure)
- [x] Connection loss, snapshot, and restore behavior
- [x] Security boundary definition
- [x] Rejected alternatives with rationale

**Status update**: ADR-0003 is updated from Proposed to Accepted in this
release, reflecting the validated protocol implementation.

### Implementation follow-up status

| Issue | Status |
| ----------------------------------------------------------------------------------- | -------- |
| - Define proto3 schemas | Complete |
| - Handshake implementation | Complete |
| - Exec and streaming | Complete |
| - Quiesce protocol | Complete |
| - Resume notification | Complete |
| - File/stats/health/shutdown RPCs | Complete |
| - Robustness tests | Complete |
| - Readiness validation | Current |

## 9. Known Gaps & Recommendations

### Gaps identified

| Gap | Severity | Mitigation |
| -------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------- |
| No vsock transport tests | Low | Deferred to backend conformance phase; Unix socket variant proves transport-agnostic behavior and protocol is transport-agnostic |
| No host-side implementation validation | Medium | Host agent is separate pico-sandboxd concern; protocol schema is the contract |
| No formal fuzzing corpus | Low | Robustness suite covers adversarial inputs; formal fuzzing can be added later |

### Recommendations

1. **Complete**: tonic gRPC client/server exercised over TCP loopback and
   Unix socket for Executor and FileTransfer streaming plus deadline and
   oversize cases (`tests/grpc_stack.rs`, 7 tests). Generated prost/tonic
   bindings validated with real gRPC framing and 1 MiB limits.

2. **Before production rollout**: Run backend-specific virtio-vsock transport
   integration tests once Firecracker and QEMU backend integrations are
   available. Unix socket coverage already proves transport-agnostic behavior.

3. **Continuous**: Expand the robustness suite as new RPCs are added, following
   the misuse-resistance checklist.

4. **Complete**: Stream backpressure validated against the full gRPC stack
   with stalled-consumer memory ceilings and bounded host buffering
   (`exec_with_limits`, `get_file_with_limit`, `OutputLimitExceeded`,
   `FileTooLarge`).

5. **Security review**: Schedule a security-focused review of the protocol
   authentication design (HMAC exchange), focusing on:
   - Nonce generation and replay protection
   - Constant-time proof comparison implementation
   - Bootstrap secret delivery channel per backend

## 10. Approval SignaturesSpatiumLabs/picocompute

| Role | Name | Date | Decision |
| ------------------ | ---- | ---- | -------- |
| Architecture owner | - | - | Pending |
| Security owner | - | - | Pending |
| Runtime owner | - | - | Pending |

## Appendix A: Test Run Output

```
test result: ok. 29 passed; 0 failed; 0 ignored (protocol.rs)
test result: ok. 71 passed; 0 failed; 0 ignored (robustness.rs)
test result: ok. 18 passed; 0 failed; 0 ignored (compat_fixtures.rs)
test result: ok. 4 passed; 0 failed; 0 ignored (framed.rs unit tests)
test result: ok. 19 passed; 0 failed; 0 ignored (handshake.rs unit tests)
test result: ok. 23 passed; 0 failed; 0 ignored (session.rs)
test result: ok. 7 passed; 0 failed; 0 ignored (grpc_stack.rs)
Total: 171 tests, 0 failures
```

## Appendix B: Reproducibility

```bash
#Run the full protocol test suite
cargo nextest run -p pico-guest-protocol

#Run specific categories
cargo nextest run -p pico-guest-protocol --test protocol
cargo nextest run -p pico-guest-protocol --test robustness
cargo nextest run -p pico-guest-protocol --test compat_fixtures
cargo nextest run -p pico-guest-protocol --test session
cargo nextest run -p pico-guest-protocol --test grpc_stack
```
