# Misuse-Resistance Checklist for New RPCs

This checklist ensures every new RPC added to the PicoCompute host-guest
protocol is tested against the misuse and robustness vectors identified
in the protocol threat model and verified by the
`pico-guest-protocol` robustness test suite.

## Before merging a new RPC

Run through each category and add at least one test case per item, or
document why the item does not apply.

---

### Framing layer

- [ ] Oversized length prefix (exceeds 1 MiB max) - verify rejection
- [ ] Truncated length prefix (fewer than 4 bytes) - verify handling
- [ ] Truncated payload (length claims more bytes than sent) - verify handling
- [ ] Invalid protobuf payload (garbage bytes) - verify rejection
- [ ] Zero-length tag + payload (valid) - verify parseable
- [ ] New request/response tag constants defined and collision-free

### Handshake

- [ ] Wrong `protocol_name` in HostHello - verify rejection
- [ ] Missing `host_nonce` - verify detection
- [ ] Missing `bootstrap_version` - verify handling
- [ ] Empty `supported_versions` - verify semantic rejection
- [ ] Identity mismatch (`image_id`, `image_digest`) - verify rejection
- [ ] Missing HMAC `proof` in GuestHello - verify detection
- [ ] Short `session_id` (< 16 bytes) in HostReply - verify detection
- [ ] Missing `outcome` in HandshakeResult - verify handling
- [ ] Invalid `ErrorCode` in HandshakeResult - verify handling
- [ ] Cross-version downgrade negotiation - verify correct version selected
- [ ] Empty capability intersection - verify rejection

### Operational messages

- [ ] Missing `RequestContext` - verify handling
- [ ] Empty `command` string in ExecRequest - verify handling
- [ ] Invalid enum values (e.g., DrainMode, HealthStatus) - verify parsing
- [ ] Negative signal number in SignalRequest - verify handling
- [ ] Empty `reason` in ShutdownRequest - verify handling
- [ ] `OperationOutcome` with missing `status` - verify handling
- [ ] All `OperationOutcome` oneof variants (Success, Failure, Canceled,
  TimedOut, Unsupported, RequiresReview) - verify round-trip
- [ ] All response result oneof variants - verify round-trip

### Identity and policy binding

- [ ] Wrong `sandbox_id` in RequestContext - verify detectable
- [ ] Wrong `session_id` in RequestContext - verify detectable
- [ ] Stale `policy_epoch` in RequestContext - verify detectable
- [ ] Wrong `protocol_version` in RequestContext - verify detectable
- [ ] Empty `session_id` (zero-length bytes) - verify detectable
- [ ] Empty `request_id` - verify handling
- [ ] Empty `operation_id` - verify handling
- [ ] Mismatch between context and body fields (e.g., sandbox_id in
  ResumeNotifyRequest) - verify detectable

### Stream robustness

- [ ] Abrupt disconnect during streaming - verify no panic
- [ ] Missing `end_of_stream` flag on last frame - verify consumable
- [ ] Duplicate frame sequence numbers - verify handling
- [ ] Sequence gap (non-contiguous frames) - verify handling
- [ ] `StreamAck` with valid `highest_contiguous` - verify round-trip
- [ ] `StreamFrame` with sequence = 0 - verify handling
- [ ] Oversized `StreamFrame` payload (> 64 KiB, within 1 MiB) - verify handling
- [ ] Response tag mismatch (wrong response tag for stream type) - verify detectable

### Replay and reflection

- [ ] Duplicate `request_id` - verify detectable
- [ ] Duplicate `operation_id` - verify detectable
- [ ] Reflection: sending response-type message with request tag - verify no panic
- [ ] Wrong-tenant: sandbox mismatch vs session scope - verify detectable
- [ ] Response tag mismatch (wrong response tag for request type) - verify detectable

### Cross-version compatibility

- [ ] v1.0-encoded messages parseable by v1.5 peer
- [ ] v1.5-encoded messages parseable by v1.0 peer
- [ ] Unknown fields added in later minor versions are tolerated
- [ ] Version field in RequestContext is correctly packed as `(major << 16) | minor`
- [ ] Golden wire-format stability: known messages produce deterministic bytes

### General invariants

- [ ] No test panics on malformed input (verify all error paths return typed errors)
- [ ] Oversized messages always produce an error containing "too large"
- [ ] Deadline fields, when absent, are tolerated (None/default)
- [ ] All tests run in CI (`cargo nextest run`)
- [ ] New message types have at least one robustness test per misuse vector
