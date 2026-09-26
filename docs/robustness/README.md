# Protocol Robustness Tests

Protocol robustness tests validate that the PicoCompute host-guest protocol
boundary resists malformed, stale, replayed, reflected, oversized, and
adversarial messages without panicking or producing unsafe lifecycle
transitions.

## Documents

- [Misuse-Resistance Checklist](misuse-resistance-checklist.md) - Checklist
  to run before merging any new RPC. Covers framing, handshake, operational,
  binding, stream, replay/reflection, and cross-version categories.
- [Fuzz and Property Evidence](fuzz-property.md) - cargo-fuzz targets, proptest
  suites, seed corpus, CI seeded runs, and nightly long fuzz jobs.

## Test suite

```bash
# Run the full robustness suite
cargo nextest run -p pico-guest-protocol

# Run only robustness tests
cargo nextest run -p pico-guest-protocol --test robustness

# Run only compatibility fixtures
cargo nextest run -p pico-guest-protocol --test compat_fixtures
```

## Coverage

The test suite covers:

- **Framing layer** (9 tests): oversized, truncated, invalid tags
- **Handshake** (12 tests): wrong protocol, identity mismatch, version/capability negotiation
- **Operational** (12 tests): missing context, invalid enums, edge cases
- **Binding** (9 tests): sandbox ID, session ID, policy epoch, protocol version
- **Stream** (7 tests): disconnect, EOS, duplicates, gaps, oversized frames
- **Replay/reflection** (5 tests): duplicate IDs, reflected messages, wrong-tenant
- **Compatibility** (28 tests): v1.0 <-> v1.5 cross-version parsing

## Splitting policy

When `tests/robustness.rs` exceeds ~3000 lines, split each module into
its own file under `tests/robustness/`. See the file header for details.
