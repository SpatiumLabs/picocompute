# Fuzz and Property Evidence

Fuzz and property tests are the detective controls for adversarial framing,
handshake, and boundary-parser inputs. Hand-written robustness cases pin known
vectors; the suites below explore randomized inputs and prove invariants hold.

## Property suites (run under nextest)

```bash
# Lifecycle state machine: no illegal jumps, terminal stays terminal, single-winner
cargo nextest run -p pico-core --test lifecycle_property

# Snapshot exclusion: secret mounts never captured
cargo nextest run -p pico-core --test snapshot_exclusion_property

# Backend selection: order fixed, floors never weaken, fail-closed gates
cargo nextest run -p pico-core --test backend_selection_property

# Protocol round-trip and compat: wire stability, version packing, negotiation
cargo nextest run -p pico-guest-protocol --test protocol_property

# Network policy parsing: CIDR, DNS first-wins, egress binding
cargo nextest run -p pico-network-agent --test policy_property
```

Each suite uses `proptest` with 256 cases by default. Failures shrink to a
minimal input; paste the printed seed into the follow-up report.

## Fuzz targets (run with cargo-fuzz, nightly required)

libFuzzer instrumentation needs the nightly compiler. `scripts/fuzz-seeded.sh`
selects `cargo +nightly` automatically when a nightly toolchain is installed.

```bash
cd fuzz
cargo +nightly fuzz build
cargo fuzz run fuzz_framing -- -runs=500 -max_total_time=20 corpus/fuzz_framing
cargo fuzz run fuzz_handshake -- -runs=500 -max_total_time=20 corpus/fuzz_handshake
cargo fuzz run fuzz_snapshot_metadata -- -runs=500 corpus/fuzz_snapshot_metadata
cargo fuzz run fuzz_backend_selection -- -runs=500 corpus/fuzz_backend_selection
cargo fuzz run fuzz_network_policy -- -runs=500 corpus/fuzz_network_policy
```

Targets:

- `fuzz_framing`: length prefix, tag dispatch, protobuf decode for
  `ExecRequest`, `RequestContext`, `StreamFrame`, handshake messages.
- `fuzz_handshake`: `GuestHello`/`HostHello` decode plus validation, proof,
  and version/capability negotiation.
- `fuzz_snapshot_metadata`: `SnapshotMetadata` and `MountContract` JSON plus
  credential-exclusion and compatibility checks.
- `fuzz_backend_selection`: workload/runtime string parsing plus policy
  evaluation with bit-derived evidence maps (pass and fail-closed paths).
- `fuzz_network_policy`: CIDR validation, DNS evaluation, denied-answer
  checks, egress compilation with interface binding assertion.

## Seed corpus

Checked-in seeds live in `fuzz/corpus/<target>/` and cover valid,
truncated, oversized, and mutated inputs per target. CI runs the seeded short
corpus via `scripts/fuzz-seeded.sh`. Long fuzz runs are a scheduled nightly
job with a stored corpus artifact (see `.github/workflows/fuzz-nightly.yaml`).

## Crash triage

1. Reproduce with the artifact file in `fuzz/artifacts/<target>/`.
2. Minimize with the printed proptest seed or libFuzzer artifact.
3. File a follow-up with the failing input attached and the target name.
4. Add a regression case to the matching property suite or robustness file.
5. Update the stored corpus with the minimized input.

## Evidence pointers

- Lifecycle safety: `crates/pico-core/tests/lifecycle_property.rs`
- Snapshot exclusion: `crates/pico-core/tests/snapshot_exclusion_property.rs`
- Backend selection: `crates/pico-core/tests/backend_selection_property.rs`
- Protocol: `crates/pico-guest-protocol/tests/protocol_property.rs`
- Network policy: `crates/pico-network-agent/tests/policy_property.rs`
- Fuzz harnesses: `fuzz/fuzz_targets/`
