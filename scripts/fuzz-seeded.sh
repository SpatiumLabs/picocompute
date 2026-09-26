#!/bin/bash
# Seeded fuzz corpus runner for CI.
#
# Builds every fuzz target with `cargo fuzz build` and runs each target for a
# short bounded time over the checked-in seed corpus. Long fuzz runs live in
# the scheduled nightly workflow with a stored corpus artifact.
#
# Usage:
#   ./scripts/fuzz-seeded.sh [--runs N] [--max-time SECS]
#
# Defaults keep CI fast: 500 runs or 20s per target, whichever hits first.
set -euo pipefail

RUNS=500
MAX_TIME=20

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --max-time) MAX_TIME="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/fuzz"

# libFuzzer instrumentation requires the nightly compiler (`-Zsanitizer`).
# Prefer `cargo +nightly` via rustup; fall back to plain cargo only when
# rustup is unavailable, in which case a stable toolchain fails with a
# clear error from the build below.
if rustup toolchain list 2>/dev/null | grep -q nightly; then
  CARGO_FUZZ="cargo +nightly fuzz"
else
  echo "warning: no nightly toolchain found; fuzz builds require nightly" >&2
  CARGO_FUZZ="cargo fuzz"
fi

if ! command -v cargo-fuzz >/dev/null 2>&1 && ! cargo fuzz --version >/dev/null 2>&1; then
  echo "installing cargo-fuzz..."
  cargo install cargo-fuzz --locked
fi

echo "building fuzz targets ($CARGO_FUZZ build)..."
$CARGO_FUZZ build

TARGETS=(fuzz_framing fuzz_handshake fuzz_snapshot_metadata fuzz_backend_selection fuzz_network_policy)

for target in "${TARGETS[@]}"; do
  echo "=== $target: seeded short run (runs=$RUNS, max_total_time=$MAX_TIME) ==="
  # libFuzzer runs the seed corpus first, then generates mutations up to the limits.
  # Crash artifacts stay in fuzz/artifacts/<target> for upload.
  $CARGO_FUZZ run "$target" -- \
    -runs="$RUNS" \
    -max_total_time="$MAX_TIME" \
    -print_final_stats=1 \
    "corpus/$target" || {
      echo "fuzz target $target found a crash; see fuzz/artifacts/$target" >&2
      exit 1
    }
done

echo "seeded fuzz run passed for ${#TARGETS[@]} targets"
