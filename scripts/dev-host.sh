#!/usr/bin/env bash
# Start sandboxd + host-agent as two processes for local development.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_DIR="${PICO_RUN_DIR:-/tmp/pico-dev}"
mkdir -p "$RUN_DIR"/{run,lib,workspaces}

export PICO_SANDBOXD_SOCKET="${PICO_SANDBOXD_SOCKET:-$RUN_DIR/run/sandboxd.sock}"
export PICO_SANDBOXD_TOKEN="${PICO_SANDBOXD_TOKEN:-dev-sandboxd-token}"
export PICO_SANDBOXD_STATE_PATH="${PICO_SANDBOXD_STATE_PATH:-$RUN_DIR/lib/sandboxd-state.db}"
export PICO_WORKSPACE_ROOT="${PICO_WORKSPACE_ROOT:-$RUN_DIR/workspaces}"
export PICO_HOST_AGENT_TOKEN="${PICO_HOST_AGENT_TOKEN:-dev-host-token}"
export PICO_HOST_AGENT_BIND_ADDR="${PICO_HOST_AGENT_BIND_ADDR:-127.0.0.1:9090}"

cleanup() {
  if [[ -n "${SANDBOXD_PID:-}" ]] && kill -0 "$SANDBOXD_PID" 2>/dev/null; then
    kill "$SANDBOXD_PID" 2>/dev/null || true
    wait "$SANDBOXD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Build first so the socket wait below only covers process startup, not a
# multi-minute cold compile (the wait loop would otherwise kill the build).
echo "building sandboxd and host-agent"
cargo build -p pico-sandboxd --bin sandboxd
cargo build -p pico-host-agent --bin pico-host-agent

echo "starting sandboxd on $PICO_SANDBOXD_SOCKET"
cargo run -p pico-sandboxd --bin sandboxd &
SANDBOXD_PID=$!

# Wait for the UDS to appear; fail fast if sandboxd dies first (e.g. a
# build failure or config error printed above).
for _ in $(seq 1 100); do
  if [[ -S "$PICO_SANDBOXD_SOCKET" ]]; then
    break
  fi
  if ! kill -0 "$SANDBOXD_PID" 2>/dev/null; then
    echo "sandboxd exited before creating $PICO_SANDBOXD_SOCKET (see error output above)" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -S "$PICO_SANDBOXD_SOCKET" ]]; then
  echo "sandboxd socket did not appear at $PICO_SANDBOXD_SOCKET" >&2
  exit 1
fi

echo "starting host-agent on $PICO_HOST_AGENT_BIND_ADDR"
cargo run -p pico-host-agent --bin pico-host-agent
