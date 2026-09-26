#!/usr/bin/env bash
# Companion for scripts/live-boot-evidence.sh on hosts without network-agent.
#
# The Firecracker adapter expects its TAP device to be pre-provisioned
# (production: network-agent owns this step and the adapter never creates
# TAPs). On dev and trial hosts without network-agent, run this watcher
# alongside the collector: it finds live_boot test processes, derives the
# same deterministic TAP identity the adapter computes from the sandbox id
# (fnv1a64, mirroring SandboxNetworkIdentity::for_sandbox; see the
# pinned_vector_for_external_tap_provisioning test in
# crates/pico-network-agent/src/identity.rs), creates the devices,
# assigns the host addresses, and raises them.
#
# Process selection is liveness-filtered: short-lived enumeration processes
# that briefly match the test binary path are ignored; only a process that
# survives a 2s window is used, newest first. The watcher keeps watching
# until killed so it outlives slow phases (e.g. the mock conformance
# baseline, which runs before the first walk) and covers every walk in the
# run; already-provisioned TAPs are skipped.
#
# Usage:
#   bash scripts/live-boot-tap-watch.sh &
#   WATCHER_PID=$!
#   scripts/live-boot-evidence.sh   # or: cargo test ... live_boot ...
#   kill "$WATCHER_PID" 2>/dev/null || true
#
# Knobs:
#   LIVE_BOOT_TAP_TAG  Sandbox tag embedded in the sandbox id
#                      (default: fc, matching sbx-live-fc-<pid>).
#   LIVE_BOOT_TAP_WATCH_SECS  How long to keep watching (default: 3600;
#                      the caller normally kills the watcher first).
set -euo pipefail

TAG="${LIVE_BOOT_TAP_TAG:-fc}"
WATCH_SECS="${LIVE_BOOT_TAP_WATCH_SECS:-3600}"

matches() {
  pgrep -f 'live_boot-[0-9a-f]' 2>/dev/null || true
}

provision() {
  local pid="$1"
  local info sbx tap hostcidr
  info="$(python3 - "$TAG" "$pid" <<'PYEOF'
import sys
tag, pid = sys.argv[1], sys.argv[2]
def fnv1a64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h
sbx = f"sbx-live-{tag}-{pid}"
h = fnv1a64(sbx.encode())
tap = "cvx%010x" % (h & 0xFFFFFFFFFF)
subnet = h % (16 * 256 * 64)
o2 = 16 + (subnet // (256 * 64))
o3 = (subnet // 64) % 256
o4 = ((subnet % 64) * 4)
print(f"{sbx} {tap} 172.{o2}.{o3}.{o4+1}/30")
PYEOF
)"
  sbx="$(echo "$info" | cut -d' ' -f1)"
  tap="$(echo "$info" | cut -d' ' -f2)"
  hostcidr="$(echo "$info" | cut -d' ' -f3)"
  if [[ -z "$tap" ]]; then
    echo "tap-watch: empty tap name for pid $pid" >&2
    return 1
  fi
  if ip link show "$tap" >/dev/null 2>&1; then
    echo "tap-watch: tap $tap already exists (sandbox $sbx)"
    return 0
  fi
  echo "tap-watch: sandbox $sbx tap $tap host $hostcidr"
  # -n: fail fast when sudo needs a password instead of hanging on a prompt
  # while backgrounded; the walk then reports the missing TAP at boot.
  sudo -n ip tuntap add dev "$tap" mode tap user "${USER:-$(id -un)}"
  sudo -n ip addr add "$hostcidr" dev "$tap"
  sudo -n ip link set dev "$tap" up
  echo "tap-watch: tap $tap up with $hostcidr"
}

deadline=$((SECONDS + WATCH_SECS))
while ((SECONDS < deadline)); do
  candidates="$(matches)"
  if [[ -n "$candidates" ]]; then
    sleep 2
    # Newest survivor first: enumeration processes exit within milliseconds
    # while the real test runs for minutes, and newest wins over a stale hung
    # process from an earlier run.
    for pid in $(echo "$candidates" | tr ' ' '\n' | sort -n -r); do
      if kill -0 "$pid" 2>/dev/null; then
        provision "$pid" || true
        break
      fi
    done
  fi
  sleep 1
done
echo "tap-watch: watch window elapsed, exiting"
