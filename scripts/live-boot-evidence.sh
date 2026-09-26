#!/usr/bin/env bash
# Collect live isolation-backend boot evidence per preview backend.
#
# Runs host preflight, the mock conformance baseline, and one ignored live
# lifecycle per preview backend (firecracker, qemu, gvisor). Each live test
# writes <backend>.json into the run directory; this script adds
# host-profile.json, per-backend test logs, and summary.json.
#
# On hosts without KVM, VMM binaries, or guest assets (for example macOS dev
# machines and stock GitHub-hosted runners) the live tests record
# status=blocked with explicit reasons and exit non-zero. Blocked is an
# expected outcome there, not a harness failure. A passing run requires the
# candidate Linux host profile documented in
# docs/robustness/live-boot-evidence/README.md.
#
# Usage:
#   scripts/live-boot-evidence.sh
#
# Knobs:
#   LIVE_BOOT_OUT_DIR   Base output dir (default: target/live-boot-evidence).
#                       A timestamped subdirectory is created per run.
#   LIVE_BOOT_BACKENDS  Space-separated subset of: firecracker qemu gvisor.
#   LIVE_BOOT_REQUIRED_BACKENDS  Subset of BACKENDS that must pass for the
#                       gate to succeed (default: firecracker qemu). Must be
#                       a subset of LIVE_BOOT_BACKENDS; anything else fails
#                       fast before the mock baseline runs. Remaining
#                       backends are optional: blocked is recorded but does not
#                       fail the gate, while failed still fails. This keeps
#                       gVisor as a best-effort trusted-fast-path signal.
#   LIVE_BOOT_TIMEOUT_SECS  Outer timeout per live walk (default 600).
#   LIVE_BOOT_HOST_IMAGE  Override for the host image identifier recorded in
#                       host-profile.json (default: /etc/os-release PRETTY_NAME).
#   All PICO_* asset/binary env vars consumed by the adapter configs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: repo root not found at $REPO_ROOT" >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
OUT_BASE="${LIVE_BOOT_OUT_DIR:-$REPO_ROOT/target/live-boot-evidence}"
OUT_DIR="$OUT_BASE/$STAMP-$HOST_TAG"
mkdir -p "$OUT_DIR"

BACKENDS="${LIVE_BOOT_BACKENDS:-firecracker qemu gvisor}"
REQUIRED_BACKENDS="${LIVE_BOOT_REQUIRED_BACKENDS:-firecracker qemu}"
TIMEOUT_SECS="${LIVE_BOOT_TIMEOUT_SECS:-600}"

# Every required backend must be a known backend under test; otherwise the
# gate would burn a full run and then fail with "required backends not run".
for req in $REQUIRED_BACKENDS; do
  case "$req" in
    firecracker|qemu|gvisor) ;;
    *)
      echo "error: unknown backend '$req' in LIVE_BOOT_REQUIRED_BACKENDS" >&2
      exit 1
      ;;
  esac
  case " $BACKENDS " in
    *" $req "*) ;;
    *)
      echo "error: required backend '$req' is not in LIVE_BOOT_BACKENDS ($BACKENDS)" >&2
      echo "hint: narrow LIVE_BOOT_REQUIRED_BACKENDS to match, e.g." >&2
      echo "hint: LIVE_BOOT_BACKENDS=firecracker LIVE_BOOT_REQUIRED_BACKENDS=firecracker" >&2
      exit 1
      ;;
  esac
done

export LIVE_BOOT_OUT_DIR="$OUT_DIR"
export LIVE_BOOT_TIMEOUT_SECS="$TIMEOUT_SECS"
# Tested revision attached to every bundle (harness prefers GITHUB_SHA, then
# git HEAD). Export here so CI and manual runs record the same value.
if [[ -z "${GITHUB_SHA:-}" ]]; then
  SOURCE_REVISION="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
else
  SOURCE_REVISION="$GITHUB_SHA"
fi
export GITHUB_SHA="$SOURCE_REVISION"
if git status --porcelain=v1 2>/dev/null | grep -q .; then
  SOURCE_DIRTY="true"
else
  SOURCE_DIRTY="false"
fi
# Production QEMU defaults enable vsock plus QMP. Development mode would
# attach TCP and the live walk fail-closes that as not evidence.
if [[ -z "${PICO_QEMU_MODE:-}" ]]; then
  export PICO_QEMU_MODE=production
fi

echo "==> live-boot evidence run"
echo "    out:      $OUT_DIR"
echo "    backends: $BACKENDS"
echo "    required: $REQUIRED_BACKENDS"
echo "    revision: $SOURCE_REVISION (dirty=$SOURCE_DIRTY)"
echo

# ---------------------------------------------------------------- host profile
echo "==> host preflight"
{
  echo "stamp: $STAMP"
  echo "revision: $SOURCE_REVISION (dirty=$SOURCE_DIRTY)"
  echo "host:  $(uname -a)"
  echo "kernel-release: $(uname -r)"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "host-image: ${PRETTY_NAME:-${NAME:-unknown} ${VERSION_ID:-}}"
  elif [[ -n "${LIVE_BOOT_HOST_IMAGE:-}" ]]; then
    echo "host-image: $LIVE_BOOT_HOST_IMAGE"
  else
    echo "host-image: unknown (no /etc/os-release)"
  fi
  if [[ -e /dev/kvm ]]; then echo "kvm: present"; else echo "kvm: MISSING"; fi
  if [[ -e /dev/vhost-vsock ]]; then echo "vhost-vsock: present"; else echo "vhost-vsock: MISSING"; fi
  for bin in firecracker jailer runsc qemu-system-x86_64 qemu-system-aarch64; do
    if command -v "$bin" >/dev/null 2>&1; then
      echo "bin:$bin: $(command -v "$bin")"
      ("$bin" --version 2>&1 || true) | head -n 2 | sed 's/^/  version: /'
    else
      echo "bin:$bin: MISSING"
    fi
  done
  HOST_ARCH="$(uname -m)"
  case "$HOST_ARCH" in
    aarch64|arm64) DEFAULT_KERNEL="/opt/pico/kernel/aarch64/vmlinux" ;;
    *) DEFAULT_KERNEL="/opt/pico/kernel/x86_64/vmlinux" ;;
  esac
  for asset in "${PICO_ROOTFS_PATH:-/opt/pico/rootfs.ext4}" \
               "${PICO_QEMU_KERNEL_PATH:-$DEFAULT_KERNEL}"; do
    if [[ -f "$asset" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        echo "asset:$asset: sha256=$(sha256sum "$asset" | awk '{print $1}')"
      elif command -v shasum >/dev/null 2>&1; then
        echo "asset:$asset: sha256=$(shasum -a 256 "$asset" | awk '{print $1}')"
      else
        echo "asset:$asset: present (no sha256 tool)"
      fi
    else
      echo "asset:$asset: MISSING"
    fi
  done
} | tee "$OUT_DIR/host-profile.txt"
echo

if command -v python3 >/dev/null 2>&1; then
  SOURCE_REVISION="$SOURCE_REVISION" SOURCE_DIRTY="$SOURCE_DIRTY" python3 - "$OUT_DIR" <<'PYEOF'
import json, subprocess, sys, os
out_dir = sys.argv[1]
def which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
def version(binary):
    path = binary if os.path.dirname(binary) else which(binary)
    if not path:
        return {"present": False}
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15)
        text = (p.stdout + p.stderr).strip()[:2000]
        return {"present": True, "path": path, "version": text or None}
    except Exception as e:
        return {"present": True, "path": path, "version": None, "error": str(e)}
def os_release():
    release = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                release[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    return release
def host_image(release):
    override = os.environ.get("LIVE_BOOT_HOST_IMAGE", "").strip()
    if override:
        return override
    if release.get("PRETTY_NAME"):
        return release["PRETTY_NAME"]
    name = release.get("NAME", "").strip()
    version = release.get("VERSION_ID", "").strip()
    if name and version:
        return f"{name} {version}"
    return name or None
arch = os.uname().machine.lower()
qemu_default = "qemu-system-aarch64" if arch in ("arm64", "aarch64") else "qemu-system-x86_64"
release = os_release()
try:
    kernel_release = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=10).stdout.strip() or None
except Exception:
    kernel_release = None
try:
    kernel_full = open("/proc/version").read().strip() or None
except Exception:
    kernel_full = None
profile = {
    "schema_version": "live-boot-host-profile/1",
    "source_revision": {
        "revision": os.environ.get("SOURCE_REVISION", "unknown"),
        "dirty": os.environ.get("SOURCE_DIRTY", "unknown") == "true",
    },
    "host_image": host_image(release),
    "os_release": release,
    "kernel_release": kernel_release,
    "kernel_full": kernel_full,
    "binaries": {b: version(b) for b in [
        os.environ.get("PICO_FIRECRACKER_BIN", "firecracker"),
        os.environ.get("PICO_FIRECRACKER_JAILER_BIN", "jailer"),
        os.environ.get("PICO_QEMU_BIN", qemu_default),
        "runsc",
    ]},
    "kvm_present": os.path.exists("/dev/kvm"),
    "vhost_vsock_present": os.path.exists("/dev/vhost-vsock"),
}
with open(os.path.join(out_dir, "host-profile.json"), "w") as f:
    json.dump(profile, f, indent=2)
print("wrote host-profile.json")
PYEOF
else
  echo "warning: python3 not found, skipping host-profile.json" >&2
fi
echo

# ------------------------------------------------------- mock baseline (control)
echo "==> mock conformance baseline (control: must pass everywhere)"
set +e
if command -v cargo-nextest >/dev/null 2>&1; then
  cargo nextest run -p pico-runtime --test conformance 2>&1 | tee "$OUT_DIR/mock-conformance.log"
else
  cargo test -p pico-runtime --test conformance 2>&1 | tee "$OUT_DIR/mock-conformance.log"
fi
MOCK_RC="${PIPESTATUS[0]}"
set -e
echo "    mock baseline exit: $MOCK_RC"
echo

# ------------------------------------------------------------------ live walks
# Portable bash (macOS ships bash 3.2: no associative arrays).
test_fn_for() {
  case "$1" in
    firecracker) echo "firecracker_live_boot_evidence" ;;
    qemu) echo "qemu_live_boot_evidence" ;;
    gvisor) echo "gvisor_live_boot_evidence" ;;
    *) echo "error: unknown backend '$1' (want: firecracker qemu gvisor)" >&2; exit 1 ;;
  esac
}

run_one() {
  local backend="$1"
  local test_fn
  test_fn="$(test_fn_for "$backend")"
  local rc
  echo "==> live walk: $backend ($test_fn)"
  set +e
  if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run -p pico-runtime --test live_boot \
      --run-ignored ignored-only -E "test($test_fn)" \
      2>&1 | tee "$OUT_DIR/$backend-test.log"
    rc="${PIPESTATUS[0]}"
  else
    cargo test -p pico-runtime --test live_boot -- \
      --ignored --exact "$test_fn" --nocapture \
      2>&1 | tee "$OUT_DIR/$backend-test.log"
    rc="${PIPESTATUS[0]}"
  fi
  set -e
  echo "$rc" > "$OUT_DIR/$backend.exit"
  echo "    exit: $rc (non-zero with status=blocked is expected off the candidate host)"
  echo
}

for backend in $BACKENDS; do
  test_fn_for "$backend" >/dev/null
  run_one "$backend"
done

# -------------------------------------------------------------------- summary
if command -v python3 >/dev/null 2>&1; then
  BACKENDS_ENV="$BACKENDS" REQUIRED_ENV="$REQUIRED_BACKENDS" MOCK_RC="$MOCK_RC" SOURCE_REVISION="$SOURCE_REVISION" SOURCE_DIRTY="$SOURCE_DIRTY" python3 - "$OUT_DIR" <<'PYEOF'
import json, os, sys
out_dir = sys.argv[1]
backends = os.environ["BACKENDS_ENV"].split()
required = [b for b in os.environ.get("REQUIRED_ENV", "").split() if b]
summary = {
    "schema_version": "live-boot-summary/1",
    "source_revision": {
        "revision": os.environ.get("SOURCE_REVISION", "unknown"),
        "dirty": os.environ.get("SOURCE_DIRTY", "unknown") == "true",
    },
    "required_backends": required,
    "mock_conformance_exit": int(os.environ["MOCK_RC"]),
    "backends": {},
}
for b in backends:
    path = os.path.join(out_dir, f"{b}.json")
    try:
        with open(path) as f:
            doc = json.load(f)
        summary["backends"][b] = {
            "status": doc.get("status"),
            "message": doc.get("message"),
            "transport": doc.get("transport"),
            "source_revision": doc.get("source_revision"),
            "host_image": (doc.get("host") or {}).get("host_image"),
            "phases": [(p.get("name"), p.get("ok"), p.get("skipped", False)) for p in doc.get("phases", [])],
        }
    except FileNotFoundError:
        summary["backends"][b] = {"status": "not-run", "message": "no evidence bundle written"}
    except json.JSONDecodeError as e:
        summary["backends"][b] = {"status": "unreadable", "message": str(e)}
with open(os.path.join(out_dir, "summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
print("wrote summary.json")
for b in backends:
    s = summary["backends"][b]
    print(f"  {b}: {s.get('status')} - {s.get('message')}")
PYEOF
else
  echo "warning: python3 not found, skipping summary.json" >&2
  for backend in $BACKENDS; do
    echo "  $backend: test exit $(cat "$OUT_DIR/$backend.exit" 2>/dev/null || echo '?') (see $backend.json)"
  done
fi

echo
echo "evidence dir: $OUT_DIR"
echo "Attach <backend>.json plus host-profile.json/summary.json as the passing candidate-host run evidence."

# Gate: mock must pass, every required backend must record status=pass.
# Optional backends (for example gVisor) may be blocked without failing the
# gate, but a failed walk always fails. Blocked on required backends means
# the host is not the candidate profile: exit 2, not a harness failure.
if command -v python3 >/dev/null 2>&1 && [[ -f "$OUT_DIR/summary.json" ]]; then
  REQUIRED_ENV="$REQUIRED_BACKENDS" python3 - "$OUT_DIR" <<'PYEOF'
import json, os, sys
summary = json.load(open(os.path.join(sys.argv[1], "summary.json")))
if summary.get("mock_conformance_exit", 1) != 0:
    print("gate: mock conformance failed")
    sys.exit(1)
backends = summary.get("backends", {})
if not backends:
    print("gate: no backends recorded")
    sys.exit(1)
if any(v.get("status") == "failed" for v in backends.values()):
    print("gate: at least one live walk failed")
    sys.exit(1)
required = summary.get("required_backends") or list(backends.keys())
missing = [b for b in required if b not in backends]
if missing:
    print(f"gate: required backends not run: {missing}")
    sys.exit(1)
if all(backends.get(b, {}).get("status") == "pass" for b in required):
    optional_blocked = [b for b, v in backends.items() if b not in required and v.get("status") != "pass"]
    if optional_blocked:
        print(f"gate: required backends passed; optional blocked/incomplete: {optional_blocked}")
    else:
        print("gate: all requested backends passed")
    sys.exit(0)
print("gate: required live walks did not all pass (blocked or incomplete)")
sys.exit(2)
PYEOF
else
  if [[ "$MOCK_RC" != "0" ]]; then
    echo "gate: mock conformance failed" >&2
    exit 1
  fi
  echo "gate: cannot evaluate summary.json; treating as incomplete" >&2
  exit 2
fi
