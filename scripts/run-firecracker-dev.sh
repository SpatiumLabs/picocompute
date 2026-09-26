#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: repo root not found at $REPO_ROOT" >&2
  exit 1
fi

# Configuration
VM_HOST="${VM_HOST:-192.168.123.4}"
VM_USER="${VM_USER:-root}"
VM_SSH_PORT="${VM_SSH_PORT:-22}"
VM_INSTALL_PATH="${VM_INSTALL_PATH:-}"
REMOTE_SUDO="${REMOTE_SUDO:-auto}"
TARGET="${TARGET:-aarch64-unknown-linux-musl}"
CARGO_PROFILE="${CARGO_PROFILE:-release}"
RUSTFLAGS="${RUSTFLAGS:-}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"
USE_PREBUILT_ASSETS="${USE_PREBUILT_ASSETS:-0}"
ASSET_ROOT="${ASSET_ROOT:-$HOME/.local/share/pico/assets}"
VM_KERNEL_PATH="${VM_KERNEL_PATH:-}"
VM_ROOTFS_PATH="${VM_ROOTFS_PATH:-}"
remote="$VM_USER@$VM_HOST"
ssh_base_args=(-o LogLevel=ERROR -p "$VM_SSH_PORT")

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi

if command -v rustup >/dev/null 2>&1; then
  rustup target add "$TARGET" >/dev/null
fi

if [[ -z "$RUSTFLAGS" && "$TARGET" == *linux-musl ]]; then
  RUSTFLAGS="-C linker=rust-lld"
fi

set_remote_sudo_for_path() {
  local destination_path="$1"

  case "$REMOTE_SUDO" in
    auto)
      if [[ "$VM_USER" == "root" ||
        "$destination_path" == "/home/$VM_USER/"* ||
        "$destination_path" == "/tmp/"* ||
        "$destination_path" == "/var/tmp/"* ]]; then
        remote_sudo=""
      else
        remote_sudo="sudo"
      fi
      ;;
    1|true|yes|on)
      remote_sudo="sudo"
      ;;
    0|false|no|off)
      remote_sudo=""
      ;;
    *)
      echo "error: REMOTE_SUDO must be auto, true, or false" >&2
      exit 1
      ;;
  esac
}

copy_to_remote() {
  local source_path="$1"
  local destination_path="$2"
  local destination_dir
  local quoted_destination_dir
  local remote_tmp
  local quoted_destination_path
  local quoted_remote_tmp

  if ! command -v ssh >/dev/null 2>&1; then
    echo "error: ssh is required" >&2
    exit 1
  fi

  if ! command -v scp >/dev/null 2>&1; then
    echo "error: scp is required" >&2
    exit 1
  fi

  destination_dir="$(dirname "$destination_path")"
  printf -v quoted_destination_dir '%q' "$destination_dir"
  set_remote_sudo_for_path "$destination_path"

  if [[ -n "$remote_sudo" ]]; then
    remote_tmp="/var/tmp/pico-asset.$$.$RANDOM"
    printf -v quoted_destination_path '%q' "$destination_path"
    printf -v quoted_remote_tmp '%q' "$remote_tmp"
    scp -o LogLevel=ERROR -P "$VM_SSH_PORT" "$source_path" "$remote:$remote_tmp"

    remote_cmd="set -eu; mkdir -p -- $quoted_destination_dir; cp -- $quoted_remote_tmp $quoted_destination_path; chmod 0644 $quoted_destination_path; rm -f -- $quoted_remote_tmp"
    ssh -tt "${ssh_base_args[@]}" "$remote" "$remote_sudo sh -c $(printf '%q' "$remote_cmd")"
  else
    # shellcheck disable=SC2029
    ssh "${ssh_base_args[@]}" "$remote" "mkdir -p -- $quoted_destination_dir"
    scp -o LogLevel=ERROR -P "$VM_SSH_PORT" "$source_path" "$remote:$destination_path"
  fi
}

# Determine guest agent binary path
if [[ "$USE_PREBUILT_ASSETS" == "1" ]]; then
  echo "==> using pre-built assets from $ASSET_ROOT"

  ROOTFS_PATH="$ASSET_ROOT/rootfs.ext4"
  KERNEL_PATH="$ASSET_ROOT/kernel/aarch64/vmlinux"
  GUEST_AGENT_PATH="$ASSET_ROOT/pico-guest-agent"

  if [[ ! -f "$ROOTFS_PATH" ]]; then
    echo "error: rootfs not found at $ROOTFS_PATH" >&2
    echo "Run scripts/build-qemu-assets-macos.sh first" >&2
    exit 1
  fi

  if [[ ! -f "$KERNEL_PATH" ]]; then
    echo "error: kernel not found at $KERNEL_PATH" >&2
    echo "Run scripts/build-qemu-assets-macos.sh first" >&2
    exit 1
  fi

  if [[ ! -f "$GUEST_AGENT_PATH" ]]; then
    echo "error: guest agent not found at $GUEST_AGENT_PATH" >&2
    echo "Run scripts/build-qemu-assets-macos.sh first" >&2
    exit 1
  fi

  built_agent="$GUEST_AGENT_PATH"
  echo "  using pre-built guest agent: $built_agent"

  # Copy kernel and rootfs to remote VM if paths are specified
  if [[ -n "$VM_KERNEL_PATH" ]]; then
    echo "==> copying kernel to remote VM: $VM_KERNEL_PATH"
    copy_to_remote "$KERNEL_PATH" "$VM_KERNEL_PATH"
  fi
  if [[ -n "$VM_ROOTFS_PATH" ]]; then
    echo "==> copying rootfs to remote VM: $VM_ROOTFS_PATH"
    copy_to_remote "$ROOTFS_PATH" "$VM_ROOTFS_PATH"
  fi
else
  # Build locally
  if [[ "$CARGO_PROFILE" == "release" ]]; then
    cargo_args=(build -p pico-guest-agent --release --target "$TARGET")
    built_agent="$REPO_ROOT/target/$TARGET/release/pico-guest-agent"
  else
    cargo_args=(build -p pico-guest-agent --target "$TARGET")
    built_agent="$REPO_ROOT/target/$TARGET/debug/pico-guest-agent"
  fi

  echo "==> building pico-guest-agent"
  echo "target: $TARGET"
  echo

  cd "$REPO_ROOT"
  RUSTFLAGS="$RUSTFLAGS" cargo "${cargo_args[@]}"

  if [[ ! -x "$built_agent" ]]; then
    echo "error: built pico-guest-agent not found: $built_agent" >&2
    exit 1
  fi
fi

if [[ "$SKIP_INSTALL" == "true" ]]; then
  echo
  echo "built pico-guest-agent: $built_agent"
  exit 0
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "error: ssh is required" >&2
  exit 1
fi

if ! command -v scp >/dev/null 2>&1; then
  echo "error: scp is required" >&2
  exit 1
fi

if [[ -z "$VM_INSTALL_PATH" ]]; then
  if [[ "$VM_USER" == "root" ]]; then
    VM_INSTALL_PATH="/root/.local/bin/pico-agent"
  else
    VM_INSTALL_PATH="/home/$VM_USER/.local/bin/pico-agent"
  fi
fi

remote="$VM_USER@$VM_HOST"
remote_tmp="/var/tmp/pico-guest-agent.$$"
install_dir="$(dirname "$VM_INSTALL_PATH")"
install_tmp="$install_dir/.pico-agent.$$"
log_path="$install_dir/pico-agent.log"

set_remote_sudo_for_path "$VM_INSTALL_PATH"

echo
echo "==> installing pico-agent on Firecracker VM"
echo "vm: $remote"
echo "install: $VM_INSTALL_PATH"
echo

scp -o LogLevel=ERROR -P "$VM_SSH_PORT" "$built_agent" "$remote:$remote_tmp"
if [[ -n "$remote_sudo" ]]; then
  # We use a single string for the remote command to keep stdin free for sudo password entry
  remote_cmd=$(cat <<EOF
set -euo pipefail
mkdir -p '$install_dir'
cp '$remote_tmp' '$install_tmp'
chmod 755 '$install_tmp'
rm -f '$remote_tmp'
mv -f '$install_tmp' '$VM_INSTALL_PATH'
if command -v pkill >/dev/null 2>&1; then
  pkill -f '$VM_INSTALL_PATH' || true
fi
nohup '$VM_INSTALL_PATH' >'$log_path' 2>&1 </dev/null &
EOF
)
  ssh -tt "${ssh_base_args[@]}" "$remote" "$remote_sudo sh -c $(printf '%q' "$remote_cmd")"
else
  # shellcheck disable=SC2087
  ssh "${ssh_base_args[@]}" "$remote" "sh -s" <<EOF
set -euo pipefail
mkdir -p '$install_dir'
cp '$remote_tmp' '$install_tmp'
chmod 755 '$install_tmp'
rm -f '$remote_tmp'
mv -f '$install_tmp' '$VM_INSTALL_PATH'
if command -v pkill >/dev/null 2>&1; then
  pkill -f '$VM_INSTALL_PATH' || true
fi
nohup '$VM_INSTALL_PATH' >'$log_path' 2>&1 </dev/null &
EOF
fi

echo
echo "installed pico-agent on $remote:$VM_INSTALL_PATH"
echo "log: $log_path"

# No cleanup needed - using pre-built agent directly from assets
