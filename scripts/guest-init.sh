#!/bin/sh
set -eu

BOOT_LOG="/var/log/pico/boot.log"
BOOT_OUTCOME="/run/pico/tmp/boot-outcome"
AGENT_BIN="/usr/local/bin/pico-agent"

boot_step() {
    echo "[$(date +%s)] $1" >> "$BOOT_LOG"
}

boot_fail() {
    boot_step "BOOT_FAILED: $1"
    echo "FAILED" > "$BOOT_OUTCOME" 2>/dev/null || true
    exit 1
}

mkdir -p /var/log/pico /run/pico/tmp /run/pico/secrets
boot_step "init_started"

[ -r /proc/mounts ] || mount -t proc proc /proc || boot_fail "proc_mount"
boot_step "proc_mounted"

grep -qs ' /dev devtmpfs ' /proc/mounts || mount -t devtmpfs devtmpfs /dev || boot_fail "devtmpfs_mount"
grep -qs ' /dev/pts devpts ' /proc/mounts || { mkdir -p /dev/pts && mount -t devpts devpts /dev/pts; } || true
boot_step "dev_mounted"

grep -qs ' /sys sysfs ' /proc/mounts || mount -t sysfs sysfs /sys || boot_fail "sysfs_mount"
boot_step "sysfs_mounted"

# Secrets live on a private RAM-backed tmpfs so credentials never reach the
# root filesystem and therefore never reach a snapshot (ADR-0007). This is
# mounted here in init rather than by the guest agent: the agent runs under a
# seccomp profile that cannot permit mount(2), and granting it that syscall
# would also widen the profile for every process the agent spawns. init is
# unfiltered and already owns the other filesystem mounts.
grep -qs ' /run/pico/secrets tmpfs ' /proc/mounts || \
  mount -t tmpfs -o mode=500,nosuid,nodev,noexec,size=1m tmpfs /run/pico/secrets \
  || boot_fail "secrets_tmpfs_mount"
boot_step "secrets_mounted"

cmdline="$(cat /proc/cmdline)"
cmdline_value() {
  key="$1"
  for part in $cmdline; do
    case "$part" in
      "$key="*) echo "${part#*=}"; return 0 ;;
    esac
  done
  return 1
}

guest_ip="$(cmdline_value pico_guest_ip || true)"
guest_prefix="$(cmdline_value pico_guest_prefix || echo 30)"
host_ip="$(cmdline_value pico_host_ip || true)"

ip link set lo up || true
if [ -n "$guest_ip" ]; then
  ip link set eth0 up || true
  ip addr add "$guest_ip/$guest_prefix" dev eth0 || true
  if [ -n "$host_ip" ]; then
    ip route add default via "$host_ip" dev eth0 || true
  fi
fi
boot_step "networking_configured"

ssh-keygen -A 2>/dev/null || true
mkdir -p /var/run/sshd
/usr/sbin/sshd 2>/dev/null || true

boot_step "ready_for_agent"

if [ -f "$AGENT_BIN" ]; then
    boot_step "agent_present"
else
    boot_fail "guest_agent_missing"
fi

echo "BOOTED $(date +%s)" > "$BOOT_OUTCOME" 2>/dev/null || true
boot_step "boot_complete"

while true; do
  "$AGENT_BIN" || {
    status="$?"
    boot_step "agent_exited status=$status"
    echo "pico-agent exited with status $status" >&2
  }
  sleep 1
done
