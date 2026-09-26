#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script is for macOS hosts" >&2
  exit 1
fi

if ! command -v limactl >/dev/null 2>&1; then
  echo "error: limactl is required. Install it with: brew install lima" >&2
  exit 1
fi

INSTANCE="${LIMA_INSTANCE:-pico-builder}"
KERNEL_VERSION="${KERNEL_VERSION:-v6.18}"
ALPINE_ROOTFS_URL="${ALPINE_ROOTFS_URL:-https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-minirootfs-latest-aarch64.tar.gz}"
ALPINE_ROOTFS_INDEX_URL="${ALPINE_ROOTFS_INDEX_URL:-https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/}"
ASSET_ROOT="${ASSET_ROOT:-$HOME/.local/share/pico/assets}"
HOST_ROOTFS_PATH="${HOST_ROOTFS_PATH:-$ASSET_ROOT/rootfs.ext4}"
HOST_KERNEL_DIR="${HOST_KERNEL_DIR:-$ASSET_ROOT/kernel/aarch64}"
HOST_KERNEL_PATH="${HOST_KERNEL_PATH:-$HOST_KERNEL_DIR/vmlinux}"
HOST_SSH_KEY_DIR="${HOST_SSH_KEY_DIR:-$ASSET_ROOT/keys}"
HOST_SSH_KEY_PATH="${HOST_SSH_KEY_PATH:-$HOST_SSH_KEY_DIR/id_pico}"
HOST_GUEST_AGENT_PATH="${HOST_GUEST_AGENT_PATH:-$ASSET_ROOT/pico-guest-agent}"
EXPORT_ROOT="/var/tmp/pico-export"
ROOTFS_SIZE="${ROOTFS_SIZE:-1G}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: repo root not found at $REPO_ROOT" >&2
  exit 1
fi

if [[ "$ASSET_ROOT" == "$HOME" || "$ASSET_ROOT" == "$HOME/"* ]] && [[ -e "$ASSET_ROOT" && ! -w "$ASSET_ROOT" ]]; then
  echo "error: $ASSET_ROOT is not writable by $USER" >&2
  echo "fix with: sudo chown -R $USER:staff ${ASSET_ROOT%/}" >&2
  exit 1
fi

if ! limactl list --format '{{ .Name }}' | grep -qx "$INSTANCE"; then
  echo "==> starting lima instance $INSTANCE"
  limactl start --name "$INSTANCE" "template://ubuntu-26.04"
else
  status="$(limactl list --format '{{if eq .Name "'"$INSTANCE"'"}}{{.Status}}{{end}}' | tr -d '\n')"
  if [[ "$status" != "Running" ]]; then
    echo "==> starting existing lima instance $INSTANCE"
    limactl start "$INSTANCE"
  fi
fi

vm_script="$(mktemp)"
HOST_REPO_TARBALL="$(mktemp -t pico-repo.XXXXXX.tar)"
tmp_kernel=""
tmp_rootfs=""
trap 'rm -f "$vm_script" "$HOST_REPO_TARBALL" "$tmp_kernel" "$tmp_rootfs"' EXIT

# Generate (or reuse) a persistent dev SSH keypair on the host. The public key
# gets baked into the rootfs as root's authorized_keys; the private key stays
# on the host so the user can `ssh -i ...` into a running VM.
if [[ ! -f "$HOST_SSH_KEY_PATH" ]]; then
  mkdir -p "$HOST_SSH_KEY_DIR"
  ssh-keygen -t ed25519 -N '' -f "$HOST_SSH_KEY_PATH" -C "pico-dev"
  chmod 600 "$HOST_SSH_KEY_PATH"
  chmod 644 "${HOST_SSH_KEY_PATH}.pub"
elif [[ ! -f "${HOST_SSH_KEY_PATH}.pub" ]]; then
  ssh-keygen -y -f "$HOST_SSH_KEY_PATH" > "${HOST_SSH_KEY_PATH}.pub"
  chmod 644 "${HOST_SSH_KEY_PATH}.pub"
fi

echo "==> packaging repo for writable build inside lima"
tar \
  --exclude .git \
  --exclude target \
  --exclude .worktrees \
  --no-xattrs \
  -czf "$HOST_REPO_TARBALL" \
  -C "$REPO_ROOT" .

cat >"$vm_script" <<EOF
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
if ! command -v sudo >/dev/null 2>&1; then
  apt-get update
  apt-get install -y sudo
fi

sudo rm -rf /var/lib/apt/lists/*
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  git \
  curl \
  clang \
  mold \
  wget \
  xz-utils \
  bc \
  flex \
  bison \
  libssl-dev \
  libelf-dev \
  dwarves \
  e2fsprogs

if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y
fi
source "\$HOME/.cargo/env"
rustup target add aarch64-unknown-linux-musl

WORK_ROOT="\$HOME/pico-qemu-assets"
EXPORT_ROOT="$EXPORT_ROOT"
KERNEL_VERSION="$KERNEL_VERSION"
ALPINE_ROOTFS_URL="$ALPINE_ROOTFS_URL"
ALPINE_ROOTFS_INDEX_URL="$ALPINE_ROOTFS_INDEX_URL"
ROOTFS_SIZE="$ROOTFS_SIZE"

mkdir -p "\$WORK_ROOT"
mkdir -p "\$WORK_ROOT/repo"
rm -rf "\$EXPORT_ROOT"
mkdir -p "\$EXPORT_ROOT"
tar -xzf /tmp/pico-repo.tar.gz -C "\$WORK_ROOT/repo"
cd "\$WORK_ROOT"

if [[ ! -d linux ]]; then
  git clone --depth 1 --branch "\$KERNEL_VERSION" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
fi

cd linux
make defconfig
scripts/config --enable VIRTIO_BLK
scripts/config --enable VIRTIO_NET
scripts/config --enable EXT4_FS
scripts/config --enable DEVTMPFS
scripts/config --enable DEVTMPFS_MOUNT
scripts/config --enable INET
scripts/config --enable PROC_FS
scripts/config --enable SYSFS
scripts/config --enable SERIAL_AMBA_PL011
scripts/config --enable PCI
scripts/config --enable PCI_HOST_GENERIC
# Bake a kernel command line and default init path so the QEMU virt machine
# routes its console to pl011 (ttyAMA0) and finds our /init script.
scripts/config --set-str CONFIG_CMDLINE "console=ttyAMA0,115200"
scripts/config --set-str CONFIG_DEFAULT_INIT "/init"
make olddefconfig
make -j"\$(nproc)" Image

source "\$HOME/.cargo/env"
cd "\$WORK_ROOT/repo"
cargo build -p pico-guest-agent --release --target aarch64-unknown-linux-musl

cd "\$WORK_ROOT"
rm -f rootfs.ext4
truncate -s "\$ROOTFS_SIZE" rootfs.ext4
mkfs.ext4 -F rootfs.ext4

rm -rf mnt
mkdir -p mnt
sudo mount -o loop rootfs.ext4 mnt
cleanup_mount() {
  if mountpoint -q mnt; then
    sudo umount mnt
  fi
}
trap cleanup_mount EXIT

resolve_alpine_rootfs_url() {
  if wget --spider -q "\$ALPINE_ROOTFS_URL"; then
    echo "\$ALPINE_ROOTFS_URL"
    return 0
  fi

  local latest_path
  latest_path="\$(
    curl -fsSL "\$ALPINE_ROOTFS_INDEX_URL" \
      | grep -o 'alpine-minirootfs-[0-9.]\+-aarch64\.tar\.gz' \
      | sort -V \
      | tail -n 1
  )"

  if [[ -z "\$latest_path" ]]; then
    echo "error: unable to resolve Alpine minirootfs from \$ALPINE_ROOTFS_INDEX_URL" >&2
    exit 1
  fi

  echo "\${ALPINE_ROOTFS_INDEX_URL%\//}/\$latest_path"
}

ROOTFS_URL="\$(resolve_alpine_rootfs_url)"
echo "==> using Alpine rootfs \$ROOTFS_URL"
wget -O alpine-minirootfs.tar.gz "\$ROOTFS_URL"
sudo tar -xzf alpine-minirootfs.tar.gz -C mnt
sudo mkdir -p mnt/usr/local/bin
sudo install -m755 "\$WORK_ROOT/repo/target/aarch64-unknown-linux-musl/release/pico-guest-agent" mnt/usr/local/bin/pico-agent

# Install openssh-server in the chroot, with /dev, /proc, /sys bind-mounted so
# apk can resolve DNS and write to /var/cache and /var/lib.
echo 'nameserver 1.1.1.1' | sudo tee mnt/etc/resolv.conf >/dev/null
sudo mount --bind /dev mnt/dev 2>/dev/null || true
sudo mount -t proc none mnt/proc 2>/dev/null || true
sudo mount -t sysfs none mnt/sys 2>/dev/null || true
sudo chroot mnt apk add --no-cache openssh-server
sudo umount mnt/sys 2>/dev/null || true
sudo umount mnt/proc 2>/dev/null || true
sudo umount mnt/dev 2>/dev/null || true

# Install the host-generated public key as root's authorized_keys.
sudo mkdir -p mnt/root/.ssh
sudo cp /tmp/pico_dev_key.pub mnt/root/.ssh/authorized_keys
sudo chmod 700 mnt/root/.ssh
sudo chmod 600 mnt/root/.ssh/authorized_keys

# Minimal dev sshd_config: key-only auth, root allowed, no PAM/no passwords.
sudo tee mnt/etc/ssh/sshd_config >/dev/null <<'SSHD_EOF'
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_ed25519_key

PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitEmptyPasswords no
PrintMotd no
SSHD_EOF

sudo mkdir -p mnt/var/run/sshd

# Replace Alpine's busybox init with a tiny shell init that brings up the
# console/network, runs a serial getty, generates host keys on first boot,
# starts sshd, and supervises the pico-agent.
sudo rm -f mnt/init mnt/sbin/init
sudo tee mnt/init >/dev/null <<'INIT_EOF'
#!/bin/sh
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
mount -t proc proc /proc
mount -t sysfs sysfs /sys

ip link set lo up
ip link set eth0 up || true
udhcpc -i eth0 -q -n || true

# Serial console login (background).
getty -L 0 ttyAMA0 vt100 &

# Generate SSH host keys on first boot (idempotent).
ssh-keygen -A 2>/dev/null || true

# Start sshd in the background.
mkdir -p /var/run/sshd
/usr/sbin/sshd

# Supervise the pico-agent. Longer sleep avoids log spam if it crashes.
while true; do
  /usr/local/bin/pico-agent
  sleep 5
done
INIT_EOF
sudo chmod +x mnt/init
echo 'nameserver 1.1.1.1' | sudo tee mnt/etc/resolv.conf >/dev/null
cleanup_mount
trap - EXIT

cp "\$WORK_ROOT/linux/arch/arm64/boot/Image" "\$EXPORT_ROOT/vmlinux"
cp "\$WORK_ROOT/rootfs.ext4" "\$EXPORT_ROOT/rootfs.ext4"
cp "\$WORK_ROOT/repo/target/aarch64-unknown-linux-musl/release/pico-guest-agent" "\$EXPORT_ROOT/pico-guest-agent"
EOF

echo "==> copying build script, repo, and dev pubkey into lima instance"
limactl copy "$vm_script" "$INSTANCE:/tmp/build-qemu-assets.sh"
limactl copy "$HOST_REPO_TARBALL" "$INSTANCE:/tmp/pico-repo.tar.gz"
limactl copy "${HOST_SSH_KEY_PATH}.pub" "$INSTANCE:/tmp/pico_dev_key.pub"

echo "==> building kernel and rootfs inside lima"
limactl shell "$INSTANCE" /bin/bash -c "chmod +x /tmp/build-qemu-assets.sh && /tmp/build-qemu-assets.sh"

tmp_kernel="$(mktemp)"
tmp_rootfs="$(mktemp)"
tmp_agent="$(mktemp)"

echo "==> copying built assets back to macOS"
limactl copy "$INSTANCE:$EXPORT_ROOT/vmlinux" "$tmp_kernel"
limactl copy "$INSTANCE:$EXPORT_ROOT/rootfs.ext4" "$tmp_rootfs"
limactl copy "$INSTANCE:$EXPORT_ROOT/pico-guest-agent" "$tmp_agent"

echo "==> installing assets under $ASSET_ROOT"
if [[ "$ASSET_ROOT" == "$HOME" || "$ASSET_ROOT" == "$HOME/"* ]]; then
  mkdir -p "$HOST_KERNEL_DIR"
  cp "$tmp_kernel" "$HOST_KERNEL_PATH"
  cp "$tmp_rootfs" "$HOST_ROOTFS_PATH"
  cp "$tmp_agent" "$HOST_GUEST_AGENT_PATH"
else
  sudo mkdir -p "$HOST_KERNEL_DIR"
  sudo cp "$tmp_kernel" "$HOST_KERNEL_PATH"
  sudo cp "$tmp_rootfs" "$HOST_ROOTFS_PATH"
  sudo cp "$tmp_agent" "$HOST_GUEST_AGENT_PATH"
  sudo chown "$(id -u):$(id -g)" "$HOST_KERNEL_PATH" "$HOST_ROOTFS_PATH" "$HOST_GUEST_AGENT_PATH"
fi
chmod u+rw "$HOST_KERNEL_PATH" "$HOST_ROOTFS_PATH" "$HOST_GUEST_AGENT_PATH"
chmod +x "$HOST_GUEST_AGENT_PATH"

echo
echo "kernel:         $HOST_KERNEL_PATH"
echo "rootfs:         $HOST_ROOTFS_PATH"
echo "guest agent:    $HOST_GUEST_AGENT_PATH"
echo "ssh key:        $HOST_SSH_KEY_PATH"
echo "ssh pub:        ${HOST_SSH_KEY_PATH}.pub"
echo
echo "To SSH into a running VM (once the picocompute network is up):"
echo "  ssh -i $HOST_SSH_KEY_PATH root@<vm-ip>"
