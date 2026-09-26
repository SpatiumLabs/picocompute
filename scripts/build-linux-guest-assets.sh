#!/usr/bin/env bash
# Build Firecracker/QEMU guest assets natively on a Linux host:
# guest kernel plus an Alpine rootfs with the musl pico-guest-agent
# and scripts/guest-init.sh as /init. Used to provision the candidate host
# profile in docs/robustness/live-boot-evidence/README.md.
#
# Proven on Ubuntu 24.04 aarch64 (Firecracker v1.17.0 live-boot evidence).
# x86_64 follows the same steps with arch-adjusted image names, but the
# Firecracker x86_64 path is not yet covered by a live-boot pass run.
#
# Usage:
#   scripts/build-linux-guest-assets.sh
#
# Knobs:
#   ASSET_ROOT      Install prefix (default: /opt/pico, the adapter
#                   default; point elsewhere for a user-owned layout plus
#                   PICO_ROOTFS_PATH / PICO_QEMU_KERNEL_PATH overrides).
#   KERNEL_VERSION  Linux version, e.g. v6.18 (default). Must stay on the v6.x
#                   CDN path below.
#   ALPINE_VERSION  Alpine release, e.g. 3.24.2 (default: latest-stable index
#                   at run time; pin this for reproducible digests).
#   ROOTFS_SIZE     Rootfs image size (default: 1G).
#   WORK_ROOT       Scratch dir (default: $HOME/pico-assets).
#   BUILD_ONLY      Comma-separated subset of: kernel, rootfs (default: both).
#                   Used by CI to cache kernel and rootfs separately.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: repo root not found at $REPO_ROOT" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH=aarch64; MUSL_TRIPLE=aarch64-unknown-linux-musl; KARCH_DIR=aarch64 ;;
  x86_64|amd64) ARCH=x86_64; MUSL_TRIPLE=x86_64-unknown-linux-musl; KARCH_DIR=x86_64 ;;
  *) echo "error: unsupported arch $ARCH" >&2; exit 1 ;;
esac

KERNEL_VERSION="${KERNEL_VERSION:-v6.18}"
ALPINE_VERSION="${ALPINE_VERSION:-}"
ROOTFS_SIZE="${ROOTFS_SIZE:-1G}"
WORK_ROOT="${WORK_ROOT:-$HOME/pico-assets}"
ASSET_ROOT="${ASSET_ROOT:-/opt/pico}"
BUILD_ONLY="${BUILD_ONLY:-kernel,rootfs}"
KERNEL_OUT_DIR="$ASSET_ROOT/kernel/$KARCH_DIR"

want_step() {
  case ",$BUILD_ONLY," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

echo "==> arch:          $ARCH ($KARCH_DIR)"
echo "==> kernel:        $KERNEL_VERSION"
echo "==> work root:     $WORK_ROOT"
echo "==> asset root:    $ASSET_ROOT"
echo

# ------------------------------------------------------------ dependencies
if ! command -v sudo >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
  echo "error: this script needs Debian/Ubuntu with sudo + apt-get" >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y \
  build-essential git curl wget xz-utils bc flex bison file \
  libssl-dev libelf-dev dwarves e2fsprogs musl-tools \
  protobuf-compiler mold

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found; install Rust (https://rustup.rs) first" >&2
  exit 1
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true

mkdir -p "$WORK_ROOT/dl"

# ------------------------------------------------------------ kernel source
if want_step kernel; then
if [[ ! -f "$WORK_ROOT/linux/Makefile" ]] \
  || [[ "$(cat "$WORK_ROOT/linux/.pico-kernel-version" 2>/dev/null)" != "$KERNEL_VERSION" ]]; then
  rm -rf "$WORK_ROOT/linux"
  KERNEL_TARBALL="$WORK_ROOT/dl/linux-${KERNEL_VERSION#v}.tar.xz"
  if [[ ! -f "$KERNEL_TARBALL" ]]; then
    curl -fSL -o "$KERNEL_TARBALL" \
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION#v}.tar.xz"
  fi
  # Digests land in evidence bundles, so verify the download against the
  # published checksums before building from it.
  EXPECTED_SHA="$(curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc \
    | grep -E "  linux-${KERNEL_VERSION#v}\\.tar\\.xz\$" | cut -d' ' -f1)"
  [[ -n "$EXPECTED_SHA" ]] || { echo "error: no published sha256 for linux-${KERNEL_VERSION#v}.tar.xz" >&2; exit 1; }
  ACTUAL_SHA="$(sha256sum "$KERNEL_TARBALL" | cut -d' ' -f1)"
  [[ "$EXPECTED_SHA" == "$ACTUAL_SHA" ]] || {
    echo "error: kernel tarball sha256 mismatch (expected $EXPECTED_SHA, got $ACTUAL_SHA)" >&2
    exit 1
  }
  tar -xf "$KERNEL_TARBALL" -C "$WORK_ROOT"
  mv "$WORK_ROOT/linux-${KERNEL_VERSION#v}" "$WORK_ROOT/linux"
  echo "$KERNEL_VERSION" > "$WORK_ROOT/linux/.pico-kernel-version"
fi
fi # want_step kernel
if want_step kernel; then
  grep -m2 -E "^VERSION |^PATCHLEVEL " "$WORK_ROOT/linux/Makefile"
fi

# ------------------------------------------------------------------ kernel
if want_step kernel; then
cd "$WORK_ROOT/linux"
make defconfig
scripts/config --enable VIRTIO
scripts/config --enable VIRTIO_BLK
scripts/config --enable VIRTIO_NET
scripts/config --enable VIRTIO_PCI
scripts/config --enable EXT4_FS
scripts/config --enable DEVTMPFS
scripts/config --enable DEVTMPFS_MOUNT
scripts/config --enable INET
scripts/config --enable PROC_FS
scripts/config --enable SYSFS
scripts/config --enable VSOCKETS
scripts/config --enable VIRTIO_VSOCKETS
scripts/config --enable IKCONFIG
scripts/config --enable IKCONFIG_PROC
if [[ "$ARCH" == "aarch64" ]]; then
  # Firecracker MMIO transport; PCI_HOST_GENERIC exists on ARM only and
  # scripts/config aborts on unknown symbols, so keep these arch-gated.
  scripts/config --enable VIRTIO_MMIO
  scripts/config --enable VIRTIO_MMIO_CMDLINE_DEVICES
  scripts/config --enable PCI_HOST_GENERIC
  scripts/config --enable SERIAL_AMBA_PL011
  scripts/config --enable SERIAL_AMBA_PL011_CONSOLE
fi
make olddefconfig
echo "==> building kernel with $(nproc) jobs"
if [[ "$ARCH" == "aarch64" ]]; then
  make -j"$(nproc)" Image
  KERNEL_IMAGE="$WORK_ROOT/linux/arch/arm64/boot/Image"
else
  # QEMU x86_64 boots bzImage via -kernel; Firecracker x86_64 wants the
  # top-level uncompressed ELF (the compressed/boot/vmlinux stub has no
  # valid 64-bit entry point and is rejected as "Invalid entry address").
  # Build and install both (QEMU selects its image through
  # PICO_QEMU_KERNEL_PATH).
  make -j"$(nproc)" bzImage vmlinux
  KERNEL_IMAGE="$WORK_ROOT/linux/vmlinux"
  KERNEL_BZIMAGE="$WORK_ROOT/linux/arch/x86/boot/bzImage"
fi
ls -la "$KERNEL_IMAGE"
fi # want_step kernel

# ------------------------------------------------------------- guest agent
if want_step rootfs; then
if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup not found; install Rust via https://rustup.rs (distro cargo cannot add targets this way)" >&2
  exit 1
fi
if ! rustup target list --installed 2>/dev/null | grep -qx "$MUSL_TRIPLE"; then
  rustup target add "$MUSL_TRIPLE"
fi
cd "$REPO_ROOT"
cargo build -p pico-guest-agent --release --target "$MUSL_TRIPLE"
AGENT_BIN="$REPO_ROOT/target/$MUSL_TRIPLE/release/pico-guest-agent"
file "$AGENT_BIN"
fi # want_step rootfs

# ------------------------------------------------------------------ rootfs
if want_step rootfs; then
ALPINE_INDEX_URL="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/$ARCH/"
ALPINE_TARBALL="$WORK_ROOT/dl/alpine-minirootfs.tar.gz"
if [[ ! -f "$ALPINE_TARBALL" ]]; then
  if [[ -n "$ALPINE_VERSION" ]]; then
    LATEST="alpine-minirootfs-$ALPINE_VERSION-$ARCH.tar.gz"
    curl -fsSL -o /dev/null "${ALPINE_INDEX_URL}${LATEST}" \
      || { echo "error: Alpine $ALPINE_VERSION not found for $ARCH" >&2; exit 1; }
  else
    LATEST="$(curl -fsSL "$ALPINE_INDEX_URL" \
      | grep -o "alpine-minirootfs-[0-9.]*-$ARCH\.tar\.gz" \
      | sort -V | tail -n 1)"
    [[ -n "$LATEST" ]] || { echo "error: cannot resolve Alpine minirootfs" >&2; exit 1; }
  fi
  echo "==> Alpine rootfs: $LATEST"
  curl -fSL -o "$ALPINE_TARBALL" "${ALPINE_INDEX_URL}${LATEST}"
  # Verify against the published checksum like the kernel above.
  EXPECTED_SHA="$(curl -fsSL "${ALPINE_INDEX_URL}${LATEST}.sha256" | cut -d' ' -f1)"
  [[ -n "$EXPECTED_SHA" ]] || { echo "error: no published sha256 for $LATEST" >&2; exit 1; }
  ACTUAL_SHA="$(sha256sum "$ALPINE_TARBALL" | cut -d' ' -f1)"
  [[ "$EXPECTED_SHA" == "$ACTUAL_SHA" ]] || {
    echo "error: Alpine tarball sha256 mismatch (expected $EXPECTED_SHA, got $ACTUAL_SHA)" >&2
    exit 1
  }
fi

RW="$WORK_ROOT/rootfs-work"
rm -rf "$RW"; mkdir -p "$RW"; cd "$RW"
rm -f rootfs.ext4
truncate -s "$ROOTFS_SIZE" rootfs.ext4
mkfs.ext4 -F -q rootfs.ext4
mkdir -p mnt
# Drop a stale mount from a previously killed run before mounting, or the
# mount below fails and the rerun aborts.
sudo umount mnt 2>/dev/null || true
sudo mount -o loop rootfs.ext4 mnt
cleanup() { mountpoint -q mnt && sudo umount mnt || true; }
trap cleanup EXIT
sudo tar -xzf "$ALPINE_TARBALL" -C mnt
sudo mkdir -p mnt/usr/local/bin
sudo install -m755 "$AGENT_BIN" mnt/usr/local/bin/pico-agent
echo 'nameserver 1.1.1.1' | sudo tee mnt/etc/resolv.conf >/dev/null
sudo mount --bind /dev mnt/dev 2>/dev/null || true
sudo mount -t proc none mnt/proc 2>/dev/null || true
sudo mount -t sysfs none mnt/sys 2>/dev/null || true
sudo chroot mnt apk add --no-cache openssh-server
sudo umount mnt/sys 2>/dev/null || true
sudo umount mnt/proc 2>/dev/null || true
sudo umount mnt/dev 2>/dev/null || true
sudo install -m755 "$REPO_ROOT/scripts/guest-init.sh" mnt/init
sudo mkdir -p mnt/var/run/sshd mnt/var/log/pico mnt/run/pico/tmp
cleanup; trap - EXIT
fi # want_step rootfs

# ----------------------------------------------------------------- install
if [[ "$ASSET_ROOT" == /opt/* || "$ASSET_ROOT" == /srv/* ]]; then
  SUDO=sudo
else
  SUDO=""
fi
# shellcheck disable=SC2086 # intentional word splitting: empty $SUDO vanishes
$SUDO mkdir -p "$KERNEL_OUT_DIR"
if want_step kernel; then
  $SUDO cp "$KERNEL_IMAGE" "$KERNEL_OUT_DIR/vmlinux"
  if [[ -n "${KERNEL_BZIMAGE:-}" ]]; then
    $SUDO cp "$KERNEL_BZIMAGE" "$KERNEL_OUT_DIR/bzImage"
  fi
fi
if want_step rootfs; then
  $SUDO cp "$RW/rootfs.ext4" "$ASSET_ROOT/rootfs.ext4"
fi
# Firecracker opens the rootfs read-write, so the files must be writable by
# the user running the walk, not just readable.
if want_step kernel; then
  $SUDO chown "$(id -u):$(id -g)" "$KERNEL_OUT_DIR/vmlinux"
  $SUDO chmod 644 "$KERNEL_OUT_DIR/vmlinux" || true
  if [[ -n "${KERNEL_BZIMAGE:-}" && -f "$KERNEL_OUT_DIR/bzImage" ]]; then
    $SUDO chown "$(id -u):$(id -g)" "$KERNEL_OUT_DIR/bzImage"
    $SUDO chmod 644 "$KERNEL_OUT_DIR/bzImage" || true
  fi
fi
if want_step rootfs; then
  $SUDO chown "$(id -u):$(id -g)" "$ASSET_ROOT/rootfs.ext4"
  $SUDO chmod 644 "$ASSET_ROOT/rootfs.ext4" || true
fi

echo
if want_step kernel; then
  echo "kernel: $KERNEL_OUT_DIR/vmlinux"
fi
if want_step rootfs; then
  echo "rootfs: $ASSET_ROOT/rootfs.ext4"
fi
if command -v sha256sum >/dev/null 2>&1; then
  if want_step kernel; then sha256sum "$KERNEL_OUT_DIR/vmlinux"; fi
  if want_step rootfs; then sha256sum "$ASSET_ROOT/rootfs.ext4"; fi
fi
echo
echo "Walk env:"
echo "  PICO_FIRECRACKER_BIN=\$HOME/pico/vmm/firecracker  (install from"
echo "    https://github.com/firecracker-microvm/firecracker/releases, verify"
echo "    the checksum, and ensure the user can open /dev/kvm)"
if [[ "$ASSET_ROOT" != "/opt/pico" ]]; then
  echo "  PICO_ROOTFS_PATH=$ASSET_ROOT/rootfs.ext4"
  echo "  PICO_QEMU_KERNEL_PATH=$KERNEL_OUT_DIR/vmlinux"
fi
