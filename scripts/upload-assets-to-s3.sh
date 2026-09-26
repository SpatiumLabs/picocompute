#!/usr/bin/env bash
set -euo pipefail

# Upload VM assets to S3 as a cache layer identified by commit hash.
# This allows cloud-init and dev builds to skip kernel compilation and
# rootfs assembly when artifacts already exist for the current commit.
#
# Usage:
#   ./scripts/upload-assets-to-s3.sh \
#     --arch aarch64 \
#     --kernel /path/to/vmlinux \
#     --rootfs /path/to/rootfs.ext4 \
#     --guest-agent /path/to/pico-guest-agent
#
# Env vars:
#   ASSET_CACHE_BUCKET   S3 bucket name (default: pico-asset-cache)
#   ASSET_CACHE_PREFIX   S3 key prefix (default: assets)
#   AWS_PROFILE          AWS profile (optional, uses default credential chain if not set)
#   COMMIT_HASH          Git commit hash (default: auto-detect from repo root)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- defaults ---
ASSET_CACHE_BUCKET="${ASSET_CACHE_BUCKET:-pico-asset-cache}"
ASSET_CACHE_PREFIX="${ASSET_CACHE_PREFIX:-assets}"
AWS_PROFILE="${AWS_PROFILE:-}"
COMMIT_HASH="${COMMIT_HASH:-"$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"}"
ARCH="${ARCH:-}"

AWS_ARGS=()
if [[ -n "$AWS_PROFILE" ]]; then
  AWS_ARGS=(--profile "$AWS_PROFILE")
fi

usage() {
  cat <<EOF
Usage: $0 --arch <arch> --kernel <vmlinux> --rootfs <rootfs.ext4> --guest-agent <pico-guest-agent>

Uploads VM assets to s3://$ASSET_CACHE_BUCKET/$ASSET_CACHE_PREFIX/<commit>/<arch>/
EOF
  exit 1
}

# --- parse args ---
arch=""
kernel=""
rootfs=""
guest_agent=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) arch="$2"; shift 2 ;;
    --kernel) kernel="$2"; shift 2 ;;
    --rootfs) rootfs="$2"; shift 2 ;;
    --guest-agent) guest_agent="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "error: unknown argument $1"; usage ;;
  esac
done

arch="${arch:-$ARCH}"
if [[ -z "$arch" ]]; then
  echo "error: --arch is required (e.g. aarch64, x86_64)" >&2
  usage
fi

if [[ -z "$kernel" || -z "$rootfs" || -z "$guest_agent" ]]; then
  echo "error: --kernel, --rootfs, and --guest-agent are required"
  usage
fi

if [[ ! -f "$kernel" ]]; then
  echo "error: kernel not found at $kernel" >&2
  exit 1
fi
if [[ ! -f "$rootfs" ]]; then
  echo "error: rootfs not found at $rootfs" >&2
  exit 1
fi
if [[ ! -f "$guest_agent" ]]; then
  echo "error: guest-agent not found at $guest_agent" >&2
  exit 1
fi

if [[ -z "$COMMIT_HASH" ]]; then
  echo "error: COMMIT_HASH is empty (not in a git repo? set COMMIT_HASH manually)" >&2
  exit 1
fi

echo "==> commit: $COMMIT_HASH"
echo "==> arch:   $arch"
echo "==> bucket: $ASSET_CACHE_BUCKET"
echo "==> prefix: $ASSET_CACHE_PREFIX"

# --- ensure bucket exists ---
echo "==> ensuring S3 bucket $ASSET_CACHE_BUCKET exists..."
if ! aws s3api head-bucket --bucket "$ASSET_CACHE_BUCKET" "${AWS_ARGS[@]}" 2>/dev/null; then
  aws s3 mb "s3://$ASSET_CACHE_BUCKET" "${AWS_ARGS[@]}"
  echo "  created bucket $ASSET_CACHE_BUCKET"
fi

# --- compute checksums and upload ---
base_key="$ASSET_CACHE_PREFIX/$COMMIT_HASH/$arch"
upload_ok=true

upload_asset() {
  local relpath="$1"
  local src="$2"
  local dst="s3://$ASSET_CACHE_BUCKET/$base_key/$relpath"

  echo "==> uploading $relpath..."
  sha=$(shasum -a 256 "$src" | cut -d' ' -f1)
  if aws s3 cp "$src" "$dst" "${AWS_ARGS[@]}"; then
    echo "  sha256: $sha"
    echo "  s3://$ASSET_CACHE_BUCKET/$base_key/$relpath"
  else
    echo "  error: upload failed for $relpath" >&2
    upload_ok=false
  fi
}

upload_asset "kernel/vmlinux" "$kernel"
upload_asset "rootfs.ext4" "$rootfs"
upload_asset "pico-guest-agent" "$guest_agent"

# --- upload a manifest file with checksums ---
echo "==> writing manifest..."
manifest=$(mktemp)
trap 'rm -f "$manifest"' EXIT
{
  echo "commit: $COMMIT_HASH"
  echo "arch: $arch"
  echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel/vmlinux: sha256=$(shasum -a 256 "$kernel" | cut -d' ' -f1) size=$(wc -c < "$kernel" | tr -d ' ')"
  echo "rootfs.ext4: sha256=$(shasum -a 256 "$rootfs" | cut -d' ' -f1) size=$(wc -c < "$rootfs" | tr -d ' ')"
  echo "pico-guest-agent: sha256=$(shasum -a 256 "$guest_agent" | cut -d' ' -f1) size=$(wc -c < "$guest_agent" | tr -d ' ')"
} > "$manifest"
aws s3 cp "$manifest" "s3://$ASSET_CACHE_BUCKET/$base_key/manifest.txt" "${AWS_ARGS[@]}"

echo
echo "=== summary ==="
echo "commit: $COMMIT_HASH"
echo "arch:   $arch"
echo "bucket: $ASSET_CACHE_BUCKET"
echo "prefix: $ASSET_CACHE_PREFIX/$COMMIT_HASH/$arch"
echo "manifest: s3://$ASSET_CACHE_BUCKET/$base_key/manifest.txt"
echo
if $upload_ok; then
  echo "upload complete"
else
  echo "upload completed with errors" >&2
  exit 1
fi
