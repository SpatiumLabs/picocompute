#!/usr/bin/env sh
# PicoCompute CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/SpatiumLabs/picocompute/main/install.sh | sh
#
# Environment:
#   PICO_VERSION      release tag to install (default: latest)
#   PICO_INSTALL_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)

set -eu

REPO="SpatiumLabs/picocompute"

log() { printf '%s\n' "$*" >&2; }
die() {
  log "error: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# Map the host to a published release artifact. The release workflow only builds
# Linux x86_64/aarch64 and macOS aarch64, so anything else is a hard error
# rather than a silent fallback.
detect_artifact() {
  os=$(uname -s)
  arch=$(uname -m)

  case "$arch" in
  x86_64 | amd64) cpu="x86_64" ;;
  aarch64 | arm64) cpu="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
  esac

  case "$os" in
  Linux) target="pico-${cpu}-unknown-linux-gnu" ;;
  Darwin)
    [ "$cpu" = "aarch64" ] ||
      die "no Intel macOS build is published; Apple silicon is required"
    target="pico-aarch64-apple-darwin"
    ;;
  *) die "unsupported operating system: $os" ;;
  esac

  printf '%s' "$target"
}

download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "curl or wget is required"
  fi
}

# sha256sum and shasum emit the same "<hash>  <file>" format, so either can
# verify a checksum file produced by the release workflow.
verify_checksum() {
  artifact="$1"
  dir="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dir" && sha256sum -c "$artifact.sha256" >/dev/null 2>&1)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$dir" && shasum -a 256 -c "$artifact.sha256" >/dev/null 2>&1)
  else
    die "sha256sum or shasum is required to verify the download"
  fi || die "checksum verification failed for $artifact"
}

main() {
  need_cmd uname

  artifact=$(detect_artifact)
  version="${PICO_VERSION:-latest}"

  if [ "$version" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$version"
  fi

  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t picocompute)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT INT TERM

  log "downloading $artifact ($version)"
  download "$base/$artifact" "$tmp/$artifact"
  download "$base/$artifact.sha256" "$tmp/$artifact.sha256"

  log "verifying checksum"
  verify_checksum "$artifact" "$tmp"

  install_dir="${PICO_INSTALL_DIR:-}"
  sudo_cmd=""
  if [ -z "$install_dir" ]; then
    if [ -w /usr/local/bin ]; then
      install_dir="/usr/local/bin"
    elif command -v sudo >/dev/null 2>&1; then
      install_dir="/usr/local/bin"
      sudo_cmd="sudo"
    else
      install_dir="$HOME/.local/bin"
      log "no write access to /usr/local/bin, falling back to $install_dir"
    fi
  fi

  chmod +x "$tmp/$artifact"
  if [ -n "$sudo_cmd" ]; then
    $sudo_cmd mkdir -p "$install_dir"
    $sudo_cmd mv "$tmp/$artifact" "$install_dir/pc"
  else
    mkdir -p "$install_dir"
    mv "$tmp/$artifact" "$install_dir/pc"
  fi

  log "installed pc to $install_dir/pc"
  case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) log "note: $install_dir is not on your PATH" ;;
  esac
}

main "$@"
