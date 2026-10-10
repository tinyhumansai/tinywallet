#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: test-distro.sh IMAGE --crate ...}"
shift
case "$image" in
  fedora:43|fedora:44|archlinux:base-devel|menci/archlinuxarm:base-devel) ;;
  *) echo "unsupported module build image: $image" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="" version="" rust_target="" host="" output="release-assets" extras='[]'
while (($#)); do
  case "$1" in
    --crate) crate="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --target) rust_target="$2"; shift 2 ;;
    --host) host="$2"; shift 2 ;;
    --extra-files-json) extras="$2"; shift 2 ;;
    --output-dir) output="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$crate" == tinywallet-module && -n "$version" && -n "$rust_target" && -n "$host" ]] || {
  echo "module crate, version, target, and host are required" >&2
  exit 2
}
[[ "$rust_target" == x86_64-unknown-linux-gnu || "$rust_target" == aarch64-unknown-linux-gnu ]] || {
  echo "unsupported distro target: $rust_target" >&2
  exit 2
}

mkdir -p "$root/$output"
docker run --rm \
  --volume "$root:/workspace" \
  --workdir /workspace \
  --env MODULE_CRATE="$crate" \
  --env MODULE_VERSION="$version" \
  --env MODULE_TARGET="$rust_target" \
  --env MODULE_HOST="$host" \
  --env EXTRA_PACKAGED_FILES="$extras" \
  --env OUTPUT_DIR="$output" \
  "$image" bash -lc '
    set -euo pipefail
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y gcc gcc-c++ cmake curl git gzip jq make openssl-devel perl tar
    else
      pacman -Syu --noconfirm base-devel cmake curl git gzip jq openssl perl
    fi
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    source "$HOME/.cargo/env"
    actual_target="$(rustc -vV | sed -n "s/^host: //p")"
    [[ "$actual_target" == "$MODULE_TARGET" ]] || {
      echo "expected $MODULE_TARGET in $MODULE_HOST image, got $actual_target" >&2
      exit 1
    }
    scripts/build-module.sh --crate "$MODULE_CRATE" --version "$MODULE_VERSION" \
      --target "$MODULE_TARGET" --host "$MODULE_HOST" \
      --extra-files-json "$EXTRA_PACKAGED_FILES" --output-dir "$OUTPUT_DIR"
    scripts/verify-module.sh --archive "$OUTPUT_DIR/$MODULE_CRATE-$MODULE_VERSION-$MODULE_HOST.tar.gz"
  '
