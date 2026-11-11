#!/usr/bin/env bash
set -euo pipefail

if command -v dnf >/dev/null 2>&1; then
  dnf install -y gcc gcc-c++ cmake curl git gzip jq make openssl-devel perl tar
else
  # The pinned Arch image runs inside Docker on hosted runners, where the
  # inner package-manager sandbox cannot be applied. Docker already isolates
  # the container, so disable only that nested sandbox.
  pacman -Syu --noconfirm --disable-sandbox base-devel cmake curl git gzip jq openssl perl
fi

case "$(uname -m)" in
  x86_64) rustup_target=x86_64-unknown-linux-gnu; rustup_sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
  aarch64) rustup_target=aarch64-unknown-linux-gnu; rustup_sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
  *) echo "unsupported rustup installer architecture: $(uname -m)" >&2; exit 2 ;;
esac

installer="$HOME/.cache/rustup-init"
mkdir -p "$(dirname "$installer")"
curl --proto "=https" --tlsv1.2 --fail --silent --show-error \
  "https://static.rust-lang.org/rustup/archive/1.28.2/$rustup_target/rustup-init" \
  --output "$installer"
echo "$rustup_sha  $installer" | sha256sum --check --status || {
  echo "rustup-init checksum verification failed" >&2
  exit 1
}
chmod +x "$installer"
"$installer" -y --profile minimal --default-toolchain 1.89.0 --no-modify-path
rm -f "$installer"
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
