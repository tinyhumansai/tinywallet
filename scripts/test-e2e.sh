#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  pwsh -NoProfile -File scripts/test-e2e.ps1
  exit
fi
target="${CARGO_TARGET_DIR:-$root/target}"
[[ "$target" == /* ]] || target="$root/$target"
mkdir -p "$target"
target="$(cd "$target" && pwd -P)"
[[ "$target" == "$root"/* ]] || { echo "CARGO_TARGET_DIR must stay inside the repository" >&2; exit 2; }
host="$(rustc -vV | sed -n 's/^host: //p')"
case "$host" in
  *-apple-darwin) name="libtinywallet_module.dylib" ;;
  *-linux-gnu) name="libtinywallet_module.so" ;;
  *-windows-*) echo "test-e2e.sh requires a Unix runner" >&2; exit 1 ;;
  *) echo "unsupported E2E host target: $host" >&2; exit 2 ;;
esac

cargo build --locked --release --package tinywallet-module
stage="$target/tinywallet-module-e2e"
rm -rf "$stage"
mkdir -p "$stage"
install -m 755 "$target/release/$name" "$stage/$name"
if command -v sha256sum >/dev/null 2>&1; then
  hash="$(sha256sum "$stage/$name" | awk '{print $1}')"
else
  hash="$(shasum -a 256 "$stage/$name" | awk '{print $1}')"
fi
printf '"%s" = "%s"\n' "$name" "$hash" > "$stage/modules.toml"
TINYWALLET_TEST_MODULE="$stage/$name" cargo test --locked --release \
  --package tinywallet-module --test module_e2e -- --ignored
TINYWALLET_TEST_MODULE="$stage/$name" cargo test --locked --release \
  --package tinywallet-module --test lifecycle_e2e -- --ignored

# The client integration tests use the same release module through its
# hash-verified local cache. Keep that artifact separate from the loader's
# ordinary module directory, then provide distinct attested and unattested
# library copies for the rejection cases.
client_cache="$target/tinywallet-client-e2e-cache"
unattested_dir="$target/tinywallet-client-unattested"
archive_name="tinywallet-module-client-test.tar.gz"
archive_path="$target/$archive_name"
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
rm -rf "$client_cache" "$unattested_dir" "$archive_path"
mkdir -m 700 "$client_cache" "$unattested_dir"
install -m 755 "$stage/$name" "$client_cache/$name"
install -m 644 "$stage/modules.toml" "$client_cache/modules.toml"
install -m 755 "$stage/$name" "$unattested_dir/$name"
(
  cd "$target"
  tar -czf "$archive_name" -C "$(basename "$client_cache")" .
)
archive_hash="$(sha256 "$archive_path")"
library_hash="$(sha256 "$stage/$name")"
install -m 644 "$archive_path" "$client_cache/$archive_name"
TINYWALLET_CLIENT_TEST_CACHE="$client_cache" \
TINYWALLET_CLIENT_TEST_ARCHIVE_NAME="$archive_name" \
TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256="$archive_hash" \
TINYWALLET_CLIENT_TEST_LIBRARY_SHA256="$library_hash" \
TINYWALLET_CLIENT_UNATTESTED_MODULE="$unattested_dir/$name" \
  cargo test --locked --release --package tinywallet-client \
    --features native-e2e --test native_e2e -- --test-threads=1
TINYWALLET_CLIENT_TEST_CACHE="$client_cache" \
TINYWALLET_CLIENT_TEST_ARCHIVE_NAME="$archive_name" \
TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256="$archive_hash" \
TINYWALLET_CLIENT_TEST_LIBRARY_SHA256="$library_hash" \
TINYWALLET_CLIENT_UNATTESTED_MODULE="$unattested_dir/$name" \
  cargo test --locked --release --package tinywallet-client \
    --features native-e2e --test attested_errors -- --test-threads=1
TINYWALLET_CLIENT_TEST_CACHE="$client_cache" \
TINYWALLET_CLIENT_TEST_ARCHIVE_NAME="$archive_name" \
TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256="$archive_hash" \
TINYWALLET_CLIENT_TEST_LIBRARY_SHA256="$library_hash" \
TINYWALLET_CLIENT_UNATTESTED_MODULE="$unattested_dir/$name" \
  cargo test --locked --release --package tinywallet-client \
    --features native-e2e --test native_unattested -- --test-threads=1
