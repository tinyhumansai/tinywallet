#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
