#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [[ "${1:-}" == --archive ]]; then shift; fi
archive="${1:?usage: verify-module.sh --archive <module-archive>}"
work="$(mktemp -d "${TMPDIR:-/tmp}/tinywallet-module-verify.XXXXXX")"
trap 'rm -rf "$work"' EXIT
case "$archive" in
  *.tar.gz) tar -xzf "$archive" -C "$work" ;;
  *) echo "unsupported module archive: $archive" >&2; exit 2 ;;
esac
case "$(uname -s)" in
  Darwin) library="$work/libtinywallet_module.dylib" ;;
  Linux) library="$work/libtinywallet_module.so" ;;
  *) echo "verify-module.sh requires a Unix runner" >&2; exit 1 ;;
esac
test -f "$work/modules.toml"
TINYWALLET_TEST_MODULE="$library" cargo test --locked --release \
  --package tinywallet-module --test module_e2e -- --ignored
