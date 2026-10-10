#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
target_root="${CARGO_TARGET_DIR:-$root/target}"
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
  echo "usage: build-module.sh --crate tinywallet-module --version VERSION --target TARGET --host HOST [--extra-files-json JSON] [--output-dir DIR]" >&2
  exit 2
}
case "$(uname -s)" in
  Darwin) extension=dylib; library="libtinywallet_module.$extension" ;;
  Linux) extension=so; library="libtinywallet_module.$extension" ;;
  *) echo "build-module.sh requires a Unix runner" >&2; exit 1 ;;
esac
cargo build --locked --release --package "$crate" --target "$rust_target"
stage="$target_root/module-package"
rm -rf "$stage"
mkdir -p "$stage" "$output"
install -m 755 "$target_root/$rust_target/release/$library" "$stage/$library"
if command -v sha256sum >/dev/null 2>&1; then
  hash="$(sha256sum "$stage/$library" | awk '{print $1}')"
else
  hash="$(shasum -a 256 "$stage/$library" | awk '{print $1}')"
fi
printf '"%s" = "%s"\n' "$library" "$hash" > "$stage/modules.toml"
cp LICENSE README.md "$stage/"
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  mkdir -p "$stage/$(dirname "$file")"
  cp "$file" "$stage/$file"
done < <(jq -r '.[]' <<<"$extras")
archive="$output/${crate}-${version}-${host}.tar.gz"
tar -C "$stage" -czf "$archive" .
echo "$archive"
