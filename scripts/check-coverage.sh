#!/usr/bin/env bash
set -euo pipefail
report="target/coverage.json"
cargo llvm-cov --workspace --all-features --all-targets --json --output-path "$report"
below="$(jq -r --arg root "$PWD" '
  .data[0].files[]
  | select(.filename | contains("/src/"))
  | select(.filename | startswith($root + "/vendor/") | not)
  | select(.summary.lines.percent < 90)
  | "\(.filename): \(.summary.lines.percent)%"
' "$report")"
if [[ -n "$below" ]]; then
  echo "Files below 90% line coverage:" >&2
  echo "$below" >&2
  exit 1
fi
