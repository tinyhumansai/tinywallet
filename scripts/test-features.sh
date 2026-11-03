#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
  pwsh -NoProfile -File scripts/test-features.ps1
  exit
fi
# The client's native integration tests need the staged module artifact from
# test-e2e.sh. Run its library tests here, and leave the artifact-backed tests
# to that dedicated lane.
cargo test --locked --workspace --all-features --exclude tinywallet-client
cargo test --locked --workspace --exclude tinywallet-client
cargo test --locked -p tinywallet-client --lib --all-features
