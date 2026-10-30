$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

cargo test --locked --workspace --all-features --exclude tinywallet-client
if ($LASTEXITCODE -ne 0) { throw 'TinyWallet all-feature workspace tests failed' }

cargo test --locked --workspace --exclude tinywallet-client
if ($LASTEXITCODE -ne 0) { throw 'TinyWallet default workspace tests failed' }

cargo test --locked -p tinywallet-client --lib --all-features
if ($LASTEXITCODE -ne 0) { throw 'TinyWallet all-feature client library tests failed' }
