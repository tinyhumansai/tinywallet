$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
$stage = Join-Path $target 'tinywallet-module-e2e'

cargo build --locked --release --package tinywallet-module
if ($LASTEXITCODE -ne 0) { throw 'Failed to build tinywallet-module' }
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
$library = Join-Path $stage 'tinywallet_module.dll'
Copy-Item -LiteralPath (Join-Path $target 'release/tinywallet_module.dll') -Destination $library
$hash = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
'"tinywallet_module.dll" = "{0}"' -f $hash |
    Set-Content -Path (Join-Path $stage 'modules.toml') -Encoding utf8NoBOM
$env:TINYWALLET_TEST_MODULE = $library
cargo test --locked --release --package tinywallet-module --test module_e2e -- --ignored
if ($LASTEXITCODE -ne 0) { throw 'TinyWallet module E2E failed' }
