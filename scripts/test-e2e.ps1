$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
$stage = Join-Path $target 'tinywallet-module-e2e'

cargo build --locked --release --package tinywallet-module
if ($LASTEXITCODE -ne 0) { throw 'Failed to build tinywallet-module' }
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
# The loader refuses a staged module when another principal can replace it.
# GitHub's Windows runner inherits broad ACEs from D:\a, so make this directory
# private before copying the digest-pinned artifact into it.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$runnerSid = "*$($identity.User.Value):(OI)(CI)F"
$adminSid = '*S-1-5-32-544:(OI)(CI)F'
$systemSid = '*S-1-5-18:(OI)(CI)F'
icacls $stage /inheritance:r /grant:r $runnerSid $adminSid $systemSid | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict module test directory permissions: $stage" }
icacls $stage /setowner $identity.Name | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set module test directory owner: $stage" }
$library = Join-Path $stage 'tinywallet_module.dll'
Copy-Item -LiteralPath (Join-Path $target 'release/tinywallet_module.dll') -Destination $library
$hash = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
'"tinywallet_module.dll" = "{0}"' -f $hash |
    Set-Content -Path (Join-Path $stage 'modules.toml') -Encoding utf8NoBOM
$env:TINYWALLET_TEST_MODULE = $library
cargo test --locked --release --package tinywallet-module --test module_e2e -- --ignored
if ($LASTEXITCODE -ne 0) { throw 'TinyWallet module E2E failed' }
