param([Parameter(Mandatory = $true)][string]$Archive)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $work
    $library = Join-Path $work 'tinywallet_module.dll'
    if (-not (Test-Path (Join-Path $work 'modules.toml'))) { throw 'modules.toml missing from archive' }
    $env:TINYWALLET_TEST_MODULE = $library
    cargo test --locked --release --package tinywallet-module --test module_e2e -- --ignored
    if ($LASTEXITCODE -ne 0) { throw 'TinyWallet module verification failed' }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
