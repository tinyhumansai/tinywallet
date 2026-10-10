param([Parameter(Mandatory = $true)][string]$Archive)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $resolvedArchive = (Resolve-Path -LiteralPath $Archive).Path
    $zip = [System.IO.Compression.ZipFile]::OpenRead($resolvedArchive)
    try {
        foreach ($entry in $zip.Entries) {
            $parts = $entry.FullName -split '[\\/]'
            $mode = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ([IO.Path]::IsPathRooted($entry.FullName) -or ($parts -contains '..') -or ($parts -contains '.') -or $mode -eq 0xA000) {
                throw "Archive member is unsafe: $($entry.FullName)"
            }
        }
    } finally {
        $zip.Dispose()
    }
    Expand-Archive -LiteralPath $Archive -DestinationPath $work
    $library = Join-Path $work 'tinywallet_module.dll'
    if (-not (Test-Path (Join-Path $work 'modules.toml'))) { throw 'modules.toml missing from archive' }
    $env:TINYWALLET_TEST_MODULE = $library
    cargo test --locked --release --package tinywallet-module --test module_e2e -- --ignored
    if ($LASTEXITCODE -ne 0) { throw 'TinyWallet module verification failed' }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
