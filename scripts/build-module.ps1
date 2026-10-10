param(
    [Parameter(Mandatory = $true)][string]$Crate,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$HostKey,
    [string]$ExtraFilesJson = '[]',
    [string]$OutputDir = 'release-assets'
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
if ($Crate -ne 'tinywallet-module') { throw "Unsupported module crate: $Crate" }
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }

cargo build --locked --release --package $Crate --target $Target
if ($LASTEXITCODE -ne 0) { throw 'Failed to build tinywallet-module' }
$stage = Join-Path $targetRoot 'module-package'
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage, $OutputDir | Out-Null
$library = Join-Path $targetRoot "$Target/release/tinywallet_module.dll"
Copy-Item -LiteralPath $library -Destination $stage
$hash = (Get-FileHash -LiteralPath (Join-Path $stage 'tinywallet_module.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
'"tinywallet_module.dll" = "{0}"' -f $hash | Set-Content -Path (Join-Path $stage 'modules.toml') -Encoding utf8NoBOM
Copy-Item -LiteralPath 'LICENSE', 'README.md' -Destination $stage
foreach ($file in ($ExtraFilesJson | ConvertFrom-Json)) {
    $destination = Join-Path $stage $file
    New-Item -ItemType Directory -Force (Split-Path $destination) | Out-Null
    Copy-Item -LiteralPath $file -Destination $destination
}
$archive = Join-Path $OutputDir "$Crate-$Version-$HostKey.zip"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output $archive
