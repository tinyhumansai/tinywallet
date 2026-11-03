param([switch]$PrepareOnly)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
New-Item -ItemType Directory -Force $target | Out-Null
$target = (Resolve-Path -LiteralPath $target).Path
$rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $target.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'CARGO_TARGET_DIR must stay inside the repository' }
$nativeTestLogs = Join-Path $target 'tinywallet-native-e2e-logs'
Remove-Item -LiteralPath $nativeTestLogs -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $nativeTestLogs | Out-Null

function Invoke-CountedNativeTest {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$ExpectedCount,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $logPath = Join-Path $nativeTestLogs "$Name.log"
    & cargo test @Arguments 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "TinyWallet native E2E target failed: $Name" }
    $summaries = @(Select-String -Path $logPath -Pattern '^test result: ok\. (\d+) passed;')
    if ($summaries.Count -eq 0) { throw "TinyWallet native E2E target reported no test result: $Name" }
    $actualCount = [int]$summaries[-1].Matches[0].Groups[1].Value
    if ($actualCount -ne $ExpectedCount) {
        throw "TinyWallet native E2E target $Name ran $actualCount tests; expected $ExpectedCount"
    }
}

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
icacls $stage /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not reset module test directory permissions: $stage" }
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
if (-not $PrepareOnly) {
    Invoke-CountedNativeTest -Name 'module_e2e' -ExpectedCount 2 -Arguments @(
        '--locked', '--release', '--package', 'tinywallet-module', '--test', 'module_e2e', '--', '--ignored'
    )
    Invoke-CountedNativeTest -Name 'lifecycle_e2e' -ExpectedCount 1 -Arguments @(
        '--locked', '--release', '--package', 'tinywallet-module', '--test', 'lifecycle_e2e', '--', '--ignored'
    )
}

# Build a local archive/cache from the same release cdylib. The Rust client
# fixture uses CachedRelease with downloads disabled and verifies both hashes.
$clientCache = Join-Path $target 'tinywallet-client-e2e-cache'
$unattestedDir = Join-Path $target 'tinywallet-client-unattested'
$archiveName = 'tinywallet-module-client-test.tar.gz'
$archivePath = Join-Path $target $archiveName
Remove-Item -LiteralPath $clientCache, $unattestedDir, $archivePath -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $clientCache, $unattestedDir | Out-Null
foreach ($privateDir in @($clientCache, $unattestedDir)) {
    icacls $privateDir /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not reset module test directory permissions: $privateDir" }
    icacls $privateDir /inheritance:r /grant:r $runnerSid $adminSid $systemSid | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not restrict module test directory permissions: $privateDir" }
    icacls $privateDir /setowner $identity.Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not set module test directory owner: $privateDir" }
}
$library = Join-Path $clientCache 'tinywallet_module.dll'
Copy-Item -LiteralPath (Join-Path $stage 'tinywallet_module.dll') -Destination $library
Copy-Item -LiteralPath (Join-Path $stage 'modules.toml') -Destination (Join-Path $clientCache 'modules.toml')
Push-Location $target
try {
    & tar.exe -czf $archiveName -C 'tinywallet-client-e2e-cache' .
    $archiveExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($archiveExitCode -ne 0) { throw 'Could not archive the local TinyWallet test module' }
Copy-Item -LiteralPath $archivePath -Destination (Join-Path $clientCache $archiveName)
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$libraryHash = (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
$unattestedModule = Join-Path $unattestedDir 'tinywallet_module.dll'
Copy-Item -LiteralPath (Join-Path $stage 'tinywallet_module.dll') -Destination $unattestedModule

$env:TINYWALLET_CLIENT_TEST_CACHE = $clientCache
$env:TINYWALLET_CLIENT_TEST_ARCHIVE_NAME = $archiveName
$env:TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256 = $archiveHash
$env:TINYWALLET_CLIENT_TEST_LIBRARY_SHA256 = $libraryHash
$env:TINYWALLET_CLIENT_UNATTESTED_MODULE = $unattestedModule
if ($PrepareOnly) { return }

Invoke-CountedNativeTest -Name 'native_e2e' -ExpectedCount 3 -Arguments @(
    '--locked', '--release', '--package', 'tinywallet-client',
    '--features', 'native-e2e', '--test', 'native_e2e', '--', '--test-threads=1'
)
Invoke-CountedNativeTest -Name 'attested_errors' -ExpectedCount 1 -Arguments @(
    '--locked', '--release', '--package', 'tinywallet-client',
    '--features', 'native-e2e', '--test', 'attested_errors', '--', '--test-threads=1'
)
Invoke-CountedNativeTest -Name 'native_unattested' -ExpectedCount 1 -Arguments @(
    '--locked', '--release', '--package', 'tinywallet-client',
    '--features', 'native-e2e', '--test', 'native_unattested', '--', '--test-threads=1'
)
