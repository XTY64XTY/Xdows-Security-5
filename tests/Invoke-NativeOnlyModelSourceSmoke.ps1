$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$scannerPath = Join-Path $repoRoot "Protection\NativeModelScanner.cs"
$text = Get-Content -LiteralPath $scannerPath -Raw

foreach ($forbidden in @(
    'ScanWithManagedInvokerFallback',
    'Xdows_Model_Invoker.ModelInvoker',
    'InitializeFlash\(',
    'InitializePro\('
)) {
    if ($text -match $forbidden) {
        throw "Managed model fallback remains in native driver scanner: $forbidden"
    }
}

if ($text -notmatch '_nativeInitializationError\s*=\s*\$"native-init-status:\{status\}"') {
    throw "Native initialization status diagnostics were not found."
}
if ($text -notmatch 'if\s*\(!_nativeReady\)(?s:.*?)native-not-ready') {
    throw "Native-only unavailable verdict was not found."
}
if ($text -notmatch 'native-status:\{status\}/\{nativeResult\.Status\}') {
    throw "Native scan status diagnostics were not found."
}

Write-Host "Native-only driver model source smoke passed."
