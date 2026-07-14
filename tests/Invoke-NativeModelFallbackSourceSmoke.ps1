$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$scannerPath = Join-Path $repoRoot "Protection\NativeModelScanner.cs"
$text = Get-Content -LiteralPath $scannerPath -Raw

if ($text -match 'return\s+new NativeModelScannerResult\(false,\s*0,\s*detectionName,\s*true,\s*error\s*\?\?\s*\$"native-status:') {
    throw "Native scan failures still return before managed fallback."
}
if ($text -notmatch 'NativeModelScannerResult\?\s+nativeFailure') {
    throw "Native failure preservation was not found."
}
if ($text -notmatch 'NativeModelScannerResult\s+managedResult\s*=\s*ScanWithManagedInvokerFallback\(path\)') {
    throw "Managed fallback after native failure was not found."
}
if ($text -notmatch 'native-error:\{nativeFailure\.ErrorMessage\};managed-error:\{managedResult\.ErrorMessage\}') {
    throw "Combined native and managed error diagnostics were not found."
}

Write-Host "Native model fallback source smoke passed."
