$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$publicPath = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
$protocolPath = Join-Path $repoRoot "Protection\DriverProtocol.cs"
$protectionPath = Join-Path $repoRoot "Protection\DriverProtection.cs"

$public = Get-Content -LiteralPath $publicPath -Raw
$protocol = Get-Content -LiteralPath $protocolPath -Raw
$protection = Get-Content -LiteralPath $protectionPath -Raw

if ($public -notmatch 'XDOWS_SECURITY_PROTOCOL_VERSION\s+4u' -or
    $protocol -notmatch 'ProtocolVersion\s*=\s*4;') {
    throw "Protocol v4 is not mirrored."
}
if ($public -notmatch 'ULONG\s+FileProtectionEnabled;\s*ULONG\s+SelfProtectionEnabled;\s*ULONG\s+ProtectedProcessId;\s*ULONG\s+StartupProtectionEnabled;\s*ULONG\s+ActiveModules;' -or
    $protocol -notmatch 'uint\s+FileProtectionEnabled;\s*public\s+uint\s+SelfProtectionEnabled;\s*public\s+uint\s+ProtectedProcessId;\s*public\s+uint\s+StartupProtectionEnabled;\s*public\s+uint\s+ActiveModules;') {
    throw "Self-protection state field order is not mirrored."
}
if ($protection -notmatch 'SelfProtectionEnabled\s*==\s*0' -or
    $protection -notmatch 'ProtectedProcessId\s*!=\s*\(uint\)Environment\.ProcessId') {
    throw "Managed runtime self-protection validation was not found."
}
if ($protection -notmatch 'RegisterProtectedProcess\(\);(?s:.*?)state\s*=\s*_client\.GetState\(\)(?s:.*?)SelfProtectionEnabled') {
    throw "Post-registration self-protection state verification was not found."
}
if ($protection -notmatch 'SetStartupProtection\(startupProtectionEnabled\)(?s:.*?)StartupProtectionEnabled') {
    throw "Post-registration startup self-protection verification was not found."
}

Write-Host "Self-protection protocol mirror smoke passed."
