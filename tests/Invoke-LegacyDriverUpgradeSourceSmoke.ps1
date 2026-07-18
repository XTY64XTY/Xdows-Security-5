$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$protocolPath = Join-Path $repoRoot "Protection\DriverProtocol.cs"
$bridgePath = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
$installerPath = Join-Path $repoRoot "Protection\DriverInstaller.cs"

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $Path"
    }
}

function Assert-NotMatch([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match $Pattern) {
        throw "$Name is still present in $Path"
    }
}

Assert-Match $protocolPath 'LegacyUpgradeProtocolVersion\s*=\s*5;' 'exact legacy upgrade protocol version'
Assert-Match $protocolPath 'LegacyUpgradeDriverBuildId\s*=\s*2026071704;' 'exact legacy upgrade driver build ID'
Assert-Match $protocolPath 'PreviousLegacyUpgradeDriverBuildId\s*=\s*2026071703;' 'exact previous legacy upgrade driver build ID'
Assert-Match $bridgePath 'TryAuthorizeLegacyUpgradeShutdown' 'legacy token authorization API'
Assert-Match $bridgePath 'response\.ProtocolVersion\s*==\s*DriverProtocol\.LegacyUpgradeProtocolVersion' 'exact legacy protocol acceptance'
Assert-Match $bridgePath 'response\.DriverBuildId\s*==\s*DriverProtocol\.LegacyUpgradeDriverBuildId' 'exact legacy build acceptance'
Assert-Match $bridgePath 'response\.DriverBuildId\s*==\s*DriverProtocol\.PreviousLegacyUpgradeDriverBuildId' 'exact previous legacy build acceptance'
Assert-Match $bridgePath 'DriverProtocol\.LegacyUpgradeProtocolVersion(?s:.*?)DriverProtocol\.AuthorizedShutdown' 'legacy token submitted through authorized shutdown IOCTL'
Assert-Match $installerPath 'initial\.Service\.IsRunning(?s:.*?)initial\.RuntimeStatus\s*!=\s*DriverProtectionRuntimeStatus\.NeedsRepair(?s:.*?)TryStopLegacyDriverForUpgradeAsync' 'running mismatched driver migration attempt'
Assert-Match $installerPath 'TryAuthorizeLegacyUpgradeShutdown(?s:.*?)DriverServiceControl\.Stop\(ServiceName\)(?s:.*?)WaitForServiceStateAsync\(\s*DriverServiceState\.Stopped' 'legacy authorize-stop-wait sequence'
Assert-NotMatch $bridgePath 'LegacyUpgradeDriverBuildId\s*(?:<=|>=|<|>)' 'range-based legacy build acceptance'
Assert-NotMatch $bridgePath 'PreviousLegacyUpgradeDriverBuildId\s*(?:<=|>=|<|>)' 'range-based previous legacy build acceptance'

Write-Host "Legacy driver upgrade source smoke passed."
