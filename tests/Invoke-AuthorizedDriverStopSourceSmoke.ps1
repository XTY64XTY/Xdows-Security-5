$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$protectionPath = Join-Path $repoRoot "Protection\DriverProtection.cs"
$serviceControlPath = Join-Path $repoRoot "Protection\DriverServiceControl.cs"

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

Assert-Match $serviceControlPath 'public\s+static\s+DriverServiceOperationResult\s+Stop\(string\s+serviceName\)' 'trusted SCM stop API'
Assert-Match $serviceControlPath 'ServiceStop(?s:.*?)OpenService(?s:.*?)ControlService' 'SERVICE_STOP request path'
Assert-Match $protectionPath 'public\s+bool\s+Stop\(\)(?s:.*?)SubmitAuthorizedShutdown\(\)(?s:.*?)CleanupLocked\(\)(?s:.*?)DriverServiceControl\.Stop\(DriverPackageLocator\.ServiceName\)' 'token-close-handles-SCM stop order'
Assert-Match $protectionPath 'DriverServiceControl\.Stop(?s:.*?)!stop\.Success(?s:.*?)RelockDriverUnloadAfterFailedStop' 'failed stop unload relock'
Assert-Match $protectionPath 'RelockDriverUnloadAfterFailedStop(?s:.*?)new\s+DriverBridgeClient\(\)(?s:.*?)Connect\(\)' 'fresh client registration relock'
Assert-NotMatch $protectionPath '_client\?\.SubmitAuthorizedShutdown\(\);' 'ignored shutdown authorization result'

Write-Host "Authorized driver stop source smoke passed."
