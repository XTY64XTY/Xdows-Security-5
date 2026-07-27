$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$files = @{
    Public = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
    Process = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\ProcessProtect.c"
    Injection = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\InjectionProtect.c"
    Protocol = Join-Path $repoRoot "Protection\DriverProtocol.cs"
    Protection = Join-Path $repoRoot "Protection\DriverProtection.cs"
    App = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required source file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

Assert-Match $files.Public 'XdowsSecurityEventBehavior\s*=\s*9' 'native behavior event'
Assert-Match $files.Protocol 'Behavior\s*=\s*9' 'managed behavior event'
Assert-Match $files.Public 'ULONG\s+BehaviorType;' 'native behavior payload'
Assert-Match $files.Protocol 'uint\s+BehaviorType;' 'managed behavior payload'
Assert-Match $files.Public 'XDOWS_SECURITY_CAP_R0_BEHAVIOR_PROTECTION\s+0x00000080u' 'native behavior capability'
Assert-Match $files.Protocol 'CapabilityR0BehaviorProtection\s*=\s*0x00000080' 'managed behavior capability'
Assert-Match $files.Public 'XDOWS_SECURITY_MODULE_BEHAVIOR\s+0x00000020u' 'native behavior module'
Assert-Match $files.Protocol 'ModuleBehavior\s*=\s*0x00000020' 'managed behavior module'

Assert-Match $files.Process 'XdowsProcessApplyBehaviorPolicy(?s:.*?)XdowsSecurityEventFlagThreatConfirmed(?s:.*?)XdowsQueueEventAndWait' 'process behavior held for decision'
Assert-Match $files.Injection 'XdowsSecurityBehaviorProcessInjection(?s:.*?)XdowsSecurityBehaviorThreadInjection' 'injection behavior correlation'
Assert-Match $files.Protection 'HandleBehaviorEventAsync(?s:.*?)TryEnterUserDecisionHold\(driverEvent\)(?s:.*?)SignerTrustService\.TryResolveProcessPath' 'pending hold precedes target path resolution'
Assert-Match $files.Protection 'HandleBehaviorEventAsync(?s:.*?)ProtectionModule\.Behavior(?s:.*?)AskUserAfterHoldAsync' 'behavior request uses interactive decision path'

foreach ($detection in @(
    'ShadowCopyDestruction',
    'HiddenPowerShell',
    'EncodedCommand',
    'PolicyBypass',
    'DownloadExecute',
    'LolbinAbuse',
    'ProcessInjection',
    'ThreadInjection'
)) {
    Assert-Match $files.Protection "Xdows\.Behavior\.$detection" "$detection detection mapping"
}

Assert-Match $files.App 'request\.Module\s*!=\s*Helper\.ProtectionModule\.Behavior(?s:.*?)ShouldUseCompactAsync' 'behavior decisions bypass compact auto-block mode'

Write-Host "R0 behavior protection managed source smoke passed."
