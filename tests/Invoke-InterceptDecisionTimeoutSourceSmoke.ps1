$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$files = @{
    Protocol = Join-Path $repoRoot "Protection\DriverProtocol.cs"
    Bridge = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
    Protection = Join-Path $repoRoot "Protection\DriverProtection.cs"
    Callback = Join-Path $repoRoot "Protection\CallBack.cs"
    Helper = Join-Path $repoRoot "Helper\InterceptWindowHelper.cs"
    App = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
    Window = Join-Path $repoRoot "Xdows-Security\InterceptWindow.xaml.cs"
    DriverPublic = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required source file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

Assert-Match $files.Protocol 'ProtocolVersion\s*=\s*6' 'managed protocol v6'
Assert-Match $files.Protocol 'DriverBuildId\s*=\s*2026072801' 'managed driver build identity'
Assert-Match $files.Protocol 'Pending\s*=\s*4' 'managed pending verdict'
Assert-Match $files.Protocol 'CapabilityUserDecisionHold\s*=\s*0x00000010' 'managed user-decision capability'
Assert-Match $files.DriverPublic 'XDOWS_SECURITY_CAP_USER_DECISION_HOLD\s+0x00000010u' 'native user-decision capability'
Assert-Match $files.Bridge 'SubmitPendingDecision\(ulong eventId\)(?s:.*?)XdowsSecurityDecisionType\.Pending' 'pending verdict submission API'
Assert-Match $files.Protection 'UserDecisionTimeout\s*=\s*TimeSpan\.FromSeconds\(25\)' '25 second user decision timeout'
Assert-Match $files.Protection 'SubmitPendingDecision\(driverEvent\.EventId\)(?s:.*?)DecisionDeadline' 'pending verdict before popup deadline'
Assert-Match $files.Protection 'user-decision-timeout-blocked' 'user timeout block diagnostic'
Assert-Match $files.Callback 'ulong\s+EventId\s*=\s*0(?s:.*?)DateTimeOffset\s+DecisionDeadline' 'decision identity and deadline'
Assert-Match $files.Helper 'DateTimeOffset\?\s+DecisionDeadline' 'intercept-window deadline setting'
Assert-Match $files.App 'DecisionDeadline\s*=\s*request\.DecisionDeadline' 'popup deadline propagation'
Assert-Match $files.App 'user-decision-timeout-blocked.*eventId:.*cid:.*module:.*path:' 'timeout application log'
Assert-Match $files.Window 'DispatcherTimer' 'countdown timer'
Assert-Match $files.Window 'Math\.Ceiling\(remaining\.TotalSeconds\)' 'stable countdown rounding'
Assert-Match $files.Window 'InterceptWindow_ConfirmCountdown' 'localized countdown button'
Assert-Match $files.Window 'ButtonPressedName\s*=\s*"Timeout"(?s:.*?)Close\(\)' 'timeout closes popup'
Assert-Match $files.Window '_decisionTimer\?\.Stop\(\)' 'countdown lifecycle cleanup'

foreach ($culture in @('zh-HANS', 'zh-HANT', 'en-US')) {
    $resource = Join-Path $repoRoot "Xdows-Security\Strings\$culture\Resources.resw"
    Assert-Match $resource 'InterceptWindow_ConfirmCountdown' "$culture countdown localization"
}

Write-Host "Intercept decision timeout source smoke passed."
