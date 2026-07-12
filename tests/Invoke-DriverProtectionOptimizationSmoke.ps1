$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$files = @{
    FileProtect = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\FileProtect.c"
    PublicHeader = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
    Bridge = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
    Protection = Join-Path $repoRoot "Protection\DriverProtection.cs"
    Normalizer = Join-Path $repoRoot "Protection\DriverPathNormalizer.cs"
    InterceptXaml = Join-Path $repoRoot "Xdows-Security\InterceptWindow.xaml"
    InterceptCode = Join-Path $repoRoot "Xdows-Security\InterceptWindow.xaml.cs"
    AppProject = Join-Path $repoRoot "Xdows-Security\Xdows-Security.csproj"
    DriverProject = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Xdows-Security-Driver.vcxproj"
    SelfProtect = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\SelfProtect.c"
    NativeModel = Join-Path $codeRoot "Xdows-Model\Xdows-Model-Native\src\xdows_model_native.cpp"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

function Assert-NotMatch([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match $Pattern) { throw "$Name is still present in $Path" }
}

Assert-Match $files.PublicHeader 'XDOWS_SECURITY_PROTOCOL_VERSION\s+2u' 'protocol v2'
Assert-Match $files.PublicHeader 'XDOWS_SECURITY_DRIVER_BUILD_ID' 'driver build identity'
Assert-Match $files.FileProtect 'FLT_STREAMHANDLE_CONTEXT' 'dirty stream-handle context'
Assert-Match $files.FileProtect 'Contexts\[0\]\.Size\s*=\s*sizeof\(XDOWS_DIRTY_HANDLE_CONTEXT\)' 'WDK-compatible stream-handle context size'
Assert-NotMatch $files.FileProtect '\.ContextSize\s*=' 'invalid FLT context registration field'
Assert-Match $files.FileProtect 'writeOpen\s*\?\s*FLT_PREOP_SUCCESS_WITH_CALLBACK\s*:\s*FLT_PREOP_SUCCESS_NO_CALLBACK' 'read-only fast path'
Assert-Match $files.FileProtect 'Operations\[1\]\.PreOperation\s*=\s*XdowsFilePreCleanup' 'dirty-only cleanup callback'
Assert-Match $files.FileProtect 'XdowsSecurityEventFileWrite' 'coalesced close-time write scan'
Assert-Match $files.Bridge 'Channel\.CreateBounded<XdowsSecurityEvent>' 'bounded event channel'
Assert-NotMatch $files.Bridge 'Task\.Delay\(150' '150 ms polling delay'
Assert-Match $files.Bridge 'Math\.Clamp\(Environment\.ProcessorCount\s*/\s*2,\s*2,\s*4\)' 'bounded worker count'
Assert-NotMatch $files.Bridge '_\s*=\s*Task\.Run\(async' 'unbounded per-event Task.Run'
Assert-Match $files.Bridge 'ErrorRevisionMismatch\s*=\s*1306' 'protocol mismatch repair signal'
Assert-Match $files.Bridge 'state\.DriverBuildId\s*!=\s*DriverProtocol\.DriverBuildId' 'runtime build identity validation'
Assert-Match $files.Protection 'ScanSingleFlightAsync' 'single-flight scanning'
Assert-Match $files.Protection 'DecisionCache\.Count\s*>=\s*4096' 'bounded verdict cache'
Assert-Match $files.Protection 'DriverPathNormalizer\.Normalize' 'NT path normalization'
Assert-Match $files.Normalizer 'GetFileInformationByHandle' 'stable volume and file identity cache key'
Assert-Match $files.Protection 'confirmed-threat-user-timeout-block' 'confirmed process threat timeout blocking'
Assert-Match $files.Protection 'confirmed-file-threat-user-timeout-block' 'confirmed file threat timeout blocking'
Assert-NotMatch $files.Protection 'Cache\(processCacheKey,\s*decisionType' 'cached user process-block decision'
Assert-NotMatch $files.InterceptXaml 'DetectionNameText|ActorPathText|CorrelationText' 'empty detail card'
Assert-Match $files.InterceptXaml 'InterceptWindow_ProtectionModuleLabel' 'protection module card'
Assert-Match $files.InterceptCode 'ThreatTypeText\.Text\s*=\s*NormalizeDetectionName\(setting\.DetectionName\)' 'detection name as threat type'
Assert-Match $files.InterceptCode '\.Replace\("\."\s*,\s*"\.\\u200B"' 'semantic detection-name wrapping opportunities'
Assert-Match $files.InterceptXaml 'ThreatTypeText[^>]+TextWrapping="WrapWholeWords"' 'whole detection-name segment wrapping'
Assert-NotMatch $files.NativeModel 'Xdows\.Model\.Native\.' 'native-only detection prefix'
Assert-Match $files.DriverProject '<SignMode>Off</SignMode>' 'self-contained test-signing build mode'
Assert-Match $files.DriverProject '<XdowsDriverPackageDirectory>\$\(OutDir\)\$\(TargetName\)</XdowsDriverPackageDirectory>' 'active driver output signing path'
Assert-Match $files.AppProject 'OutDir=\$\(XdowsDriverProjectOutput\)' 'isolated current driver build output'
Assert-NotMatch $files.SelfProtect 'MainThreadId\s*==\s*0' 'zero main-thread rejection'
Assert-Match $files.SelfProtect 'PsGetThreadProcessId' 'all guarded-process threads covered by self-protection'

foreach ($culture in @('zh-HANS', 'zh-HANT', 'en-US')) {
    $resource = Join-Path $repoRoot "Xdows-Security\Strings\$culture\Resources.resw"
    Assert-Match $resource 'InterceptWindow_ProtectionModuleLabel\.Text' "$culture protection module label"
    Assert-Match $resource 'InterceptWindow_Backend_Driver' "$culture driver backend"
    Assert-Match $resource 'InterceptWindow_Backend_Compatibility' "$culture compatibility backend"
}

Write-Host "Driver protection optimization smoke passed."
