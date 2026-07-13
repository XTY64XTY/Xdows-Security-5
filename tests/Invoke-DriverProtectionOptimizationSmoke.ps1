$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$files = @{
    FileProtect = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\FileProtect.c"
    PublicHeader = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
    Bridge = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
    Protocol = Join-Path $repoRoot "Protection\DriverProtocol.cs"
    Protection = Join-Path $repoRoot "Protection\DriverProtection.cs"
    LegacyFiles = Join-Path $repoRoot "Protection\LegacyFiles.cs"
    LegacyProcess = Join-Path $repoRoot "Protection\LegacyProcess.cs"
    Normalizer = Join-Path $repoRoot "Protection\DriverPathNormalizer.cs"
    InterceptXaml = Join-Path $repoRoot "Xdows-Security\InterceptWindow.xaml"
    InterceptCode = Join-Path $repoRoot "Xdows-Security\InterceptWindow.xaml.cs"
    AppCode = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
    AppProject = Join-Path $repoRoot "Xdows-Security\Xdows-Security.csproj"
    DriverProject = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Xdows-Security-Driver.vcxproj"
    SelfProtect = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\SelfProtect.c"
    ProcessProtect = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\ProcessProtect.c"
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
Assert-Match $files.FileProtect 'Operations\[1\]\.MajorFunction\s*=\s*IRP_MJ_WRITE' 'actual write dirty tracking'
Assert-Match $files.FileProtect 'Operations\[2\]\.PreOperation\s*=\s*XdowsFilePreCleanup' 'dirty-only cleanup callback'
Assert-Match $files.FileProtect 'FltGetDestinationFileNameInformation' 'rename destination extension inspection'
Assert-Match $files.FileProtect 'FltDoCompletionProcessingWhenSafe' 'safe cleanup callback dispatch'
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
Assert-Match $files.Protection 'bool\s+quarantineSucceeded\s*=\s*await\s+QuarantineManager\s*\.AddToQuarantine' 'awaited driver quarantine result'
Assert-Match $files.Protection 'quarantine-failed' 'driver quarantine failure reason'
Assert-NotMatch $files.Protection '_\s*=\s*QuarantineManager\.AddToQuarantine' 'discarded driver quarantine task'
Assert-Match $files.LegacyFiles 'async\s+void\s+OnChanged' 'async compatibility file event handler'
Assert-Match $files.LegacyFiles 'bool\s+quarantineSucceeded\s*=\s*await\s+QuarantineManager\.AddToQuarantine' 'awaited compatibility file quarantine'
Assert-NotMatch $files.LegacyFiles '_\s*=\s*QuarantineManager\.AddToQuarantine' 'discarded compatibility file quarantine task'
Assert-Match $files.LegacyProcess 'WaitForExitAsync' 'process exit before compatibility quarantine'
Assert-Match $files.LegacyProcess 'bool\s+quarantineSucceeded\s*=\s*await\s+QuarantineManager\.AddToQuarantine' 'awaited compatibility process quarantine'
Assert-NotMatch $files.LegacyProcess '_\s*=\s*QuarantineManager\.AddToQuarantine' 'discarded compatibility process quarantine task'
Assert-NotMatch $files.Protection 'Cache\(processCacheKey,\s*decisionType' 'cached user process-block decision'
Assert-Match $files.Protection 'sensitive-op-fast-allow' 'non-blocking sensitive-operation allow path'
Assert-NotMatch $files.Protection 'private\s+Task<XdowsSecurityDecision>\s+HandleSensitiveOperationAsync(?s:.*?)SignerTrustService\.Evaluate' 'unused signature-chain work in sensitive-operation hot path'
Assert-Match $files.Protection 'Connecting DriverBridgeClient(?s:.*?)RegisterProtectedProcess\(\)(?s:.*?)Creating NativeModelScanner' 'driver connection before model initialization'
Assert-Match $files.Protection 'ProcessProtectionEnabled\s*==\s*0' 'inactive process module startup rejection'
Assert-Match $files.Protection 'FileProtectionEnabled\s*==\s*0' 'inactive file module startup rejection'
Assert-Match $files.Protection 'ProcessProtectionEnabled\s*==\s*0\s*\|\|\s*state\.FileProtectionEnabled\s*==\s*0' 'incomplete runtime protection status rejection'
Assert-Match $files.Protection 'ActiveModules\s*&\s*DriverProtocol\.RequiredModules' 'required runtime module mask validation'
Assert-Match $files.Protocol 'RequiredModules\s*=\s*ModuleTokenAuth\s*\|\s*ModuleProcess\s*\|\s*ModuleFile\s*\|\s*ModuleInjection\s*\|\s*ModuleSelfProtect' 'managed required module mask'
Assert-Match $files.AppCode 'StartPipeListener\(\);(?s:.*?)Task\.Run\(\(\)\s*=>\s*\{(?s:.*?)ProtectionStatus\.RestoreProtections\(\);(?s:.*?)await InitializeLocalizer\(\);' 'protection restore before optional startup work'
Assert-NotMatch $files.InterceptXaml 'DetectionNameText|ActorPathText|CorrelationText' 'empty detail card'
Assert-Match $files.InterceptXaml 'InterceptWindow_ProtectionModuleLabel' 'protection module card'
Assert-Match $files.InterceptCode 'ThreatTypeText\.Text\s*=\s*NormalizeDetectionName\(setting\.DetectionName\)' 'detection name as threat type'
Assert-Match $files.InterceptCode '\.Replace\("\."\s*,\s*"\.\\u200B"' 'semantic detection-name wrapping opportunities'
Assert-Match $files.InterceptCode 'LanguageChanged\s*\+=\s*OnLanguageChanged' 'named intercept localization handler'
Assert-Match $files.InterceptCode 'LanguageChanged\s*-=\s*OnLanguageChanged' 'closed intercept localization handler cleanup'
Assert-Match $files.InterceptCode 'OnLanguageChanged(?s:.*?)DispatcherQueue\.TryEnqueue\(UpdateWindowHeightAndPosition\)' 'localized intercept window remeasurement'
Assert-Match $files.InterceptXaml 'ThreatTypeText[^>]+TextWrapping="WrapWholeWords"' 'whole detection-name segment wrapping'
Assert-NotMatch $files.NativeModel 'Xdows\.Model\.Native\.' 'native-only detection prefix'
Assert-Match $files.DriverProject '<SignMode>Off</SignMode>' 'self-contained test-signing build mode'
Assert-Match $files.DriverProject '<XdowsDriverPackageDirectory>\$\(OutDir\)\$\(TargetName\)</XdowsDriverPackageDirectory>' 'active driver output signing path'
Assert-Match $files.AppProject 'OutDir=\$\(XdowsDriverProjectOutput\)' 'isolated current driver build output'
Assert-NotMatch $files.SelfProtect 'MainThreadId\s*==\s*0' 'zero main-thread rejection'
Assert-Match $files.SelfProtect 'PsGetThreadProcessId' 'all guarded-process threads covered by self-protection'
Assert-Match $files.ProcessProtect 'XDOWS_PROCESS_LAUNCH_VERDICT_TIMEOUT_MS\s+32000u' 'process verdict timeout aligned with the 30-second UI decision window'

foreach ($culture in @('zh-HANS', 'zh-HANT', 'en-US')) {
    $resource = Join-Path $repoRoot "Xdows-Security\Strings\$culture\Resources.resw"
    Assert-Match $resource 'InterceptWindow_ProtectionModuleLabel\.Text' "$culture protection module label"
    Assert-Match $resource 'InterceptWindow_Backend_Driver' "$culture driver backend"
    Assert-Match $resource 'InterceptWindow_Backend_Compatibility' "$culture compatibility backend"
}

Write-Host "Driver protection optimization smoke passed."
