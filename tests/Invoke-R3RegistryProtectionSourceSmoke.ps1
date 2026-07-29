param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Read-RequiredFile([string]$RelativePath) {
    $path = Join-Path $repoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file missing: $path"
    }
    return Get-Content -LiteralPath $path -Raw
}

function Assert-Match([string]$Text, [string]$Pattern, [string]$Label) {
    if ($Text -notmatch $Pattern) {
        throw "Missing R3 registry protection evidence: $Label"
    }
}

function Assert-NotMatch([string]$Text, [string]$Pattern, [string]$Label) {
    if ($Text -match $Pattern) {
        throw "Unexpected R3 registry protection evidence: $Label"
    }
}

$files = @{
    Rules = Read-RequiredFile 'Xdows-Local\RegistryScan.cs'
    Protection = Read-RequiredFile 'Protection\LegacyRegistryProtection.cs'
    Project = Read-RequiredFile 'Protection\Protection.csproj'
    App = Read-RequiredFile 'Xdows-Security\App.xaml.cs'
    Settings = Read-RequiredFile 'Xdows-Security\Views\SettingsPage.xaml'
    SettingsCode = Read-RequiredFile 'Xdows-Security\Views\SettingsPage.xaml.cs'
    Modules = Read-RequiredFile 'Helper\InterceptWindowHelper.cs'
    Intercept = Read-RequiredFile 'Xdows-Security\InterceptWindow.xaml.cs'
    En = Read-RequiredFile 'Xdows-Security\Strings\en-US\Resources.resw'
    ZhHans = Read-RequiredFile 'Xdows-Security\Strings\zh-HANS\Resources.resw'
    ZhHant = Read-RequiredFile 'Xdows-Security\Strings\zh-HANT\Resources.resw'
}

Assert-Match $files.Rules 'RegistryRuleCategory(?s:.*?)Primary(?s:.*?)Secondary(?s:.*?)Other' 'single categorized rule source'
Assert-Match $files.Rules 'Recommended\s*\{[^\r\n]*new\(true, false\)' 'recommended category defaults'
Assert-Match $files.Rules 'DiagnosticTestPath' 'safe HKCU diagnostic rule'
Assert-Match $files.Protection 'Channel\.CreateBounded<RegistryObservation>' 'bounded single-reader event queue'
Assert-Match $files.Protection 'RegistryCreate(?s:.*?)RegistryDelete(?s:.*?)RegistrySetValue(?s:.*?)RegistryDeleteValue(?s:.*?)RegistrySetInformation' 'mutation event coverage'
Assert-Match $files.Protection 'SignerTrustService\.Evaluate(?s:.*?)IsTrusted' 'trusted signer bypass'
Assert-Match $files.Protection 'RunTraceLoopAsync(?s:.*?)CreateTraceSession(?s:.*?)recovered' 'trace recovery loop'
Assert-Match $files.Protection 'DriverDecisionService\.AskUserAsync' 'serialized direct user decision'
Assert-Match $files.Protection 'TryStopActor' 'block action against known modifier'
Assert-NotMatch $files.Protection 'class\s+ETW|partial\s+class\s+ETW' 'removed ETW framework remains absent'
Assert-Match $files.Project 'Microsoft\.Diagnostics\.Tracing\.TraceEvent' 'dedicated registry trace dependency'
Assert-Match $files.App '4\s*=>\s*LegacyRegistryProtection' 'Run ID 4 wiring'
Assert-Match $files.App 'RestoreProtection\(4\)' 'startup state restoration'
Assert-Match $files.Settings 'RegistrySecondaryToggle(?s:.*?)RegistryOtherToggle' 'category toggles'
Assert-Match $files.SettingsCode 'RegistryProtectionSecondary(?s:.*?)RegistryProtectionOther' 'category setting persistence'
Assert-Match $files.Modules 'Registry' 'registry protection module'
Assert-Match $files.Intercept 'InterceptWindow_Module_Registry' 'registry module UI mapping'
foreach ($resource in @($files.En, $files.ZhHans, $files.ZhHant)) {
    Assert-Match $resource 'InterceptWindow_Module_Registry' 'localized registry module label'
}

foreach ($relative in @(
    'Xdows-Security\Views\SettingsPage.xaml',
    'Xdows-Security\Strings\en-US\Resources.resw',
    'Xdows-Security\Strings\zh-HANS\Resources.resw',
    'Xdows-Security\Strings\zh-HANT\Resources.resw')) {
    [xml](Read-RequiredFile $relative) | Out-Null
}

Write-Host 'R3 registry protection source smoke passed.'
