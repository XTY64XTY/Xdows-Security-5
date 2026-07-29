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
        throw "Missing R3 boot protection evidence: $Label"
    }
}

function Assert-NotMatch([string]$Text, [string]$Pattern, [string]$Label) {
    if ($Text -match $Pattern) {
        throw "Unexpected R3 boot protection evidence: $Label"
    }
}

$files = @{
    Protection = Read-RequiredFile 'Protection\LegacyBootProtection.cs'
    Disk = Read-RequiredFile 'Helper\DiskOperator.cs'
    App = Read-RequiredFile 'Xdows-Security\App.xaml.cs'
    SettingsXaml = Read-RequiredFile 'Xdows-Security\Views\SettingsPage.xaml'
    SettingsCode = Read-RequiredFile 'Xdows-Security\Views\SettingsPage.xaml.cs'
}

Assert-Match $files.Protection 'class LegacyBootProtection\s*:\s*IProtectionModel' 'independent compatibility protection model'
Assert-Match $files.Protection 'TimeSpan\.FromSeconds\(5\)' 'recommended five-second polling interval'
Assert-Match $files.Protection 'BootProtectionSnapshotService\.ApplySnapshot\(baseline, observed, changes\)(?s:.*?)RequestDecisionAsync' 'repair before user notification'
Assert-Match $files.Protection 'BootProtectionUserDecision\.AllowChange(?s:.*?)ApplySnapshot\(observed, baseline, changes\)(?s:.*?)_store\.Save\(observed\)' 'released change reapplication and trusted baseline update'
Assert-Match $files.Protection 'CryptProtectData' 'DPAPI-protected baseline authentication key'
Assert-Match $files.Protection 'HMACSHA256' 'authenticated baseline manifest'
Assert-Match $files.Protection 'GPT\.PrimaryEntries' 'primary GPT entry protection'
Assert-Match $files.Protection 'GPT\.BackupHeader' 'backup GPT header protection'
Assert-Match $files.Protection '@"EFI\\Microsoft\\Boot"' 'active Microsoft EFI path protection'
Assert-Match $files.Protection 'name\.Equals\("BCD"' 'BCD protection'
Assert-Match $files.Protection 'name\.StartsWith\("BCD\.LOG"' 'volatile BCD log exclusion'
Assert-Match $files.Protection 'MSFT_Partition WHERE IsSystem = TRUE' 'active Windows boot-partition discovery'
Assert-Match $files.Protection 'EnumerateFilesWithoutReparsePoints' 'reparse-safe EFI enumeration'
Assert-Match $files.Protection 'EnsureNoReparsePoints' 'reparse-safe boot repair paths'
Assert-NotMatch $files.Protection 'ETW|EventSource|TraceEvent' 'ETW dependency'

Assert-Match $files.Disk 'GetLogicalSectorSize' 'logical sector-size query'
Assert-Match $files.Disk 'ReadDiskRegion' 'bounded arbitrary disk reads'
Assert-Match $files.Disk 'WriteDiskRegion' 'read-back verified disk-region repair'
Assert-Match $files.Disk 'MaxRawRegionSize\s*=\s*16\s*\*\s*1024\s*\*\s*1024' 'raw-region allocation limit'

Assert-Match $files.App 'RestoreProtection\(2\)' 'startup restoration for R3 boot protection'
Assert-Match $files.App '2\s*=>\s*LegacyBootProtection' 'Run ID 2 mapping'
Assert-Match $files.App 'BootProtectionDecisionCallbackAsync' 'background repair decision dialog'
Assert-Match $files.SettingsXaml 'x:Name="BootProtectionToggle"' 'named boot protection switch'
Assert-Match $files.SettingsXaml 'AutomationProperties\.AutomationId="SettingsBootProtectionToggle"' 'boot switch AutomationId'
$bootToggleBlock = [regex]::Match(
    $files.SettingsXaml,
    '<ToggleSwitch(?=[^>]*x:Name="BootProtectionToggle")[^>]*/>',
    [System.Text.RegularExpressions.RegexOptions]::Singleline).Value
Assert-NotMatch $bootToggleBlock 'IsEnabled="False"' 'permanently disabled boot switch'
Assert-Match $files.SettingsCode 'ConfirmBootProtectionBaselineAsync' 'first-enable user baseline confirmation'
Assert-Match $files.SettingsCode 'Task\.Run\(ProtectionStatus\.CreateBootProtectionBaseline\)' 'baseline I/O off the UI thread'

$requiredResources = @(
    'SettingsPage_Protection_Boot_Toggle.AutomationProperties.Name',
    'SettingsPage_Protection_Boot_Baseline_Title',
    'SettingsPage_Protection_Boot_Baseline_Warning',
    'SettingsPage_Protection_Boot_Detection_Title',
    'SettingsPage_Protection_Boot_Detection_KeepRepair',
    'SettingsPage_Protection_Boot_Detection_AllowChange'
)

foreach ($culture in @('en-US', 'zh-HANS', 'zh-HANT')) {
    $resourcePath = Join-Path $repoRoot "Xdows-Security\Strings\$culture\Resources.resw"
    [xml]$resourceXml = [System.IO.File]::ReadAllText(
        $resourcePath,
        [System.Text.Encoding]::UTF8)
    $names = @($resourceXml.root.data | ForEach-Object { $_.name })
    foreach ($resource in $requiredResources) {
        if ($names -notcontains $resource) {
            throw "Missing $culture resource: $resource"
        }
    }
}

Write-Host 'R3 boot protection source smoke passed.'
