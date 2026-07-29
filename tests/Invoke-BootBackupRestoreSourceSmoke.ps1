$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Disk = Join-Path $repoRoot "Helper\DiskOperator.cs"
    Xaml = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml"
    Code = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml.cs"
}
$resources = @(
    Join-Path $repoRoot "Xdows-Security\Strings\zh-HANS\Resources.resw"
    Join-Path $repoRoot "Xdows-Security\Strings\zh-HANT\Resources.resw"
    Join-Path $repoRoot "Xdows-Security\Strings\en-US\Resources.resw"
)

foreach ($path in @($files.Values) + $resources) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required source file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

function Assert-NotMatch([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match $Pattern) { throw "$Name is still present in $Path" }
}

Assert-Match $files.Disk 'BootSectorSize\s*=\s*512' 'fixed raw .bin sector size'
Assert-Match $files.Disk 'QueryDosDeviceW\(null' 'physical disk auto-enumeration'
Assert-Match $files.Disk 'IoctlStorageQueryProperty' 'disk model and serial query'
Assert-Match $files.Disk 'IoctlDiskGetLengthInfo' 'disk capacity query'
Assert-Match $files.Disk 'IoctlDiskGetDriveLayoutEx' 'partition style query'
Assert-Match $files.Disk 'IoctlVolumeGetVolumeDiskExtents' 'system disk mapping'
Assert-Match $files.Disk 'WriteBootSector(?s:.*?)IsValidBootSector(?s:.*?)WriteDiskRegion' 'validated boot-sector write delegation'
Assert-Match $files.Disk 'WriteDiskRegion(?s:.*?)GenericRead\s*\|\s*GenericWrite(?s:.*?)WriteFile(?s:.*?)FlushFileBuffers(?s:.*?)ReadDiskRegion(?s:.*?)SequenceEqual' 'validated online write and readback'
Assert-Match $files.Disk 'data\[BootSectorSize\s*-\s*2\]\s*==\s*0x55(?s:.*?)data\[BootSectorSize\s*-\s*1\]\s*==\s*0xAA' '55 AA boot signature validation'
Assert-NotMatch $files.Disk 'FSCTL_LOCK_VOLUME|FSCTL_DISMOUNT_VOLUME|IoctlVolumeOffline' 'volume lock or dismount path'

Assert-Match $files.Xaml 'x:Name="BootSaveButton"(?s:.*?)AutomationProperties\.AutomationId="SettingsBootBackupButton"' 'backup button automation identity'
Assert-Match $files.Xaml 'x:Name="BootRestoreButton"(?s:.*?)AutomationProperties\.AutomationId="SettingsBootRestoreButton"(?s:.*?)Click="Boot_Restore_Button_Click"' 'enabled restore button handler'
Assert-NotMatch $files.Xaml 'SettingsPage_Protection_Boot_Open"(?:(?!</controls:SettingsCard>).)*IsEnabled="False"' 'disabled restore settings card'

Assert-Match $files.Code 'Boot_Save_Button_Click(?s:.*?)SelectBootDiskAsync(?s:.*?)DiskOperator\.ReadBootSector\(selected\.Disk\.Index\)' 'backup selected disk read'
Assert-Match $files.Code 'FileTypeChoices\.Add\((?s:.*?)\["\.bin"\]\)' '.bin save picker filter'
Assert-Match $files.Code 'await\s+File\.WriteAllBytesAsync\(file\.Path,\s*bootSector\)' 'awaited backup file write'
Assert-Match $files.Code 'Boot_Restore_Button_Click(?s:.*?)FileTypeFilter\.Add\("\.bin"\)(?s:.*?)DiskOperator\.IsValidBootSector(?s:.*?)SelectBootDiskAsync(?s:.*?)ConfirmBootRestoreAsync(?s:.*?)DiskOperator\.WriteBootSector' 'validated restore workflow'
Assert-Match $files.Code 'ConfirmBootRestoreAsync(?s:.*?)InfoBarSeverity\.Warning(?s:.*?)DefaultButton\s*=\s*ContentDialogButton\.Close' 'destructive restore confirmation defaults to cancel'
Assert-Match $files.Code 'AutomationProperties\.SetAutomationId\(diskSelector,\s*"BootPhysicalDiskSelector"\)' 'disk selector automation identity'
Assert-Match $files.Code 'Task\.Run\(DiskOperator\.GetPhysicalDisks\)' 'disk enumeration off UI thread'
Assert-Match $files.Code 'Task\.Run\(\(\)\s*=>\s*DiskOperator\.WriteBootSector' 'raw write off UI thread'
Assert-NotMatch $files.Code 'ReadBootSector\(0\)' 'hardcoded PhysicalDrive0 backup'
Assert-NotMatch $files.Code '_\s*=\s*File\.WriteAllBytesAsync' 'fire-and-forget backup write'

$requiredResourceKeys = @(
    'SettingsPage_Protection_Boot_DiskDialog_Title',
    'SettingsPage_Protection_Boot_DiskDialog_BackupInstruction',
    'SettingsPage_Protection_Boot_DiskDialog_RestoreInstruction',
    'SettingsPage_Protection_Boot_Disk_DetailsFormat',
    'SettingsPage_Protection_Boot_InvalidBackup_Message',
    'SettingsPage_Protection_Boot_RestoreConfirm_Warning',
    'SettingsPage_Protection_Boot_RestoreConfirm_Primary',
    'SettingsPage_Protection_Boot_RestoreSuccess_Message',
    'SettingsPage_Protection_Boot_OperationFailed_Message'
)
foreach ($resource in $resources) {
    [xml]([System.IO.File]::ReadAllText(
        $resource,
        [System.Text.Encoding]::UTF8)) | Out-Null
    foreach ($key in $requiredResourceKeys) {
        Assert-Match $resource ([regex]::Escape($key)) "$key localization"
    }
}

Write-Host "Boot backup and online restore source smoke passed."
