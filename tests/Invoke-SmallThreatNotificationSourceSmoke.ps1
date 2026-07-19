$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    App = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
    SettingsXaml = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml"
    SettingsCode = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml.cs"
    CompactXaml = Join-Path $repoRoot "Xdows-Security\SmallThreatNotificationWindow.xaml"
    CompactCode = Join-Path $repoRoot "Xdows-Security\SmallThreatNotificationWindow.xaml.cs"
    ModeService = Join-Path $repoRoot "Xdows-Security\Services\ThreatNotificationModeService.cs"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) { throw "Required source file missing: $path" }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) { throw "$Name was not found in $Path" }
}

Assert-Match $files.SettingsXaml 'SettingsPage_Feature_ThreatNotificationMode(?s:.*?)Tag="Normal"(?s:.*?)Tag="Compact"' 'normal and compact notification choices'
Assert-Match $files.SettingsXaml 'CompactNotificationWhenGamingToggle(?s:.*?)SettingsPage_Feature_ThreatNotificationMode_GameList(?s:.*?)l:Uids\.Uid="AllPage_OpenLink"' 'conditional gaming option and reused open-link localization'
Assert-Match $files.SettingsCode 'ThreatNotificationModeService\.NormalMode' 'normal notification default'
Assert-Match $files.SettingsCode 'ThreatNotificationModeComboBox\.IsEnabled\s*=\s*!toggle\.IsOn' 'notification combo disabled by gaming condition'
Assert-Match $files.SettingsCode 'GameListSettingsUri' 'game-list settings link'

Assert-Match $files.ModeService 'ShouldUseCompactAsync' 'notification mode decision service'
Assert-Match $files.ModeService 'Task\.Run\(IsGameRunning\)' 'off-UI-thread game detection'
Assert-Match $files.ModeService 'SemaphoreSlim\s+GameDetectionLock\s*=\s*new\(1,\s*1\)' 'single-flight game detection'
Assert-Match $files.ModeService 'GameStateCacheDuration\s*=\s*TimeSpan\.FromSeconds\(2\)' 'short game-state cache'
Assert-Match $files.ModeService 'SHQueryUserNotificationState' 'full-screen Direct3D game detection'
Assert-Match $files.ModeService 'GameConfigStore\\Children' 'Windows registered game list detection'
Assert-Match $files.ModeService 'GameListCacheDuration\s*=\s*TimeSpan\.FromMinutes\(5\)' 'bounded game-list cache refresh'

Assert-Match $files.CompactCode 'NoActivateStyle\s*=\s*0x08000000' 'non-activating window style'
Assert-Match $files.CompactCode 'manager\.IsAlwaysOnTop\s*=\s*true' 'always-on-top window'
Assert-Match $files.CompactCode 'SystemBackdropConfiguration.*IsInputActive\s*=\s*true' 'always-active Mica configuration'
Assert-Match $files.CompactCode 'static SmallThreatNotificationWindow\? _current' 'single compact window bound'
Assert-Match $files.CompactCode 'DispatcherTimer.*TimeSpan\.FromSeconds\(AutoDismissSeconds\)' 'automatic compact notification dismissal'
Assert-Match $files.CompactCode 'PlayEntranceAnimation(?s:.*?)CreateVector3KeyFrameAnimation(?s:.*?)CreateScalarKeyFrameAnimation' 'slide and fade entrance animation'
Assert-Match $files.CompactCode 'BeginExitAnimation(?s:.*?)CreateScopedBatch\(CompositionBatchTypes\.Animation\)' 'batched exit animation'
Assert-Match $files.CompactCode 'UISettings\(\)\.AnimationsEnabled' 'system animation preference respected'
Assert-Match $files.CompactCode 'DismissTimer_Tick(?s:.*?)BeginExitAnimation\(false\)' 'automatic dismissal plays exit animation'
Assert-Match $files.CompactCode 'NotificationButton_Click(?s:.*?)BeginExitAnimation\(true\)' 'click plays exit animation before normal notification'
Assert-Match $files.CompactCode 'CompleteExit(?s:.*?)InterceptWindow\.ShowOrActivate' 'completed click exit opens normal notification'
Assert-Match $files.CompactXaml 'SmallThreatNotificationButton' 'compact notification accessible click target'

Assert-Match $files.App 'ThreatNotificationModeService\.ShouldUseCompactAsync' 'notification mode routing'
Assert-Match $files.App 'InterceptWindowButtonType\.ReminderOnly(?s:.*?)return ProtectionUserDecision\.Block' 'compact driver notification automatically blocks'
Assert-Match $files.App 'ShowProcessedThreatNotificationAsync' 'processed compatibility notification routing'

foreach ($culture in @('zh-HANS', 'zh-HANT', 'en-US')) {
    $resource = Join-Path $repoRoot "Xdows-Security\Strings\$culture\Resources.resw"
    Assert-Match $resource 'SettingsPage_Feature_ThreatNotificationMode\.Header' "$culture notification setting localization"
    Assert-Match $resource 'SmallThreatNotification_Handled_Title' "$culture compact notification localization"
    Assert-Match $resource 'SmallThreatNotification_Detail_Format' "$culture compact notification detail localization"
}

Write-Host "Small threat notification source smoke passed."
