$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$mainWindowPath = Join-Path $repoRoot "Xdows-Security\MainWindow.xaml.cs"
$settingsPath = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml.cs"
$resourcePaths = @(
    (Join-Path $repoRoot "Xdows-Security\Strings\en-US\Resources.resw"),
    (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANS\Resources.resw"),
    (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANT\Resources.resw")
)

function Assert-Match([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -notmatch $Pattern) {
        throw "Missing $Name."
    }
}

function Assert-NotMatch([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -match $Pattern) {
        throw "Unexpected $Name."
    }
}

$mainWindow = Get-Content -Raw $mainWindowPath
$settings = Get-Content -Raw $settingsPath

Assert-Match $mainWindow 'DeviceChangeSubClassProc(?s:.*?)WM_CLOSE(?s:.*?)SC_CLOSE(?s:.*?)HandleUntrustedCloseRequest\(\)(?s:.*?)return\s+0' 'untrusted close-message interception'
Assert-Match $mainWindow 'MainWindow_Closing(?s:.*?)_voluntaryExitAuthorized(?s:.*?)return;(?s:.*?)e\.Cancel\s*=\s*true(?s:.*?)HandleUntrustedCloseRequest\(\)' 'closing-event fallback guard'
Assert-Match $mainWindow 'private\s+bool\s+AuthorizeVoluntaryExit\(\)(?s:.*?)_voluntaryExitAuthorized\s*=\s*true(?s:.*?)ProtectionStatus\.PrepareVoluntaryExit\(\)(?s:.*?)App\.ReleaseResources\(\)' 'explicit voluntary-exit authorization order'
Assert-Match $mainWindow 'public\s+void\s+CloseVoluntarily\(\)(?s:.*?)AuthorizeVoluntaryExit\(\);(?s:.*?)Close\(\)' 'trusted close path'
Assert-Match $mainWindow 'RestartVoluntarily\(string\s+executablePath\)(?s:.*?)AuthorizeVoluntaryExit\(\)(?s:.*?)Process\.Start(?s:.*?)Close\(\)' 'trusted restart path'
Assert-Match $mainWindow '_trayQuitItem\.Click\s*\+=\s*async(?s:.*?)CloseVoluntarily\(\)' 'trusted tray exit path'
Assert-NotMatch $mainWindow 'GetAwaiter\(\)\.GetResult\(\)' 'blocking UI verification'
Assert-NotMatch $mainWindow '_allowCloseFromTray' 'legacy close bypass flag'

Assert-Match $settings 'RestartOOBEButton_Click(?s:.*?)App\.MainWindow\?\.RestartVoluntarily\(executablePath\)' 'OOBE restart voluntary exit'
Assert-Match $settings 'ResetConfigButton_Click(?s:.*?)App\.MainWindow\?\.CloseVoluntarily\(\)' 'configuration reset voluntary exit'
Assert-NotMatch $settings 'Application\.Current\.Exit\(\)|Environment\.Exit\(0\)' 'unprotected settings exit'

foreach ($resourcePath in $resourcePaths) {
    $resources = Get-Content -Raw $resourcePath
    Assert-Match $resources 'name="MainWindow_CloseConfirmation_Title"' "localized close title in $resourcePath"
    Assert-Match $resources 'name="MainWindow_CloseConfirmation_Content"' "localized close content in $resourcePath"
}

Write-Host "Window self-protection smoke passed."
