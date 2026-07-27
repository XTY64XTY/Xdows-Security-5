$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$settingsPage = Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml"
$resources = @(
    Join-Path $repoRoot "Xdows-Security\Strings\zh-HANS\Resources.resw"
    Join-Path $repoRoot "Xdows-Security\Strings\zh-HANT\Resources.resw"
    Join-Path $repoRoot "Xdows-Security\Strings\en-US\Resources.resw"
)

if (!(Test-Path -LiteralPath $settingsPage)) {
    throw "Required source file missing: $settingsPage"
}

foreach ($path in $resources) {
    if (!(Test-Path -LiteralPath $path)) {
        throw "Required source file missing: $path"
    }
}

function Assert-NotMatch([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match $Pattern) {
        throw "$Name remains in $Path"
    }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $Path"
    }
}

Assert-NotMatch $settingsPage 'SettingsPage_Protection_Behavior' 'unfinished behavior protection settings'
foreach ($path in $resources) {
    Assert-NotMatch $path 'SettingsPage_Protection_Behavior' 'unused behavior settings resources'
    Assert-Match $path 'InterceptWindow_Module_Behavior' 'behavior interception module resource'
}

Write-Host "Settings behavior placeholder removal source smoke passed."
