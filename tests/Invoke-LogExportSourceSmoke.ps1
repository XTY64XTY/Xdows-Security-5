$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$homePage = Join-Path $repoRoot "Xdows-Security\Views\HomePage.xaml.cs"
$homeXaml = Join-Path $repoRoot "Xdows-Security\Views\HomePage.xaml"
$exportDialogXaml = Join-Path $repoRoot "Xdows-Security\Dialog\LogExportDialog.xaml"
$logService = Join-Path $repoRoot "Xdows-Security\Services\LogService.cs"
$resourceFiles = @(
    (Join-Path $repoRoot "Xdows-Security\Strings\en-US\Resources.resw"),
    (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANS\Resources.resw"),
    (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANT\Resources.resw")
)

$requiredFiles = @($homePage, $homeXaml, $exportDialogXaml, $logService) + $resourceFiles
foreach ($path in $requiredFiles) {
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

Assert-Match $homePage 'private\s+async\s+void\s+ExportLog_Click(?s:.*?)await\s+ShowExportDialogAsync\(\)' 'awaited export click handler'
Assert-NotMatch $homePage '_\s*=\s*ShowExportDialogAsync\(\)' 'discarded export task'
Assert-Match $homePage 'XamlRoot\.ContentIslandEnvironment\.AppWindowId' 'page-owned save picker'
Assert-Match $logService 'ExportAsync(?s:.*?)await\s+FlushAsync\(token\)' 'log write barrier before export'
Assert-Match $homePage 'LogExportDialog_Failed_Title' 'localized export failure title'
Assert-Match $homePage 'LogExportDialog_Failed_Message' 'localized export failure message'
Assert-Match $logService 'sealed\s+record\s+FlushRequest' 'log write flush marker'
Assert-Match $logService 'TaskCreationOptions\.RunContinuationsAsynchronously' 'asynchronous flush continuation'
Assert-Match $logService 'WriteAsync\(new\s+FlushRequest' 'queued flush barrier'
Assert-Match $logService 'case\s+FlushRequest' 'write-pump flush handling'
Assert-Match $homeXaml 'x:Name="LogExportButton"[^>]+AutomationProperties\.AutomationId="LogExportButton"' 'export button automation id'
Assert-Match $exportDialogXaml 'x:Name="FromDatePicker"[^>]+AutomationProperties\.AutomationId="LogExportFromDatePicker"' 'from-date automation id'
Assert-Match $exportDialogXaml 'x:Name="KeywordBox"[^>]+AutomationProperties\.AutomationId="LogExportKeywordBox"' 'keyword automation id'

foreach ($path in $resourceFiles) {
    Assert-Match $path 'name="LogExportDialog_Failed_Title"' 'localized export failure title resource'
    Assert-Match $path 'name="LogExportDialog_Failed_Message"' 'localized export failure message resource'
}

Write-Host "Log export source smoke passed."
