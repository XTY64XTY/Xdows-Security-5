$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$normalizerPath = Join-Path $repoRoot "Protection\DriverPathNormalizer.cs"
$text = Get-Content -LiteralPath $normalizerPath -Raw

function Assert-Match([string]$Pattern, [string]$Name) {
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $normalizerPath"
    }
}

Assert-Match 'StartsWith\(@"\\SystemRoot\\"(?s:.*?)GetSystemRoot' 'SystemRoot path expansion'
Assert-Match 'StartsWith\(@"\\\?\?\\UNC\\"(?s:.*?)@"\\\\"' 'NT UNC path expansion'
Assert-Match 'StartsWith\("Volume\{"(?s:.*?)@"\\\\\?\\"' 'volume GUID path expansion'
Assert-Match 'StartsWith\(@"\\Device\\Mup\\"(?s:.*?)@"\\\\"' 'MUP network path expansion'
Assert-Match 'StartsWith\(@"\\DosDevices\\"' 'DosDevices path expansion'

Write-Host "Driver path normalization coverage smoke passed."
