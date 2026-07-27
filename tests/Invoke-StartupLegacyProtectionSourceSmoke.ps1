$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    App = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
    ProcessProtection = Join-Path $repoRoot "Protection\LegacyProcess.cs"
    FileProtection = Join-Path $repoRoot "Protection\LegacyFiles.cs"
}

foreach ($path in $files.Values) {
    if (!(Test-Path -LiteralPath $path)) {
        throw "Required source file missing: $path"
    }
}

function Assert-Match([string]$Path, [string]$Pattern, [string]$Name) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch $Pattern) {
        throw "$Name was not found in $Path"
    }
}

Assert-Match $files.App 'public\s+static\s+void\s+RestoreDriverProtection\(\)(?s:.*?)RestoreProtection\(5\);' 'dedicated early driver restore'
Assert-Match $files.App 'public\s+static\s+void\s+RestoreLegacyProtections\(\)(?s:.*?)if\s*\(!IsRun\(5\)\)(?s:.*?)RestoreProtection\(0\);(?s:.*?)RestoreProtection\(1\);' 'dedicated legacy protection restore'
Assert-Match $files.App 'Task\s+restoreDriverProtectionTask\s*=\s*Task\.Run\(\(\)\s*=>(?s:.*?)RestoreDriverProtection\(\)' 'driver restore starts before optional startup work'
Assert-Match $files.App 'InitializeMainWindow\(\);(?s:.*?)await\s+restoreDriverProtectionTask\.ConfigureAwait\(false\);(?s:.*?)RestoreLegacyProtections\(\);' 'legacy restore waits until window initialization and driver restore completion'
Assert-Match $files.ProcessProtection 'if\s*\(!Helper\.ScanEngine\.ModelEngineScan\.InitializeForProtection\(\)\)\s*return\s+false;' 'process protection rejects failed model initialization'
Assert-Match $files.FileProtection 'if\s*\(!Helper\.ScanEngine\.ModelEngineScan\.InitializeForProtection\(\)\)\s*return\s+false;' 'file protection rejects failed model initialization'

Write-Host "Startup legacy protection source smoke passed."
