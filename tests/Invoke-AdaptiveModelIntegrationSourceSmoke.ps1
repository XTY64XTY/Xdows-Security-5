$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$files = @{
    Settings = Get-Content -LiteralPath (Join-Path $repoRoot "Xdows-Security\Views\SettingsPage.xaml") -Raw
    ScanEngine = Get-Content -LiteralPath (Join-Path $repoRoot "Helper\ScanEngine.cs") -Raw
    App = Get-Content -LiteralPath (Join-Path $repoRoot "Xdows-Security\App.xaml.cs") -Raw
    SecurityPage = Get-Content -LiteralPath (Join-Path $repoRoot "Xdows-Security\Views\SecurityPage.xaml.cs") -Raw
    NativeScanner = Get-Content -LiteralPath (Join-Path $repoRoot "Protection\NativeModelScanner.cs") -Raw
    EnvironmentChecker = Get-Content -LiteralPath (Join-Path $repoRoot "Protection\DriverEnvironmentChecker.cs") -Raw
    Installer = Get-Content -LiteralPath (Join-Path $repoRoot "Protection\DriverInstaller.cs") -Raw
    ProtectionProject = Get-Content -LiteralPath (Join-Path $repoRoot "Protection\Protection.csproj") -Raw
    AppProject = Get-Content -LiteralPath (Join-Path $repoRoot "Xdows-Security\Xdows-Security.csproj") -Raw
    DriverProtocol = Get-Content -LiteralPath (Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h") -Raw
}

function Assert-Match([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -notmatch $Pattern) {
        throw "$Name was not found."
    }
}

Assert-Match $files.Settings 'Tag="Standard"(?s:.*?)Tag="Adaptive"(?s:.*?)Tag="Pro"' 'Adaptive option between Standard and Pro'
Assert-Match $files.ScanEngine '"Adaptive"\s*=>\s*Xdows_Model_Invoker\.ModelMode\.Adaptive' 'Adaptive settings mapping'
Assert-Match $files.ScanEngine 'ModelMode\.Adaptive(?s:.*?)ModelInvoker\.InitializeAdaptive\(\)' 'Adaptive managed initialization'
Assert-Match $files.ScanEngine 'ModelMode\.Adaptive\s*=>\s*"Adaptive"' 'Adaptive managed detection tag'
Assert-Match $files.App '"Adaptive"\s*=>\s*NativeModelScannerMode\.Adaptive' 'Adaptive driver-protection settings mapping'
Assert-Match $files.SecurityPage 'ModelMode\.Adaptive\s*=>\s*"Adaptive"' 'Adaptive scan log tag'
Assert-Match $files.NativeScanner 'Adaptive\s*=\s*3' 'Adaptive native ABI mode'
Assert-Match $files.DriverProtocol 'XdowsSecurityModelAdaptive\s*=\s*3' 'Adaptive driver protocol mode'

foreach ($asset in @(
    'Xdows-Model-Pro-Standard.onnx',
    'Xdows-Model-Pro-Flash.onnx',
    'Xdows-Model-Pro-RawStat.onnx',
    'Xdows-Model-Pro-Structural.onnx'
)) {
    $escapedAsset = [regex]::Escape($asset)
    Assert-Match $files.EnvironmentChecker $escapedAsset "Environment check for $asset"
    Assert-Match $files.Installer $escapedAsset "Repair copy for $asset"
}

Assert-Match $files.ProtectionProject 'Xdows-Model-Pro-\*\.onnx' 'Protection output for Pro branch models'
Assert-Match $files.AppProject 'Xdows-Model-Pro-\*\.onnx' 'App build and publish output for Pro branch models'

Write-Host "Adaptive model integration source smoke passed."
