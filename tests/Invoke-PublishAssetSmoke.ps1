param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot "Xdows-Security.slnx"

if (!$SkipBuild) {
    $msbuild = "D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe"
    if (!(Test-Path -LiteralPath $msbuild)) {
        throw "MSBuild was not found at $msbuild. Visual Studio/WDK MSBuild is required so the Xdows Security solution can build the driver project."
    }

    & $msbuild $solution /p:Configuration=$Configuration /p:Platform=$Platform /p:WindowsTargetPlatformVersion=10.0.28000.0 /p:SignMode=Off /m
    if ($LASTEXITCODE -ne 0) {
        throw "Xdows-Security build failed with exit code $LASTEXITCODE"
    }
}

$rid = if ($Platform -eq "ARM64") { "win-arm64" } else { "win-x64" }
$appProjectRoot = Join-Path $repoRoot "Xdows-Security"
$outputCandidates = @(
    (Join-Path $appProjectRoot "bin\$Platform\$Configuration\net10.0-windows10.0.26100.0\$rid"),
    (Join-Path $appProjectRoot "bin\$Platform\$Configuration\net10.0-windows10.0.26100.0"),
    (Join-Path $appProjectRoot "bin\$Configuration\net10.0-windows10.0.26100.0\$rid"),
    (Join-Path $appProjectRoot "bin\$Configuration\net10.0-windows10.0.26100.0")
)

$outputDir = $outputCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (!$outputDir) {
    throw "App output directory was not found for $Platform/$Configuration."
}

$requiredFiles = @(
    "Xdows-Model.onnx",
    "Xdows-Model-Flash.onnx",
    "Xdows-Model-Pro.onnx",
    "Xdows-Model-Native.dll",
    "onnxruntime.dll",
    "onnxruntime_providers_shared.dll",
    "Driver\Xdows-Security-Driver.inf",
    "Driver\Xdows-Security-Driver.sys",
    "Driver\xdows-security-driver.cat"
)

$results = foreach ($relative in $requiredFiles) {
    $path = Join-Path $outputDir $relative
    if (!(Test-Path $path)) {
        throw "Required publish asset was not found: $path. Build Xdows-Security.slnx with Visual Studio/MSBuild for $Configuration|$Platform."
    }

    $item = Get-Item -LiteralPath $path
    if ($item.Length -le 0) {
        throw "Publish asset is empty: $path"
    }

    [pscustomobject]@{
        RelativePath = $relative
        Length = $item.Length
    }
}

$results | Format-Table -AutoSize
Write-Host "Publish asset smoke passed for output: $outputDir"
