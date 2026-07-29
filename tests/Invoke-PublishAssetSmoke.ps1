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

$nativeBuildOutput = Join-Path $appProjectRoot "obj\XdowsModelNative\$Platform\$Configuration\Xdows-Model-Native.dll"
if (!(Test-Path -LiteralPath $nativeBuildOutput)) {
    throw "Deterministic native model build output was not found: $nativeBuildOutput"
}

$requiredFiles = @(
    "Xdows-Model.onnx",
    "Xdows-Model-Flash.onnx",
    "Xdows-Model-Pro.onnx",
    "Xdows-Model-Pro-Standard.onnx",
    "Xdows-Model-Pro-Flash.onnx",
    "Xdows-Model-Pro-RawStat.onnx",
    "Xdows-Model-Pro-Structural.onnx",
    "Xdows-Model-Native.dll",
    "onnxruntime.dll",
    "onnxruntime_providers_shared.dll",
    "Xdows-Security-Driver.sys",
    "Driver\Xdows-Security-Driver.inf",
    "Driver\Xdows-Security-Driver.sys",
    "Driver\xdows-security-driver.cat",
    "Driver\BootFilter\Xdows-Security-BootFilter.inf",
    "Driver\BootFilter\Xdows-Security-BootFilter.sys",
    "Driver\BootFilter\xdows-security-bootfilter.cat"
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

$packagedNative = Join-Path $outputDir "Xdows-Model-Native.dll"
$sourceNativeHash = (Get-FileHash -LiteralPath $nativeBuildOutput -Algorithm SHA256).Hash
$packagedNativeHash = (Get-FileHash -LiteralPath $packagedNative -Algorithm SHA256).Hash
if ($sourceNativeHash -ne $packagedNativeHash) {
    throw "Packaged native model hash does not match the current native build output. Source=$sourceNativeHash Packaged=$packagedNativeHash"
}

$driverSource = Join-Path (Split-Path -Parent $repoRoot) "Xdows-Security-Driver\Xdows-Security-Driver\$Platform\$Configuration\Xdows-Security-Driver\Xdows-Security-Driver.sys"
$driverRootCopy = Join-Path $outputDir "Xdows-Security-Driver.sys"
$driverPackageCopy = Join-Path $outputDir "Driver\Xdows-Security-Driver.sys"
if (!(Test-Path -LiteralPath $driverSource)) {
    throw "Current driver build output was not found: $driverSource"
}

$driverHashes = @($driverSource, $driverRootCopy, $driverPackageCopy) |
    ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash } |
    Select-Object -Unique
if ($driverHashes.Count -ne 1) {
    throw "Driver hashes differ between source, output root, and packaged Driver directory: $($driverHashes -join ', ')"
}

$bootFilterSource = Join-Path (Split-Path -Parent $repoRoot) "Xdows-Security-Driver\Xdows-Security-BootFilter\$Platform\$Configuration\Xdows-Security-BootFilter\Xdows-Security-BootFilter.sys"
$bootFilterPackageCopy = Join-Path $outputDir "Driver\BootFilter\Xdows-Security-BootFilter.sys"
if (!(Test-Path -LiteralPath $bootFilterSource)) {
    throw "Current boot filter build output was not found: $bootFilterSource"
}
if ((Get-FileHash -LiteralPath $bootFilterSource -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $bootFilterPackageCopy -Algorithm SHA256).Hash) {
    throw "Packaged boot filter hash does not match the current boot filter build output."
}

$results | Format-Table -AutoSize
Write-Host "Publish asset smoke passed for output: $outputDir"
