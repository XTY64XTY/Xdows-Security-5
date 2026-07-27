param(
    [string]$PackageDirectory = "",

    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$serviceName = "Xdows-Security-Driver"
$devicePaths = @("\\.\XdowsSecurityDriver", "\\.\Global\XdowsSecurityDriver")
$ioctlGetState = [Convert]::ToUInt32("80002014", 16)
$expectedProtocolVersion = [uint32]6
$expectedDriverBuildId = [uint64]2026072801
$expectedStateSize = [uint32]176
$expectedCapabilities = [uint32]0x0000007F

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-DefaultPackageDirectory {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    return Join-Path $repoRoot "Xdows-Security\bin\x64\Release\net10.0-windows10.0.26100.0\win-x64\Driver"
}

function Invoke-CheckedProcess {
    param(
        [string]$FileName,
        [string]$Arguments,
        [switch]$IgnoreExitCode
    )

    $stdoutPath = Join-Path $env:TEMP "xdows-driver-smoke-$([Guid]::NewGuid()).out"
    $stderrPath = Join-Path $env:TEMP "xdows-driver-smoke-$([Guid]::NewGuid()).err"

    try {
        $process = Start-Process -FilePath $FileName -ArgumentList $Arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $output = ""
        if (Test-Path $stdoutPath) {
            $output += Get-Content -Raw -LiteralPath $stdoutPath
        }
        if (Test-Path $stderrPath) {
            $output += Get-Content -Raw -LiteralPath $stderrPath
        }

        if (!$IgnoreExitCode -and $process.ExitCode -ne 0) {
            throw "$FileName $Arguments failed with exit code $($process.ExitCode): $($output.Trim())"
        }

        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $output
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-ServiceQueryOutput {
    $result = Invoke-CheckedProcess -FileName "sc.exe" -Arguments "query `"$serviceName`"" -IgnoreExitCode
    return $result.Output
}

function Test-ServiceRunning {
    $query = Get-ServiceQueryOutput
    return $query -match "RUNNING"
}

function Stop-DriverServiceIfNeeded {
    if (!(Test-ServiceRunning)) {
        return
    }

    Invoke-CheckedProcess -FileName "sc.exe" -Arguments "stop `"$serviceName`"" -IgnoreExitCode | Out-Null
    for ($i = 0; $i -lt 12; $i++) {
        if (!(Test-ServiceRunning)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    Invoke-CheckedProcess -FileName "fltmc.exe" -Arguments "unload `"$serviceName`"" -IgnoreExitCode | Out-Null
    for ($i = 0; $i -lt 12; $i++) {
        if (!(Test-ServiceRunning)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "Driver service is running but the bridge is unreachable and the service could not be stopped. Restart Windows before reinstalling the driver."
}

if (!(Test-IsAdministrator)) {
    throw "Driver runtime smoke requires an elevated PowerShell session."
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class XdowsDriverSmokeNative
{
    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DiInstallDriver(IntPtr hwndParent, string fullInfPath, uint flags, out bool rebootRequired);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

function Invoke-DriverInstall {
    param([string]$InfPath)

    $rebootRequired = $false
    $ok = [XdowsDriverSmokeNative]::DiInstallDriver([IntPtr]::Zero, $InfPath, 0, [ref]$rebootRequired)
    if (!$ok) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "DiInstallDriver failed with Win32 error $errorCode."
    }

    if ($rebootRequired) {
        Write-Warning "DiInstallDriver reported that a reboot is required."
    }
}

function Test-DriverBridge {
    $genericReadWrite = [Convert]::ToUInt32("C0000000", 16)
    $fileShareReadWrite = [uint32]0x00000003
    $openExisting = [uint32]3
    $fileAttributeNormal = [uint32]0x00000080
    $invalidHandle = [IntPtr]::new(-1)

    $handle = $invalidHandle
    $lastError = 0
    foreach ($path in $devicePaths) {
        $handle = [XdowsDriverSmokeNative]::CreateFile(
            $path,
            $genericReadWrite,
            $fileShareReadWrite,
            [IntPtr]::Zero,
            $openExisting,
            $fileAttributeNormal,
            [IntPtr]::Zero)

        if ($handle -ne $invalidHandle) {
            break
        }

        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($handle -eq $invalidHandle) {
        return [pscustomobject]@{
            Reachable = $false
            Win32Error = $lastError
            State = $null
        }
    }

    try {
        $buffer = [byte[]]::new($expectedStateSize)
        $bytesReturned = [uint32]0
        $ok = [XdowsDriverSmokeNative]::DeviceIoControl(
            $handle,
            $ioctlGetState,
            [IntPtr]::Zero,
            0,
            $buffer,
            [uint32]$buffer.Length,
            [ref]$bytesReturned,
            [IntPtr]::Zero)

        if (!$ok) {
            return [pscustomobject]@{
                Reachable = $false
                Win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                State = $null
            }
        }

        if ($bytesReturned -lt $expectedStateSize) {
            throw "Driver state response is truncated. Expected at least $expectedStateSize bytes, received $bytesReturned."
        }

        return [pscustomobject]@{
            Reachable = $true
            Win32Error = 0
            State = [pscustomobject]@{
                HeaderSize = [BitConverter]::ToUInt32($buffer, 0)
                HeaderVersion = [BitConverter]::ToUInt32($buffer, 4)
                ClientConnected = [BitConverter]::ToUInt32($buffer, 8)
                PendingEventCount = [BitConverter]::ToUInt32($buffer, 12)
                DroppedEventCount = [BitConverter]::ToUInt32($buffer, 16)
                ProcessProtectionEnabled = [BitConverter]::ToUInt32($buffer, 20)
                FileProtectionEnabled = [BitConverter]::ToUInt32($buffer, 24)
                SelfProtectionEnabled = [BitConverter]::ToUInt32($buffer, 28)
                ProtectedProcessId = [BitConverter]::ToUInt32($buffer, 32)
                StartupProtectionEnabled = [BitConverter]::ToUInt32($buffer, 36)
                ActiveModules = [BitConverter]::ToUInt32($buffer, 40)
                ProtocolVersion = [BitConverter]::ToUInt32($buffer, 44)
                Capabilities = [BitConverter]::ToUInt32($buffer, 48)
                DriverBuildId = [BitConverter]::ToUInt64($buffer, 56)
            }
        }
    }
    finally {
        [XdowsDriverSmokeNative]::CloseHandle($handle) | Out-Null
    }
}

if ([string]::IsNullOrWhiteSpace($PackageDirectory)) {
    $PackageDirectory = Resolve-DefaultPackageDirectory
}

$infPath = Join-Path $PackageDirectory "Xdows-Security-Driver.inf"
$sysPath = Join-Path $PackageDirectory "Xdows-Security-Driver.sys"
$catPath = Join-Path $PackageDirectory "xdows-security-driver.cat"
$certificatePath = Join-Path $PackageDirectory "Xdows-Security-Driver-Test.cer"

foreach ($required in @($infPath, $sysPath, $catPath)) {
    if (!(Test-Path -LiteralPath $required)) {
        throw "Required driver package file was not found: $required"
    }
}

if (Test-Path -LiteralPath $certificatePath) {
    Invoke-CheckedProcess -FileName "certutil.exe" -Arguments "-addstore -f Root `"$certificatePath`"" | Out-Null
    Invoke-CheckedProcess -FileName "certutil.exe" -Arguments "-addstore -f TrustedPublisher `"$certificatePath`"" | Out-Null
}

if (!$SkipInstall) {
    Stop-DriverServiceIfNeeded
    Invoke-DriverInstall -InfPath $infPath
}

Invoke-CheckedProcess -FileName "sc.exe" -Arguments "start `"$serviceName`"" -IgnoreExitCode | Out-Null

$lastBridge = $null
for ($i = 0; $i -lt 20; $i++) {
    $lastBridge = Test-DriverBridge
    if ($lastBridge.Reachable) {
        if ($lastBridge.State.HeaderVersion -ne $expectedProtocolVersion -or
            $lastBridge.State.ProtocolVersion -ne $expectedProtocolVersion -or
            $lastBridge.State.DriverBuildId -ne $expectedDriverBuildId -or
            ($lastBridge.State.Capabilities -band $expectedCapabilities) -ne $expectedCapabilities) {
            throw "Driver protocol/build mismatch. Expected v$expectedProtocolVersion/$expectedDriverBuildId, received header v$($lastBridge.State.HeaderVersion), state v$($lastBridge.State.ProtocolVersion)/$($lastBridge.State.DriverBuildId)."
        }
        $lastBridge.State | Format-List
        Write-Host "Driver runtime smoke passed. Service started and bridge IOCTL succeeded."
        exit 0
    }

    Start-Sleep -Milliseconds 500
}

$serviceQuery = Get-ServiceQueryOutput
throw "Driver bridge did not become reachable. Last Win32 error: $($lastBridge.Win32Error). Service query: $serviceQuery"
