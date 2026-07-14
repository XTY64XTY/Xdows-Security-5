$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$driverPublicHeader = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
$protocolCs = Join-Path $repoRoot "Protection\DriverProtocol.cs"
$bridgeClientCs = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
$driverProtectionCs = Join-Path $repoRoot "Protection\DriverProtection.cs"

foreach ($required in @($driverPublicHeader, $protocolCs, $bridgeClientCs, $driverProtectionCs)) {
    if (!(Test-Path $required)) {
        throw "Required source file was not found: $required"
    }
}

$publicText = Get-Content -Raw -LiteralPath $driverPublicHeader
$protocolText = Get-Content -Raw -LiteralPath $protocolCs
$bridgeText = Get-Content -Raw -LiteralPath $bridgeClientCs
$protectionText = Get-Content -Raw -LiteralPath $driverProtectionCs

$checks = New-Object System.Collections.Generic.List[string]

function Read-Number {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Name
    )

    if ($Text -notmatch $Pattern) {
        throw "Could not find $Name with pattern: $Pattern"
    }

    $value = $Matches[1]
    if ($value.StartsWith("0x", [StringComparison]::OrdinalIgnoreCase)) {
        return [Convert]::ToUInt32($value.Substring(2), 16)
    }

    return [Convert]::ToUInt32($value)
}

function Assert-Equal {
    param(
        [object]$Expected,
        [object]$Actual,
        [string]$Name
    )

    if ($Expected -ne $Actual) {
        throw "$Name mismatch. Expected=$Expected Actual=$Actual"
    }

    $checks.Add($Name) | Out-Null
}

$constants = @(
    @{ C = "XDOWS_SECURITY_PROTOCOL_VERSION"; Cs = "ProtocolVersion"; Expected = 3 },
    @{ C = "XDOWS_SECURITY_MAX_PATH_CHARS"; Cs = "MaxPathChars"; Expected = 520 },
    @{ C = "XDOWS_SECURITY_MAX_COMMAND_CHARS"; Cs = "MaxCommandChars"; Expected = 1024 },
    @{ C = "XDOWS_SECURITY_MAX_REASON_CHARS"; Cs = "MaxReasonChars"; Expected = 128 },
    @{ C = "XDOWS_SECURITY_TOKEN_CHARS"; Cs = "TokenChars"; Expected = 64 },
    @{ C = "XDOWS_SECURITY_MAX_LOG_MODULE_CHARS"; Cs = "MaxLogModuleChars"; Expected = 32 },
    @{ C = "XDOWS_SECURITY_MAX_LOG_MESSAGE_CHARS"; Cs = "MaxLogMessageChars"; Expected = 256 },
    @{ C = "XDOWS_SECURITY_MODULE_TOKEN_AUTH"; Cs = "ModuleTokenAuth"; Expected = 1 },
    @{ C = "XDOWS_SECURITY_MODULE_PROCESS"; Cs = "ModuleProcess"; Expected = 2 },
    @{ C = "XDOWS_SECURITY_MODULE_FILE"; Cs = "ModuleFile"; Expected = 4 },
    @{ C = "XDOWS_SECURITY_MODULE_INJECTION"; Cs = "ModuleInjection"; Expected = 8 },
    @{ C = "XDOWS_SECURITY_MODULE_SELF_PROTECT"; Cs = "ModuleSelfProtect"; Expected = 16 }
)

$cBuildId = Read-Number $publicText "#define\s+XDOWS_SECURITY_DRIVER_BUILD_ID\s+([0-9]+)ULL" "XDOWS_SECURITY_DRIVER_BUILD_ID"
$csBuildId = Read-Number $protocolText "public\s+const\s+ulong\s+DriverBuildId\s+=\s+([0-9]+);" "DriverBuildId"
Assert-Equal $cBuildId $csBuildId "Driver build ID"

foreach ($constant in $constants) {
    $cValue = Read-Number $publicText "#define\s+$($constant.C)\s+(0x[0-9A-Fa-f]+|[0-9]+)u?" $constant.C
    $csValue = Read-Number $protocolText "public\s+const\s+(?:uint|int)\s+$($constant.Cs)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+);" $constant.Cs
    Assert-Equal $constant.Expected $cValue "$($constant.C) expected value"
    Assert-Equal $cValue $csValue "$($constant.C) mirrors DriverProtocol.$($constant.Cs)"
}

if ($publicText -notmatch 'ULONG\s+ProcessProtectionEnabled;\s*ULONG\s+FileProtectionEnabled;\s*ULONG\s+SelfProtectionEnabled;\s*ULONG\s+ProtectedProcessId;\s*ULONG\s+ActiveModules;\s*ULONG\s+ProtocolVersion;' -or
    $protocolText -notmatch 'uint\s+ProcessProtectionEnabled;\s*public\s+uint\s+FileProtectionEnabled;\s*public\s+uint\s+SelfProtectionEnabled;\s*public\s+uint\s+ProtectedProcessId;\s*public\s+uint\s+ActiveModules;\s*public\s+uint\s+ProtocolVersion;') {
    throw "XdowsSecurityState module fields are not mirrored in protocol order."
}
$checks.Add("XdowsSecurityState module field order") | Out-Null

$cDeviceType = Read-Number $publicText "#define\s+FILE_DEVICE_XDOWS_SECURITY\s+(0x[0-9A-Fa-f]+)u?" "FILE_DEVICE_XDOWS_SECURITY"
$csDeviceType = Read-Number $protocolText "private\s+const\s+uint\s+FileDeviceXdowsSecurity\s+=\s+(0x[0-9A-Fa-f]+);" "FileDeviceXdowsSecurity"
Assert-Equal $cDeviceType $csDeviceType "File device type"

$ioctls = @(
    @{ C = "REGISTER_CLIENT"; Cs = "RegisterClient"; Function = 0x801 },
    @{ C = "HEARTBEAT"; Cs = "Heartbeat"; Function = 0x802 },
    @{ C = "GET_NEXT_EVENT"; Cs = "GetNextEvent"; Function = 0x803 },
    @{ C = "SUBMIT_DECISION"; Cs = "SubmitDecision"; Function = 0x804 },
    @{ C = "GET_STATE"; Cs = "GetState"; Function = 0x805 },
    @{ C = "DISCONNECT_CLIENT"; Cs = "DisconnectClient"; Function = 0x806 },
    @{ C = "REGISTER_PROTECTED_PROCESS"; Cs = "RegisterProtectedProcess"; Function = 0x807 },
    @{ C = "SET_VOLUNTARY_EXIT"; Cs = "SetVoluntaryExit"; Function = 0x808 },
    @{ C = "AUTHORIZED_SHUTDOWN"; Cs = "AuthorizedShutdown"; Function = 0x809 },
    @{ C = "GET_NEXT_LOG"; Cs = "GetNextLog"; Function = 0x80A }
)

foreach ($ioctl in $ioctls) {
    $cFunction = Read-Number $publicText "(?s)#define\s+IOCTL_XDOWS_SECURITY_$($ioctl.C)\s+\\\s+CTL_CODE\(FILE_DEVICE_XDOWS_SECURITY,\s+(0x[0-9A-Fa-f]+)" "IOCTL_XDOWS_SECURITY_$($ioctl.C)"
    $csFunction = Read-Number $protocolText "public\s+static\s+readonly\s+uint\s+$($ioctl.Cs)\s+=\s+CtlCode\(FileDeviceXdowsSecurity,\s+(0x[0-9A-Fa-f]+)" "DriverProtocol.$($ioctl.Cs)"
    Assert-Equal $ioctl.Function $cFunction "IOCTL_XDOWS_SECURITY_$($ioctl.C) function"
    Assert-Equal $cFunction $csFunction "IOCTL_XDOWS_SECURITY_$($ioctl.C) mirrors DriverProtocol.$($ioctl.Cs)"

    if ($bridgeText -notmatch "DriverProtocol\.$($ioctl.Cs)\b") {
        throw "DriverBridgeClient does not reference DriverProtocol.$($ioctl.Cs)"
    }

    $checks.Add("DriverBridgeClient uses $($ioctl.Cs)") | Out-Null
}

$enums = @(
    @{ C = "XdowsSecurityEventNone"; Cs = "None"; Value = 0 },
    @{ C = "XdowsSecurityEventProcessCreate"; Cs = "ProcessCreate"; Value = 1 },
    @{ C = "XdowsSecurityEventFileCreate"; Cs = "FileCreate"; Value = 2 },
    @{ C = "XdowsSecurityEventFileWrite"; Cs = "FileWrite"; Value = 3 },
    @{ C = "XdowsSecurityEventFileRename"; Cs = "FileRename"; Value = 4 },
    @{ C = "XdowsSecurityEventProcessHandle"; Cs = "ProcessHandle"; Value = 5 },
    @{ C = "XdowsSecurityEventThreadHandle"; Cs = "ThreadHandle"; Value = 6 },
    @{ C = "XdowsSecurityEventImageLoad"; Cs = "ImageLoad"; Value = 7 },
    @{ C = "XdowsSecurityEventDriverLog"; Cs = "DriverLog"; Value = 8 },
    @{ C = "XdowsSecurityDecisionUnknown"; Cs = "Unknown"; Value = 0 },
    @{ C = "XdowsSecurityDecisionAllow"; Cs = "Allow"; Value = 1 },
    @{ C = "XdowsSecurityDecisionBlock"; Cs = "Block"; Value = 2 },
    @{ C = "XdowsSecurityDecisionTimeout"; Cs = "Timeout"; Value = 3 },
    @{ C = "XdowsSecurityModelStandard"; Cs = "Standard"; Value = 0 },
    @{ C = "XdowsSecurityModelFlash"; Cs = "Flash"; Value = 1 },
    @{ C = "XdowsSecurityModelPro"; Cs = "Pro"; Value = 2 },
    @{ C = "XdowsSecurityLogDebug"; Cs = "Debug"; Value = 0 },
    @{ C = "XdowsSecurityLogInfo"; Cs = "Info"; Value = 1 },
    @{ C = "XdowsSecurityLogWarning"; Cs = "Warning"; Value = 2 },
    @{ C = "XdowsSecurityLogError"; Cs = "Error"; Value = 3 },
    @{ C = "XdowsSecurityLogFatal"; Cs = "Fatal"; Value = 4 }
)

foreach ($enum in $enums) {
    $cValue = Read-Number $publicText "$($enum.C)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+)" $enum.C
    $csValue = Read-Number $protocolText "\b$($enum.Cs)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+)" $enum.Cs
    Assert-Equal $enum.Value $cValue "$($enum.C) expected value"
    Assert-Equal $cValue $csValue "$($enum.C) mirrors C# enum $($enum.Cs)"
}

foreach ($eventName in @("ProcessCreate", "FileCreate", "FileWrite", "FileRename", "ProcessHandle", "ThreadHandle", "ImageLoad")) {
    if ($protectionText -notmatch "XdowsSecurityEventType\.$eventName\b") {
        throw "DriverProtection does not handle XdowsSecurityEventType.$eventName"
    }

    $checks.Add("DriverProtection handles $eventName") | Out-Null
}

if ($bridgeText -notmatch "ErrorNoMoreItems\s+=\s+259") {
    throw "DriverBridgeClient must treat ERROR_NO_MORE_ITEMS as an empty event/log queue."
}

$checks.Add("DriverBridgeClient handles ERROR_NO_MORE_ITEMS") | Out-Null

[pscustomobject]@{
    SourceHeader = $driverPublicHeader
    ProtocolMirror = $protocolCs
    CheckCount = $checks.Count
    Status = "Passed"
}

Write-Host "Driver bridge protocol smoke passed with $($checks.Count) checks."
