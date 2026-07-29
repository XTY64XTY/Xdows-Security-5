$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot
$driverPublicHeader = Join-Path $codeRoot "Xdows-Security-Driver\Xdows-Security-Driver\Public.h"
$protocolCs = Join-Path $repoRoot "Protection\DriverProtocol.cs"
$bridgeClientCs = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
$driverProtectionCs = Join-Path $repoRoot "Protection\DriverProtection.cs"
$runtimeSmokePs1 = Join-Path $repoRoot "tests\Invoke-DriverRuntimeSmoke.ps1"

foreach ($required in @($driverPublicHeader, $protocolCs, $bridgeClientCs, $driverProtectionCs, $runtimeSmokePs1)) {
    if (!(Test-Path $required)) {
        throw "Required source file was not found: $required"
    }
}

$publicText = Get-Content -Raw -LiteralPath $driverPublicHeader
$protocolText = Get-Content -Raw -LiteralPath $protocolCs
$bridgeText = Get-Content -Raw -LiteralPath $bridgeClientCs
$protectionText = Get-Content -Raw -LiteralPath $driverProtectionCs
$runtimeSmokeText = Get-Content -Raw -LiteralPath $runtimeSmokePs1

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
    @{ C = "XDOWS_SECURITY_PROTOCOL_VERSION"; Cs = "ProtocolVersion"; Expected = 8 },
    @{ C = "XDOWS_SECURITY_EVENT_TYPE_COUNT"; Cs = "EventTypeCount"; Expected = 11 },
    @{ C = "XDOWS_SECURITY_CAP_PRIORITY_QUEUE"; Cs = "CapabilityPriorityQueue"; Expected = 1 },
    @{ C = "XDOWS_SECURITY_CAP_DIRTY_WRITE_COALESCING"; Cs = "CapabilityDirtyWriteCoalescing"; Expected = 2 },
    @{ C = "XDOWS_SECURITY_CAP_BUILD_ID"; Cs = "CapabilityBuildId"; Expected = 4 },
    @{ C = "XDOWS_SECURITY_CAP_STARTUP_SELF_PROTECT"; Cs = "CapabilityStartupSelfProtect"; Expected = 8 },
    @{ C = "XDOWS_SECURITY_CAP_USER_DECISION_HOLD"; Cs = "CapabilityUserDecisionHold"; Expected = 16 },
    @{ C = "XDOWS_SECURITY_CAP_PROCESS_MANAGEMENT"; Cs = "CapabilityProcessManagement"; Expected = 32 },
    @{ C = "XDOWS_SECURITY_CAP_ENHANCED_SELF_PROTECT"; Cs = "CapabilityEnhancedSelfProtect"; Expected = 64 },
    @{ C = "XDOWS_SECURITY_CAP_R0_BEHAVIOR_PROTECTION"; Cs = "CapabilityR0BehaviorProtection"; Expected = 128 },
    @{ C = "XDOWS_SECURITY_CAP_R0_BOOT_PROTECTION"; Cs = "CapabilityR0BootProtection"; Expected = 256 },
    @{ C = "XDOWS_SECURITY_MAX_PATH_CHARS"; Cs = "MaxPathChars"; Expected = 520 },
    @{ C = "XDOWS_SECURITY_MAX_COMMAND_CHARS"; Cs = "MaxCommandChars"; Expected = 1024 },
    @{ C = "XDOWS_SECURITY_MAX_REASON_CHARS"; Cs = "MaxReasonChars"; Expected = 128 },
    @{ C = "XDOWS_SECURITY_TOKEN_CHARS"; Cs = "TokenChars"; Expected = 64 },
    @{ C = "XDOWS_SECURITY_MAX_LOG_MODULE_CHARS"; Cs = "MaxLogModuleChars"; Expected = 32 },
    @{ C = "XDOWS_SECURITY_MAX_LOG_MESSAGE_CHARS"; Cs = "MaxLogMessageChars"; Expected = 256 },
    @{ C = "XDOWS_SECURITY_MAX_PROCESS_NAME_CHARS"; Cs = "MaxProcessNameChars"; Expected = 260 },
    @{ C = "XDOWS_SECURITY_PROCESS_BATCH_SIZE"; Cs = "ProcessBatchSize"; Expected = 64 },
    @{ C = "XDOWS_SECURITY_MODULE_TOKEN_AUTH"; Cs = "ModuleTokenAuth"; Expected = 1 },
    @{ C = "XDOWS_SECURITY_MODULE_PROCESS"; Cs = "ModuleProcess"; Expected = 2 },
    @{ C = "XDOWS_SECURITY_MODULE_FILE"; Cs = "ModuleFile"; Expected = 4 },
    @{ C = "XDOWS_SECURITY_MODULE_INJECTION"; Cs = "ModuleInjection"; Expected = 8 },
    @{ C = "XDOWS_SECURITY_MODULE_SELF_PROTECT"; Cs = "ModuleSelfProtect"; Expected = 16 },
    @{ C = "XDOWS_SECURITY_MODULE_BEHAVIOR"; Cs = "ModuleBehavior"; Expected = 32 }
)

$cBuildId = Read-Number $publicText "#define\s+XDOWS_SECURITY_DRIVER_BUILD_ID\s+([0-9]+)ULL" "XDOWS_SECURITY_DRIVER_BUILD_ID"
$csBuildId = Read-Number $protocolText "public\s+const\s+ulong\s+DriverBuildId\s+=\s+([0-9]+);" "DriverBuildId"
$runtimeBuildId = Read-Number $runtimeSmokeText '\$expectedDriverBuildId\s*=\s*\[uint64\]([0-9]+)' "runtime smoke driver build ID"
Assert-Equal $cBuildId $csBuildId "Driver build ID"
Assert-Equal $cBuildId $runtimeBuildId "Runtime smoke driver build ID"

$runtimeProtocolVersion = Read-Number $runtimeSmokeText '\$expectedProtocolVersion\s*=\s*\[uint32\]([0-9]+)' "runtime smoke protocol version"
Assert-Equal 8 $runtimeProtocolVersion "Runtime smoke protocol version"

foreach ($offsetCheck in @(
    @{ Pattern = 'FileProtectionEnabled\s*=\s*\[BitConverter\]::ToUInt32\(\$buffer,\s*24\)'; Name = "runtime file protection offset" },
    @{ Pattern = 'SelfProtectionEnabled\s*=\s*\[BitConverter\]::ToUInt32\(\$buffer,\s*28\)'; Name = "runtime self-protection offset" },
    @{ Pattern = 'StartupProtectionEnabled\s*=\s*\[BitConverter\]::ToUInt32\(\$buffer,\s*36\)'; Name = "runtime startup protection offset" },
    @{ Pattern = 'BootProtectionEnabled\s*=\s*\[BitConverter\]::ToUInt32\(\$buffer,\s*40\)'; Name = "runtime boot protection offset" },
    @{ Pattern = 'ProtocolVersion\s*=\s*\[BitConverter\]::ToUInt32\(\$buffer,\s*48\)'; Name = "runtime protocol offset" },
    @{ Pattern = 'DriverBuildId\s*=\s*\[BitConverter\]::ToUInt64\(\$buffer,\s*56\)'; Name = "runtime build ID offset" }
)) {
    if ($runtimeSmokeText -notmatch $offsetCheck.Pattern) {
        throw "$($offsetCheck.Name) was not found in $runtimeSmokePs1"
    }
    $checks.Add($offsetCheck.Name) | Out-Null
}

foreach ($constant in $constants) {
    $cValue = Read-Number $publicText "#define\s+$($constant.C)\s+(0x[0-9A-Fa-f]+|[0-9]+)u?" $constant.C
    $csValue = Read-Number $protocolText "public\s+const\s+(?:uint|int)\s+$($constant.Cs)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+);" $constant.Cs
    Assert-Equal $constant.Expected $cValue "$($constant.C) expected value"
    Assert-Equal $cValue $csValue "$($constant.C) mirrors DriverProtocol.$($constant.Cs)"
}

if ($publicText -notmatch 'ULONG\s+ProcessProtectionEnabled;\s*ULONG\s+FileProtectionEnabled;\s*ULONG\s+SelfProtectionEnabled;\s*ULONG\s+ProtectedProcessId;\s*ULONG\s+StartupProtectionEnabled;\s*ULONG\s+BootProtectionEnabled;\s*ULONG\s+ActiveModules;\s*ULONG\s+ProtocolVersion;' -or
    $protocolText -notmatch 'uint\s+ProcessProtectionEnabled;\s*public\s+uint\s+FileProtectionEnabled;\s*public\s+uint\s+SelfProtectionEnabled;\s*public\s+uint\s+ProtectedProcessId;\s*public\s+uint\s+StartupProtectionEnabled;\s*public\s+uint\s+BootProtectionEnabled;\s*public\s+uint\s+ActiveModules;\s*public\s+uint\s+ProtocolVersion;') {
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
    @{ C = "GET_NEXT_LOG"; Cs = "GetNextLog"; Function = 0x80A },
    @{ C = "SET_STARTUP_PROTECTION"; Cs = "SetStartupProtection"; Function = 0x80B },
    @{ C = "QUERY_PROCESSES"; Cs = "QueryProcesses"; Function = 0x80C },
    @{ C = "OPERATE_PROCESS"; Cs = "OperateProcess"; Function = 0x80D },
    @{ C = "SET_BOOT_PROTECTION"; Cs = "SetBootProtection"; Function = 0x80E }
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
    @{ C = "XdowsSecurityEventBehavior"; Cs = "Behavior"; Value = 9 },
    @{ C = "XdowsSecurityEventBootWrite"; Cs = "BootWrite"; Value = 10 },
    @{ C = "XdowsSecurityBehaviorVssDeletion"; Cs = "VssDeletion"; Value = 1 },
    @{ C = "XdowsSecurityBehaviorHiddenPowerShell"; Cs = "HiddenPowerShell"; Value = 2 },
    @{ C = "XdowsSecurityBehaviorEncodedCommand"; Cs = "EncodedCommand"; Value = 3 },
    @{ C = "XdowsSecurityBehaviorPolicyBypass"; Cs = "PolicyBypass"; Value = 4 },
    @{ C = "XdowsSecurityBehaviorDownloadExecute"; Cs = "DownloadExecute"; Value = 5 },
    @{ C = "XdowsSecurityBehaviorLolbinAbuse"; Cs = "LolbinAbuse"; Value = 6 },
    @{ C = "XdowsSecurityBehaviorProcessInjection"; Cs = "ProcessInjection"; Value = 7 },
    @{ C = "XdowsSecurityBehaviorThreadInjection"; Cs = "ThreadInjection"; Value = 8 },
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
    @{ C = "XdowsSecurityLogFatal"; Cs = "Fatal"; Value = 4 },
    @{ C = "XdowsSecurityProcessOperationNone"; Cs = "None"; Value = 0 },
    @{ C = "XdowsSecurityProcessOperationSuspend"; Cs = "Suspend"; Value = 1 },
    @{ C = "XdowsSecurityProcessOperationResume"; Cs = "Resume"; Value = 2 },
    @{ C = "XdowsSecurityProcessOperationTerminate"; Cs = "Terminate"; Value = 3 }
)

foreach ($enum in $enums) {
    $cValue = Read-Number $publicText "$($enum.C)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+)" $enum.C
    $csValue = Read-Number $protocolText "\b$($enum.Cs)\s+=\s+(0x[0-9A-Fa-f]+|[0-9]+)" $enum.Cs
    Assert-Equal $enum.Value $cValue "$($enum.C) expected value"
    Assert-Equal $cValue $csValue "$($enum.C) mirrors C# enum $($enum.Cs)"
}

foreach ($eventName in @("ProcessCreate", "FileCreate", "FileWrite", "FileRename", "ProcessHandle", "ThreadHandle", "ImageLoad", "Behavior", "BootWrite")) {
    if ($protectionText -notmatch "XdowsSecurityEventType\.$eventName\b") {
        throw "DriverProtection does not handle XdowsSecurityEventType.$eventName"
    }

    $checks.Add("DriverProtection handles $eventName") | Out-Null
}

if ($bridgeText -notmatch "ErrorNoMoreItems\s+=\s+259") {
    throw "DriverBridgeClient must treat ERROR_NO_MORE_ITEMS as an empty event/log queue."
}

$checks.Add("DriverBridgeClient handles ERROR_NO_MORE_ITEMS") | Out-Null

if ($publicText -notmatch 'XDOWS_SECURITY_PROCESS_QUERY_REQUEST(?s:.*?)ULONG\s+Cursor;\s*ULONG\s+Reserved;\s*WCHAR\s+AuthorizationToken\[XDOWS_SECURITY_TOKEN_CHARS\s*\+\s*1\]' -or
    $protocolText -notmatch 'XdowsProcessQueryRequest(?s:.*?)uint\s+Cursor;\s*public\s+uint\s+Reserved;(?s:.*?)string\s+AuthorizationToken;') {
    throw "Process query request fields are not mirrored in protocol order."
}
$checks.Add("Process query request field order") | Out-Null

if ($publicText -notmatch 'XDOWS_SECURITY_PROCESS_ENTRY(?s:.*?)ULONG\s+ProcessId;\s*ULONG\s+ParentProcessId;\s*ULONG\s+SessionId;\s*ULONG\s+ThreadCount;\s*ULONG\s+HandleCount;\s*ULONG\s+BasePriority;\s*ULONGLONG\s+WorkingSetBytes;\s*ULONGLONG\s+PrivateBytes;' -or
    $protocolText -notmatch 'XdowsDriverProcessEntry(?s:.*?)uint\s+ProcessId;\s*public\s+uint\s+ParentProcessId;\s*public\s+uint\s+SessionId;\s*public\s+uint\s+ThreadCount;\s*public\s+uint\s+HandleCount;\s*public\s+uint\s+BasePriority;\s*public\s+ulong\s+WorkingSetBytes;\s*public\s+ulong\s+PrivateBytes;') {
    throw "Process entry fields are not mirrored in protocol order."
}
$checks.Add("Process entry field order") | Out-Null

[pscustomobject]@{
    SourceHeader = $driverPublicHeader
    ProtocolMirror = $protocolCs
    CheckCount = $checks.Count
    Status = "Passed"
}

Write-Host "Driver bridge protocol smoke passed with $($checks.Count) checks."
