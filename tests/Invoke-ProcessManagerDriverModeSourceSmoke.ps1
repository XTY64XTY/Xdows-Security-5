$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$protocol = Get-Content -Raw (Join-Path $repoRoot "Protection\DriverProtocol.cs")
$bridge = Get-Content -Raw (Join-Path $repoRoot "Protection\DriverBridgeClient.cs")
$protection = Get-Content -Raw (Join-Path $repoRoot "Protection\DriverProtection.cs")
$app = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\App.xaml.cs")
$xaml = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\Plugins\ProcessManagerView.xaml")
$view = Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\Plugins\ProcessManagerView.xaml.cs")
$resources = @(
    Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANS\Resources.resw")
    Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\Strings\zh-HANT\Resources.resw")
    Get-Content -Raw (Join-Path $repoRoot "Xdows-Security\Strings\en-US\Resources.resw")
)

function Assert-Match([string]$Text, [string]$Pattern, [string]$Name) {
    if ($Text -notmatch $Pattern) {
        throw "$Name was not found."
    }
}

Assert-Match $protocol 'ProtocolVersion\s*=\s*6' 'protocol v6'
Assert-Match $protocol 'CapabilityProcessManagement\s*=\s*0x00000020' 'process management capability mirror'
Assert-Match $protocol 'QueryProcesses\s*=\s*CtlCode\(FileDeviceXdowsSecurity,\s*0x80C' 'process query IOCTL mirror'
Assert-Match $protocol 'OperateProcess\s*=\s*CtlCode\(FileDeviceXdowsSecurity,\s*0x80D' 'process operation IOCTL mirror'
Assert-Match $bridge 'AuthorizationToken\s*=\s*token' 'query authorization token forwarding'
Assert-Match $bridge 'AuthorizationToken\s*=\s*GetAuthorizationToken\(\)' 'operation authorization token forwarding'
Assert-Match $protection 'GetProcesses\(\)(?s:.*?)client\.QueryProcesses' 'driver process list public API'
Assert-Match $protection 'OperateProcess\(uint processId(?s:.*?)client\.OperateProcess' 'driver process operation public API'
Assert-Match $app 'GetDriverProcesses\(\)' 'app driver process list bridge'
Assert-Match $xaml 'x:Name="ViewModeToggle"(?s:.*?)x:Name="DriverModeToggle"' 'driver toggle after tree toggle'
Assert-Match $xaml '<StackPanel(?s:.*?)Orientation="Horizontal"(?s:.*?)Spacing="4"(?s:.*?)x:Name="ViewModeToggle"(?s:.*?)MinWidth="0"(?s:.*?)x:Name="DriverModeToggle"(?s:.*?)MinWidth="0"' 'compact shared toggle layout'
Assert-Match $xaml 'AutomationProperties\.AutomationId="ProcessManagerDriverModeToggle"' 'driver toggle automation ID'
Assert-Match $view 'if \(!ProtectionStatus\.IsRun\(5\)\)(?s:.*?)SetDriverModeToggleSilently\(false\)' 'driver protection prerequisite'
Assert-Match $view 'ShowDriverModeDisclaimerAsync\(\)' 'per-enable disclaimer'
Assert-Match $view 'ProtectionStatus\.GetDriverProcesses\(\)' 'driver list routing'
Assert-Match $view 'DriverProcessOperation\.Suspend' 'driver suspend routing'
Assert-Match $view 'DriverProcessOperation\.Resume' 'driver resume routing'
Assert-Match $view 'DriverProcessOperation\.Terminate' 'driver terminate routing'

foreach ($resource in $resources) {
    Assert-Match $resource 'ProcessManager_DriverModeToggle\.OnContent' 'localized driver toggle'
    Assert-Match $resource 'ProcessManager_DriverMode_Disclaimer_Text' 'localized driver disclaimer'
    Assert-Match $resource 'ProcessManager_DriverMode_RequiresProtection_Text' 'localized driver prerequisite'
}

Write-Host "Process manager driver mode source smoke passed."
