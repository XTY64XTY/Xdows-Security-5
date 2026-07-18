$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$files = @{
    Protocol = Join-Path $repoRoot "Protection\DriverProtocol.cs"
    Bridge = Join-Path $repoRoot "Protection\DriverBridgeClient.cs"
    Protection = Join-Path $repoRoot "Protection\DriverProtection.cs"
    Startup = Join-Path $repoRoot "Xdows-Security\Services\StartupService.cs"
    App = Join-Path $repoRoot "Xdows-Security\App.xaml.cs"
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

Assert-Match $files.Protocol 'ProtocolVersion\s*=\s*6;' 'protocol v6 mirror'
Assert-Match $files.Protocol 'DriverBuildId\s*=\s*2026071801;' 'startup protection driver build mirror'
Assert-Match $files.Protocol 'SetStartupProtection\s*=\s*CtlCode\(FileDeviceXdowsSecurity,\s*0x80B' 'startup protection IOCTL mirror'
Assert-Match $files.Protocol 'uint\s+StartupProtectionEnabled;' 'startup protection runtime state mirror'
Assert-Match $files.Protocol 'struct\s+XdowsStartupProtectionRequest' 'startup protection request mirror'
Assert-Match $files.Bridge 'void\s+SetStartupProtection\(bool\s+enabled\)' 'managed startup protection request API'
Assert-Match $files.Bridge 'DriverProtocol\.SetStartupProtection' 'managed startup protection IOCTL use'
Assert-Match $files.Protection 'RegisterProtectedProcess\(\);(?s:.*?)SetStartupProtection' 'startup state synchronized after guarded process registration'
Assert-Match $files.Protection 'TrySetStartupProtection\(bool\s+enabled\)(?s:.*?)lock\s*\(StateLock\)' 'serialized runtime startup state synchronization'
Assert-Match $files.Startup 'SynchronizeStartupProtection\(true\)(?s:.*?)SetValue' 'enable kernel protection before creating startup value'
Assert-Match $files.Startup 'IsStartupConfiguredForCurrentExecutable' 'current startup executable validation'
Assert-Match $files.Startup 'string\.Equals\(configuredPath,\s*currentPath,\s*StringComparison\.OrdinalIgnoreCase\)' 'startup path equality check'
Assert-Match $files.Startup 'EnsureCurrentStartupCommand\(\)(?s:.*?)EnableStartup\(\)' 'stale startup command repair'
Assert-Match $files.Startup 'SetValue(?s:.*?)SynchronizeStartupProtection\(true\)' 'enable state re-synchronized after creating startup value'
Assert-Match $files.Startup 'EnableStartup\(\)(?s:.*?)SetValue(?s:.*?)catch(?s:.*?)SynchronizeStartupProtection\(wasEnabled\)' 'enable failure kernel rollback'
Assert-Match $files.Startup 'DeleteValue(?s:.*?)SynchronizeStartupProtection\(false\)' 'disable value deletion before kernel protection disable'
Assert-Match $files.Startup 'SynchronizeStartupProtection\(false\)(?s:.*?)SetValue' 'disable synchronization failure registry rollback'
Assert-Match $files.App 'EnsureDefaultStartup\(\)(?s:.*?)EnsureCurrentStartupCommand\(\)' 'startup command validation on launch'

Write-Host "Managed startup self-protection source smoke passed."
