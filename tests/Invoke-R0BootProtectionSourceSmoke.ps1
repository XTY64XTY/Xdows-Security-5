param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$codeRoot = Split-Path -Parent $repoRoot

function Read-RequiredFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required source file missing: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw
}

function Assert-Match([string]$Text, [string]$Pattern, [string]$Label) {
    if ($Text -notmatch $Pattern) {
        throw "Missing R0 boot protection evidence: $Label"
    }
}

$files = @{
    Native = Read-RequiredFile (Join-Path $codeRoot 'Xdows-Security-Driver\Xdows-Security-BootFilter\Public.h')
    Managed = Read-RequiredFile (Join-Path $repoRoot 'Protection\BootFilterProtocol.cs')
    Client = Read-RequiredFile (Join-Path $repoRoot 'Protection\BootFilterClient.cs')
    MainNative = Read-RequiredFile (Join-Path $codeRoot 'Xdows-Security-Driver\Xdows-Security-Driver\Public.h')
    MainManaged = Read-RequiredFile (Join-Path $repoRoot 'Protection\DriverProtocol.cs')
    Bridge = Read-RequiredFile (Join-Path $repoRoot 'Protection\DriverBridgeClient.cs')
    Protection = Read-RequiredFile (Join-Path $repoRoot 'Protection\DriverProtection.cs')
    BootSnapshot = Read-RequiredFile (Join-Path $repoRoot 'Protection\LegacyBootProtection.cs')
    Installer = Read-RequiredFile (Join-Path $repoRoot 'Protection\DriverInstaller.cs')
    Locator = Read-RequiredFile (Join-Path $repoRoot 'Protection\DriverPackageLocator.cs')
    Project = Read-RequiredFile (Join-Path $repoRoot 'Xdows-Security\Xdows-Security.csproj')
    App = Read-RequiredFile (Join-Path $repoRoot 'Xdows-Security\App.xaml.cs')
}

Assert-Match $files.Native 'XDOWS_BOOT_PROTOCOL_VERSION\s+1u' 'native boot filter protocol version'
Assert-Match $files.Managed 'ProtocolVersion\s*=\s*1' 'managed boot filter protocol version'
Assert-Match $files.Native 'XDOWS_BOOT_DRIVER_BUILD_ID\s+2026072901ULL' 'native boot filter build identity'
Assert-Match $files.Managed 'DriverBuildId\s*=\s*2026072901' 'managed boot filter build identity'
Assert-Match $files.Native 'XDOWS_BOOT_MAX_REQUEST_BYTES\s*\(1u\s*\*\s*1024u\s*\*\s*1024u\)' 'native 1 MiB request limit'
Assert-Match $files.Managed 'MaxRequestBytes\s*=\s*1\s*\*\s*1024\s*\*\s*1024' 'managed 1 MiB request limit'
Assert-Match $files.Native 'XDOWS_BOOT_MAX_PENDING_BYTES\s*\(8u\s*\*\s*1024u\s*\*\s*1024u\)' 'native 8 MiB pending limit'
Assert-Match $files.Managed 'MaxPendingBytes\s*=\s*8\s*\*\s*1024\s*\*\s*1024' 'managed 8 MiB pending limit'
Assert-Match $files.Native 'XDOWS_BOOT_DECISION_TIMEOUT_MS\s+25000u' 'native 25-second decision timeout'
Assert-Match $files.Managed 'DecisionTimeoutMs\s*=\s*25_000' 'managed 25-second decision timeout'
Assert-Match $files.Client 'BootFilterProtocol\.Configure' 'raw region configuration IOCTL'
Assert-Match $files.Client 'BootFilterProtocol\.GetNextEvent' 'raw write event pump'
Assert-Match $files.Client 'BootFilterDecisionType\.Block' 'managed fail-closed decision'

Assert-Match $files.MainNative 'XDOWS_SECURITY_PROTOCOL_VERSION\s+8u' 'native main protocol v8'
Assert-Match $files.MainManaged 'ProtocolVersion\s*=\s*8' 'managed main protocol v8'
Assert-Match $files.MainNative 'XDOWS_SECURITY_CAP_R0_BOOT_PROTECTION\s+0x00000100u' 'native R0 boot capability'
Assert-Match $files.MainManaged 'CapabilityR0BootProtection\s*=\s*0x00000100' 'managed R0 boot capability'
Assert-Match $files.Bridge 'SetBootProtection\(BootDriverProtectionConfiguration' 'EFI and BCD configuration bridge'
Assert-Match $files.BootSnapshot 'CreateDriverConfiguration' 'system boot disk configuration factory'
Assert-Match $files.BootSnapshot 'CaptureInitialRawRegions' 'validated MBR and GPT ranges'
Assert-Match $files.BootSnapshot 'GetNtVolumeRoot' 'active boot volume NT mapping'

Assert-Match $files.Protection 'EnsureBootFilterInstalledAndStartedAsync' 'boot filter install/start integration'
Assert-Match $files.Protection 'HandleRawBootWriteAsync' 'raw boot write user decision'
Assert-Match $files.Protection 'HandleBootFileWriteAsync' 'EFI and BCD user decision'
Assert-Match $files.Protection 'ProtectionModule\.Boot' 'boot interception module'
Assert-Match $files.Protection 'DriverDecisionService\.AskUserAsync' '25-second serialized popup decision'
Assert-Match $files.App 'ProtectionModule\.Behavior\s+and\s+not\s+Helper\.ProtectionModule\.Boot' 'boot decisions bypass compact auto-block'

Assert-Match $files.Installer 'BootFilterLoadWorkflow' 'dedicated package workflow'
Assert-Match $files.Locator 'BootFilterServiceName\s*=\s*"Xdows-Security-BootFilter"' 'boot filter service identity'
Assert-Match $files.Locator 'Path\.Combine\(DriverDirectory,\s*"BootFilter"\)' 'isolated boot filter package directory'
Assert-Match $files.Project 'XdowsBootFilterProject' 'single-solution build integration'
Assert-Match $files.Project 'Driver\\BootFilter' 'output and publish package integration'

Write-Host 'R0 boot protection managed source smoke passed.'
