using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using TrustQuarantine;
using Helper;
using static Protection.CallBack;

namespace Protection;

public enum DriverProtectionRuntimeStatus
{
    NotInstalled,
    NotRunning,
    Loading,
    Protected,
    NeedsRepair,
    Error
}

public enum DriverProtectionLogSeverity
{
    Debug,
    Info,
    Warning,
    Error,
    Fatal
}

public sealed record DriverProtectionLogEntry(
    ulong EventId,
    ulong CorrelationId,
    DriverProtectionLogSeverity Severity,
    uint DroppedCount,
    DateTimeOffset Timestamp,
    string Module,
    string Message);

public enum DriverProcessOperation
{
    Suspend,
    Resume,
    Terminate
}

public sealed record DriverProcessInfo(
    uint ProcessId,
    uint ParentProcessId,
    uint SessionId,
    uint ThreadCount,
    uint HandleCount,
    uint BasePriority,
    ulong WorkingSetBytes,
    ulong PrivateBytes,
    string Name);

public sealed class DriverProtection : IProtectionModel
{
    private static readonly TimeSpan UserDecisionTimeout = TimeSpan.FromSeconds(25);

    private sealed record DecisionCacheEntry(
        XdowsSecurityDecisionType Decision,
        string Reason,
        DateTimeOffset ExpiresAt);
    private sealed record PendingQuarantine(
        ulong EventId,
        ulong CorrelationId,
        string Path,
        string DetectionName);

    private static readonly Lock StateLock = new();
    private static readonly ConcurrentDictionary<string, DecisionCacheEntry> DecisionCache = new(StringComparer.OrdinalIgnoreCase);
    // F1: Raised from 4 to 16. Pro model ScanFile takes ~480ms; with only 4
    // concurrent slots the limiter was exhausted by the FileCreate flood
    // (3357 events in 2 minutes), causing unrelated events to queue until
    // the 5s kernel timeout fired and blocked them.
    private static readonly int ScanWorkerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
    private static readonly SemaphoreSlim ScanLimiter = new(ScanWorkerCount, ScanWorkerCount);
    private static readonly ConcurrentDictionary<string, Lazy<Task<NativeModelScannerResult>>> InFlightScans = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<ulong, PendingQuarantine> _pendingQuarantines = new();

    private CancellationTokenSource? _cts;
    private Task? _pumpTask;
    private Task? _bootPumpTask;
    private Task? _logTask;
    private Task? _quarantineTask;
    private Channel<PendingQuarantine>? _quarantineChannel;
    private DriverBridgeClient? _client;
    private BootFilterClient? _bootClient;
    private NativeModelScanner? _scanner;
    private InterceptCallBack? _interceptCallBack;

    public const string DriverProtectionName = "Driver";
    public string Name => DriverProtectionName;

    public NativeModelScannerMode ModelMode { get; set; } = NativeModelScannerMode.Standard;

    public Func<ProtectionDecisionRequest, CancellationToken, Task<ProtectionUserDecision>>? DecisionCallback { get; set; }
    public Action<DriverProtectionLogEntry>? LogCallback { get; set; }
    public Func<bool>? StartupProtectionStateProvider { get; set; }

    private void Log(string module, string message)
    {
        LogCallback?.Invoke(new DriverProtectionLogEntry(
            0, 0, DriverProtectionLogSeverity.Info, 0, DateTimeOffset.Now, module, message));
    }

    private static bool HasRequiredModules(XdowsSecurityState state)
    {
        return (state.ActiveModules & DriverProtocol.RequiredModules) == DriverProtocol.RequiredModules;
    }

    private static bool HasRequiredCapabilities(XdowsSecurityState state)
    {
        return (state.Capabilities & DriverProtocol.RequiredCapabilities) ==
            DriverProtocol.RequiredCapabilities;
    }

    public static DriverProtectionRuntimeStatus QueryRuntimeStatus()
    {
        if (DriverBridgeClient.TryQueryStateWithoutRegister(out var state, out int error))
        {
            if (state.ClientConnected == 0)
                return DriverProtectionRuntimeStatus.NotRunning;

            return state.ProcessProtectionEnabled == 0 ||
                state.FileProtectionEnabled == 0 ||
                state.SelfProtectionEnabled == 0 ||
                state.ProtectedProcessId != (uint)Environment.ProcessId ||
                !HasRequiredModules(state) ||
                !HasRequiredCapabilities(state)
                ? DriverProtectionRuntimeStatus.NeedsRepair
                : DriverProtectionRuntimeStatus.Protected;
        }

        return error switch
        {
            2 or 3 => DriverProtectionRuntimeStatus.NotInstalled,
            5 or DriverBridgeClient.ErrorRevisionMismatch => DriverProtectionRuntimeStatus.NeedsRepair,
            _ => DriverProtectionRuntimeStatus.Error
        };
    }

    public bool Run(InterceptCallBack interceptCallBack)
    {
        lock (StateLock)
        {
            if (IsRun())
                return true;

            try
            {
                _interceptCallBack = interceptCallBack;
                _cts = new CancellationTokenSource();
                DriverRepairResult driverReady = DriverInstaller
                    .EnsureInstalledAndStartedAsync(_cts.Token)
                    .GetAwaiter()
                    .GetResult();
                if (!driverReady.Success)
                {
                    LogCallback?.Invoke(new DriverProtectionLogEntry(
                        0,
                        0,
                        DriverProtectionLogSeverity.Error,
                        0,
                        DateTimeOffset.Now,
                        "Installer",
                        driverReady.Message));
                    CleanupLocked();
                    return false;
                }

                DriverRepairResult bootFilterReady = DriverInstaller
                    .EnsureBootFilterInstalledAndStartedAsync(_cts.Token)
                    .GetAwaiter()
                    .GetResult();
                if (!bootFilterReady.Success)
                {
                    LogCallback?.Invoke(new DriverProtectionLogEntry(
                        0,
                        0,
                        DriverProtectionLogSeverity.Error,
                        0,
                        DateTimeOffset.Now,
                        "BootProtect",
                        bootFilterReady.Message));
                    CleanupLocked();
                    return false;
                }

                BootDriverProtectionConfiguration bootConfiguration =
                    BootProtectionSnapshotService.CreateDriverConfiguration();

                _client = new DriverBridgeClient();
                Log("Bridge", "Connecting DriverBridgeClient...");
                _client.Connect();
                XdowsSecurityState state = _client.GetState();
                Log("Bridge", $"DriverBridgeClient connected protocol={state.ProtocolVersion} build={state.DriverBuildId} capabilities=0x{state.Capabilities:X8} modules=0x{state.ActiveModules:X8} process={state.ProcessProtectionEnabled} file={state.FileProtectionEnabled}");
                if (state.ProcessProtectionEnabled == 0 ||
                    state.FileProtectionEnabled == 0 ||
                    !HasRequiredModules(state) ||
                    !HasRequiredCapabilities(state))
                {
                    throw new InvalidOperationException(
                        $"Required driver protection modules or capabilities are not active " +
                        $"(modules=0x{state.ActiveModules:X8}, requiredModules=0x{DriverProtocol.RequiredModules:X8}, " +
                        $"capabilities=0x{state.Capabilities:X8}, requiredCapabilities=0x{DriverProtocol.RequiredCapabilities:X8}, " +
                        $"process={state.ProcessProtectionEnabled}, file={state.FileProtectionEnabled}).");
                }

                _client.SetBootProtection(bootConfiguration);
                state = _client.GetState();
                if (state.BootProtectionEnabled == 0)
                    throw new InvalidOperationException("The main minifilter did not activate EFI and BCD protection.");

                _bootClient = new BootFilterClient();
                _bootClient.Connect();
                _bootClient.Configure(bootConfiguration);
                BootFilterState bootState = _bootClient.GetState();
                if (bootState.ClientConnected == 0 ||
                    bootState.Configured == 0 ||
                    bootState.Attached == 0 ||
                    bootState.DiskNumber != (uint)bootConfiguration.DiskIndex)
                {
                    throw new InvalidOperationException(
                        $"Boot filter state is incomplete " +
                        $"(connected={bootState.ClientConnected}, configured={bootState.Configured}, " +
                        $"attached={bootState.Attached}, disk={bootState.DiskNumber}, " +
                        $"expectedDisk={bootConfiguration.DiskIndex}).");
                }
                Log(
                    "BootProtect",
                    $"R0 boot protection attached PhysicalDrive{bootConfiguration.DiskIndex} " +
                    $"rawRanges={bootConfiguration.RawRegions.Count} volumes={bootConfiguration.NtVolumeRoots.Count}");

                Log("Scanner", $"Creating NativeModelScanner mode={ModelMode}");
                _scanner = new NativeModelScanner(ModelMode);
                Log("Scanner", $"NativeModelScanner created, NativeReady={_scanner.NativeReady}, Mode={_scanner.Mode}");
                if (!_scanner.NativeReady)
                {
                    throw new InvalidOperationException(
                        $"Native model initialization failed: {_scanner.InitializationError ?? "unknown"}.");
                }

                _client.RegisterProtectedProcess();
                state = _client.GetState();
                Log("Bridge", $"Self-protection registered active={state.SelfProtectionEnabled} protectedPid={state.ProtectedProcessId} expectedPid={Environment.ProcessId}");
                if (state.SelfProtectionEnabled == 0 ||
                    state.ProtectedProcessId != (uint)Environment.ProcessId)
                {
                    throw new InvalidOperationException(
                        $"Driver self-protection did not activate for the current process (active={state.SelfProtectionEnabled}, protectedPid={state.ProtectedProcessId}, expectedPid={Environment.ProcessId}).");
                }

                bool startupProtectionEnabled = StartupProtectionStateProvider?.Invoke() == true;
                _client.SetStartupProtection(startupProtectionEnabled);
                state = _client.GetState();
                if ((state.StartupProtectionEnabled != 0) != startupProtectionEnabled)
                {
                    throw new InvalidOperationException(
                        $"Driver startup self-protection state mismatch " +
                        $"(active={state.StartupProtectionEnabled}, expected={startupProtectionEnabled}).");
                }
                Log("Bridge", $"Startup self-protection synchronized active={state.StartupProtectionEnabled}");

                DriverBridgeClient client = _client;
                _quarantineChannel = Channel.CreateBounded<PendingQuarantine>(new BoundedChannelOptions(32)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });
                _quarantineTask = Task.Run(() => RunQuarantinePumpAsync(_quarantineChannel.Reader, _cts.Token));
                _pumpTask = Task.Run(() => client.RunEventPumpAsync(
                    HandleDriverEventAsync,
                    QueuePostDecisionWorkAsync,
                    _cts.Token));
                BootFilterClient bootClient = _bootClient;
                _bootPumpTask = Task.Run(() => bootClient.RunEventPumpAsync(
                    HandleRawBootWriteAsync,
                    _cts.Token));
                _logTask = Task.Run(() => RunLogPumpAsync(client, _cts.Token));
                Log("Bridge", "Event pump and log pump started");
                return true;
            }
            catch (Exception ex)
            {
                Log("Bridge", $"Driver protection start failed: {ex}");
                try
                {
                    if (DriverBridgeClient.TryQueryStateWithoutRegister(out var driverState, out _))
                    {
                        Log("Bridge", $"Runtime driver reports headerSize={driverState.Header.Size} headerVersion={driverState.Header.Version} protocolVersion={driverState.ProtocolVersion} buildId={driverState.DriverBuildId} modules=0x{driverState.ActiveModules:X8} process={driverState.ProcessProtectionEnabled} file={driverState.FileProtectionEnabled}; client expects protocolVersion={DriverProtocol.ProtocolVersion} buildId={DriverProtocol.DriverBuildId}");
                    }
                    else
                    {
                        Log("Bridge", "Unable to query runtime driver state after connection failure.");
                    }
                }
                catch (Exception diagEx)
                {
                    Log("Bridge", $"State query after failure also failed: {diagEx.Message}");
                }
                CleanupLocked();
                return false;
            }
        }
    }

    public bool Stop()
    {
        lock (StateLock)
        {
            if (_cts is null)
                return true;

            bool shutdownAuthorized = false;
            try
            {
                shutdownAuthorized = _client?.SubmitAuthorizedShutdown() == true;
                if (!shutdownAuthorized)
                {
                    Log("Bridge", "Driver stop denied because shutdown token authorization failed.");
                    return false;
                }

                _cts?.Cancel();
                CleanupLocked();

                DriverServiceOperationResult bootStop = DriverServiceControl.Stop(
                    DriverPackageLocator.BootFilterServiceName);
                DriverServiceOperationResult stop = DriverServiceControl.Stop(DriverPackageLocator.ServiceName);
                if (!stop.Success || !bootStop.Success)
                {
                    Log("Bridge", $"Authorized driver stop failed: main={stop.Message}; boot={bootStop.Message}");
                    if (!stop.Success)
                        RelockDriverUnloadAfterFailedStop();
                    return false;
                }

                Log("Bridge", $"Authorized driver stop accepted: main={stop.Message}; boot={bootStop.Message}");
                return true;
            }
            catch (Exception ex)
            {
                Log("Bridge", $"Driver stop failed: {ex.Message}");
                if (shutdownAuthorized)
                {
                    CleanupLocked();
                    RelockDriverUnloadAfterFailedStop();
                }
                return false;
            }
        }
    }

    private void RelockDriverUnloadAfterFailedStop()
    {
        try
        {
            using var relockClient = new DriverBridgeClient();
            relockClient.Connect();
            Log("Bridge", "Driver unload relocked after failed SCM stop.");
        }
        catch (Exception ex)
        {
            Log("Bridge", $"CRITICAL: failed to relock driver unload after SCM stop failure: {ex.Message}");
        }
    }

    public bool IsRun()
    {
        return _cts is { IsCancellationRequested: false } &&
            _client is { IsConnected: true } &&
            _bootClient is { IsConnected: true };
    }

    public bool TrySetVoluntaryExit(bool isVoluntaryExit)
    {
        try
        {
            _client?.SetVoluntaryExit(isVoluntaryExit);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void CleanupLocked()
    {
        _quarantineChannel?.Writer.TryComplete();
        _pendingQuarantines.Clear();

        try
        {
            _client?.Disconnect();
        }
        catch
        {
        }

        _client?.Dispose();
        _client = null;

        try
        {
            _bootClient?.Disconnect();
        }
        catch
        {
        }
        _bootClient?.Dispose();
        _bootClient = null;

        _scanner?.Dispose();
        _scanner = null;

        _cts?.Dispose();
        _cts = null;
        _pumpTask = null;
        _bootPumpTask = null;
        _logTask = null;
        _quarantineTask = null;
        _quarantineChannel = null;
        _interceptCallBack = null;
    }

    public IReadOnlyList<DriverProcessInfo> GetProcesses()
    {
        lock (StateLock)
        {
            DriverBridgeClient client = GetRunningClient();
            return client.QueryProcesses()
                .Select(entry => new DriverProcessInfo(
                    entry.ProcessId,
                    entry.ParentProcessId,
                    entry.SessionId,
                    entry.ThreadCount,
                    entry.HandleCount,
                    entry.BasePriority,
                    entry.WorkingSetBytes,
                    entry.PrivateBytes,
                    entry.ImageName ?? string.Empty))
                .ToArray();
        }
    }

    public void OperateProcess(uint processId, DriverProcessOperation operation)
    {
        lock (StateLock)
        {
            DriverBridgeClient client = GetRunningClient();
            XdowsSecurityProcessOperation driverOperation = operation switch
            {
                DriverProcessOperation.Suspend => XdowsSecurityProcessOperation.Suspend,
                DriverProcessOperation.Resume => XdowsSecurityProcessOperation.Resume,
                DriverProcessOperation.Terminate => XdowsSecurityProcessOperation.Terminate,
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };

            client.OperateProcess(processId, driverOperation);
        }
    }

    private DriverBridgeClient GetRunningClient()
    {
        if (!IsRun() || _client is not { IsConnected: true } client)
            throw new InvalidOperationException("Driver protection must be running before using driver process management.");

        return client;
    }

    private void QueueQuarantineAfterBlock(
        XdowsSecurityEvent driverEvent,
        string path,
        string detectionName)
    {
        _pendingQuarantines[driverEvent.EventId] = new PendingQuarantine(
            driverEvent.EventId,
            driverEvent.CorrelationId,
            path,
            detectionName);
    }

    private async ValueTask QueuePostDecisionWorkAsync(
        XdowsSecurityEvent driverEvent,
        XdowsSecurityDecision decision,
        CancellationToken token)
    {
        if (decision.Decision == (uint)XdowsSecurityDecisionType.Block)
        {
            LogCallback?.Invoke(new DriverProtectionLogEntry(
                driverEvent.EventId,
                driverEvent.CorrelationId,
                DriverProtectionLogSeverity.Info,
                0,
                DateTimeOffset.Now,
                "Decision",
                "Block decision submitted to kernel."));
        }

        if (!_pendingQuarantines.TryRemove(driverEvent.EventId, out PendingQuarantine? pending) ||
            decision.Decision != (uint)XdowsSecurityDecisionType.Block)
        {
            return;
        }

        Channel<PendingQuarantine>? channel = _quarantineChannel;
        if (channel is null)
            return;

        await channel.Writer.WriteAsync(pending, token).ConfigureAwait(false);
    }

    private async Task RunQuarantinePumpAsync(
        ChannelReader<PendingQuarantine> reader,
        CancellationToken token)
    {
        try
        {
            await foreach (PendingQuarantine pending in reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                bool quarantineSucceeded = await QuarantineManager
                    .AddToQuarantine(pending.Path, pending.DetectionName)
                    .ConfigureAwait(false);
                LogCallback?.Invoke(new DriverProtectionLogEntry(
                    pending.EventId,
                    pending.CorrelationId,
                    quarantineSucceeded ? DriverProtectionLogSeverity.Info : DriverProtectionLogSeverity.Error,
                    0,
                    DateTimeOffset.Now,
                    "Quarantine",
                    quarantineSucceeded
                        ? $"Blocked threat quarantined: {pending.Path}"
                        : $"Blocked threat could not be quarantined: {pending.Path}"));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
    }

    public bool TrySetStartupProtection(bool enabled)
    {
        lock (StateLock)
        {
            if (!IsRun() || _client is null)
                return true;

            try
            {
                _client.SetStartupProtection(enabled);
                XdowsSecurityState state = _client.GetState();
                bool synchronized = (state.StartupProtectionEnabled != 0) == enabled;
                if (!synchronized)
                {
                    Log("Bridge", $"Startup self-protection state mismatch active={state.StartupProtectionEnabled} expected={enabled}");
                }
                return synchronized;
            }
            catch (Exception ex)
            {
                Log("Bridge", $"Failed to synchronize startup self-protection: {ex.Message}");
                return false;
            }
        }
    }

    private async Task RunLogPumpAsync(DriverBridgeClient client, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                if (client.TryGetNextLog(out XdowsDriverLogEntry entry))
                {
                    LogCallback?.Invoke(ConvertLogEntry(entry));
                    continue;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                LogCallback?.Invoke(new DriverProtectionLogEntry(
                    0,
                    0,
                    DriverProtectionLogSeverity.Warning,
                    0,
                    DateTimeOffset.Now,
                    "Bridge",
                    $"Driver log polling failed: {ex.GetType().Name}"));
            }

            await Task.Delay(500, token).ConfigureAwait(false);
        }
    }

    private static DriverProtectionLogEntry ConvertLogEntry(XdowsDriverLogEntry entry)
    {
        DateTimeOffset timestamp;
        try
        {
            timestamp = DateTimeOffset.FromFileTime(entry.Timestamp);
        }
        catch
        {
            timestamp = DateTimeOffset.Now;
        }

        return new DriverProtectionLogEntry(
            entry.EventId,
            entry.CorrelationId,
            MapLogSeverity(entry.Severity),
            entry.DroppedCount,
            timestamp,
            CleanDriverString(entry.Module),
            CleanDriverString(entry.Message));
    }

    private static DriverProtectionLogSeverity MapLogSeverity(uint severity)
    {
        return severity switch
        {
            0 => DriverProtectionLogSeverity.Debug,
            1 => DriverProtectionLogSeverity.Info,
            2 => DriverProtectionLogSeverity.Warning,
            3 => DriverProtectionLogSeverity.Error,
            4 => DriverProtectionLogSeverity.Fatal,
            _ => DriverProtectionLogSeverity.Info
        };
    }

    private async Task<XdowsSecurityDecision> HandleDriverEventAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        return (XdowsSecurityEventType)driverEvent.EventType switch
        {
            XdowsSecurityEventType.ProcessCreate => await HandleProcessCreateAsync(driverEvent, token).ConfigureAwait(false),
            XdowsSecurityEventType.FileCreate or
                XdowsSecurityEventType.FileWrite or
                XdowsSecurityEventType.FileRename => await HandleFileEventAsync(driverEvent, token).ConfigureAwait(false),
            XdowsSecurityEventType.ProcessHandle or
                XdowsSecurityEventType.ThreadHandle or
                XdowsSecurityEventType.ImageLoad => await HandleSensitiveOperationAsync(driverEvent, token).ConfigureAwait(false),
            XdowsSecurityEventType.Behavior => await HandleBehaviorEventAsync(driverEvent, token).ConfigureAwait(false),
            XdowsSecurityEventType.BootWrite => await HandleBootFileWriteAsync(driverEvent, token).ConfigureAwait(false),
            _ => DriverBridgeClient.CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Allow, "unsupported-event")
        };
    }

    private async Task<XdowsSecurityDecision> HandleBootFileWriteAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!TryEnterUserDecisionHold(driverEvent))
        {
            return DriverBridgeClient.CreateDecision(
                driverEvent.EventId,
                XdowsSecurityDecisionType.Block,
                "boot-file-user-hold-failed-block");
        }

        string path = DriverPathNormalizer.Normalize(CleanDriverString(driverEvent.ImagePath));
        string? actorPath = ResolveActorPath(driverEvent);
        var request = new ProtectionDecisionRequest(
            string.IsNullOrWhiteSpace(path) ? "EFI/BCD" : path,
            "Boot",
            "Xdows.R0.BootFileWrite",
            100,
            checked((int)driverEvent.ProcessId),
            checked((int)driverEvent.ParentProcessId),
            null,
            actorPath,
            EventId: driverEvent.EventId,
            CorrelationId: driverEvent.CorrelationId,
            Module: ProtectionModule.Boot,
            Backend: ProtectionBackend.Driver,
            DecisionDeadline: DateTimeOffset.UtcNow.Add(UserDecisionTimeout));
        ProtectionUserDecision userDecision = await AskUserAfterHoldAsync(
            request,
            driverEvent,
            token).ConfigureAwait(false);

        return userDecision == ProtectionUserDecision.Allow
            ? Allow(driverEvent.EventId, "user-release-boot-file")
            : DriverBridgeClient.CreateDecision(
                driverEvent.EventId,
                XdowsSecurityDecisionType.Block,
                userDecision == ProtectionUserDecision.Timeout
                    ? "boot-file-user-timeout-block"
                    : "user-block-boot-file");
    }

    private async Task<BootFilterDecisionType> HandleRawBootWriteAsync(
        BootFilterWriteEvent writeEvent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        DateTimeOffset deadline = DateTimeOffset.UtcNow.Add(UserDecisionTimeout);
        string path = $"PhysicalDrive{writeEvent.DiskNumber} @ 0x{writeEvent.Offset:X} (+{writeEvent.Length} bytes)";
        string? actorPath = writeEvent.ProcessId == 0
            ? null
            : DriverPathNormalizer.Normalize(SignerTrustService.TryResolveProcessPath(writeEvent.ProcessId));
        var request = new ProtectionDecisionRequest(
            path,
            "Boot",
            "Xdows.R0.RawBootWrite",
            100,
            checked((int)writeEvent.ProcessId),
            0,
            null,
            actorPath,
            EventId: writeEvent.EventId,
            CorrelationId: writeEvent.EventId,
            Module: ProtectionModule.Boot,
            Backend: ProtectionBackend.Driver,
            DecisionDeadline: deadline);

        LogCallback?.Invoke(new DriverProtectionLogEntry(
            writeEvent.EventId,
            writeEvent.EventId,
            DriverProtectionLogSeverity.Warning,
            0,
            DateTimeOffset.Now,
            "BootProtect",
            $"Raw boot write blocked pending user decision: {path}"));

        if (DecisionCallback is null)
            return BootFilterDecisionType.Block;

        ProtectionUserDecision decision = await DriverDecisionService.AskUserAsync(
            callbackToken => DecisionCallback(request, callbackToken),
            deadline - DateTimeOffset.UtcNow,
            token).ConfigureAwait(false);
        return decision == ProtectionUserDecision.Allow
            ? BootFilterDecisionType.Allow
            : BootFilterDecisionType.Block;
    }

    private async Task<XdowsSecurityDecision> HandleBehaviorEventAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!TryEnterUserDecisionHold(driverEvent))
        {
            return DriverBridgeClient.CreateDecision(
                driverEvent.EventId,
                XdowsSecurityDecisionType.Block,
                "behavior-user-hold-failed-block");
        }

        XdowsSecurityBehaviorType behaviorType = (XdowsSecurityBehaviorType)driverEvent.BehaviorType;
        string imagePath = DriverPathNormalizer.Normalize(CleanDriverString(driverEvent.ImagePath));
        string actorPath = ResolveActorPath(driverEvent) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(imagePath) && driverEvent.ProcessId != 0)
        {
            imagePath = DriverPathNormalizer.Normalize(
                SignerTrustService.TryResolveProcessPath(driverEvent.ProcessId));
        }
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            imagePath = !string.IsNullOrWhiteSpace(actorPath)
                ? actorPath
                : $"PID {driverEvent.ProcessId}";
        }

        DateTimeOffset decisionDeadline = DateTimeOffset.UtcNow.Add(UserDecisionTimeout);
        var request = new ProtectionDecisionRequest(
            imagePath,
            "Behavior",
            BehaviorTypeToDetectionName(behaviorType),
            100,
            checked((int)driverEvent.ProcessId),
            checked((int)driverEvent.ParentProcessId),
            CleanDriverString(driverEvent.CommandLine),
            string.IsNullOrWhiteSpace(actorPath) ? null : actorPath,
            EventId: driverEvent.EventId,
            CorrelationId: driverEvent.CorrelationId,
            Module: ProtectionModule.Behavior,
            Backend: ProtectionBackend.Driver,
            DecisionDeadline: decisionDeadline);

        ProtectionUserDecision userDecision = await AskUserAfterHoldAsync(
            request,
            driverEvent,
            token).ConfigureAwait(false);

        if (userDecision == ProtectionUserDecision.Allow)
            return Allow(driverEvent.EventId, "user-release-behavior");

        string reason = userDecision == ProtectionUserDecision.Timeout
            ? "behavior-user-timeout-block"
            : "user-block-behavior";
        return DriverBridgeClient.CreateDecision(
            driverEvent.EventId,
            XdowsSecurityDecisionType.Block,
            reason);
    }

    private async Task<XdowsSecurityDecision> HandleProcessCreateAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        string imagePath = DriverPathNormalizer.Normalize(CleanDriverString(driverEvent.ImagePath));
        string commandLine = CleanDriverString(driverEvent.CommandLine);

        if (string.IsNullOrWhiteSpace(imagePath))
            return Allow(driverEvent.EventId, "empty-image-path");

        if (TrustManager.IsPathTrusted(imagePath))
            return Allow(driverEvent.EventId, "trusted-path", TimeSpan.FromMinutes(10));

        CleanupDecisionCache();
        string processCacheKey = BuildDecisionCacheKey("process", imagePath);

        if (DecisionCache.TryGetValue(processCacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason);
        }

        await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
        NativeModelScannerResult scan;
        try
        {
            // F3: Re-check cache after acquiring limiter; another thread may have
            // scanned the same image while we were queued.
            if (DecisionCache.TryGetValue(processCacheKey, out var cachedAfterWait) &&
                cachedAfterWait.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return DriverBridgeClient.CreateDecision(driverEvent.EventId, cachedAfterWait.Decision, cachedAfterWait.Reason);
            }

            Log("Scan", $"ProcessCreate scanning: {imagePath}");
            long scanStarted = Stopwatch.GetTimestamp();
            scan = await ScanSingleFlightAsync(imagePath, token).ConfigureAwait(false);
            Log("Scan", $"ProcessCreate result: IsThreat={scan.IsThreat} Prob={scan.Probability} Error={scan.ErrorMessage ?? "(none)"} Native={scan.UsedNativeEngine} ElapsedMs={Stopwatch.GetElapsedTime(scanStarted).TotalMilliseconds:F1}");
        }
        finally
        {
            ScanLimiter.Release();
        }

        // AskUser outside ScanLimiter to avoid deadlock: holding the limiter
        // during a 25s popup would exhaust the worker slots and block all other
        // scans, causing driver timeouts and system lockup.
        if (!string.IsNullOrWhiteSpace(scan.ErrorMessage))
        {
            // Extraction/runtime failures are infrastructure failures, not
            // confirmed threats. Fail open briefly and keep the error in the
            // diagnostic log; presenting a synthetic threat here causes every
            // unsupported or temporarily inaccessible file to be reported.
            Log("Scan", $"ProcessCreate model infrastructure error, allowing briefly: {scan.ErrorMessage}");
            Cache(processCacheKey, XdowsSecurityDecisionType.Allow, "model-infrastructure-error-allow", TimeSpan.FromSeconds(30));
            return Allow(driverEvent.EventId, "model-infrastructure-error-allow");
        }

        if (!scan.IsThreat)
        {
            Cache(processCacheKey, XdowsSecurityDecisionType.Allow, "model-safe", TimeSpan.FromMinutes(10));
            return Allow(driverEvent.EventId, "model-safe", TimeSpan.FromMinutes(1));
        }

        ProtectionUserDecision userDecision = await AskUserForThreatDecisionAsync(
            imagePath,
            commandLine,
            driverEvent,
            scan,
            actorPath: ResolveActorPath(driverEvent),
            actorTrust: null,
            actorScan: null,
            token).ConfigureAwait(false);

        if (userDecision == ProtectionUserDecision.Allow)
        {
            Cache(processCacheKey, XdowsSecurityDecisionType.Allow, "user-release", TimeSpan.FromMinutes(5));
            return Allow(driverEvent.EventId, "user-release", TimeSpan.FromMinutes(5));
        }

        XdowsSecurityDecisionType decisionType = XdowsSecurityDecisionType.Block;
        string reason = userDecision == ProtectionUserDecision.Timeout
            ? "confirmed-threat-user-timeout-block"
            : "user-block-threat";
        string detectionName = string.IsNullOrWhiteSpace(scan.DetectionName)
            ? "Xdows.Model.ProcessThreat"
            : scan.DetectionName;
        QueueQuarantineAfterBlock(driverEvent, imagePath, detectionName);

        // Do not cache an interactive block. Each later execution attempt must
        // surface a fresh interception prompt instead of being blocked silently.
        return DriverBridgeClient.CreateDecision(driverEvent.EventId, decisionType, reason);
    }

    private async Task<XdowsSecurityDecision> HandleFileEventAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        string filePath = DriverPathNormalizer.Normalize(CleanDriverString(driverEvent.ImagePath));
        if (string.IsNullOrWhiteSpace(filePath))
            return Allow(driverEvent.EventId, "empty-file-path");

        if (!File.Exists(filePath))
            return Allow(driverEvent.EventId, "file-missing");

        if (TrustManager.IsPathTrusted(filePath))
            return Allow(driverEvent.EventId, "trusted-file", TimeSpan.FromMinutes(10));

        string cacheKey = BuildDecisionCacheKey(driverEvent.EventType.ToString(), filePath);
        CleanupDecisionCache();
        if (DecisionCache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason);
        }

        await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
        NativeModelScannerResult scan;
        string? actorPath;
        SignerTrustResult? actorTrust;
        NativeModelScannerResult? actorScan;
        try
        {
            // F3: Re-check cache after acquiring limiter; another thread may have
            // scanned the same file while we were queued.
            if (DecisionCache.TryGetValue(cacheKey, out var cachedAfterWait) &&
                cachedAfterWait.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return DriverBridgeClient.CreateDecision(driverEvent.EventId, cachedAfterWait.Decision, cachedAfterWait.Reason);
            }

            Log("Scan", $"FileEvent scanning: {filePath}");
            long scanStarted = Stopwatch.GetTimestamp();
            scan = await ScanSingleFlightAsync(filePath, token).ConfigureAwait(false);
            Log("Scan", $"FileEvent result: IsThreat={scan.IsThreat} Prob={scan.Probability} Error={scan.ErrorMessage ?? "(none)"} Native={scan.UsedNativeEngine} ElapsedMs={Stopwatch.GetElapsedTime(scanStarted).TotalMilliseconds:F1}");

            if (!string.IsNullOrWhiteSpace(scan.ErrorMessage))
            {
                Cache(cacheKey, XdowsSecurityDecisionType.Allow, "model-error", TimeSpan.FromSeconds(5));
                return Allow(driverEvent.EventId, "model-error:" + scan.ErrorMessage);
            }

            if (!scan.IsThreat)
            {
                Cache(cacheKey, XdowsSecurityDecisionType.Allow, "model-safe", TimeSpan.FromMinutes(10));
                return Allow(driverEvent.EventId, "model-safe", TimeSpan.FromMinutes(1));
            }

            actorPath = ResolveActorPath(driverEvent);
            actorTrust = SignerTrustService.Evaluate(actorPath);
            actorScan = null;
            if (actorTrust is { IsTrusted: false } &&
                !string.IsNullOrWhiteSpace(actorPath) &&
                File.Exists(actorPath) &&
                !string.Equals(actorPath, filePath, StringComparison.OrdinalIgnoreCase))
            {
                Log("Scan", $"SensitiveOp scanning actor: {actorPath}");
                actorScan = await ScanSingleFlightAsync(actorPath, token).ConfigureAwait(false);
                Log("Scan", $"SensitiveOp actor result: IsThreat={actorScan.IsThreat} Prob={actorScan.Probability} Error={actorScan.ErrorMessage ?? "(none)"} Native={actorScan.UsedNativeEngine}");
            }
        }
        finally
        {
            ScanLimiter.Release();
        }

        // AskUser outside ScanLimiter to avoid deadlock: holding the limiter
        // during a 25s popup would exhaust the worker slots and block all other
        // scans, causing driver timeouts and system lockup.
        ProtectionUserDecision userDecision = await AskUserForThreatDecisionAsync(
            filePath,
            string.Empty,
            driverEvent,
            scan,
            actorPath,
            actorTrust,
            actorScan,
            token).ConfigureAwait(false);

        if (userDecision == ProtectionUserDecision.Allow)
        {
            Cache(cacheKey, XdowsSecurityDecisionType.Allow, "user-release", TimeSpan.FromMinutes(5));
            return Allow(driverEvent.EventId, "user-release", TimeSpan.FromMinutes(5));
        }

        string detectionName = string.IsNullOrWhiteSpace(scan.DetectionName)
            ? "Xdows.Model.FileThreat"
            : scan.DetectionName;
        QueueQuarantineAfterBlock(driverEvent, filePath, detectionName);

        XdowsSecurityDecisionType decisionType = XdowsSecurityDecisionType.Block;
        string reason = userDecision == ProtectionUserDecision.Timeout
            ? "confirmed-file-threat-user-timeout-block"
            : "user-block-file-threat";
        Cache(cacheKey, decisionType, reason, TimeSpan.FromSeconds(10));
        return DriverBridgeClient.CreateDecision(driverEvent.EventId, decisionType, reason);
    }

    private Task<XdowsSecurityDecision> HandleSensitiveOperationAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string actorPath = ResolveActorPath(driverEvent) ?? string.Empty;
        string targetPath = CleanDriverString(driverEvent.ImagePath);
        string cacheKey = $"{driverEvent.EventType}:{actorPath}:{targetPath}:{driverEvent.ProcessId}";

        CleanupDecisionCache();
        if (DecisionCache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return Task.FromResult(DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason));
        }

        // The current policy allows both trusted and untrusted sensitive
        // operations. Avoid expensive Authenticode chain construction here:
        // it cannot change the verdict and regularly exceeds the driver's
        // 500 ms synchronous consultation budget during handle-event floods.
        Cache(cacheKey, XdowsSecurityDecisionType.Allow, "sensitive-op-fast-allow", TimeSpan.FromMinutes(5));
        return Task.FromResult(Allow(driverEvent.EventId, "sensitive-op-fast-allow", TimeSpan.FromMinutes(5)));
    }

    private async Task<ProtectionUserDecision> AskUserForThreatDecisionAsync(
        string imagePath,
        string commandLine,
        XdowsSecurityEvent driverEvent,
        NativeModelScannerResult scan,
        string? actorPath,
        SignerTrustResult? actorTrust,
        NativeModelScannerResult? actorScan,
        CancellationToken token)
    {
        if (!TryEnterUserDecisionHold(driverEvent))
            return ProtectionUserDecision.Block;

        string protectionType = DriverEventTypeToProtectionType((XdowsSecurityEventType)driverEvent.EventType);
        DateTimeOffset decisionDeadline = DateTimeOffset.UtcNow.Add(UserDecisionTimeout);
        var request = new ProtectionDecisionRequest(
            imagePath,
            protectionType,
            string.IsNullOrWhiteSpace(scan.DetectionName) ? "Xdows.Model.Threat" : scan.DetectionName,
            scan.Probability,
            checked((int)driverEvent.ProcessId),
            checked((int)driverEvent.ParentProcessId),
            string.IsNullOrWhiteSpace(commandLine) ? null : commandLine,
            actorPath,
            actorTrust?.Reason,
            driverEvent.EventId,
            driverEvent.CorrelationId,
            actorScan?.DetectionName,
            actorScan?.Probability ?? 0,
            DriverEventTypeToModule((XdowsSecurityEventType)driverEvent.EventType),
            ProtectionBackend.Driver,
            decisionDeadline);

        return await AskUserAfterHoldAsync(request, driverEvent, token).ConfigureAwait(false);
    }

    private bool TryEnterUserDecisionHold(XdowsSecurityEvent driverEvent)
    {
        DriverBridgeClient? client = _client;
        if (client is null)
            return false;

        try
        {
            client.SubmitPendingDecision(driverEvent.EventId);
            return true;
        }
        catch (Exception ex)
        {
            LogCallback?.Invoke(new DriverProtectionLogEntry(
                driverEvent.EventId,
                driverEvent.CorrelationId,
                DriverProtectionLogSeverity.Error,
                0,
                DateTimeOffset.Now,
                "Decision",
                $"Confirmed threat could not enter user-decision hold; blocking immediately: {ex.GetType().Name}"));
            return false;
        }
    }

    private async Task<ProtectionUserDecision> AskUserAfterHoldAsync(
        ProtectionDecisionRequest request,
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        if (DecisionCallback is not null)
        {
            ProtectionUserDecision decision = await DriverDecisionService.AskUserAsync(
                callbackToken => DecisionCallback(request, callbackToken),
                request.DecisionDeadline - DateTimeOffset.UtcNow,
                token).ConfigureAwait(false);
            if (decision == ProtectionUserDecision.Timeout)
            {
                LogCallback?.Invoke(new DriverProtectionLogEntry(
                    driverEvent.EventId,
                    driverEvent.CorrelationId,
                    DriverProtectionLogSeverity.Warning,
                    0,
                    DateTimeOffset.Now,
                    "Decision",
                    $"user-decision-timeout-blocked module={request.Module} path={request.Path}"));
            }
            return decision;
        }

        _interceptCallBack?.Invoke(new ProtectionInterceptEvent(
            request.Path,
            true,
            request.DetectionName,
            request.Probability,
            request.Module,
            request.Backend));
        return ProtectionUserDecision.Block;
    }

    private static XdowsSecurityDecision Allow(ulong eventId, string reason, TimeSpan? ttl = null)
    {
        uint cacheTtlMs = ttl is null ? 0 : checked((uint)ttl.Value.TotalMilliseconds);
        return DriverBridgeClient.CreateDecision(eventId, XdowsSecurityDecisionType.Allow, reason, cacheTtlMs);
    }

    private static void Cache(
        string imagePath,
        XdowsSecurityDecisionType decision,
        string reason,
        TimeSpan ttl)
    {
        if (DecisionCache.Count >= 4096)
        {
            foreach (string key in DecisionCache
                .OrderBy(entry => entry.Value.ExpiresAt)
                .Take(256)
                .Select(entry => entry.Key))
            {
                DecisionCache.TryRemove(key, out _);
            }
        }
        DecisionCache[imagePath] = new DecisionCacheEntry(decision, reason, DateTimeOffset.UtcNow.Add(ttl));
    }

    private static void CleanupDecisionCache()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (var entry in DecisionCache)
        {
            if (entry.Value.ExpiresAt <= now)
                DecisionCache.TryRemove(entry.Key, out _);
        }
    }

    private static string BuildDecisionCacheKey(string prefix, string path)
    {
        try
        {
            return $"{prefix}:{DriverPathNormalizer.GetStableFileIdentity(path)}";
        }
        catch
        {
            return $"{prefix}:{path}";
        }
    }

    private async Task<NativeModelScannerResult> ScanSingleFlightAsync(string path, CancellationToken token)
    {
        string key = $"{ModelMode}:{path}";
        Lazy<Task<NativeModelScannerResult>> lazy = InFlightScans.GetOrAdd(
            key,
            _ => new Lazy<Task<NativeModelScannerResult>>(
                () => Task.Run(() => (_scanner ?? new NativeModelScanner(ModelMode)).ScanFile(path), token),
                LazyThreadSafetyMode.ExecutionAndPublication));
        try
        {
            return await lazy.Value.WaitAsync(token).ConfigureAwait(false);
        }
        finally
        {
            InFlightScans.TryRemove(new KeyValuePair<string, Lazy<Task<NativeModelScannerResult>>>(key, lazy));
        }
    }

    private static string? ResolveActorPath(XdowsSecurityEvent driverEvent)
    {
        string actorPath = DriverPathNormalizer.Normalize(CleanDriverString(driverEvent.ActorImagePath));
        if (!string.IsNullOrWhiteSpace(actorPath))
            return actorPath;

        if (driverEvent.CreatingProcessId != 0)
            return SignerTrustService.TryResolveProcessPath(driverEvent.CreatingProcessId);

        if (driverEvent.ProcessId != 0)
            return SignerTrustService.TryResolveProcessPath(driverEvent.ProcessId);

        return null;
    }

    private static string DriverEventTypeToProtectionType(XdowsSecurityEventType type)
    {
        return type switch
        {
            XdowsSecurityEventType.ProcessCreate => "Process",
            XdowsSecurityEventType.FileCreate => "FileCreate",
            XdowsSecurityEventType.FileWrite => "FileWrite",
            XdowsSecurityEventType.FileRename => "FileRename",
            XdowsSecurityEventType.ProcessHandle => "ProcessHandle",
            XdowsSecurityEventType.ThreadHandle => "ThreadHandle",
            XdowsSecurityEventType.ImageLoad => "ImageLoad",
            XdowsSecurityEventType.Behavior => "Behavior",
            _ => "Driver"
        };
    }

    private static string BehaviorTypeToDetectionName(XdowsSecurityBehaviorType type)
    {
        return type switch
        {
            XdowsSecurityBehaviorType.VssDeletion => "Xdows.Behavior.ShadowCopyDestruction",
            XdowsSecurityBehaviorType.HiddenPowerShell => "Xdows.Behavior.HiddenPowerShell",
            XdowsSecurityBehaviorType.EncodedCommand => "Xdows.Behavior.EncodedCommand",
            XdowsSecurityBehaviorType.PolicyBypass => "Xdows.Behavior.PolicyBypass",
            XdowsSecurityBehaviorType.DownloadExecute => "Xdows.Behavior.DownloadExecute",
            XdowsSecurityBehaviorType.LolbinAbuse => "Xdows.Behavior.LolbinAbuse",
            XdowsSecurityBehaviorType.ProcessInjection => "Xdows.Behavior.ProcessInjection",
            XdowsSecurityBehaviorType.ThreadInjection => "Xdows.Behavior.ThreadInjection",
            _ => "Xdows.Behavior.Unknown"
        };
    }

    private static ProtectionModule DriverEventTypeToModule(XdowsSecurityEventType type)
    {
        return type switch
        {
            XdowsSecurityEventType.ProcessCreate => ProtectionModule.Process,
            XdowsSecurityEventType.FileCreate or
                XdowsSecurityEventType.FileWrite or
                XdowsSecurityEventType.FileRename => ProtectionModule.File,
            XdowsSecurityEventType.ProcessHandle or
                XdowsSecurityEventType.ThreadHandle or
                XdowsSecurityEventType.ImageLoad => ProtectionModule.Injection,
            XdowsSecurityEventType.Behavior => ProtectionModule.Behavior,
            _ => ProtectionModule.Unknown
        };
    }

    private static string CleanDriverString(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        int nullIndex = value.IndexOf('\0');
        string cleaned = nullIndex >= 0 ? value[..nullIndex] : value;
        return cleaned.Trim();
    }
}
