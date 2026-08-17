using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Channels;
using TrustQuarantine;
using Helper;
using Xdows_Local;
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

    // Injection protection (Beta) toggle from the app settings. When the
    // provider returns false, every driver injection consultation is allowed
    // without prompting. Null or true keeps injection protection active.
    public Func<bool>? InjectionProtectionEnabledProvider { get; set; }

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
            DriverBridgeClient.ErrorRevisionMismatch => DriverProtectionRuntimeStatus.NeedsRepair,
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

                // Create the native model scanner BEFORE connecting to the
                // driver and BEFORE registering self-protection. Once
                // self-protection is active, our ObRegisterCallbacks strip
                // THREAD_IMPERSONATE / THREAD_SET_THREAD_TOKEN from handles
                // that external processes (e.g. antivirus daemons such as
                // Huorong's HipsDaemon) open to our threads. An AV daemon
                // that impersonates the requesting thread to scan a DLL
                // being image-mapped then fails with
                // STATUS_BAD_IMPERSONATION_LEVEL (Win32 1346), and the AV's
                // minifilter propagates that failure to the SEC_IMAGE
                // section creation — breaking LoadLibrary for any new DLL.
                // Loading the native model here, in the pre-registration
                // state, avoids that interaction entirely.
                Log("Scanner", $"Creating NativeModelScanner mode={ModelMode}");
                _scanner = new NativeModelScanner(ModelMode);
                Log("Scanner", $"NativeModelScanner created, NativeReady={_scanner.NativeReady}, Mode={_scanner.Mode}, Engine={NativeModelLibraryLoader.LoadedFrom ?? "unloaded"}");
                if (!_scanner.NativeReady)
                {
                    throw new InvalidOperationException(
                        $"Native model initialization failed: {_scanner.InitializationError ?? "unknown"}.");
                }

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

                _client.RegisterProtectedProcess();
                state = _client.GetState();
                Log("Bridge", $"Self-protection registered active={state.SelfProtectionEnabled} protectedPid={state.ProtectedProcessId} expectedPid={Environment.ProcessId}");
                if (state.SelfProtectionEnabled == 0 ||
                    state.ProtectedProcessId != (uint)Environment.ProcessId)
                {
                    throw new InvalidOperationException(
                        $"Driver self-protection did not activate for the current process (active={state.SelfProtectionEnabled}, protectedPid={state.ProtectedProcessId}, expectedPid={Environment.ProcessId}).");
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

                // Configure R0 registry protection
                var registryOptions = RegistryProtectionOptions.Recommended;
                var registryNativePaths = BuildNativeRegistryRulePaths(registryOptions);
                _client.SetRegistryProtection(true, registryNativePaths);
                Log("RegistryProtect", $"R0 registry protection configured rules={registryNativePaths.Count}");

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
            XdowsSecurityEventType.RegistryWrite => await HandleRegistryEventAsync(driverEvent, token).ConfigureAwait(false),
            _ => DriverBridgeClient.CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Allow, "unsupported-event")
        };
    }

    private async Task<XdowsSecurityDecision> HandleRegistryEventAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        string registryPath = CleanDriverString(driverEvent.ImagePath);
        string valueName = CleanDriverString(driverEvent.RegistryValueName);
        string? actorPath = ResolveActorPath(driverEvent);

        // False-positive gate. The kernel already skips PID<=4, the registered
        // client, and CI-trusted actors, but its CI cache only covers processes
        // it observed being created and it cannot consult the trust list or the
        // model. Evaluate the acting image here before taking the kernel wait
        // and prompting the user: legitimate installers, Windows servicing
        // components, and signed third-party updaters write these keys
        // constantly.
        if (!string.IsNullOrWhiteSpace(actorPath))
        {
            if (TrustManager.IsPathTrusted(actorPath))
                return Allow(driverEvent.EventId, "registry-actor-trusted-list", TimeSpan.FromMinutes(10));

            SignerTrustResult actorTrust = SignerTrustService.Evaluate(actorPath);
            if (actorTrust.IsTrusted)
                return Allow(driverEvent.EventId, $"registry-actor-signer-trusted:{actorTrust.Reason}", TimeSpan.FromMinutes(10));

            // Unsigned does not mean malicious. Only an actor the model calls a
            // threat justifies interrupting the user for a registry write.
            if (File.Exists(actorPath))
            {
                string actorCacheKey = BuildDecisionCacheKey("RegistryActor", actorPath);
                CleanupDecisionCache();
                if (DecisionCache.TryGetValue(actorCacheKey, out var cachedActor) &&
                    cachedActor.ExpiresAt > DateTimeOffset.UtcNow)
                {
                    if (cachedActor.Decision == XdowsSecurityDecisionType.Allow)
                        return Allow(driverEvent.EventId, cachedActor.Reason);
                }
                else
                {
                    await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
                    NativeModelScannerResult actorScan;
                    try
                    {
                        actorScan = await ScanSingleFlightAsync(actorPath, token).ConfigureAwait(false);
                    }
                    finally
                    {
                        ScanLimiter.Release();
                    }

                    if (!string.IsNullOrWhiteSpace(actorScan.ErrorMessage))
                    {
                        // Model infrastructure failure is not evidence. Allow
                        // briefly and keep the reason in the diagnostic log.
                        Cache(
                            actorCacheKey,
                            XdowsSecurityDecisionType.Allow,
                            "registry-actor-model-error",
                            TimeSpan.FromSeconds(30));
                        return Allow(driverEvent.EventId, "registry-actor-model-error");
                    }

                    if (!actorScan.IsThreat)
                    {
                        Cache(
                            actorCacheKey,
                            XdowsSecurityDecisionType.Allow,
                            "registry-actor-model-safe",
                            TimeSpan.FromMinutes(10));
                        return Allow(driverEvent.EventId, "registry-actor-model-safe", TimeSpan.FromMinutes(1));
                    }
                }
            }
        }

        if (!TryEnterUserDecisionHold(driverEvent))
        {
            return DriverBridgeClient.CreateDecision(
                driverEvent.EventId,
                XdowsSecurityDecisionType.Block,
                "registry-user-hold-failed-block");
        }

        string operation = ((XdowsSecurityRegistryOperation)driverEvent.RegistryOperation) switch
        {
            XdowsSecurityRegistryOperation.CreateKey => "CreateKey",
            XdowsSecurityRegistryOperation.SetValue => "SetValue",
            XdowsSecurityRegistryOperation.DeleteValue => "DeleteValue",
            XdowsSecurityRegistryOperation.DeleteKey => "DeleteKey",
            XdowsSecurityRegistryOperation.RenameKey => "RenameKey",
            XdowsSecurityRegistryOperation.RestoreKey => "RestoreKey",
            XdowsSecurityRegistryOperation.ReplaceKey => "ReplaceKey",
            XdowsSecurityRegistryOperation.UnloadKey => "UnloadKey",
            _ => "Registry"
        };

        var request = new ProtectionDecisionRequest(
            string.IsNullOrWhiteSpace(registryPath) ? "Registry" : registryPath,
            $"Registry {operation}{(string.IsNullOrEmpty(valueName) ? string.Empty : $" -> {valueName}")}",
            RegistryScan.DetectionName,
            0,
            checked((int)driverEvent.ProcessId),
            checked((int)driverEvent.ParentProcessId),
            null,
            actorPath,
            string.IsNullOrWhiteSpace(actorPath) ? "Unknown" : "Unverified",
            EventId: driverEvent.EventId,
            CorrelationId: driverEvent.CorrelationId,
            ActorDetectionName: null,
            ActorProbability: 0,
            Module: ProtectionModule.Registry,
            Backend: ProtectionBackend.Driver,
            DecisionDeadline: DateTimeOffset.UtcNow.Add(UserDecisionTimeout));

        ProtectionUserDecision userDecision = await AskUserAfterHoldAsync(
            request,
            driverEvent,
            token).ConfigureAwait(false);

        if (userDecision == ProtectionUserDecision.Allow)
            return Allow(driverEvent.EventId, "user-release-registry");

        string reason = userDecision == ProtectionUserDecision.Timeout
            ? "registry-user-timeout-block"
            : "user-block-registry";
        return DriverBridgeClient.CreateDecision(
            driverEvent.EventId,
            XdowsSecurityDecisionType.Block,
            reason);
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

        // Injection protection master switch (Beta). Disabled means every
        // injection/thread-injection consultation is allowed immediately;
        // checked before the user-decision hold so no kernel wait is spent.
        if (((XdowsSecurityBehaviorType)driverEvent.BehaviorType is
                XdowsSecurityBehaviorType.ProcessInjection
                or XdowsSecurityBehaviorType.ThreadInjection) &&
            InjectionProtectionEnabledProvider?.Invoke() == false)
        {
            return Allow(driverEvent.EventId, "injection-protection-disabled", TimeSpan.Zero);
        }

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

        // Self fast-allow: our own scanning activity must never prompt. The
        // kernel-side ClientProcessId exemption covers the registered client
        // only; heartbeat disconnect windows and helper binaries deployed
        // beside the main executable would otherwise reach the prompt path,
        // and unsigned dev/publish builds cannot pass any signer gate.
        if ((behaviorType is XdowsSecurityBehaviorType.ProcessInjection
                or XdowsSecurityBehaviorType.ThreadInjection) &&
            IsOwnDeploymentImage(actorPath))
        {
            return Allow(driverEvent.EventId, "behavior-handle-self", TimeSpan.FromMinutes(10));
        }

        // Self-as-target: our own image is guarded by the SelfProtect module
        // with its own policy, so an injection consultation about our own
        // executable is only actionable when the actor itself is untrusted.
        // Signed system actors (WMI hosts, shell, telemetry) routinely open
        // handles to every user-mode process, including ours; our unsigned
        // image can never pass the target-side signer gate below.
        if ((behaviorType is XdowsSecurityBehaviorType.ProcessInjection
                or XdowsSecurityBehaviorType.ThreadInjection) &&
            !imagePath.StartsWith("PID ", StringComparison.Ordinal) &&
            IsOwnDeploymentImage(imagePath) &&
            !string.IsNullOrWhiteSpace(actorPath) &&
            !actorPath.StartsWith("PID ", StringComparison.Ordinal) &&
            !IsOwnDeploymentImage(actorPath) &&
            (TrustManager.IsPathTrusted(actorPath) ||
             SignerTrustService.Evaluate(actorPath).IsTrusted))
        {
            return Allow(driverEvent.EventId, "behavior-handle-self-target", TimeSpan.FromMinutes(10));
        }

        // Trust gate for handle-based behavior detections. Cross-process
        // handle / injection heuristics routinely fire on legitimate,
        // Authenticode-signed system components (smartscreen.exe,
        // ShellHost.exe) and third-party security daemons performing normal
        // monitoring — previously every such event became a "confirmed
        // threat" prompt (Probability=100) that timeout-blocked the
        // operation. Command-line behaviors (HiddenPowerShell,
        // EncodedCommand, LolbinAbuse, ...) stay on the prompt path: they
        // remain high-fidelity even for signed binaries.
        //
        // When the target image path could not be resolved (protected or
        // already-exited process, shown as "PID nnnn"), decide on the actor
        // image instead: the actor is what determines whether the handle
        // request is benign monitoring.
        if (behaviorType is XdowsSecurityBehaviorType.ProcessInjection
            or XdowsSecurityBehaviorType.ThreadInjection)
        {
            // The trust question is always about the acting image: it is what
            // requested the dangerous handle. Falling back to the target image
            // (as this gate previously did whenever the actor was unresolved)
            // let an untrusted actor inherit the trust of a signed victim, and
            // conversely reported signed system actors as threats whenever the
            // target happened to be unsigned.
string gatePath = actorPath;

            if (!string.IsNullOrWhiteSpace(gatePath) &&
                !gatePath.StartsWith("PID ", StringComparison.Ordinal))
            {
                // System-root actors (Windows\System32, Windows\SysWOW64, ...)
                // are signed OS components performing routine monitoring.
                // Allow them before signature evaluation so system services
                // do not block on disk I/O or model scans for every handle
                // request during startup.
                if (IsUnderSystemRoot(gatePath))
                    return Allow(driverEvent.EventId, "behavior-handle-system-actor", TimeSpan.FromMinutes(10));

                if (TrustManager.IsPathTrusted(gatePath))
                    return Allow(driverEvent.EventId, "behavior-handle-trusted-list", TimeSpan.FromMinutes(10));

                SignerTrustResult actorTrust = SignerTrustService.Evaluate(gatePath);
                if (actorTrust.IsTrusted)
                    return Allow(driverEvent.EventId, $"behavior-handle-signer-trusted:{actorTrust.Reason}", TimeSpan.FromMinutes(10));

                // Unsigned is not malicious. Debuggers, launchers, overlays and
                // in-house tools legitimately open dangerous handles, and the
                // kernel CI cache cannot help when ci.dll exports are missing
                // or the actor predates the driver. Ask the model before
                // interrupting the user.
                if (File.Exists(gatePath))
                {
                    string gateCacheKey = BuildDecisionCacheKey("BehaviorActor", gatePath);
                    CleanupDecisionCache();
                    if (DecisionCache.TryGetValue(gateCacheKey, out var cachedGate) &&
                        cachedGate.ExpiresAt > DateTimeOffset.UtcNow)
                    {
                        if (cachedGate.Decision == XdowsSecurityDecisionType.Allow)
                            return Allow(driverEvent.EventId, cachedGate.Reason);
                    }
                    else
                    {
                        await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
                        NativeModelScannerResult gateScan;
                        try
                        {
                            gateScan = await ScanSingleFlightAsync(gatePath, token).ConfigureAwait(false);
                        }
                        finally
                        {
                            ScanLimiter.Release();
                        }

                        if (!string.IsNullOrWhiteSpace(gateScan.ErrorMessage))
                        {
                            Cache(
                                gateCacheKey,
                                XdowsSecurityDecisionType.Allow,
                                "behavior-handle-model-error",
                                TimeSpan.FromSeconds(30));
                            return Allow(driverEvent.EventId, "behavior-handle-model-error");
                        }

                        if (!gateScan.IsThreat)
                        {
                            Cache(
                                gateCacheKey,
                                XdowsSecurityDecisionType.Allow,
                                "behavior-handle-model-safe",
                                TimeSpan.FromMinutes(10));
                            return Allow(driverEvent.EventId, "behavior-handle-model-safe", TimeSpan.FromMinutes(1));
                        }
                    }
                }
            }
            else
            {
                // No acting image to judge. Per the driver's fail-open bridge
                // policy, absence of evidence must not become a confirmed
                // threat prompt for a Beta detection.
                return Allow(driverEvent.EventId, "behavior-handle-actor-unknown", TimeSpan.FromMinutes(1));
            }
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

    private static readonly Lazy<string?> OwnDeploymentDirectory = new(
        () =>
        {
            string? processPath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(processPath))
                return null;
            try
            {
                string? directory = Path.GetDirectoryName(processPath);
                return string.IsNullOrWhiteSpace(directory) ? null : directory;
            }
            catch
            {
                return null;
            }
        },
        LazyThreadSafetyMode.ExecutionAndPublication);

    private static bool IsOwnDeploymentImage(string? actorPath)
    {
        string? ownDirectory = OwnDeploymentDirectory.Value;
        if (string.IsNullOrWhiteSpace(actorPath) || ownDirectory is null)
            return false;

        try
        {
            string? directory = Path.GetDirectoryName(actorPath);
            return string.Equals(directory, ownDirectory, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsUnderSystemRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        try
        {
            string systemRoot = Environment.GetFolderPath(
                Environment.SpecialFolder.Windows).TrimEnd('\\');
            if (string.IsNullOrWhiteSpace(systemRoot))
                return false;

            string full = Path.GetFullPath(path);
            return full.StartsWith(
                systemRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
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

    private static List<string> BuildNativeRegistryRulePaths(RegistryProtectionOptions options)
    {
        string userSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        var paths = new List<string>();

        foreach (var rule in RegistryScan.Rules)
        {
            if (!options.Includes(rule.Category))
                continue;

            if (rule.Root == RegistryRuleRoot.LocalMachine)
            {
                paths.Add($@"\REGISTRY\MACHINE\{rule.KeyPath}");
            }
            else if (!string.IsNullOrEmpty(userSid))
            {
                paths.Add($@"\REGISTRY\USER\{userSid}\{rule.KeyPath}");
            }
        }

        return paths;
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
