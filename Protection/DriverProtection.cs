using System.Collections.Concurrent;
using System.Diagnostics;
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

public sealed class DriverProtection : IProtectionModel
{
    private sealed record DecisionCacheEntry(
        XdowsSecurityDecisionType Decision,
        string Reason,
        DateTimeOffset ExpiresAt);

    private static readonly Lock StateLock = new();
    private static readonly ConcurrentDictionary<string, DecisionCacheEntry> DecisionCache = new(StringComparer.OrdinalIgnoreCase);
    // F1: Raised from 4 to 16. Pro model ScanFile takes ~480ms; with only 4
    // concurrent slots the limiter was exhausted by the FileCreate flood
    // (3357 events in 2 minutes), causing unrelated events to queue until
    // the 5s kernel timeout fired and blocked them.
    private static readonly int ScanWorkerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
    private static readonly SemaphoreSlim ScanLimiter = new(ScanWorkerCount, ScanWorkerCount);
    private static readonly ConcurrentDictionary<string, Lazy<Task<NativeModelScannerResult>>> InFlightScans = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _pumpTask;
    private Task? _logTask;
    private DriverBridgeClient? _client;
    private NativeModelScanner? _scanner;
    private InterceptCallBack? _interceptCallBack;

    public const string DriverProtectionName = "Driver";
    public string Name => DriverProtectionName;

    public NativeModelScannerMode ModelMode { get; set; } = NativeModelScannerMode.Standard;

    public Func<ProtectionDecisionRequest, CancellationToken, Task<ProtectionUserDecision>>? DecisionCallback { get; set; }
    public Action<DriverProtectionLogEntry>? LogCallback { get; set; }

    private void Log(string module, string message)
    {
        LogCallback?.Invoke(new DriverProtectionLogEntry(
            0, 0, DriverProtectionLogSeverity.Info, 0, DateTimeOffset.Now, module, message));
    }

    public static DriverProtectionRuntimeStatus QueryRuntimeStatus()
    {
        if (DriverBridgeClient.TryQueryStateWithoutRegister(out var state, out int error))
        {
            return state.ClientConnected != 0
                ? DriverProtectionRuntimeStatus.Protected
                : DriverProtectionRuntimeStatus.NotRunning;
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

                Log("Scanner", $"Creating NativeModelScanner mode={ModelMode}");
                _scanner = new NativeModelScanner(ModelMode);
                Log("Scanner", $"NativeModelScanner created, NativeReady={_scanner.NativeReady}, Mode={_scanner.Mode}");
                _client = new DriverBridgeClient();
                Log("Bridge", "Connecting DriverBridgeClient...");
                _client.Connect();
                XdowsSecurityState state = _client.GetState();
                Log("Bridge", $"DriverBridgeClient connected protocol={state.ProtocolVersion} build={state.DriverBuildId} capabilities=0x{state.Capabilities:X8}");
                _client.RegisterProtectedProcess();
                DriverBridgeClient client = _client;
                _pumpTask = Task.Run(() => client.RunEventPumpAsync(HandleDriverEventAsync, _cts.Token));
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
                        Log("Bridge", $"Runtime driver reports headerSize={driverState.Header.Size} headerVersion={driverState.Header.Version} protocolVersion={driverState.ProtocolVersion} buildId={driverState.DriverBuildId}; client expects protocolVersion={DriverProtocol.ProtocolVersion} buildId={DriverProtocol.DriverBuildId}");
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
            if (!IsRun())
                return true;

            try
            {
                _cts?.Cancel();
                try
                {
                    _pumpTask?.Wait(2000);
                    _logTask?.Wait(2000);
                }
                catch
                {
                }

                try
                {
                    _client?.SubmitAuthorizedShutdown();
                }
                catch
                {
                }

                CleanupLocked();
                return true;
            }
            catch
            {
                CleanupLocked();
                return false;
            }
        }
    }

    public bool IsRun()
    {
        return _cts is { IsCancellationRequested: false } &&
            _client is { IsConnected: true };
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
        try
        {
            _client?.Disconnect();
        }
        catch
        {
        }

        _client?.Dispose();
        _client = null;

        _scanner?.Dispose();
        _scanner = null;

        _cts?.Dispose();
        _cts = null;
        _pumpTask = null;
        _logTask = null;
        _interceptCallBack = null;
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
            _ => DriverBridgeClient.CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Allow, "unsupported-event")
        };
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
        // during a 30s popup would exhaust the 16 slots and block all other
        // scans, causing driver timeouts and system lockup.
        if (!string.IsNullOrWhiteSpace(scan.ErrorMessage))
        {
            // Model feature-extraction failed. For ProcessCreate this means
            // we cannot determine if the executable is safe. Fail-ask:
            // prompt the user rather than silently allowing a potentially
            // malicious binary (e.g. malware with malformed PE header that
            // bypasses IsPeFile). User Allow -> cache; user Block -> block;
            // user Timeout -> allow (fail-open to avoid system lockup).
            Log("Scan", $"ProcessCreate model-error, escalating to user: {scan.ErrorMessage}");
            NativeModelScannerResult errorScan = new NativeModelScannerResult(
                true, 50, "ModelExtractionError", false, scan.ErrorMessage);
            ProtectionUserDecision errorDecision = await AskUserForThreatDecisionAsync(
                imagePath,
                commandLine,
                driverEvent,
                errorScan,
                actorPath: ResolveActorPath(driverEvent),
                actorTrust: null,
                actorScan: null,
                token).ConfigureAwait(false);

            if (errorDecision == ProtectionUserDecision.Allow)
            {
                Cache(processCacheKey, XdowsSecurityDecisionType.Allow, "user-release-model-error", TimeSpan.FromMinutes(5));
                return Allow(driverEvent.EventId, "user-release-model-error");
            }
            if (errorDecision == ProtectionUserDecision.Timeout)
            {
                Cache(processCacheKey, XdowsSecurityDecisionType.Allow, "model-error-timeout-allow", TimeSpan.FromSeconds(30));
                return Allow(driverEvent.EventId, "model-error-timeout-allow");
            }

            Cache(processCacheKey, XdowsSecurityDecisionType.Block, "user-block-model-error", TimeSpan.FromSeconds(10));
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Block, "user-block-model-error");
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
        // during a 30s popup would exhaust the 16 slots and block all other
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
        _ = QuarantineManager.AddToQuarantine(filePath, detectionName);

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
        string protectionType = DriverEventTypeToProtectionType((XdowsSecurityEventType)driverEvent.EventType);
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
            driverEvent.CorrelationId,
            actorScan?.DetectionName,
            actorScan?.Probability ?? 0,
            DriverEventTypeToModule((XdowsSecurityEventType)driverEvent.EventType),
            ProtectionBackend.Driver);

        if (DecisionCallback is not null)
        {
            return await DriverDecisionService.AskUserAsync(
                callbackToken => DecisionCallback(request, callbackToken),
                TimeSpan.FromSeconds(30),
                token).ConfigureAwait(false);
        }

        _interceptCallBack?.Invoke(new ProtectionInterceptEvent(
            imagePath,
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
            _ => "Driver"
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
