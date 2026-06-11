using System.Collections.Concurrent;
using TrustQuarantine;
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
    private static readonly SemaphoreSlim ScanLimiter = new(4, 4);

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
            5 => DriverProtectionRuntimeStatus.NeedsRepair,
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
                _scanner = new NativeModelScanner(ModelMode);
                _client = new DriverBridgeClient();
                _client.Connect();
                _client.RegisterProtectedProcess();
                DriverBridgeClient client = _client;
                _pumpTask = Task.Run(() => client.RunEventPumpAsync(HandleDriverEventAsync, _cts.Token));
                _logTask = Task.Run(() => RunLogPumpAsync(client, _cts.Token));
                return true;
            }
            catch
            {
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
        string imagePath = CleanDriverString(driverEvent.ImagePath);
        string commandLine = CleanDriverString(driverEvent.CommandLine);

        if (string.IsNullOrWhiteSpace(imagePath))
            return Allow(driverEvent.EventId, "empty-image-path");

        if (TrustManager.IsPathTrusted(imagePath))
            return Allow(driverEvent.EventId, "trusted-path", TimeSpan.FromMinutes(10));

        CleanupDecisionCache();

        if (DecisionCache.TryGetValue(imagePath, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason);
        }

        await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
        try
        {
            NativeModelScanner scanner = _scanner ?? new NativeModelScanner(ModelMode);
            NativeModelScannerResult scan = scanner.ScanFile(imagePath);

            if (!string.IsNullOrWhiteSpace(scan.ErrorMessage))
            {
                Cache(imagePath, XdowsSecurityDecisionType.Allow, "model-error", TimeSpan.FromSeconds(30));
                return Allow(driverEvent.EventId, "model-error:" + scan.ErrorMessage);
            }

            if (!scan.IsThreat)
            {
                Cache(imagePath, XdowsSecurityDecisionType.Allow, "model-safe", TimeSpan.FromMinutes(1));
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
                Cache(imagePath, XdowsSecurityDecisionType.Allow, "user-release", TimeSpan.FromMinutes(5));
                return Allow(driverEvent.EventId, "user-release", TimeSpan.FromMinutes(5));
            }

            XdowsSecurityDecisionType decisionType = userDecision == ProtectionUserDecision.Timeout
                ? XdowsSecurityDecisionType.Timeout
                : XdowsSecurityDecisionType.Block;
            string reason = userDecision == ProtectionUserDecision.Timeout
                ? "user-timeout-threat"
                : "user-block-threat";

            Cache(imagePath, decisionType, reason, TimeSpan.FromSeconds(10));
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, decisionType, reason);
        }
        finally
        {
            ScanLimiter.Release();
        }
    }

    private async Task<XdowsSecurityDecision> HandleFileEventAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        string filePath = CleanDriverString(driverEvent.ImagePath);
        if (string.IsNullOrWhiteSpace(filePath))
            return Allow(driverEvent.EventId, "empty-file-path");

        if (!File.Exists(filePath))
            return Allow(driverEvent.EventId, "file-missing");

        if (TrustManager.IsPathTrusted(filePath))
            return Allow(driverEvent.EventId, "trusted-file", TimeSpan.FromMinutes(10));

        string cacheKey = $"{driverEvent.EventType}:{filePath}";
        CleanupDecisionCache();
        if (DecisionCache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason);
        }

        await ScanLimiter.WaitAsync(token).ConfigureAwait(false);
        try
        {
            NativeModelScanner scanner = _scanner ?? new NativeModelScanner(ModelMode);
            NativeModelScannerResult scan = scanner.ScanFile(filePath);

            if (!string.IsNullOrWhiteSpace(scan.ErrorMessage))
            {
                Cache(cacheKey, XdowsSecurityDecisionType.Allow, "model-error", TimeSpan.FromSeconds(30));
                return Allow(driverEvent.EventId, "model-error:" + scan.ErrorMessage);
            }

            if (!scan.IsThreat)
            {
                Cache(cacheKey, XdowsSecurityDecisionType.Allow, "model-safe", TimeSpan.FromMinutes(1));
                return Allow(driverEvent.EventId, "model-safe", TimeSpan.FromMinutes(1));
            }

            string? actorPath = ResolveActorPath(driverEvent);
            SignerTrustResult? actorTrust = SignerTrustService.Evaluate(actorPath);
            NativeModelScannerResult? actorScan = null;
            if (actorTrust is { IsTrusted: false } &&
                !string.IsNullOrWhiteSpace(actorPath) &&
                File.Exists(actorPath) &&
                !string.Equals(actorPath, filePath, StringComparison.OrdinalIgnoreCase))
            {
                actorScan = scanner.ScanFile(actorPath);
            }

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

            XdowsSecurityDecisionType decisionType = userDecision == ProtectionUserDecision.Timeout
                ? XdowsSecurityDecisionType.Timeout
                : XdowsSecurityDecisionType.Block;
            string reason = userDecision == ProtectionUserDecision.Timeout
                ? "user-timeout-file-threat"
                : "user-block-file-threat";

            Cache(cacheKey, decisionType, reason, TimeSpan.FromSeconds(10));
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, decisionType, reason);
        }
        finally
        {
            ScanLimiter.Release();
        }
    }

    private async Task<XdowsSecurityDecision> HandleSensitiveOperationAsync(
        XdowsSecurityEvent driverEvent,
        CancellationToken token)
    {
        string actorPath = ResolveActorPath(driverEvent) ?? string.Empty;
        string targetPath = CleanDriverString(driverEvent.ImagePath);
        string cacheKey = $"{driverEvent.EventType}:{actorPath}:{targetPath}:{driverEvent.ProcessId}";

        CleanupDecisionCache();
        if (DecisionCache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return DriverBridgeClient.CreateDecision(driverEvent.EventId, cached.Decision, cached.Reason);
        }

        SignerTrustResult actorTrust = SignerTrustService.Evaluate(actorPath);
        if (actorTrust.IsTrusted)
        {
            Cache(cacheKey, XdowsSecurityDecisionType.Allow, "trusted-actor", TimeSpan.FromMinutes(10));
            return Allow(driverEvent.EventId, "trusted-actor", TimeSpan.FromMinutes(10));
        }

        var scan = new NativeModelScannerResult(
            true,
            100,
            ((XdowsSecurityEventType)driverEvent.EventType).ToString(),
            false,
            null);

        ProtectionUserDecision userDecision = await AskUserForThreatDecisionAsync(
            string.IsNullOrWhiteSpace(targetPath) ? actorPath : targetPath,
            string.Empty,
            driverEvent,
            scan,
            actorPath,
            actorTrust,
            null,
            token).ConfigureAwait(false);

        if (userDecision == ProtectionUserDecision.Allow)
        {
            Cache(cacheKey, XdowsSecurityDecisionType.Allow, "user-release-sensitive-operation", TimeSpan.FromMinutes(5));
            return Allow(driverEvent.EventId, "user-release-sensitive-operation", TimeSpan.FromMinutes(5));
        }

        XdowsSecurityDecisionType decisionType = userDecision == ProtectionUserDecision.Timeout
            ? XdowsSecurityDecisionType.Timeout
            : XdowsSecurityDecisionType.Block;
        string reason = userDecision == ProtectionUserDecision.Timeout
            ? "user-timeout-sensitive-operation"
            : "user-block-sensitive-operation";
        Cache(cacheKey, decisionType, reason, TimeSpan.FromSeconds(10));
        return DriverBridgeClient.CreateDecision(driverEvent.EventId, decisionType, reason);
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
            actorScan?.Probability ?? 0);

        if (DecisionCallback is not null)
        {
            return await DriverDecisionService.AskUserAsync(
                callbackToken => DecisionCallback(request, callbackToken),
                TimeSpan.FromSeconds(30),
                token).ConfigureAwait(false);
        }

        _interceptCallBack?.Invoke(true, imagePath, protectionType);
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

    private static string? ResolveActorPath(XdowsSecurityEvent driverEvent)
    {
        string actorPath = CleanDriverString(driverEvent.ActorImagePath);
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

    private static string CleanDriverString(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        int nullIndex = value.IndexOf('\0');
        string cleaned = nullIndex >= 0 ? value[..nullIndex] : value;
        return cleaned.Trim();
    }
}
