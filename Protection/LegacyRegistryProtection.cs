using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using TrustQuarantine;
using Xdows_Local;
using static Protection.CallBack;

namespace Protection;

public sealed class LegacyRegistryProtection : IProtectionModel
{
    private sealed record RegistryObservation(
        string Path,
        string Operation,
        int ProcessId,
        RegistryProtectionRule Rule,
        DateTimeOffset Timestamp);

    private static readonly TimeSpan DecisionTimeout = TimeSpan.FromSeconds(25);
    private const long DuplicateWindowMilliseconds = 500;

    private readonly Lock _gate = new();
    private readonly string _traceSessionName =
        $"Xdows-Security-Registry-{Environment.ProcessId}-{Guid.NewGuid():N}";
    private readonly ConcurrentDictionary<string, long> _recentObservations =
        new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;
    private TraceEventSession? _traceSession;
    private Channel<RegistryObservation>? _observations;
    private Task? _traceTask;
    private Task? _processorTask;
    private InterceptCallBack? _interceptCallback;
    private long _nextEventId;

    public string Name => "Registry";
    public Func<RegistryProtectionOptions>? OptionsProvider { get; set; }
    public Func<ProtectionDecisionRequest, CancellationToken, Task<ProtectionUserDecision>>? DecisionCallback { get; set; }
    public Action<string>? LogCallback { get; set; }

    public bool Run(InterceptCallBack interceptCallBack)
    {
        lock (_gate)
        {
            if (IsRunningLocked())
                return true;
            if (!Helper.ScanEngine.ModelEngineScan.InitializeForProtection())
                return false;

            try
            {
                _cts = new CancellationTokenSource();
                _interceptCallback = interceptCallBack;
                _observations = Channel.CreateBounded<RegistryObservation>(
                    new BoundedChannelOptions(256)
                    {
                        SingleReader = true,
                        SingleWriter = false,
                        FullMode = BoundedChannelFullMode.DropWrite
                    });

                _traceSession = CreateTraceSession();
                TraceEventSession initialSession = _traceSession;
                Channel<RegistryObservation> channel = _observations;
                CancellationToken token = _cts.Token;
                _processorTask = Task.Run(
                    () => ProcessObservationsAsync(channel.Reader, token),
                    token);
                _traceTask = Task.Run(
                    () => RunTraceLoopAsync(initialSession, token),
                    token);
                Log("R3 registry protection started.");
                return true;
            }
            catch (Exception ex)
            {
                Log($"R3 registry protection failed to start: {ex.Message}");
                CleanupLocked();
                return false;
            }
        }
    }

    public bool Stop()
    {
        lock (_gate)
        {
            if (!IsRunningLocked())
                return true;

            try
            {
                _cts?.Cancel();
                _observations?.Writer.TryComplete();
                _traceSession?.Dispose();
                CleanupLocked();
                Log("R3 registry protection stopped.");
                return true;
            }
            catch (Exception ex)
            {
                Log($"R3 registry protection stop failed: {ex.Message}");
                CleanupLocked();
                return false;
            }
        }
    }

    public bool IsRun()
    {
        lock (_gate)
            return IsRunningLocked();
    }

    private bool IsRunningLocked() => _cts is { IsCancellationRequested: false };

    private TraceEventSession CreateTraceSession()
    {
        var session = new TraceEventSession(
            _traceSessionName,
            null)
        {
            StopOnDispose = true
        };
        var parser = new KernelTraceEventParser(session.Source);
        parser.RegistryCreate += data => Observe(data, "CreateKey");
        parser.RegistryDelete += data => Observe(data, "DeleteKey");
        parser.RegistrySetValue += data => Observe(data, "SetValue");
        parser.RegistryDeleteValue += data => Observe(data, "DeleteValue");
        parser.RegistrySetInformation += data => Observe(data, "RenameKey");
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Registry);
        return session;
    }

    private async Task RunTraceLoopAsync(
        TraceEventSession initialSession,
        CancellationToken token)
    {
        TraceEventSession session = initialSession;
        while (!token.IsCancellationRequested)
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                Log($"Registry trace session stopped unexpectedly: {ex.Message}");
            }
            finally
            {
                session.Dispose();
            }

            if (token.IsCancellationRequested)
                break;

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), token).ConfigureAwait(false);
                session = CreateTraceSession();
                lock (_gate)
                {
                    if (IsRunningLocked())
                        _traceSession = session;
                }
                Log("Registry trace session recovered.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log($"Registry trace recovery failed: {ex.Message}");
            }
        }
    }

    private void Observe(RegistryTraceData data, string operation)
    {
        if (_cts is not { IsCancellationRequested: false } ||
            _observations is null ||
            data.ProcessID == 4 ||
            data.ProcessID == Environment.ProcessId ||
            string.IsNullOrWhiteSpace(data.KeyName))
        {
            return;
        }

        RegistryProtectionOptions options = GetOptions();
        if (!RegistryScan.TryMatch(data.KeyName, options, out RegistryProtectionRule? rule) ||
            rule is null)
        {
            return;
        }

        long now = Environment.TickCount64;
        if (_recentObservations.Count > 2048)
        {
            foreach ((string key, long timestamp) in _recentObservations)
            {
                if (now - timestamp > TimeSpan.FromMinutes(1).TotalMilliseconds)
                    _recentObservations.TryRemove(key, out _);
            }
        }
        string duplicateKey = $"{rule.CanonicalPath}|{data.ProcessID}|{operation}";
        if (_recentObservations.TryGetValue(duplicateKey, out long previous) &&
            now - previous < DuplicateWindowMilliseconds)
        {
            return;
        }
        _recentObservations[duplicateKey] = now;

        var observation = new RegistryObservation(
            data.KeyName,
            operation,
            data.ProcessID,
            rule,
            data.TimeStamp);
        if (!_observations.Writer.TryWrite(observation))
            Log($"Registry observation dropped because the queue is full: {rule.CanonicalPath}");
    }

    private async Task ProcessObservationsAsync(
        ChannelReader<RegistryObservation> reader,
        CancellationToken token)
    {
        try
        {
            await foreach (RegistryObservation observation in reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                try
                {
                    await ProcessObservationAsync(observation, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Log($"Registry observation processing failed: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task ProcessObservationAsync(
        RegistryObservation observation,
        CancellationToken token)
    {
        string? actorPath = observation.ProcessId > 0
            ? DriverPathNormalizer.Normalize(
                SignerTrustService.TryResolveProcessPath((uint)observation.ProcessId))
            : null;
        SignerTrustResult actorTrust = SignerTrustService.Evaluate(actorPath);
        if (actorTrust.IsTrusted)
        {
            Log(
                $"Trusted process changed {observation.Rule.CanonicalPath}: " +
                $"{actorPath} ({actorTrust.Reason})");
            return;
        }

        bool actorThreat = false;
        string actorDetection = string.Empty;
        if (!string.IsNullOrWhiteSpace(actorPath) && File.Exists(actorPath))
        {
            try
            {
                (actorThreat, actorDetection) = Helper.ScanEngine.ModelEngineScan.ScanFile(actorPath);
            }
            catch (Exception ex)
            {
                Log($"Registry actor scan failed for {actorPath}: {ex.Message}");
            }
        }

        ulong eventId = unchecked((ulong)Interlocked.Increment(ref _nextEventId));
        DateTimeOffset deadline = DateTimeOffset.UtcNow.Add(DecisionTimeout);
        var request = new ProtectionDecisionRequest(
            observation.Rule.CanonicalPath,
            $"Registry {observation.Operation}",
            RegistryScan.DetectionName,
            actorThreat ? 100 : 0,
            observation.ProcessId,
            0,
            null,
            actorPath,
            string.IsNullOrWhiteSpace(actorPath) ? "Unknown" : actorTrust.Reason,
            EventId: eventId,
            CorrelationId: eventId,
            ActorDetectionName: actorThreat ? actorDetection : null,
            ActorProbability: actorThreat ? 100 : 0,
            Module: Helper.ProtectionModule.Registry,
            Backend: Helper.ProtectionBackend.Compatibility,
            DecisionDeadline: deadline);

        Log(
            $"Registry change pending user decision: operation={observation.Operation} " +
            $"path={observation.Path} pid={observation.ProcessId} actor={actorPath ?? "unknown"}");

        ProtectionUserDecision decision = DecisionCallback is null
            ? ProtectionUserDecision.Block
            : await DriverDecisionService.AskUserAsync(
                callbackToken => DecisionCallback(request, callbackToken),
                deadline - DateTimeOffset.UtcNow,
                token).ConfigureAwait(false);
        if (decision == ProtectionUserDecision.Allow)
        {
            Log($"User allowed registry change: {observation.Rule.CanonicalPath}");
            return;
        }

        bool stopped = TryStopActor(observation.ProcessId);
        bool quarantined = false;
        if (stopped && actorThreat && !string.IsNullOrWhiteSpace(actorPath))
        {
            quarantined = await QuarantineManager
                .AddToQuarantine(actorPath, actorDetection)
                .ConfigureAwait(false);
        }

        Log(
            $"Registry change blocked after detection: path={observation.Rule.CanonicalPath} " +
            $"decision={decision} actorStopped={stopped} quarantined={quarantined}");
        if (stopped && !string.IsNullOrWhiteSpace(actorPath))
        {
            _interceptCallback?.Invoke(new ProtectionInterceptEvent(
                actorPath,
                true,
                actorThreat ? actorDetection : RegistryScan.DetectionName,
                actorThreat ? 100 : 0,
                Helper.ProtectionModule.Registry,
                Helper.ProtectionBackend.Compatibility));
        }
    }

    private static bool TryStopActor(int processId)
    {
        if (processId <= 4 || processId == Environment.ProcessId)
            return false;

        try
        {
            using Process process = Process.GetProcessById(processId);
            process.Kill(entireProcessTree: true);
            return process.WaitForExit(2000);
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
            _traceSession?.Dispose();
        }
        catch
        {
        }
        _traceSession = null;
        _observations?.Writer.TryComplete();
        _observations = null;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _traceTask = null;
        _processorTask = null;
        _interceptCallback = null;
        _recentObservations.Clear();
    }

    private RegistryProtectionOptions GetOptions()
    {
        try
        {
            return OptionsProvider?.Invoke() ?? RegistryProtectionOptions.Recommended;
        }
        catch
        {
            return RegistryProtectionOptions.Recommended;
        }
    }

    private void Log(string message)
    {
        try
        {
            LogCallback?.Invoke(message);
        }
        catch
        {
        }
    }
}
