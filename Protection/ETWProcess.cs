using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;
using System.Diagnostics;
using TrustQuarantine;
using static Protection.CallBack;

namespace Protection
{
    public partial class ETW
    {
        public class ProcessProtection : IProtectionModel
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;
            private static TraceEventSession? session;
            public const string Name = "Process";
            string IProtectionModel.Name => Name;

            private static readonly ConcurrentDictionary<int, DateTime> _recentProcesses = new();
            private static readonly ConcurrentDictionary<string, DateTime> _scannedPaths = new();
            private static readonly ConcurrentDictionary<int, (string? path, DateTime timestamp)> _processPathCache = new();
            private static readonly TimeSpan _dedupWindow = TimeSpan.FromSeconds(5);
            private static readonly TimeSpan _pathCacheWindow = TimeSpan.FromMinutes(1);
            private static readonly TimeSpan _processPathCacheWindow = TimeSpan.FromSeconds(30);

            public bool Run(InterceptCallBack interceptCallBack)
            {
                lock (lockObj)
                {
                    if (isRunning)
                        return true;

                    try
                    {
                        Helper.ScanEngine.ModelEngineScan.Initialize();

                        isRunning = true;

                        session = new TraceEventSession($"Xdows-Security-{Name}", null);
                        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                        var parser = new KernelTraceEventParser(session.Source);
                        parser.ProcessStart += (data) => OnNewProcess(data, interceptCallBack);

                        _ = Task.Run(() =>
                        {
                            try
                            {
                                session.Source.Process();
                            }
                            finally
                            {
                                lock (lockObj)
                                {
                                    isRunning = false;
                                }
                            }
                        });

                        _ = Task.Run(CleanupLoop);

                        return true;
                    }
                    catch
                    {
                        session?.Dispose();
                        session = null;
                        isRunning = false;
                        return false;
                    }
                }
            }

            public bool Stop()
            {
                lock (lockObj)
                {
                    if (!isRunning)
                        return true;

                    try
                    {
                        session?.Dispose();
                    }
                    finally
                    {
                        session = null;
                        isRunning = false;
                        _recentProcesses.Clear();
                        _scannedPaths.Clear();
                        _processPathCache.Clear();
                    }
                    return true;
                }
            }

            public bool IsRun()
            {
                lock (lockObj)
                {
                    return isRunning;
                }
            }

            private static async Task CleanupLoop()
            {
                while (isRunning)
                {
                    await Task.Delay(TimeSpan.FromSeconds(30));
                    
                    var cutoff = DateTime.UtcNow - _dedupWindow;
                    foreach (var key in _recentProcesses.Where(x => x.Value < cutoff).Select(x => x.Key).ToList())
                    {
                        _recentProcesses.TryRemove(key, out _);
                    }

                    var pathCutoff = DateTime.UtcNow - _pathCacheWindow;
                    foreach (var key in _scannedPaths.Where(x => x.Value < pathCutoff).Select(x => x.Key).ToList())
                    {
                        _scannedPaths.TryRemove(key, out _);
                    }

                    var processPathCutoff = DateTime.UtcNow - _processPathCacheWindow;
                    foreach (var key in _processPathCache.Where(x => x.Value.timestamp < processPathCutoff).Select(x => x.Key).ToList())
                    {
                        _processPathCache.TryRemove(key, out _);
                    }
                }
            }

            private static void OnNewProcess(ProcessTraceData data, InterceptCallBack interceptCallBack)
            {
                try
                {
                    if (data.ProcessID is 0 or 4)
                        return;

                    var now = DateTime.UtcNow;
                    
                    if (_recentProcesses.TryGetValue(data.ProcessID, out var lastSeen))
                    {
                        if (now - lastSeen < _dedupWindow)
                            return;
                    }
                    _recentProcesses[data.ProcessID] = now;

                    string? path = null;
                    try
                    {
                        if (_processPathCache.TryGetValue(data.ProcessID, out var cachedEntry))
                        {
                            path = cachedEntry.path;
                        }
                        else
                        {
                            using var process = Process.GetProcessById(data.ProcessID);
                            path = process.MainModule?.FileName;
                            _processPathCache[data.ProcessID] = (path, now);
                        }
                    }
                    catch
                    {
                        return;
                    }

                    if (string.IsNullOrEmpty(path) || TrustManager.IsPathTrusted(path))
                        return;

                    if (_scannedPaths.TryGetValue(path, out var lastScanned))
                    {
                        if (now - lastScanned < _pathCacheWindow)
                            return;
                    }
                    _scannedPaths[path] = now;

                    _ = Task.Run(() =>
                    {
                        try
                        {
                            var (isVirus, result) = Helper.ScanEngine.ModelEngineScan.ScanFile(path);
                            if (!isVirus)
                                return;

                            try
                            {
                                using var proc = Process.GetProcessById(data.ProcessID);
                                if (!proc.HasExited)
                                {
                                    proc.Kill();
                                }
                                _ = QuarantineManager.AddToQuarantine(path, result);
                                interceptCallBack(true, path, Name);
                            }
                            catch
                            {
                                interceptCallBack(false, path, Name);
                            }
                        }
                        catch { }
                    });
                }
                catch { }
            }
        }
    }
}
