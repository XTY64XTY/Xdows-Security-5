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
            public const string Name = "Process";
            string IProtectionModel.Name => Name;

            private static readonly ConcurrentDictionary<int, DateTime> _recentProcesses = new();
            private static readonly ConcurrentDictionary<string, DateTime> _scannedPaths = new();
            private static readonly TimeSpan _dedupWindow = TimeSpan.FromSeconds(5);
            private static readonly TimeSpan _pathCacheWindow = TimeSpan.FromMinutes(1);

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

                        monitoringSession = new TraceEventSession("Xdows-Security", null);
                        monitoringSession.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.ProcessStart += (data) => OnNewProcess(data, interceptCallBack);

                        _ = Task.Run(() =>
                        {
                            try
                            {
                                monitoringSession.Source.Process();
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
                        monitoringSession?.Dispose();
                        monitoringSession = null;
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
                        monitoringSession?.Dispose();
                    }
                    finally
                    {
                        monitoringSession = null;
                        isRunning = false;
                        _recentProcesses.Clear();
                        _scannedPaths.Clear();
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
                }
            }

            private static async void OnNewProcess(ProcessTraceData data, InterceptCallBack interceptCallBack)
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
                        using var process = Process.GetProcessById(data.ProcessID);
                        path = process.MainModule?.FileName;
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

                    await Task.Run(() =>
                    {
                        var (isVirus, result) = Helper.ScanEngine.ModelEngineScan.ScanFile(path);
                        if (!isVirus)
                            return;

                        try
                        {
                            using var proc = Process.GetProcessById(data.ProcessID);
                            proc.Kill();
                            _ = QuarantineManager.AddToQuarantine(path, result);
                            interceptCallBack(true, path, Name);
                        }
                        catch
                        {
                            interceptCallBack(false, path, Name);
                        }
                    });
                }
                catch { }
            }
        }
    }
}
