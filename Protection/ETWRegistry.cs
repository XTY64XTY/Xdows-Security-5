using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using TrustQuarantine;
using static Protection.CallBack;

namespace Protection
{
    public partial class ETW
    {
        public class RegistryProtection : IProtectionModel
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;
            private static TraceEventSession? session;
            public const string Name = "Registry";

            string IProtectionModel.Name => Name;

            public bool Run(InterceptCallBack interceptCallBack)
            {
                lock (lockObj)
                {
                    if (isRunning)
                        return true;

                    try
                    {
                        Helper.ScanEngine.ModelEngineScan.Initialize();

                        session = new TraceEventSession($"Xdows-Security-{Name}", null);
                        session.EnableKernelProvider(
                            KernelTraceEventParser.Keywords.Registry
                        );

                        var parser = new KernelTraceEventParser(session.Source);
                        parser.RegistryCreate += (data) => OnRegistryChanged(data, interceptCallBack);
                        parser.RegistrySetValue += (data) => OnRegistryChanged(data, interceptCallBack);
                        parser.RegistryDelete += (data) => OnRegistryChanged(data, interceptCallBack);

                        isRunning = true;
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

                        return true;
                    }
                    catch
                    {
                        session?.Dispose();
                        session = null;
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

            private static void OnRegistryChanged(RegistryTraceData data, InterceptCallBack interceptCallBack)
            {
                try
                {
                    if (data.ProcessID is 0 or 4 || data.ProcessID == Environment.ProcessId || data.KeyName == string.Empty)
                        return;
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
                    string registryScanResult = new Xdows_Local.RegistryScan().Scan(data.KeyName);
                    if (registryScanResult != string.Empty)
                    {
                        try
                        {
                            using var proc = Process.GetProcessById(data.ProcessID);
                            proc.Kill();
                            _ = QuarantineManager.AddToQuarantine(path, registryScanResult);
                            interceptCallBack(true, path, Name);

                        }
                        catch
                        {
                            interceptCallBack(false, path, Name);
                        }
                        return;

                    }
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
                }
                catch { }
            }
        }
    }
}
