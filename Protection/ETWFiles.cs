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
        public class FilesProtection : IProtectionModel
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;
            private static TraceEventSession? session;
            public const string Name = "Files";

            private static readonly HashSet<string> _notifiedFiles = new(StringComparer.OrdinalIgnoreCase);
            private static readonly Lock _notifiedFilesLock = new();

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
                            KernelTraceEventParser.Keywords.FileIO |
                            KernelTraceEventParser.Keywords.FileIOInit,
                            KernelTraceEventParser.Keywords.None
                        );

                        var parser = new KernelTraceEventParser(session.Source);
                        parser.FileIOCreate += (data) => OnFileCreate(data, interceptCallBack);

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
                        lock (_notifiedFilesLock)
                        {
                            _notifiedFiles.Clear();
                        }
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

            private static void OnFileCreate(FileIOCreateTraceData data, InterceptCallBack interceptCallBack)
            {
                try
                {
                    string? filePath = data.FileName;
                    if (string.IsNullOrEmpty(filePath) ||
                        data.ProcessID is 0 or 4 ||
                        !Path.Exists(filePath) ||
                        Path.EndsInDirectorySeparator(filePath) ||
                        data.ProcessID == Environment.ProcessId ||
                        filePath.Contains(":\\Windows\\") ||
                        filePath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
                        filePath.Length > 32767)
                        return;

                    if (!IsSuspiciousExtension(filePath))
                        return;

                    string? creatorProcessPath = null;
                    try
                    {
                        using var process = Process.GetProcessById(data.ProcessID);
                        creatorProcessPath = process.MainModule?.FileName;
                    }
                    catch
                    {
                        return;
                    }

                    if (string.IsNullOrEmpty(creatorProcessPath) || TrustManager.IsPathTrusted(creatorProcessPath))
                        return;

                    HandleCreatedFile(filePath, data.ProcessID, interceptCallBack);
                }
                catch { }
            }

            private static void HandleCreatedFile(string filePath, int creatorProcessId, InterceptCallBack interceptCallBack)
            {
                try
                {
                    var (isFileVirus, fileResult) = Helper.ScanEngine.ModelEngineScan.ScanFile(filePath);
                    if (isFileVirus)
                    {
                        bool alreadyNotified;
                        lock (_notifiedFilesLock)
                        {
                            alreadyNotified = !_notifiedFiles.Add(filePath);
                        }

                        try
                        {
                            TerminateProcessByPath(filePath);
                        }
                        catch { }

                        try
                        {
                            _ = QuarantineManager.AddToQuarantine(filePath, fileResult);
                            if (!alreadyNotified)
                            {
                                interceptCallBack(true, filePath, Name);
                            }
                        }
                        catch
                        {
                            if (!alreadyNotified)
                            {
                                interceptCallBack(false, filePath, Name);
                            }
                        }
                    }
                }
                catch { }
            }

            private static void TerminateProcessByPath(string filePath)
            {
                try
                {
                    var processes = Process.GetProcesses();
                    foreach (var proc in processes)
                    {
                        try
                        {
                            if (proc.MainModule?.FileName?.Equals(filePath, StringComparison.OrdinalIgnoreCase) == true)
                            {
                                proc.Kill();
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }

            private static bool IsSuspiciousExtension(string filePath)
            {
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                return ext is ".exe" or ".dll" or ".sys" or ".scr" or ".bat"
                    or ".cmd" or ".ps1" or ".vbs" or ".js" or ".jse"
                    or ".wsf" or ".msi" or ".msp" or ".cab" or ".zip"
                    or ".rar" or ".7z" or ".iso" or ".doc" or ".docx"
                    or ".xls" or ".xlsx" or ".ppt" or ".pptx" or ".pdf";
            }
        }
    }
}
