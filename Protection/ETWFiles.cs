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
            public const string Name = "Files";

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

                        monitoringSession = new TraceEventSession("Xdows-Security", null);
                        monitoringSession.EnableKernelProvider(
                            KernelTraceEventParser.Keywords.FileIO |
                            KernelTraceEventParser.Keywords.FileIOInit,
                            KernelTraceEventParser.Keywords.None
                        );

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.FileIOCreate += (data) => OnFileCreate(data, interceptCallBack);

                        isRunning = true;
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

            private void OnFileCreate(FileIOCreateTraceData data, InterceptCallBack interceptCallBack)
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
            private readonly List<string> TempList = [];
            private void HandleCreatedFile(string filePath, int creatorProcessId, InterceptCallBack interceptCallBack)
            {
                try
                {
                    var (isFileVirus, fileResult) = Helper.ScanEngine.ModelEngineScan.ScanFile(filePath);
                    if (isFileVirus)
                    {
                        bool isInTempList = TempList.Contains(filePath);
                        TempList.Add(filePath);
                        try
                        {
                            TerminateProcessByPath(filePath);
                        }
                        catch { }
                        try
                        {
                            _ = QuarantineManager.AddToQuarantine(filePath, fileResult);
                            if (!isInTempList)
                            {
                                interceptCallBack(true, filePath, Name);
                            }
                        }
                        catch
                        {
                            if (!isInTempList)
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
