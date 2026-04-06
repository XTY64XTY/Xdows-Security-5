using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using TrustQuarantine;
using static Protection.CallBack;

namespace Protection
{
    public class LegacyProcessProtection : IProtectionModel
    {
        // 感谢 XiaoWeiSecurity 对开源杀毒软件项目（特别是主动防御）的巨大贡献！！

        private static CancellationTokenSource? _cts = null;
        private static Task? _monitorTask = null;
        public const string Name = "Process";
        string IProtectionModel.Name => Name;

        public bool Run(InterceptCallBack toastCallBack)
        {
            Helper.ScanEngine.ModelEngineScan.Initialize();

            if (IsRun())
                return true;
            try
            {
                _cts = new CancellationTokenSource();
                _monitorTask = Task.Run(async () => await MonitorNewProcessesLoop(toastCallBack, _cts.Token), _cts.Token);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Stop()
        {
            if (!IsRun())
                return true;
            try
            {
                if (_cts is null || _monitorTask is null)
                    return true;
                try
                {
                    _cts.Cancel();
                    _monitorTask.Wait(2000);
                }
                catch { }
            }
            catch
            {
                return false;
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
                _monitorTask = null;
            }

            return true;
        }

        public bool IsRun()
        {
            return _cts is { IsCancellationRequested: false };
        }

        private static readonly List<int> _oldPids = [];

        private static async Task MonitorNewProcessesLoop(InterceptCallBack interceptCallBack, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var currentPids = GetProcessIdList();
                    if (_oldPids.Count == 0)
                    {
                        _oldPids.AddRange(currentPids);
                    }
                    else
                    {
                        var newPids = currentPids.Except(_oldPids).Distinct().ToList();

                        foreach (int pid in newPids)
                        {
                            string path = ProcessPidToPath(pid);
                            if (string.IsNullOrEmpty(path))
                                continue;

                            if (TrustManager.IsPathTrusted(path))
                                continue;

                            var (isVirus, result) = Helper.ScanEngine.ModelEngineScan.ScanFile(path);

                            if (isVirus)
                            {
                                try
                                {
                                    using var proc = Process.GetProcessById(pid);
                                    proc.Kill();
                                    _ = QuarantineManager.AddToQuarantine(path, result);
                                    interceptCallBack(true, path, Name);
                                }
                                catch
                                {
                                    interceptCallBack(false, path, Name);
                                }
                            }
                        }

                        _oldPids.Clear();
                        _oldPids.AddRange(currentPids);
                    }
                }
                catch
                {
                }
                try
                {
                    await Task.Delay(10, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private static List<int> GetProcessIdList()
        {
            return ProcessMonitorHelper.GetProcessIdList();
        }

        private static string ProcessPidToPath(int pid)
        {
            return ProcessMonitorHelper.GetProcessPathById(pid);
        }
    }
}
