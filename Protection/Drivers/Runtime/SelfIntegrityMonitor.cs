using System.Security.Cryptography;

namespace Protection;

public enum SelfIntegrityIssue
{
    /// <summary>磁盘上的主程序已被替换或修改。</summary>
    ExecutableReplaced,

    /// <summary>驱动服务不再处于运行状态。</summary>
    DriverServiceStopped,

    /// <summary>驱动仍在，但桥接/自保护状态不再是 Protected。</summary>
    BridgeLost
}

public sealed record SelfIntegrityViolation(SelfIntegrityIssue Issue, string Detail, DateTimeOffset DetectedAt);

/// <summary>
/// 定期确认三件事：磁盘上的主程序没被替换、驱动服务还在跑、桥接仍处于受保护状态。
///
/// 只检测、只上报，不尝试自动修复——用户态没有可靠手段把被摘掉的内核回调装回去，
/// 擅自重启服务反而会把「防护仍在工作」变成「防护彻底消失」。
/// </summary>
public sealed class SelfIntegrityMonitor : IDisposable
{
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(5);

    private readonly TimeSpan _interval;
    private readonly Func<bool> _shouldBeProtected;
    private readonly string _executablePath;
    private readonly string _baselineHash;
    private readonly CancellationTokenSource _cts = new();

    // 同一个问题只报一次，恢复后重新布防，避免每 5 秒刷一条相同的日志。
    private readonly HashSet<SelfIntegrityIssue> _reported = [];

    private Task? _loop;

    public SelfIntegrityMonitor(Func<bool> shouldBeProtected, TimeSpan? interval = null)
    {
        _shouldBeProtected = shouldBeProtected;
        _interval = interval ?? DefaultInterval;
        _executablePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Unable to determine the current process image path.");
        _baselineHash = ComputeHash(_executablePath);
    }

    public event Action<SelfIntegrityViolation>? ViolationDetected;

    public void Start()
    {
        _loop ??= Task.Run(() => RunAsync(_cts.Token));
    }

    private async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            CheckExecutable();
            CheckDriver();
        }
    }

    private void CheckExecutable()
    {
        string current = ComputeHash(_executablePath);
        if (string.Equals(current, _baselineHash, StringComparison.Ordinal))
        {
            _reported.Remove(SelfIntegrityIssue.ExecutableReplaced);
            return;
        }

        Report(
            SelfIntegrityIssue.ExecutableReplaced,
            $"Executable image changed on disk (expected {_baselineHash}, found {current}).");
    }

    /// <summary>
    /// 驱动相关的两项只在「用户期望防护开启」时检查，否则手动关闭防护会立刻变成误报。
    /// </summary>
    private void CheckDriver()
    {
        if (!_shouldBeProtected())
        {
            _reported.Remove(SelfIntegrityIssue.DriverServiceStopped);
            _reported.Remove(SelfIntegrityIssue.BridgeLost);
            return;
        }

        DriverServiceSnapshot service = DriverServiceControl.Query(DriverPackageLocator.ServiceName);
        if (service.IsRunning)
        {
            _reported.Remove(SelfIntegrityIssue.DriverServiceStopped);
        }
        else
        {
            Report(
                SelfIntegrityIssue.DriverServiceStopped,
                $"Driver service is {service.State}. {service.Detail}");
        }

        DriverProtectionRuntimeStatus status = DriverProtection.QueryRuntimeStatus();
        if (status == DriverProtectionRuntimeStatus.Protected)
        {
            _reported.Remove(SelfIntegrityIssue.BridgeLost);
        }
        else
        {
            Report(
                SelfIntegrityIssue.BridgeLost,
                $"Driver runtime status is {status}; self-protection is no longer confirmed.");
        }
    }

    private void Report(SelfIntegrityIssue issue, string detail)
    {
        if (!_reported.Add(issue))
            return;

        ViolationDetected?.Invoke(new SelfIntegrityViolation(issue, detail, DateTimeOffset.Now));
    }

    private static string ComputeHash(string path)
    {
        using FileStream stream = File.Open(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();

        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // 退出路径上等不到循环结束也无所谓，进程马上就没了。
        }
    }
}
