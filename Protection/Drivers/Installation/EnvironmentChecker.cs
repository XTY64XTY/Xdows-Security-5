using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Protection;

public enum DriverEnvironmentCheckStatus
{
    Passed,
    Failed
}

/// <summary>
/// 环境检测的四项检查。成员名同时是资源键片段：
/// <c>DriverEnvironmentPage_Check_{Id}</c>、<c>_Ok_{Id}</c>。
/// </summary>
public enum DriverEnvironmentCheckId
{
    Administrator,
    TestSigning,
    FileIntegrity,
    DriverStarted
}

/// <summary>
/// 失败时的提示类别。决定界面给哪一句说明、按钮做什么。
/// </summary>
public enum DriverEnvironmentCheckHint
{
    None,

    /// <summary>设备环境不满足，只能重装或改用兼容防护。</summary>
    Unrepairable,

    /// <summary>驱动只是没启动，引导用户去开驱动防护即可。</summary>
    DriverNotStarted,

    /// <summary>测试模式已写入 BCD，但当前内核尚未生效，需要重启；此时可以撤销。</summary>
    TestSigningPendingRestart
}

/// <summary>单项检查结果。只描述事实，文案由页面按 Id + Status + Hint 查资源。</summary>
public sealed record DriverEnvironmentCheckItem(
    DriverEnvironmentCheckId Id,
    DriverEnvironmentCheckStatus Status,
    string? Diagnostic = null,
    DriverEnvironmentCheckHint Hint = DriverEnvironmentCheckHint.None)
{
    public bool Passed => Status == DriverEnvironmentCheckStatus.Passed;

    /// <summary>四项检查里只有「测试模式」可以自动修改，其余失败都属于环境不满足。</summary>
    public bool CanRepair => Id == DriverEnvironmentCheckId.TestSigning;
}

public sealed record DriverEnvironmentReport(
    IReadOnlyList<DriverEnvironmentCheckItem> Items,
    DateTimeOffset CheckedAt)
{
    public bool IsHealthy => Items.All(i => i.Passed);

    public int FailedCount => Items.Count(i => !i.Passed);
}

public static class DriverEnvironmentChecker
{
    /// <summary>SystemInformationClass = SystemCodeIntegrityInformation（winternl.h，数值 103）。</summary>
    private const int SystemCodeIntegrityInformationClass = 103;

    /// <summary>CODEINTEGRITY_OPTION_TESTSIGN：当前内核允许加载测试签名驱动。</summary>
    private const uint CodeIntegrityOptionTestSign = 0x02;

    /// <summary>按页面显示顺序检查四项。</summary>
    public static async Task<DriverEnvironmentReport> CheckAsync(CancellationToken token = default)
    {
        var items = new List<DriverEnvironmentCheckItem>
        {
            CheckAdministrator(),
            await CheckTestSigningAsync(token).ConfigureAwait(false),
            CheckFileIntegrity(),
            CheckDriverStarted()
        };

        return new DriverEnvironmentReport(items, DateTimeOffset.Now);
    }

    private static DriverEnvironmentCheckItem CheckAdministrator()
    {
        bool isAdmin = false;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            // 查询失败按“非管理员”处理：安装或启动驱动时会再报一次权限错误。
        }

        return new DriverEnvironmentCheckItem(
            DriverEnvironmentCheckId.Administrator,
            isAdmin ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            isAdmin ? null : "The current process does not run with administrator rights.");
    }

    /// <summary>
    /// 测试模式分两步看：BCD 里是否写入（bcdedit），以及当前内核是否已经生效
    /// （NtQuerySystemInformation）。两者不一致就是「已设置、待重启」。
    /// </summary>
    private static async Task<DriverEnvironmentCheckItem> CheckTestSigningAsync(CancellationToken token)
    {
        if (IsTestSigningActive())
        {
            return new DriverEnvironmentCheckItem(
                DriverEnvironmentCheckId.TestSigning,
                DriverEnvironmentCheckStatus.Passed,
                "Windows test-signing is active.");
        }

        CommandResult result = await DriverCommandLine
            .RunAsync("bcdedit", ["/enum", "{current}"], token)
            .ConfigureAwait(false);

        bool? configured = result.Started ? TryReadTestSigning(result.Output) : null;

        return configured == true
            ? new DriverEnvironmentCheckItem(
                DriverEnvironmentCheckId.TestSigning,
                DriverEnvironmentCheckStatus.Failed,
                "Test-signing is configured in BCD but not active yet.",
                DriverEnvironmentCheckHint.TestSigningPendingRestart)
            : new DriverEnvironmentCheckItem(
                DriverEnvironmentCheckId.TestSigning,
                DriverEnvironmentCheckStatus.Failed,
                result.Started
                    ? "Test-signing is not enabled."
                    : "Unable to run bcdedit.");
    }

    /// <summary>
    /// 从 bcdedit 输出里读 testsigning 的值，找不到返回 null。
    /// 只认以 <c>testsigning</c> 开头的那一行——整段输出里还有别的 "Yes"
    /// （例如 hypervisorlaunchtype），用 Contains("Yes") 判断会误判。
    /// </summary>
    private static bool? TryReadTestSigning(string output)
    {
        foreach (string line in output.Split('\n'))
        {
            string trimmed = line.Trim();
            int separator = trimmed.IndexOfAny([' ', '\t']);
            if (separator <= 0)
                continue;

            if (!trimmed[..separator].Equals("testsigning", StringComparison.OrdinalIgnoreCase))
                continue;

            return trimmed[separator..].Trim().Equals("Yes", StringComparison.OrdinalIgnoreCase);
        }

        return null;
    }

    /// <summary>
    /// 当前内核是否允许测试签名驱动。BCD 改动必须重启才生效，所以这个状态
    /// 与 bcdedit 的持久配置可能不一致，正是「待重启」的判定依据。
    /// </summary>
    private static bool IsTestSigningActive()
    {
        var info = new SystemCodeIntegrityInformation
        {
            Length = (uint)Marshal.SizeOf<SystemCodeIntegrityInformation>()
        };

        int status = NtQuerySystemInformation(
            SystemCodeIntegrityInformationClass,
            ref info,
            (int)info.Length,
            out _);

        return status >= 0 && (info.CodeIntegrityOptions & CodeIntegrityOptionTestSign) != 0;
    }

    /// <summary>
    /// 驱动包文件是否齐全。主驱动与引导过滤驱动都必须在程序目录的 Driver\ 下，
    /// 缺一个都装不起来。
    /// </summary>
    private static DriverEnvironmentCheckItem CheckFileIntegrity()
    {
        string driverDirectory = DriverPackageLocator.DriverDirectory;
        string bootFilterDirectory = Path.Combine(driverDirectory, "BootFilter");

        string[] required =
        [
            Path.Combine(driverDirectory, DriverPackageLocator.InfName),
            Path.Combine(driverDirectory, DriverPackageLocator.SysName),
            Path.Combine(driverDirectory, DriverPackageLocator.CatName),
            Path.Combine(bootFilterDirectory, DriverPackageLocator.BootFilterInfName),
            Path.Combine(bootFilterDirectory, DriverPackageLocator.BootFilterSysName),
            Path.Combine(bootFilterDirectory, DriverPackageLocator.BootFilterCatName)
        ];

        string[] missing = required
            .Where(path => !File.Exists(path))
            .Select(path => Path.GetRelativePath(AppContext.BaseDirectory, path))
            .ToArray();

        return new DriverEnvironmentCheckItem(
            DriverEnvironmentCheckId.FileIntegrity,
            missing.Length == 0 ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            missing.Length == 0
                ? $"All driver files are present under {Path.GetRelativePath(AppContext.BaseDirectory, driverDirectory)}."
                : $"Missing: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// 驱动是否正常启动：服务处于 RUNNING，且桥接设备可用（已连接或可连接）。
    /// 只装了服务没启动、或服务在跑但设备打不开，都算未正常启动。
    /// </summary>
    private static DriverEnvironmentCheckItem CheckDriverStarted()
    {
        DriverServiceSnapshot service = DriverServiceControl.Query(DriverPackageLocator.ServiceName);
        DriverProtectionRuntimeStatus runtimeStatus = DriverProtection.QueryRuntimeStatus();

        bool started = service.IsRunning &&
            runtimeStatus is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected;

        // 服务没在跑（含未安装）时，用户能做的动作是去开驱动防护，不是重装软件。
        DriverEnvironmentCheckHint hint = service.IsRunning
            ? DriverEnvironmentCheckHint.Unrepairable
            : DriverEnvironmentCheckHint.DriverNotStarted;

        return new DriverEnvironmentCheckItem(
            DriverEnvironmentCheckId.DriverStarted,
            started ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            $"Service: {service.State}; runtime: {runtimeStatus}.",
            started ? DriverEnvironmentCheckHint.None : hint);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemCodeIntegrityInformation
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        ref SystemCodeIntegrityInformation systemInformation,
        int systemInformationLength,
        out int returnLength);
}
