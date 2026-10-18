using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Protection;

public sealed record UntrustedKernelDriver(
    string ServiceName,
    string? ImagePath,
    string Reason,
    DateTimeOffset DetectedAt);

/// <summary>
/// 监视「新出现的、签名不可信的内核驱动服务」。
///
/// 只用文档化接口：<c>EnumServicesStatusEx</c> 枚举运行中的驱动服务，
/// <c>QueryServiceConfig</c> 取映像路径，<c>WinVerifyTrust</c> 校验嵌入签名。
///
/// 已知边界：看不到「没有服务记录、被直接映射进内核」的驱动——那需要
/// <c>PsSetLoadImageNotifyRoutine</c>，属于驱动侧能力，用户态无法覆盖。
/// 启动时已经存在的驱动不参与判定，只报「新出现且签名不可信」的。
/// </summary>
public sealed class KernelDriverMonitor : IDisposable
{
    private const uint ScManagerConnect = 0x0001;
    private const int ScEnumProcessInfo = 0;
    private const uint ServiceDriver = 0x0000000B;
    private const uint ServiceStateAll = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceQueryConfig = 0x0001;
    private const int ErrorMoreData = 234;

    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(2);

    // 自己的驱动是自签测试证书，WinVerifyTrust 必然判为不受信，不能当成可疑项。
    private static readonly HashSet<string> SelfDriverServices = new(StringComparer.OrdinalIgnoreCase)
    {
        DriverPackageLocator.ServiceName,
        DriverPackageLocator.BootFilterServiceName
    };

    private readonly TimeSpan _interval;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<string> _knownServices = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reportedServices = new(StringComparer.OrdinalIgnoreCase);

    private Task? _loop;

    public KernelDriverMonitor(TimeSpan? interval = null)
    {
        _interval = interval ?? DefaultInterval;
    }

    public event Action<UntrustedKernelDriver>? UntrustedDriverDetected;

    public void Start()
    {
        if (_loop is not null)
            return;

        // 基线：启动时已经在跑的驱动都是装机时装的，报出来只有噪音。
        foreach (string name in EnumerateRunningDriverServices())
            _knownServices.Add(name);

        _loop = Task.Run(() => RunAsync(_cts.Token));
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

            Scan();
        }
    }

    private void Scan()
    {
        foreach (string serviceName in EnumerateRunningDriverServices())
        {
            if (!_knownServices.Add(serviceName))
                continue;

            if (SelfDriverServices.Contains(serviceName))
                continue;

            string? imagePath = TryGetImagePath(serviceName);
            string? normalized = NormalizeImagePath(imagePath);

            if (normalized is null)
            {
                Report(serviceName, imagePath, "The driver image path could not be resolved from its service configuration.");
                continue;
            }

            if (!IsSignatureTrusted(normalized))
            {
                Report(serviceName, normalized, "The driver image is not signed by a trusted publisher.");
            }
        }
    }

    private void Report(string serviceName, string? imagePath, string reason)
    {
        if (!_reportedServices.Add(serviceName))
            return;

        UntrustedDriverDetected?.Invoke(new UntrustedKernelDriver(
            serviceName,
            imagePath,
            reason,
            DateTimeOffset.Now));
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

    /// <summary>枚举处于 RUNNING 的内核驱动服务名。</summary>
    private static List<string> EnumerateRunningDriverServices()
    {
        var result = new List<string>();

        using SafeServiceHandle manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
            return result;

        uint resumeHandle = 0;
        NativeMethods.EnumServicesStatusEx(
            manager,
            ScEnumProcessInfo,
            ServiceDriver,
            ServiceStateAll,
            IntPtr.Zero,
            0,
            out uint bytesNeeded,
            out _,
            ref resumeHandle,
            null);

        if (bytesNeeded == 0)
            return result;

        // 多给一点余量，避免枚举过程中服务数变化导致缓冲区不足。
        uint bufferSize = bytesNeeded + 64 * 1024;
        IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);

        try
        {
            resumeHandle = 0;
            while (true)
            {
                bool ok = NativeMethods.EnumServicesStatusEx(
                    manager,
                    ScEnumProcessInfo,
                    ServiceDriver,
                    ServiceStateAll,
                    buffer,
                    bufferSize,
                    out bytesNeeded,
                    out uint returned,
                    ref resumeHandle,
                    null);

                if (bytesNeeded > bufferSize)
                    break;

                int entrySize = Marshal.SizeOf<EnumServiceStatusProcess>();
                for (int i = 0; i < returned; i++)
                {
                    IntPtr entryPointer = IntPtr.Add(buffer, i * entrySize);
                    var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(entryPointer);

                    if (entry.ServiceStatusProcess.CurrentState != ServiceRunning)
                        continue;

                    string? serviceName = Marshal.PtrToStringUni(entry.ServiceName);
                    if (!string.IsNullOrEmpty(serviceName))
                        result.Add(serviceName);
                }

                if (ok)
                    break;

                if (Marshal.GetLastWin32Error() != ErrorMoreData)
                    break;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static string? TryGetImagePath(string serviceName)
    {
        using SafeServiceHandle manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
            return null;

        using SafeServiceHandle service = NativeMethods.OpenService(manager, serviceName, ServiceQueryConfig);
        if (service.IsInvalid)
            return null;

        NativeMethods.QueryServiceConfig(service, IntPtr.Zero, 0, out uint needed);
        if (needed == 0)
            return null;

        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!NativeMethods.QueryServiceConfig(service, buffer, needed, out _))
                return null;

            var config = Marshal.PtrToStructure<QueryServiceConfig>(buffer);
            return Marshal.PtrToStringUni(config.BinaryPathName);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// 把服务配置里的映像路径变成文件系统路径：去掉 <c>\??\</c> 前缀，
    /// 展开 <c>\SystemRoot\</c>，剥掉外层引号。
    /// </summary>
    private static string? NormalizeImagePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        string path = raw.Trim().Trim('"');
        if (path.Length == 0)
            return null;

        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            path = path[4..];
        }
        else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            path = Path.Combine(windows, path[@"\SystemRoot\".Length..]);
        }

        return path;
    }

    /// <summary>
    /// 用 WinVerifyTrust 校验嵌入签名。返回 true 只代表「签名链可信」，
    /// 不代表这个驱动安全——判定可信的驱动仍可能是恶意的，那属于行为判定的范畴。
    /// </summary>
    private static bool IsSignatureTrusted(string path)
    {
        if (!File.Exists(path))
            return false;

        IntPtr filePathPointer = Marshal.StringToHGlobalUni(path);
        IntPtr fileInfoPointer = IntPtr.Zero;
        IntPtr trustDataPointer = IntPtr.Zero;

        try
        {
            var fileInfo = new WintrustFileInfo
            {
                Size = (uint)Marshal.SizeOf<WintrustFileInfo>(),
                FilePath = filePathPointer
            };

            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var trustData = new WintrustData
            {
                Size = (uint)Marshal.SizeOf<WintrustData>(),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                File = fileInfoPointer,
                StateAction = WtdStateActionVerify
            };

            trustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustData>());
            Marshal.StructureToPtr(trustData, trustDataPointer, false);

            Guid action = WintrustActionGenericVerifyV2;
            uint result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, trustDataPointer);

            // 关闭状态，释放 WinVerifyTrust 内部持有的资源。
            trustData.StateAction = WtdStateActionClose;
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            action = WintrustActionGenericVerifyV2;
            NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, trustDataPointer);

            return result == 0;
        }
        finally
        {
            if (trustDataPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(trustDataPointer);

            if (fileInfoPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(fileInfoPointer);

            Marshal.FreeHGlobal(filePathPointer);
        }
    }

    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint Size;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public ServiceStatusProcess ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfig
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseServiceHandle(handle);
        }
    }

    private static class NativeMethods
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeServiceHandle OpenSCManager(
            string? machineName,
            string? databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeServiceHandle OpenService(
            SafeServiceHandle serviceControlManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumServicesStatusEx(
            SafeServiceHandle serviceControlManager,
            int infoLevel,
            uint serviceType,
            uint serviceState,
            IntPtr services,
            uint bufferSize,
            out uint bytesNeeded,
            out uint servicesReturned,
            ref uint resumeHandle,
            string? groupName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceConfig(
            SafeServiceHandle service,
            IntPtr serviceConfig,
            uint bufferSize,
            out uint bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(nint service);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint WinVerifyTrust(
            IntPtr windowHandle,
            ref Guid actionId,
            IntPtr trustData);
    }
}
