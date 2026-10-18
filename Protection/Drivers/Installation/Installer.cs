using Microsoft.Windows.Storage;
using Xdows_Model_Config;

namespace Protection;

public sealed record DriverRepairResult(bool Success, string Message);

public static class DriverInstaller
{
    /// <summary>
    /// 执行某一项检查的自动修复。四项检查里只有「测试模式」可以自动开启，
    /// 其余失败都属于设备环境不满足，只能重装或改用兼容防护。
    /// </summary>
    public static Task<DriverRepairResult> RepairAsync(
        DriverEnvironmentCheckItem item,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(item);

        return item.Id switch
        {
            // 已写入 BCD 但还没重启时，同一个按钮的作用反过来：撤销这次修改。
            DriverEnvironmentCheckId.TestSigning => item.Hint == DriverEnvironmentCheckHint.TestSigningPendingRestart
                ? DisableTestSigningAsync(token)
                : EnableTestSigningAsync(token),

            _ => Task.FromResult(new DriverRepairResult(
                false,
                "Only test-signing can be repaired automatically. Reinstall the application or enable compatibility protection."))
        };
    }

    /// <summary>
    /// 开启测试模式。修改后必须重启才生效，所以成功时返回的是「已设置，需要重启」。
    /// </summary>
    private static async Task<DriverRepairResult> EnableTestSigningAsync(CancellationToken token)
    {
        CommandResult result = await DriverCommandLine
            .RunAsync("bcdedit", ["/set", "testsigning", "on"], token)
            .ConfigureAwait(false);

        return result.Success
            ? new DriverRepairResult(
                true,
                "Test-signing has been enabled. Restart Windows, then enable driver protection again.")
            : new DriverRepairResult(
                false,
                $"Failed to enable test-signing: {result.ShortOutput}");
    }

    /// <summary>
    /// 撤销尚未生效的测试模式设置。与开启一样，重启后才完全生效。
    /// </summary>
    private static async Task<DriverRepairResult> DisableTestSigningAsync(CancellationToken token)
    {
        CommandResult result = await DriverCommandLine
            .RunAsync("bcdedit", ["/set", "testsigning", "off"], token)
            .ConfigureAwait(false);

        return result.Success
            ? new DriverRepairResult(
                true,
                "Test-signing has been disabled. Restart Windows to apply the change.")
            : new DriverRepairResult(
                false,
                $"Failed to disable test-signing: {result.ShortOutput}");
    }

    public static Task<DriverRepairResult> InstallAndStartDriverAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.InstallAndStartAsync(token);
    }

    public static Task<DriverRepairResult> EnsureInstalledAndStartedAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.EnsureReadyAsync(token);
    }

    public static Task<DriverRepairResult> EnsureBootFilterInstalledAndStartedAsync(CancellationToken token = default)
    {
        return BootFilterLoadWorkflow.EnsureReadyAsync(token);
    }

    public static Task<DriverRepairResult> UninstallDriverAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.UninstallAsync(token);
    }

    public static Task<DriverRepairResult> StartServiceAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.StartAsync(token);
    }

    public static Task<DriverRepairResult> RestartBridgeAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.RestartBridgeAsync(token);
    }

    public static Task<DriverRepairResult> CopyModelAssetsAsync(CancellationToken token = default)
    {
        return Task.Run(() =>
        {
            string outputDirectory = AppContext.BaseDirectory;
            Directory.CreateDirectory(outputDirectory);

            // 原生 DLL 与运行时依赖留在程序集目录；模型与模型清单按 <程序集目录>\Models\
            // 分发（布局约定见 Xdows-Model 的 ModelLayout），不能摊平到根目录。
            string[] flatAssets =
            [
                "Xdows-Model-Native.dll",
                "onnxruntime.dll",
                "onnxruntime_providers_shared.dll"
            ];

            var targets = new List<string>(flatAssets.Length + ModelLayout.RequiredFileNames.Count);
            targets.AddRange(flatAssets);
            foreach (string model in ModelLayout.RequiredFileNames)
                targets.Add(ModelLayout.RelativePath(model));

            var ready = new List<string>();
            var missing = new List<string>();
            var failed = new List<string>();

            foreach (string relativePath in targets)
            {
                token.ThrowIfCancellationRequested();
                string targetPath = Path.Combine(outputDirectory, relativePath);
                if (File.Exists(targetPath))
                {
                    ready.Add(relativePath);
                    continue;
                }

                string? source = FindAsset(relativePath);
                if (source is null)
                {
                    missing.Add(relativePath);
                    continue;
                }

                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                    File.Copy(source, targetPath, overwrite: false);
                    ready.Add(relativePath);
                }
                catch (IOException ex)
                {
                    failed.Add($"{relativePath}: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    failed.Add($"{relativePath}: {ex.Message}");
                }
            }

            if (missing.Count > 0 || failed.Count > 0)
            {
                var parts = new List<string>();
                if (ready.Count > 0)
                    parts.Add($"Ready: {string.Join(", ", ready)}");
                if (missing.Count > 0)
                    parts.Add($"missing: {string.Join(", ", missing)}");
                if (failed.Count > 0)
                    parts.Add($"failed: {string.Join("; ", failed)}");
                string message = string.Join("; ", parts) + ".";
                return new DriverRepairResult(false, message);
            }

            return new DriverRepairResult(true, $"Model assets are ready in {outputDirectory}.");
        }, token);
    }

    /// <summary>
    /// 查找待补齐的资产。<paramref name="relativePath"/> 是相对程序集目录的路径
    /// （模型为 <c>Models\xxx.onnx</c>，原生 DLL 与运行时依赖就是文件名本身）。
    /// 依次尝试：标准相对路径、程序集目录下的扁平旧位置、开发机 LocalSettings 里
    /// 显式配置的 ModelSourceRoot 递归搜索。
    /// </summary>
    private static string? FindAsset(string relativePath)
    {
        string standardCandidate = Path.Combine(AppContext.BaseDirectory, relativePath);
        if (File.Exists(standardCandidate))
            return standardCandidate;

        // 兼容模型直接摊在程序集目录的旧部署。
        string fileName = Path.GetFileName(relativePath);
        string legacyCandidate = Path.Combine(AppContext.BaseDirectory, fileName);
        if (!string.Equals(legacyCandidate, standardCandidate, StringComparison.OrdinalIgnoreCase) &&
            File.Exists(legacyCandidate))
        {
            return legacyCandidate;
        }

        try
        {
            var localSettings = ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security").LocalSettings;
            if (localSettings.Values.TryGetValue("ModelSourceRoot", out var raw) &&
                raw is string modelRoot &&
                !string.IsNullOrWhiteSpace(modelRoot) &&
                Directory.Exists(modelRoot))
            {
                return Directory
                    .EnumerateFiles(modelRoot, fileName, SearchOption.AllDirectories)
                    .FirstOrDefault();
            }
        }
        catch
        {
            // 设置读取失败时静默回退：不阻塞驱动安装流程
        }

        return null;
    }
}

internal static class BootFilterLoadWorkflow
{
    public static async Task<DriverRepairResult> EnsureReadyAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        DriverPackage? package = DriverPackageLocator.FindBootFilter();
        if (package is null)
            return new DriverRepairResult(false, DriverPackageLocator.CreateBootFilterNotFoundMessage());

        DriverRepairResult trust = DriverCertificateTrustInstaller.TrustIfPresent(package);
        if (!trust.Success)
            return trust;

        DriverServiceSnapshot service = DriverServiceControl.Query(DriverPackageLocator.BootFilterServiceName);
        if (service.IsMissing)
        {
            DriverRepairResult install = await Task.Run(() =>
            {
                if (!DriverPackageInstaller.Install(package.InfPath, out bool rebootRequired, out string message))
                    return new DriverRepairResult(false, message);

                if (rebootRequired)
                {
                    return new DriverRepairResult(
                        false,
                        "Boot filter package was installed, but a restart is required before the new driver can be loaded. " +
                        "Restart Windows, then start driver protection.");
                }

                return new DriverRepairResult(true, message);
            }, token).ConfigureAwait(false);
            if (!install.Success)
                return install;
            service = DriverServiceControl.Query(DriverPackageLocator.BootFilterServiceName);
        }

        if (service.State == DriverServiceState.Unknown || service.IsMissing)
            return new DriverRepairResult(false, $"Boot filter service is unavailable. {service.Detail}");
        if (!service.IsRunning)
        {
            DriverServiceOperationResult start = DriverServiceControl.Start(DriverPackageLocator.BootFilterServiceName);
            if (!start.Success)
                return new DriverRepairResult(false, start.Message);

            for (int attempt = 0; attempt < 20; attempt++)
            {
                await Task.Delay(250, token).ConfigureAwait(false);
                service = DriverServiceControl.Query(DriverPackageLocator.BootFilterServiceName);
                if (service.IsRunning)
                    break;
            }
        }

        return service.IsRunning
            ? new DriverRepairResult(true, "Boot filter service is installed and running without requiring a restart.")
            : new DriverRepairResult(false, $"Boot filter service did not enter RUNNING state. {service.Detail}");
    }
}

internal static class DriverLoadWorkflow
{
    private const string ServiceName = DriverPackageLocator.ServiceName;
    private const int BridgeProbeAttempts = 24;
    private static readonly TimeSpan BridgeProbeDelay = TimeSpan.FromMilliseconds(500);

    public static Task<DriverRepairResult> InstallAndStartAsync(CancellationToken token)
    {
        return EnsureReadyCoreAsync("Driver package installed, service started, and bridge is reachable", token);
    }

    public static Task<DriverRepairResult> EnsureReadyAsync(CancellationToken token)
    {
        return EnsureReadyCoreAsync("Driver bridge is reachable", token);
    }

    public static Task<DriverRepairResult> StartAsync(CancellationToken token)
    {
        return EnsureReadyCoreAsync("Driver service started and bridge is reachable", token);
    }

    public static Task<DriverRepairResult> RestartBridgeAsync(CancellationToken token)
    {
        return EnsureReadyCoreAsync("Driver bridge is reachable", token);
    }

    public static async Task<DriverRepairResult> UninstallAsync(CancellationToken token)
    {
        DriverLoadSnapshot snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        if (snapshot.Service.State == DriverServiceState.Unknown)
        {
            return new DriverRepairResult(
                false,
                $"Unable to query driver service. {snapshot.Service.Detail}");
        }

        if (snapshot.Service.IsRunning || snapshot.Service.IsTransitioning)
        {
            return new DriverRepairResult(
                false,
                $"Driver service is loaded or changing state ({snapshot.Service.State}). Restart Windows before uninstalling the loaded driver package.");
        }

        CommandResult drivers = await DriverCommandLine
            .RunAsync("pnputil", ["/enum-drivers"], token)
            .ConfigureAwait(false);
        if (!drivers.Success)
            return new DriverRepairResult(false, $"Unable to enumerate drivers: {drivers.ShortOutput}");

        string? publishedName = FindPublishedName(drivers.Output);
        if (string.IsNullOrWhiteSpace(publishedName))
            return new DriverRepairResult(true, "Driver package is not installed.");

        CommandResult delete = await DriverCommandLine
            .RunAsync("pnputil", ["/delete-driver", publishedName, "/uninstall", "/force"], token)
            .ConfigureAwait(false);

        return delete.Success
            ? new DriverRepairResult(true, $"Driver package {publishedName} uninstalled.")
            : new DriverRepairResult(false, $"Driver package uninstall failed: {delete.ShortOutput}");
    }

    /// <summary>
    /// 把驱动从“当前状态”推到“桥接可用”。顺序是有意的，不能调换：
    /// 先判就绪 → 处理已加载的旧版 → 排掉中间态 → 定位包 → 信任证书 →
    /// 安装 → 起服务 → 等桥接。每一步失败都不再往下走，避免把
    /// “驱动已被停掉但新包没装上”这种中间态留下来。
    /// </summary>
    private static async Task<DriverRepairResult> EnsureReadyCoreAsync(
        string successPrefix,
        CancellationToken token)
    {
        DriverLoadSnapshot snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        if (snapshot.BridgeReady)
            return Ready(successPrefix, snapshot);

        DriverPackage? package = null;
        bool packageTrusted = false;

        // 服务在跑：要么是旧版驱动需要就地升级，要么是残留实例只能重启。
        if (snapshot.Service.IsRunning)
        {
            if (snapshot.RuntimeStatus != DriverProtectionRuntimeStatus.NeedsRepair)
                return CreateLoadedWithoutBridgeResult(snapshot);

            // 停旧驱动前先信任证书，否则停完才发现装不上，防护会凭空消失一段时间。
            package = DriverPackageLocator.Find();
            if (package is null)
                return NotFound();

            DriverRepairResult trustOfLegacy = DriverCertificateTrustInstaller.TrustIfPresent(package);
            if (!trustOfLegacy.Success)
                return trustOfLegacy;
            packageTrusted = true;

            DriverRepairResult stopOfLegacy = await TryStopLegacyDriverForUpgradeAsync(token).ConfigureAwait(false);
            if (!stopOfLegacy.Success)
                return stopOfLegacy;

            snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        }

        if (TryDescribeBlockingServiceState(snapshot.Service, out DriverRepairResult? blocked))
            return blocked!;

        package ??= DriverPackageLocator.Find();
        if (package is null)
            return NotFound();

        if (!packageTrusted)
        {
            DriverRepairResult trust = DriverCertificateTrustInstaller.TrustIfPresent(package);
            if (!trust.Success)
                return trust;
        }

        DriverRepairResult install = await InstallPackageAsync(package, token).ConfigureAwait(false);
        if (!install.Success)
            return install;

        DriverRepairResult start = await StartServiceAfterInstallAsync(token).ConfigureAwait(false);
        if (!start.Success)
            return start;

        // 服务进 RUNNING 只说明内核接受了映像，设备对象还要一会儿才出现。
        DriverLoadSnapshot ready = await WaitForBridgeAsync(token).ConfigureAwait(false);
        if (ready.BridgeReady)
            return Ready(successPrefix, ready);

        if (ready.Service.IsRunning)
            return CreateLoadedWithoutBridgeResult(ready);

        return new DriverRepairResult(
            false,
            $"Driver did not become ready. Runtime: {ready.RuntimeStatus}. Service: {ready.Service.Detail}. Install: {install.Message} Start: {start.Message}");
    }

    private static DriverRepairResult Ready(string successPrefix, DriverLoadSnapshot snapshot)
    {
        return new DriverRepairResult(true, $"{successPrefix}: {snapshot.RuntimeStatus}.");
    }

    private static DriverRepairResult NotFound()
    {
        return new DriverRepairResult(false, DriverPackageLocator.CreateNotFoundMessage());
    }

    /// <summary>
    /// 服务正在切换或状态查询失败时，安装和启动都没有意义，先报出去。
    /// </summary>
    private static bool TryDescribeBlockingServiceState(
        DriverServiceSnapshot service,
        out DriverRepairResult? failure)
    {
        if (service.IsTransitioning)
        {
            failure = new DriverRepairResult(
                false,
                $"Driver service is changing state ({service.State}). Wait for it to finish or restart Windows before repairing driver protection.");
            return true;
        }

        if (service.State == DriverServiceState.Unknown)
        {
            failure = new DriverRepairResult(
                false,
                $"Unable to query driver service. {service.Detail}");
            return true;
        }

        failure = null;
        return false;
    }

    /// <summary>
    /// 安装完成后重新查询服务（安装器会注册服务），再交给统一的启动逻辑。
    /// </summary>
    private static async Task<DriverRepairResult> StartServiceAfterInstallAsync(CancellationToken token)
    {
        DriverServiceSnapshot registered = DriverServiceControl.Query(ServiceName);
        if (registered.IsMissing)
        {
            return new DriverRepairResult(
                false,
                $"Driver package install completed, but service {ServiceName} was not registered.");
        }

        if (registered.State == DriverServiceState.Unknown)
        {
            return new DriverRepairResult(
                false,
                $"Driver package install completed, but service state could not be queried. {registered.Detail}");
        }

        return await StartServiceCoreAsync(registered, token).ConfigureAwait(false);
    }

    private static async Task<DriverRepairResult> TryStopLegacyDriverForUpgradeAsync(
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!DriverBridgeClient.TryAuthorizeLegacyUpgradeShutdown(out string authorizationMessage))
        {
            return new DriverRepairResult(
                false,
                $"Loaded driver could not be authorized for in-place upgrade. {authorizationMessage} Restart Windows, then retry the repair.");
        }

        DriverServiceOperationResult stop = DriverServiceControl.Stop(ServiceName);
        if (!stop.Success)
        {
            return new DriverRepairResult(
                false,
                $"Legacy driver accepted upgrade authorization, but SCM stop failed. {stop.Message}");
        }

        DriverServiceSnapshot stopped = await WaitForServiceStateAsync(
            DriverServiceState.Stopped,
            token).ConfigureAwait(false);
        if (stopped.State != DriverServiceState.Stopped)
        {
            return new DriverRepairResult(
                false,
                $"Legacy driver did not stop after upgrade authorization. {stopped.Detail}");
        }

        return new DriverRepairResult(
            true,
            $"{authorizationMessage} Driver service stopped and is ready for package replacement.");
    }

    private static Task<DriverRepairResult> InstallPackageAsync(DriverPackage package, CancellationToken token)
    {
        return Task.Run(() =>
        {
            if (!DriverPackageInstaller.Install(package.InfPath, out bool rebootRequired, out string message))
                return new DriverRepairResult(false, message);

            if (rebootRequired)
            {
                return new DriverRepairResult(
                    false,
                    "Driver package was installed, but a restart is required before the new driver can be loaded. " +
                    "Restart Windows, then start driver protection.");
            }

            return new DriverRepairResult(true, message);
        }, token);
    }

    private static async Task<DriverRepairResult> StartServiceCoreAsync(
        DriverServiceSnapshot service,
        CancellationToken token)
    {
        if (service.IsRunning)
            return new DriverRepairResult(true, "Driver service is already running.");

        if (service.IsMissing)
            return new DriverRepairResult(false, $"Driver service {ServiceName} is not installed.");

        if (service.IsTransitioning)
            return new DriverRepairResult(false, $"Driver service is changing state ({service.State}). Wait for it to finish before starting driver protection.");

        if (service.State == DriverServiceState.Unknown)
            return new DriverRepairResult(false, $"Unable to query driver service. {service.Detail}");

        DriverServiceOperationResult start = DriverServiceControl.Start(ServiceName);
        if (start.Success)
        {
            DriverServiceSnapshot running = await WaitForServiceStateAsync(DriverServiceState.Running, token).ConfigureAwait(false);
            return running.IsRunning
                ? new DriverRepairResult(true, "Driver service is running.")
                : new DriverRepairResult(false, $"Driver service did not enter RUNNING state. Service: {running.Detail}. Start: {start.Message}");
        }

        return new DriverRepairResult(false, $"Driver service start failed: {start.Message}");
    }

    /// <summary>
    /// 轮询等待桥接可用。两种情况可以提前结束，不必等满整个窗口：
    /// 服务已经不在跑（不会自己回来），以及协议/构建号不匹配（等多久都不会变）。
    /// </summary>
    private static async Task<DriverLoadSnapshot> WaitForBridgeAsync(CancellationToken token)
    {
        DriverLoadSnapshot snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        bool versionMismatchChecked = false;

        for (int attempt = 0; attempt < BridgeProbeAttempts; attempt++)
        {
            if (snapshot.BridgeReady)
                return snapshot;

            if (attempt > 0 && !snapshot.Service.IsRunning)
                return snapshot;

            if (!versionMismatchChecked &&
                snapshot.RuntimeStatus == DriverProtectionRuntimeStatus.NeedsRepair)
            {
                versionMismatchChecked = true;
                if (IsDriverVersionMismatch())
                    return snapshot;
            }

            await Task.Delay(BridgeProbeDelay, token).ConfigureAwait(false);
            snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        }

        return snapshot;
    }

    /// <summary>
    /// Checks whether the loaded driver's protocol version or build ID differs
    /// from what the client expects. This indicates an outdated driver binary
    /// in the driver store or a stale driver still resident in kernel memory.
    /// </summary>
    private static bool IsDriverVersionMismatch()
    {
        if (!DriverBridgeClient.TryQueryRawDriverState(out var rawState, out _))
            return false;

        return rawState.ProtocolVersion != DriverProtocol.ProtocolVersion ||
            rawState.DriverBuildId != DriverProtocol.DriverBuildId;
    }

    /// <summary>
    /// Builds a human-readable diagnostic string explaining why the bridge is
    /// not reachable. Distinguishes version mismatch (outdated binary) from
    /// stale client registration (previous instance still connected).
    /// </summary>
    private static string? GetBridgeDiagnosticDetail()
    {
        if (DriverBridgeClient.TryQueryRawDriverState(out var rawState, out int rawError))
        {
            if (rawState.ProtocolVersion != DriverProtocol.ProtocolVersion ||
                rawState.DriverBuildId != DriverProtocol.DriverBuildId)
            {
                return $"Loaded driver reports protocol v{rawState.ProtocolVersion}/build {rawState.DriverBuildId}, " +
                    $"but the client expects protocol v{DriverProtocol.ProtocolVersion}/build {DriverProtocol.DriverBuildId}. " +
                    $"The installed driver binary is outdated — rebuild and redeploy the driver package.";
            }

            if (rawState.ClientConnected != 0)
            {
                return $"A previous client (PID {rawState.ProtectedProcessId}) is still registered with the driver. " +
                    "Wait for the heartbeat to expire or restart Windows.";
            }

            return null;
        }

        return rawError switch
        {
            2 or 3 => "Driver device is not accessible (not installed).",
            _ => $"Driver state query failed with Win32 error {rawError}."
        };
    }

    private static async Task<DriverServiceSnapshot> WaitForServiceStateAsync(
        DriverServiceState expected,
        CancellationToken token)
    {
        DriverServiceSnapshot snapshot = DriverServiceControl.Query(ServiceName);
        for (int attempt = 0; attempt < 20; attempt++)
        {
            if (snapshot.State == expected || snapshot.IsMissing)
                return snapshot;

            await Task.Delay(250, token).ConfigureAwait(false);
            snapshot = DriverServiceControl.Query(ServiceName);
        }

        return snapshot;
    }

    private static Task<DriverLoadSnapshot> ReadSnapshotAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        DriverProtectionRuntimeStatus runtimeStatus = DriverProtection.QueryRuntimeStatus();
        DriverServiceSnapshot service = DriverServiceControl.Query(ServiceName);
        return Task.FromResult(new DriverLoadSnapshot(runtimeStatus, service));
    }

    private static DriverRepairResult CreateLoadedWithoutBridgeResult(DriverLoadSnapshot snapshot)
    {
        string? detail = GetBridgeDiagnosticDetail();
        string suffix = string.IsNullOrWhiteSpace(detail) ? string.Empty : $" {detail}";

        return new DriverRepairResult(
            false,
            $"Driver service is loaded, but the Xdows Security bridge is not reachable ({snapshot.RuntimeStatus}).{suffix} Restart Windows before repairing, reinstalling, or starting driver protection.");
    }

    private static string? FindPublishedName(string pnputilOutput)
    {
        string? currentPublishedName = null;

        using var reader = new StringReader(pnputilOutput);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            string trimmed = line.Trim();
            int colon = trimmed.IndexOf(':');
            if (colon <= 0)
                continue;

            string key = trimmed[..colon].Trim();
            string value = trimmed[(colon + 1)..].Trim();

            if (key.Equals("Published Name", StringComparison.OrdinalIgnoreCase))
            {
                currentPublishedName = value;
                continue;
            }

            if (key.Equals("Original Name", StringComparison.OrdinalIgnoreCase))
            {
                if (value.Equals(DriverPackageLocator.InfName, StringComparison.OrdinalIgnoreCase))
                    return currentPublishedName;
            }
        }

        return null;
    }

    private sealed record DriverLoadSnapshot(
        DriverProtectionRuntimeStatus RuntimeStatus,
        DriverServiceSnapshot Service)
    {
        public bool BridgeReady =>
            RuntimeStatus is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected;
    }
}
