using System.Diagnostics;

namespace Protection;

public sealed record DriverRepairResult(bool Success, string Message);

public static class DriverInstaller
{
    public static Task<DriverRepairResult> RepairAsync(
        DriverEnvironmentCheckItem item,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(item);

        return item.Id switch
        {
            "package" or "service" => InstallAndStartDriverAsync(token),
            "communication" => DriverProtection.QueryRuntimeStatus() == DriverProtectionRuntimeStatus.NeedsRepair
                ? InstallAndStartDriverAsync(token)
                : RestartBridgeAsync(token),
            "model" => CopyModelAssetsAsync(token),
            "testsigning" => ShowTestSigningPromptAsync(),
            "admin" => Task.FromResult(new DriverRepairResult(
                false,
                "Restart Xdows Security as administrator, then run the repair again.")),
            _ => Task.FromResult(new DriverRepairResult(false, $"No repair action is registered for {item.Id}."))
        };
    }

    public static Task<DriverRepairResult> InstallAndStartDriverAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.InstallAndStartAsync(token);
    }

    public static Task<DriverRepairResult> EnsureInstalledAndStartedAsync(CancellationToken token = default)
    {
        return DriverLoadWorkflow.EnsureReadyAsync(token);
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

            string[] assets =
            [
                "Xdows-Model.onnx",
                "Xdows-Model-Flash.onnx",
                "Xdows-Model-Pro.onnx",
                "Xdows-Model-Pro-Standard.onnx",
                "Xdows-Model-Pro-Flash.onnx",
                "Xdows-Model-Pro-RawStat.onnx",
                "Xdows-Model-Pro-Structural.onnx",
                "Xdows-Model-Native.dll",
                "onnxruntime.dll",
                "onnxruntime_providers_shared.dll"
            ];

            var ready = new List<string>();
            var missing = new List<string>();
            var failed = new List<string>();

            foreach (string asset in assets)
            {
                token.ThrowIfCancellationRequested();
                string targetPath = Path.Combine(outputDirectory, asset);
                if (File.Exists(targetPath))
                {
                    ready.Add(asset);
                    continue;
                }

                string? source = FindAsset(asset);
                if (source is null)
                {
                    missing.Add(asset);
                    continue;
                }

                try
                {
                    File.Copy(source, targetPath, overwrite: false);
                    ready.Add(asset);
                }
                catch (IOException ex)
                {
                    failed.Add($"{asset}: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    failed.Add($"{asset}: {ex.Message}");
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

    private static Task<DriverRepairResult> ShowTestSigningPromptAsync()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/k echo Run as administrator if needed: bcdedit /set testsigning on && echo Restart Windows after changing test-signing.",
                UseShellExecute = true
            });
        }
        catch
        {
        }

        return Task.FromResult(new DriverRepairResult(
            false,
            "Enable test-signing with: bcdedit /set testsigning on, then restart Windows. Production builds need a valid driver signature instead."));
    }

    private static string? FindAsset(string fileName)
    {
        string[] roots =
        [
            AppContext.BaseDirectory,
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "win-x64")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Xdows-Security-Publish")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Xdows-Security-Publish", "win-x64")),
            @"D:\Code\Xdows-Model\Xdows-Model-Invoker",
            @"D:\Code\Xdows-Model\x64\Debug",
            @"D:\Code\Xdows-Model\x64\Release",
            @"D:\Code\Xdows-Model\ARM64\Debug",
            @"D:\Code\Xdows-Model\ARM64\Release",
            @"D:\Code\Xdows-Model\Xdows-Model-Invoker\bin\x64\Debug\net10.0-windows10.0.26100.0",
            @"D:\Code\Xdows-Model\Xdows-Model-Caller\bin\x64\Debug\net10.0-windows10.0.26100.0",
            @"D:\Code\Xdows-Model\Xdows-Model-Invoker\bin\Debug\net10.0-windows10.0.26100.0",
            @"D:\Code\Xdows-Model\Xdows-Model-Caller\bin\Debug\net10.0-windows10.0.26100.0"
        ];

        foreach (string root in roots)
        {
            string candidate = Path.Combine(root, fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        try
        {
            return Directory
                .EnumerateFiles(@"D:\Code\Xdows-Model", fileName, SearchOption.AllDirectories)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
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

        CommandResult drivers = await RunCommandAsync("pnputil", ["/enum-drivers"], token).ConfigureAwait(false);
        if (!drivers.Success)
            return new DriverRepairResult(false, $"Unable to enumerate drivers: {drivers.ShortOutput}");

        string? publishedName = FindPublishedName(drivers.Output);
        if (string.IsNullOrWhiteSpace(publishedName))
            return new DriverRepairResult(true, "Driver package is not installed.");

        CommandResult delete = await RunCommandAsync(
            "pnputil",
            ["/delete-driver", publishedName, "/uninstall", "/force"],
            token).ConfigureAwait(false);

        return delete.Success
            ? new DriverRepairResult(true, $"Driver package {publishedName} uninstalled.")
            : new DriverRepairResult(false, $"Driver package uninstall failed: {delete.ShortOutput}");
    }

    private static async Task<DriverRepairResult> EnsureReadyCoreAsync(
        string successPrefix,
        CancellationToken token)
    {
        DriverLoadSnapshot initial = await ReadSnapshotAsync(token).ConfigureAwait(false);
        DriverPackage? package = null;
        bool packageTrusted = false;
        if (initial.BridgeReady)
            return new DriverRepairResult(true, $"{successPrefix}: {initial.RuntimeStatus}.");

        if (initial.Service.IsRunning)
        {
            if (initial.RuntimeStatus != DriverProtectionRuntimeStatus.NeedsRepair)
                return CreateLoadedWithoutBridgeResult(initial);

            package = DriverPackageLocator.Find();
            if (package is null)
                return new DriverRepairResult(false, DriverPackageLocator.CreateNotFoundMessage());

            DriverRepairResult legacyTrust = DriverCertificateTrustInstaller.TrustIfPresent(package);
            if (!legacyTrust.Success)
                return legacyTrust;
            packageTrusted = true;

            DriverRepairResult legacyStop = await TryStopLegacyDriverForUpgradeAsync(token).ConfigureAwait(false);
            if (!legacyStop.Success)
                return legacyStop;

            initial = await ReadSnapshotAsync(token).ConfigureAwait(false);
        }

        if (initial.Service.IsTransitioning)
        {
            return new DriverRepairResult(
                false,
                $"Driver service is changing state ({initial.Service.State}). Wait for it to finish or restart Windows before repairing driver protection.");
        }

        if (initial.Service.State == DriverServiceState.Unknown)
        {
            return new DriverRepairResult(
                false,
                $"Unable to query driver service. {initial.Service.Detail}");
        }

        package ??= DriverPackageLocator.Find();
        if (package is null)
            return new DriverRepairResult(false, DriverPackageLocator.CreateNotFoundMessage());

        if (!packageTrusted)
        {
            DriverRepairResult trust = DriverCertificateTrustInstaller.TrustIfPresent(package);
            if (!trust.Success)
                return trust;
        }

        DriverRepairResult install = await InstallPackageAsync(package, token).ConfigureAwait(false);
        if (!install.Success)
            return install;

        DriverServiceSnapshot afterInstall = DriverServiceControl.Query(ServiceName);
        if (afterInstall.IsMissing)
        {
            return new DriverRepairResult(
                false,
                $"Driver package install completed, but service {ServiceName} was not registered. Install: {install.Message}");
        }

        if (afterInstall.State == DriverServiceState.Unknown)
        {
            return new DriverRepairResult(
                false,
                $"Driver package install completed, but service state could not be queried. {afterInstall.Detail}");
        }

        DriverRepairResult start = await StartServiceCoreAsync(afterInstall, token).ConfigureAwait(false);
        if (!start.Success)
            return start;

        DriverLoadSnapshot ready = await WaitForBridgeAsync(token).ConfigureAwait(false);
        if (ready.BridgeReady)
            return new DriverRepairResult(true, $"{successPrefix}: {ready.RuntimeStatus}.");

        if (ready.Service.IsRunning)
            return CreateLoadedWithoutBridgeResult(ready);

        return new DriverRepairResult(
            false,
            $"Driver did not become ready. Runtime: {ready.RuntimeStatus}. Service: {ready.Service.Detail}. Install: {install.Message}. Start: {start.Message}");
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
            return DriverPackageInstaller.Install(package.InfPath, out string message)
                ? new DriverRepairResult(true, message)
                : new DriverRepairResult(false, message);
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

    private static async Task<DriverLoadSnapshot> WaitForBridgeAsync(CancellationToken token)
    {
        DriverLoadSnapshot snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        for (int attempt = 0; attempt < BridgeProbeAttempts; attempt++)
        {
            if (snapshot.BridgeReady)
                return snapshot;

            if (!snapshot.Service.IsRunning && attempt > 0)
                return snapshot;

            await Task.Delay(BridgeProbeDelay, token).ConfigureAwait(false);
            snapshot = await ReadSnapshotAsync(token).ConfigureAwait(false);
        }

        return snapshot;
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
        return new DriverRepairResult(
            false,
            $"Driver service is loaded, but the Xdows Security bridge is not reachable ({snapshot.RuntimeStatus}). Restart Windows before repairing, reinstalling, or starting driver protection.");
    }

    private static async Task<CommandResult> RunCommandAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken token)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            foreach (string argument in arguments)
                process.StartInfo.ArgumentList.Add(argument);

            if (!process.Start())
                return new CommandResult(false, -1, string.Empty);

            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(token);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(token);
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            string output = await outputTask.ConfigureAwait(false);
            string error = await errorTask.ConfigureAwait(false);
            return new CommandResult(true, process.ExitCode, output + error);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        {
            return new CommandResult(false, -1, ex.GetType().Name);
        }
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

    private sealed record CommandResult(bool Started, int ExitCode, string Output)
    {
        public bool Success => Started && ExitCode == 0;

        public string ShortOutput
        {
            get
            {
                string value = string.IsNullOrWhiteSpace(Output) ? "No command output." : Output.Trim();
                return value.Length <= 700 ? value : value[..700];
            }
        }
    }
}
