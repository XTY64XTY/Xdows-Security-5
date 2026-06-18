using System.Diagnostics;

namespace Protection;

public sealed record DriverRepairResult(bool Success, string Message);

public static class DriverInstaller
{
    private const string ServiceName = DriverPackageLocator.ServiceName;

    public static Task<DriverRepairResult> RepairAsync(
        DriverEnvironmentCheckItem item,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(item);

        return item.Id switch
        {
            "package" or "service" => InstallAndStartDriverAsync(token),
            "communication" => RestartBridgeAsync(token),
            "model" => CopyModelAssetsAsync(token),
            "testsigning" => ShowTestSigningPromptAsync(),
            "admin" => Task.FromResult(new DriverRepairResult(
                false,
                "Restart Xdows Security as administrator, then run the repair again.")),
            _ => Task.FromResult(new DriverRepairResult(false, $"No repair action is registered for {item.Id}."))
        };
    }

    public static async Task<DriverRepairResult> InstallAndStartDriverAsync(CancellationToken token = default)
    {
        DriverPackage? package = DriverPackageLocator.Find();
        if (package is null)
            return new DriverRepairResult(false, DriverPackageLocator.CreateNotFoundMessage());

        await StopServiceIfPresentAsync(token).ConfigureAwait(false);

        DriverRepairResult install = await Task.Run(() =>
        {
            return DriverPackageInstaller.Install(package.InfPath, out string installMessage)
                ? new DriverRepairResult(true, installMessage)
                : new DriverRepairResult(false, installMessage);
        }, token).ConfigureAwait(false);

        if (!install.Success)
            return install;

        DriverRepairResult start = await StartServiceAsync(token).ConfigureAwait(false);
        if (!start.Success)
        {
            string serviceState = await QueryServiceStateAsync(token).ConfigureAwait(false);
            return new DriverRepairResult(
                false,
                $"Driver package installed, but service start failed. Install: {install.Message} Start: {start.Message} Service: {serviceState}");
        }

        return new DriverRepairResult(true, "Driver installed and service started.");
    }

    public static async Task<DriverRepairResult> EnsureInstalledAndStartedAsync(CancellationToken token = default)
    {
        DriverProtectionRuntimeStatus runtimeStatus = DriverProtection.QueryRuntimeStatus();
        if (runtimeStatus is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected)
            return new DriverRepairResult(true, $"Driver bridge is reachable: {runtimeStatus}.");

        DriverPackage? package = DriverPackageLocator.Find();
        if (package is null)
            return new DriverRepairResult(false, DriverPackageLocator.CreateNotFoundMessage());

        DriverRepairResult start = await StartServiceAsync(token).ConfigureAwait(false);
        if (start.Success)
        {
            runtimeStatus = await WaitForBridgeAsync(token).ConfigureAwait(false);
            if (runtimeStatus is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected)
                return new DriverRepairResult(true, $"Driver service started and bridge is reachable: {runtimeStatus}.");
        }

        DriverRepairResult install = await InstallAndStartDriverAsync(token).ConfigureAwait(false);
        if (!install.Success)
            return install;

        runtimeStatus = await WaitForBridgeAsync(token).ConfigureAwait(false);
        return runtimeStatus is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected
            ? new DriverRepairResult(true, $"Driver installed, started, and bridge is reachable: {runtimeStatus}.")
            : new DriverRepairResult(false, $"Driver installed and started, but bridge is not reachable: {runtimeStatus}.");
    }

    public static async Task<DriverRepairResult> UninstallDriverAsync(CancellationToken token = default)
    {
        await StopServiceIfPresentAsync(token).ConfigureAwait(false);

        var enumDrivers = await DriverEnvironmentChecker.RunCommandAsync(
            "pnputil",
            "/enum-drivers",
            token).ConfigureAwait(false);

        if (!enumDrivers.Started || enumDrivers.ExitCode != 0)
            return new DriverRepairResult(false, $"Unable to enumerate drivers: {TrimCommandOutput(enumDrivers.Output)}");

        string? publishedName = FindPublishedName(enumDrivers.Output);
        if (string.IsNullOrWhiteSpace(publishedName))
            return new DriverRepairResult(true, "Driver package is not installed.");

        var delete = await DriverEnvironmentChecker.RunCommandAsync(
            "pnputil",
            $"/delete-driver {publishedName} /uninstall /force",
            token).ConfigureAwait(false);

        if (delete.Started && delete.ExitCode == 0)
            return new DriverRepairResult(true, $"Driver package {publishedName} uninstalled.");

        string output = TrimCommandOutput(delete.Output);
        bool rebootLikely = output.Contains("reboot", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("restart", StringComparison.OrdinalIgnoreCase);
        return new DriverRepairResult(
            false,
            rebootLikely ? $"{output} A restart may be required before retrying." : output);
    }

    public static async Task<DriverRepairResult> StartServiceAsync(CancellationToken token = default)
    {
        var start = await DriverEnvironmentChecker.RunCommandAsync(
            "sc.exe",
            $"start \"{ServiceName}\"",
            token).ConfigureAwait(false);

        bool alreadyRunning = start.Output.Contains("1056", StringComparison.OrdinalIgnoreCase) ||
            start.Output.Contains("already", StringComparison.OrdinalIgnoreCase) ||
            start.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);

        if (start.Started && (start.ExitCode == 0 || alreadyRunning))
            return new DriverRepairResult(true, "Driver service is running.");

        var query = await DriverEnvironmentChecker.RunCommandAsync(
            "sc.exe",
            $"query \"{ServiceName}\"",
            token).ConfigureAwait(false);

        if (query.Started && query.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            return new DriverRepairResult(true, "Driver service is running.");

        return new DriverRepairResult(false, TrimCommandOutput(start.Output + query.Output));
    }

    public static async Task<DriverRepairResult> RestartBridgeAsync(CancellationToken token = default)
    {
        DriverRepairResult start = await StartServiceAsync(token).ConfigureAwait(false);
        if (!start.Success)
            return start;

        DriverProtectionRuntimeStatus status = DriverProtection.QueryRuntimeStatus();
        return status is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected
            ? new DriverRepairResult(true, $"Driver bridge is reachable: {status}.")
            : new DriverRepairResult(false, $"Driver bridge still is not reachable: {status}.");
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

    private static string TrimCommandOutput(string output)
    {
        string value = string.IsNullOrWhiteSpace(output) ? "No command output." : output.Trim();
        return value.Length <= 700 ? value : value[..700];
    }

    private static async Task<DriverProtectionRuntimeStatus> WaitForBridgeAsync(CancellationToken token)
    {
        DriverProtectionRuntimeStatus status = DriverProtection.QueryRuntimeStatus();
        for (int attempt = 0; attempt < 10; attempt++)
        {
            if (status is DriverProtectionRuntimeStatus.NotRunning or DriverProtectionRuntimeStatus.Protected)
                return status;

            await Task.Delay(300, token).ConfigureAwait(false);
            status = DriverProtection.QueryRuntimeStatus();
        }

        return status;
    }

    private static async Task StopServiceIfPresentAsync(CancellationToken token)
    {
        var query = await DriverEnvironmentChecker.RunCommandAsync(
            "sc.exe",
            $"query \"{ServiceName}\"",
            token).ConfigureAwait(false);

        if (!query.Started || query.ExitCode != 0)
            return;

        if (!query.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            return;

        await DriverEnvironmentChecker.RunCommandAsync(
            "sc.exe",
            $"stop \"{ServiceName}\"",
            token).ConfigureAwait(false);
    }

    private static async Task<string> QueryServiceStateAsync(CancellationToken token)
    {
        var query = await DriverEnvironmentChecker.RunCommandAsync(
            "sc.exe",
            $"query \"{ServiceName}\"",
            token).ConfigureAwait(false);

        return query.Started
            ? TrimCommandOutput(query.Output)
            : "Unable to run sc.exe query.";
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

            if (key.Contains("Published Name", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("发布名称", StringComparison.OrdinalIgnoreCase))
            {
                currentPublishedName = value;
                continue;
            }

            if (key.Contains("Original Name", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("原始名称", StringComparison.OrdinalIgnoreCase))
            {
                if (value.Equals(DriverPackageLocator.InfName, StringComparison.OrdinalIgnoreCase))
                    return currentPublishedName;
            }
        }

        return null;
    }
}
