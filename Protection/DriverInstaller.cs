using System.Diagnostics;

namespace Protection;

public sealed record DriverRepairResult(bool Success, string Message);

public static class DriverInstaller
{
    private const string ServiceName = "Xdows-Security-Driver";

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
        string? infPath = DriverEnvironmentChecker.FindDriverInf();
        if (string.IsNullOrWhiteSpace(infPath))
            return new DriverRepairResult(false, "Driver INF was not found.");

        await StopServiceIfPresentAsync(token).ConfigureAwait(false);

        var install = await DriverEnvironmentChecker.RunCommandAsync(
            "pnputil",
            $"/add-driver \"{infPath}\" /install",
            token).ConfigureAwait(false);

        if (!install.Started || install.ExitCode != 0)
        {
            return new DriverRepairResult(
                false,
                $"Driver install failed: {TrimCommandOutput(install.Output)}");
        }

        DriverRepairResult start = await StartServiceAsync(token).ConfigureAwait(false);
        if (!start.Success)
            return new DriverRepairResult(false, $"Driver installed, but service start failed: {start.Message}");

        return new DriverRepairResult(true, "Driver installed and service started.");
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

            var copied = new List<string>();
            var missing = new List<string>();

            foreach (string asset in assets)
            {
                token.ThrowIfCancellationRequested();
                string? source = FindAsset(asset);
                if (source is null)
                {
                    missing.Add(asset);
                    continue;
                }

                File.Copy(source, Path.Combine(outputDirectory, asset), overwrite: true);
                copied.Add(asset);
            }

            if (missing.Count > 0)
            {
                string message = copied.Count > 0
                    ? $"Copied {string.Join(", ", copied)}; missing {string.Join(", ", missing)}."
                    : $"Missing source files: {string.Join(", ", missing)}.";
                return new DriverRepairResult(false, message);
            }

            return new DriverRepairResult(true, $"Copied model assets to {outputDirectory}.");
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
                if (value.Equals("Xdows-Security-Driver.inf", StringComparison.OrdinalIgnoreCase))
                    return currentPublishedName;
            }
        }

        return null;
    }
}
