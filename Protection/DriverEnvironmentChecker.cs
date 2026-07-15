using System.Diagnostics;
using System.Security.Principal;

namespace Protection;

public enum DriverEnvironmentCheckStatus
{
    Passed,
    Warning,
    Failed
}

public sealed record DriverEnvironmentCheckItem(
    string Id,
    string Title,
    string Detail,
    DriverEnvironmentCheckStatus Status,
    bool CanRepair,
    string RepairAction)
{
    public bool Passed => Status == DriverEnvironmentCheckStatus.Passed;
    public string StatusText => Status.ToString();
}

public sealed record DriverEnvironmentReport(
    IReadOnlyList<DriverEnvironmentCheckItem> Items,
    DateTimeOffset CheckedAt)
{
    public bool IsHealthy => Items.All(i => i.Status == DriverEnvironmentCheckStatus.Passed);
}

public static class DriverEnvironmentChecker
{
    private const string ServiceName = DriverPackageLocator.ServiceName;

    public static async Task<DriverEnvironmentReport> CheckAsync(CancellationToken token = default)
    {
        DriverProtectionRuntimeStatus runtimeStatus = DriverProtection.QueryRuntimeStatus();
        var items = new List<DriverEnvironmentCheckItem>
        {
            CheckAdministrator(),
            await CheckTestSigningAsync(token).ConfigureAwait(false),
            CheckDriverPackage(),
            CheckDriverService(runtimeStatus),
            CheckDriverCommunication(runtimeStatus),
            CheckModelAssets()
        };

        return new DriverEnvironmentReport(items, DateTimeOffset.Now);
    }

    public static string? FindDriverInf()
    {
        return DriverPackageLocator.Find()?.InfPath;
    }

    public static string? FindDriverSys()
    {
        return DriverPackageLocator.Find()?.SysPath;
    }

    private static DriverEnvironmentCheckItem CheckAdministrator()
    {
        bool isAdmin = false;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
        }

        return new DriverEnvironmentCheckItem(
            "admin",
            "Administrator",
            isAdmin ? "Current process has administrator rights." : "Start Xdows Security as administrator to install or start the driver.",
            isAdmin ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            false,
            "Restart as administrator");
    }

    private static async Task<DriverEnvironmentCheckItem> CheckTestSigningAsync(CancellationToken token)
    {
        var result = await RunCommandAsync("bcdedit", "/enum {current}", token).ConfigureAwait(false);
        if (!result.Started)
        {
            return new DriverEnvironmentCheckItem(
                "testsigning",
                "Driver signing",
                "Unable to query test-signing state. Formal driver signing may still work.",
                DriverEnvironmentCheckStatus.Warning,
                false,
                "Open signing help");
        }

        bool enabled = result.Output.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
            result.Output.Contains("Yes", StringComparison.OrdinalIgnoreCase);

        return new DriverEnvironmentCheckItem(
            "testsigning",
            "Driver signing",
            enabled ? "Windows test-signing is enabled." : "Test-signing is not enabled. Unsigned development drivers will not load.",
            enabled ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Warning,
            false,
            "Open signing help");
    }

    private static DriverEnvironmentCheckItem CheckDriverPackage()
    {
        DriverPackage? package = DriverPackageLocator.Find();

        string detail = package is not null
            ? $"Driver package found: {package.DirectoryPath}"
            : DriverPackageLocator.CreateNotFoundMessage();

        return new DriverEnvironmentCheckItem(
            "package",
            "Driver package",
            detail,
            package is not null ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            package is not null,
            "Install driver");
    }

    private static DriverEnvironmentCheckItem CheckDriverService(DriverProtectionRuntimeStatus runtimeStatus)
    {
        DriverServiceSnapshot service = DriverServiceControl.Query(ServiceName);
        if (service.IsMissing)
        {
            return new DriverEnvironmentCheckItem(
                "service",
                "Driver service",
                "Driver service is not installed.",
                DriverEnvironmentCheckStatus.Failed,
                FindDriverInf() is not null,
                "Install driver");
        }

        if (service.State == DriverServiceState.Unknown)
        {
            return new DriverEnvironmentCheckItem(
                "service",
                "Driver service",
                $"Unable to query driver service. {service.Detail}",
                DriverEnvironmentCheckStatus.Failed,
                false,
                "Restart as administrator");
        }

        if (service.IsTransitioning)
        {
            return new DriverEnvironmentCheckItem(
                "service",
                "Driver service",
                $"Driver service is changing state ({service.State}). Wait for it to finish or restart Windows.",
                DriverEnvironmentCheckStatus.Failed,
                false,
                "Restart Windows");
        }

        if (service.IsRunning && runtimeStatus == DriverProtectionRuntimeStatus.NotInstalled)
        {
            return new DriverEnvironmentCheckItem(
                "service",
                "Driver service",
                "Driver service is running, but the Xdows Security bridge device is missing. Restart Windows before repairing or starting driver protection.",
                DriverEnvironmentCheckStatus.Failed,
                false,
                "Restart Windows");
        }

        return new DriverEnvironmentCheckItem(
            "service",
            "Driver service",
            service.IsRunning ? "Driver service is running." : $"Driver service is installed but not running. {service.Detail}",
            service.IsRunning ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            true,
            "Start service");
    }

    private static DriverEnvironmentCheckItem CheckDriverCommunication(DriverProtectionRuntimeStatus status)
    {
        DriverEnvironmentCheckStatus checkStatus = status switch
        {
            DriverProtectionRuntimeStatus.Protected => DriverEnvironmentCheckStatus.Passed,
            DriverProtectionRuntimeStatus.NotRunning => DriverEnvironmentCheckStatus.Warning,
            _ => DriverEnvironmentCheckStatus.Failed
        };

        string detail = status == DriverProtectionRuntimeStatus.Protected
            ? $"Driver device query returned {status}."
            : status == DriverProtectionRuntimeStatus.NotRunning
                ? $"Driver device is reachable but no client is connected ({status}). Start driver protection."
                : $"Driver device query failed: {status}.";

        return new DriverEnvironmentCheckItem(
            "communication",
            "Driver communication",
            detail,
            checkStatus,
            status != DriverProtectionRuntimeStatus.NotInstalled,
            "Restart bridge");
    }

    private static DriverEnvironmentCheckItem CheckModelAssets()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string[] models =
        [
            "Xdows-Model.onnx",
            "Xdows-Model-Flash.onnx",
            "Xdows-Model-Pro.onnx",
            "Xdows-Model-Pro-Standard.onnx",
            "Xdows-Model-Pro-Flash.onnx",
            "Xdows-Model-Pro-RawStat.onnx",
            "Xdows-Model-Pro-Structural.onnx",
            "onnxruntime.dll",
            "onnxruntime_providers_shared.dll"
        ];

        int foundModels = models.Count(name => File.Exists(Path.Combine(baseDirectory, name)));
        bool nativeFound = File.Exists(Path.Combine(baseDirectory, "Xdows-Model-Native.dll"));
        bool modelOk = foundModels == models.Length;

        DriverEnvironmentCheckStatus status = modelOk && nativeFound
            ? DriverEnvironmentCheckStatus.Passed
            : modelOk ? DriverEnvironmentCheckStatus.Warning : DriverEnvironmentCheckStatus.Failed;

        string detail = $"Models: {foundModels}/{models.Length}, native DLL: {nativeFound}.";
        return new DriverEnvironmentCheckItem(
            "model",
            "Native model assets",
            detail,
            status,
            true,
            "Copy model files");
    }

    internal static async Task<CommandResult> RunCommandAsync(string fileName, string arguments, CancellationToken token)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            if (!process.Start())
                return new CommandResult(false, -1, string.Empty);

            string output = await process.StandardOutput.ReadToEndAsync(token).ConfigureAwait(false);
            string error = await process.StandardError.ReadToEndAsync(token).ConfigureAwait(false);
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            return new CommandResult(true, process.ExitCode, output + error);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        {
            return new CommandResult(false, -1, ex.GetType().Name);
        }
    }

    internal sealed record CommandResult(bool Started, int ExitCode, string Output);
}
