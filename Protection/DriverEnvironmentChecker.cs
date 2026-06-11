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
    private const string ServiceName = "Xdows-Security-Driver";

    public static async Task<DriverEnvironmentReport> CheckAsync(CancellationToken token = default)
    {
        var items = new List<DriverEnvironmentCheckItem>
        {
            CheckAdministrator(),
            await CheckTestSigningAsync(token).ConfigureAwait(false),
            CheckDriverPackage(),
            await CheckDriverServiceAsync(token).ConfigureAwait(false),
            CheckDriverCommunication(),
            CheckModelAssets()
        };

        return new DriverEnvironmentReport(items, DateTimeOffset.Now);
    }

    public static string? FindDriverInf()
    {
        string[] candidates =
        [
            Path.Combine(AppContext.BaseDirectory, "Driver", "Xdows-Security-Driver.inf"),
            Path.Combine(AppContext.BaseDirectory, "Xdows-Security-Driver.inf"),
            @"D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver\Xdows-Security-Driver.inf",
            @"D:\Code\Xdows-Security-Driver\x64\Release\Xdows-Security-Driver\Xdows-Security-Driver.inf",
            @"D:\Code\Xdows-Security-Driver\Xdows-Security-Driver\Xdows-Security-Driver.inf"
        ];

        return candidates.FirstOrDefault(File.Exists);
    }

    public static string? FindDriverSys()
    {
        string[] candidates =
        [
            Path.Combine(AppContext.BaseDirectory, "Driver", "Xdows-Security-Driver.sys"),
            Path.Combine(AppContext.BaseDirectory, "Xdows-Security-Driver.sys"),
            @"D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver\Xdows-Security-Driver.sys",
            @"D:\Code\Xdows-Security-Driver\x64\Release\Xdows-Security-Driver\Xdows-Security-Driver.sys",
            @"D:\Code\Xdows-Security-Driver\x64\Debug\Xdows-Security-Driver.sys",
            @"D:\Code\Xdows-Security-Driver\x64\Release\Xdows-Security-Driver.sys",
            @"D:\Code\Xdows-Security-Driver\Xdows-Security-Driver\Xdows-Security-Driver.sys"
        ];

        return candidates.FirstOrDefault(File.Exists);
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
        string? inf = FindDriverInf();
        string? sys = FindDriverSys();
        string? cat = inf is null ? null : Path.ChangeExtension(inf, ".cat");
        bool infOk = inf is not null;
        bool sysOk = sys is not null;
        bool catOk = cat is not null && File.Exists(cat);
        bool packageOk = infOk && sysOk && catOk;

        string detail = packageOk
            ? $"Driver package found: {inf}"
            : $"Missing package files. inf:{infOk}, sys:{sysOk}, cat:{catOk}";

        return new DriverEnvironmentCheckItem(
            "package",
            "Driver package",
            detail,
            packageOk ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            infOk,
            "Install driver");
    }

    private static async Task<DriverEnvironmentCheckItem> CheckDriverServiceAsync(CancellationToken token)
    {
        var result = await RunCommandAsync("sc.exe", $"query \"{ServiceName}\"", token).ConfigureAwait(false);
        if (!result.Started || result.ExitCode != 0)
        {
            return new DriverEnvironmentCheckItem(
                "service",
                "Driver service",
                "Driver service is not installed.",
                DriverEnvironmentCheckStatus.Failed,
                FindDriverInf() is not null,
                "Install driver");
        }

        bool running = result.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        return new DriverEnvironmentCheckItem(
            "service",
            "Driver service",
            running ? "Driver service is running." : "Driver service is installed but not running.",
            running ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
            true,
            "Start service");
    }

    private static DriverEnvironmentCheckItem CheckDriverCommunication()
    {
        DriverProtectionRuntimeStatus status = DriverProtection.QueryRuntimeStatus();
        bool ok = status == DriverProtectionRuntimeStatus.Protected ||
            status == DriverProtectionRuntimeStatus.NotRunning;

        return new DriverEnvironmentCheckItem(
            "communication",
            "Driver communication",
            ok ? $"Driver device query returned {status}." : $"Driver device query failed: {status}.",
            ok ? DriverEnvironmentCheckStatus.Passed : DriverEnvironmentCheckStatus.Failed,
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
