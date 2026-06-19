namespace Protection;

internal sealed record DriverPackage(
    string DirectoryPath,
    string InfPath,
    string SysPath,
    string CatPath,
    string? CertificatePath);

internal static class DriverPackageLocator
{
    internal const string ServiceName = "Xdows-Security-Driver";
    internal const string InfName = "Xdows-Security-Driver.inf";
    internal const string SysName = "Xdows-Security-Driver.sys";

    public static DriverPackage? Find()
    {
        foreach (string directory in EnumerateCandidateDirectories().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            DriverPackage? package = TryCreatePackage(directory);
            if (package is not null)
                return package;
        }

        return null;
    }

    public static string CreateNotFoundMessage()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string driverDirectory = Path.Combine(baseDirectory, "Driver");
        string? overrideDirectory = Environment.GetEnvironmentVariable("XDOWS_SECURITY_DRIVER_PACKAGE");
        string overrideText = string.IsNullOrWhiteSpace(overrideDirectory)
            ? "not set"
            : overrideDirectory;

        return $"Driver package was not found. Expected: {driverDirectory}. XDOWS_SECURITY_DRIVER_PACKAGE: {overrideText}. Build or publish Xdows-Security so the output contains the Driver directory.";
    }

    public static IEnumerable<string> EnumerateCandidateDirectories()
    {
        string? overrideDirectory = Environment.GetEnvironmentVariable("XDOWS_SECURITY_DRIVER_PACKAGE");
        if (!string.IsNullOrWhiteSpace(overrideDirectory))
            yield return overrideDirectory;

        yield return Path.Combine(AppContext.BaseDirectory, "Driver");
    }

    private static DriverPackage? TryCreatePackage(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return null;

        string infPath = Path.Combine(directory, InfName);
        string sysPath = Path.Combine(directory, SysName);
        if (!File.Exists(infPath) || !File.Exists(sysPath))
            return null;

        string? catPath = ResolveCatalogPath(infPath);
        if (string.IsNullOrWhiteSpace(catPath) || !File.Exists(catPath))
            return null;

        string? certificatePath = ResolveCertificatePath(directory);
        return new DriverPackage(directory, infPath, sysPath, catPath, certificatePath);
    }

    private static string? ResolveCatalogPath(string infPath)
    {
        string directory = Path.GetDirectoryName(infPath) ?? string.Empty;
        string? catalogName = ReadCatalogName(infPath);
        if (!string.IsNullOrWhiteSpace(catalogName))
        {
            string catalogPath = Path.Combine(directory, catalogName);
            if (File.Exists(catalogPath))
                return catalogPath;
        }

        string fallback = Path.ChangeExtension(infPath, ".cat");
        if (File.Exists(fallback))
            return fallback;

        try
        {
            return Directory
                .EnumerateFiles(directory, "*.cat", SearchOption.TopDirectoryOnly)
                .FirstOrDefault(path => Path.GetFileName(path).Contains("xdows-security-driver", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadCatalogName(string infPath)
    {
        try
        {
            foreach (string rawLine in File.ReadLines(infPath))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith(';'))
                    continue;

                int equals = line.IndexOf('=');
                if (equals <= 0)
                    continue;

                string key = line[..equals].Trim();
                if (!key.Equals("CatalogFile", StringComparison.OrdinalIgnoreCase))
                    continue;

                string value = line[(equals + 1)..].Trim();
                return value.Trim('"');
            }
        }
        catch
        {
        }

        return null;
    }

    private static string? ResolveCertificatePath(string directory)
    {
        string preferred = Path.Combine(directory, "Xdows-Security-Driver-Test.cer");
        if (File.Exists(preferred))
            return preferred;

        try
        {
            return Directory
                .EnumerateFiles(directory, "*.cer", SearchOption.TopDirectoryOnly)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }
}
