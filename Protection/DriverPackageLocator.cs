namespace Protection;

internal sealed record DriverPackage(
    string DirectoryPath,
    string InfPath,
    string SysPath,
    string CatPath);

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
        string candidates = string.Join(
            "; ",
            EnumerateCandidateDirectories()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(24));

        return $"Driver package was not found. Base directory: {baseDirectory}. Checked: {candidates}. Build Xdows-Security.slnx and copy the full win-x64 output folder, including Driver assets.";
    }

    public static IEnumerable<string> EnumerateCandidateDirectories()
    {
        string baseDirectory = AppContext.BaseDirectory;
        yield return Path.Combine(baseDirectory, "Driver");
        yield return baseDirectory;

        string? overrideDirectory = Environment.GetEnvironmentVariable("XDOWS_SECURITY_DRIVER_PACKAGE");
        if (!string.IsNullOrWhiteSpace(overrideDirectory))
            yield return overrideDirectory;

        DirectoryInfo? current = new(baseDirectory);
        while (current is not null)
        {
            yield return Path.Combine(current.FullName, "Driver");
            yield return current.FullName;

            if (string.Equals(current.Name, "Xdows-Security", StringComparison.OrdinalIgnoreCase) &&
                current.Parent is not null)
            {
                string driverRepo = Path.Combine(current.Parent.FullName, "Xdows-Security-Driver");
                foreach (string directory in EnumerateRepositoryPackageDirectories(driverRepo))
                    yield return directory;
            }

            current = current.Parent;
        }

        foreach (string directory in EnumerateNearbyPackageDirectories(baseDirectory))
            yield return directory;
    }

    private static IEnumerable<string> EnumerateRepositoryPackageDirectories(string driverRepo)
    {
        foreach (string platform in new[] { "x64", "ARM64" })
        {
            foreach (string configuration in new[] { "Debug", "Release" })
            {
                yield return Path.Combine(driverRepo, platform, configuration, ServiceName);
                yield return Path.Combine(driverRepo, platform, configuration);
            }
        }

        yield return Path.Combine(driverRepo, ServiceName);
    }

    private static IEnumerable<string> EnumerateNearbyPackageDirectories(string baseDirectory)
    {
        foreach (string root in EnumerateNearbyRoots(baseDirectory).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            yield return Path.Combine(root, "Driver");
            yield return Path.Combine(root, ServiceName);
            yield return Path.Combine(root, "Xdows-Security-Driver");
            yield return Path.Combine(root, "Xdows-Security-Driver", ServiceName);
            yield return Path.Combine(root, "Xdows-Security-Publish");
            yield return Path.Combine(root, "Xdows-Security-Publish", "Driver");
            yield return Path.Combine(root, "win-x64");
            yield return Path.Combine(root, "win-x64", "Driver");

            foreach (string directory in SearchForInfDirectories(root))
                yield return directory;
        }
    }

    private static IEnumerable<string> EnumerateNearbyRoots(string baseDirectory)
    {
        DirectoryInfo? current = new(baseDirectory);
        for (int i = 0; current is not null && i < 4; i++)
        {
            yield return current.FullName;
            current = current.Parent;
        }

        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (!string.IsNullOrWhiteSpace(desktop))
            yield return desktop;
    }

    private static IEnumerable<string> SearchForInfDirectories(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            yield break;

        int yielded = 0;
        IEnumerator<string>? enumerator = null;
        try
        {
            enumerator = Directory.EnumerateFiles(root, InfName, SearchOption.AllDirectories).GetEnumerator();
        }
        catch
        {
            yield break;
        }

        using (enumerator)
        {
            while (yielded < 32)
            {
                string path;
                try
                {
                    if (!enumerator.MoveNext())
                        yield break;
                    path = enumerator.Current;
                }
                catch
                {
                    yield break;
                }

                string? directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    yielded++;
                    yield return directory;
                }
            }
        }
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

        return new DriverPackage(directory, infPath, sysPath, catPath);
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
}
