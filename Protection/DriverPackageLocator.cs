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
    internal const string BootFilterServiceName = "Xdows-Security-BootFilter";
    internal const string InfName = "Xdows-Security-Driver.inf";
    internal const string SysName = "Xdows-Security-Driver.sys";
    internal const string CatName = "xdows-security-driver.cat";
    internal const string CertificateName = "Xdows-Security-Driver-Test.cer";
    internal const string BootFilterInfName = "Xdows-Security-BootFilter.inf";
    internal const string BootFilterSysName = "Xdows-Security-BootFilter.sys";
    internal const string BootFilterCatName = "xdows-security-bootfilter.cat";

    public static string DriverDirectory => Path.Combine(AppContext.BaseDirectory, "Driver");

    public static DriverPackage? Find()
    {
        return TryCreatePackage(DriverDirectory);
    }

    public static DriverPackage? FindBootFilter()
    {
        string directory = Path.Combine(DriverDirectory, "BootFilter");
        return TryCreatePackage(
            directory,
            BootFilterInfName,
            BootFilterSysName,
            BootFilterCatName);
    }

    public static string CreateNotFoundMessage()
    {
        return $"Driver package was not found. Expected files: {Path.Combine(DriverDirectory, InfName)}, {Path.Combine(DriverDirectory, SysName)}, {Path.Combine(DriverDirectory, CatName)}. Build or publish Xdows-Security so the output contains the Driver directory.";
    }

    public static string CreateBootFilterNotFoundMessage()
    {
        string directory = Path.Combine(DriverDirectory, "BootFilter");
        return $"Boot filter package was not found. Expected files: {Path.Combine(directory, BootFilterInfName)}, {Path.Combine(directory, BootFilterSysName)}, {Path.Combine(directory, BootFilterCatName)}.";
    }

    private static DriverPackage? TryCreatePackage(string directory)
    {
        return TryCreatePackage(directory, InfName, SysName, CatName);
    }

    private static DriverPackage? TryCreatePackage(
        string directory,
        string infName,
        string sysName,
        string catName)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return null;

        string infPath = Path.Combine(directory, infName);
        string sysPath = Path.Combine(directory, sysName);
        if (!File.Exists(infPath) || !File.Exists(sysPath))
            return null;

        string catPath = Path.Combine(directory, catName);
        if (!File.Exists(catPath))
            return null;

        string certificatePath = Path.Combine(directory, CertificateName);
        if (!File.Exists(certificatePath))
            certificatePath = string.Empty;

        return new DriverPackage(directory, infPath, sysPath, catPath, certificatePath);
    }
}
