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
    internal const string CatName = "xdows-security-driver.cat";
    internal const string CertificateName = "Xdows-Security-Driver-Test.cer";

    public static string DriverDirectory => Path.Combine(AppContext.BaseDirectory, "Driver");

    public static DriverPackage? Find()
    {
        return TryCreatePackage(DriverDirectory);
    }

    public static string CreateNotFoundMessage()
    {
        return $"Driver package was not found. Expected files: {Path.Combine(DriverDirectory, InfName)}, {Path.Combine(DriverDirectory, SysName)}, {Path.Combine(DriverDirectory, CatName)}. Build or publish Xdows-Security so the output contains the Driver directory.";
    }

    private static DriverPackage? TryCreatePackage(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return null;

        string infPath = Path.Combine(directory, InfName);
        string sysPath = Path.Combine(directory, SysName);
        if (!File.Exists(infPath) || !File.Exists(sysPath))
            return null;

        string catPath = Path.Combine(directory, CatName);
        if (!File.Exists(catPath))
            return null;

        string certificatePath = Path.Combine(directory, CertificateName);
        if (!File.Exists(certificatePath))
            certificatePath = string.Empty;

        return new DriverPackage(directory, infPath, sysPath, catPath, certificatePath);
    }
}
