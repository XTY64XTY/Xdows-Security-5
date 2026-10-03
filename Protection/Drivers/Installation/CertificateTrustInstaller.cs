using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Protection;

internal static class DriverCertificateTrustInstaller
{
    public static DriverRepairResult TrustIfPresent(DriverPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);

        if (string.IsNullOrWhiteSpace(package.CertificatePath) || !File.Exists(package.CertificatePath))
            return new DriverRepairResult(true, "No driver test certificate was provided.");

        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificateFromFile(package.CertificatePath);
            TrustCertificate(certificate, StoreName.Root);
            TrustCertificate(certificate, StoreName.TrustedPublisher);
            return new DriverRepairResult(true, $"Driver test certificate is trusted: {certificate.Thumbprint}.");
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or IOException)
        {
            return new DriverRepairResult(false, $"Driver test certificate trust failed: {ex.Message}");
        }
    }

    private static void TrustCertificate(X509Certificate2 certificate, StoreName storeName)
    {
        using var store = new X509Store(storeName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);

        X509Certificate2Collection existing = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            certificate.Thumbprint,
            validOnly: false);

        if (existing.Count == 0)
            store.Add(certificate);
    }
}
