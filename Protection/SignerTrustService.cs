using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TrustQuarantine;

namespace Protection;

public sealed record SignerTrustResult(
    bool IsTrusted,
    bool IsSigned,
    bool ChainValid,
    string Subject,
    string Reason);

public static class SignerTrustService
{
    public static SignerTrustResult Evaluate(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new SignerTrustResult(false, false, false, string.Empty, "file-not-found");

        if (TrustManager.IsPathTrusted(path))
            return new SignerTrustResult(true, false, false, string.Empty, "trusted-list");

        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            using var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.NoFlag
                }
            };

            using var cert2 = new X509Certificate2(certificate);
            bool chainValid = chain.Build(cert2);
            return new SignerTrustResult(
                chainValid,
                true,
                chainValid,
                cert2.Subject,
                chainValid ? "signature-chain-valid" : "signature-chain-invalid");
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return new SignerTrustResult(false, false, false, string.Empty, ex.GetType().Name);
        }
    }

    public static string? TryResolveProcessPath(uint processId)
    {
        if (processId is 0 or 4)
            return null;

        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }
}
