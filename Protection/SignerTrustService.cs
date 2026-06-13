using System.Diagnostics;
using System.Runtime.InteropServices;
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
            using X509Certificate2? cert2 = TryReadAuthenticodeSignerCertificate(path);
            if (cert2 is null)
                return new SignerTrustResult(false, false, false, string.Empty, "authenticode-signer-not-found");

            using var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.NoFlag
                }
            };

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

    private static X509Certificate2? TryReadAuthenticodeSignerCertificate(string path)
    {
        nint storeHandle = 0;
        nint messageHandle = 0;
        nint signerInfoBuffer = 0;
        nint certInfoBuffer = 0;
        nint certContextHandle = 0;

        try
        {
            if (!NativeMethods.CryptQueryObject(
                NativeMethods.CertQueryObjectFile,
                path,
                NativeMethods.CertQueryContentFlagPkcs7SignedEmbedded,
                NativeMethods.CertQueryFormatFlagBinary,
                0,
                out _,
                out _,
                out _,
                out storeHandle,
                out messageHandle,
                out _))
            {
                return null;
            }

            int signerInfoSize = 0;
            if (!NativeMethods.CryptMsgGetParam(
                messageHandle,
                NativeMethods.CmsgSignerInfoParam,
                0,
                0,
                ref signerInfoSize) ||
                signerInfoSize <= 0)
            {
                return null;
            }

            signerInfoBuffer = Marshal.AllocHGlobal(signerInfoSize);
            if (!NativeMethods.CryptMsgGetParam(
                messageHandle,
                NativeMethods.CmsgSignerInfoParam,
                0,
                signerInfoBuffer,
                ref signerInfoSize))
            {
                return null;
            }

            CmsgSignerInfo signerInfo = Marshal.PtrToStructure<CmsgSignerInfo>(signerInfoBuffer);
            var certInfo = new CertInfo
            {
                Issuer = signerInfo.Issuer,
                SerialNumber = signerInfo.SerialNumber
            };

            certInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<CertInfo>());
            Marshal.StructureToPtr(certInfo, certInfoBuffer, false);

            certContextHandle = NativeMethods.CertFindCertificateInStore(
                storeHandle,
                NativeMethods.X509AsnEncoding | NativeMethods.Pkcs7AsnEncoding,
                0,
                NativeMethods.CertFindSubjectCert,
                certInfoBuffer,
                0);

            if (certContextHandle == 0)
                return null;

            CertContext certContext = Marshal.PtrToStructure<CertContext>(certContextHandle);
            if (certContext.CertEncoded == 0 || certContext.CertEncodedSize <= 0)
                return null;

            byte[] encodedCertificate = new byte[certContext.CertEncodedSize];
            Marshal.Copy(certContext.CertEncoded, encodedCertificate, 0, encodedCertificate.Length);
            return X509CertificateLoader.LoadCertificate(encodedCertificate);
        }
        finally
        {
            if (certContextHandle != 0)
                NativeMethods.CertFreeCertificateContext(certContextHandle);
            if (certInfoBuffer != 0)
                Marshal.FreeHGlobal(certInfoBuffer);
            if (signerInfoBuffer != 0)
                Marshal.FreeHGlobal(signerInfoBuffer);
            if (messageHandle != 0)
                NativeMethods.CryptMsgClose(messageHandle);
            if (storeHandle != 0)
                NativeMethods.CertCloseStore(storeHandle, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptoApiBlob
    {
        public int Size;
        public nint Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAlgorithmIdentifier
    {
        public nint ObjectId;
        public CryptoApiBlob Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAttributes
    {
        public int Count;
        public nint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CmsgSignerInfo
    {
        public int Version;
        public CryptoApiBlob Issuer;
        public CryptoApiBlob SerialNumber;
        public CryptAlgorithmIdentifier HashAlgorithm;
        public CryptAlgorithmIdentifier HashEncryptionAlgorithm;
        public CryptoApiBlob EncryptedHash;
        public CryptAttributes AuthAttributes;
        public CryptAttributes UnauthAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertInfo
    {
        public int Version;
        public CryptoApiBlob SerialNumber;
        public CryptAlgorithmIdentifier SignatureAlgorithm;
        public CryptoApiBlob Issuer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertContext
    {
        public int CertEncodingType;
        public nint CertEncoded;
        public int CertEncodedSize;
        public nint CertInfo;
        public nint CertStore;
    }

    private static partial class NativeMethods
    {
        public const int X509AsnEncoding = 0x00000001;
        public const int Pkcs7AsnEncoding = 0x00010000;
        public const int CertQueryObjectFile = 0x00000001;
        public const int CertQueryContentFlagPkcs7SignedEmbedded = 0x00000400;
        public const int CertQueryFormatFlagBinary = 0x00000002;
        public const int CmsgSignerInfoParam = 0x00000006;
        public const int CertFindSubjectCert = 0x000B0000;

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptQueryObject(
            int objectType,
            string objectPath,
            int expectedContentTypeFlags,
            int expectedFormatTypeFlags,
            int flags,
            out int messageAndCertEncodingType,
            out int contentType,
            out int formatType,
            out nint certStore,
            out nint message,
            out nint context);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptMsgGetParam(
            nint cryptMsg,
            int paramType,
            int index,
            nint data,
            ref int dataSize);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern nint CertFindCertificateInStore(
            nint certStore,
            int certEncodingType,
            int findFlags,
            int findType,
            nint findPara,
            nint previousCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertFreeCertificateContext(nint certContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptMsgClose(nint cryptMsg);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertCloseStore(nint certStore, int flags);
    }
}
