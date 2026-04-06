using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TrustQuarantine
{
    internal static class TrustManagerHelper
    {
        public static string? CalculateFileHash(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return null;

            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        public static async Task<string?> CalculateFileHashAsync(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return null;

            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hashBytes = await sha256.ComputeHashAsync(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        public static bool IsPathTrusted(string filePath, string trustFolderPath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                string? fileHash = CalculateFileHash(filePath);
                if (string.IsNullOrEmpty(fileHash))
                    return false;

                string trustFile = Path.Combine(trustFolderPath, fileHash.ToLowerInvariant() + ".json");
                return File.Exists(trustFile);
            }
            catch
            {
                return false;
            }
        }

        public static string? CreateTrustItemJson(string filePath, string hash)
        {
            if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(hash))
                return null;

            try
            {
                var item = new
                {
                    SourcePath = filePath,
                    Hash = hash
                };
                return JsonSerializer.Serialize(item);
            }
            catch
            {
                return null;
            }
        }
    }
}
