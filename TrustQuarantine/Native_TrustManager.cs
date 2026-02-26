using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TrustQuarantine
{
    internal static class Native_TrustManager
    {
        private const string DLL_NAME = "Xdows.Native.Trust.dll";

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CalculateFileSha256(
            [MarshalAs(UnmanagedType.LPWStr)] string filePath,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder hash,
            uint hashSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int IsFileTrusted(
            [MarshalAs(UnmanagedType.LPWStr)] string filePath,
            [MarshalAs(UnmanagedType.LPWStr)] string trustFolderPath);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CreateTrustItemJson(
            [MarshalAs(UnmanagedType.LPWStr)] string filePath,
            [MarshalAs(UnmanagedType.LPWStr)] string hash,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder json,
            uint jsonSize);

        public static string? CalculateFileHashManaged(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return null;

            StringBuilder hash = new StringBuilder(65);
            if (CalculateFileSha256(filePath, hash, (uint)hash.Capacity) != 0)
            {
                return hash.ToString().ToLowerInvariant();
            }
            return null;
        }

        public static async Task<string?> CalculateFileHashAsyncManaged(string filePath)
        {
            return await Task.Run(() => CalculateFileHashManaged(filePath));
        }

        public static bool IsPathTrustedManaged(string filePath, string trustFolderPath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                return IsFileTrusted(filePath, trustFolderPath) != 0;
            }
            catch
            {
                return false;
            }
        }

        public static string? CreateTrustItemJsonManaged(string filePath, string hash)
        {
            if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(hash))
                return null;

            StringBuilder json = new StringBuilder(1024);
            if (CreateTrustItemJson(filePath, hash, json, (uint)json.Capacity) != 0)
            {
                return json.ToString();
            }
            return null;
        }
    }
}
