using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Xdows_Local
{
    internal static class Native_RegistryScanner
    {
        private const string DLL_NAME = "Xdows.Native.Registry.dll";

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ScanRegistryKey(
            [MarshalAs(UnmanagedType.LPWStr)] string keyPath,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder threatType,
            uint threatTypeSize);

        public static string ScanManaged(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return string.Empty;

            StringBuilder threatType = new StringBuilder(256);
            int result = ScanRegistryKey(key, threatType, (uint)threatType.Capacity);

            return result != 0 ? threatType.ToString() : string.Empty;
        }
    }
}
