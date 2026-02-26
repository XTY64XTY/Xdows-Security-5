using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Xdows_Local
{
    internal static class Native_ScriptScanner
    {
        private const string DLL_NAME = "Xdows.Native.Script.dll";

        [StructLayout(LayoutKind.Sequential)]
        public struct ScriptScanResult
        {
            public int Score;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
            public string Tags;
        }

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ScanScriptFile(
            [MarshalAs(UnmanagedType.LPWStr)] string filePath,
            byte[] content,
            uint contentSize,
            out ScriptScanResult result);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int IsScriptFile(
            [MarshalAs(UnmanagedType.LPWStr)] string extension);

        public static (int score, string extra) ScanScriptFileManaged(string filePath, byte[] fileContent)
        {
            if (fileContent == null || fileContent.Length == 0)
                return (0, string.Empty);

            ScriptScanResult result = new ScriptScanResult();
            int ret = ScanScriptFile(filePath, fileContent, (uint)fileContent.Length, out result);

            if (ret != 0)
            {
                return (result.Score, result.Tags);
            }

            return (0, string.Empty);
        }

        public static bool IsScriptFileManaged(string extension)
        {
            if (string.IsNullOrEmpty(extension))
                return false;

            return IsScriptFile(extension) != 0;
        }
    }
}
