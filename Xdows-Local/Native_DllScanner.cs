using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Xdows_Local
{
    internal static class Native_DllScanner
    {
        private const string DLL_NAME = "Xdows.Native.PE.dll";

        [StructLayout(LayoutKind.Sequential)]
        public struct PEExportInfo
        {
            public IntPtr ExportNames;
            public int ExportCount;
        }

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ScanDllExports(
            ref PEExportInfo peInfo,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder detection,
            uint detectionSize);

        public static bool ScanManaged(string[] exportsName)
        {
            if (exportsName == null || exportsName.Length == 0)
                return false;

            IntPtr[] namePointers = new IntPtr[exportsName.Length];
            GCHandle[] handles = new GCHandle[exportsName.Length];

            try
            {
                for (int i = 0; i < exportsName.Length; i++)
                {
                    handles[i] = GCHandle.Alloc(
                        Marshal.StringToHGlobalUni(exportsName[i] ?? string.Empty),
                        GCHandleType.Pinned);
                    namePointers[i] = handles[i].AddrOfPinnedObject();
                }

                GCHandle arrayHandle = GCHandle.Alloc(namePointers, GCHandleType.Pinned);
                try
                {
                    PEExportInfo info = new PEExportInfo
                    {
                        ExportNames = arrayHandle.AddrOfPinnedObject(),
                        ExportCount = exportsName.Length
                    };

                    StringBuilder detection = new StringBuilder(256);
                    int result = ScanDllExports(ref info, detection, (uint)detection.Capacity);

                    return result != 0;
                }
                finally
                {
                    arrayHandle.Free();
                }
            }
            finally
            {
                for (int i = 0; i < handles.Length; i++)
                {
                    if (handles[i].IsAllocated)
                    {
                        Marshal.FreeHGlobal((IntPtr)handles[i].Target);
                        handles[i].Free();
                    }
                }
            }
        }
    }
}
