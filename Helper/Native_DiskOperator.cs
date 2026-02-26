using System;
using System.Runtime.InteropServices;

namespace Helper
{
    internal static class Native_DiskOperator
    {
        private const string DLL_NAME = "Xdows.Native.Core.dll";

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReadBootSector(int driveIndex, byte[] buffer, uint bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReadVolumeBootRecord([MarshalAs(UnmanagedType.LPWStr)] string driveLetter, byte[] buffer, uint bufferSize);

        public static byte[]? ReadBootSectorManaged(int physicalDriveIndex)
        {
            byte[] buffer = new byte[512];
            int result = ReadBootSector(physicalDriveIndex, buffer, (uint)buffer.Length);
            return result != 0 ? buffer : null;
        }

        public static byte[]? ReadVolumeBootRecordManaged(string driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter))
                return null;

            string cleanLetter = driveLetter.TrimEnd(':').ToUpper();
            byte[] buffer = new byte[512];
            int result = ReadVolumeBootRecord(cleanLetter, buffer, (uint)buffer.Length);
            return result != 0 ? buffer : null;
        }
    }
}
