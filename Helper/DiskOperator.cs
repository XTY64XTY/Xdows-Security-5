using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Helper
{
    public static class DiskOperator
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

        public static byte[] ReadBootSector(int physicalDriveIndex)
        {
            const uint SECTOR_SIZE = 512;
            string devicePath = $"\\\\.\\PhysicalDrive{physicalDriveIndex}";

            using var handle = CreateFileW(
                devicePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (handle.IsInvalid)
                return [];

            byte[] buffer = new byte[SECTOR_SIZE];
            bool success = ReadFile(handle, buffer, SECTOR_SIZE, out uint bytesRead, IntPtr.Zero);

            return success && bytesRead == SECTOR_SIZE ? buffer : [];
        }

        public static byte[] ReadVolumeBootRecord(string driveLetter)
        {
            const uint SECTOR_SIZE = 512;
            string cleanLetter = driveLetter.TrimEnd(':').ToUpper();
            string devicePath = $"\\\\.\\{cleanLetter}:";

            using var handle = CreateFileW(
                devicePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (handle.IsInvalid)
                return [];

            byte[] buffer = new byte[SECTOR_SIZE];
            bool success = ReadFile(handle, buffer, SECTOR_SIZE, out uint bytesRead, IntPtr.Zero);

            return success && bytesRead == SECTOR_SIZE ? buffer : [];
        }
    }
}
