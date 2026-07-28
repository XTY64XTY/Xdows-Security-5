using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Helper
{
    public enum PhysicalDiskPartitionStyle
    {
        Mbr,
        Gpt,
        Raw,
        Unknown
    }

    public sealed record PhysicalDiskInfo(
        Int32 Index,
        String Model,
        String SerialNumber,
        Int64 SizeBytes,
        PhysicalDiskPartitionStyle PartitionStyle,
        String BusType,
        Boolean IsSystemDisk)
    {
        public String DevicePath => $"\\\\.\\PhysicalDrive{Index}";
    }

    public static class DiskOperator
    {
        public const Int32 BootSectorSize = 512;

        private const UInt32 GenericRead = 0x80000000;
        private const UInt32 GenericWrite = 0x40000000;
        private const UInt32 FileShareRead = 0x00000001;
        private const UInt32 FileShareWrite = 0x00000002;
        private const UInt32 OpenExisting = 3;
        private const UInt32 FileAttributeNormal = 0x00000080;
        private const UInt32 FileBegin = 0;

        private const UInt32 IoctlStorageQueryProperty = 0x002D1400;
        private const UInt32 IoctlDiskGetDriveLayoutEx = 0x00070050;
        private const UInt32 IoctlDiskGetLengthInfo = 0x0007405C;
        private const UInt32 IoctlVolumeGetVolumeDiskExtents = 0x00560000;
        private const Int32 ErrorInsufficientBuffer = 122;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            String lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern Boolean ReadFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            out UInt32 lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern Boolean WriteFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            out UInt32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern Boolean SetFilePointerEx(
            SafeFileHandle hFile,
            Int64 liDistanceToMove,
            out Int64 lpNewFilePointer,
            UInt32 dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern Boolean FlushFileBuffers(SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern Boolean DeviceIoControl(
            SafeFileHandle hDevice,
            UInt32 dwIoControlCode,
            Byte[]? lpInBuffer,
            UInt32 nInBufferSize,
            Byte[]? lpOutBuffer,
            UInt32 nOutBufferSize,
            out UInt32 lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern UInt32 QueryDosDeviceW(
            String? lpDeviceName,
            [Out] Char[] lpTargetPath,
            UInt32 ucchMax);

        public static IReadOnlyList<PhysicalDiskInfo> GetPhysicalDisks()
        {
            HashSet<Int32> systemDiskNumbers = GetSystemDiskNumbers();
            SortedSet<Int32> diskNumbers = GetPhysicalDiskNumbers();
            diskNumbers.UnionWith(systemDiskNumbers);

            List<PhysicalDiskInfo> disks = [];
            foreach (Int32 diskNumber in diskNumbers)
            {
                String devicePath = GetPhysicalDrivePath(diskNumber);
                using SafeFileHandle handle = OpenDevice(devicePath, 0);

                String model = String.Empty;
                String serialNumber = String.Empty;
                String busType = "Unknown";
                Int64 sizeBytes = 0;
                PhysicalDiskPartitionStyle partitionStyle = PhysicalDiskPartitionStyle.Unknown;

                if (!handle.IsInvalid)
                {
                    (model, serialNumber, busType) = QueryStorageIdentity(handle);
                    sizeBytes = QueryDiskLength(handle);
                    partitionStyle = QueryPartitionStyle(handle);
                }

                disks.Add(new PhysicalDiskInfo(
                    diskNumber,
                    model,
                    serialNumber,
                    sizeBytes,
                    partitionStyle,
                    busType,
                    systemDiskNumbers.Contains(diskNumber)));
            }

            return disks;
        }

        public static Byte[] ReadBootSector(Int32 physicalDriveIndex)
        {
            return ReadSector(GetPhysicalDrivePath(physicalDriveIndex));
        }

        public static Byte[] ReadVolumeBootRecord(String driveLetter)
        {
            if (String.IsNullOrWhiteSpace(driveLetter))
                throw new ArgumentException("A drive letter is required.", nameof(driveLetter));

            String cleanLetter = driveLetter.Trim().TrimEnd(':').ToUpperInvariant();
            if (cleanLetter.Length != 1 || cleanLetter[0] is < 'A' or > 'Z')
                throw new ArgumentException("The drive letter is invalid.", nameof(driveLetter));

            return ReadSector($"\\\\.\\{cleanLetter}:");
        }

        public static void WriteBootSector(Int32 physicalDriveIndex, Byte[] bootSector)
        {
            ArgumentNullException.ThrowIfNull(bootSector);
            if (!IsValidBootSector(bootSector))
            {
                throw new InvalidDataException(
                    $"A boot-sector backup must be exactly {BootSectorSize} bytes and end with the 55 AA signature.");
            }

            String devicePath = GetPhysicalDrivePath(physicalDriveIndex);
            using (SafeFileHandle handle = OpenDevice(devicePath, GenericRead | GenericWrite))
            {
                ThrowIfInvalid(handle, devicePath);
                SeekToBeginning(handle, devicePath);

                if (!WriteFile(
                        handle,
                        bootSector,
                        BootSectorSize,
                        out UInt32 bytesWritten,
                        IntPtr.Zero))
                {
                    throw CreateWin32Exception($"Failed to write {devicePath}");
                }

                if (bytesWritten != BootSectorSize)
                    throw new IOException($"Only {bytesWritten} of {BootSectorSize} bytes were written to {devicePath}.");

                if (!FlushFileBuffers(handle))
                    throw CreateWin32Exception($"Failed to flush {devicePath}");
            }

            Byte[] verification = ReadBootSector(physicalDriveIndex);
            if (!verification.AsSpan().SequenceEqual(bootSector))
                throw new IOException($"The boot-sector write verification failed for {devicePath}.");
        }

        public static Boolean IsValidBootSector(ReadOnlySpan<Byte> data)
        {
            return data.Length == BootSectorSize &&
                data[BootSectorSize - 2] == 0x55 &&
                data[BootSectorSize - 1] == 0xAA;
        }

        private static Byte[] ReadSector(String devicePath)
        {
            using SafeFileHandle handle = OpenDevice(devicePath, GenericRead);
            ThrowIfInvalid(handle, devicePath);
            SeekToBeginning(handle, devicePath);

            Byte[] buffer = new Byte[BootSectorSize];
            if (!ReadFile(handle, buffer, BootSectorSize, out UInt32 bytesRead, IntPtr.Zero))
                throw CreateWin32Exception($"Failed to read {devicePath}");

            if (bytesRead != BootSectorSize)
                throw new IOException($"Only {bytesRead} of {BootSectorSize} bytes were read from {devicePath}.");

            return buffer;
        }

        private static SafeFileHandle OpenDevice(String devicePath, UInt32 access)
        {
            return CreateFileW(
                devicePath,
                access,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);
        }

        private static void ThrowIfInvalid(SafeFileHandle handle, String devicePath)
        {
            if (handle.IsInvalid)
                throw CreateWin32Exception($"Failed to open {devicePath}");
        }

        private static void SeekToBeginning(SafeFileHandle handle, String devicePath)
        {
            if (!SetFilePointerEx(handle, 0, out _, FileBegin))
                throw CreateWin32Exception($"Failed to seek {devicePath}");
        }

        private static Win32Exception CreateWin32Exception(String operation)
        {
            Int32 error = Marshal.GetLastWin32Error();
            return new Win32Exception(error, $"{operation}. Win32 error {error}.");
        }

        private static String GetPhysicalDrivePath(Int32 physicalDriveIndex)
        {
            if (physicalDriveIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(physicalDriveIndex));

            return $"\\\\.\\PhysicalDrive{physicalDriveIndex}";
        }

        private static SortedSet<Int32> GetPhysicalDiskNumbers()
        {
            Int32 bufferSize = 4096;
            while (bufferSize <= 1024 * 1024)
            {
                Char[] buffer = new Char[bufferSize];
                UInt32 length = QueryDosDeviceW(null, buffer, (UInt32)buffer.Length);
                if (length != 0)
                {
                    String[] deviceNames = new String(buffer, 0, (Int32)length)
                        .Split('\0', StringSplitOptions.RemoveEmptyEntries);
                    SortedSet<Int32> diskNumbers = [];
                    foreach (String deviceName in deviceNames)
                    {
                        const String prefix = "PhysicalDrive";
                        if (deviceName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                            Int32.TryParse(deviceName.AsSpan(prefix.Length), out Int32 diskNumber) &&
                            diskNumber >= 0)
                        {
                            diskNumbers.Add(diskNumber);
                        }
                    }
                    return diskNumbers;
                }

                if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
                    throw CreateWin32Exception("Failed to enumerate physical disks");

                bufferSize *= 2;
            }

            throw new IOException("The physical disk device list exceeded the supported size.");
        }

        private static HashSet<Int32> GetSystemDiskNumbers()
        {
            HashSet<Int32> diskNumbers = [];
            String? systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            if (String.IsNullOrWhiteSpace(systemRoot) || systemRoot.Length < 2)
                return diskNumbers;

            String volumePath = $"\\\\.\\{systemRoot[..2]}";
            using SafeFileHandle handle = OpenDevice(volumePath, 0);
            if (handle.IsInvalid)
                return diskNumbers;

            Byte[] output = new Byte[64 * 1024];
            if (!DeviceIoControl(
                    handle,
                    IoctlVolumeGetVolumeDiskExtents,
                    null,
                    0,
                    output,
                    (UInt32)output.Length,
                    out UInt32 bytesReturned,
                    IntPtr.Zero) ||
                bytesReturned < 32)
            {
                return diskNumbers;
            }

            UInt32 count = BitConverter.ToUInt32(output, 0);
            const Int32 firstExtentOffset = 8;
            const Int32 extentSize = 24;
            for (UInt32 index = 0; index < count; index++)
            {
                Int32 offset = firstExtentOffset + checked((Int32)index * extentSize);
                if (offset + extentSize > bytesReturned)
                    break;

                diskNumbers.Add(checked((Int32)BitConverter.ToUInt32(output, offset)));
            }

            return diskNumbers;
        }

        private static (String Model, String SerialNumber, String BusType) QueryStorageIdentity(
            SafeFileHandle handle)
        {
            Byte[] query = new Byte[12];
            Byte[] output = new Byte[4096];
            if (!DeviceIoControl(
                    handle,
                    IoctlStorageQueryProperty,
                    query,
                    (UInt32)query.Length,
                    output,
                    (UInt32)output.Length,
                    out UInt32 bytesReturned,
                    IntPtr.Zero) ||
                bytesReturned < 36)
            {
                return (String.Empty, String.Empty, "Unknown");
            }

            String vendor = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 12));
            String product = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 16));
            String serial = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 24));
            UInt32 busTypeValue = BitConverter.ToUInt32(output, 28);
            String model = String.Join(' ', new[] { vendor, product }.Where(value => !String.IsNullOrWhiteSpace(value)));
            return (model.Trim(), serial.Trim(), FormatBusType(busTypeValue));
        }

        private static String ReadDescriptorString(Byte[] buffer, UInt32 bytesReturned, UInt32 offset)
        {
            if (offset == 0 || offset >= bytesReturned)
                return String.Empty;

            Int32 start = checked((Int32)offset);
            Int32 limit = checked((Int32)Math.Min(bytesReturned, (UInt32)buffer.Length));
            Int32 end = start;
            while (end < limit && buffer[end] != 0)
                end++;

            return Encoding.ASCII.GetString(buffer, start, end - start).Trim();
        }

        private static Int64 QueryDiskLength(SafeFileHandle handle)
        {
            Byte[] output = new Byte[8];
            return DeviceIoControl(
                    handle,
                    IoctlDiskGetLengthInfo,
                    null,
                    0,
                    output,
                    (UInt32)output.Length,
                    out UInt32 bytesReturned,
                    IntPtr.Zero) &&
                bytesReturned >= output.Length
                ? BitConverter.ToInt64(output, 0)
                : 0;
        }

        private static PhysicalDiskPartitionStyle QueryPartitionStyle(SafeFileHandle handle)
        {
            Byte[] output = new Byte[64 * 1024];
            if (!DeviceIoControl(
                    handle,
                    IoctlDiskGetDriveLayoutEx,
                    null,
                    0,
                    output,
                    (UInt32)output.Length,
                    out UInt32 bytesReturned,
                    IntPtr.Zero) ||
                bytesReturned < sizeof(UInt32))
            {
                return PhysicalDiskPartitionStyle.Unknown;
            }

            return BitConverter.ToUInt32(output, 0) switch
            {
                0 => PhysicalDiskPartitionStyle.Mbr,
                1 => PhysicalDiskPartitionStyle.Gpt,
                2 => PhysicalDiskPartitionStyle.Raw,
                _ => PhysicalDiskPartitionStyle.Unknown
            };
        }

        private static String FormatBusType(UInt32 busType)
        {
            return busType switch
            {
                1 => "SCSI",
                2 => "ATAPI",
                3 => "ATA",
                4 => "IEEE 1394",
                6 => "Fibre Channel",
                7 => "USB",
                8 => "RAID",
                9 => "iSCSI",
                10 => "SAS",
                11 => "SATA",
                12 => "SD",
                13 => "MMC",
                14 => "Virtual",
                15 => "File-backed virtual",
                16 => "Storage Spaces",
                17 => "NVMe",
                18 => "SCM",
                19 => "UFS",
                _ => "Unknown"
            };
        }
    }
}
