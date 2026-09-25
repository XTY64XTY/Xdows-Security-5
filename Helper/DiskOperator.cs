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
        int Index,
        string Model,
        string SerialNumber,
        Int64 SizeBytes,
        PhysicalDiskPartitionStyle PartitionStyle,
        string BusType,
        bool IsSystemDisk)
    {
        public string DevicePath => $"\\\\.\\PhysicalDrive{Index}";
    }

    public static class DiskOperator
    {
        public const int BootSectorSize = 512;

        private const UInt32 GenericRead = 0x80000000;
        private const UInt32 GenericWrite = 0x40000000;
        private const UInt32 FileShareRead = 0x00000001;
        private const UInt32 FileShareWrite = 0x00000002;
        private const UInt32 OpenExisting = 3;
        private const UInt32 FileAttributeNormal = 0x00000080;
        private const UInt32 FileBegin = 0;

        private const UInt32 IoctlStorageQueryProperty = 0x002D1400;
        private const UInt32 IoctlDiskGetDriveLayoutEx = 0x00070050;
        private const UInt32 IoctlDiskGetDriveGeometryEx = 0x000700A0;
        private const UInt32 IoctlDiskGetLengthInfo = 0x0007405C;
        private const UInt32 IoctlVolumeGetVolumeDiskExtents = 0x00560000;
        private const int ErrorInsufficientBuffer = 122;
        private const int MaxRawRegionSize = 16 * 1024 * 1024;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            out UInt32 lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            out UInt32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(
            SafeFileHandle hFile,
            Int64 liDistanceToMove,
            out Int64 lpNewFilePointer,
            UInt32 dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushFileBuffers(SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
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
            string? lpDeviceName,
            [Out] Char[] lpTargetPath,
            UInt32 ucchMax);

        public static IReadOnlyList<PhysicalDiskInfo> GetPhysicalDisks()
        {
            HashSet<int> systemDiskNumbers = GetSystemDiskNumbers();
            SortedSet<int> diskNumbers = GetPhysicalDiskNumbers();
            diskNumbers.UnionWith(systemDiskNumbers);

            List<PhysicalDiskInfo> disks = [];
            foreach (int diskNumber in diskNumbers)
            {
                string devicePath = GetPhysicalDrivePath(diskNumber);
                using SafeFileHandle handle = OpenDevice(devicePath, 0);

                string model = string.Empty;
                string serialNumber = string.Empty;
                string busType = "Unknown";
                Int64 sizeBytes = 0;
                PhysicalDiskPartitionStyle partitionStyle = PhysicalDiskPartitionStyle.Unknown;

                if (!handle.IsInvalid)
                {
                    (model, serialNumber, busType) = QueryStorageIdentity(handle);
                    sizeBytes = QueryDiskLength(handle);
                    partitionStyle = QueryPartitionStyle(handle);
                }

                if (sizeBytes <= 0)
                {
                    // Some storage stacks refuse IOCTL_DISK_GET_LENGTH_INFO on a
                    // zero-access handle. Retry with read access before giving up,
                    // otherwise callers see a bogus disk size of 0.
                    sizeBytes = QueryDiskLengthWithReadAccess(devicePath);
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

        public static Byte[] ReadBootSector(int physicalDriveIndex)
        {
            return ReadDiskRegion(physicalDriveIndex, 0, BootSectorSize);
        }

        public static Byte[] ReadVolumeBootRecord(string driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter))
                throw new ArgumentException("A drive letter is required.", nameof(driveLetter));

            string cleanLetter = driveLetter.Trim().TrimEnd(':').ToUpperInvariant();
            if (cleanLetter.Length != 1 || cleanLetter[0] is < 'A' or > 'Z')
                throw new ArgumentException("The drive letter is invalid.", nameof(driveLetter));

            return ReadSector($"\\\\.\\{cleanLetter}:");
        }

        public static void WriteBootSector(int physicalDriveIndex, Byte[] bootSector)
        {
            ArgumentNullException.ThrowIfNull(bootSector);
            if (!IsValidBootSector(bootSector))
            {
                throw new InvalidDataException(
                    $"A boot-sector backup must be exactly {BootSectorSize} bytes and end with the 55 AA signature.");
            }

            WriteDiskRegion(physicalDriveIndex, 0, bootSector);
        }

        public static Int64 GetDiskLength(int physicalDriveIndex)
        {
            string devicePath = GetPhysicalDrivePath(physicalDriveIndex);
            using SafeFileHandle handle = OpenDevice(devicePath, GenericRead);
            ThrowIfInvalid(handle, devicePath);

            Int64 diskLength = QueryDiskLength(handle);
            if (diskLength <= 0)
                throw new IOException($"The size of {devicePath} could not be determined.");

            return diskLength;
        }

        public static int GetLogicalSectorSize(int physicalDriveIndex)
        {
            string devicePath = GetPhysicalDrivePath(physicalDriveIndex);
            using SafeFileHandle handle = OpenDevice(devicePath, 0);
            ThrowIfInvalid(handle, devicePath);

            Byte[] output = new Byte[256];
            if (!DeviceIoControl(
                    handle,
                    IoctlDiskGetDriveGeometryEx,
                    null,
                    0,
                    output,
                    (UInt32)output.Length,
                    out UInt32 bytesReturned,
                    IntPtr.Zero) ||
                bytesReturned < 24)
            {
                throw CreateWin32Exception($"Failed to query disk geometry for {devicePath}");
            }

            UInt32 bytesPerSector = BitConverter.ToUInt32(output, 20);
            if (bytesPerSector is < BootSectorSize or > 64 * 1024 ||
                (bytesPerSector & (bytesPerSector - 1)) != 0)
            {
                throw new IOException($"Disk {physicalDriveIndex} reported an invalid logical sector size: {bytesPerSector}.");
            }

            return checked((int)bytesPerSector);
        }

        public static Byte[] ReadDiskRegion(int physicalDriveIndex, Int64 offset, int length)
        {
            ValidateRegion(offset, length);
            string devicePath = GetPhysicalDrivePath(physicalDriveIndex);
            using SafeFileHandle handle = OpenDevice(devicePath, GenericRead);
            ThrowIfInvalid(handle, devicePath);
            ValidateRegionWithinDevice(handle, offset, length, devicePath);
            Seek(handle, devicePath, offset);

            Byte[] buffer = new Byte[length];
            if (!ReadFile(handle, buffer, (UInt32)length, out UInt32 bytesRead, IntPtr.Zero))
                throw CreateWin32Exception($"Failed to read {devicePath} at offset {offset}");

            if (bytesRead != length)
                throw new IOException($"Only {bytesRead} of {length} bytes were read from {devicePath} at offset {offset}.");

            return buffer;
        }

        public static void WriteDiskRegion(int physicalDriveIndex, Int64 offset, Byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            ValidateRegion(offset, data.Length);

            string devicePath = GetPhysicalDrivePath(physicalDriveIndex);
            using (SafeFileHandle handle = OpenDevice(devicePath, GenericRead | GenericWrite))
            {
                ThrowIfInvalid(handle, devicePath);
                ValidateRegionWithinDevice(handle, offset, data.Length, devicePath);
                Seek(handle, devicePath, offset);

                if (!WriteFile(handle, data, (UInt32)data.Length, out UInt32 bytesWritten, IntPtr.Zero))
                    throw CreateWin32Exception($"Failed to write {devicePath} at offset {offset}");

                if (bytesWritten != data.Length)
                    throw new IOException($"Only {bytesWritten} of {data.Length} bytes were written to {devicePath} at offset {offset}.");

                if (!FlushFileBuffers(handle))
                    throw CreateWin32Exception($"Failed to flush {devicePath}");
            }

            Byte[] verification = ReadDiskRegion(physicalDriveIndex, offset, data.Length);
            if (!verification.AsSpan().SequenceEqual(data))
                throw new IOException($"The disk-region write verification failed for {devicePath} at offset {offset}.");
        }

        public static bool IsValidBootSector(ReadOnlySpan<Byte> data)
        {
            return data.Length == BootSectorSize &&
                data[BootSectorSize - 2] == 0x55 &&
                data[BootSectorSize - 1] == 0xAA;
        }

        private static Byte[] ReadSector(string devicePath)
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

        private static void ValidateRegion(Int64 offset, int length)
        {
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (length <= 0 || length > MaxRawRegionSize)
                throw new ArgumentOutOfRangeException(nameof(length), $"Raw disk regions must be between 1 and {MaxRawRegionSize} bytes.");
            _ = checked(offset + length);
        }

        private static void ValidateRegionWithinDevice(
            SafeFileHandle handle,
            Int64 offset,
            int length,
            string devicePath)
        {
            Int64 diskLength = QueryDiskLength(handle);
            if (diskLength <= 0)
                throw new IOException($"The size of {devicePath} could not be determined.");
            if (checked(offset + length) > diskLength)
                throw new ArgumentOutOfRangeException(nameof(length), "The raw disk region extends past the end of the device.");
        }

        private static SafeFileHandle OpenDevice(string devicePath, UInt32 access)
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

        private static void ThrowIfInvalid(SafeFileHandle handle, string devicePath)
        {
            if (handle.IsInvalid)
                throw CreateWin32Exception($"Failed to open {devicePath}");
        }

        private static void SeekToBeginning(SafeFileHandle handle, string devicePath)
        {
            Seek(handle, devicePath, 0);
        }

        private static void Seek(SafeFileHandle handle, string devicePath, Int64 offset)
        {
            if (!SetFilePointerEx(handle, offset, out Int64 newOffset, FileBegin) || newOffset != offset)
                throw CreateWin32Exception($"Failed to seek {devicePath} to offset {offset}");
        }

        private static Win32Exception CreateWin32Exception(string operation)
        {
            int error = Marshal.GetLastWin32Error();
            return new Win32Exception(error, $"{operation}. Win32 error {error}.");
        }

        private static string GetPhysicalDrivePath(int physicalDriveIndex)
        {
            if (physicalDriveIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(physicalDriveIndex));

            return $"\\\\.\\PhysicalDrive{physicalDriveIndex}";
        }

        private static SortedSet<int> GetPhysicalDiskNumbers()
        {
            int bufferSize = 4096;
            while (bufferSize <= 1024 * 1024)
            {
                Char[] buffer = new Char[bufferSize];
                UInt32 length = QueryDosDeviceW(null, buffer, (UInt32)buffer.Length);
                if (length != 0)
                {
                    string[] deviceNames = new string(buffer, 0, (int)length)
                        .Split('\0', StringSplitOptions.RemoveEmptyEntries);
                    SortedSet<int> diskNumbers = [];
                    foreach (string deviceName in deviceNames)
                    {
                        const string prefix = "PhysicalDrive";
                        if (deviceName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                            int.TryParse(deviceName.AsSpan(prefix.Length), out int diskNumber) &&
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

        private static HashSet<int> GetSystemDiskNumbers()
        {
            HashSet<int> diskNumbers = [];
            string? systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrWhiteSpace(systemRoot) || systemRoot.Length < 2)
                return diskNumbers;

            string volumePath = $"\\\\.\\{systemRoot[..2]}";
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
            const int firstExtentOffset = 8;
            const int extentSize = 24;
            for (UInt32 index = 0; index < count; index++)
            {
                int offset = firstExtentOffset + checked((int)index * extentSize);
                if (offset + extentSize > bytesReturned)
                    break;

                diskNumbers.Add(checked((int)BitConverter.ToUInt32(output, offset)));
            }

            return diskNumbers;
        }

        private static (string Model, string SerialNumber, string BusType) QueryStorageIdentity(
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
                return (string.Empty, string.Empty, "Unknown");
            }

            string vendor = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 12));
            string product = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 16));
            string serial = ReadDescriptorString(output, bytesReturned, BitConverter.ToUInt32(output, 24));
            UInt32 busTypeValue = BitConverter.ToUInt32(output, 28);
            string model = string.Join(' ', new[] { vendor, product }.Where(value => !string.IsNullOrWhiteSpace(value)));
            return (model.Trim(), serial.Trim(), FormatBusType(busTypeValue));
        }

        private static string ReadDescriptorString(Byte[] buffer, UInt32 bytesReturned, UInt32 offset)
        {
            if (offset == 0 || offset >= bytesReturned)
                return string.Empty;

            int start = checked((int)offset);
            int limit = checked((int)Math.Min(bytesReturned, (UInt32)buffer.Length));
            int end = start;
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

        private static Int64 QueryDiskLengthWithReadAccess(string devicePath)
        {
            using SafeFileHandle handle = OpenDevice(devicePath, GenericRead);
            return handle.IsInvalid ? 0 : QueryDiskLength(handle);
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

        private static string FormatBusType(UInt32 busType)
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
