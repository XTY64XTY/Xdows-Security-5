using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace Helper;

/// <summary>
/// Enumerates active NTFS file records through the volume's master file table.
/// Callers must retain their directory-walk fallback because direct volume access
/// can be unavailable even when the underlying file system is NTFS.
/// </summary>
public static class NtfsFileTableIndexer
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FsctlEnumUsnData = 0x000900B3;
    private const int ErrorHandleEof = 38;
    private const int OutputBufferSize = 1024 * 1024;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const ulong NtfsFileRecordNumberMask = 0x0000FFFFFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct MftEnumData
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private sealed record FileRecord(
        ulong ReferenceNumber,
        ulong ParentReferenceNumber,
        string Name,
        bool IsDirectory);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        ref MftEnumData input,
        int inputSize,
        byte[] output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    public static bool TryEnumerateFiles(
        string rootPath,
        out IReadOnlyList<string> files,
        out string? errorMessage)
    {
        files = [];
        errorMessage = null;

        try
        {
            string fullRoot = Path.GetFullPath(rootPath);
            string? volumeRoot = Path.GetPathRoot(fullRoot);
            if (string.IsNullOrEmpty(volumeRoot))
            {
                errorMessage = "The path does not have a volume root.";
                return false;
            }

            DriveInfo drive = new(volumeRoot);
            if (!drive.IsReady)
            {
                errorMessage = $"Volume '{volumeRoot}' is not ready.";
                return false;
            }
            if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            {
                errorMessage = $"Volume '{volumeRoot}' uses the unsupported '{drive.DriveFormat}' file system.";
                return false;
            }

            string volumeDevice = $@"\\.\{volumeRoot.TrimEnd(Path.DirectorySeparatorChar)}";
            using SafeFileHandle handle = CreateFileW(
                volumeDevice,
                GenericRead,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                int errorCode = Marshal.GetLastWin32Error();
                errorMessage = $"Unable to open volume '{volumeRoot}'. Win32 error {errorCode}: {new Win32Exception(errorCode).Message}";
                return false;
            }

            if (!TryReadFileRecords(handle, out Dictionary<ulong, FileRecord> records, out errorMessage))
                return false;

            string normalizedRoot = Path.TrimEndingDirectorySeparator(fullRoot);
            if (!TryGetFileReferenceNumber(normalizedRoot, out ulong rootReferenceNumber, out errorMessage))
                return false;

            Dictionary<ulong, List<FileRecord>> childrenByParent = new();
            foreach (FileRecord record in records.Values)
            {
                ulong parentRecordNumber = GetRecordNumber(record.ParentReferenceNumber);
                if (!childrenByParent.TryGetValue(parentRecordNumber, out List<FileRecord>? children))
                {
                    children = [];
                    childrenByParent[parentRecordNumber] = children;
                }
                children.Add(record);
            }

            List<string> result = new(records.Count);
            Queue<(ulong ReferenceNumber, string Path)> directories = new();
            HashSet<ulong> visitedDirectories = [];
            ulong rootRecordNumber = GetRecordNumber(rootReferenceNumber);
            directories.Enqueue((rootRecordNumber, normalizedRoot));
            visitedDirectories.Add(rootRecordNumber);

            while (directories.TryDequeue(out (ulong ReferenceNumber, string Path) directory))
            {
                if (!childrenByParent.TryGetValue(directory.ReferenceNumber, out List<FileRecord>? children))
                    continue;

                foreach (FileRecord record in children)
                {
                    string childPath = Path.Combine(directory.Path, record.Name);
                    if (record.IsDirectory)
                    {
                        ulong childRecordNumber = GetRecordNumber(record.ReferenceNumber);
                        if (visitedDirectories.Add(childRecordNumber))
                            directories.Enqueue((childRecordNumber, childPath));
                    }
                    else
                    {
                        result.Add(childPath);
                    }
                }
            }

            if (result.Count == 0 && Directory.EnumerateFileSystemEntries(normalizedRoot).Any())
            {
                errorMessage = $"No NTFS child records were found for file reference 0x{rootReferenceNumber:X}.";
                return false;
            }

            files = result;
            return true;
        }
        catch (Exception ex)
        {
            files = [];
            errorMessage = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static bool TryReadFileRecords(
        SafeFileHandle handle,
        out Dictionary<ulong, FileRecord> records,
        out string? errorMessage)
    {
        records = [];
        errorMessage = null;
        MftEnumData input = new()
        {
            StartFileReferenceNumber = 0,
            LowUsn = 0,
            HighUsn = long.MaxValue
        };
        byte[] buffer = new byte[OutputBufferSize];

        while (true)
        {
            bool succeeded = DeviceIoControl(
                handle,
                FsctlEnumUsnData,
                ref input,
                Marshal.SizeOf<MftEnumData>(),
                buffer,
                buffer.Length,
                out int bytesReturned,
                IntPtr.Zero);

            if (!succeeded)
            {
                int errorCode = Marshal.GetLastWin32Error();
                if (errorCode == ErrorHandleEof)
                    return true;

                errorMessage = $"FSCTL_ENUM_USN_DATA failed. Win32 error {errorCode}: {new Win32Exception(errorCode).Message}";
                return false;
            }

            if (bytesReturned < sizeof(ulong))
            {
                errorMessage = $"FSCTL_ENUM_USN_DATA returned an invalid {bytesReturned}-byte response.";
                return false;
            }

            input.StartFileReferenceNumber = BitConverter.ToUInt64(buffer, 0);
            int offset = sizeof(ulong);
            while (offset < bytesReturned)
            {
                if (bytesReturned - offset < 60)
                {
                    errorMessage = "The NTFS file table response contains a truncated USN record header.";
                    return false;
                }

                uint recordLength = BitConverter.ToUInt32(buffer, offset);
                ushort majorVersion = BitConverter.ToUInt16(buffer, offset + 4);
                if (recordLength < 60 || offset + recordLength > bytesReturned)
                {
                    errorMessage = $"The NTFS file table response contains an invalid {recordLength}-byte USN record.";
                    return false;
                }
                if (majorVersion != 2)
                {
                    errorMessage = $"Unsupported USN record version {majorVersion}.";
                    return false;
                }

                ulong referenceNumber = BitConverter.ToUInt64(buffer, offset + 8);
                ulong parentReferenceNumber = BitConverter.ToUInt64(buffer, offset + 16);
                uint attributes = BitConverter.ToUInt32(buffer, offset + 52);
                ushort nameLength = BitConverter.ToUInt16(buffer, offset + 56);
                ushort nameOffset = BitConverter.ToUInt16(buffer, offset + 58);
                if (nameOffset + nameLength > recordLength || (nameLength & 1) != 0)
                {
                    errorMessage = "The NTFS file table response contains an invalid file name range.";
                    return false;
                }

                string name = Encoding.Unicode.GetString(buffer, offset + nameOffset, nameLength);
                records[referenceNumber] = new FileRecord(
                    referenceNumber,
                    parentReferenceNumber,
                    name,
                    (attributes & FileAttributeDirectory) != 0);

                offset += checked((int)recordLength);
            }
        }
    }

    private static bool TryGetFileReferenceNumber(
        string directoryPath,
        out ulong referenceNumber,
        out string? errorMessage)
    {
        referenceNumber = 0;
        errorMessage = null;
        using SafeFileHandle handle = CreateFileW(
            directoryPath,
            0,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int errorCode = Marshal.GetLastWin32Error();
            errorMessage = $"Unable to open directory '{directoryPath}'. Win32 error {errorCode}: {new Win32Exception(errorCode).Message}";
            return false;
        }

        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            int errorCode = Marshal.GetLastWin32Error();
            errorMessage = $"Unable to read the file ID for '{directoryPath}'. Win32 error {errorCode}: {new Win32Exception(errorCode).Message}";
            return false;
        }

        referenceNumber = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        return true;
    }

    private static ulong GetRecordNumber(ulong referenceNumber) =>
        referenceNumber & NtfsFileRecordNumberMask;
}
