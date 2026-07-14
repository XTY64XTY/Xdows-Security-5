using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Protection;

internal static class DriverPathNormalizer
{
    private static readonly Lazy<IReadOnlyList<(string Device, string Drive)>> DeviceMappings =
        new(BuildDeviceMappings, LazyThreadSafetyMode.ExecutionAndPublication);

    public static string Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;

        string normalized = path.Trim();
        if (normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(GetSystemRoot(), normalized[@"\SystemRoot\".Length..]);

        if (normalized.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + normalized[@"\??\UNC\".Length..];

        if (normalized.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            normalized = normalized[@"\??\".Length..];
            if (normalized.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase))
                return @"\\?\" + normalized;
        }

        if (normalized.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[@"\DosDevices\".Length..];
            if (normalized.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                return @"\\" + normalized[@"UNC\".Length..];
        }

        if (normalized.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + normalized[@"\Device\Mup\".Length..];

        if (!normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return normalized;

        foreach ((string device, string drive) in DeviceMappings.Value)
        {
            if (normalized.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                (normalized.Length == device.Length || normalized[device.Length] == '\\'))
            {
                return drive + normalized[device.Length..];
            }
        }

        return normalized;
    }

    public static string GetStableFileIdentity(string path)
    {
        try
        {
            using SafeFileHandle handle = File.OpenHandle(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (GetFileInformationByHandle(handle, out ByHandleFileInformation info))
            {
                ulong fileIndex = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
                ulong fileSize = ((ulong)info.FileSizeHigh << 32) | info.FileSizeLow;
                long lastWrite = ((long)info.LastWriteTimeHigh << 32) | info.LastWriteTimeLow;
                return $"{info.VolumeSerialNumber:X8}:{fileIndex:X16}:{fileSize}:{lastWrite}";
            }
        }
        catch
        {
        }

        var fallback = new FileInfo(path);
        return $"{path}:{fallback.Length}:{fallback.LastWriteTimeUtc.Ticks}";
    }

    private static IReadOnlyList<(string Device, string Drive)> BuildDeviceMappings()
    {
        var mappings = new List<(string Device, string Drive)>();
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            string root = drive.Name.TrimEnd('\\');
            if (root.Length != 2)
                continue;

            var target = new StringBuilder(1024);
            if (QueryDosDevice(root, target, target.Capacity) != 0)
                mappings.Add((target.ToString(), root));
        }

        return mappings
            .OrderByDescending(mapping => mapping.Device.Length)
            .ToArray();
    }

    private static string GetSystemRoot()
    {
        string? systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (!string.IsNullOrWhiteSpace(systemRoot))
            return systemRoot.TrimEnd('\\');

        return Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maxLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
        public uint LastWriteTimeLow => unchecked((uint)LastWriteTime);
        public uint LastWriteTimeHigh => unchecked((uint)(LastWriteTime >> 32));
    }
}
