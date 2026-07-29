using System.Runtime.InteropServices;

namespace Protection;

internal static class BootFilterProtocol
{
    public const uint ProtocolVersion = 1;
    public const ulong DriverBuildId = 2026072901;
    public const int MaxRanges = 8;
    public const uint MaxRequestBytes = 1 * 1024 * 1024;
    public const uint MaxPendingBytes = 8 * 1024 * 1024;
    public const uint DecisionTimeoutMs = 25_000;
    public static readonly string[] DevicePaths =
    [
        @"\\.\XdowsSecurityBootFilter",
        @"\\.\Global\XdowsSecurityBootFilter"
    ];

    private const uint FileDeviceXdowsBoot = 0x8001;
    private const uint MethodBuffered = 0;
    private const uint FileReadData = 0x0001;
    private const uint FileWriteData = 0x0002;

    public static readonly uint RegisterClient = CtlCode(FileDeviceXdowsBoot, 0x901, MethodBuffered, FileReadData | FileWriteData);
    public static readonly uint Configure = CtlCode(FileDeviceXdowsBoot, 0x902, MethodBuffered, FileReadData | FileWriteData);
    public static readonly uint GetNextEvent = CtlCode(FileDeviceXdowsBoot, 0x903, MethodBuffered, FileReadData | FileWriteData);
    public static readonly uint SubmitDecision = CtlCode(FileDeviceXdowsBoot, 0x904, MethodBuffered, FileReadData | FileWriteData);
    public static readonly uint GetState = CtlCode(FileDeviceXdowsBoot, 0x905, MethodBuffered, FileReadData | FileWriteData);

    public static BootFilterHeader Header<T>() where T : struct => new()
    {
        Size = checked((uint)Marshal.SizeOf<T>()),
        Version = ProtocolVersion
    };

    private static uint CtlCode(uint deviceType, uint function, uint method, uint access) =>
        (deviceType << 16) | (access << 14) | (function << 2) | method;
}

internal enum BootFilterDecisionType : uint
{
    Unknown = 0,
    Allow = 1,
    Block = 2
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterHeader
{
    public uint Size;
    public uint Version;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterRegisterRequest
{
    public BootFilterHeader Header;
    public uint ClientProcessId;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterRegisterResponse
{
    public BootFilterHeader Header;
    public uint ProtocolVersion;
    public uint MaxRequestBytes;
    public uint MaxPendingBytes;
    public uint DecisionTimeoutMs;
    public ulong DriverBuildId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterRawRange
{
    public long Offset;
    public ulong Length;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterConfigureRequest
{
    public BootFilterHeader Header;
    public uint DiskNumber;
    public uint RangeCount;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = BootFilterProtocol.MaxRanges)]
    public BootFilterRawRange[] Ranges;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterWriteEvent
{
    public BootFilterHeader Header;
    public ulong EventId;
    public uint DiskNumber;
    public uint ProcessId;
    public long Offset;
    public uint Length;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterDecision
{
    public BootFilterHeader Header;
    public ulong EventId;
    public uint Decision;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BootFilterState
{
    public BootFilterHeader Header;
    public uint ClientConnected;
    public uint Configured;
    public uint Attached;
    public uint DiskNumber;
    public uint PendingRequestCount;
    public uint PendingBytes;
    public uint BlockedNoClientCount;
    public uint BlockedResourceCount;
    public uint TimedOutCount;
    public uint Reserved;
    public ulong DriverBuildId;
}
