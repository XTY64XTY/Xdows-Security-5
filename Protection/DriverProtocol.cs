using System.Runtime.InteropServices;

namespace Protection;

internal static class DriverProtocol
{
    public const uint ProtocolVersion = 6;
    public const ulong DriverBuildId = 2026071802;
    public const uint LegacyUpgradeProtocolVersion = 6;
    public const ulong LegacyUpgradeDriverBuildId = 2026071801;
    public const uint PreviousLegacyUpgradeProtocolVersion = 5;
    public const ulong PreviousLegacyUpgradeDriverBuildId = 2026071704;
    public const ulong OldestLegacyUpgradeDriverBuildId = 2026071703;
    public const int EventTypeCount = 9;
    public const uint CapabilityPriorityQueue = 0x00000001;
    public const uint CapabilityDirtyWriteCoalescing = 0x00000002;
    public const uint CapabilityBuildId = 0x00000004;
    public const uint CapabilityStartupSelfProtect = 0x00000008;
    public const uint CapabilityUserDecisionHold = 0x00000010;
    public const uint CapabilityProcessManagement = 0x00000020;
    public const uint RequiredCapabilities = CapabilityPriorityQueue |
        CapabilityDirtyWriteCoalescing |
        CapabilityBuildId |
        CapabilityStartupSelfProtect |
        CapabilityUserDecisionHold |
        CapabilityProcessManagement;
    public const uint ModuleTokenAuth = 0x00000001;
    public const uint ModuleProcess = 0x00000002;
    public const uint ModuleFile = 0x00000004;
    public const uint ModuleInjection = 0x00000008;
    public const uint ModuleSelfProtect = 0x00000010;
    public const uint RequiredModules = ModuleTokenAuth | ModuleProcess | ModuleFile | ModuleInjection | ModuleSelfProtect;
    public const int MaxPathChars = 520;
    public const int MaxCommandChars = 1024;
    public const int MaxReasonChars = 128;
    public const int TokenChars = 64;
    public const int MaxLogModuleChars = 32;
    public const int MaxLogMessageChars = 256;
    public const int MaxProcessNameChars = 260;
    public const int ProcessBatchSize = 64;
    public const string DevicePath = @"\\.\XdowsSecurityDriver";
    public const string GlobalDevicePath = @"\\.\Global\XdowsSecurityDriver";
    public static readonly string[] DevicePaths = [DevicePath, GlobalDevicePath];

    private const uint FileDeviceXdowsSecurity = 0x8000;
    private const uint MethodBuffered = 0;
    private const uint FileAnyAccess = 0;

    public static readonly uint RegisterClient = CtlCode(FileDeviceXdowsSecurity, 0x801, MethodBuffered, FileAnyAccess);
    public static readonly uint Heartbeat = CtlCode(FileDeviceXdowsSecurity, 0x802, MethodBuffered, FileAnyAccess);
    public static readonly uint GetNextEvent = CtlCode(FileDeviceXdowsSecurity, 0x803, MethodBuffered, FileAnyAccess);
    public static readonly uint SubmitDecision = CtlCode(FileDeviceXdowsSecurity, 0x804, MethodBuffered, FileAnyAccess);
    public static readonly uint GetState = CtlCode(FileDeviceXdowsSecurity, 0x805, MethodBuffered, FileAnyAccess);
    public static readonly uint DisconnectClient = CtlCode(FileDeviceXdowsSecurity, 0x806, MethodBuffered, FileAnyAccess);
    public static readonly uint RegisterProtectedProcess = CtlCode(FileDeviceXdowsSecurity, 0x807, MethodBuffered, FileAnyAccess);
    public static readonly uint SetVoluntaryExit = CtlCode(FileDeviceXdowsSecurity, 0x808, MethodBuffered, FileAnyAccess);
    public static readonly uint AuthorizedShutdown = CtlCode(FileDeviceXdowsSecurity, 0x809, MethodBuffered, FileAnyAccess);
    public static readonly uint GetNextLog = CtlCode(FileDeviceXdowsSecurity, 0x80A, MethodBuffered, FileAnyAccess);
    public static readonly uint SetStartupProtection = CtlCode(FileDeviceXdowsSecurity, 0x80B, MethodBuffered, FileAnyAccess);
    public static readonly uint QueryProcesses = CtlCode(FileDeviceXdowsSecurity, 0x80C, MethodBuffered, FileAnyAccess);
    public static readonly uint OperateProcess = CtlCode(FileDeviceXdowsSecurity, 0x80D, MethodBuffered, FileAnyAccess);

    private static uint CtlCode(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | method;
    }

    public static XdowsProtocolHeader Header<T>() where T : struct
    {
        return new XdowsProtocolHeader
        {
            Size = (uint)Marshal.SizeOf<T>(),
            Version = ProtocolVersion
        };
    }
}

internal enum XdowsSecurityEventType : uint
{
    None = 0,
    ProcessCreate = 1,
    FileCreate = 2,
    FileWrite = 3,
    FileRename = 4,
    ProcessHandle = 5,
    ThreadHandle = 6,
    ImageLoad = 7,
    DriverLog = 8
}

internal enum XdowsSecurityDecisionType : uint
{
    Unknown = 0,
    Allow = 1,
    Block = 2,
    Timeout = 3,
    Pending = 4
}

internal enum XdowsSecurityModelMode : uint
{
    Standard = 0,
    Flash = 1,
    Pro = 2
}

internal enum XdowsSecurityLogSeverity : uint
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Fatal = 4
}

internal enum XdowsSecurityProcessOperation : uint
{
    None = 0,
    Suspend = 1,
    Resume = 2,
    Terminate = 3
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsProtocolHeader
{
    public uint Size;
    public uint Version;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsRegisterRequest
{
    public XdowsProtocolHeader Header;
    public uint ClientProcessId;
    public uint Flags;
    public uint HeartbeatTimeoutMs;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsRegisterResponse
{
    public XdowsProtocolHeader Header;
    public uint Status;
    public uint ProtocolVersion;
    public uint DefaultKernelWaitTimeoutMs;
    public uint Capabilities;
    public ulong DriverBuildId;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.TokenChars + 1)]
    public string ShutdownToken;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsHeartbeatRequest
{
    public XdowsProtocolHeader Header;
    public uint ClientProcessId;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsSecurityEvent
{
    public XdowsProtocolHeader Header;
    public ulong EventId;
    public ulong CorrelationId;
    public uint EventType;
    public uint Flags;
    public uint ProcessId;
    public uint ParentProcessId;
    public uint CreatingProcessId;
    public uint CreatingThreadId;
    public uint KernelWaitTimeoutMs;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxPathChars)]
    public string ImagePath;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxPathChars)]
    public string ActorImagePath;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxCommandChars)]
    public string CommandLine;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsSecurityDecision
{
    public XdowsProtocolHeader Header;
    public ulong EventId;
    public uint Decision;
    public uint CacheTtlMs;
    public uint ResultCode;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxReasonChars)]
    public string Reason;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsSecurityState
{
    public XdowsProtocolHeader Header;
    public uint ClientConnected;
    public uint PendingEventCount;
    public uint DroppedEventCount;
    public uint ProcessProtectionEnabled;
    public uint FileProtectionEnabled;
    public uint SelfProtectionEnabled;
    public uint ProtectedProcessId;
    public uint StartupProtectionEnabled;
    public uint ActiveModules;
    public uint ProtocolVersion;
    public uint Capabilities;
    public ulong DriverBuildId;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = DriverProtocol.EventTypeCount)]
    public uint[] ReceivedByType;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = DriverProtocol.EventTypeCount)]
    public uint[] DroppedByType;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = DriverProtocol.EventTypeCount)]
    public uint[] TimedOutByType;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsProtectedProcessRequest
{
    public XdowsProtocolHeader Header;
    public uint ProcessId;
    public uint MainThreadId;
    public uint Flags;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsVoluntaryExitRequest
{
    public XdowsProtocolHeader Header;
    public uint ProcessId;
    public uint IsVoluntaryExit;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsShutdownRequest
{
    public XdowsProtocolHeader Header;
    public uint Flags;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.TokenChars + 1)]
    public string ShutdownToken;
}

[StructLayout(LayoutKind.Sequential)]
internal struct XdowsStartupProtectionRequest
{
    public XdowsProtocolHeader Header;
    public uint ProcessId;
    public uint Enabled;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsProcessQueryRequest
{
    public XdowsProtocolHeader Header;
    public uint Cursor;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.TokenChars + 1)]
    public string AuthorizationToken;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsDriverProcessEntry
{
    public uint ProcessId;
    public uint ParentProcessId;
    public uint SessionId;
    public uint ThreadCount;
    public uint HandleCount;
    public uint BasePriority;
    public ulong WorkingSetBytes;
    public ulong PrivateBytes;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxProcessNameChars)]
    public string ImageName;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsProcessQueryResponse
{
    public XdowsProtocolHeader Header;
    public uint Count;
    public uint NextCursor;
    public uint HasMore;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = DriverProtocol.ProcessBatchSize)]
    public XdowsDriverProcessEntry[] Entries;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsProcessOperationRequest
{
    public XdowsProtocolHeader Header;
    public uint ProcessId;
    public uint Operation;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.TokenChars + 1)]
    public string AuthorizationToken;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct XdowsDriverLogEntry
{
    public XdowsProtocolHeader Header;
    public ulong EventId;
    public ulong CorrelationId;
    public uint Severity;
    public uint DroppedCount;
    public long Timestamp;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxLogModuleChars)]
    public string Module;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxLogMessageChars)]
    public string Message;
}
