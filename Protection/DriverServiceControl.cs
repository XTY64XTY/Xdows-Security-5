using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Protection;

internal enum DriverServiceState
{
    Missing,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Unknown
}

internal sealed record DriverServiceSnapshot(DriverServiceState State, string Detail)
{
    public bool IsMissing => State == DriverServiceState.Missing;
    public bool IsRunning => State == DriverServiceState.Running;
    public bool IsTransitioning => State is DriverServiceState.StartPending or DriverServiceState.StopPending;
}

internal sealed record DriverServiceOperationResult(bool Success, int ErrorCode, string Message);

internal static class DriverServiceControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceControlStop = 0x00000001;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceNotActive = 1062;

    public static DriverServiceSnapshot Query(string serviceName)
    {
        using SafeServiceHandle manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
            return Unknown("OpenSCManager failed", Marshal.GetLastWin32Error());

        using SafeServiceHandle service = NativeMethods.OpenService(manager, serviceName, ServiceQueryStatus);
        if (service.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            return error == ErrorServiceDoesNotExist
                ? new DriverServiceSnapshot(DriverServiceState.Missing, "Driver service is not installed.")
                : Unknown("OpenService failed", error);
        }

        return QueryStatus(service);
    }

    public static DriverServiceOperationResult Start(string serviceName)
    {
        using SafeServiceHandle manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            return new DriverServiceOperationResult(false, error, FormatError("OpenSCManager failed", error));
        }

        using SafeServiceHandle service = NativeMethods.OpenService(
            manager,
            serviceName,
            ServiceQueryStatus | ServiceStart);
        if (service.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            string message = error == ErrorServiceDoesNotExist
                ? "Driver service is not installed."
                : FormatError("OpenService failed", error);
            return new DriverServiceOperationResult(false, error, message);
        }

        if (NativeMethods.StartService(service, 0, nint.Zero))
            return new DriverServiceOperationResult(true, 0, "StartService accepted.");

        int startError = Marshal.GetLastWin32Error();
        return startError == ErrorServiceAlreadyRunning
            ? new DriverServiceOperationResult(true, startError, "Driver service is already running.")
            : new DriverServiceOperationResult(false, startError, FormatError("StartService failed", startError));
    }

    public static DriverServiceOperationResult Stop(string serviceName)
    {
        using SafeServiceHandle manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            return new DriverServiceOperationResult(false, error, FormatError("OpenSCManager failed", error));
        }

        using SafeServiceHandle service = NativeMethods.OpenService(
            manager,
            serviceName,
            ServiceQueryStatus | ServiceStop);
        if (service.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            return new DriverServiceOperationResult(false, error, FormatError("OpenService failed", error));
        }

        DriverServiceSnapshot snapshot = QueryStatus(service);
        if (snapshot.State == DriverServiceState.Stopped)
            return new DriverServiceOperationResult(true, 0, "Driver service is already stopped.");
        if (snapshot.State == DriverServiceState.StopPending)
            return new DriverServiceOperationResult(true, 0, "Driver service stop is already pending.");

        if (NativeMethods.ControlService(service, ServiceControlStop, out _))
            return new DriverServiceOperationResult(true, 0, "ControlService(STOP) accepted.");

        int stopError = Marshal.GetLastWin32Error();
        DriverServiceSnapshot afterFailure = QueryStatus(service);
        if (afterFailure.State is DriverServiceState.Stopped or DriverServiceState.StopPending)
        {
            return new DriverServiceOperationResult(
                true,
                stopError,
                $"Driver service entered {afterFailure.State} while ControlService returned an error.");
        }

        return stopError == ErrorServiceNotActive
            ? new DriverServiceOperationResult(true, stopError, "Driver service is already stopped.")
            : new DriverServiceOperationResult(false, stopError, FormatError("ControlService(STOP) failed", stopError));
    }

    private static DriverServiceSnapshot QueryStatus(SafeServiceHandle service)
    {
        if (!NativeMethods.QueryServiceStatusEx(
            service,
            ScStatusProcessInfo,
            out ServiceStatusProcess status,
            Marshal.SizeOf<ServiceStatusProcess>(),
            out _))
        {
            return Unknown("QueryServiceStatusEx failed", Marshal.GetLastWin32Error());
        }

        DriverServiceState state = status.CurrentState switch
        {
            1 => DriverServiceState.Stopped,
            2 => DriverServiceState.StartPending,
            3 => DriverServiceState.StopPending,
            4 => DriverServiceState.Running,
            _ => DriverServiceState.Unknown
        };

        string detail =
            $"State: {state} ({status.CurrentState}), Win32ExitCode: {status.Win32ExitCode}, ServiceSpecificExitCode: {status.ServiceSpecificExitCode}, ProcessId: {status.ProcessId}.";
        return new DriverServiceSnapshot(state, detail);
    }

    private static DriverServiceSnapshot Unknown(string operation, int error)
    {
        return new DriverServiceSnapshot(DriverServiceState.Unknown, FormatError(operation, error));
    }

    private static string FormatError(string operation, int error)
    {
        string name = error switch
        {
            2 => "ERROR_FILE_NOT_FOUND",
            3 => "ERROR_PATH_NOT_FOUND",
            5 => "ERROR_ACCESS_DENIED",
            1053 => "ERROR_SERVICE_REQUEST_TIMEOUT",
            ErrorServiceAlreadyRunning => "ERROR_SERVICE_ALREADY_RUNNING",
            ErrorServiceDoesNotExist => "ERROR_SERVICE_DOES_NOT_EXIST",
            1058 => "ERROR_SERVICE_DISABLED",
            1072 => "ERROR_SERVICE_MARKED_FOR_DELETE",
            1077 => "ERROR_SERVICE_NEVER_STARTED",
            1115 => "ERROR_SHUTDOWN_IN_PROGRESS",
            _ => "WIN32_ERROR"
        };

        return $"{operation}: {name} (0x{unchecked((uint)error):X8}, {error}).";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseServiceHandle(handle);
        }
    }

    private static class NativeMethods
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeServiceHandle OpenSCManager(
            string? machineName,
            string? databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeServiceHandle OpenService(
            SafeServiceHandle serviceControlManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceStatusEx(
            SafeServiceHandle service,
            int infoLevel,
            out ServiceStatusProcess buffer,
            int bufferSize,
            out int bytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(
            SafeServiceHandle service,
            int serviceArgumentCount,
            nint serviceArguments);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(
            SafeServiceHandle service,
            uint control,
            out ServiceStatus serviceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(nint service);
    }
}
