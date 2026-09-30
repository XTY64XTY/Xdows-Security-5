using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Xdows_Security.Views
{
    internal static partial class NativeMethods
    {
        [LibraryImport("kernel32.dll")]
        public static partial nint GetCurrentProcess();

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(nint tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, uint bufferLength, nint previousState, nint returnLength);

        [LibraryImport("ntdll.dll")]
        public static partial int NtTerminateProcess(nint processHandle, int exitStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetConsoleCtrlHandler(nint handlerRoutine, [MarshalAs(UnmanagedType.Bool)] bool add);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(nint hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(nint hThread, ref CONTEXT64 lpContext);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumServicesStatusExW(
            nint hSCManager,
            int infoLevel,
            uint dwServiceType,
            uint dwServiceState,
            byte[]? lpServices,
            uint cbBufSize,
            out uint pcbBytesNeeded,
            out uint lpServicesReturned,
            ref uint lpResumeHandle,
            string? pszGroupName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint OpenServiceW(nint hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(nint hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(nint hSCObject);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        public static extern int RmRegisterResources(
            uint dwSessionHandle,
            uint nFiles,
            string[]? rgsFilenames,
            uint nApplications,
            RM_UNIQUE_PROCESS[]? rgApplications,
            uint nServices,
            string[]? rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        public static extern int RmShutdown(uint dwSessionHandle, uint lActionFlags, nint fnStatus);

        [DllImport("rstrtmgr.dll")]
        public static extern int RmEndSession(uint dwSessionHandle);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS_PROCESS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
            public uint dwProcessId;
            public uint dwServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ENUM_SERVICE_STATUS_PROCESS
        {
            public nint lpServiceName;
            public nint lpDisplayName;
            public SERVICE_STATUS_PROCESS ServiceStatusProcess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RM_FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RM_UNIQUE_PROCESS
        {
            public uint dwProcessId;
            public RM_FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Explicit, Size = 1232)]
        public struct CONTEXT64
        {
            [FieldOffset(48)]
            public uint ContextFlags;

            [FieldOffset(128)]
            public ulong Rcx;

            [FieldOffset(136)]
            public ulong Rdx;

            [FieldOffset(248)]
            public ulong Rip;
        }

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;
        public const uint CTRL_C_EVENT = 0;
        public const uint CTRL_BREAK_EVENT = 1;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint CONTEXT_AMD64 = 0x00100000;
        public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
        public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER;
        public const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        public const uint SERVICE_QUERY_STATUS = 0x0004;
        public const uint SERVICE_STOP = 0x0020;
        public const uint SERVICE_CONTROL_STOP = 0x00000001;
        public const uint SERVICE_WIN32 = 0x00000030;
        public const uint SERVICE_STATE_ALL = 0x00000003;
        public const int SC_ENUM_PROCESS_INFO = 0;
        public const int ERROR_MORE_DATA = 234;
        public const uint RM_FORCE_SHUTDOWN = 0x00000001;
        public const uint RM_SHUTDOWN_ONLY_REGISTERED = 0x00000010;
    }

    public sealed partial class ProcessManagerView
    {
        private const string DebugKillOnExitHelperArgument = "--xdows-debug-kill-on-exit";

        public static bool TryRunDebugKillOnExitHelper(string[] args)
        {
            if (args.Length < 3 || !string.Equals(args[1], DebugKillOnExitHelperArgument, StringComparison.Ordinal))
                return false;

            int exitCode = 1;
            if (int.TryParse(args[2], out var processId))
                exitCode = RunDebugKillOnExitHelper(processId);

            Environment.Exit(exitCode);
            return true;
        }

        private static int RunDebugKillOnExitHelper(int processId)
        {
            try
            {
                NativeMethods.DebugSetProcessKillOnExit(true);
                if (!NativeMethods.DebugActiveProcess(processId))
                    return 2;

                Thread.Sleep(150);
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        private static (bool Success, string Message) TryEnableDebugPrivilege()
        {
            if (!NativeMethods.OpenProcessToken(
                NativeMethods.GetCurrentProcess(),
                NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
                out var tokenHandle))
            {
                return (false, FormatLocalized("ProcessManagerKill_OpenProcessTokenFailed", GetLastSystemError()));
            }

            try
            {
                if (!NativeMethods.LookupPrivilegeValueW(null, "SeDebugPrivilege", out var luid))
                    return (false, FormatLocalized("ProcessManagerKill_LookupPrivilegeValueFailed", GetLastSystemError()));

                var privileges = new NativeMethods.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                };

                if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref privileges, 0, 0, 0))
                    return (false, FormatLocalized("ProcessManagerKill_AdjustTokenPrivilegesFailed", GetLastSystemError()));

                var error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ERROR_NOT_ALL_ASSIGNED)
                    return (false, Localize("ProcessManagerKill_SeDebugPrivilegeNotAssigned"));

                return (true, Localize("ProcessManagerKill_SeDebugPrivilegeEnabled"));
            }
            finally
            {
                NativeMethods.CloseHandle(tokenHandle);
            }
        }

        private static (bool Success, string Message) TryNtTerminateProcess(int processId)
        {
            var hProcess = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_TERMINATE | NativeMethods.SYNCHRONIZE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                processId);

            if (hProcess == 0)
                return (false, GetLastSystemError());

            try
            {
                var status = NativeMethods.NtTerminateProcess(hProcess, unchecked((int)NativeMethods.FORCED_TERMINATION_EXIT_CODE));
                if (status != 0)
                    return (false, FormatLocalized("ProcessManagerKill_NtTerminateProcessStatus", status));

                var wait = NativeMethods.WaitForSingleObject(hProcess, 3000);
                if (wait == NativeMethods.WAIT_OBJECT_0 || WaitForProcessExit(processId, 500))
                    return (true, Localize("ProcessManagerKill_NtTerminateProcessSuccess"));

                return (false, FormatLocalized("ProcessManagerKill_NtTerminateProcessWaitReturned", wait));
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static (bool Success, string Message) TryRemoteExitRoutines(int processId)
        {
            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            nint hProcess = OpenProcessForRemoteExecution(processId, out var openError);
            if (hProcess == 0)
                return (false, openError);

            try
            {
                var attempts = new List<string>();

                foreach (var routine in GetOneArgumentExitRoutines())
                {
                    var result = TryStartRemoteExitRoutine(hProcess, processId, routine.Name, routine.Address, (nint)NativeMethods.FORCED_TERMINATION_EXIT_CODE);
                    attempts.Add(result.Message);
                    if (result.Success)
                        return result;
                }

                var failFast = ResolveProcAddress(["kernel32.dll", "kernelbase.dll"], "RaiseFailFastException", out var failFastError);
                if (failFast != 0)
                {
                    var result = TryStartRemoteRaiseFailFast(hProcess, processId, failFast);
                    attempts.Add(result.Message);
                    if (result.Success)
                        return result;
                }
                else
                {
                    attempts.Add(failFastError);
                }

                return (false, string.Join(Localize("ProcessManagerKill_AttemptsSeparator"), attempts));
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static (bool Success, string Message) TryDebugKillOnExit(int processId)
        {
            var executablePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executablePath))
                return (false, Localize("ProcessManagerKill_CannotLocateExecutable"));

            try
            {
                using var helper = Process.Start(new ProcessStartInfo
                {
                    FileName = executablePath,
                    Arguments = $"{DebugKillOnExitHelperArgument} {processId}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                if (helper == null)
                    return (false, Localize("ProcessManagerKill_CannotStartHelper"));

                helper.WaitForExit(5000);
                if (WaitForProcessExit(processId, 3000))
                    return (true, FormatLocalized("ProcessManagerKill_HelperTriggeredKillOnExit", helper.Id));

                var exitCodeText = helper.HasExited ? helper.ExitCode.ToString() : Localize("ProcessManagerKill_HelperStillRunning");
                return (false, FormatLocalized("ProcessManagerKill_HelperStartedTargetRunning", exitCodeText));
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        private static (bool Success, string Message) TryHijackThreadContextToExit(int processId)
        {
            if (!Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture != Architecture.X64)
                return (false, Localize("ProcessManagerKill_ContextHijackX64Only"));

            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            var exitRoutine = ResolveProcAddress(["ntdll.dll", "kernel32.dll"], "RtlExitUserProcess", out var procError);
            if (exitRoutine == 0)
                return (false, procError);

            var threadIds = GetProcessThreadIds(processId, out var threadError);
            if (threadIds.Count == 0)
                return (false, threadError ?? Localize("ProcessManagerKill_NoEnumerableThreads"));

            var failed = 0;
            string? firstError = null;

            foreach (var threadId in threadIds)
            {
                var hThread = NativeMethods.OpenThread(
                    NativeMethods.THREAD_SUSPEND_RESUME |
                    NativeMethods.THREAD_GET_CONTEXT |
                    NativeMethods.THREAD_SET_CONTEXT |
                    NativeMethods.THREAD_QUERY_INFORMATION,
                    false,
                    (uint)threadId);

                if (hThread == 0)
                {
                    failed++;
                    firstError ??= FormatLocalized("ProcessManagerKill_ThreadOpenFailed", threadId, GetLastSystemError());
                    continue;
                }

                try
                {
                    if (NativeMethods.SuspendThread(hThread) == uint.MaxValue)
                    {
                        failed++;
                        firstError ??= FormatLocalized("ProcessManagerKill_ThreadSuspendFailed", threadId);
                        continue;
                    }

                    var resumed = false;
                    try
                    {
                        var context = new NativeMethods.CONTEXT64 { ContextFlags = NativeMethods.CONTEXT_FULL };
                        if (!NativeMethods.GetThreadContext(hThread, ref context))
                        {
                            failed++;
                            firstError ??= FormatLocalized("ProcessManagerKill_ThreadGetContextFailed", threadId, GetLastSystemError());
                            continue;
                        }

                        context.Rip = (ulong)exitRoutine;
                        context.Rcx = NativeMethods.FORCED_TERMINATION_EXIT_CODE;
                        context.Rdx = 0;

                        if (!NativeMethods.SetThreadContext(hThread, ref context))
                        {
                            failed++;
                            firstError ??= FormatLocalized("ProcessManagerKill_ThreadSetContextFailed", threadId, GetLastSystemError());
                            continue;
                        }

                        NativeMethods.ResumeThread(hThread);
                        resumed = true;

                        if (WaitForProcessExit(processId, 3000))
                            return (true, FormatLocalized("ProcessManagerKill_ThreadHijackSuccess", threadId));
                    }
                    finally
                    {
                        if (!resumed)
                            NativeMethods.ResumeThread(hThread);
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }

            return (false, FormatLocalized("ProcessManagerKill_ThreadHijackIncomplete", threadIds.Count, failed, firstError ?? ""));
        }

        private static (bool Success, string Message) TryApcExitRoutines(int processId)
        {
            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            var attempts = new List<string>();

            foreach (var routine in GetOneArgumentExitRoutines())
            {
                var result = TryQueueApcRoutine(processId, routine.Name, routine.Address, (nint)NativeMethods.FORCED_TERMINATION_EXIT_CODE);
                attempts.Add(result.Message);
                if (result.Success)
                    return result;
            }

            return (false, string.Join(Localize("ProcessManagerKill_AttemptsSeparator"), attempts));
        }

        private static (bool Success, string Message) TryConsoleCtrlEvent(int processId)
        {
            if (!NativeMethods.AttachConsole((uint)processId))
                return (false, FormatLocalized("ProcessManagerKill_AttachConsoleFailed", GetLastSystemError()));

            try
            {
                NativeMethods.SetConsoleCtrlHandler(0, true);

                var breakToGroup = NativeMethods.GenerateConsoleCtrlEvent(NativeMethods.CTRL_BREAK_EVENT, (uint)processId);
                if (WaitForProcessExit(processId, 1500))
                    return (true, Localize("ProcessManagerKill_CtrlBreakSent"));

                var ctrlC = NativeMethods.GenerateConsoleCtrlEvent(NativeMethods.CTRL_C_EVENT, 0);
                if (WaitForProcessExit(processId, 2500))
                    return (true, Localize("ProcessManagerKill_CtrlCSent"));

                return (false, FormatLocalized("ProcessManagerKill_ConsoleEventsIncomplete", breakToGroup, ctrlC));
            }
            finally
            {
                NativeMethods.SetConsoleCtrlHandler(0, false);
                NativeMethods.FreeConsole();
            }
        }

        private static (bool Success, string Message) TryStopServiceProcess(int processId)
        {
            var serviceNames = FindServiceNamesByProcessId((uint)processId, out var error);
            if (serviceNames.Count == 0)
                return (false, error ?? Localize("ProcessManagerKill_NoServiceForPid"));

            var scm = NativeMethods.OpenSCManagerW(null, null, NativeMethods.SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == 0)
                return (false, FormatLocalized("ProcessManagerKill_OpenSCManagerFailed", GetLastSystemError()));

            try
            {
                var stopped = 0;
                var failed = 0;
                string? firstError = null;

                foreach (var serviceName in serviceNames)
                {
                    var service = NativeMethods.OpenServiceW(
                        scm,
                        serviceName,
                        NativeMethods.SERVICE_STOP | NativeMethods.SERVICE_QUERY_STATUS);

                    if (service == 0)
                    {
                        failed++;
                        firstError ??= FormatLocalized("ProcessManagerKill_OpenServiceFailed", serviceName, GetLastSystemError());
                        continue;
                    }

                    try
                    {
                        var status = new NativeMethods.SERVICE_STATUS();
                        if (NativeMethods.ControlService(service, NativeMethods.SERVICE_CONTROL_STOP, ref status))
                        {
                            stopped++;
                        }
                        else
                        {
                            failed++;
                            firstError ??= FormatLocalized("ProcessManagerKill_ControlServiceStopFailed", serviceName, GetLastSystemError());
                        }
                    }
                    finally
                    {
                        NativeMethods.CloseServiceHandle(service);
                    }
                }

                if (WaitForProcessExit(processId, 7000))
                    return (true, FormatLocalized("ProcessManagerKill_ServiceStopSuccess", stopped, serviceNames.Count));

                return (false, FormatLocalized("ProcessManagerKill_ServiceStopIncomplete", stopped, serviceNames.Count, failed, firstError ?? ""));
            }
            finally
            {
                NativeMethods.CloseServiceHandle(scm);
            }
        }

        private static (bool Success, string Message) TryRestartManagerShutdown(int processId)
        {
            NativeMethods.RM_UNIQUE_PROCESS rmProcess;

            try
            {
                using var process = Process.GetProcessById(processId);
                var fileTime = process.StartTime.ToFileTimeUtc();
                rmProcess = new NativeMethods.RM_UNIQUE_PROCESS
                {
                    dwProcessId = (uint)processId,
                    ProcessStartTime = new NativeMethods.RM_FILETIME
                    {
                        dwLowDateTime = (uint)(fileTime & 0xFFFFFFFF),
                        dwHighDateTime = (uint)(fileTime >> 32)
                    }
                };
            }
            catch (Exception ex)
            {
                return (false, FormatLocalized("ProcessManagerKill_CannotBuildRmIdentity", ex.Message));
            }

            var sessionKey = new StringBuilder(64);
            var startStatus = NativeMethods.RmStartSession(out var sessionHandle, 0, sessionKey);
            if (startStatus != 0)
                return (false, FormatLocalized("ProcessManagerKill_RmStartSessionFailed", startStatus));

            try
            {
                var registerStatus = NativeMethods.RmRegisterResources(sessionHandle, 0, null, 1, [rmProcess], 0, null);
                if (registerStatus != 0)
                    return (false, FormatLocalized("ProcessManagerKill_RmRegisterResourcesFailed", registerStatus));

                var shutdownStatus = NativeMethods.RmShutdown(
                    sessionHandle,
                    NativeMethods.RM_FORCE_SHUTDOWN | NativeMethods.RM_SHUTDOWN_ONLY_REGISTERED,
                    0);

                if (WaitForProcessExit(processId, 7000))
                    return (true, FormatLocalized("ProcessManagerKill_RmShutdownSuccess", shutdownStatus));

                return (false, FormatLocalized("ProcessManagerKill_RmShutdownTargetRunning", shutdownStatus));
            }
            finally
            {
                NativeMethods.RmEndSession(sessionHandle);
            }
        }

        private static (bool Success, string Message) TryStartRemoteExitRoutine(nint hProcess, int processId, string routineName, nint address, nint parameter)
        {
            if (address == 0)
                return (false, FormatLocalized("ProcessManagerKill_ProcAddressInvalid", routineName));

            var thread = StartRemoteThread(hProcess, address, parameter);
            if (thread.Handle == 0)
                return (false, FormatLocalized("ProcessManagerKill_CreateRemoteThreadFailed", routineName, thread.Error));

            try
            {
                NativeMethods.WaitForSingleObject(thread.Handle, 2500);
                if (WaitForProcessExit(processId, 2500))
                    return (true, FormatLocalized("ProcessManagerKill_RemoteThreadExitSuccess", thread.ThreadId, routineName));

                return (false, FormatLocalized("ProcessManagerKill_RemoteThreadTargetRunning", routineName));
            }
            finally
            {
                NativeMethods.CloseHandle(thread.Handle);
            }
        }

        private static (bool Success, string Message) TryStartRemoteRaiseFailFast(nint hProcess, int processId, nint raiseFailFast)
        {
            if (!Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture != Architecture.X64)
                return (false, Localize("ProcessManagerKill_FailFastStubX64Only"));

            var code = new List<byte>(
            [
                0x48, 0x83, 0xEC, 0x28,
                0x48, 0x31, 0xC9,
                0x48, 0x31, 0xD2,
                0x45, 0x31, 0xC0,
                0x48, 0xB8
            ]);
            code.AddRange(BitConverter.GetBytes((ulong)raiseFailFast));
            code.AddRange([0xFF, 0xD0, 0xCC]);

            var remoteCode = RemoteAllocAndWrite(hProcess, [.. code], NativeMethods.PAGE_EXECUTE_READWRITE);
            if (remoteCode.Address == 0)
                return (false, FormatLocalized("ProcessManagerKill_FailFastWriteRemoteCodeFailed", remoteCode.Error));

            var thread = StartRemoteThread(hProcess, remoteCode.Address, 0);
            if (thread.Handle == 0)
            {
                TryFreeRemoteMemory(hProcess, remoteCode.Address);
                return (false, FormatLocalized("ProcessManagerKill_FailFastCreateRemoteThreadFailed", thread.Error));
            }

            try
            {
                NativeMethods.WaitForSingleObject(thread.Handle, 2500);
                if (WaitForProcessExit(processId, 3000))
                    return (true, FormatLocalized("ProcessManagerKill_FailFastThreadExitSuccess", thread.ThreadId));

                TryFreeRemoteMemory(hProcess, remoteCode.Address);
                return (false, Localize("ProcessManagerKill_FailFastThreadTargetRunning"));
            }
            finally
            {
                NativeMethods.CloseHandle(thread.Handle);
            }
        }

        private static (bool Success, string Message) TryQueueApcRoutine(int processId, string routineName, nint routineAddress, nint parameter)
        {
            if (routineAddress == 0)
                return (false, FormatLocalized("ProcessManagerKill_ProcAddressInvalid", routineName));

            var threadIds = GetProcessThreadIds(processId, out var threadError);
            if (threadIds.Count == 0)
                return (false, threadError ?? Localize("ProcessManagerKill_NoEnumerableThreads"));

            var queued = 0;
            var alerted = 0;
            var failed = 0;
            string? firstError = null;

            foreach (var threadId in threadIds)
            {
                var hThread = NativeMethods.OpenThread(
                    NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_ALERT | NativeMethods.THREAD_QUERY_INFORMATION,
                    false,
                    (uint)threadId);

                if (hThread == 0)
                {
                    failed++;
                    firstError ??= FormatLocalized("ProcessManagerKill_ThreadOpenFailed", threadId, GetLastSystemError());
                    continue;
                }

                try
                {
                    if (NativeMethods.QueueUserAPC(routineAddress, hThread, parameter) == 0)
                    {
                        failed++;
                        firstError ??= FormatLocalized("ProcessManagerKill_QueueUserAPCFailed", threadId, GetLastSystemError());
                        continue;
                    }

                    queued++;
                    if (NativeMethods.NtAlertThread(hThread) == 0)
                        alerted++;
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }

            if (WaitForProcessExit(processId, 5000))
                return (true, FormatLocalized("ProcessManagerKill_ApcExitSuccess", routineName, queued, threadIds.Count, alerted));

            return (false, FormatLocalized("ProcessManagerKill_ApcExitIncomplete", routineName, queued, threadIds.Count, alerted, failed, firstError ?? ""));
        }

        private static List<string> FindServiceNamesByProcessId(uint processId, out string? error)
        {
            error = null;

            var scm = NativeMethods.OpenSCManagerW(null, null, NativeMethods.SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == 0)
            {
                error = FormatLocalized("ProcessManagerKill_OpenSCManagerFailed", GetLastSystemError());
                return [];
            }

            try
            {
                uint bytesNeeded = 0;
                uint servicesReturned = 0;
                uint resumeHandle = 0;

                NativeMethods.EnumServicesStatusExW(
                    scm,
                    NativeMethods.SC_ENUM_PROCESS_INFO,
                    NativeMethods.SERVICE_WIN32,
                    NativeMethods.SERVICE_STATE_ALL,
                    null,
                    0,
                    out bytesNeeded,
                    out servicesReturned,
                    ref resumeHandle,
                    null);

                if (bytesNeeded == 0)
                {
                    error = FormatLocalized("ProcessManagerKill_EnumServicesBufferQueryFailed", GetLastSystemError());
                    return [];
                }

                var buffer = new byte[bytesNeeded];
                resumeHandle = 0;

                if (!NativeMethods.EnumServicesStatusExW(
                    scm,
                    NativeMethods.SC_ENUM_PROCESS_INFO,
                    NativeMethods.SERVICE_WIN32,
                    NativeMethods.SERVICE_STATE_ALL,
                    buffer,
                    (uint)buffer.Length,
                    out bytesNeeded,
                    out servicesReturned,
                    ref resumeHandle,
                    null))
                {
                    error = FormatLocalized("ProcessManagerKill_EnumServicesFailed", GetLastSystemError());
                    return [];
                }

                var services = new List<string>();
                var itemSize = Marshal.SizeOf<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>();
                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

                try
                {
                    var baseAddress = handle.AddrOfPinnedObject();
                    for (var i = 0; i < servicesReturned; i++)
                    {
                        var itemAddress = baseAddress + (i * itemSize);
                        var item = Marshal.PtrToStructure<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>(itemAddress);
                        if (item.ServiceStatusProcess.dwProcessId != processId)
                            continue;

                        var serviceName = Marshal.PtrToStringUni(item.lpServiceName);
                        if (!string.IsNullOrWhiteSpace(serviceName))
                            services.Add(serviceName);
                    }
                }
                finally
                {
                    handle.Free();
                }

                return services;
            }
            finally
            {
                NativeMethods.CloseServiceHandle(scm);
            }
        }

        private static List<(string Name, nint Address)> GetOneArgumentExitRoutines()
        {
            var routines = new List<(string Name, nint Address)>();

            var exitProcess = ResolveProcAddress(["kernel32.dll"], "ExitProcess", out _);
            if (exitProcess != 0)
                routines.Add(("ExitProcess", exitProcess));

            var rtlExitUserProcess = ResolveProcAddress(["ntdll.dll"], "RtlExitUserProcess", out _);
            if (rtlExitUserProcess != 0)
                routines.Add(("RtlExitUserProcess", rtlExitUserProcess));

            var fatalExit = ResolveProcAddress(["kernel32.dll"], "FatalExit", out _);
            if (fatalExit != 0)
                routines.Add(("FatalExit", fatalExit));

            return routines;
        }

        private static nint ResolveProcAddress(string[] moduleNames, string procName, out string error)
        {
            var errors = new List<string>();

            foreach (var moduleName in moduleNames)
            {
                var proc = GetLocalProcAddress(moduleName, procName, out var procError);
                if (proc != 0)
                {
                    error = "";
                    return proc;
                }

                errors.Add(procError);
            }

            error = string.Join(Localize("ProcessManagerKill_AttemptsSeparator"), errors);
            return 0;
        }
    }
}
