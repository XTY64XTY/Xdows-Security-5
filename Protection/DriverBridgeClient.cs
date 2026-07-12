using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace Protection;

internal sealed class DriverBridgeClient : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const int ErrorNoMoreItems = 259;

    private SafeFileHandle? _handle;
    private uint _clientProcessId;
    private readonly DriverShutdownToken _shutdownToken = new();

    public bool IsConnected => _handle is { IsClosed: false, IsInvalid: false };
    public bool HasShutdownToken => _shutdownToken.HasToken;

    public void Connect()
    {
        if (IsConnected)
            return;

        _handle = OpenDriverDevice(out int openError);
        if (_handle is null)
        {
            throw new Win32Exception(openError, "Failed to open Xdows Security driver device.");
        }

        _clientProcessId = checked((uint)Environment.ProcessId);
        var request = new XdowsRegisterRequest
        {
            Header = DriverProtocol.Header<XdowsRegisterRequest>(),
            ClientProcessId = _clientProcessId,
            HeartbeatTimeoutMs = 10_000
        };

        if (!DeviceIoControl(request, DriverProtocol.RegisterClient, out XdowsRegisterResponse response))
        {
            int error = Marshal.GetLastWin32Error();
            Disconnect();
            throw new Win32Exception(error, "Failed to register Xdows Security driver client.");
        }

        if (response.ProtocolVersion != DriverProtocol.ProtocolVersion ||
            response.DriverBuildId != DriverProtocol.DriverBuildId)
        {
            Disconnect();
            throw new InvalidOperationException(
                $"Driver protocol/build mismatch. Expected v{DriverProtocol.ProtocolVersion}/{DriverProtocol.DriverBuildId}, " +
                $"received v{response.ProtocolVersion}/{response.DriverBuildId}.");
        }

        _shutdownToken.Capture(response.ShutdownToken);
    }

    public async Task RunEventPumpAsync(
        Func<XdowsSecurityEvent, CancellationToken, Task<XdowsSecurityDecision>> handler,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(handler);
        EnsureConnected();

        using var heartbeatCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task heartbeatTask = Task.Run(() => HeartbeatLoopAsync(heartbeatCts.Token), heartbeatCts.Token);

        int workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
        var channel = Channel.CreateBounded<XdowsSecurityEvent>(new BoundedChannelOptions(256)
        {
            SingleWriter = true,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait
        });
        Task[] workers = Enumerable.Range(0, workerCount)
            .Select(_ => RunDecisionWorkerAsync(channel.Reader, handler, token))
            .ToArray();

        try
        {
            while (!token.IsCancellationRequested)
            {
                XdowsSecurityEvent? nextEvent = TryGetNextEvent();
                if (nextEvent is null)
                {
                    continue;
                }
                await channel.Writer.WriteAsync(nextEvent.Value, token).ConfigureAwait(false);
            }
        }
        finally
        {
            channel.Writer.TryComplete();
            try
            {
                await Task.WhenAll(workers).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            heartbeatCts.Cancel();
            try
            {
                await heartbeatTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    private async Task RunDecisionWorkerAsync(
        ChannelReader<XdowsSecurityEvent> reader,
        Func<XdowsSecurityEvent, CancellationToken, Task<XdowsSecurityDecision>> handler,
        CancellationToken token)
    {
        await foreach (XdowsSecurityEvent driverEvent in reader.ReadAllAsync(token).ConfigureAwait(false))
        {
            XdowsSecurityDecision decision;
            try
            {
                decision = await handler(driverEvent, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                decision = CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Timeout, "bridge-cancelled");
            }
            catch (Exception ex)
            {
                decision = CreateDecision(driverEvent.EventId, XdowsSecurityDecisionType.Allow, "bridge-error:" + ex.GetType().Name);
            }

            try
            {
                SubmitDecision(decision);
            }
            catch
            {
            }
        }
    }

    public XdowsSecurityState GetState()
    {
        EnsureConnected();

        if (!DeviceIoControlNoInput(DriverProtocol.GetState, out XdowsSecurityState state))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to query driver state.");

        return state;
    }

    public bool TryGetNextLog(out XdowsDriverLogEntry entry)
    {
        EnsureConnected();

        bool ok = DeviceIoControlNoInput(DriverProtocol.GetNextLog, out entry);
        if (ok)
            return true;

        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNoMoreItems)
            return false;

        throw new Win32Exception(error, "Failed to get next Xdows Security driver log entry.");
    }

    public static bool TryQueryStateWithoutRegister(out XdowsSecurityState state, out int win32Error)
    {
        state = default;
        win32Error = 0;

        using SafeFileHandle? handle = OpenDriverDevice(out int openError);
        if (handle is null)
        {
            win32Error = openError;
            return false;
        }

        int outSize = Marshal.SizeOf<XdowsSecurityState>();
        IntPtr outPtr = Marshal.AllocHGlobal(outSize);
        try
        {
            ZeroMemory(outPtr, outSize);
            bool ok = DeviceIoControl(handle, DriverProtocol.GetState, IntPtr.Zero, 0, outPtr, (uint)outSize, out _, IntPtr.Zero);
            if (ok)
            {
                state = Marshal.PtrToStructure<XdowsSecurityState>(outPtr);
                return true;
            }

            win32Error = Marshal.GetLastWin32Error();
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    public void RegisterProtectedProcess(uint mainThreadId = 0)
    {
        EnsureConnected();

        var request = new XdowsProtectedProcessRequest
        {
            Header = DriverProtocol.Header<XdowsProtectedProcessRequest>(),
            ProcessId = _clientProcessId,
            MainThreadId = mainThreadId
        };

        if (!DeviceIoControlNoOutput(request, DriverProtocol.RegisterProtectedProcess))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to register protected process.");
    }

    public void SetVoluntaryExit(bool isVoluntaryExit)
    {
        EnsureConnected();

        var request = new XdowsVoluntaryExitRequest
        {
            Header = DriverProtocol.Header<XdowsVoluntaryExitRequest>(),
            ProcessId = _clientProcessId,
            IsVoluntaryExit = isVoluntaryExit ? 1u : 0u
        };

        if (!DeviceIoControlNoOutput(request, DriverProtocol.SetVoluntaryExit))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to set voluntary exit state.");
    }

    public bool SubmitAuthorizedShutdown()
    {
        EnsureConnected();

        string? token = _shutdownToken.Consume();
        if (string.IsNullOrWhiteSpace(token))
            return false;

        var request = new XdowsShutdownRequest
        {
            Header = DriverProtocol.Header<XdowsShutdownRequest>(),
            ShutdownToken = token
        };

        bool ok = DeviceIoControlNoOutput(request, DriverProtocol.AuthorizedShutdown);
        if (!ok)
        {
            _shutdownToken.Capture(token);
        }

        return ok;
    }

    public void Disconnect()
    {
        if (_handle is { IsClosed: false, IsInvalid: false })
        {
            _ = DeviceIoControlNoBuffers(DriverProtocol.DisconnectClient);
        }

        _handle?.Dispose();
        _handle = null;
        _shutdownToken.Clear();
    }

    public void Dispose()
    {
        Disconnect();
    }

    public static XdowsSecurityDecision CreateDecision(
        ulong eventId,
        XdowsSecurityDecisionType decision,
        string reason,
        uint cacheTtlMs = 0,
        uint resultCode = 0)
    {
        return new XdowsSecurityDecision
        {
            Header = DriverProtocol.Header<XdowsSecurityDecision>(),
            EventId = eventId,
            Decision = (uint)decision,
            CacheTtlMs = cacheTtlMs,
            ResultCode = resultCode,
            Reason = Truncate(reason, DriverProtocol.MaxReasonChars - 1)
        };
    }

    private async Task HeartbeatLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                SendHeartbeat();
            }
            catch
            {
            }

            await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
        }
    }

    private void SendHeartbeat()
    {
        EnsureConnected();

        var request = new XdowsHeartbeatRequest
        {
            Header = DriverProtocol.Header<XdowsHeartbeatRequest>(),
            ClientProcessId = _clientProcessId
        };

        _ = DeviceIoControlNoOutput(request, DriverProtocol.Heartbeat);
    }

    private XdowsSecurityEvent? TryGetNextEvent()
    {
        EnsureConnected();

        bool ok = DeviceIoControlNoInput(DriverProtocol.GetNextEvent, out XdowsSecurityEvent securityEvent);
        if (ok)
            return securityEvent;

        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNoMoreItems)
            return null;

        throw new Win32Exception(error, "Failed to get next Xdows Security driver event.");
    }

    private void SubmitDecision(XdowsSecurityDecision decision)
    {
        EnsureConnected();

        if (!DeviceIoControlNoOutput(decision, DriverProtocol.SubmitDecision))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to submit driver decision.");
    }

    private void EnsureConnected()
    {
        if (!IsConnected)
            throw new InvalidOperationException("Driver bridge is not connected.");
    }

    private static SafeFileHandle? OpenDriverDevice(out int win32Error)
    {
        win32Error = 0;

        foreach (string path in DriverProtocol.DevicePaths)
        {
            SafeFileHandle handle = CreateFile(
                path,
                GenericRead | GenericWrite,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);

            if (!handle.IsInvalid)
                return handle;

            win32Error = Marshal.GetLastWin32Error();
            handle.Dispose();
        }

        return null;
    }

    private bool DeviceIoControlNoBuffers(uint ioctl)
    {
        EnsureConnected();
        return DeviceIoControl(_handle!, ioctl, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
    }

    private bool DeviceIoControlNoInput<TOut>(uint ioctl, out TOut output) where TOut : struct
    {
        EnsureConnected();

        int outSize = Marshal.SizeOf<TOut>();
        IntPtr outPtr = Marshal.AllocHGlobal(outSize);
        try
        {
            ZeroMemory(outPtr, outSize);
            bool ok = DeviceIoControl(_handle!, ioctl, IntPtr.Zero, 0, outPtr, (uint)outSize, out _, IntPtr.Zero);
            output = ok ? Marshal.PtrToStructure<TOut>(outPtr) : default;
            return ok;
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    private bool DeviceIoControlNoOutput<TIn>(TIn input, uint ioctl) where TIn : struct
    {
        EnsureConnected();

        int inSize = Marshal.SizeOf<TIn>();
        IntPtr inPtr = Marshal.AllocHGlobal(inSize);
        try
        {
            Marshal.StructureToPtr(input, inPtr, false);
            return DeviceIoControl(_handle!, ioctl, inPtr, (uint)inSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }
        finally
        {
            Marshal.DestroyStructure<TIn>(inPtr);
            Marshal.FreeHGlobal(inPtr);
        }
    }

    private bool DeviceIoControl<TIn, TOut>(TIn input, uint ioctl, out TOut output)
        where TIn : struct
        where TOut : struct
    {
        EnsureConnected();

        int inSize = Marshal.SizeOf<TIn>();
        int outSize = Marshal.SizeOf<TOut>();
        IntPtr inPtr = Marshal.AllocHGlobal(inSize);
        IntPtr outPtr = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.StructureToPtr(input, inPtr, false);
            ZeroMemory(outPtr, outSize);

            bool ok = DeviceIoControl(_handle!, ioctl, inPtr, (uint)inSize, outPtr, (uint)outSize, out _, IntPtr.Zero);
            output = ok ? Marshal.PtrToStructure<TOut>(outPtr) : default;
            return ok;
        }
        finally
        {
            Marshal.DestroyStructure<TIn>(inPtr);
            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);
        }
    }

    private static void ZeroMemory(IntPtr ptr, int size)
    {
        for (int i = 0; i < size; i++)
            Marshal.WriteByte(ptr, i, 0);
    }

    private static string Truncate(string value, int maxChars)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
            return value;

        return value[..maxChars];
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
}
