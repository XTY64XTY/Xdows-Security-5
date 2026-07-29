using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Protection;

internal sealed class BootFilterClient : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const int ErrorNoMoreItems = 259;

    private SafeFileHandle? _controlHandle;
    private SafeFileHandle? _eventHandle;

    public bool IsConnected => IsOpen(_controlHandle) && IsOpen(_eventHandle);

    public void Connect()
    {
        if (IsConnected)
            return;

        _controlHandle = OpenDevice(out int openError);
        if (_controlHandle is null)
            throw new Win32Exception(openError, "Failed to open the Xdows boot filter device.");

        var request = new BootFilterRegisterRequest
        {
            Header = BootFilterProtocol.Header<BootFilterRegisterRequest>(),
            ClientProcessId = checked((uint)Environment.ProcessId)
        };
        if (!DeviceIoControl(request, BootFilterProtocol.RegisterClient, out BootFilterRegisterResponse response))
        {
            int error = Marshal.GetLastWin32Error();
            Disconnect();
            throw new Win32Exception(error, "Failed to register the Xdows boot filter client.");
        }

        if (response.Header.Size != Marshal.SizeOf<BootFilterRegisterResponse>() ||
            response.Header.Version != BootFilterProtocol.ProtocolVersion ||
            response.ProtocolVersion != BootFilterProtocol.ProtocolVersion ||
            response.DriverBuildId != BootFilterProtocol.DriverBuildId ||
            response.MaxRequestBytes != BootFilterProtocol.MaxRequestBytes ||
            response.MaxPendingBytes != BootFilterProtocol.MaxPendingBytes ||
            response.DecisionTimeoutMs != BootFilterProtocol.DecisionTimeoutMs)
        {
            Disconnect();
            throw new InvalidDataException("The boot filter protocol, build identity, or resource limits do not match the app.");
        }

        _eventHandle = OpenDevice(out int eventOpenError);
        if (_eventHandle is null)
        {
            Disconnect();
            throw new Win32Exception(eventOpenError, "Failed to open the Xdows boot filter event channel.");
        }
    }

    public void Configure(BootDriverProtectionConfiguration configuration)
    {
        EnsureConnected();
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.RawRegions.Count is < 1 or > BootFilterProtocol.MaxRanges)
            throw new InvalidDataException("Boot filter configuration requires between one and eight raw disk regions.");

        BootFilterRawRange[] ranges = configuration.RawRegions
            .Select(region => new BootFilterRawRange
            {
                Offset = region.Offset,
                Length = checked((ulong)region.Data.LongLength)
            })
            .Concat(Enumerable.Repeat(default(BootFilterRawRange), BootFilterProtocol.MaxRanges))
            .Take(BootFilterProtocol.MaxRanges)
            .ToArray();
        var request = new BootFilterConfigureRequest
        {
            Header = BootFilterProtocol.Header<BootFilterConfigureRequest>(),
            DiskNumber = checked((uint)configuration.DiskIndex),
            RangeCount = checked((uint)configuration.RawRegions.Count),
            Ranges = ranges
        };

        if (!DeviceIoControlNoOutput(request, BootFilterProtocol.Configure))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to configure protected raw boot regions.");
    }

    public BootFilterState GetState()
    {
        EnsureConnected();
        if (!DeviceIoControlNoInput(_controlHandle!, BootFilterProtocol.GetState, out BootFilterState state))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to query boot filter state.");
        return state;
    }

    public async Task RunEventPumpAsync(
        Func<BootFilterWriteEvent, CancellationToken, Task<BootFilterDecisionType>> handler,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(handler);
        EnsureConnected();

        while (!token.IsCancellationRequested)
        {
            BootFilterWriteEvent? next = TryGetNextEvent();
            if (next is null)
                continue;

            BootFilterDecisionType decision;
            try
            {
                decision = await handler(next.Value, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                decision = BootFilterDecisionType.Block;
            }
            catch
            {
                decision = BootFilterDecisionType.Block;
            }

            SubmitDecision(next.Value.EventId, decision);
        }
    }

    public void Disconnect()
    {
        _eventHandle?.Dispose();
        _eventHandle = null;
        _controlHandle?.Dispose();
        _controlHandle = null;
    }

    public void Dispose() => Disconnect();

    private BootFilterWriteEvent? TryGetNextEvent()
    {
        EnsureConnected();
        if (DeviceIoControlNoInput(_eventHandle!, BootFilterProtocol.GetNextEvent, out BootFilterWriteEvent writeEvent))
            return writeEvent;

        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNoMoreItems)
            return null;
        throw new Win32Exception(error, "Failed to get the next boot filter event.");
    }

    private void SubmitDecision(ulong eventId, BootFilterDecisionType decision)
    {
        var request = new BootFilterDecision
        {
            Header = BootFilterProtocol.Header<BootFilterDecision>(),
            EventId = eventId,
            Decision = (uint)decision
        };
        if (!DeviceIoControlNoOutput(request, BootFilterProtocol.SubmitDecision))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to submit the boot filter decision.");
    }

    private void EnsureConnected()
    {
        if (!IsConnected)
            throw new InvalidOperationException("Boot filter bridge is not connected.");
    }

    private static bool IsOpen(SafeFileHandle? handle) =>
        handle is { IsClosed: false, IsInvalid: false };

    private static SafeFileHandle? OpenDevice(out int win32Error)
    {
        win32Error = 0;
        foreach (string path in BootFilterProtocol.DevicePaths)
        {
            SafeFileHandle handle = CreateFile(
                path,
                GenericRead | GenericWrite,
                FileShareRead | FileShareWrite,
                nint.Zero,
                OpenExisting,
                FileAttributeNormal,
                nint.Zero);
            if (!handle.IsInvalid)
                return handle;

            win32Error = Marshal.GetLastWin32Error();
            handle.Dispose();
        }
        return null;
    }

    private bool DeviceIoControlNoOutput<TIn>(TIn input, uint ioctl) where TIn : struct
    {
        EnsureConnected();
        return DeviceIoControlNoOutput(_controlHandle!, input, ioctl);
    }

    private static bool DeviceIoControlNoOutput<TIn>(SafeFileHandle handle, TIn input, uint ioctl) where TIn : struct
    {
        int inputSize = Marshal.SizeOf<TIn>();
        nint inputPointer = Marshal.AllocHGlobal(inputSize);
        try
        {
            Marshal.StructureToPtr(input, inputPointer, false);
            return DeviceIoControl(handle, ioctl, inputPointer, checked((uint)inputSize), nint.Zero, 0, out _, nint.Zero);
        }
        finally
        {
            Marshal.DestroyStructure<TIn>(inputPointer);
            Marshal.FreeHGlobal(inputPointer);
        }
    }

    private bool DeviceIoControl<TIn, TOut>(TIn input, uint ioctl, out TOut output)
        where TIn : struct where TOut : struct
    {
        EnsureControlOpen();
        int inputSize = Marshal.SizeOf<TIn>();
        int outputSize = Marshal.SizeOf<TOut>();
        nint inputPointer = Marshal.AllocHGlobal(inputSize);
        nint outputPointer = Marshal.AllocHGlobal(outputSize);
        try
        {
            Marshal.StructureToPtr(input, inputPointer, false);
            ZeroMemory(outputPointer, outputSize);
            bool result = DeviceIoControl(
                _controlHandle!,
                ioctl,
                inputPointer,
                checked((uint)inputSize),
                outputPointer,
                checked((uint)outputSize),
                out _,
                nint.Zero);
            output = result ? Marshal.PtrToStructure<TOut>(outputPointer) : default;
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<TIn>(inputPointer);
            Marshal.FreeHGlobal(inputPointer);
            Marshal.FreeHGlobal(outputPointer);
        }
    }

    private static bool DeviceIoControlNoInput<TOut>(SafeFileHandle handle, uint ioctl, out TOut output)
        where TOut : struct
    {
        int outputSize = Marshal.SizeOf<TOut>();
        nint outputPointer = Marshal.AllocHGlobal(outputSize);
        try
        {
            ZeroMemory(outputPointer, outputSize);
            bool result = DeviceIoControl(
                handle,
                ioctl,
                nint.Zero,
                0,
                outputPointer,
                checked((uint)outputSize),
                out _,
                nint.Zero);
            output = result ? Marshal.PtrToStructure<TOut>(outputPointer) : default;
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(outputPointer);
        }
    }

    private void EnsureControlOpen()
    {
        if (!IsOpen(_controlHandle))
            throw new InvalidOperationException("Boot filter control channel is not connected.");
    }

    private static void ZeroMemory(nint pointer, int length)
    {
        for (int offset = 0; offset < length; offset++)
            Marshal.WriteByte(pointer, offset, 0);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        nint input,
        uint inputSize,
        nint output,
        uint outputSize,
        out uint bytesReturned,
        nint overlapped);
}
