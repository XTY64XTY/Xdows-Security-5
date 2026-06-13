using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Protection;

internal static class DriverRootDeviceInstaller
{
    private static readonly Guid ActivityMonitorClassGuid = new("b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2");
    private const string HardwareId = @"Root\XdowsSecurityDriver";

    public static bool EnsureExists(out string message)
    {
        try
        {
            Guid classGuid = ActivityMonitorClassGuid;
            nint deviceInfoSet = NativeMethods.SetupDiGetClassDevs(
                ref classGuid,
                null,
                0,
                0);

            if (deviceInfoSet != NativeMethods.InvalidHandleValue)
            {
                try
                {
                    if (ContainsRootDevice(deviceInfoSet))
                    {
                        message = "Driver root device is present.";
                        return true;
                    }
                }
                finally
                {
                    NativeMethods.SetupDiDestroyDeviceInfoList(deviceInfoSet);
                }
            }

            return CreateRootDevice(out message);
        }
        catch (Exception ex) when (ex is Win32Exception or OverflowException)
        {
            message = ex.Message;
            return false;
        }
    }

    private static bool ContainsRootDevice(nint deviceInfoSet)
    {
        for (uint index = 0; ; index++)
        {
            var deviceInfo = CreateDeviceInfoData();
            if (!NativeMethods.SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfo))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ErrorNoMoreItems)
                    return false;
                throw new Win32Exception(error, "Unable to enumerate driver devices.");
            }

            if (HasHardwareId(deviceInfoSet, ref deviceInfo))
                return true;
        }
    }

    private static bool HasHardwareId(nint deviceInfoSet, ref SpDevInfoData deviceInfo)
    {
        NativeMethods.SetupDiGetDeviceRegistryProperty(
            deviceInfoSet,
            ref deviceInfo,
            NativeMethods.SpdrpHardwareId,
            out _,
            null,
            0,
            out uint requiredSize);

        int error = Marshal.GetLastWin32Error();
        if (requiredSize == 0)
        {
            if (error is NativeMethods.ErrorInvalidData or NativeMethods.ErrorNotFound)
                return false;
            if (error != NativeMethods.ErrorInsufficientBuffer)
                throw new Win32Exception(error, "Unable to read the driver hardware ID.");
        }

        byte[] buffer = new byte[requiredSize];
        if (!NativeMethods.SetupDiGetDeviceRegistryProperty(
            deviceInfoSet,
            ref deviceInfo,
            NativeMethods.SpdrpHardwareId,
            out _,
            buffer,
            checked((uint)buffer.Length),
            out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read the driver hardware ID.");
        }

        string hardwareIds = Encoding.Unicode.GetString(buffer);
        return hardwareIds
            .Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Any(value => value.Equals(HardwareId, StringComparison.OrdinalIgnoreCase));
    }

    private static bool CreateRootDevice(out string message)
    {
        Guid classGuid = ActivityMonitorClassGuid;
        nint deviceInfoSet = NativeMethods.SetupDiCreateDeviceInfoList(ref classGuid, 0);
        if (deviceInfoSet == NativeMethods.InvalidHandleValue)
        {
            message = FormatLastError("Unable to create the driver device information set.");
            return false;
        }

        try
        {
            var deviceInfo = CreateDeviceInfoData();
            if (!NativeMethods.SetupDiCreateDeviceInfo(
                deviceInfoSet,
                "XdowsSecurityDriver",
                ref classGuid,
                "Xdows Security Protection Driver",
                0,
                NativeMethods.DicdGenerateId,
                ref deviceInfo))
            {
                message = FormatLastError("Unable to create the driver root device.");
                return false;
            }

            byte[] hardwareId = Encoding.Unicode.GetBytes(HardwareId + "\0\0");
            if (!NativeMethods.SetupDiSetDeviceRegistryProperty(
                deviceInfoSet,
                ref deviceInfo,
                NativeMethods.SpdrpHardwareId,
                hardwareId,
                checked((uint)hardwareId.Length)))
            {
                message = FormatLastError("Unable to assign the driver hardware ID.");
                return false;
            }

            if (!NativeMethods.SetupDiCallClassInstaller(
                NativeMethods.DifRegisterDevice,
                deviceInfoSet,
                ref deviceInfo))
            {
                message = FormatLastError("Unable to register the driver root device.");
                return false;
            }

            message = "Driver root device was registered.";
            return true;
        }
        finally
        {
            NativeMethods.SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }
    }

    private static SpDevInfoData CreateDeviceInfoData()
    {
        return new SpDevInfoData
        {
            Size = checked((uint)Marshal.SizeOf<SpDevInfoData>())
        };
    }

    private static string FormatLastError(string prefix)
    {
        int error = Marshal.GetLastWin32Error();
        return $"{prefix} {new Win32Exception(error).Message} ({error}).";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SpDevInfoData
    {
        public uint Size;
        public Guid ClassGuid;
        public uint DeviceInstance;
        public nint Reserved;
    }

    private static class NativeMethods
    {
        public static readonly nint InvalidHandleValue = new(-1);

        public const uint DicdGenerateId = 0x00000001;
        public const uint DifRegisterDevice = 0x00000019;
        public const uint SpdrpHardwareId = 0x00000001;
        public const int ErrorInvalidData = 13;
        public const int ErrorInsufficientBuffer = 122;
        public const int ErrorNoMoreItems = 259;
        public const int ErrorNotFound = 1168;

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern nint SetupDiGetClassDevs(
            ref Guid classGuid,
            string? enumerator,
            nint parentWindow,
            uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiEnumDeviceInfo(
            nint deviceInfoSet,
            uint memberIndex,
            ref SpDevInfoData deviceInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiGetDeviceRegistryProperty(
            nint deviceInfoSet,
            ref SpDevInfoData deviceInfoData,
            uint property,
            out uint propertyRegDataType,
            [Out] byte[]? propertyBuffer,
            uint propertyBufferSize,
            out uint requiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern nint SetupDiCreateDeviceInfoList(ref Guid classGuid, nint parentWindow);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiCreateDeviceInfo(
            nint deviceInfoSet,
            string deviceName,
            ref Guid classGuid,
            string deviceDescription,
            nint parentWindow,
            uint creationFlags,
            ref SpDevInfoData deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiSetDeviceRegistryProperty(
            nint deviceInfoSet,
            ref SpDevInfoData deviceInfoData,
            uint property,
            byte[] propertyBuffer,
            uint propertyBufferSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiCallClassInstaller(
            uint installFunction,
            nint deviceInfoSet,
            ref SpDevInfoData deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiDestroyDeviceInfoList(nint deviceInfoSet);
    }
}
