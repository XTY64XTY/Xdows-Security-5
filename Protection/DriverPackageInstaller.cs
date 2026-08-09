using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Protection;

internal static class DriverPackageInstaller
{
    public static bool Install(string infPath, out bool rebootRequired, out string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(infPath);
        rebootRequired = false;

        try
        {
            if (!NativeMethods.DiInstallDriver(
                0,
                infPath,
                0,
                out rebootRequired))
            {
                message = FormatLastError("Driver package install failed.");
                return false;
            }

            message = rebootRequired
                ? "Driver package installed. A restart is required."
                : "Driver package installed.";
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or OverflowException)
        {
            message = ex.Message;
            return false;
        }
    }

    private static string FormatLastError(string prefix)
    {
        int error = Marshal.GetLastWin32Error();
        return $"{prefix} {new Win32Exception(error).Message} (0x{unchecked((uint)error):X8}, {error}).";
    }

    private static class NativeMethods
    {
        [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DiInstallDriver(
            nint parentWindow,
            string fullInfPath,
            uint flags,
            [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);
    }
}
