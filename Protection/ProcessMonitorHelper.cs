using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Protection
{
    internal static partial class ProcessMonitorHelper
    {
        [LibraryImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool EnumProcesses([In, Out] int[] lpidProcess, int cb, out int lpcbNeeded);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseHandle(nint hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public static List<int> GetProcessIdList()
        {
            const int maxCount = 4096;
            int[] pids = new int[maxCount];

            if (!EnumProcesses(pids, pids.Length * 4, out int neededBytes))
                throw new Win32Exception();

            int returnedCount = neededBytes / 4;
            return [.. pids.Take(returnedCount).Where(id => id > 0).Distinct()];
        }

        public static string GetProcessPathById(int pid)
        {
            nint hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == 0)
                return string.Empty;

            try
            {
                StringBuilder path = new(4096);
                uint size = (uint)path.Capacity;

                if (QueryFullProcessImageNameW(hProcess, 0, path, ref size))
                {
                    return path.ToString();
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }

            return string.Empty;
        }
    }
}
