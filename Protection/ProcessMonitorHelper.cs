using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Protection
{
    internal static class ProcessMonitorHelper
    {
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcesses(int[] lpidProcess, int cb, out int lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public static List<int> GetProcessIdList()
        {
            const int maxCount = 4096;
            int[] pids = new int[maxCount];

            if (!EnumProcesses(pids, pids.Length * 4, out int neededBytes))
                throw new Win32Exception();

            int returnedCount = neededBytes / 4;
            return pids.Take(returnedCount).Where(id => id > 0).Distinct().ToList();
        }

        public static string GetProcessPathById(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
                return string.Empty;

            try
            {
                StringBuilder path = new StringBuilder(4096);
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
