using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Protection
{
    internal static class Native_ProcessMonitor
    {
        private const string DLL_NAME = "Xdows.Native.Process.dll";

        public delegate void NewProcessCallback(uint pid, [MarshalAs(UnmanagedType.LPWStr)] string path, IntPtr userData);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EnumProcessesNative(uint[] pids, uint maxCount, out uint returnedCount);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GetProcessPathById(uint pid, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, uint pathSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void MonitorProcesses(NewProcessCallback callback, IntPtr userData, ref int stopFlag);

        public static List<int> GetProcessIdListManaged()
        {
            const uint maxCount = 4096;
            uint[] pids = new uint[maxCount];

            if (EnumProcessesNative(pids, maxCount, out uint returnedCount) != 0)
            {
                return pids.Take((int)returnedCount).Where(id => id > 0).Select(id => (int)id).Distinct().ToList();
            }

            return new List<int>();
        }

        public static string GetProcessPathByIdManaged(int pid)
        {
            StringBuilder path = new StringBuilder(4096);
            if (GetProcessPathById((uint)pid, path, (uint)path.Capacity) != 0)
            {
                return path.ToString();
            }
            return string.Empty;
        }
    }
}
