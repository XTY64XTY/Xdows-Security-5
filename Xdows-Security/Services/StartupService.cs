using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;

namespace Xdows_Security.Services
{
    public static class StartupService
    {
        private const string RegistryKeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        public const string MinimizedArg = "--minimized";

        public static bool IsStartupEnabled()
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, false);
                if (key == null) return false;

                return key.GetValue(AppInfo.AppId) != null;
            }
            catch
            {
                return false;
            }
        }

        public static bool EnableStartup()
        {
            try
            {
                string? exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return false;

                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, true);
                if (key == null) return false;

                key.SetValue(AppInfo.AppId, $"\"{exePath}\" {MinimizedArg}", RegistryValueKind.String);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool DisableStartup()
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, true);
                if (key == null) return false;

                key.DeleteValue(AppInfo.AppId, false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsMinimizedStart()
        {
            string[] args = Environment.GetCommandLineArgs();
            for (int i = 1; i < args.Length; i++)
            {
                if (string.Equals(args[i], MinimizedArg, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
