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
            bool wasEnabled = IsStartupEnabled();
            if (!TryGetStartupCommand(out string startupCommand))
                return false;

            if (!global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(true))
                return false;

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, true);
                if (key == null)
                    throw new InvalidOperationException("HKLM Run key is unavailable.");

                object? previousValue = key.GetValue(
                    AppInfo.AppId,
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames);
                RegistryValueKind previousKind = previousValue != null
                    ? key.GetValueKind(AppInfo.AppId)
                    : RegistryValueKind.String;
                key.SetValue(AppInfo.AppId, startupCommand, RegistryValueKind.String);
                if (!global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(true))
                {
                    if (previousValue == null)
                        key.DeleteValue(AppInfo.AppId, false);
                    else
                        key.SetValue(AppInfo.AppId, previousValue, previousKind);

                    _ = global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(wasEnabled);
                    return false;
                }
                return true;
            }
            catch
            {
                _ = global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(wasEnabled);
                return false;
            }
        }

        public static bool DisableStartup()
        {
            object? previousValue = null;
            RegistryValueKind previousKind = RegistryValueKind.String;
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, true);
                if (key == null) return false;

                previousValue = key.GetValue(AppInfo.AppId, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (previousValue != null)
                    previousKind = key.GetValueKind(AppInfo.AppId);

                key.DeleteValue(AppInfo.AppId, false);
                if (global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(false))
                    return true;

                if (previousValue != null)
                    key.SetValue(AppInfo.AppId, previousValue, previousKind);
                _ = global::Xdows_Security.ProtectionStatus.SynchronizeStartupProtection(true);
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryGetStartupCommand(out string startupCommand)
        {
            startupCommand = string.Empty;
            try
            {
                string? exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return false;

                startupCommand = $"\"{exePath}\" {MinimizedArg}";
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
