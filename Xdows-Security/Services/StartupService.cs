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

        public static bool EnsureCurrentStartupCommand()
        {
            return IsStartupConfiguredForCurrentExecutable() || EnableStartup();
        }

        private static bool IsStartupConfiguredForCurrentExecutable()
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(RegistryKeyPath, false);
                string? command = key?.GetValue(
                    AppInfo.AppId,
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if (!TryParseExecutablePath(command, out string configuredPath) ||
                    !TryGetCurrentExecutablePath(out string currentPath))
                {
                    return false;
                }

                return string.Equals(configuredPath, currentPath, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
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
            if (!TryGetCurrentExecutablePath(out string exePath))
                return false;

            startupCommand = $"\"{exePath}\" {MinimizedArg}";
            return true;
        }

        private static bool TryGetCurrentExecutablePath(out string executablePath)
        {
            executablePath = string.Empty;
            try
            {
                string? path = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    return false;

                executablePath = Path.GetFullPath(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryParseExecutablePath(string? command, out string executablePath)
        {
            executablePath = string.Empty;
            if (string.IsNullOrWhiteSpace(command))
                return false;

            string trimmed = command.Trim();
            string rawPath;
            if (trimmed[0] == '"')
            {
                int closingQuote = trimmed.IndexOf('"', 1);
                if (closingQuote <= 1)
                    return false;

                rawPath = trimmed[1..closingQuote];
            }
            else
            {
                int separator = trimmed.IndexOfAny([' ', '\t']);
                rawPath = separator < 0 ? trimmed : trimmed[..separator];
            }

            try
            {
                executablePath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(rawPath));
                return File.Exists(executablePath);
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
