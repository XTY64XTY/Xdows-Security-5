using Microsoft.Windows.Storage;
using Microsoft.Win32;
using System;
using System.IO;
using WinUI3Localizer;

namespace Xdows_Security.Services
{
    public static class ContextMenuService
    {
        private const string MenuKeyFile = @"Software\Classes\*\shell\Xdows-Security";
        private const string MenuKeyDirectory = @"Software\Classes\Directory\shell\Xdows-Security";
        private const string CommandSubKey = "command";
        private const string SettingKey = "ContextMenuScan";

        private static readonly string ExePath = ProcessPath();

        private static string ProcessPath()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            string? fileName = process.MainModule?.FileName;
            process.Dispose();
            return fileName ?? AppDomain.CurrentDomain.BaseDirectory + "Xdows-Security.exe";
        }

        private static string GetScanCommand() => $"\"{ExePath}\" %1";

        public static bool IsEnabled()
        {
            return IsCommandMatch(MenuKeyFile, GetScanCommand()) && IsCommandMatch(MenuKeyDirectory, GetScanCommand());
        }

        public static bool Register()
        {
            try
            {
                string menuText = GetLocalizedMenuText();
                string commandValue = GetScanCommand();
                
                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", $"Registering context menu with command: {commandValue}");

                RegisterKey(MenuKeyFile, menuText, commandValue);
                RegisterKey(MenuKeyDirectory, menuText, commandValue);

                App.LocalSettings.Values[SettingKey] = true;
                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", "Context menu registered successfully");
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to register context menu: {ex.Message}");
                return false;
            }
        }

        public static bool Unregister()
        {
            try
            {
                UnregisterKey(MenuKeyFile);
                UnregisterKey(MenuKeyDirectory);

                App.LocalSettings.Values[SettingKey] = false;
                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", "Context menu unregistered successfully");
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to unregister context menu: {ex.Message}");
                return false;
            }
        }

        public static void UpdateMenuText()
        {
            if (!IsEnabled()) return;

            try
            {
                string menuText = GetLocalizedMenuText();
                UpdateKeyText(MenuKeyFile, menuText);
                UpdateKeyText(MenuKeyDirectory, menuText);
                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", "Context menu text updated successfully");
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to update menu text: {ex.Message}");
            }
        }

        public static void ValidateOnStartup()
        {
            string expectedCommand = GetScanCommand();
            bool isEnabled = IsCommandMatch(MenuKeyFile, expectedCommand) && IsCommandMatch(MenuKeyDirectory, expectedCommand);
            bool settingEnabled = App.LocalSettings.Values.TryGetValue(SettingKey, out var raw) && raw is bool b && b;

            if (settingEnabled && !isEnabled)
            {
                try
                {
                    string menuText = GetLocalizedMenuText();
                    RegisterKey(MenuKeyFile, menuText, expectedCommand);
                    RegisterKey(MenuKeyDirectory, menuText, expectedCommand);
                    LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", "Context menu restored on startup");
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to restore context menu: {ex.Message}");
                    App.LocalSettings.Values[SettingKey] = false;
                }
            }
            else if (!settingEnabled && isEnabled)
            {
                try
                {
                    UnregisterKey(MenuKeyFile);
                    UnregisterKey(MenuKeyDirectory);
                    LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenu", "Context menu removed on startup");
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to remove context menu: {ex.Message}");
                }
            }
            else if (settingEnabled && isEnabled)
            {
                try
                {
                    string menuText = GetLocalizedMenuText();
                    UpdateKeyText(MenuKeyFile, menuText);
                    UpdateKeyText(MenuKeyDirectory, menuText);
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to update menu text on startup: {ex.Message}");
                }
            }
        }

        private static bool IsCommandMatch(string keyPath, string expectedCommand)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(Path.Combine(keyPath, CommandSubKey));
                if (key == null) return false;

                string? currentCommand = key.GetValue("") as string;
                return string.Equals(currentCommand, expectedCommand, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to check command match: {ex.Message}");
                return false;
            }
        }

        private static void RegisterKey(string keyPath, string menuText, string commandValue)
        {
            using var key = Registry.CurrentUser.CreateSubKey(keyPath);
            key.SetValue("", menuText);
            key.SetValue("icon", ExePath);
            key.SetValue("MultiSelectModel", "Player");

            using var cmdKey = key.CreateSubKey(CommandSubKey);
            cmdKey.SetValue("", commandValue);
        }

        private static void UnregisterKey(string keyPath)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(keyPath);
            }
            catch { }
        }

        private static void UpdateKeyText(string keyPath, string menuText)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
                if (key != null)
                {
                    key.SetValue("", menuText);
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenu", $"Failed to update key text: {ex.Message}");
            }
        }

        private static string GetLocalizedMenuText()
        {
            try
            {
                return Localizer.Get().GetLocalizedString("ContextMenu_ScanWith");
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ContextMenu", $"Failed to get localized text: {ex.Message}");
                return "Scan with Xdows Security";
            }
        }
    }
}
