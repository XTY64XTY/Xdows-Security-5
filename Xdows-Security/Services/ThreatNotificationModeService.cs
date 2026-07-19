using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Services;

internal static class ThreatNotificationModeService
{
    internal const string NotificationModeSetting = "ThreatNotificationMode";
    internal const string CompactMode = "Compact";
    internal const string NormalMode = "Normal";
    internal const string UseCompactWhenGamingSetting = "UseCompactThreatNotificationsWhenGaming";
    internal const string GameListSettingsUri = "ms-settings:gaming-gamemode";

    private static readonly object GameListLock = new();
    private static readonly SemaphoreSlim GameDetectionLock = new(1, 1);
    private static readonly TimeSpan GameListCacheDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan GameStateCacheDuration = TimeSpan.FromSeconds(2);
    private static HashSet<string> _gameDirectoryNames = new(StringComparer.OrdinalIgnoreCase);
    private static DateTimeOffset _gameListUpdatedAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _gameStateUpdatedAt = DateTimeOffset.MinValue;
    private static bool _isGameRunning;

    internal static async Task<bool> ShouldUseCompactAsync()
    {
        var settings = App.LocalSettings;
        bool onlyWhenGaming = settings.Values.TryGetValue(UseCompactWhenGamingSetting, out object? gamingRaw) &&
                              gamingRaw is bool gaming && gaming;

        if (onlyWhenGaming)
            return await IsGameRunningCachedAsync().ConfigureAwait(false);

        string mode = settings.Values.TryGetValue(NotificationModeSetting, out object? modeRaw) && modeRaw is string savedMode
            ? savedMode
            : NormalMode;
        return string.Equals(mode, CompactMode, StringComparison.Ordinal);
    }

    private static async Task<bool> IsGameRunningCachedAsync()
    {
        if (DateTimeOffset.UtcNow - _gameStateUpdatedAt < GameStateCacheDuration)
            return _isGameRunning;

        await GameDetectionLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow - _gameStateUpdatedAt < GameStateCacheDuration)
                return _isGameRunning;

            _isGameRunning = await Task.Run(IsGameRunning).ConfigureAwait(false);
            _gameStateUpdatedAt = DateTimeOffset.UtcNow;
            return _isGameRunning;
        }
        finally
        {
            GameDetectionLock.Release();
        }
    }

    private static bool IsGameRunning()
    {
        try
        {
            if (SHQueryUserNotificationState(out QueryUserNotificationState state) == 0 &&
                state == QueryUserNotificationState.RunningDirect3DFullScreen)
            {
                return true;
            }
        }
        catch
        {
        }

        HashSet<string> gameDirectoryNames = GetRegisteredGameDirectoryNames();
        if (gameDirectoryNames.Count == 0)
            return false;

        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    string? executablePath = process.MainModule?.FileName;
                    string? directoryName = Path.GetFileName(Path.GetDirectoryName(executablePath));
                    if (!string.IsNullOrWhiteSpace(directoryName) && gameDirectoryNames.Contains(directoryName))
                        return true;
                }
                catch
                {
                }
            }
        }

        return false;
    }

    private static HashSet<string> GetRegisteredGameDirectoryNames()
    {
        lock (GameListLock)
        {
            if (DateTimeOffset.UtcNow - _gameListUpdatedAt < GameListCacheDuration)
                return _gameDirectoryNames;

            HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
            try
            {
                using RegistryKey? children = Registry.CurrentUser.OpenSubKey(@"System\GameConfigStore\Children");
                if (children is not null)
                {
                    foreach (string childName in children.GetSubKeyNames())
                    {
                        using RegistryKey? child = children.OpenSubKey(childName);
                        if (child?.GetValue("ExeParentDirectory") is string directoryName &&
                            !string.IsNullOrWhiteSpace(directoryName))
                        {
                            names.Add(directoryName.Trim());
                        }
                    }
                }
            }
            catch
            {
            }

            _gameDirectoryNames = names;
            _gameListUpdatedAt = DateTimeOffset.UtcNow;
            return _gameDirectoryNames;
        }
    }

    [DllImport("shell32.dll")]
    private static extern int SHQueryUserNotificationState(out QueryUserNotificationState state);

    private enum QueryUserNotificationState
    {
        NotPresent = 1,
        Busy = 2,
        RunningDirect3DFullScreen = 3,
        PresentationMode = 4,
        AcceptsNotifications = 5,
        QuietTime = 6,
        App = 7
    }
}
