using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
    internal const string GamePathsSetting = "CompactThreatNotificationGamePaths";

    private static readonly SemaphoreSlim GameDetectionLock = new(1, 1);
    private static readonly TimeSpan GameStateCacheDuration = TimeSpan.FromSeconds(2);
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

    // 读取用户配置的游戏可执行文件路径列表（换行分隔存储于本地设置）
    internal static List<string> GetGameExecutablePaths()
    {
        var settings = App.LocalSettings;
        if (!settings.Values.TryGetValue(GamePathsSetting, out object? raw) ||
            raw is not string serialized ||
            string.IsNullOrWhiteSpace(serialized))
        {
            return new List<string>();
        }

        var result = new List<string>();
        foreach (string part in serialized.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string path = part.Trim();
            if (path.Length > 0)
                result.Add(path);
        }
        return result;
    }

    // 保存用户配置的游戏可执行文件路径列表
    internal static void SaveGameExecutablePaths(IEnumerable<string> paths)
    {
        var settings = App.LocalSettings;
        settings.Values[GamePathsSetting] = string.Join(
            '\n',
            paths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()));
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
        // 优先：系统级全屏 Direct3D 检测，对全屏游戏最可靠
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

        // 补充：与用户配置的游戏可执行文件路径精确比对（忽略大小写）
        HashSet<string> gamePaths = new(GetGameExecutablePaths(), StringComparer.OrdinalIgnoreCase);
        if (gamePaths.Count == 0)
            return false;

        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    string? executablePath = process.MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(executablePath) && gamePaths.Contains(executablePath))
                        return true;
                }
                catch
                {
                }
            }
        }

        return false;
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
