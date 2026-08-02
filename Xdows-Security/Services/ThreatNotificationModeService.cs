using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Xdows_Security.Services;

internal static class ThreatNotificationModeService
{
    internal const string NotificationModeSetting = "ThreatNotificationMode";
    internal const string CompactMode = "Compact";
    internal const string NormalMode = "Normal";
    internal const string UseCompactWhenGamingSetting = "UseCompactThreatNotificationsWhenGaming";
    internal const string GamePathsSetting = "CompactThreatNotificationGamePaths";

    internal static async Task<bool> ShouldUseCompactAsync()
    {
        var settings = App.LocalSettings;
        bool onlyWhenGaming = settings.Values.TryGetValue(UseCompactWhenGamingSetting, out object? gamingRaw) &&
                              gamingRaw is bool gaming && gaming;

        if (onlyWhenGaming)
            return await Task.Run(IsGameRunning).ConfigureAwait(false);

        string mode = settings.Values.TryGetValue(NotificationModeSetting, out object? modeRaw) && modeRaw is string savedMode
            ? savedMode
            : NormalMode;
        return string.Equals(mode, CompactMode, StringComparison.Ordinal);
    }

    // 读取用户配置的游戏可执行文件路径列表（换行分隔存储于本地设置）
    internal static List<string> GetGameExecutablePaths()
    {
        try
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
        catch
        {
            return new List<string>();
        }
    }

    // 保存用户配置的游戏可执行文件路径列表
    internal static void SaveGameExecutablePaths(IEnumerable<string> paths)
    {
        var settings = App.LocalSettings;
        settings.Values[GamePathsSetting] = string.Join(
            '\n',
            paths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()));
    }

    // 每次弹窗前实时检测：遍历进程并与用户配置路径逐一对比（忽略大小写）
    private static bool IsGameRunning()
    {
        HashSet<string> gamePaths = new(StringComparer.OrdinalIgnoreCase);
        foreach (string path in GetGameExecutablePaths())
        {
            try
            {
                gamePaths.Add(Path.GetFullPath(path.Trim()));
            }
            catch
            {
                gamePaths.Add(path.Trim());
            }
        }
        if (gamePaths.Count == 0)
            return false;

        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch
        {
            return false;
        }

        foreach (Process process in processes)
        {
            try
            {
                using (process)
                {
                    string? executablePath = GetProcessExecutablePath(process);
                    if (string.IsNullOrWhiteSpace(executablePath))
                        continue;

                    try
                    {
                        executablePath = Path.GetFullPath(executablePath);
                    }
                    catch
                    {
                    }

                    if (gamePaths.Contains(executablePath))
                        return true;
                }
            }
            catch
            {
            }
        }

        return false;
    }

    // 获取进程可执行文件完整路径，优先使用 QueryFullProcessImageName（对高权限进程更友好），
    // 回退到 Process.MainModule.FileName。
    private static string? GetProcessExecutablePath(Process process)
    {
        try
        {
            StringBuilder buffer = new(1024);
            uint size = (uint)buffer.Capacity;
            if (QueryFullProcessImageName(process.Handle, 0, buffer, ref size))
                return buffer.ToString();
        }
        catch
        {
        }

        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
        }

        return null;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, [Out] StringBuilder buffer, ref uint size);
}
