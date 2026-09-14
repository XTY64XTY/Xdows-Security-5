using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Xdows_Security.Services
{
    /// <summary>右键菜单项所在的注册表配置单元。</summary>
    public enum ContextMenuHive
    {
        LocalMachine,
        CurrentUser
    }

    /// <summary>
    /// 右键菜单中的一条菜单项：静态 verb（<c>shell</c> 下的子键）或 COM 外壳扩展
    /// （<c>shellex\ContextMenuHandlers</c> 下的子键）。
    /// </summary>
    public sealed class ContextMenuEntry : INotifyPropertyChanged
    {
        private string _keyName = "";
        private string _registryPath = "";
        private string _relativePath = "";
        private bool _isEnabled = true;

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>菜单显示名称（已解析间接资源字符串）。</summary>
        public string Name { get; set; } = "";

        /// <summary>注册表子键名。禁用时会带 <see cref="ShellContextMenuService.DisabledSuffix"/> 后缀。</summary>
        public string KeyName
        {
            get => _keyName;
            set => Set(ref _keyName, value, nameof(KeyName));
        }

        /// <summary>菜单位置，如“所有文件”“文件夹空白处”。</summary>
        public string Scope { get; set; } = "";

        /// <summary>菜单类型：静态菜单项 / 外壳扩展。</summary>
        public string Kind { get; set; } = "";

        /// <summary>展开后要执行的命令行，或外壳扩展的模块路径。</summary>
        public string Target { get; set; } = "";

        /// <summary>完整的注册表路径，如 <c>HKLM\SOFTWARE\Classes\*\shell\Foo</c>。</summary>
        public string RegistryPath
        {
            get => _registryPath;
            set => Set(ref _registryPath, value, nameof(RegistryPath));
        }

        /// <summary>相对于配置单元根的子键路径，用于打开可写句柄。</summary>
        public string RelativePath
        {
            get => _relativePath;
            set => _relativePath = value;
        }

        /// <summary>所在配置单元。</summary>
        public ContextMenuHive Hive { get; set; }

        /// <summary>是否为 COM 外壳扩展。</summary>
        public bool IsShellExtension { get; set; }

        /// <summary>命令或模块是否位于系统目录（判断是否系统自带项）。</summary>
        public bool IsSystem { get; set; }

        /// <summary>是否仅在按住 Shift 时出现。</summary>
        public bool ExtendedOnly { get; set; }

        /// <summary>当前是否启用。</summary>
        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (!Set(ref _isEnabled, value, nameof(IsEnabled))) return;
                Raise(nameof(Status));
            }
        }

        public string HiveName => Hive == ContextMenuHive.LocalMachine ? "HKLM" : "HKCU";

        public string Status => IsEnabled ? "已启用" : "已禁用";

        public string Source => IsSystem ? "系统" : "第三方";

        public string ExtendedHint => ExtendedOnly ? "（需按住 Shift）" : "";

        /// <summary>
        /// 修改注册表失败时 <see cref="IsEnabled"/> 并没有变化，绑定不会自动刷新，
        /// 用它在界面上把开关拨回真实状态（会重新广播 <see cref="IsEnabled"/>）。
        /// </summary>
        public void ResyncIsEnabled() => Raise(nameof(IsEnabled));

        public override string ToString() => Name;

        private bool Set<T>(ref T field, T value, string propertyName)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;

            field = value;
            Raise(propertyName);
            return true;
        }

        private void Raise(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    /// <summary>
    /// 枚举并修改资源管理器右键菜单项。菜单项来自注册表的
    /// <c>Software\Classes\&lt;作用域&gt;\shell</c> 与
    /// <c>Software\Classes\&lt;作用域&gt;\shellex\ContextMenuHandlers</c>。
    /// 静态菜单项通过 <c>LegacyDisable</c> 值开关，外壳扩展通过给子键加/去后缀开关，
    /// 两种方式都可逆且不破坏原有内容。
    /// </summary>
    public static class ShellContextMenuService
    {
        /// <summary>禁用外壳扩展时追加到子键名的后缀，资源管理器会忽略改名后的项。</summary>
        public const string DisabledSuffix = ".XdowsDisabled";

        private const string LegacyDisableValue = "LegacyDisable";
        private const string ShellBranch = "shell";
        private const string HandlerBranch = @"shellex\ContextMenuHandlers";

        internal const string Win11ClassicMenuKey =
            @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32";

        private const string Win11ClassicMenuClsid = "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}";

        private sealed record ScopeDefinition(string Root, string Display);

        // 作用域顺序即界面中的排序顺序。
        private static readonly ScopeDefinition[] Scopes =
        [
            new("*", "所有文件"),
            new("AllFilesystemObjects", "所有文件系统对象"),
            new("Directory", "文件夹"),
            new(@"Directory\Background", "文件夹空白处"),
            new("Folder", "文件夹（含虚拟文件夹）"),
            new("Drive", "驱动器"),
            new("DesktopBackground", "桌面背景"),
            new("LibraryFolder", "库文件夹"),
            new("lnkfile", "快捷方式"),
            new("exefile", "可执行文件"),
            new("batfile", "批处理文件"),
            new("cmdfile", "命令脚本"),
            new("regfile", "注册表文件"),
            new("txtfile", "文本文档"),
            new("imagefile", "图像文件"),
            new("htmlfile", "网页文件"),
            new("msofiledrop", "拖放"),
            new(@"SystemFileAssociations\text", "文本类文件"),
            new(@"SystemFileAssociations\image", "图像类文件"),
            new(@"SystemFileAssociations\audio", "音频类文件"),
            new(@"SystemFileAssociations\video", "视频类文件")
        ];

        /// <summary>界面“位置”下拉框的选项，首项为“全部”。</summary>
        public static IReadOnlyList<string> ScopeNames { get; } = BuildScopeNames();

        /// <summary>删除菜单项前导出的 .reg 备份目录。</summary>
        public static string BackupDirectory { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Xdows-Security",
            "ContextMenuBackups");

        private static List<string> BuildScopeNames()
        {
            var names = new List<string> { "全部" };
            names.AddRange(Scopes.Select(s => s.Display));
            return names;
        }

        /// <summary>扫描全部作用域下的右键菜单项。耗时操作，应在后台线程调用。</summary>
        public static List<ContextMenuEntry> Enumerate()
        {
            var sink = new List<ContextMenuEntry>();

            // 外层按作用域、内层按配置单元，使列表天然按位置分组；同名的 HKCU 项排在 HKLM 之后。
            foreach (var scope in Scopes)
            {
                foreach (var hive in new[] { ContextMenuHive.LocalMachine, ContextMenuHive.CurrentUser })
                {
                    CollectVerbs(sink, hive, scope);
                    CollectHandlers(sink, hive, scope);
                }
            }

            return sink;
        }

        /// <summary>把菜单项设为启用或禁用。返回是否成功。</summary>
        public static bool SetEnabled(ContextMenuEntry entry, bool enabled)
        {
            return entry.IsShellExtension
                ? RenameHandlerKey(entry, enabled)
                : ToggleLegacyDisable(entry, enabled);
        }

        /// <summary>删除菜单项，删除前先导出 .reg 备份。备份路径通过 <paramref name="message"/> 返回。</summary>
        public static bool TryDelete(ContextMenuEntry entry, out string message)
        {
            message = "";
            try
            {
                string? backup = ExportBackup(entry);

                using var root = OpenBaseKey(entry.Hive);
                if (root == null)
                {
                    message = "无法打开注册表根键，操作已取消。";
                    return false;
                }

                root.DeleteSubKeyTree(entry.RelativePath, throwOnMissingSubKey: false);

                message = backup == null
                    ? "已删除该菜单项。"
                    : $"已删除该菜单项，备份文件：{backup}";

                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenuManager",
                    $"Deleted context menu entry {entry.RegistryPath}");
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenuManager",
                    $"Failed to delete {entry.RegistryPath}: {ex.Message}");
                return false;
            }
        }

        /// <summary>导出菜单项注册表项到本地备份目录，返回 .reg 文件路径。</summary>
        public static string? ExportBackup(ContextMenuEntry entry)
        {
            try
            {
                Directory.CreateDirectory(BackupDirectory);

                string safeName = MakeSafeFileName(entry.KeyName);
                if (string.IsNullOrWhiteSpace(safeName)) safeName = "entry";

                string file = Path.Combine(BackupDirectory, $"{DateTime.Now:yyyyMMdd-HHmmss}-{safeName}.reg");

                using var process = Process.Start(new ProcessStartInfo("reg.exe",
                    $"export \"{entry.HiveName}\\{entry.RelativePath}\" \"{file}\" /y")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                process?.WaitForExit(15000);

                return File.Exists(file) ? file : null;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ContextMenuManager",
                    $"Failed to export backup for {entry.RegistryPath}: {ex.Message}");
                return null;
            }
        }

        /// <summary>在注册表编辑器中定位到该菜单项。</summary>
        public static bool OpenInRegedit(ContextMenuEntry entry)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"))
                {
                    key?.SetValue("LastKey", $"{entry.HiveName}\\{entry.RelativePath}");
                }

                using var process = Process.Start(new ProcessStartInfo("regedit.exe") { UseShellExecute = true });
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenuManager",
                    $"Failed to open regedit: {ex.Message}");
                return false;
            }
        }

        /// <summary>当前是否已启用 Windows 11 经典右键菜单。</summary>
        public static bool IsClassicMenuEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(Win11ClassicMenuKey);
                return key != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>切换 Windows 11 经典右键菜单（需重启资源管理器或重新登录后生效）。</summary>
        public static bool SetClassicMenuEnabled(bool enabled)
        {
            try
            {
                if (enabled)
                {
                    using var key = Registry.CurrentUser.CreateSubKey(Win11ClassicMenuKey);
                    key?.SetValue("", "", RegistryValueKind.String);
                }
                else
                {
                    Registry.CurrentUser.DeleteSubKeyTree(Win11ClassicMenuKey, throwOnMissingSubKey: false);

                    using var clsid = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID", writable: true);
                    clsid?.DeleteSubKey(Win11ClassicMenuClsid, throwOnMissingSubKey: false);
                }

                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenuManager",
                    $"Win11 classic context menu set to {enabled}");
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenuManager",
                    $"Failed to toggle classic context menu: {ex.Message}");
                return false;
            }
        }

        private static void CollectVerbs(List<ContextMenuEntry> sink, ContextMenuHive hive, ScopeDefinition scope)
        {
            string relative = $@"{BasePath(hive)}\{scope.Root}\{ShellBranch}";

            try
            {
                using var root = OpenBaseKey(hive);
                using var shellKey = root?.OpenSubKey(relative);
                if (shellKey == null) return;

                foreach (string verbName in shellKey.GetSubKeyNames())
                {
                    using var verbKey = shellKey.OpenSubKey(verbName);
                    if (verbKey == null) continue;

                    // ProgrammaticAccessOnly 的项永远不会出现在菜单里，直接跳过。
                    if (verbKey.GetValue("ProgrammaticAccessOnly") != null) continue;

                    string command = ReadCommand(verbKey);

                    sink.Add(new ContextMenuEntry
                    {
                        Name = ResolveVerbName(verbKey, verbName),
                        KeyName = verbName,
                        Scope = scope.Display,
                        Kind = "静态菜单项",
                        Target = ResolveTarget(verbKey, command),
                        Hive = hive,
                        RelativePath = $@"{relative}\{verbName}",
                        RegistryPath = $@"{HiveName(hive)}\{relative}\{verbName}",
                        IsShellExtension = false,
                        IsSystem = LooksLikeSystem(command),
                        ExtendedOnly = verbKey.GetValue("Extended") != null,
                        IsEnabled = verbKey.GetValue(LegacyDisableValue) == null
                    });
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ContextMenuManager",
                    $"Failed to read {HiveName(hive)}\\{relative}: {ex.Message}");
            }
        }

        private static void CollectHandlers(List<ContextMenuEntry> sink, ContextMenuHive hive, ScopeDefinition scope)
        {
            string relative = $@"{BasePath(hive)}\{scope.Root}\{HandlerBranch}";

            try
            {
                using var root = OpenBaseKey(hive);
                using var handlerRoot = root?.OpenSubKey(relative);
                if (handlerRoot == null) return;

                foreach (string handlerName in handlerRoot.GetSubKeyNames())
                {
                    using var handlerKey = handlerRoot.OpenSubKey(handlerName);
                    if (handlerKey == null) continue;

                    string clsid = handlerKey.GetValue("") as string ?? "";
                    string module = ResolveComModule(clsid);
                    bool disabled = handlerName.EndsWith(DisabledSuffix, StringComparison.OrdinalIgnoreCase);

                    sink.Add(new ContextMenuEntry
                    {
                        Name = ResolveHandlerName(handlerName, module),
                        KeyName = handlerName,
                        Scope = scope.Display,
                        Kind = "外壳扩展",
                        Target = string.IsNullOrWhiteSpace(module)
                            ? (string.IsNullOrWhiteSpace(clsid) ? "—" : clsid)
                            : module,
                        Hive = hive,
                        RelativePath = $@"{relative}\{handlerName}",
                        RegistryPath = $@"{HiveName(hive)}\{relative}\{handlerName}",
                        IsShellExtension = true,
                        IsSystem = LooksLikeSystem(module),
                        ExtendedOnly = false,
                        IsEnabled = !disabled
                    });
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ContextMenuManager",
                    $"Failed to read {HiveName(hive)}\\{relative}: {ex.Message}");
            }
        }

        private static bool ToggleLegacyDisable(ContextMenuEntry entry, bool enabled)
        {
            try
            {
                using var root = OpenBaseKey(entry.Hive);
                using var key = root?.OpenSubKey(entry.RelativePath, writable: true);
                if (key == null) return false;

                if (enabled) key.DeleteValue(LegacyDisableValue, throwOnMissingValue: false);
                else key.SetValue(LegacyDisableValue, "", RegistryValueKind.String);

                entry.IsEnabled = enabled;
                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenuManager",
                    $"{(enabled ? "Enabled" : "Disabled")} {entry.RegistryPath}");
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenuManager",
                    $"Failed to set {entry.RegistryPath}: {ex.Message}");
                return false;
            }
        }

        private static bool RenameHandlerKey(ContextMenuEntry entry, bool enabled)
        {
            try
            {
                using var root = OpenBaseKey(entry.Hive);
                if (root == null) return false;

                string? parentRelative = Path.GetDirectoryName(entry.RelativePath)?.Replace('/', '\\');
                if (string.IsNullOrEmpty(parentRelative)) return false;

                bool disabled = entry.KeyName.EndsWith(DisabledSuffix, StringComparison.OrdinalIgnoreCase);
                string targetName = enabled
                    ? (disabled ? entry.KeyName[..^DisabledSuffix.Length] : entry.KeyName)
                    : (disabled ? entry.KeyName : entry.KeyName + DisabledSuffix);

                if (string.Equals(entry.KeyName, targetName, StringComparison.Ordinal))
                {
                    entry.IsEnabled = enabled;
                    return true;
                }

                using var parent = root.OpenSubKey(parentRelative, writable: true);
                if (parent == null) return false;

                using (var source = parent.OpenSubKey(entry.KeyName))
                {
                    if (source == null) return false;
                    using var destination = parent.CreateSubKey(targetName);
                    CopyKey(source, destination);
                }

                parent.DeleteSubKeyTree(entry.KeyName, throwOnMissingSubKey: false);

                entry.KeyName = targetName;
                entry.RelativePath = $@"{parentRelative}\{targetName}";
                entry.RegistryPath = $@"{entry.HiveName}\{entry.RelativePath}";
                entry.IsEnabled = enabled;

                LogText.AddNewLog(LogText.LogLevel.INFO, "ContextMenuManager",
                    $"{(enabled ? "Enabled" : "Disabled")} {entry.RegistryPath}");
                return true;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "ContextMenuManager",
                    $"Failed to set {entry.RegistryPath}: {ex.Message}");
                return false;
            }
        }

        private static void CopyKey(RegistryKey source, RegistryKey destination)
        {
            foreach (string valueName in source.GetValueNames())
            {
                destination.SetValue(valueName, source.GetValue(valueName) ?? "", source.GetValueKind(valueName));
            }

            foreach (string subName in source.GetSubKeyNames())
            {
                using var sourceSub = source.OpenSubKey(subName);
                if (sourceSub == null) continue;

                using var destinationSub = destination.CreateSubKey(subName);
                CopyKey(sourceSub, destinationSub);
            }
        }

        private static string MakeSafeFileName(string raw)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            var builder = new StringBuilder(raw.Length);

            foreach (char c in raw)
            {
                builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }

            return builder.ToString();
        }

        private static RegistryKey? OpenBaseKey(ContextMenuHive hive)
            => hive == ContextMenuHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;

        private static string BasePath(ContextMenuHive hive)
            => hive == ContextMenuHive.LocalMachine ? @"SOFTWARE\Classes" : @"Software\Classes";

        private static string HiveName(ContextMenuHive hive)
            => hive == ContextMenuHive.LocalMachine ? "HKLM" : "HKCU";

        private static string ReadCommand(RegistryKey verbKey)
        {
            try
            {
                using var commandKey = verbKey.OpenSubKey("command");
                return commandKey?.GetValue("") as string ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string ResolveTarget(RegistryKey verbKey, string command)
        {
            if (!string.IsNullOrWhiteSpace(command)) return command;
            if (verbKey.GetValue("SubCommands") != null) return "（级联子菜单）";
            return "—";
        }

        private static string ResolveVerbName(RegistryKey verbKey, string keyName)
        {
            string? raw = verbKey.GetValue("MUIVerb") as string;
            if (string.IsNullOrWhiteSpace(raw)) raw = verbKey.GetValue("") as string;
            if (string.IsNullOrWhiteSpace(raw)) return keyName;

            return ResolveIndirectString(raw) ?? raw;
        }

        private static string ResolveHandlerName(string keyName, string module)
        {
            if (!string.IsNullOrWhiteSpace(module))
            {
                try
                {
                    string? description = FileVersionInfo.GetVersionInfo(module).FileDescription;
                    if (!string.IsNullOrWhiteSpace(description)) return description;
                    return Path.GetFileName(module);
                }
                catch
                {
                    // 模块可能已被卸载或不可访问，退回键名。
                }
            }

            return keyName;
        }

        private static string ResolveComModule(string clsid)
        {
            if (string.IsNullOrWhiteSpace(clsid)) return "";

            string[] candidates =
            [
                $@"CLSID\{clsid}\InprocServer32",
                $@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32",
                $@"Software\Classes\CLSID\{clsid}\InprocServer32"
            ];
            RegistryKey[] roots = [Registry.ClassesRoot, Registry.LocalMachine, Registry.CurrentUser];

            for (int i = 0; i < candidates.Length; i++)
            {
                try
                {
                    using var key = roots[i].OpenSubKey(candidates[i]);
                    if (key?.GetValue("") is string value && !string.IsNullOrWhiteSpace(value))
                    {
                        return Environment.ExpandEnvironmentVariables(value);
                    }
                }
                catch
                {
                    // 忽略单个失败的探测，继续尝试下一个位置。
                }
            }

            return "";
        }

        private static bool LooksLikeSystem(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return true;
            if (path.StartsWith('@')) return true;

            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(windows)) return true;

            return Environment.ExpandEnvironmentVariables(path)
                .StartsWith(windows, StringComparison.OrdinalIgnoreCase);
        }

        private static string? ResolveIndirectString(string value)
        {
            if (!value.StartsWith('@')) return null;

            try
            {
                var buffer = new StringBuilder(512);
                if (SHLoadIndirectString(value, buffer, buffer.Capacity, IntPtr.Zero) == 0)
                {
                    string text = buffer.ToString();
                    if (!string.IsNullOrWhiteSpace(text)) return text;
                }
            }
            catch
            {
                // 解析失败时保留原始字符串。
            }

            return null;
        }

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int SHLoadIndirectString(
            string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved);
    }
}
