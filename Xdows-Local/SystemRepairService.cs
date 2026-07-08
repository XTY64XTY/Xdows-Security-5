using Microsoft.Win32;

namespace Xdows_Local
{
    /// <summary>
    /// 系统修复服务：扫描并修复被恶意软件篡改的注册表项。
    /// 覆盖 IFEO 映像劫持、AppInit_DLLs 注入、BootExecute 启动命令、
    /// 辅助功能后门、Winlogon 登录链、Run/RunOnce 启动项、
    /// 系统工具禁用策略与资源管理器显示劫持。
    /// </summary>
    public static class SystemRepairService
    {
        // ── 数据结构 ──

        public enum IssueSeverity { Low, Medium, High }

        public sealed class SystemIssue
        {
            public String Id { get; set; } = String.Empty;
            public String Category { get; set; } = String.Empty;
            public String Name { get; set; } = String.Empty;
            public String Description { get; set; } = String.Empty;
            public String RegistryPath { get; set; } = String.Empty;
            public String? CurrentValue { get; set; }
            public String? ExpectedValue { get; set; }
            public IssueSeverity Severity { get; set; }
            public Boolean CanFix { get; set; }
            public FixAction Action { get; set; }
        }

        public sealed class RepairSummary
        {
            public Int32 Total;
            public Int32 High;
            public Int32 Medium;
            public Int32 Low;
            public Int32 Fixed;
        }

        public sealed class RepairResult
        {
            public List<SystemIssue> Issues = new();
            public RepairSummary Summary = new();
        }

        public sealed class RepairFixResult
        {
            public Boolean Success;
            public List<String> FixedIds = new();
            public List<String> FailedIds = new();
            public String Message = String.Empty;
        }

        /// <summary>
        /// 修复动作类型。DeleteValue=删除键值；SetDword=写入 DWORD；SetString=写入字符串（恢复默认值）。
        /// </summary>
        public enum FixAction { DeleteValue, SetDword, SetString }

        // ── Hive 解析 ──

        private static RegistryKey? OpenHiveRoot(String hive)
        {
            return hive switch
            {
                "HKLM" => Registry.LocalMachine,
                "HKCU" => Registry.CurrentUser,
                "HKU" => Registry.Users,
                _ => null
            };
        }

        private static String? ReadString(String hive, String subkey, String value)
        {
            try
            {
                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) return null;
                using RegistryKey? key = root.OpenSubKey(subkey);
                if (key is null) return null;
                Object? raw = key.GetValue(value);
                // 处理 REG_MULTI_SZ（如 BootExecute）——合并为空格分隔字符串
                if (raw is String[] arr) return String.Join(" ", arr);
                return raw as String;
            }
            catch (Exception) { return null; }
        }

        private static Int32? ReadDword(String hive, String subkey, String value)
        {
            try
            {
                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) return null;
                using RegistryKey? key = root.OpenSubKey(subkey);
                if (key is null) return null;
                Object? raw = key.GetValue(value);
                return raw is Int32 i ? i : null;
            }
            catch (Exception) { return null; }
        }

        private static Boolean WriteDword(String hive, String subkey, String value, Int32 data)
        {
            try
            {
                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) return false;
                using RegistryKey? key = root.CreateSubKey(subkey, writable: true);
                if (key is null) return false;
                key.SetValue(value, data, RegistryValueKind.DWord);
                return true;
            }
            catch (Exception) { return false; }
        }

        private static Boolean WriteString(String hive, String subkey, String value, String data)
        {
            try
            {
                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) return false;
                using RegistryKey? key = root.CreateSubKey(subkey, writable: true);
                if (key is null) return false;
                key.SetValue(value, data, RegistryValueKind.String);
                return true;
            }
            catch (Exception) { return false; }
        }

        private static Boolean DeleteValue(String hive, String subkey, String value)
        {
            try
            {
                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) return false;
                // 键不存在时视为已删除，不创建空键
                using RegistryKey? key = root.OpenSubKey(subkey, writable: true);
                if (key is null) return true;
                key.DeleteValue(value, throwOnMissingValue: false);
                return true;
            }
            catch (Exception) { return false; }
        }

        // ── 通用策略检查 ──

        private static void CheckDwordPolicy(
            List<SystemIssue> issues, String category, String name, String description,
            String hive, String subkey, String value, Int32 expected, IssueSeverity severity)
        {
            Int32? current = ReadDword(hive, subkey, value);
            if (current is null || current.Value == expected) return;

            issues.Add(new SystemIssue
            {
                Id = $"{hive}\\{subkey}\\{value}",
                Category = category,
                Name = name,
                Description = description,
                RegistryPath = $"{hive}\\{subkey}\\{value}",
                CurrentValue = current.Value.ToString(),
                ExpectedValue = expected.ToString(),
                Severity = severity,
                CanFix = true,
                Action = FixAction.SetDword
            });
        }

        // ── A. 系统工具禁用策略 ──

        private static void CheckSystemToolPolicies(List<SystemIssue> issues)
        {
            const String policy = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
            const String explorerPolicy = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";

            CheckDwordPolicy(issues, "系统工具禁用", "任务管理器被禁用", "DisableTaskMgr 被设为 1，任务管理器无法打开", "HKCU", policy, "DisableTaskMgr", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "注册表编辑器被禁用", "DisableRegistryTools 被设为 1，regedit 无法打开", "HKCU", policy, "DisableRegistryTools", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "命令提示符被禁用", "DisableCMD 被设为 1，cmd 无法打开", "HKCU", policy, "DisableCMD", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "控制面板被禁用", "NoControlPanel 被设为 1，控制面板无法打开", "HKCU", policy, "NoControlPanel", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "文件夹选项被禁用", "NoFolderOptions 被设为 1，文件夹选项无法打开", "HKCU", policy, "NoFolderOptions", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "运行对话框被禁用", "NoRun 被设为 1，Win+R 无法使用", "HKCU", policy, "NoRun", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "查找功能被禁用", "NoFind 被设为 1，搜索功能被禁用", "HKCU", policy, "NoFind", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "桌面图标被隐藏", "NoDesktop 被设为 1，桌面不显示图标", "HKCU", policy, "NoDesktop", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "关机选项被禁用", "NoClose 被设为 1，无法通过开始菜单关机", "HKCU", policy, "NoClose", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "注销选项被禁用", "NoLogOff 被设为 1，无法注销", "HKCU", policy, "NoLogOff", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "Windows 键被禁用", "NoWinKeys 被设为 1，Win 键失效", "HKCU", policy, "NoWinKeys", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "锁定工作站被禁用", "DisableLockWorkstation 被设为 1，Win+L 无法锁定", "HKCU", policy, "DisableLockWorkstation", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "更改密码被禁用", "DisableChangePassword 被设为 1，无法更改密码", "HKCU", policy, "DisableChangePassword", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "快速用户切换被隐藏", "HideFastUserSwitching 被设为 1，快速用户切换被隐藏", "HKCU", policy, "HideFastUserSwitching", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "系统工具禁用", "通知中心被禁用", "DisableNotificationCenter 被设为 1，通知中心无法打开", "HKCU", policy, "DisableNotificationCenter", 0, IssueSeverity.Low);

            CheckDwordPolicy(issues, "系统工具禁用", "磁盘驱动器被隐藏", "NoDrives 非 0，可能隐藏或禁访盘符", "HKCU", explorerPolicy, "NoDrives", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "MMC 控制台被禁用", "DisableMMC 被设为 1，services.msc/gpedit.msc 等无法打开", "HKCU", explorerPolicy, "DisableMMC", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "Windows Script Host 被禁用", "Enabled 被设为 0，WSH 被禁用（病毒常禁用杀软脚本）", "HKLM", "SOFTWARE\\Microsoft\\Windows Script Host\\Settings", "Enabled", 1, IssueSeverity.Medium);

            // 系统还原
            CheckDwordPolicy(issues, "系统工具禁用", "系统还原被禁用", "DisableSR 被设为 1，系统还原被禁用", "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableSR", 0, IssueSeverity.Medium);
            CheckDwordPolicy(issues, "系统工具禁用", "系统还原配置被禁用", "DisableConfig 被设为 1，无法配置系统还原", "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableConfig", 0, IssueSeverity.Medium);

            // CMD AutoRun 劫持
            String? autoRun = ReadString("HKCU", "Software\\Microsoft\\Command Processor", "AutoRun");
            if (!String.IsNullOrWhiteSpace(autoRun))
            {
                issues.Add(new SystemIssue
                {
                    Id = "HKCU\\Software\\Microsoft\\Command Processor\\AutoRun",
                    Category = "系统工具禁用",
                    Name = "CMD AutoRun 劫持",
                    Description = "命令处理器 AutoRun 被设置，打开 cmd 即执行恶意命令",
                    RegistryPath = "HKCU\\Software\\Microsoft\\Command Processor\\AutoRun",
                    CurrentValue = autoRun,
                    ExpectedValue = "(空)",
                    Severity = IssueSeverity.High,
                    CanFix = true,
                    Action = FixAction.DeleteValue
                });
            }
        }

        // ── B. 资源管理器显示劫持 ──

        private static void CheckExplorerDisplay(List<SystemIssue> issues)
        {
            const String subkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";

            CheckDwordPolicy(issues, "资源管理器显示劫持", "文件扩展名被隐藏", "文件扩展名被强制隐藏，常见于双扩展名病毒配合", "HKCU", subkey, "HideFileExt", 0, IssueSeverity.Low);
            CheckDwordPolicy(issues, "资源管理器显示劫持", "显示系统文件被禁用", "资源管理器未显示受保护的操作系统文件", "HKCU", subkey, "ShowSuperHidden", 1, IssueSeverity.Low);
        }

        // ── C. 映像劫持与进程后门 ──

        private static void CheckIfeoDebugger(List<SystemIssue> issues)
        {
            const String baseKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            // 辅助功能后门目标，单独检测，避免重复
            HashSet<String> accessibility = new(StringComparer.OrdinalIgnoreCase)
            {
                "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe"
            };

            using RegistryKey? hklm = Registry.LocalMachine.OpenSubKey(baseKey);
            if (hklm is null) return;

            foreach (String subkeyName in hklm.GetSubKeyNames())
            {
                if (accessibility.Contains(subkeyName)) continue;

                String subkeyPath = $"{baseKey}\\{subkeyName}";
                String? debugger = ReadString("HKLM", subkeyPath, "Debugger");
                if (!String.IsNullOrWhiteSpace(debugger))
                {
                    issues.Add(new SystemIssue
                    {
                        Id = $"HKLM\\{subkeyPath}\\Debugger",
                        Category = "映像劫持与进程后门",
                        Name = $"IFEO 调试器劫持: {subkeyName}",
                        Description = "Image File Execution Options 下存在非空 Debugger 值，可能劫持程序启动",
                        RegistryPath = $"HKLM\\{subkeyPath}\\Debugger",
                        CurrentValue = debugger,
                        ExpectedValue = "(空)",
                        Severity = IssueSeverity.High,
                        CanFix = true,
                        Action = FixAction.DeleteValue
                    });
                }
            }
        }

        private static void CheckAppInitDlls(List<SystemIssue> issues)
        {
            const String subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

            String? dlls = ReadString("HKLM", subkey, "AppInit_DLLs");
            if (!String.IsNullOrWhiteSpace(dlls))
            {
                issues.Add(new SystemIssue
                {
                    Id = $"HKLM\\{subkey}\\AppInit_DLLs",
                    Category = "映像劫持与进程后门",
                    Name = "AppInit_DLLs 注入",
                    Description = "系统启动时加载 AppInit_DLLs，常被恶意软件用于 DLL 注入",
                    RegistryPath = $"HKLM\\{subkey}\\AppInit_DLLs",
                    CurrentValue = dlls,
                    ExpectedValue = "(空)",
                    Severity = IssueSeverity.High,
                    CanFix = true,
                    Action = FixAction.DeleteValue
                });
            }

            Int32? load = ReadDword("HKLM", subkey, "LoadAppInit_DLLs");
            if (load == 1)
            {
                issues.Add(new SystemIssue
                {
                    Id = $"HKLM\\{subkey}\\LoadAppInit_DLLs",
                    Category = "映像劫持与进程后门",
                    Name = "LoadAppInit_DLLs 已启用",
                    Description = "LoadAppInit_DLLs 被启用，允许 AppInit_DLLs 注入",
                    RegistryPath = $"HKLM\\{subkey}\\LoadAppInit_DLLs",
                    CurrentValue = "1",
                    ExpectedValue = "0",
                    Severity = IssueSeverity.Medium,
                    CanFix = true,
                    Action = FixAction.SetDword
                });
            }
        }

        private static void CheckBootExecute(List<SystemIssue> issues)
        {
            const String subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
            String? v = ReadString("HKLM", subkey, "BootExecute");
            if (String.IsNullOrEmpty(v)) return;

            String normalized = System.Text.RegularExpressions.Regex.Replace(v.Trim().ToLowerInvariant().Replace('\0', ' '), @"\s+", " ").Trim();
            if (normalized != "autocheck autochk *")
            {
                issues.Add(new SystemIssue
                {
                    Id = $"HKLM\\{subkey}\\BootExecute",
                    Category = "映像劫持与进程后门",
                    Name = "BootExecute 启动项被篡改",
                    Description = "Session Manager BootExecute 值异常，可能包含恶意启动命令",
                    RegistryPath = $"HKLM\\{subkey}\\BootExecute",
                    CurrentValue = v,
                    ExpectedValue = "autocheck autochk *",
                    Severity = IssueSeverity.High,
                    CanFix = true,
                    Action = FixAction.SetString
                });
            }
        }

        private static void CheckAccessibilityBackdoors(List<SystemIssue> issues)
        {
            const String baseKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            String[] targets = { "sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe" };

            foreach (String target in targets)
            {
                String subkey = $"{baseKey}\\{target}";
                String? debugger = ReadString("HKLM", subkey, "Debugger");
                if (!String.IsNullOrWhiteSpace(debugger))
                {
                    issues.Add(new SystemIssue
                    {
                        Id = $"HKLM\\{subkey}\\Debugger",
                        Category = "映像劫持与进程后门",
                        Name = $"{target} 辅助功能后门",
                        Description = $"{target} 被 IFEO Debugger 劫持，常见于按 5 次 Shift 等辅助功能触发后门",
                        RegistryPath = $"HKLM\\{subkey}\\Debugger",
                        CurrentValue = debugger,
                        ExpectedValue = "(空)",
                        Severity = IssueSeverity.High,
                        CanFix = true,
                        Action = FixAction.DeleteValue
                    });
                }
            }
        }

        // ── D. 登录与启动链劫持 ──

        private static void CheckWinlogon(List<SystemIssue> issues)
        {
            const String subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

            String? shell = ReadString("HKLM", subkey, "Shell");
            if (!String.Equals(shell, "explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new SystemIssue
                {
                    Id = $"HKLM\\{subkey}\\Shell",
                    Category = "登录与启动链劫持",
                    Name = "Winlogon Shell 异常",
                    Description = "登录后启动的 Shell 不是默认 explorer.exe，可能被恶意替换",
                    RegistryPath = $"HKLM\\{subkey}\\Shell",
                    CurrentValue = shell,
                    ExpectedValue = "explorer.exe",
                    Severity = IssueSeverity.High,
                    CanFix = true,
                    Action = FixAction.SetString
                });
            }

            String? userinit = ReadString("HKLM", subkey, "Userinit");
            String expected = @"C:\Windows\system32\userinit.exe,";
            if (!String.Equals(userinit, expected, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new SystemIssue
                {
                    Id = $"HKLM\\{subkey}\\Userinit",
                    Category = "登录与启动链劫持",
                    Name = "Winlogon Userinit 异常",
                    Description = "Userinit 启动路径被修改，可能附加恶意程序",
                    RegistryPath = $"HKLM\\{subkey}\\Userinit",
                    CurrentValue = userinit,
                    ExpectedValue = expected,
                    Severity = IssueSeverity.High,
                    CanFix = true,
                    Action = FixAction.SetString
                });
            }
        }

        private static readonly String[][] RunStartupPaths =
        [
            ["HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
            ["HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
            ["HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"],
            ["HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"],
            ["HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"],
            ["HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"],
            ["HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"],
            ["HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"],
        ];

        private static void CheckRunStartup(List<SystemIssue> issues)
        {
            String[] suspiciousPaths = [@"\temp\", @"\tmp\", @"\appdata\", @"\downloads\", @"\desktop\"];
            String[] suspiciousExts = [".bat", ".cmd", ".vbs", ".js", ".ps1", ".wsf", ".wsh"];

            foreach (String[] entry in RunStartupPaths)
            {
                String hive = entry[0];
                String subkey = entry[1];

                using RegistryKey? root = OpenHiveRoot(hive);
                if (root is null) continue;
                using RegistryKey? key = root.OpenSubKey(subkey);
                if (key is null) continue;

                foreach (String name in key.GetValueNames())
                {
                    Object? raw = key.GetValue(name);
                    if (raw is not String s) continue;
                    String value = s.TrimEnd('\0');
                    if (String.IsNullOrEmpty(value)) continue;

                    if (IsSuspiciousStartup(value, suspiciousPaths, suspiciousExts))
                    {
                        issues.Add(new SystemIssue
                        {
                            Id = $"{hive}\\{subkey}\\{name}",
                            Category = "登录与启动链劫持",
                            Name = $"可疑启动项: {name}",
                            Description = "启动项指向 Temp/AppData/脚本等可疑位置或无签名路径",
                            RegistryPath = $"{hive}\\{subkey}\\{name}",
                            CurrentValue = value,
                            ExpectedValue = "(删除)",
                            Severity = IssueSeverity.Medium,
                            CanFix = true,
                            Action = FixAction.DeleteValue
                        });
                    }
                }
            }
        }

        private static Boolean IsSuspiciousStartup(String value, String[] suspiciousPaths, String[] suspiciousExts)
        {
            String lower = value.ToLowerInvariant();
            foreach (String p in suspiciousPaths)
            {
                if (lower.Contains(p)) return true;
            }
            foreach (String ext in suspiciousExts)
            {
                if (lower.EndsWith(ext, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        // ── 主入口：扫描 ──

        public static RepairResult Scan()
        {
            List<SystemIssue> issues = new();

            CheckSystemToolPolicies(issues);
            CheckExplorerDisplay(issues);
            CheckIfeoDebugger(issues);
            CheckAppInitDlls(issues);
            CheckBootExecute(issues);
            CheckAccessibilityBackdoors(issues);
            CheckWinlogon(issues);
            CheckRunStartup(issues);

            RepairSummary summary = new()
            {
                Total = issues.Count,
                High = issues.Count(i => i.Severity == IssueSeverity.High),
                Medium = issues.Count(i => i.Severity == IssueSeverity.Medium),
                Low = issues.Count(i => i.Severity == IssueSeverity.Low),
                Fixed = 0
            };

            return new RepairResult { Issues = issues, Summary = summary };
        }

        // ── 主入口：修复 ──

        public static RepairFixResult Fix(IEnumerable<String> issueIds, RepairResult? scanResult = null)
        {
            // 构建 id → issue 映射，若调用方传入 scanResult 则用之，否则现场重扫
            Dictionary<String, SystemIssue> issueMap = new();
            RepairResult result = scanResult ?? Scan();
            foreach (SystemIssue issue in result.Issues)
            {
                issueMap[issue.Id] = issue;
            }

            List<String> fixedList = new();
            List<String> failedList = new();

            foreach (String id in issueIds)
            {
                if (!issueMap.TryGetValue(id, out SystemIssue? issue))
                {
                    failedList.Add(id);
                    continue;
                }

                // 解析 hive\subkey\value
                String[] parts = issue.RegistryPath.Split('\\');
                if (parts.Length < 4)
                {
                    failedList.Add(id);
                    continue;
                }
                String hive = parts[0];
                String value = parts[^1];
                String subkey = String.Join('\\', parts, 1, parts.Length - 2);

                Boolean ok = issue.Action switch
                {
                    FixAction.SetDword => TrySetDwordFromIssue(issue, hive, subkey, value),
                    FixAction.SetString => TrySetStringFromIssue(issue, hive, subkey, value),
                    FixAction.DeleteValue => DeleteValue(hive, subkey, value),
                    _ => DeleteValue(hive, subkey, value)
                };

                if (ok) fixedList.Add(id);
                else failedList.Add(id);
            }

            return new RepairFixResult
            {
                Success = failedList.Count == 0,
                FixedIds = fixedList,
                FailedIds = failedList,
                Message = $"已修复 {fixedList.Count} 项，失败 {failedList.Count} 项"
            };
        }

        private static Boolean TrySetDwordFromIssue(SystemIssue issue, String hive, String subkey, String value)
        {
            // 从 ExpectedValue 解析目标 DWORD
            if (!Int32.TryParse(issue.ExpectedValue, out Int32 target)) return false;
            return WriteDword(hive, subkey, value, target);
        }

        private static Boolean TrySetStringFromIssue(SystemIssue issue, String hive, String subkey, String value)
        {
            // 从 ExpectedValue 恢复默认字符串值
            if (String.IsNullOrEmpty(issue.ExpectedValue) || issue.ExpectedValue == "(空)") return DeleteValue(hive, subkey, value);
            return WriteString(hive, subkey, value, issue.ExpectedValue);
        }
    }
}
