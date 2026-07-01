using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    internal static partial class NativeMethods
    {
        [LibraryImport("kernel32.dll")]
        public static partial nint OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

        [LibraryImport("kernel32.dll")]
        public static partial uint SuspendThread(nint hThread);

        [LibraryImport("kernel32.dll")]
        public static partial uint ResumeThread(nint hThread);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool TerminateThread(nint hThread, uint dwExitCode);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool CloseHandle(nint hHandle);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial nint OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int processId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool TerminateProcess(nint hProcess, uint uExitCode);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool GetExitCodeProcess(nint hProcess, out uint lpExitCode);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool GetExitCodeThread(nint hThread, out uint lpExitCode);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool VirtualFreeEx(nint hProcess, nint lpAddress, nuint dwSize, uint dwFreeType);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint GetModuleHandleW(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint LoadLibraryW(string lpLibFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern nint GetProcAddress(nint hModule, string lpProcName);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool DebugActiveProcess(int dwProcessId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool DebugActiveProcessStop(int dwProcessId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool DebugSetProcessKillOnExit([MarshalAs(UnmanagedType.Bool)] bool killOnExit);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool DebugBreakProcess(nint process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitForDebugEvent(ref DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial uint QueueUserAPC(nint pfnAPC, nint hThread, nint dwData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool IsWow64Process(nint hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [LibraryImport("ntdll.dll")]
        public static partial int NtQueryInformationProcess(nint processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

        [LibraryImport("ntdll.dll")]
        public static partial int NtQueryInformationProcess(nint processHandle, int processInformationClass, ref nint processInformation, uint processInformationLength, out uint returnLength);

        [LibraryImport("ntdll.dll")]
        public static partial int NtAlertThread(nint threadHandle);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowVisible(nint hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EndTask(nint hWnd, [MarshalAs(UnmanagedType.Bool)] bool fShutDown, [MarshalAs(UnmanagedType.Bool)] bool fForce);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate bool EnumWindowsProc(nint hWnd, nint lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public nint Reserved1;
            public nint PebBaseAddress;
            public nint Reserved2_0;
            public nint Reserved2_1;
            public nint UniqueProcessId;
            public nint InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSGBOXPARAMSW
        {
            public uint cbSize;
            public nint hwndOwner;
            public nint hInstance;
            public nint lpszText;
            public nint lpszCaption;
            public uint dwStyle;
            public nint lpszIcon;
            public nuint dwContextHelpId;
            public nint lpfnMsgBoxCallback;
            public uint dwLanguageId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DEBUG_EVENT
        {
            public uint dwDebugEventCode;
            public uint dwProcessId;
            public uint dwThreadId;
            public DEBUG_EVENT_UNION u;
        }

        [StructLayout(LayoutKind.Explicit, Size = 176)]
        public struct DEBUG_EVENT_UNION
        {
            [FieldOffset(0)]
            public uint ExceptionCode;
        }

        public const uint THREAD_TERMINATE = 0x0001;
        public const uint THREAD_ALERT = 0x0004;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint WAIT_OBJECT_0 = 0x00000000;
        public const uint WAIT_TIMEOUT = 0x00000102;
        public const uint STILL_ACTIVE = 259;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint MB_OK = 0x00000000;
        public const uint MB_ICONERROR = 0x00000010;
        public const uint MB_SETFOREGROUND = 0x00010000;
        public const uint FORCED_TERMINATION_EXIT_CODE = 0xE11D0;
        public const int ProcessBasicInformation = 0;
        public const int ProcessCommandLineInformation = 60;
    }

    public sealed partial class ProcessManagerView : UserControl
    {
        private List<ProcessInfoEx> _allProcesses = [];
        private bool _isTreeView;

        public ProcessManagerView()
        {
            InitializeComponent();
            SortCombo.SelectedIndex = 0;
            _ = RefreshProcesses();
        }

        private bool IsTreeView
        {
            get => _isTreeView;
            set
            {
                _isTreeView = value;
                ProcessList.Visibility = value ? Visibility.Collapsed : Visibility.Visible;
                ProcessTree.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
                ListHeader.Visibility = value ? Visibility.Collapsed : Visibility.Visible;
                SortCombo.IsEnabled = !value;
            }
        }

        private async Task RefreshProcesses()
        {
            LoadingPanel.Visibility = Visibility.Visible;
            ProcessList.Visibility = Visibility.Collapsed;
            ProcessTree.Visibility = Visibility.Collapsed;

            try
            {
                var list = await Task.Run(() =>
                    Process.GetProcesses()
                        .Select(p => new ProcessInfoEx(p))
                        .OrderBy(p => p.Name)
                        .ToList()
                );

                _allProcesses = list;

                if (IsTreeView)
                {
                    await LoadParentIdsAsync();
                    BuildProcessTree();
                }
                else
                {
                    ApplyFilterAndSort();
                }
            }
            catch (Exception ex)
            {
                await ShowDialogAsync("刷新失败", ex.Message);
            }
            finally
            {
                LoadingPanel.Visibility = Visibility.Collapsed;
                if (IsTreeView)
                    ProcessTree.Visibility = Visibility.Visible;
                else
                    ProcessList.Visibility = Visibility.Visible;
            }
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e)
            => await RefreshProcesses();

        private async void ViewModeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            IsTreeView = ViewModeToggle.IsOn;

            if (IsTreeView)
            {
                LoadingPanel.Visibility = Visibility.Visible;
                ProcessTree.Visibility = Visibility.Collapsed;

                try
                {
                    await LoadParentIdsAsync();
                    BuildProcessTree();
                }
                catch (Exception ex)
                {
                    await ShowDialogAsync("切换失败", $"无法加载树状图: {ex.Message}");
                    ViewModeToggle.IsOn = false;
                    IsTreeView = false;
                    ApplyFilterAndSort();
                    return;
                }

                LoadingPanel.Visibility = Visibility.Collapsed;
                ProcessTree.Visibility = Visibility.Visible;
            }
            else
            {
                ApplyFilterAndSort();
            }
        }

        private async Task LoadParentIdsAsync()
        {
            var needLoad = _allProcesses.Where(p => !p.IsParentIdLoaded).ToList();
            if (needLoad.Count == 0) return;

            await Task.Run(() =>
            {
                Parallel.ForEach(needLoad, p => p.LoadParentId());
            });
        }

        private void BuildProcessTree()
        {
            ProcessTree.RootNodes.Clear();

            var lookup = _allProcesses.ToDictionary(p => p.Id);
            var childrenMap = new Dictionary<uint, List<ProcessInfoEx>>();
            var roots = new List<ProcessInfoEx>();

            foreach (var proc in _allProcesses)
            {
                if (proc.ParentId == 0 || !lookup.ContainsKey(proc.ParentId))
                {
                    roots.Add(proc);
                }
                else
                {
                    if (!childrenMap.TryGetValue(proc.ParentId, out var children))
                    {
                        children = [];
                        childrenMap[proc.ParentId] = children;
                    }
                    children.Add(proc);
                }
            }

            var visited = new HashSet<uint>();

            foreach (var root in roots.OrderBy(p => p.Name))
            {
                var node = CreateTreeNode(root, childrenMap, visited);
                if (node != null)
                    ProcessTree.RootNodes.Add(node);
            }
        }

        private static TreeViewNode? CreateTreeNode(ProcessInfoEx process, Dictionary<uint, List<ProcessInfoEx>> childrenMap, HashSet<uint> visited)
        {
            if (!visited.Add(process.Id))
                return null;

            var node = new TreeViewNode { Content = process };

            if (childrenMap.TryGetValue(process.Id, out var children))
            {
                foreach (var child in children.OrderBy(p => p.Name))
                {
                    var childNode = CreateTreeNode(child, childrenMap, visited);
                    if (childNode != null)
                        node.Children.Add(childNode);
                }
            }

            return node;
        }

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyFilterAndSort();

        private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
            => ApplyFilterAndSort();

        private void ApplyFilterAndSort()
        {
            if (IsTreeView) return;

            var keyword = SearchBox.Text?.Trim() ?? "";
            IEnumerable<ProcessInfoEx> filtered = _allProcesses;

            if (!string.IsNullOrEmpty(keyword))
            {
                if (uint.TryParse(keyword, out var pid))
                    filtered = _allProcesses.Where(p => p.Id == pid);
                else
                    filtered = _allProcesses.Where(p => p.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase));
            }

            ProcessList.ItemsSource = ApplySort(filtered).ToList();
        }

        private IEnumerable<ProcessInfoEx> ApplySort(IEnumerable<ProcessInfoEx> src)
        {
            var tag = (SortCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Name";
            return tag switch
            {
                "Id" => src.OrderBy(p => p.Id),
                "Memory" => src.OrderByDescending(p => p.MemoryBytes),
                "Threads" => src.OrderByDescending(p => p.ThreadCount),
                "Handles" => src.OrderByDescending(p => p.HandleCount),
                _ => src.OrderBy(p => p.Name)
            };
        }

        private ProcessInfoEx? GetProcessInfoFromSender(object sender)
        {
            if (sender is MenuFlyoutItem menuItem)
                return menuItem.DataContext as ProcessInfoEx;

            if (IsTreeView)
            {
                if (ProcessTree.SelectedNode?.Content is ProcessInfoEx treeInfo)
                    return treeInfo;
                return null;
            }

            return ProcessList.SelectedItem as ProcessInfoEx;
        }

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;
            await KillProcessAsync(info);
        }

        private async Task KillProcessAsync(ProcessInfoEx info)
        {
            var confirm = new ContentDialog
            {
                Title = $"你希望结束 {info.Name} ({info.Id}) 吗？",
                Content = "如果某个打开的程序与此进程关联，则会关闭此程序并且将丢失所有未保存的数据。如果结束某个系统进程，则可能导致系统不稳定。你确定要继续吗？",
                PrimaryButtonText = "结束",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

            var result = await Task.Run(() => KillProcessWithFallbacks((int)info.Id));

            if (result.Success)
                await ShowDialogAsync("结束成功", $"进程 {info.Name} 已结束。\n\n{result.ToDisplayText()}");
            else
                await ShowDialogAsync("结束失败", $"无法结束进程 {info.Name}。\n\n{result.ToDisplayText()}");

            await RefreshProcesses();
        }

        private async void Suspend_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var (success, error) = await Task.Run(() =>
            {
                try
                {
                    SuspendProcess((int)info.Id);
                    return (true, "");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });

            if (success)
                await ShowDialogAsync("挂起成功", $"进程 {info.Name} 已挂起。");
            else
                await ShowDialogAsync("挂起失败", $"无法挂起进程: {error}");
        }

        private async void Resume_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var (success, error) = await Task.Run(() =>
            {
                try
                {
                    ResumeProcess((int)info.Id);
                    return (true, "");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });

            if (success)
                await ShowDialogAsync("恢复成功", $"进程 {info.Name} 已恢复。");
            else
                await ShowDialogAsync("恢复失败", $"无法恢复进程: {error}");
        }

        private async void ShowProcessDetail_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            await info.EnsureExtendedInfoLoadedAsync();

            var items = new List<(string Key, string Value)>
            {
                ("进程名称", info.Name),
                ("进程编号", info.Id.ToString()),
                ("父进程ID", info.ParentId.ToString()),
                ("会话ID", info.SessionId.ToString()),
                ("使用内存", info.Memory),
                ("私有内存", info.PrivateMemory),
                ("线程数", info.ThreadCount.ToString()),
                ("句柄数", info.HandleCount.ToString()),
                ("优先级", info.PriorityClass.ToString()),
                ("架构", info.IsWow64 ? "32位 (WOW64)" : "64位")
            };

            if (!string.IsNullOrEmpty(info.ImagePath))
            {
                items.Add(("文件路径", info.ImagePath));

                try
                {
                    var fi = new FileInfo(info.ImagePath);
                    if (fi.Exists)
                    {
                        items.Add(("创建时间", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")));
                        items.Add(("修改时间", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")));
                        items.Add(("文件大小", $"{fi.Length / 1024.0 / 1024.0:F2} MB"));

                        var versionInfo = FileVersionInfo.GetVersionInfo(fi.FullName);
                        items.Add(("文件版本", versionInfo.FileVersion ?? "-"));
                        items.Add(("产品版本", versionInfo.ProductVersion ?? "-"));
                        items.Add(("公司名称", versionInfo.CompanyName ?? "-"));
                        items.Add(("产品名称", versionInfo.ProductName ?? "-"));
                        items.Add(("文件描述", versionInfo.FileDescription ?? "-"));
                    }
                }
                catch { }
            }
            else
            {
                items.Add(("文件路径", "拒绝访问或已退出"));
            }

            if (!string.IsNullOrEmpty(info.CommandLine))
                items.Add(("命令行", info.CommandLine));

            var listView = new ListView
            {
                SelectionMode = ListViewSelectionMode.None,
                IsItemClickEnabled = false,
                Padding = new Thickness(0),
                Margin = new Thickness(0)
            };

            var compactStyle = new Style(typeof(ListViewItem));
            compactStyle.Setters.Add(new Setter { Property = ListViewItem.PaddingProperty, Value = new Thickness(0) });
            compactStyle.Setters.Add(new Setter { Property = ListViewItem.MinHeightProperty, Value = 0d });
            compactStyle.Setters.Add(new Setter { Property = ListViewItem.MarginProperty, Value = new Thickness(0) });
            listView.ItemContainerStyle = compactStyle;

            int itemIndex = 0;
            foreach (var (key, value) in items)
            {
                var keyBlock = new TextBlock
                {
                    Text = key,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Top
                };
                Grid.SetColumn(keyBlock, 0);

                var valueBlock = new TextBlock
                {
                    Text = value,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap
                };
                Grid.SetColumn(valueBlock, 1);

                var row = new Grid
                {
                    ColumnDefinitions =
                    {
                        new ColumnDefinition { Width = new GridLength(100) },
                        new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }
                    },
                    Padding = new Thickness(0, 2, 0, 2),
                    ColumnSpacing = 16,
                    Children = { keyBlock, valueBlock }
                };

                int delay = itemIndex * 15;
                row.Loaded += (s, e) => App.PlayEntranceAnimation(row, "up", delayMs: delay);

                listView.Items.Add(row);
                itemIndex++;
            }

            var dialog = new ContentDialog
            {
                Title = "详细信息",
                Content = listView,
                CloseButtonText = "关闭",
                XamlRoot = this.XamlRoot,
                PrimaryButtonText = "定位文件",
                SecondaryButtonText = "结束进程",
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            };

            var result = await dialog.ShowAsync();

            if (result == ContentDialogResult.Primary)
            {
                if (string.IsNullOrEmpty(info.ImagePath))
                {
                    await ShowDialogAsync("无法定位文件", "无法访问此进程的文件路径。");
                }
                else
                {
                    try
                    {
                        var safeFilePath = info.ImagePath.Replace("\"", "\\\"");
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"/select,\"{safeFilePath}\"",
                            UseShellExecute = true
                        });
                    }
                    catch (Exception ex)
                    {
                        await ShowDialogAsync("无法定位文件", $"无法定位文件，因为{ex.Message}");
                    }
                }
            }
            else if (result == ContentDialogResult.Secondary)
            {
                await KillProcessAsync(info);
            }
        }

        private async Task ShowDialogAsync(string title, string content)
        {
            await new ContentDialog
            {
                Title = title,
                Content = content,
                CloseButtonText = "确定",
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            }.ShowAsync();
        }

        private ElementTheme GetDialogTheme()
            => (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default;

        public static void SuspendProcess(int processId)
        {
            var process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads)
            {
                var hThread = NativeMethods.OpenThread(NativeMethods.THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (hThread != 0)
                {
                    _ = NativeMethods.SuspendThread(hThread);
                    NativeMethods.CloseHandle(hThread);
                }
            }
        }

        public static void ResumeProcess(int processId)
        {
            var process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads)
            {
                var hThread = NativeMethods.OpenThread(NativeMethods.THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (hThread != 0)
                {
                    _ = NativeMethods.ResumeThread(hThread);
                    NativeMethods.CloseHandle(hThread);
                }
            }
        }

        private static ProcessKillResult KillProcessWithFallbacks(int processId)
        {
            var result = new ProcessKillResult();

            if (processId == Environment.ProcessId)
            {
                result.Add("保护当前进程", false, "不会结束 Xdows Security 自身。");
                return result;
            }

            if (HasProcessExited(processId))
            {
                result.Success = true;
                result.Add("检查进程状态", true, "目标进程已经退出。");
                return result;
            }

            AddAttempt(result, "直接结束目标进程", () => TryTerminateDirectly(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "销毁目标所有线程使进程退出", () => TryTerminateThreads(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "调试器 / 异常控制路径强制结束", () => TryDebugExceptionKill(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "制造目标进程不可恢复异常 / 崩溃", () => TryCrashWithRemoteFatalExit(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "EndTask(fForce=TRUE) 结束窗口任务", () => TryEndTaskForProcess(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "注入使其弹出窗口，再用 EndTask", () => TryInjectMessageBoxThenEndTask(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, "APC 注入指向无效地址直接崩溃", () => TryCrashWithApcGarbage(processId));
            if (CompleteIfExited(result, processId)) return result;

            if (HasProcessExited(processId))
            {
                result.Success = true;
                result.Add("退出确认", true, "目标进程已退出。");
            }
            else
            {
                result.Add("最终状态", false, "进程仍在运行。");
            }

            return result;
        }

        private static void AddAttempt(ProcessKillResult result, string name, Func<(bool Success, string Message)> action)
        {
            try
            {
                var (success, message) = action();
                result.Add(name, success, message);
            }
            catch (Exception ex)
            {
                result.Add(name, false, ex.Message);
            }
        }

        private static bool CompleteIfExited(ProcessKillResult result, int processId)
        {
            if (!WaitForProcessExit(processId, 500))
                return false;

            result.Success = true;
            result.Add("退出确认", true, "目标进程已退出。");
            return true;
        }

        private static (bool Success, string Message) TryTerminateDirectly(int processId)
        {
            var messages = new List<string>();

            try
            {
                using var process = Process.GetProcessById(processId);
                process.Kill();

                if (process.WaitForExit(3000))
                    return (true, "Process.Kill 已结束目标进程。");

                messages.Add("Process.Kill 已发送终止请求，但等待退出超时");
            }
            catch (Exception ex)
            {
                messages.Add($"Process.Kill 失败: {ex.Message}");
            }

            var native = TryTerminateProcessNative(processId);
            if (native.Success)
            {
                if (messages.Count == 0)
                    return native;

                return (true, $"{native.Message}；{string.Join("；", messages)}");
            }

            messages.Add($"TerminateProcess 失败: {native.Message}");
            return (false, string.Join("；", messages));
        }

        private static (bool Success, string Message) TryTerminateProcessNative(int processId)
        {
            nint hProcess = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_TERMINATE | NativeMethods.SYNCHRONIZE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                processId);

            if (hProcess == 0)
                return (false, GetLastSystemError());

            try
            {
                if (!NativeMethods.TerminateProcess(hProcess, NativeMethods.FORCED_TERMINATION_EXIT_CODE))
                    return (false, GetLastSystemError());

                var wait = NativeMethods.WaitForSingleObject(hProcess, 3000);
                if (wait == NativeMethods.WAIT_OBJECT_0)
                    return (true, "TerminateProcess 已结束目标进程。");

                if (NativeMethods.GetExitCodeProcess(hProcess, out var exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
                    return (true, $"TerminateProcess 已结束目标进程，退出码 0x{exitCode:X}。");

                if (wait == NativeMethods.WAIT_TIMEOUT)
                    return (false, "TerminateProcess 已调用，但等待退出超时。");

                return (false, $"TerminateProcess 已调用，但等待返回 0x{wait:X}。");
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static (bool Success, string Message) TryTerminateThreads(int processId)
        {
            List<int> threadIds = [];

            try
            {
                using var process = Process.GetProcessById(processId);
                foreach (ProcessThread thread in process.Threads)
                {
                    threadIds.Add(thread.Id);
                }
            }
            catch (Exception ex)
            {
                return (false, $"无法枚举线程: {ex.Message}");
            }

            if (threadIds.Count == 0)
                return (false, "目标进程没有可枚举线程。");

            var terminated = 0;
            var failed = 0;
            string? firstError = null;

            foreach (var threadId in threadIds)
            {
                var hThread = NativeMethods.OpenThread(NativeMethods.THREAD_TERMINATE, false, (uint)threadId);
                if (hThread == 0)
                {
                    failed++;
                    firstError ??= $"线程 {threadId}: {GetLastSystemError()}";
                    continue;
                }

                try
                {
                    if (NativeMethods.TerminateThread(hThread, NativeMethods.FORCED_TERMINATION_EXIT_CODE))
                    {
                        terminated++;
                    }
                    else
                    {
                        failed++;
                        firstError ??= $"线程 {threadId}: {GetLastSystemError()}";
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }

            if (terminated == 0)
                return (false, $"未能结束任何线程。{firstError ?? "无详细错误。"}");

            if (WaitForProcessExit(processId, 3000))
                return (true, $"已结束 {terminated}/{threadIds.Count} 个线程，进程已退出。");

            var message = $"已结束 {terminated}/{threadIds.Count} 个线程，但进程仍在运行。";
            if (failed > 0)
                message += $" {failed} 个线程失败。{firstError}";

            return (false, message);
        }

        private static (bool Success, string Message) TryDebugExceptionKill(int processId)
        {
            if (!NativeMethods.DebugActiveProcess(processId))
                return (false, $"DebugActiveProcess 失败: {GetLastSystemError()}");

            var sawException = false;
            var attached = true;
            var breakRequested = false;
            string? breakError = null;

            try
            {
                NativeMethods.DebugSetProcessKillOnExit(false);

                nint hProcess = NativeMethods.OpenProcess(
                    NativeMethods.PROCESS_CREATE_THREAD |
                    NativeMethods.PROCESS_VM_OPERATION |
                    NativeMethods.PROCESS_VM_WRITE |
                    NativeMethods.PROCESS_VM_READ |
                    NativeMethods.PROCESS_QUERY_INFORMATION |
                    NativeMethods.SYNCHRONIZE,
                    false,
                    processId);

                if (hProcess != 0)
                {
                    try
                    {
                        breakRequested = NativeMethods.DebugBreakProcess(hProcess);
                        if (!breakRequested)
                            breakError = GetLastSystemError();
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProcess);
                    }
                }
                else
                {
                    breakError = GetLastSystemError();
                }

                var stopwatch = Stopwatch.StartNew();
                while (stopwatch.ElapsedMilliseconds < 7000)
                {
                    var debugEvent = new NativeMethods.DEBUG_EVENT();
                    if (!NativeMethods.WaitForDebugEvent(ref debugEvent, 500))
                    {
                        if (HasProcessExited(processId))
                            return (true, "调试器已接管目标，进程已退出。");

                        continue;
                    }

                    if (debugEvent.dwDebugEventCode == NativeMethods.EXIT_PROCESS_DEBUG_EVENT)
                    {
                        attached = false;
                        NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_CONTINUE);
                        return (true, "调试事件报告目标进程已退出。");
                    }

                    if (debugEvent.dwDebugEventCode == NativeMethods.EXCEPTION_DEBUG_EVENT)
                    {
                        sawException = true;
                        NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_EXCEPTION_NOT_HANDLED);

                        if (WaitForProcessExit(processId, 2000))
                        {
                            attached = false;
                            var exceptionText = debugEvent.u.ExceptionCode == NativeMethods.EXCEPTION_BREAKPOINT
                                ? "断点异常"
                                : $"异常 0x{debugEvent.u.ExceptionCode:X}";
                            return (true, $"已通过调试器传递 {exceptionText}，目标进程已退出。");
                        }

                        continue;
                    }

                    NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_CONTINUE);
                }

                var message = breakRequested
                    ? "已附加调试器并请求 DebugBreakProcess，但目标未退出。"
                    : $"已附加调试器，但无法请求 DebugBreakProcess: {breakError ?? "未知错误"}。";

                if (sawException)
                    message += " 已观察到异常事件但目标仍在运行。";

                return (false, message);
            }
            finally
            {
                if (attached && !HasProcessExited(processId))
                    NativeMethods.DebugActiveProcessStop(processId);
            }
        }

        private static (bool Success, string Message) TryCrashWithRemoteFatalExit(int processId)
        {
            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            var fatalExit = GetLocalProcAddress("kernel32.dll", "FatalExit", out var procError);
            if (fatalExit == 0)
                return (false, procError);

            nint hProcess = OpenProcessForRemoteExecution(processId, out var openError);
            if (hProcess == 0)
                return (false, openError);

            try
            {
                var (hThread, threadId, threadError) = StartRemoteThread(hProcess, fatalExit, (nint)NativeMethods.FORCED_TERMINATION_EXIT_CODE);
                if (hThread == 0)
                    return (false, $"CreateRemoteThread(FatalExit) 失败: {threadError}");

                try
                {
                    NativeMethods.WaitForSingleObject(hThread, 3000);
                    if (WaitForProcessExit(processId, 3000))
                        return (true, $"已在目标进程创建 FatalExit 线程 {threadId}，目标进程已退出。");

                    var exitText = NativeMethods.GetExitCodeThread(hThread, out var exitCode)
                        ? $"远程线程退出码 0x{exitCode:X}。"
                        : $"无法读取远程线程退出码: {GetLastSystemError()}";

                    return (false, $"FatalExit 远程线程已创建，但目标进程仍在运行。{exitText}");
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static (bool Success, string Message) TryEndTaskForProcess(int processId)
        {
            var windows = FindTopLevelWindowsForProcess((uint)processId);
            if (windows.Count == 0)
                return (false, "未找到该进程的可见顶层窗口。");

            var successCount = 0;
            string? firstError = null;

            foreach (var hWnd in windows)
            {
                if (NativeMethods.EndTask(hWnd, false, true))
                {
                    successCount++;
                }
                else
                {
                    firstError ??= GetLastSystemError();
                }
            }

            if (WaitForProcessExit(processId, 3000))
                return (true, $"EndTask 已处理 {successCount}/{windows.Count} 个窗口，进程已退出。");

            if (successCount > 0)
                return (false, $"EndTask 已处理 {successCount}/{windows.Count} 个窗口，但进程仍在运行。");

            return (false, $"EndTask 未成功处理窗口。{firstError ?? "无详细错误。"}");
        }

        private static (bool Success, string Message) TryInjectMessageBoxThenEndTask(int processId)
        {
            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            nint hProcess = OpenProcessForRemoteExecution(processId, out var openError);
            if (hProcess == 0)
                return (false, openError);

            var remoteAllocations = new List<nint>();
            nint hThread = 0;

            try
            {
                var loadResult = EnsureRemoteModuleLoaded(hProcess, "user32.dll");
                if (!loadResult.Success)
                    return (false, loadResult.Message);

                var messageBoxIndirect = GetLocalProcAddress("user32.dll", "MessageBoxIndirectW", out var procError);
                if (messageBoxIndirect == 0)
                    return (false, procError);

                var text = Encoding.Unicode.GetBytes("Xdows Security 正在结束此进程。\0");
                var caption = Encoding.Unicode.GetBytes("Xdows Security\0");

                var textRemote = RemoteAllocAndWrite(hProcess, text, NativeMethods.PAGE_READWRITE);
                if (textRemote.Address == 0)
                    return (false, $"写入远程消息文本失败: {textRemote.Error}");
                remoteAllocations.Add(textRemote.Address);

                var captionRemote = RemoteAllocAndWrite(hProcess, caption, NativeMethods.PAGE_READWRITE);
                if (captionRemote.Address == 0)
                    return (false, $"写入远程标题失败: {captionRemote.Error}");
                remoteAllocations.Add(captionRemote.Address);

                var parameters = new NativeMethods.MSGBOXPARAMSW
                {
                    cbSize = (uint)Marshal.SizeOf<NativeMethods.MSGBOXPARAMSW>(),
                    lpszText = textRemote.Address,
                    lpszCaption = captionRemote.Address,
                    dwStyle = NativeMethods.MB_OK | NativeMethods.MB_ICONERROR | NativeMethods.MB_SETFOREGROUND
                };

                var parameterBytes = StructureToBytes(parameters);
                var parameterRemote = RemoteAllocAndWrite(hProcess, parameterBytes, NativeMethods.PAGE_READWRITE);
                if (parameterRemote.Address == 0)
                    return (false, $"写入 MessageBoxIndirectW 参数失败: {parameterRemote.Error}");
                remoteAllocations.Add(parameterRemote.Address);

                var thread = StartRemoteThread(hProcess, messageBoxIndirect, parameterRemote.Address);
                if (thread.Handle == 0)
                    return (false, $"CreateRemoteThread(MessageBoxIndirectW) 失败: {thread.Error}");

                hThread = thread.Handle;
                NativeMethods.WaitForSingleObject(hThread, 750);

                var endTaskResult = TryEndTaskForProcess(processId);
                if (WaitForProcessExit(processId, 3000))
                    return (true, $"已注入 MessageBoxIndirectW 线程 {thread.ThreadId} 并调用 EndTask，目标进程已退出。{endTaskResult.Message}");

                return (false, $"已注入 MessageBoxIndirectW 线程 {thread.ThreadId}，但 EndTask 后目标仍在运行。{endTaskResult.Message}");
            }
            finally
            {
                var canFreeRemoteMemory = hThread == 0 || IsThreadExited(hThread);
                if (canFreeRemoteMemory)
                {
                    foreach (var allocation in remoteAllocations)
                        TryFreeRemoteMemory(hProcess, allocation);
                }

                if (hThread != 0)
                    NativeMethods.CloseHandle(hThread);

                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static (bool Success, string Message) TryCrashWithApcGarbage(int processId)
        {
            if (!IsPointerInjectionCompatible(processId, out var compatibilityError))
                return (false, compatibilityError);

            var threadIds = GetProcessThreadIds(processId, out var threadError);
            if (threadIds.Count == 0)
                return (false, threadError ?? "目标进程没有可枚举线程。");

            nint hProcess = OpenProcessForRemoteExecution(processId, out var openError);
            if (hProcess == 0)
                return (false, openError);

            nint remoteGarbage = 0;

            try
            {
                var garbage = Encoding.ASCII.GetBytes("Xdows_APC_GARBAGE_TARGET_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789");
                var allocation = RemoteAllocAndWrite(hProcess, garbage, NativeMethods.PAGE_READWRITE);
                if (allocation.Address == 0)
                    return (false, $"写入远程垃圾指令失败: {allocation.Error}");

                remoteGarbage = allocation.Address;

                var queued = 0;
                var alerted = 0;
                var failed = 0;
                string? firstError = null;

                foreach (var threadId in threadIds)
                {
                    var hThread = NativeMethods.OpenThread(
                        NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_ALERT | NativeMethods.THREAD_QUERY_INFORMATION,
                        false,
                        (uint)threadId);

                    if (hThread == 0)
                    {
                        failed++;
                        firstError ??= $"线程 {threadId}: {GetLastSystemError()}";
                        continue;
                    }

                    try
                    {
                        if (NativeMethods.QueueUserAPC(remoteGarbage, hThread, 0) == 0)
                        {
                            failed++;
                            firstError ??= $"线程 {threadId}: QueueUserAPC 失败: {GetLastSystemError()}";
                            continue;
                        }

                        queued++;

                        if (NativeMethods.NtAlertThread(hThread) == 0)
                            alerted++;
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hThread);
                    }
                }

                if (WaitForProcessExit(processId, 5000))
                    return (true, $"已向 {queued}/{threadIds.Count} 个线程注入 APC 垃圾入口并 alert {alerted} 个线程，目标进程已退出。");

                return (false, $"已向 {queued}/{threadIds.Count} 个线程排队 APC，alert {alerted} 个线程，目标仍在运行。失败 {failed} 个。{firstError ?? ""}");
            }
            finally
            {
                if (remoteGarbage != 0 && HasProcessExited(processId) == false)
                    TryFreeRemoteMemory(hProcess, remoteGarbage);

                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static List<nint> FindTopLevelWindowsForProcess(uint processId)
        {
            var windows = new List<nint>();

            NativeMethods.EnumWindows((hWnd, _) =>
            {
                NativeMethods.GetWindowThreadProcessId(hWnd, out var windowProcessId);
                if (windowProcessId == processId && NativeMethods.IsWindowVisible(hWnd))
                    windows.Add(hWnd);

                return true;
            }, 0);

            return windows;
        }

        private static nint OpenProcessForRemoteExecution(int processId, out string error)
        {
            const uint access =
                NativeMethods.PROCESS_CREATE_THREAD |
                NativeMethods.PROCESS_QUERY_INFORMATION |
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION |
                NativeMethods.PROCESS_VM_OPERATION |
                NativeMethods.PROCESS_VM_READ |
                NativeMethods.PROCESS_VM_WRITE |
                NativeMethods.SYNCHRONIZE;

            var hProcess = NativeMethods.OpenProcess(access, false, processId);
            if (hProcess != 0)
            {
                error = "";
                return hProcess;
            }

            error = GetLastSystemError();
            return 0;
        }

        private static bool IsPointerInjectionCompatible(int processId, out string reason)
        {
            reason = "";

            if (!Environment.Is64BitOperatingSystem)
                return true;

            var hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (hProcess == 0)
            {
                reason = $"无法查询目标进程架构: {GetLastSystemError()}";
                return false;
            }

            try
            {
                if (!NativeMethods.IsWow64Process(hProcess, out var targetIsWow64))
                {
                    reason = $"IsWow64Process 失败: {GetLastSystemError()}";
                    return false;
                }

                if (Environment.Is64BitProcess && targetIsWow64)
                {
                    reason = "目标进程是 32 位 WOW64，当前进程是 64 位，远程函数地址和 APC 指针不兼容。";
                    return false;
                }

                if (!Environment.Is64BitProcess && !targetIsWow64)
                {
                    reason = "目标进程是 64 位，当前进程是 32 位，远程函数地址和 APC 指针不兼容。";
                    return false;
                }

                return true;
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        private static nint GetLocalProcAddress(string moduleName, string procName, out string error)
        {
            error = "";

            var module = NativeMethods.GetModuleHandleW(moduleName);
            if (module == 0)
                module = NativeMethods.LoadLibraryW(moduleName);

            if (module == 0)
            {
                error = $"加载本地模块 {moduleName} 失败: {GetLastSystemError()}";
                return 0;
            }

            var proc = NativeMethods.GetProcAddress(module, procName);
            if (proc == 0)
            {
                error = $"解析 {moduleName}!{procName} 失败: {GetLastSystemError()}";
                return 0;
            }

            return proc;
        }

        private static (bool Success, string Message) EnsureRemoteModuleLoaded(nint hProcess, string moduleName)
        {
            var loadLibrary = GetLocalProcAddress("kernel32.dll", "LoadLibraryW", out var procError);
            if (loadLibrary == 0)
                return (false, procError);

            var moduleNameBytes = Encoding.Unicode.GetBytes(moduleName + "\0");
            var remoteModuleName = RemoteAllocAndWrite(hProcess, moduleNameBytes, NativeMethods.PAGE_READWRITE);
            if (remoteModuleName.Address == 0)
                return (false, $"写入远程模块名失败: {remoteModuleName.Error}");

            nint hThread = 0;

            try
            {
                var thread = StartRemoteThread(hProcess, loadLibrary, remoteModuleName.Address);
                if (thread.Handle == 0)
                    return (false, $"CreateRemoteThread(LoadLibraryW) 失败: {thread.Error}");

                hThread = thread.Handle;
                var wait = NativeMethods.WaitForSingleObject(hThread, 5000);

                if (wait == NativeMethods.WAIT_OBJECT_0)
                    return (true, $"已通过 LoadLibraryW 加载 {moduleName}。");

                if (wait == NativeMethods.WAIT_TIMEOUT)
                    return (false, $"LoadLibraryW({moduleName}) 等待超时。");

                return (false, $"LoadLibraryW({moduleName}) 等待返回 0x{wait:X}。");
            }
            finally
            {
                if (hThread != 0)
                    NativeMethods.CloseHandle(hThread);

                TryFreeRemoteMemory(hProcess, remoteModuleName.Address);
            }
        }

        private static (nint Handle, uint ThreadId, string Error) StartRemoteThread(nint hProcess, nint startAddress, nint parameter)
        {
            var hThread = NativeMethods.CreateRemoteThread(hProcess, 0, 0, startAddress, parameter, 0, out var threadId);
            if (hThread == 0)
                return (0, 0, GetLastSystemError());

            return (hThread, threadId, "");
        }

        private static (nint Address, string Error) RemoteAllocAndWrite(nint hProcess, byte[] bytes, uint protection)
        {
            var remoteAddress = NativeMethods.VirtualAllocEx(
                hProcess,
                0,
                (nuint)bytes.Length,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                protection);

            if (remoteAddress == 0)
                return (0, GetLastSystemError());

            if (!NativeMethods.WriteProcessMemory(hProcess, remoteAddress, bytes, (nuint)bytes.Length, out var written) || written != (nuint)bytes.Length)
            {
                var error = GetLastSystemError();
                TryFreeRemoteMemory(hProcess, remoteAddress);
                return (0, error);
            }

            return (remoteAddress, "");
        }

        private static void TryFreeRemoteMemory(nint hProcess, nint remoteAddress)
        {
            if (remoteAddress == 0)
                return;

            NativeMethods.VirtualFreeEx(hProcess, remoteAddress, 0, NativeMethods.MEM_RELEASE);
        }

        private static bool IsThreadExited(nint hThread)
            => NativeMethods.GetExitCodeThread(hThread, out var exitCode) && exitCode != NativeMethods.STILL_ACTIVE;

        private static byte[] StructureToBytes<T>(T value)
            where T : struct
        {
            var size = Marshal.SizeOf<T>();
            var bytes = new byte[size];
            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                Marshal.Copy(buffer, bytes, 0, size);
                return bytes;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static List<int> GetProcessThreadIds(int processId, out string? error)
        {
            error = null;

            try
            {
                using var process = Process.GetProcessById(processId);
                return process.Threads.Cast<ProcessThread>().Select(static thread => thread.Id).ToList();
            }
            catch (Exception ex)
            {
                error = $"无法枚举线程: {ex.Message}";
                return [];
            }
        }

        private static bool WaitForProcessExit(int processId, int timeoutMilliseconds)
        {
            var stopwatch = Stopwatch.StartNew();

            do
            {
                if (HasProcessExited(processId))
                    return true;

                System.Threading.Thread.Sleep(100);
            }
            while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds);

            return HasProcessExited(processId);
        }

        private static bool HasProcessExited(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                return process.HasExited;
            }
            catch (ArgumentException)
            {
                return true;
            }
            catch (InvalidOperationException)
            {
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string GetLastSystemError()
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == 0)
                error = Marshal.GetLastWin32Error();

            return error == 0
                ? "未知错误"
                : $"{new Win32Exception(error).Message} (0x{error:X})";
        }

        private sealed class ProcessKillResult
        {
            private readonly List<ProcessKillAttempt> _attempts = [];

            public bool Success { get; set; }

            public void Add(string name, bool success, string message, bool skipped = false)
                => _attempts.Add(new ProcessKillAttempt(name, success, message, skipped));

            public string ToDisplayText()
                => string.Join("\n", _attempts.Select(static attempt => attempt.ToDisplayText()));
        }

        private sealed class ProcessKillAttempt(string name, bool success, string message, bool skipped)
        {
            public string ToDisplayText()
            {
                var status = skipped ? "跳过" : success ? "成功" : "失败";
                return $"{status}: {name} - {message}";
            }
        }
    }

    public sealed class ProcessInfoEx
    {
        public string Name { get; }
        public uint Id { get; }
        public uint SessionId { get; }
        public string Memory { get; }
        public string PrivateMemory { get; }
        public long MemoryBytes { get; }
        public uint ThreadCount { get; }
        public uint HandleCount { get; }
        public uint PriorityClass { get; }

        private uint _parentId;
        private bool _parentIdLoaded;
        private string _imagePath = "";
        private string _commandLine = "";
        private bool _isWow64;
        private bool _extendedLoaded;

        public uint ParentId => _parentId;
        public bool IsParentIdLoaded => _parentIdLoaded;
        public string ImagePath => _imagePath;
        public string CommandLine => _commandLine;
        public bool IsWow64 => _isWow64;

        public override string ToString() => $"{Name}   PID: {Id}   {Memory}";

        public ProcessInfoEx(Process process)
        {
            Name = process.ProcessName + ".exe";
            Id = (uint)process.Id;
            SessionId = (uint)process.SessionId;
            ThreadCount = (uint)process.Threads.Count;
            HandleCount = (uint)process.HandleCount;
            PriorityClass = (uint)process.BasePriority;

            try
            {
                MemoryBytes = process.WorkingSet64;
                Memory = FormatSize(MemoryBytes);
                PrivateMemory = FormatSize(process.PrivateMemorySize64);
            }
            catch
            {
                MemoryBytes = 0;
                Memory = "N/A";
                PrivateMemory = "N/A";
            }
        }

        public void LoadParentId()
        {
            if (_parentIdLoaded) return;
            _parentIdLoaded = true;

            var hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (int)Id);
            if (hProcess == 0)
                hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, (int)Id);

            if (hProcess != 0)
            {
                try
                {
                    _parentId = QueryParentProcessId(hProcess);
                }
                finally
                {
                    NativeMethods.CloseHandle(hProcess);
                }
            }
        }

        public async Task EnsureExtendedInfoLoadedAsync()
        {
            if (_extendedLoaded) return;
            _extendedLoaded = true;

            if (!_parentIdLoaded)
                LoadParentId();

            await Task.Run(() =>
            {
                var hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (int)Id);

                if (hProcess == 0)
                    hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, (int)Id);

                if (hProcess != 0)
                {
                    try
                    {
                        if (!_parentIdLoaded)
                            _parentId = QueryParentProcessId(hProcess);
                        _imagePath = QueryFullProcessImageName(hProcess);
                        _commandLine = QueryCommandLine(hProcess);
                        _isWow64 = QueryIsWow64(hProcess);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProcess);
                    }
                }
            });
        }

        private static uint QueryParentProcessId(nint hProcess)
        {
            try
            {
                var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
                int status = NativeMethods.NtQueryInformationProcess(hProcess, NativeMethods.ProcessBasicInformation, ref pbi, (uint)Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _);
                if (status == 0)
                    return (uint)(int)pbi.InheritedFromUniqueProcessId;
            }
            catch { }
            return 0;
        }

        private static string QueryFullProcessImageName(nint hProcess)
        {
            try
            {
                uint size = 1024;
                var builder = new StringBuilder((int)size);
                if (NativeMethods.QueryFullProcessImageNameW(hProcess, 0, builder, ref size))
                    return builder.ToString();
            }
            catch { }
            return "";
        }

        private static string QueryCommandLine(nint hProcess)
        {
            try
            {
                nint commandLineInfo = 0;
                int status = NativeMethods.NtQueryInformationProcess(hProcess, NativeMethods.ProcessCommandLineInformation, ref commandLineInfo, (uint)IntPtr.Size, out var returnLength);

                if (status != 0 || commandLineInfo == 0)
                    return "";

                var buffer = new byte[returnLength];
                if (NativeMethods.ReadProcessMemory(hProcess, commandLineInfo, buffer, buffer.Length, out int bytesRead))
                {
                    int length = BitConverter.ToUInt16(buffer, 0);
                    nint stringBuffer = IntPtr.Size == 8
                        ? unchecked((nint)BitConverter.ToInt64(buffer, 8))
                        : BitConverter.ToInt32(buffer, 4);

                    var stringBytes = new byte[length];
                    if (NativeMethods.ReadProcessMemory(hProcess, stringBuffer, stringBytes, length, out bytesRead))
                        return Encoding.Unicode.GetString(stringBytes);
                }
            }
            catch { }
            return "";
        }

        private static bool QueryIsWow64(nint hProcess)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;
            try
            {
                return NativeMethods.IsWow64Process(hProcess, out bool isWow64) && isWow64;
            }
            catch { }
            return false;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes >= 1073741824)
                return $"{bytes / 1073741824.0:F2} GB";
            if (bytes >= 1048576)
                return $"{bytes / 1048576.0:F2} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024.0:F2} KB";
            return $"{bytes} B";
        }

    }
}
