using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Composition;
using System;
using System.Collections.Generic;
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
        public static partial bool CloseHandle(nint hHandle);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial nint OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int processId);

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

        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
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

            var (success, error) = await Task.Run(() =>
            {
                try
                {
                    using var process = Process.GetProcessById((int)info.Id);
                    process.Kill();
                    process.WaitForExit(5000);
                    return (true, "");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });

            if (success)
                await ShowDialogAsync("结束成功", $"进程 {info.Name} 已成功结束。");
            else
                await ShowDialogAsync("结束失败", $"不能结束这个进程，因为 {error}。");

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
