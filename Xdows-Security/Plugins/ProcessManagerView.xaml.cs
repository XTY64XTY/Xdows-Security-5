using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Protection;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;

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
        private bool _isDriverMode;
        private bool _suppressDriverModeToggle;
        private int _refreshGeneration;

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
            int refreshGeneration = Interlocked.Increment(ref _refreshGeneration);
            bool useDriverMode = _isDriverMode;
            LoadingPanel.Visibility = Visibility.Visible;
            ProcessList.Visibility = Visibility.Collapsed;
            ProcessTree.Visibility = Visibility.Collapsed;

            try
            {
                var list = await Task.Run(() => useDriverMode
                    ? ProtectionStatus.GetDriverProcesses()
                        .Select(process => new ProcessInfoEx(process))
                        .OrderBy(process => process.Name)
                        .ToList()
                    : GetUserModeProcessSnapshot());

                if (refreshGeneration != Volatile.Read(ref _refreshGeneration))
                    return;

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
                if (refreshGeneration != Volatile.Read(ref _refreshGeneration))
                    return;

                if (useDriverMode && !ProtectionStatus.IsRun(5))
                {
                    _isDriverMode = false;
                    SetDriverModeToggleSilently(false);
                }

                await ShowDialogAsync(
                    Localize("ProcessManager_RefreshFailed_Title"),
                    FormatLocalized("ProcessManager_RefreshFailed_Text", ex.Message));
            }
            finally
            {
                if (refreshGeneration == Volatile.Read(ref _refreshGeneration))
                {
                    LoadingPanel.Visibility = Visibility.Collapsed;
                    if (IsTreeView)
                        ProcessTree.Visibility = Visibility.Visible;
                    else
                        ProcessList.Visibility = Visibility.Visible;
                }
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
                    await ShowDialogAsync(Localize("ProcessManager_SwitchFailed_Title"), FormatLocalized("ProcessManager_TreeLoadFailed_Text", ex.Message));
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

        private async void DriverModeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (_suppressDriverModeToggle)
                return;

            if (!DriverModeToggle.IsOn)
            {
                _isDriverMode = false;
                await RefreshProcesses();
                return;
            }

            if (!ProtectionStatus.IsRun(5))
            {
                SetDriverModeToggleSilently(false);
                await ShowDialogAsync(
                    Localize("ProcessManager_DriverMode_RequiresProtection_Title"),
                    Localize("ProcessManager_DriverMode_RequiresProtection_Text"));
                return;
            }

            if (!await ShowDriverModeDisclaimerAsync())
            {
                SetDriverModeToggleSilently(false);
                return;
            }

            _isDriverMode = true;
            await RefreshProcesses();
        }

        private async Task<bool> ShowDriverModeDisclaimerAsync()
        {
            ContentDialogResult result = await new ContentDialog
            {
                Title = Localize("ProcessManager_DriverMode_Disclaimer_Title"),
                Content = new TextBlock
                {
                    Text = Localize("ProcessManager_DriverMode_Disclaimer_Text"),
                    TextWrapping = TextWrapping.Wrap
                },
                PrimaryButtonText = Localize("Button_Confirm"),
                CloseButtonText = Localize("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            }.ShowAsync();

            return result == ContentDialogResult.Primary;
        }

        private void SetDriverModeToggleSilently(bool isOn)
        {
            _suppressDriverModeToggle = true;
            DriverModeToggle.IsOn = isOn;
            _suppressDriverModeToggle = false;
        }

        private static List<ProcessInfoEx> GetUserModeProcessSnapshot()
        {
            Process[] processes = Process.GetProcesses();
            try
            {
                return processes
                    .Select(process => new ProcessInfoEx(process))
                    .OrderBy(process => process.Name)
                    .ToList();
            }
            finally
            {
                foreach (Process process in processes)
                    process.Dispose();
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
                Title = FormatLocalized("ProcessManager_Terminate_Confirm_Title", info.Name, info.Id),
                Content = Localize("ProcessManager_Terminate_Confirm_Text"),
                PrimaryButtonText = Localize("ProcessManager_Terminate_Button"),
                CloseButtonText = Localize("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

            if (_isDriverMode)
            {
                try
                {
                    await Task.Run(() => ProtectionStatus.OperateDriverProcess(info.Id, DriverProcessOperation.Terminate));
                    await ShowDialogAsync(
                        Localize("ProcessManager_Terminate_Success_Title"),
                        FormatLocalized("ProcessManager_Terminate_Success_Text", info.Name));
                }
                catch (Exception ex)
                {
                    await ShowDialogAsync(
                        Localize("ProcessManager_Terminate_Failed_Title"),
                        FormatLocalized("ProcessManager_Operation_Failed_Text", info.Name, ex.Message));
                }

                await RefreshProcesses();
                return;
            }

            var result = await Task.Run(() => KillProcessWithFallbacks((int)info.Id));

            if (result.Success)
                await ShowDialogAsync(Localize("ProcessManager_Kill_Success_Title"), FormatLocalized("ProcessManager_Kill_Success_Text", info.Name, result.ToDisplayText()));
            else
                await ShowDialogAsync(Localize("ProcessManager_Kill_Failed_Title"), FormatLocalized("ProcessManager_Kill_Failed_Text", info.Name, result.ToDisplayText()));

            await RefreshProcesses();
        }

        private async void Suspend_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;
            bool useDriverMode = _isDriverMode;

            var (success, error) = await Task.Run(() =>
            {
                try
                {
                    if (useDriverMode)
                        ProtectionStatus.OperateDriverProcess(info.Id, DriverProcessOperation.Suspend);
                    else
                        SuspendProcess((int)info.Id);
                    return (true, "");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });

            if (success)
                await ShowDialogAsync(
                    Localize("ProcessManager_Suspend_Success_Title"),
                    FormatLocalized("ProcessManager_Suspend_Success_Text", info.Name));
            else
                await ShowDialogAsync(
                    Localize("ProcessManager_Suspend_Failed_Title"),
                    FormatLocalized("ProcessManager_Operation_Failed_Text", info.Name, error));
        }

        private async void Resume_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;
            bool useDriverMode = _isDriverMode;

            var (success, error) = await Task.Run(() =>
            {
                try
                {
                    if (useDriverMode)
                        ProtectionStatus.OperateDriverProcess(info.Id, DriverProcessOperation.Resume);
                    else
                        ResumeProcess((int)info.Id);
                    return (true, "");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });

            if (success)
                await ShowDialogAsync(
                    Localize("ProcessManager_Resume_Success_Title"),
                    FormatLocalized("ProcessManager_Resume_Success_Text", info.Name));
            else
                await ShowDialogAsync(
                    Localize("ProcessManager_Resume_Failed_Title"),
                    FormatLocalized("ProcessManager_Operation_Failed_Text", info.Name, error));
        }

        private async void ShowProcessDetail_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            await info.EnsureExtendedInfoLoadedAsync();

            var items = new List<(string Key, string Value)>
            {
                (Localize("ProcessManager_Details_ProcessName"), info.Name),
                (Localize("ProcessManager_Details_ProcessId"), info.Id.ToString()),
                (Localize("ProcessManager_Details_ParentId"), info.ParentId.ToString()),
                (Localize("ProcessManager_Details_SessionId"), info.SessionId.ToString()),
                (Localize("ProcessManager_Details_MemoryUsage"), info.Memory),
                (Localize("ProcessManager_Details_PrivateMemory"), info.PrivateMemory),
                (Localize("ProcessManager_Details_ThreadCount"), info.ThreadCount.ToString()),
                (Localize("ProcessManager_Details_HandleCount"), info.HandleCount.ToString()),
                (Localize("ProcessManager_Details_Priority"), info.PriorityClass.ToString()),
                (Localize("ProcessManager_Details_Architecture"), info.IsWow64 ? Localize("ProcessManager_Details_ArchWow64") : Localize("ProcessManager_Details_ArchX64"))
            };

            if (!string.IsNullOrEmpty(info.ImagePath))
            {
                items.Add((Localize("ProcessManager_Details_FilePath"), info.ImagePath));

                try
                {
                    var fi = new FileInfo(info.ImagePath);
                    if (fi.Exists)
                    {
                        items.Add((Localize("ProcessManager_Details_CreationTime"), fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")));
                        items.Add((Localize("ProcessManager_Details_ModifyTime"), fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")));
                        items.Add((Localize("ProcessManager_Details_FileSize"), $"{fi.Length / 1024.0 / 1024.0:F2} MB"));

                        var versionInfo = FileVersionInfo.GetVersionInfo(fi.FullName);
                        items.Add((Localize("ProcessManager_Details_FileVersion"), versionInfo.FileVersion ?? "-"));
                        items.Add((Localize("ProcessManager_Details_ProductVersion"), versionInfo.ProductVersion ?? "-"));
                        items.Add((Localize("ProcessManager_Details_CompanyName"), versionInfo.CompanyName ?? "-"));
                        items.Add((Localize("ProcessManager_Details_ProductName"), versionInfo.ProductName ?? "-"));
                        items.Add((Localize("ProcessManager_Details_FileDescription"), versionInfo.FileDescription ?? "-"));
                    }
                }
                catch { }
            }
            else
            {
                items.Add((Localize("ProcessManager_Details_FilePath"), Localize("ProcessManager_Details_AccessDenied")));
            }

            if (!string.IsNullOrEmpty(info.CommandLine))
                items.Add((Localize("ProcessManager_Details_CommandLine"), info.CommandLine));

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
                Title = Localize("ProcessManager_Details_Title"),
                Content = listView,
                CloseButtonText = Localize("ProcessManager_Close"),
                XamlRoot = this.XamlRoot,
                PrimaryButtonText = Localize("ProcessManager_LocateFile"),
                SecondaryButtonText = Localize("ProcessManager_KillProcess"),
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            };

            var result = await dialog.ShowAsync();

            if (result == ContentDialogResult.Primary)
            {
                if (string.IsNullOrEmpty(info.ImagePath))
                {
                    await ShowDialogAsync(Localize("ProcessManager_LocateFileFailed_Title"), Localize("ProcessManager_LocateFileFailed_NoPath"));
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
                        await ShowDialogAsync(Localize("ProcessManager_LocateFileFailed_Title"), FormatLocalized("ProcessManager_LocateFileFailed_Text", ex.Message));
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
                CloseButtonText = Localize("ProcessManager_OK"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            }.ShowAsync();
        }

        private ElementTheme GetDialogTheme()
            => (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default;

        private static string Localize(string key)
        {
            string value = Localizer.Get().GetLocalizedString(key);
            return string.IsNullOrWhiteSpace(value) ? key : value;
        }

        private static string FormatLocalized(string key, params object[] args)
            => string.Format(CultureInfo.CurrentCulture, Localize(key), args);

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
                result.Add(Localize("ProcessManager_Attempt_ProtectSelf"), false, Localize("ProcessManager_Attempt_ProtectSelf_Message"));
                return result;
            }

            if (HasProcessExited(processId))
            {
                result.Success = true;
                result.Add(Localize("ProcessManager_Attempt_CheckStatus"), true, Localize("ProcessManager_Attempt_CheckStatus_Message"));
                return result;
            }

            AddAttempt(result, Localize("ProcessManager_Attempt_EnableSeDebugPrivilege"), TryEnableDebugPrivilege);

            AddAttempt(result, Localize("ProcessManager_Attempt_RestartManager"), () => TryRestartManagerShutdown(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_StopService"), () => TryStopServiceProcess(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_ConsoleCtrlEvent"), () => TryConsoleCtrlEvent(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_TerminateDirectly"), () => TryTerminateDirectly(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_NtTerminateProcess"), () => TryNtTerminateProcess(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_TerminateThreads"), () => TryTerminateThreads(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_DebugExceptionKill"), () => TryDebugExceptionKill(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_DebugKillOnExit"), () => TryDebugKillOnExit(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_RemoteExitRoutines"), () => TryRemoteExitRoutines(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_HijackThreadContext"), () => TryHijackThreadContextToExit(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_RemoteFatalExit"), () => TryCrashWithRemoteFatalExit(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_EndTask"), () => TryEndTaskForProcess(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_InjectMessageBoxEndTask"), () => TryInjectMessageBoxThenEndTask(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_ApcExitRoutines"), () => TryApcExitRoutines(processId));
            if (CompleteIfExited(result, processId)) return result;

            AddAttempt(result, Localize("ProcessManager_Attempt_ApcGarbage"), () => TryCrashWithApcGarbage(processId));
            if (CompleteIfExited(result, processId)) return result;

            if (HasProcessExited(processId))
            {
                result.Success = true;
                result.Add(Localize("ProcessManager_Attempt_ExitConfirmed"), true, Localize("ProcessManager_Attempt_ExitConfirmed_Message"));
            }
            else
            {
                result.Add(Localize("ProcessManager_Attempt_FinalStatus"), false, Localize("ProcessManager_Attempt_FinalStatus_Message"));
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
            result.Add(Localize("ProcessManager_Attempt_ExitConfirmed"), true, Localize("ProcessManager_Attempt_ExitConfirmed_Message"));
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
                    return (true, Localize("ProcessManager_ProcessKill_Succeeded"));

                messages.Add(Localize("ProcessManager_ProcessKill_Timeout"));
            }
            catch (Exception ex)
            {
                messages.Add(FormatLocalized("ProcessManager_ProcessKill_Failed", ex.Message));
            }

            var native = TryTerminateProcessNative(processId);
            if (native.Success)
            {
                if (messages.Count == 0)
                    return native;

                return (true, $"{native.Message}；{string.Join("；", messages)}");
            }

            messages.Add(FormatLocalized("ProcessManager_TerminateProcess_Failed", native.Message));
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
                    return (true, Localize("ProcessManager_TerminateProcess_Succeeded"));

                if (NativeMethods.GetExitCodeProcess(hProcess, out var exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
                    return (true, FormatLocalized("ProcessManager_TerminateProcess_Succeeded_ExitCode", exitCode));

                if (wait == NativeMethods.WAIT_TIMEOUT)
                    return (false, Localize("ProcessManager_TerminateProcess_WaitTimeout"));

                return (false, FormatLocalized("ProcessManager_TerminateProcess_WaitReturn", wait));
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
                return (false, FormatLocalized("ProcessManager_EnumerateThreads_Failed", ex.Message));
            }

            if (threadIds.Count == 0)
                return (false, Localize("ProcessManager_NoEnumerableThreads"));

            var terminated = 0;
            var failed = 0;
            string? firstError = null;

            foreach (var threadId in threadIds)
            {
                var hThread = NativeMethods.OpenThread(NativeMethods.THREAD_TERMINATE, false, (uint)threadId);
                if (hThread == 0)
                {
                    failed++;
                    firstError ??= FormatLocalized("ProcessManager_Thread_Error", threadId, GetLastSystemError());
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
                        firstError ??= FormatLocalized("ProcessManager_Thread_Error", threadId, GetLastSystemError());
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }

            if (terminated == 0)
                return (false, FormatLocalized("ProcessManager_TerminateThreads_None", firstError ?? Localize("ProcessManager_NoDetailError")));

            if (WaitForProcessExit(processId, 3000))
                return (true, FormatLocalized("ProcessManager_TerminateThreads_Success", terminated, threadIds.Count));

            var message = FormatLocalized("ProcessManager_TerminateThreads_Partial", terminated, threadIds.Count);
            if (failed > 0)
                message += FormatLocalized("ProcessManager_TerminateThreads_FailedDetail", failed, firstError ?? string.Empty);

            return (false, message);
        }

        private static (bool Success, string Message) TryDebugExceptionKill(int processId)
        {
            if (!NativeMethods.DebugActiveProcess(processId))
                return (false, FormatLocalized("ProcessManager_DebugAttach_Failed", GetLastSystemError()));

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
                            return (true, Localize("ProcessManager_Debug_TakeoverExited"));

                        continue;
                    }

                    if (debugEvent.dwDebugEventCode == NativeMethods.EXIT_PROCESS_DEBUG_EVENT)
                    {
                        attached = false;
                        NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_CONTINUE);
                        return (true, Localize("ProcessManager_Debug_EventExited"));
                    }

                    if (debugEvent.dwDebugEventCode == NativeMethods.EXCEPTION_DEBUG_EVENT)
                    {
                        sawException = true;
                        NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_EXCEPTION_NOT_HANDLED);

                        if (WaitForProcessExit(processId, 2000))
                        {
                            attached = false;
                            var exceptionText = debugEvent.u.ExceptionCode == NativeMethods.EXCEPTION_BREAKPOINT
                                ? Localize("ProcessManager_Exception_Breakpoint")
                                : FormatLocalized("ProcessManager_Exception_Code", debugEvent.u.ExceptionCode);
                            return (true, FormatLocalized("ProcessManager_Debug_PassedExceptionExited", exceptionText));
                        }

                        continue;
                    }

                    NativeMethods.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NativeMethods.DBG_CONTINUE);
                }

                var message = breakRequested
                    ? Localize("ProcessManager_Debug_BreakNoExit")
                    : FormatLocalized("ProcessManager_Debug_BreakFailed", breakError ?? Localize("ProcessManager_UnknownError"));

                if (sawException)
                    message += Localize("ProcessManager_Debug_ExceptionObserved");

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
                    return (false, FormatLocalized("ProcessManager_RemoteThread_FatalExit_Failed", threadError));

                try
                {
                    NativeMethods.WaitForSingleObject(hThread, 3000);
                    if (WaitForProcessExit(processId, 3000))
                        return (true, FormatLocalized("ProcessManager_FatalExit_ThreadExited", threadId));

                    var exitText = NativeMethods.GetExitCodeThread(hThread, out var exitCode)
                        ? FormatLocalized("ProcessManager_RemoteThread_ExitCode", exitCode)
                        : FormatLocalized("ProcessManager_RemoteThread_ExitCodeReadFailed", GetLastSystemError());

                    return (false, FormatLocalized("ProcessManager_FatalExit_StillRunning", exitText));
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
                return (false, Localize("ProcessManager_EndTask_NoWindows"));

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
                return (true, FormatLocalized("ProcessManager_EndTask_Success", successCount, windows.Count));

            if (successCount > 0)
                return (false, FormatLocalized("ProcessManager_EndTask_Partial", successCount, windows.Count));

            return (false, FormatLocalized("ProcessManager_EndTask_NoSuccess", firstError ?? Localize("ProcessManager_NoDetailError")));
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

                var text = Encoding.Unicode.GetBytes(FormatLocalized("ProcessManager_Mbox_Text") + "\0");
                var caption = Encoding.Unicode.GetBytes("Xdows Security\0");

                var textRemote = RemoteAllocAndWrite(hProcess, text, NativeMethods.PAGE_READWRITE);
                if (textRemote.Address == 0)
                    return (false, FormatLocalized("ProcessManager_WriteRemote_TextFailed", textRemote.Error));
                remoteAllocations.Add(textRemote.Address);

                var captionRemote = RemoteAllocAndWrite(hProcess, caption, NativeMethods.PAGE_READWRITE);
                if (captionRemote.Address == 0)
                    return (false, FormatLocalized("ProcessManager_WriteRemote_CaptionFailed", captionRemote.Error));
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
                    return (false, FormatLocalized("ProcessManager_WriteRemote_ParamsFailed", parameterRemote.Error));
                remoteAllocations.Add(parameterRemote.Address);

                var thread = StartRemoteThread(hProcess, messageBoxIndirect, parameterRemote.Address);
                if (thread.Handle == 0)
                    return (false, FormatLocalized("ProcessManager_RemoteThread_MsgBox_Failed", thread.Error));

                hThread = thread.Handle;
                NativeMethods.WaitForSingleObject(hThread, 750);

                var endTaskResult = TryEndTaskForProcess(processId);
                if (WaitForProcessExit(processId, 3000))
                    return (true, FormatLocalized("ProcessManager_MsgBox_EndTask_Success", thread.ThreadId, endTaskResult.Message));

                return (false, FormatLocalized("ProcessManager_MsgBox_EndTask_StillRunning", thread.ThreadId, endTaskResult.Message));
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
                return (false, threadError ?? Localize("ProcessManager_NoEnumerableThreads"));

            nint hProcess = OpenProcessForRemoteExecution(processId, out var openError);
            if (hProcess == 0)
                return (false, openError);

            nint remoteGarbage = 0;

            try
            {
                var garbage = Encoding.ASCII.GetBytes("Xdows_APC_GARBAGE_TARGET_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789");
                var allocation = RemoteAllocAndWrite(hProcess, garbage, NativeMethods.PAGE_READWRITE);
                if (allocation.Address == 0)
                    return (false, FormatLocalized("ProcessManager_WriteRemote_GarbageFailed", allocation.Error));

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
                        firstError ??= FormatLocalized("ProcessManager_Thread_Error", threadId, GetLastSystemError());
                        continue;
                    }

                    try
                    {
                        if (NativeMethods.QueueUserAPC(remoteGarbage, hThread, 0) == 0)
                        {
                            failed++;
                            firstError ??= FormatLocalized("ProcessManager_Apc_QueueFailed", threadId, GetLastSystemError());
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
                    return (true, FormatLocalized("ProcessManager_ApcGarbage_Success", queued, threadIds.Count, alerted));

                return (false, FormatLocalized("ProcessManager_ApcGarbage_StillRunning", queued, threadIds.Count, alerted, failed, firstError ?? ""));
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
                reason = FormatLocalized("ProcessManager_QueryArch_Failed", GetLastSystemError());
                return false;
            }

            try
            {
                if (!NativeMethods.IsWow64Process(hProcess, out var targetIsWow64))
                {
                    reason = FormatLocalized("ProcessManager_IsWow64_Failed", GetLastSystemError());
                    return false;
                }

                if (Environment.Is64BitProcess && targetIsWow64)
                {
                    reason = Localize("ProcessManager_Incompatible_Wow64Target");
                    return false;
                }

                if (!Environment.Is64BitProcess && !targetIsWow64)
                {
                    reason = Localize("ProcessManager_Incompatible_X64Target");
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
                error = FormatLocalized("ProcessManager_LoadModule_Failed", moduleName, GetLastSystemError());
                return 0;
            }

            var proc = NativeMethods.GetProcAddress(module, procName);
            if (proc == 0)
            {
                error = FormatLocalized("ProcessManager_ResolveProc_Failed", moduleName, procName, GetLastSystemError());
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
                return (false, FormatLocalized("ProcessManager_WriteRemote_ModuleNameFailed", remoteModuleName.Error));

            nint hThread = 0;

            try
            {
                var thread = StartRemoteThread(hProcess, loadLibrary, remoteModuleName.Address);
                if (thread.Handle == 0)
                    return (false, FormatLocalized("ProcessManager_RemoteThread_LoadLibrary_Failed", thread.Error));

                hThread = thread.Handle;
                var wait = NativeMethods.WaitForSingleObject(hThread, 5000);

                if (wait == NativeMethods.WAIT_OBJECT_0)
                    return (true, FormatLocalized("ProcessManager_LoadLibrary_Loaded", moduleName));

                if (wait == NativeMethods.WAIT_TIMEOUT)
                    return (false, FormatLocalized("ProcessManager_LoadLibrary_Timeout", moduleName));

                return (false, FormatLocalized("ProcessManager_LoadLibrary_WaitReturn", moduleName, wait));
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
                error = FormatLocalized("ProcessManager_EnumerateThreads_Failed", ex.Message);
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
                ? Localize("ProcessManager_UnknownError")
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
                var status = skipped ? Localize("ProcessManager_Result_Skipped") : success ? Localize("ProcessManager_Result_Success") : Localize("ProcessManager_Result_Failed");
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

        public ProcessInfoEx(DriverProcessInfo process)
        {
            Name = string.IsNullOrWhiteSpace(process.Name)
                ? $"PID {process.ProcessId}"
                : process.Name;
            Id = process.ProcessId;
            SessionId = process.SessionId;
            ThreadCount = process.ThreadCount;
            HandleCount = process.HandleCount;
            PriorityClass = process.BasePriority;
            MemoryBytes = process.WorkingSetBytes > long.MaxValue
                ? long.MaxValue
                : (long)process.WorkingSetBytes;
            Memory = FormatSize(MemoryBytes);
            PrivateMemory = FormatSize(process.PrivateBytes > long.MaxValue
                ? long.MaxValue
                : (long)process.PrivateBytes);
            _parentId = process.ParentProcessId;
            _parentIdLoaded = true;
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
