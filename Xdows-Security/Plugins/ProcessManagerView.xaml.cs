using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class ProcessManagerView : UserControl
    {
        private List<ProcessInfoEx> _allProcesses = [];

        public ProcessManagerView()
        {
            this.InitializeComponent();
            SortCombo.SelectedIndex = 0;
            _ = RefreshProcesses();
        }

        private async Task RefreshProcesses()
        {
            try
            {
                var list = await Task.Run(() =>
                {
                    var processes = Process.GetProcesses()
                        .Select(p => new ProcessInfoEx(p))
                        .OrderBy(p => p.Name)
                        .ToList();
                    return processes;
                });

                _allProcesses = list;
                ApplyFilterAndSort();
            }
            catch (Exception ex)
            {
                var dialog = new ContentDialog
                {
                    Title = "刷新失败",
                    Content = ex.Message,
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                };

                await dialog.ShowAsync();
            }
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e)
        {
            await RefreshProcesses();
        }

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyFilterAndSort();

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
            => ApplyFilterAndSort();

        private void ApplyFilterAndSort()
        {
            var keyword = SearchBox.Text?.Trim() ?? "";
            IEnumerable<ProcessInfoEx> filtered = _allProcesses;

            if (!string.IsNullOrEmpty(keyword))
            {
                if (uint.TryParse(keyword, out var pid))
                {
                    filtered = _allProcesses.Where(p => p.Id == pid);
                }
                else
                {
                    filtered = _allProcesses
                        .Where(p => p.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase));
                }
            }

            ProcessList.ItemsSource = ApplySort(filtered).ToList();
        }

        private async void ShowProcessDetail_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var sp = new StackPanel { Spacing = 8 };
            void AddLine(string key, string value)
            {
                sp.Children.Add(new TextBlock
                {
                    Text = $"{key}: {value}",
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap
                });
            }

            AddLine("进程名称", info.Name);
            AddLine("进程编号", info.Id.ToString());
            AddLine("父进程ID", info.ParentId.ToString());
            AddLine("会话ID", info.SessionId.ToString());
            AddLine("使用内存", info.Memory);
            AddLine("私有内存", info.PrivateMemory);
            AddLine("线程数", info.ThreadCount.ToString());
            AddLine("句柄数", info.HandleCount.ToString());
            AddLine("优先级", info.PriorityClass.ToString());
            AddLine("架构", info.IsWow64 ? "32位 (WOW64)" : "64位");

            if (!string.IsNullOrEmpty(info.ImagePath))
            {
                AddLine("文件路径", info.ImagePath);

                try
                {
                    var fi = new FileInfo(info.ImagePath);
                    if (fi.Exists)
                    {
                        AddLine("创建时间", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"));
                        AddLine("修改时间", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                        AddLine("文件大小", $"{fi.Length / 1024.0 / 1024.0:F2} MB");

                        var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(fi.FullName);
                        AddLine("文件版本", versionInfo.FileVersion ?? "-");
                        AddLine("产品版本", versionInfo.ProductVersion ?? "-");
                        AddLine("公司名称", versionInfo.CompanyName ?? "-");
                        AddLine("产品名称", versionInfo.ProductName ?? "-");
                        AddLine("文件描述", versionInfo.FileDescription ?? "-");
                    }
                }
                catch { }
            }
            else
            {
                AddLine("文件路径", "拒绝访问或已退出");
            }

            if (!string.IsNullOrEmpty(info.CommandLine))
            {
                AddLine("命令行", info.CommandLine);
            }

            var dialog = new ContentDialog
            {
                Title = "详细信息",
                Content = new ScrollViewer
                {
                    Content = sp,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                },
                CloseButtonText = "关闭",
                XamlRoot = this.XamlRoot,
                PrimaryButtonText = "定位文件",
                SecondaryButtonText = "结束进程",
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Close
            };

            var result = await dialog.ShowAsync();

            if (result == ContentDialogResult.Primary)
            {
                if (string.IsNullOrEmpty(info.ImagePath))
                {
                    await new ContentDialog
                    {
                        Title = "无法定位文件",
                        Content = "无法访问此进程的文件路径。",
                        CloseButtonText = "确定",
                        RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        XamlRoot = this.XamlRoot,
                        DefaultButton = ContentDialogButton.Close
                    }.ShowAsync();
                }
                else
                {
                    try
                    {
                        var safeFilePath = info.ImagePath.Replace("\"", "\\\"");
                        var psi = new ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"/select,\"{safeFilePath}\"",
                            UseShellExecute = true
                        };
                        Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        await new ContentDialog
                        {
                            Title = "无法定位文件",
                            Content = $"无法定位文件，因为{ex.Message}",
                            CloseButtonText = "确定",
                            RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            XamlRoot = this.XamlRoot,
                            DefaultButton = ContentDialogButton.Close
                        }.ShowAsync();
                    }
                }
            }
            else if (result == ContentDialogResult.Secondary)
            {
                await KillProcessAsync(info);
            }
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

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;
            await KillProcessAsync(info);
        }

        private ProcessInfoEx? GetProcessInfoFromSender(object sender)
        {
            if (sender is MenuFlyoutItem menuItem)
            {
                return menuItem.DataContext as ProcessInfoEx;
            }
            return ProcessList.SelectedItem as ProcessInfoEx;
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
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

            var result = await Task.Run(() => TryKill(info.Id));

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "结束成功",
                    Content = $"进程 {info.Name} 已成功结束。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot,
                    DefaultButton = ContentDialogButton.Close
                }.ShowAsync();
            }
            else
            {
                await new ContentDialog
                {
                    Title = "结束失败",
                    Content = $"不能结束这个进程，因为 {result.Error}。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot,
                    DefaultButton = ContentDialogButton.Close
                }.ShowAsync();
            }

            await RefreshProcesses();
        }

        private KillResult TryKill(uint pid)
        {
            try
            {
                var process = Process.GetProcessById((int)pid);
                process.Kill();
                process.WaitForExit(5000);
                return new KillResult { Success = true };
            }
            catch (Exception ex)
            {
                return new KillResult { Success = false, Error = ex.Message };
            }
        }

        private async void Suspend_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var result = await Task.Run(() =>
            {
                try
                {
                    SuspendProcess((int)info.Id);
                    return (Success: true, Error: "");
                }
                catch (Exception ex)
                {
                    return (Success: false, Error: ex.Message);
                }
            });

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "挂起成功",
                    Content = $"进程 {info.Name} 已挂起。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
            else
            {
                await new ContentDialog
                {
                    Title = "挂起失败",
                    Content = $"无法挂起进程: {result.Error}",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
        }

        private async void Resume_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var result = await Task.Run(() =>
            {
                try
                {
                    ResumeProcess((int)info.Id);
                    return (Success: true, Error: "");
                }
                catch (Exception ex)
                {
                    return (Success: false, Error: ex.Message);
                }
            });

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "恢复成功",
                    Content = $"进程 {info.Name} 已恢复。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
            else
            {
                await new ContentDialog
                {
                    Title = "恢复失败",
                    Content = $"无法恢复进程: {result.Error}",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
        }

        private record KillResult
        {
            public bool Success { get; init; }
            public string Error { get; init; } = "";
        }

        // P/Invoke for suspending and resuming processes
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const int ProcessBasicInformation = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public static void SuspendProcess(int processId)
        {
            var process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads)
            {
                var hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (hThread != IntPtr.Zero)
                {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        }

        public static void ResumeProcess(int processId)
        {
            var process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads)
            {
                var hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (hThread != IntPtr.Zero)
                {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        }

        public static uint GetParentProcessId(int processId)
        {
            var pbi = new PROCESS_BASIC_INFORMATION();
            uint returnLength;
            var process = Process.GetProcessById(processId);
            int status = NtQueryInformationProcess(process.Handle, ProcessBasicInformation, ref pbi, (uint)Marshal.SizeOf(pbi), out returnLength);
            if (status != 0)
                throw new Win32Exception(status);
            return (uint)pbi.InheritedFromUniqueProcessId.ToInt32();
        }
    }

    public sealed class ProcessInfoEx
    {
        public string Name { get; }
        public uint Id { get; }
        public uint ParentId { get; }
        public uint SessionId { get; }
        public string Memory { get; }
        public string PrivateMemory { get; }
        public long MemoryBytes { get; }
        public uint ThreadCount { get; }
        public uint HandleCount { get; }
        public uint PriorityClass { get; }
        public bool IsWow64 { get; }
        public string ImagePath { get; }
        public string CommandLine { get; }

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
                ParentId = ProcessManagerView.GetParentProcessId(process.Id);
            }
            catch
            {
                ParentId = 0;
            }

            try
            {
                ImagePath = process.MainModule?.FileName ?? "";
            }
            catch
            {
                ImagePath = "";
            }

            try
            {
                CommandLine = GetCommandLine(process.Id);
            }
            catch
            {
                CommandLine = "";
            }

            try
            {
                IsWow64 = IsWow64Process(process.Handle);
            }
            catch
            {
                IsWow64 = false;
            }

            try
            {
                MemoryBytes = process.WorkingSet64;
                Memory = $"{MemoryBytes / 1024 / 1024} MB";
                PrivateMemory = $"{process.PrivateMemorySize64 / 1024 / 1024} MB";
            }
            catch
            {
                MemoryBytes = 0;
                Memory = "N/A";
                PrivateMemory = "N/A";
            }
        }

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        private static bool IsWow64Process(IntPtr hProcess)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;
            bool isWow64;
            return IsWow64Process(hProcess, out isWow64) && isWow64;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref IntPtr processInformation, uint processInformationLength, out uint returnLength);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const int ProcessCommandLineInformation = 60;

        private static string GetCommandLine(int processId)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
                if (processHandle == IntPtr.Zero)
                    return "";

                try
                {
                    IntPtr commandLineInfo = IntPtr.Zero;
                    uint returnLength;
                    int status = NtQueryInformationProcess(processHandle, ProcessCommandLineInformation, ref commandLineInfo, (uint)IntPtr.Size, out returnLength);
                    
                    if (status != 0 || commandLineInfo == IntPtr.Zero)
                        return "";

                    // Read UNICODE_STRING structure
                    var buffer = new byte[returnLength];
                    if (ReadProcessMemory(processHandle, commandLineInfo, buffer, buffer.Length, out int bytesRead))
                    {
                        // UNICODE_STRING: Length(2), MaximumLength(2), Buffer(4/8)
                        int length = BitConverter.ToUInt16(buffer, 0);
                        IntPtr stringBuffer = IntPtr.Size == 8 
                            ? (IntPtr)BitConverter.ToInt64(buffer, 8) 
                            : (IntPtr)BitConverter.ToInt32(buffer, 4);
                        
                        var stringBytes = new byte[length];
                        if (ReadProcessMemory(processHandle, stringBuffer, stringBytes, length, out bytesRead))
                        {
                            return System.Text.Encoding.Unicode.GetString(stringBytes);
                        }
                    }
                    return "";
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch
            {
                return "";
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);
    }
}
