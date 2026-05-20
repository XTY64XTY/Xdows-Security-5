# USB 可移动设备自动扫描 — 实现提示词

## 项目上下文

- **项目**：Xdows Security 5，WinUI 3 + C# 杀毒软件
- **目标框架**：`net10.0-windows10.0.26100.0`，最低 `10.0.17763.0`
- **UI 框架**：WinUI 3 (Windows App SDK 2.0.1)，WinUIEx 2.9.0
- **本地化**：WinUI3Localizer，三语言 en-US / zh-HANS / zh-HANT
- **设置存储**：`Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings`
- **日志系统**：`LogText.AddNewLog(LogLevel, tag, message)` + `LogService`
- **代码风格**：无注释，遵循现有代码约定

## 功能规格

### 交互流程

```
USB 设备插入
  → WM_DEVICECHANGE + DBT_DEVICEARRIVAL (MainWindow SubclassProc)
    → 解析 DEV_BROADCAST_VOLUME 获取盘符
      → 检查 UsbAutoScan 设置开关（默认 true）
        → 开启：右下角弹出 UsbScanWindow，静默开始单线程扫描
        → 关闭：忽略

扫描进行中：
  → 弹窗显示：设备名 + 进度条 + 已扫描文件数/威胁数
  → "打开设备"按钮始终可点击
  → "暂停"/"取消"按钮可操作
  → 多设备排队：第一个扫完再扫下一个

扫描完成：
  → 无威胁：显示"安全"，5秒后自动关闭弹窗
  → 有威胁：显示威胁数 + "查看威胁"按钮（跳转 SecurityPage），"打开设备"按钮仍可用，弹窗不自动关闭

所有扫描事件写入 LogService
```

### 关键决策

| # | 决策 | 选择 |
|---|------|------|
| 1 | 触发方式 | 静默自动扫描，单个开关控制（默认开启） |
| 2 | 弹窗内容 | 进度 + 结果摘要 + 打开设备按钮 |
| 3 | 打开设备按钮 | 始终可点击，有威胁时额外显示"查看威胁" |
| 4 | 设备检测 | WndProc SubclassProc + WM_DEVICECHANGE |
| 5 | 扫描范围 | 仅可执行文件扩展名 |
| 6 | 扫描实现 | 内联轻量扫描，单线程，可暂停/取消 |
| 7 | 与 SecurityPage 并行 | 直接并行，互不影响 |
| 8 | 弹窗实现 | 新建 UsbScanWindow 类 |
| 9 | 设置项 | 单个 ToggleSwitch 开关 |
| 10 | 威胁处理 | 仅列出，跳转 SecurityPage 手动处理 |
| 11 | 代码位置 | 主项目 Services 目录 |
| 12 | 弹窗关闭 | 无威胁5秒自动关闭，有威胁保持显示 |
| 13 | 多设备 | 排队扫描 |
| 14 | 日志 | 写入 LogService |

---

## 需要创建/修改的文件

### 1. 新建 `Helper/PInvoke/User32/DEV_BROADCAST.cs`

定义 P/Invoke 结构体：

```csharp
namespace Helper.PInvoke.User32;

[StructLayout(LayoutKind.Sequential)]
public struct DEV_BROADCAST_HDR
{
    public uint dbch_size;
    public uint dbch_devicetype;
    public uint dbch_reserved;
}

// dbch_devicetype = 2 (DBT_DEVTYP_VOLUME)
[StructLayout(LayoutKind.Sequential)]
public struct DEV_BROADCAST_VOLUME
{
    public uint dbcv_size;
    public uint dbcv_devicetype;
    public uint dbcv_reserved;
    public uint dbcv_unitmask;
    public ushort dbcv_flags;
}

public static class DeviceType
{
    public const uint DBT_DEVTYP_VOLUME = 2;
}

public static class DeviceEvent
{
    public const int DBT_DEVICEARRIVAL = 0x8000;
    public const int DBT_DEVICEREMOVECOMPLETE = 0x8004;
}

public static class VolumeFlags
{
    public const ushort DBTF_MEDIA = 0x0001;
    public const ushort DBTF_NET = 0x0002;
}
```

### 2. 新建 `Xdows-Security/Services/UsbScanService.cs`

核心扫描服务，职责：
- 接收设备盘符，排队管理
- 单线程扫描可执行文件
- 可暂停/取消
- 扫描结果通过事件通知 UI
- 写入日志

```csharp
using Helper;
using Helper.PInvoke.User32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security.Services;

public class UsbScanThreatInfo
{
    public string FilePath { get; set; } = string.Empty;
    public string VirusName { get; set; } = string.Empty;
    public string EngineName { get; set; } = string.Empty;
}

public class UsbScanProgressEventArgs : EventArgs
{
    public string DriveLetter { get; set; } = string.Empty;
    public string DriveLabel { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public int TotalFiles { get; set; }
    public int ThreatsFound { get; set; }
    public bool IsCompleted { get; set; }
    public bool IsPaused { get; set; }
    public bool IsCancelled { get; set; }
    public List<UsbScanThreatInfo> Threats { get; set; } = [];
}

public class UsbScanService
{
    private static UsbScanService? _instance;
    public static UsbScanService Instance => _instance ??= new UsbScanService();

    private readonly ConcurrentQueue<string> _pendingDrives = new();
    private CancellationTokenSource? _cts;
    private bool _isPaused;
    private bool _isScanning;
    private readonly object _lock = new();

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".msi"
    };

    public event EventHandler<UsbScanProgressEventArgs>? ProgressChanged;
    public event EventHandler<UsbScanProgressEventArgs>? ScanCompleted;
    public event EventHandler<string>? ScanStarted;

    public bool IsScanning => _isScanning;

    public void EnqueueDrive(string driveLetter)
    {
        var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;
        bool enabled = !(settings.Values["UsbAutoScan"] is bool b && !b);
        if (!enabled) return;

        _pendingDrives.Enqueue(driveLetter);
        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan", $"Device queued: {driveLetter}");

        lock (_lock)
        {
            if (!_isScanning)
            {
                _ = ProcessQueueAsync();
            }
        }
    }

    public void Pause()
    {
        _isPaused = true;
    }

    public void Resume()
    {
        _isPaused = false;
    }

    public void Cancel()
    {
        _cts?.Cancel();
        _isPaused = false;
    }

    private async Task ProcessQueueAsync()
    {
        lock (_lock) { _isScanning = true; }

        while (_pendingDrives.TryDequeue(out string? driveLetter))
        {
            _cts = new CancellationTokenSource();
            _isPaused = false;
            await ScanDriveAsync(driveLetter, _cts.Token);
            _cts.Dispose();
            _cts = null;
        }

        lock (_lock) { _isScanning = false; }
    }

    private async Task ScanDriveAsync(string driveLetter, CancellationToken token)
    {
        string driveRoot = $"{driveLetter}:\\";
        string driveLabel = GetDriveLabel(driveLetter);

        ScanStarted?.Invoke(this, driveLetter);
        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan", $"Scanning {driveRoot} ({driveLabel})");

        var threats = new List<UsbScanThreatInfo>();
        int filesScanned = 0;
        int totalFiles = 0;

        try
        {
            var files = EnumerateExecutableFiles(driveRoot);
            var fileList = files.ToList();
            totalFiles = fileList.Count;

            var args = new UsbScanProgressEventArgs
            {
                DriveLetter = driveLetter,
                DriveLabel = driveLabel,
                TotalFiles = totalFiles
            };
            ProgressChanged?.Invoke(this, args);

            var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;
            bool useModelScan = !(settings.Values["ModelScan"] is bool ms && !ms);
            bool useLocalScan = settings.Values["LocalScan"] is true;
            bool useCloudScan = settings.Values["CloudScan"] is true;
            bool deepScan = settings.Values["DeepScan"] is true;
            bool extraData = settings.Values["ExtraData"] is true;
            bool useExactRule = settings.Values["ExactRuleScan"] is true;
            bool useVirusFamily = settings.Values["VirusFamily"] is true;

            ScanEngine.ModelEngineScan? modelEngine = null;
            if (useModelScan)
            {
                try { modelEngine = ScanEngine.ModelEngineScan; }
                catch { useModelScan = false; }
            }

            foreach (var file in fileList)
            {
                while (_isPaused && !token.IsCancellationRequested)
                    await Task.Delay(100, token);

                if (token.IsCancellationRequested) break;

                try
                {
                    if (TrustManager.IsPathTrusted(file))
                    {
                        filesScanned++;
                        continue;
                    }

                    string? md5Hash = null;
                    if (useCloudScan)
                    {
                        try { md5Hash = await ScanEngine.GetFileMD5Async(file); } catch { }
                    }

                    var scanRes = await SecurityPage.RunScansOnFileAsync(
                        file, null, md5Hash,
                        deepScan, extraData,
                        useLocalScan, useCloudScan, useModelScan,
                        false, useVirusFamily,
                        modelEngine, token);

                    if (!string.IsNullOrEmpty(scanRes.VirusInfo))
                    {
                        threats.Add(new UsbScanThreatInfo
                        {
                            FilePath = file,
                            VirusName = scanRes.VirusInfo,
                            EngineName = scanRes.EngineName
                        });
                        LogText.AddNewLog(LogText.LogLevel.WARN, "UsbScan", $"Threat found: {file} - {scanRes.VirusInfo} ({scanRes.EngineName})");
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "UsbScan", $"Scan file failed: {file} - {ex.Message}");
                }

                filesScanned++;

                ProgressChanged?.Invoke(this, new UsbScanProgressEventArgs
                {
                    DriveLetter = driveLetter,
                    DriveLabel = driveLabel,
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    ThreatsFound = threats.Count,
                    IsPaused = _isPaused
                });
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            LogText.AddNewLog(LogText.LogLevel.ERROR, "UsbScan", $"Scan drive failed: {driveRoot} - {ex.Message}");
        }

        var completedArgs = new UsbScanProgressEventArgs
        {
            DriveLetter = driveLetter,
            DriveLabel = driveLabel,
            FilesScanned = filesScanned,
            TotalFiles = totalFiles,
            ThreatsFound = threats.Count,
            Threats = threats,
            IsCompleted = true,
            IsCancelled = token.IsCancellationRequested
        };
        ScanCompleted?.Invoke(this, completedArgs);

        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan",
            token.IsCancellationRequested
                ? $"Scan cancelled: {driveRoot}"
                : $"Scan completed: {driveRoot} - {filesScanned} files, {threats.Count} threats");
    }

    private static IEnumerable<string> EnumerateExecutableFiles(string root)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Where(f => ExecutableExtensions.Contains(Path.GetExtension(f)));
        }
        catch { return Enumerable.Empty<string>(); }
    }

    private static string GetDriveLabel(string driveLetter)
    {
        try
        {
            var drive = new DriveInfo($"{driveLetter}:\\");
            return string.IsNullOrWhiteSpace(drive.VolumeLabel)
                ? $"{driveLetter}:"
                : $"{driveLetter}: ({drive.VolumeLabel})";
        }
        catch { return $"{driveLetter}:"; }
    }
}
```

**重要**：`RunScansOnFileAsync` 当前是 `SecurityPage` 的 `private` 方法，需要改为 `internal static` 以便 `UsbScanService` 调用。在 `SecurityPage.xaml.cs` 中将方法签名从 `private async Task<ScanResult> RunScansOnFileAsync(...)` 改为 `internal static async Task<ScanResult> RunScansOnFileAsync(...)`。由于方法内不使用 `this`，改为 static 是安全的。

### 3. 新建 `Xdows-Security/UsbScanWindow.xaml`

右下角扫描进度弹窗，参考 InterceptWindow 的窗口样式：

```xml
<?xml version="1.0" encoding="utf-8"?>
<Window
    x:Class="Xdows_Security.UsbScanWindow"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    xmlns:l="using:WinUI3Localizer"
    mc:Ignorable="d">
    <StackPanel x:Name="RootPanel">
        <local:TitleBarMenu OwnerWindow="{x:Bind Mode=OneTime}" 
                            xmlns:local="using:Xdows_Security"/>
        <TitleBar x:Name="TitleBarControl" Height="40" 
                  l:Uids.Uid="UsbScanWindow_Title"/>
        <Border Padding="20,0,20,20">
            <StackPanel Spacing="8">
                <!-- 设备信息 -->
                <Grid Margin="0,0,0,4">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Border Grid.Column="0" Background="{ThemeResource ControlFillColorDefaultBrush}" 
                            CornerRadius="8" Width="40" Height="40" Margin="0,0,12,0"
                            BorderThickness="1" BorderBrush="{ThemeResource ControlElevationBorderBrush}">
                        <FontIcon x:Name="StatusIcon" Glyph="&#xE88E;" FontSize="20"
                                  Foreground="{ThemeResource AccentTextFillColorPrimaryBrush}"
                                  HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel Grid.Column="1" VerticalAlignment="Center">
                        <TextBlock x:Name="DeviceNameText" FontSize="14" FontWeight="SemiBold"
                                   TextWrapping="Wrap"/>
                        <TextBlock x:Name="StatusText" FontSize="12"
                                   Foreground="{ThemeResource TextFillColorSecondaryBrush}"
                                   TextWrapping="Wrap" Margin="0,2,0,0"/>
                    </StackPanel>
                </Grid>

                <!-- 进度条 -->
                <ProgressBar x:Name="ScanProgressBar" IsIndeterminate="True" 
                             VerticalAlignment="Center" Margin="0,4,0,4"/>

                <!-- 统计信息 -->
                <Grid Margin="0,4,0,4">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0">
                        <TextBlock l:Uids.Uid="UsbScanWindow_FilesScanned" FontSize="11"
                                   Foreground="{ThemeResource TextFillColorSecondaryBrush}"/>
                        <TextBlock x:Name="FilesScannedText" FontSize="14" FontWeight="SemiBold"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1">
                        <TextBlock l:Uids.Uid="UsbScanWindow_ThreatsFound" FontSize="11"
                                   Foreground="{ThemeResource TextFillColorSecondaryBrush}"/>
                        <TextBlock x:Name="ThreatsFoundText" FontSize="14" FontWeight="SemiBold"
                                   Foreground="{ThemeResource SystemFillColorCriticalBrush}"/>
                    </StackPanel>
                </Grid>

                <!-- 结果区域（扫描完成后显示） -->
                <Border x:Name="ResultBorder" Visibility="Collapsed"
                        Background="{ThemeResource SystemFillColorSuccessBackgroundBrush}" 
                        CornerRadius="8" Padding="12" Margin="0,4,0,4"
                        BorderThickness="1" BorderBrush="{ThemeResource SystemFillColorSuccessBrush}">
                    <StackPanel>
                        <TextBlock x:Name="ResultTitleText" FontSize="13" FontWeight="SemiBold"/>
                        <TextBlock x:Name="ResultDetailText" FontSize="12" Margin="0,2,0,0"
                                   TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>

                <!-- 操作按钮 -->
                <Grid Margin="0,8,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <Button x:Name="OpenDeviceButton" Grid.Column="0"
                            l:Uids.Uid="UsbScanWindow_OpenDevice"
                            Click="OpenDeviceButton_Click"
                            HorizontalAlignment="Stretch"/>
                    <Button x:Name="ViewThreatsButton" Grid.Column="1"
                            l:Uids.Uid="UsbScanWindow_ViewThreats"
                            Click="ViewThreatsButton_Click"
                            Visibility="Collapsed"
                            Margin="8,0,0,0"
                            Style="{StaticResource AccentButtonStyle}"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="8,0,0,0"
                                x:Name="ScanControlPanel">
                        <Button x:Name="PauseButton" 
                                l:Uids.Uid="UsbScanWindow_Pause"
                                Click="PauseButton_Click"
                                Margin="0,0,4,0"/>
                        <Button x:Name="CancelButton"
                                l:Uids.Uid="UsbScanWindow_Cancel"
                                Click="CancelButton_Click"/>
                    </StackPanel>
                </Grid>
            </StackPanel>
        </Border>
    </StackPanel>
</Window>
```

### 4. 新建 `Xdows-Security/UsbScanWindow.xaml.cs`

```csharp
using Microsoft.UI.Xaml;
using System;
using System.IO;
using System.Linq;
using Xdows_Security.Services;
using WinUI3Localizer;

namespace Xdows_Security;

public sealed partial class UsbScanWindow : Window
{
    private readonly string _driveLetter;
    private readonly string _driveLabel;
    private readonly DispatcherQueueTimer _autoCloseTimer;
    private List<UsbScanThreatInfo>? _threats;

    public UsbScanWindow(string driveLetter, string driveLabel)
    {
        this.InitializeComponent();
        _driveLetter = driveLetter;
        _driveLabel = driveLabel;

        var manager = WinUIEx.WindowManager.Get(this);
        manager.MinWidth = 340;
        manager.MinHeight = 260;
        manager.Width = 380;
        manager.IsMaximizable = false;
        manager.IsMinimizable = false;
        manager.IsResizable = false;
        manager.IsTitleBarVisible = false;
        manager.IsAlwaysOnTop = true;
        this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();

        DeviceNameText.Text = driveLabel;
        StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Scanning");
        FilesScannedText.Text = "0";
        ThreatsFoundText.Text = "0";

        _autoCloseTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _autoCloseTimer.Interval = TimeSpan.FromSeconds(5);
        _autoCloseTimer.Tick += (_, _) =>
        {
            _autoCloseTimer.Stop();
            this.Close();
        };

        UsbScanService.Instance.ProgressChanged += OnProgressChanged;
        UsbScanService.Instance.ScanCompleted += OnScanCompleted;

        RootPanel.Loaded += (_, _) =>
        {
            DispatcherQueue.TryEnqueue(() => UpdateWindowHeightAndPosition());
        };

        PositionWindowAtBottomRight();
        App.PlayEntranceAnimation(RootPanel, "right");
    }

    private void OnProgressChanged(object? sender, UsbScanProgressEventArgs e)
    {
        if (e.DriveLetter != _driveLetter) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            FilesScannedText.Text = e.FilesScanned.ToString();
            ThreatsFoundText.Text = e.ThreatsFound.ToString();
            if (e.TotalFiles > 0)
            {
                ScanProgressBar.IsIndeterminate = false;
                ScanProgressBar.Value = e.TotalFiles > 0 ? (double)e.FilesScanned / e.TotalFiles * 100 : 0;
            }
            if (e.IsPaused)
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Paused");
                PauseButton.Content = Localizer.Get().GetLocalizedString("UsbScanWindow_Resume");
            }
            else
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Scanning");
                PauseButton.Content = Localizer.Get().GetLocalizedString("UsbScanWindow_Pause");
            }
        });
    }

    private void OnScanCompleted(object? sender, UsbScanProgressEventArgs e)
    {
        if (e.DriveLetter != _driveLetter) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            UsbScanService.Instance.ProgressChanged -= OnProgressChanged;
            UsbScanService.Instance.ScanCompleted -= OnScanCompleted;

            ScanControlPanel.Visibility = Visibility.Collapsed;
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;

            _threats = e.Threats;

            if (e.IsCancelled)
            {
                StatusIcon.Glyph = "\uE711";
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Cancelled");
                ResultBorder.Visibility = Visibility.Visible;
                ResultBorder.Background = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCautionBackgroundBrush"];
                ResultBorder.BorderBrush = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCautionBrush"];
                ResultTitleText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Cancelled");
                _autoCloseTimer.Start();
                return;
            }

            if (e.ThreatsFound > 0)
            {
                StatusIcon.Glyph = "\uE7BA";
                StatusIcon.Foreground = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBrush"];
                StatusText.Text = string.Format(
                    Localizer.Get().GetLocalizedString("UsbScanWindow_Status_ThreatsFound"),
                    e.ThreatsFound);
                ResultBorder.Visibility = Visibility.Visible;
                ResultBorder.Background = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBackgroundBrush"];
                ResultBorder.BorderBrush = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBrush"];
                ResultTitleText.Text = string.Format(
                    Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Threats"),
                    e.ThreatsFound);
                ResultDetailText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_ThreatsDetail");
                ViewThreatsButton.Visibility = Visibility.Visible;
            }
            else
            {
                StatusIcon.Glyph = "\uE73E";
                StatusIcon.Foreground = 
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorSuccessBrush"];
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Safe");
                ResultBorder.Visibility = Visibility.Visible;
                ResultTitleText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Safe");
                _autoCloseTimer.Start();
            }

            UpdateWindowHeightAndPosition();
        });
    }

    private void PauseButton_Click(object sender, RoutedEventArgs e)
    {
        if (UsbScanService.Instance.IsScanning)
        {
            // Toggle pause/resume — the service reads _isPaused internally
            // We need a way to know current state; simplest: check button content
            if (PauseButton.Content?.ToString() == Localizer.Get().GetLocalizedString("UsbScanWindow_Pause"))
                UsbScanService.Instance.Pause();
            else
                UsbScanService.Instance.Resume();
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        UsbScanService.Instance.Cancel();
    }

    private void OpenDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"{_driveLetter}:\\",
                UseShellExecute = true
            });
        }
        catch { }
    }

    private void ViewThreatsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (App.MainWindow != null)
            {
                App.MainWindow.Activate();
                App.MainWindow.GoToPage("Security");
            }
        }
        catch { }
    }

    private void UpdateWindowHeightAndPosition()
    {
        try
        {
            var manager = WinUIEx.WindowManager.Get(this);
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea == null) return;

            var workArea = displayArea.WorkArea;
            double desiredHeight = RootPanel.ActualHeight;
            double minHeight = manager.MinHeight;
            double maxHeight = Math.Max(minHeight, workArea.Height - 16);
            double newHeight = Math.Clamp(desiredHeight, minHeight, maxHeight);
            int newHeightInt = (int)Math.Ceiling(newHeight);
            if (manager.Height != newHeightInt) manager.Height = newHeightInt;
            PositionWindowAtBottomRight();
        }
        catch { }
    }

    private void PositionWindowAtBottomRight()
    {
        try
        {
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea != null)
            {
                var workArea = displayArea.WorkArea;
                var windowWidth = AppWindow.Size.Width;
                var windowHeight = AppWindow.Size.Height;
                var x = workArea.Width - windowWidth - 20;
                var y = workArea.Height - windowHeight - 8;
                this.AppWindow.Move(new Windows.Graphics.PointInt32(x, y));
            }
        }
        catch { }
    }
}
```

### 5. 修改 `Xdows-Security/MainWindow.xaml.cs`

在现有的 SubclassProc（TitleBarMenu.cs 中的 `MainWindowSubClassProc`）中添加 `WM_DEVICECHANGE` 处理。

**方案**：在 `MainWindow.xaml.cs` 中使用 WinUIEx 的 `WindowMessageReceived` 事件（更简洁，不需要修改 TitleBarMenu.cs）。

在 MainWindow 构造函数中添加：

```csharp
var winExManager = WinUIEx.WindowManager.Get(this);
winExManager.WindowMessageReceived += OnWindowMessage;
```

添加方法：

```csharp
private void OnWindowMessage(object? sender, WinUIEx.WindowMessageEventArgs e)
{
    if (e.Message != (int)Helper.PInvoke.User32.WindowMessage.WM_DEVICECHANGE)
        return;

    const int DBT_DEVICEARRIVAL = 0x8000;
    if (e.WParam != (UIntPtr)DBT_DEVICEARRIVAL)
        return;

    try
    {
        var hdr = Marshal.PtrToStructure<Helper.PInvoke.User32.DEV_BROADCAST_HDR>(e.LParam);
        if (hdr.dbch_devicetype != Helper.PInvoke.User32.DeviceType.DBT_DEVTYP_VOLUME)
            return;

        var vol = Marshal.PtrToStructure<Helper.PInvoke.User32.DEV_BROADCAST_VOLUME>(e.LParam);
        if ((vol.dbcv_flags & Helper.PInvoke.User32.VolumeFlags.DBTF_NET) != 0)
            return;

        char driveLetter = DriveMaskToLetter(vol.dbcv_unitmask);
        if (driveLetter == '\0') return;

        DispatcherQueue.TryEnqueue(() =>
        {
            var service = Services.UsbScanService.Instance;
            service.EnqueueDrive(driveLetter.ToString());

            var scanWindow = new UsbScanWindow(
                driveLetter.ToString(),
                service.GetDriveLabel(driveLetter.ToString()));
            scanWindow.Activate();
        });
    }
    catch { }
}

private static char DriveMaskToLetter(uint unitMask)
{
    for (int i = 0; i < 26; i++)
    {
        if ((unitMask & (1u << i)) != 0)
            return (char)('A' + i);
    }
    return '\0';
}
```

**注意**：需要将 `UsbScanService` 中的 `GetDriveLabel` 方法改为 `public static`，以便 MainWindow 调用。

### 6. 修改 `Xdows-Security/Views/SecurityPage.xaml.cs`

将 `RunScansOnFileAsync` 从 `private async Task<ScanResult>` 改为 `internal static async Task<ScanResult>`：

```csharp
// 原来：
private async Task<ScanResult> RunScansOnFileAsync(String filePath, Byte[]? fileBytes, String? md5Hash, ...)

// 改为：
internal static async Task<ScanResult> RunScansOnFileAsync(String filePath, Byte[]? fileBytes, String? md5Hash, ...)
```

由于方法内不使用任何实例成员（所有状态通过参数传入），改为 static 是安全的。`ScanResult` 已经是嵌套的 record，需一并改为 `internal`：

```csharp
// 原来：
private record ScanResult(String EngineName, String? VirusInfo, String? FamilyInfo = null);

// 改为：
internal record ScanResult(String EngineName, String? VirusInfo, String? FamilyInfo = null);
```

### 7. 修改 `Xdows-Security/Views/SettingsPage.xaml`

在 Protection 区段（注册表保护 SettingsExpander 之后）添加 USB 自动扫描开关：

```xml
<controls:SettingsCard
    VerticalAlignment="Top"
    l:Uids.Uid="SettingsPage_UsbAutoScan"
    HeaderIcon="{ui:FontIcon Glyph=&#xE88E;}"
    Margin="0,0,0,4">
    <ToggleSwitch x:Name="UsbAutoScanToggle" Toggled="Toggled_SaveToggleData" Tag="UsbAutoScan"/>
</controls:SettingsCard>
```

### 8. 修改 `Xdows-Security/Views/SettingsPage.xaml.cs`

在设置加载逻辑中添加 `UsbAutoScan` 的默认值处理（默认 true）：

```csharp
if (!settings.Values.ContainsKey("UsbAutoScan"))
{
    settings.Values["UsbAutoScan"] = true;
}
```

`Toggled_SaveToggleData` 事件处理器已存在，会根据 `Tag` 自动保存到 `LocalSettings`，无需额外代码。

### 9. 本地化字符串 — 三语言 Resources.resw

需要添加的本地化 key：

| Key | zh-HANS | en-US | zh-HANT |
|-----|---------|-------|---------|
| `UsbScanWindow_Title` | USB 设备扫描 | USB Device Scan | USB 設備掃描 |
| `UsbScanWindow_Status_Scanning` | 正在扫描... | Scanning... | 正在掃描... |
| `UsbScanWindow_Status_Paused` | 已暂停 | Paused | 已暫停 |
| `UsbScanWindow_Status_Safe` | 安全 | Safe | 安全 |
| `UsbScanWindow_Status_ThreatsFound` | 发现 {0} 个威胁 | {0} threat(s) found | 發現 {0} 個威脅 |
| `UsbScanWindow_Status_Cancelled` | 已取消 | Cancelled | 已取消 |
| `UsbScanWindow_FilesScanned` | 已扫描文件 | Files scanned | 已掃描文件 |
| `UsbScanWindow_ThreatsFound` | 发现威胁 | Threats found | 發現威脅 |
| `UsbScanWindow_Result_Safe` | 未发现威胁 | No threats found | 未發現威脅 |
| `UsbScanWindow_Result_Threats` | 发现 {0} 个威胁 | {0} threat(s) found | 發現 {0} 個威脅 |
| `UsbScanWindow_Result_ThreatsDetail` | 点击"查看威胁"处理 | Click "View Threats" to handle | 點擊「查看威脅」處理 |
| `UsbScanWindow_Result_Cancelled` | 扫描已取消 | Scan cancelled | 掃描已取消 |
| `UsbScanWindow_OpenDevice` | 打开设备 | Open Device | 打開設備 |
| `UsbScanWindow_ViewThreats` | 查看威胁 | View Threats | 查看威脅 |
| `UsbScanWindow_Pause` | 暂停 | Pause | 暫停 |
| `UsbScanWindow_Resume` | 继续 | Resume | 繼續 |
| `UsbScanWindow_Cancel` | 取消 | Cancel | 取消 |
| `SettingsPage_UsbAutoScan.Title` | USB 自动扫描 | USB Auto Scan | USB 自動掃描 |
| `SettingsPage_UsbAutoScan.Description` | 检测到可移动设备时自动扫描 | Automatically scan when removable device is detected | 偵測到可移除設備時自動掃描 |

---

## 实现顺序

1. `Helper/PInvoke/User32/DEV_BROADCAST.cs` — P/Invoke 结构体
2. `SecurityPage.xaml.cs` — 将 `RunScansOnFileAsync` 和 `ScanResult` 改为 `internal static`
3. `Services/UsbScanService.cs` — 扫描服务核心
4. `UsbScanWindow.xaml` + `.cs` — 右下角弹窗
5. `MainWindow.xaml.cs` — WM_DEVICECHANGE 处理
6. `SettingsPage.xaml` + `.cs` — 设置开关
7. 三语言 `Resources.resw` — 本地化字符串
8. 构建验证

## 注意事项

- `RunScansOnFileAsync` 改为 static 后，所有内部调用不受影响（它本来就是无状态的）
- `UsbScanWindow` 关闭时需要取消订阅事件，避免内存泄漏。在 `OnScanCompleted` 中已取消订阅，但窗口被用户直接关闭时也需处理——在 Window.Closed 事件中取消订阅
- `WM_DEVICECHANGE` 需要窗口句柄，WinUIEx 的 `WindowMessageReceived` 事件自动处理了这一点
- `DEV_BROADCAST_VOLUME` 的 `dbcv_unitmask` 是位掩码，bit 0 = A:, bit 1 = B:, ..., bit 25 = Z:
- 网络驱动器（`DBTF_NET`）应被过滤掉，不触发扫描
- 设置 key 为 `UsbAutoScan`，默认值为 `true`
