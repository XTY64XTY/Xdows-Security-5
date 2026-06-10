using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using WinRT.Interop;
using WinUI3Localizer;
using Xdows_Security.Services;

namespace Xdows_Security.Views
{
    public sealed partial class HomePage : Page
    {
        private const double LogScrollEdgeThreshold = 8;

        private bool _entrancePlayed;
        private bool _langHandlerAttached;

        private sealed class WeakEventTimer
        {
            private readonly DispatcherQueueTimer _timer;
            public event EventHandler<object?>? Tick;

            public WeakEventTimer(TimeSpan interval)
            {
                _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
                _timer.Interval = interval;
                _timer.Tick += (_, e) => Tick?.Invoke(this, e);
            }
            public void Start() => _timer.Start();
            public void Stop() => _timer.Stop();
        }

        private static class SystemInfoModel
        {
            [StructLayout(LayoutKind.Sequential)]
            private struct MEMORYSTATUSEX
            {
                public uint dwLength, dwMemoryLoad;
                public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile,
                             ullAvailPageFile, ullTotalVirtual, ullAvailVirtual,
                             ullAvailExtendedVirtual;
            }
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

            public static (bool ok, uint load, string display) GetMemory()
            {
                var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (!GlobalMemoryStatusEx(ref mem)) return (false, 0, "");
                double t = mem.ullTotalPhys, a = mem.ullAvailPhys, u = t - a;
                string[] units = ["B", "KB", "MB", "GB"];
                int idx = 0;
                while (t >= 1024 && idx < units.Length - 1) { t /= 1024; a /= 1024; u /= 1024; idx++; }
                return (true, mem.dwMemoryLoad, $"{u:F1} {units[idx]} / {t:F1} {units[idx]} ({mem.dwMemoryLoad}%)");
            }
        }

        private readonly WeakEventTimer _sysTimer = new(TimeSpan.FromSeconds(60));
        private readonly WeakEventTimer _protTimer = new(TimeSpan.FromSeconds(10));

        private readonly ObservableCollection<LogEntry> _logEntries = [];
        private LogText.LogLevel[] _selectedLevels = [];
        private string? _searchKeyword;
        private bool _isLoadingOlder;
        private bool _hasMoreOlder = true;
        private bool _isAutoScroll = true;
        private ScrollViewer? _logScrollViewer;
        private DispatcherQueueTimer? _logThrottleTimer;
        private LogEntry? _pendingLogEntry;

        public HomePage()
        {
            InitializeComponent();

            Loaded += HomePage_Loaded;
            Unloaded += HomePage_Unloaded;

            LogListView.ItemsSource = _logEntries;

            UpdateLogEmptyState();

            LogListView.Loaded += LogListView_Loaded;
            LogListView.Unloaded += LogListView_Unloaded;

            LogSearchBox.QuerySubmitted += LogSearchBox_QuerySubmitted;
            LogSearchBox.TextChanged += LogSearchBox_TextChanged;

            LogText.TextChanged += OnLogTextChanged;
            LogService.LogAdded += OnLogAdded;
            Xdows_Security.ProtectionStatus.StateChanged += OnProtectionStateChanged;

            _logThrottleTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _logThrottleTimer.Interval = TimeSpan.FromMilliseconds(100);
            _logThrottleTimer.Tick += OnLogThrottleTick;

            LoadData();
            InitTimers();
            RefreshPomes();
        }

        private void HomePage_Unloaded(object sender, RoutedEventArgs e)
        {
            DetachLogScrollViewer();

            if (!_langHandlerAttached) return;
            _langHandlerAttached = false;
            try { Localizer.Get().LanguageChanged -= OnLanguageChanged; } catch { }
            try { Xdows_Security.ProtectionStatus.StateChanged -= OnProtectionStateChanged; } catch { }
        }

        private void LogListView_Loaded(object sender, RoutedEventArgs e)
        {
            AttachLogScrollViewer();
        }

        private void LogListView_Unloaded(object sender, RoutedEventArgs e)
        {
            DetachLogScrollViewer();
        }

        private void DetachLogScrollViewer()
        {
            if (_logScrollViewer is null) return;

            _logScrollViewer.ViewChanged -= LogScroll_ViewChanged;
            _logScrollViewer = null;
        }

        private void AttachLogScrollViewer()
        {
            if (_logScrollViewer is not null) return;

            LogListView.ApplyTemplate();
            _logScrollViewer = FindDescendant<ScrollViewer>(LogListView);
            if (_logScrollViewer is null) return;

            _logScrollViewer.ViewChanged += LogScroll_ViewChanged;
            _isAutoScroll = IsLogScrolledToBottom(_logScrollViewer);
        }

        private async void HomePage_Loaded(object sender, RoutedEventArgs e)
        {
            if (!_langHandlerAttached)
            {
                _langHandlerAttached = true;
                try { Localizer.Get().LanguageChanged += OnLanguageChanged; } catch { }
            }

            if (_entrancePlayed) return;
            _entrancePlayed = true;

            if (CardsPanel is null) return;

            var cards = CardsPanel.Children.OfType<InfoCard>().ToArray();
            for (int i = 0; i < cards.Length; i++)
            {
                var card = cards[i];
                card.Visibility = Visibility.Visible;
                await Task.Delay(70);
            }

            await LoadInitialLogsAsync();
        }

        private async Task LoadInitialLogsAsync()
        {
            var count = CalculateInitialCount();
            var logs = LogService.GetLatestLogs(count, _selectedLevels, _searchKeyword);
            _logEntries.Clear();
            foreach (var log in logs)
                _logEntries.Add(log);
            _hasMoreOlder = logs.Count >= count;

            UpdateLogEmptyState();

            await Task.Delay(50);
            AttachLogScrollViewer();
            ScrollLogsToBottom();
            _isAutoScroll = true;
        }

        private int CalculateInitialCount()
        {
            double height = _logScrollViewer?.ActualHeight ?? LogListView.ActualHeight;
            if (height <= 0) height = 216;
            return (int)(height / 18) + 20;
        }

        private async void LogScroll_ViewChanged(object? sender, ScrollViewerViewChangedEventArgs e)
        {
            if (sender is not ScrollViewer scrollViewer) return;

            _isAutoScroll = IsLogScrolledToBottom(scrollViewer);

            if (_isLoadingOlder || !_hasMoreOlder) return;

            if (scrollViewer.VerticalOffset <= LogScrollEdgeThreshold && scrollViewer.ScrollableHeight > 0)
            {
                await LoadOlderLogsAsync(scrollViewer);
            }
        }

        private async Task LoadOlderLogsAsync(ScrollViewer scrollViewer)
        {
            if (_isLoadingOlder || !_hasMoreOlder || _logEntries.Count == 0) return;

            _isLoadingOlder = true;
            try
            {
                long oldestId = _logEntries[0].Id;
                LogText.LogLevel[] levelsSnapshot = [.. _selectedLevels];
                string? keywordSnapshot = _searchKeyword;

                var older = await Task.Run(() =>
                    LogService.GetOlderLogs(oldestId, 50, levelsSnapshot, keywordSnapshot));

                if (older.Count == 0)
                {
                    _hasMoreOlder = false;
                    return;
                }

                if (_logEntries.Count == 0 ||
                    _logEntries[0].Id != oldestId ||
                    !levelsSnapshot.SequenceEqual(_selectedLevels) ||
                    keywordSnapshot != _searchKeyword)
                {
                    return;
                }

                double prevScrollableHeight = scrollViewer.ScrollableHeight;

                for (int i = 0; i < older.Count; i++)
                    _logEntries.Insert(i, older[i]);

                await Task.Delay(10);
                double offsetAdjustment = scrollViewer.ScrollableHeight - prevScrollableHeight;
                scrollViewer.ChangeView(null, scrollViewer.VerticalOffset + offsetAdjustment, null, true);
            }
            finally
            {
                _isLoadingOlder = false;
            }
        }

        private void OnLogTextChanged(object? sender, EventArgs e) { }

        private void OnProtectionStateChanged(object? sender, EventArgs e)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                LoadProtection();
                UpdateData();
            });
        }

        private void OnLogAdded(object? sender, LogEntry entry)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => OnLogAdded(sender, entry));
                return;
            }

            _pendingLogEntry = entry;
            if (_logThrottleTimer is { IsRunning: false })
                _logThrottleTimer.Start();
        }

        private void OnLogThrottleTick(DispatcherQueueTimer sender, object args)
        {
            _logThrottleTimer?.Stop();
            if (_pendingLogEntry is null) return;

            if (_selectedLevels.Length > 0 && !_selectedLevels.Contains(_pendingLogEntry.Level))
            {
                _pendingLogEntry = null;
                return;
            }

            if (!string.IsNullOrWhiteSpace(_searchKeyword) &&
                !_pendingLogEntry.Text.Contains(_searchKeyword, StringComparison.OrdinalIgnoreCase))
            {
                _pendingLogEntry = null;
                return;
            }

            var entry = _pendingLogEntry;
            _pendingLogEntry = null;

            _logEntries.Add(entry);
            _hasMoreOlder = true;

            UpdateLogEmptyState();
            AttachLogScrollViewer();

            if (_isAutoScroll)
            {
                ScrollLogsToBottom();
            }
        }

        private bool IsLogScrolledToBottom(ScrollViewer scrollViewer)
        {
            return scrollViewer.ScrollableHeight <= LogScrollEdgeThreshold ||
                   scrollViewer.VerticalOffset >= scrollViewer.ScrollableHeight - LogScrollEdgeThreshold;
        }

        private void ScrollLogsToBottom()
        {
            if (_logScrollViewer is not null)
            {
                _logScrollViewer.ChangeView(null, _logScrollViewer.ScrollableHeight, null, true);
                return;
            }

            if (_logEntries.Count > 0)
            {
                LogListView.ScrollIntoView(_logEntries[^1]);
            }
        }

        private static T? FindDescendant<T>(DependencyObject? parent) where T : DependencyObject
        {
            if (parent is null) return null;

            int childCount = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < childCount; i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                if (child is T target) return target;

                T? result = FindDescendant<T>(child);
                if (result is not null) return result;
            }

            return null;
        }

        private void LogSearchBox_QuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
        {
            _searchKeyword = string.IsNullOrWhiteSpace(args.QueryText) ? null : args.QueryText.Trim();
            _ = LoadInitialLogsAsync();
        }

        private void LogSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput &&
                string.IsNullOrEmpty(sender.Text))
            {
                _searchKeyword = null;
                _ = LoadInitialLogsAsync();
            }
        }

        private void RefreshPomes_Click(object sender, RoutedEventArgs e) => RefreshPomes();
        private void CopyPomes_Click(object sender, RoutedEventArgs e)
        {
            var pkg = new DataPackage();
            pkg.SetText(PomesLine.Text);
            Clipboard.SetContent(pkg);
        }

        private void RefreshSysInfo_Click(object sender, RoutedEventArgs e) => LoadData();

        private void RefreshStatistics_Click(object sender, RoutedEventArgs e) => LoadStatistics();

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogText.ClearLog();
            _logEntries.Clear();
            _hasMoreOlder = false;
            UpdateLogEmptyState();
        }

        private void UpdateLogEmptyState()
        {
            bool isEmpty = _logEntries.Count == 0;
            LogEmptyStatePanel.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
            LogListView.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
            LogEmptyStateText.Text = Localizer.Get().GetLocalizedString("HomePage_LogEmptyState");
        }

        private void ExportLog_Click(object sender, RoutedEventArgs e)
        {
            _ = ShowExportDialogAsync();
        }

        private async Task ShowExportDialogAsync()
        {
            var dialog = new LogExportDialog
            {
                XamlRoot = this.XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            try
            {
                var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
                var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
                var picker = new FileSavePicker(windowId)
                {
                    SuggestedFileName = $"XdowsSecurity_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                    DefaultFileExtension = ".log",
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                    SuggestedFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                PickFileResult file = await picker.PickSaveFileAsync();
                if (file is null) return;

                await LogService.ExportAsync(file.Path,
                    dialog.SelectedLevels, dialog.SearchKeyword,
                    dialog.FromDate, dialog.ToDate);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ExportLog", ex.Message);
            }
        }

        private void LogManage_Click(object sender, RoutedEventArgs e)
        {
            _ = ShowLogManagementDialogAsync();
        }

        private async Task ShowLogManagementDialogAsync()
        {
            var dialog = new LogManagementDialog
            {
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
            await LoadInitialLogsAsync();
        }

        private void CopySysInfo_Click(object sender, RoutedEventArgs e)
        {
            var pkg = new DataPackage();
            pkg.SetText($"OSName: {OsName.Text}\nOSVersion: {OsVersion.Text}\nMemoryUsage: {MemoryUsage.Text}");
            Clipboard.SetContent(pkg);
        }

        private void LogLevelFilter_MenuClick(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleMenuFlyoutItem item) return;
            var flyout = LogLevelFilter.Flyout as MenuFlyout;
            var allItem = flyout!.Items.OfType<ToggleMenuFlyoutItem>().FirstOrDefault(t => t.Tag.ToString() == "All");

            var selected = flyout!.Items
                                  .OfType<ToggleMenuFlyoutItem>()
                                  .Where(t => t.Tag.ToString() != "All" && t.IsChecked)
                                  .Select(t => t.Tag.ToString()!)
                                  .ToArray();

            if (item.Tag.ToString() == "All")
            {
                bool newState = item.IsChecked;
                foreach (var toggle in flyout.Items.OfType<ToggleMenuFlyoutItem>())
                    if (toggle.Tag.ToString() != "All") toggle.IsChecked = newState;
                selected = newState
                    ? Enum.GetNames(typeof(LogText.LogLevel))
                    : [];
            }
            else
            {
                if (allItem is not null)
                {
                    var levelItems = flyout.Items.OfType<ToggleMenuFlyoutItem>()
                        .Where(t => t.Tag.ToString() != "All").ToList();
                    allItem.IsChecked = levelItems.All(t => t.IsChecked);
                }
            }

            LogLevelFilter_Internal(selected);
        }

        private void RefreshPomes()
        {
            var all = Localizer.Get().GetLocalizedString("HomePage_Pomes")
                               .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            PomesLine.Text = all.OrderBy(_ => Guid.NewGuid()).FirstOrDefault() ?? "";
        }

        private void OnLanguageChanged(object? sender, LanguageChangedEventArgs e)
        {
            try
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        RefreshPomes();
                        UpdateMemory();
                        LoadProtection();
                        UpdateData();
                    }
                    catch { }
                });
            }
            catch { }
        }

        private void LogLevelFilter_Internal(string[]? selected)
        {
            _selectedLevels = selected?.Length > 0
                ? selected.Select(s => Enum.Parse<LogText.LogLevel>(s)).ToArray()
                : [];
            _ = LoadInitialLogsAsync();
        }

        private void InitTimers()
        {
            _sysTimer.Tick += (_, _) => { UpdateMemory(); LoadProtection(); };
            _protTimer.Tick += (_, _) => UpdateData();
            _sysTimer.Start();
            _protTimer.Start();
        }

        private void LoadData()
        {
            try
            {
                OsName.Text = App.OsName;
                OsVersion.Text = App.OsVersion;
            }
            catch (Exception ex)
            {
                OsName.Text = Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
                OsVersion.Text = Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
                LogText.AddNewLog(LogText.LogLevel.WARN, "LoadSystemInfo", ex.Message);
            }
            UpdateMemory();
            LoadProtection();
            LoadStatistics();
            UpdateData();
        }

        private void UpdateMemory()
        {
            var (ok, _, disp) = SystemInfoModel.GetMemory();

            MemoryUsage.Text = ok ? disp : Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
        }

        private void LoadProtection()
        {
            var st = Localizer.Get().GetLocalizedString("AllPage_Status").Split(',');
            var ok = Xdows_Security.ProtectionStatus.IsOpen();
            string driverStatus = Localizer.Get().GetLocalizedString(Xdows_Security.ProtectionStatus.GetDriverStatusKey());
            ProtectionStatus.Text = Xdows_Security.ProtectionStatus.IsRun(5) && !string.IsNullOrWhiteSpace(driverStatus)
                ? driverStatus
                : ok ? st[0] : st[1];
            ProtectionStatus.Foreground = ok
            ? new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 78, 201, 176))
            : new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 241, 82, 98));

            var lastScan = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings.Values["LastScanTime"] as string ?? "";

            LastScanTime.Text = string.IsNullOrEmpty(lastScan) ? WinUI3Localizer.Localizer.Get().GetLocalizedString("AllPage_Undefined") : lastScan;

            var threatCount = (int)(Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings.Values["ThreatCount"] ?? 0);
            ThreatCount.Text = threatCount.ToString();
        }

        private void LoadStatistics()
        {
            TotalScans.Text = Statistics.ScansQuantity.ToString();
            TotalThreats.Text = Statistics.VirusQuantity.ToString();
        }

        private void UpdateData()
        {
            var ok = Xdows_Security.ProtectionStatus.IsOpen();
            HomePageText.Text = Localizer.Get().GetLocalizedString(ok ? "HomePage_TextBlock_Open"
                                                                 : "HomePage_TextBlock_Close");
            HomePageIcon.Glyph = ok ? "\uE73E" : "\uE711";
        }
    }
}
