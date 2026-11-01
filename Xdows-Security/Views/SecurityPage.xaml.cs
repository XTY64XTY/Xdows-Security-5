using Helper;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;
using Xdows_Security.Services;
using ApplicationDataContainer = Microsoft.Windows.Storage.ApplicationDataContainer;

namespace Xdows_Security.Views
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public partial class VirusRow : INotifyPropertyChanged
    {
        private string _filePath = string.Empty;
        private string _virusName = string.Empty;
        private string _familyName = string.Empty;
        private string _engineName = string.Empty;
        private bool _useFamilyEngine;
        private bool _isChecked = true;

        public string FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); }
        }

        public string VirusName
        {
            get => _virusName;
            set { _virusName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public string FamilyName
        {
            get => _familyName;
            set { _familyName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public string EngineName
        {
            get => _engineName;
            set { _engineName = value; OnPropertyChanged(); }
        }

        public bool UseFamilyEngine
        {
            get => _useFamilyEngine;
            set { _useFamilyEngine = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public bool IsChecked
        {
            get => _isChecked;
            set { if (_isChecked == value) return; _isChecked = value; OnPropertyChanged(); }
        }

        public string DisplayName => _useFamilyEngine && !string.IsNullOrWhiteSpace(_familyName) && _familyName != Localizer.Get().GetLocalizedString("AllPage_Undefined") ? _familyName : _virusName;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public partial class MoreScanItem : INotifyPropertyChanged
    {
        private string _path = string.Empty;
        private bool _isFolder;

        public string Path
        {
            get => _path;
            set { _path = value; OnPropertyChanged(); }
        }

        public bool IsFolder
        {
            get => _isFolder;
            set { _isFolder = value; OnPropertyChanged(); OnPropertyChanged(nameof(IconGlyph)); }
        }

        public string IconGlyph => _isFolder ? "\uE8B7" : "\uE8A5";

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public sealed partial class SecurityPage : Page
    {
        private readonly DispatcherQueue _dispatcherQueue;
        private CancellationTokenSource? _cts;
        private bool _isPaused = false;
        // 暂停信号：Set=运行中，Reset=已暂停。配合 WaitWhilePausedAsync 实现零轮询等待
        private readonly ManualResetEventSlim _pauseEvent = new(initialState: true);
        // 缓存 UI 格式化字符串，避免每次 UpdateScanStats 都查询本地化资源
        private string? _fmtScanSummary;
        private string? _fmtScanSummaryCompleted;
        // 状态行显示的耗时（秒）与速度（文件/秒），由扫描循环按节流节奏写入
        private double _scanElapsedSeconds;
        private double _scanSpeed;
        private bool _taskbarProgressActive = false;
        private bool _lastShowScanProgress = false;
        private int _filesScanned = 0;
        private int _threatsFound = 0;
        private int _scanId = 0;
        private ContentDialog? _moreScanDialog;
        private ContentDialog? _detailsDialog;
        private readonly Dictionary<string, List<(string EntryPath, string VirusName)>> _zipFileThreats = [];
        private ObservableCollection<VirusRow>? CurrentResults;
        private int _scanTotalFiles;
        private bool _isScanRunning;
        private bool _threatListVisible;
        private bool _threatListShown;
        private int _threatListVisualToken;
        private double _cancelElapsedSeconds;
        private int _cancelScannedCount;

        private bool IsCurrentScan(int scanId, CancellationToken token)
        {
            if (token.IsCancellationRequested) return false;
            return scanId == _scanId;
        }

        private static void ShowWithEntranceAnimation(UIElement element, string kind = "up", int delayMs = 0)
        {
            element.Visibility = Visibility.Visible;
            // 先置透明再强制布局：从 Visible 到 Storyboard 生效之间会渲染一帧完整元素，那一帧就是看到的黑闪
            element.Opacity = 0;
            element.UpdateLayout();
            App.PlayEntranceAnimation(element, kind, delayMs: delayMs);
        }

        private static void HideWithVisualReset(UIElement element)
        {
            App.ResetElementVisualState(element);
            element.Visibility = Visibility.Collapsed;
        }

        private void ShowBackToVirusListButton()
        {
            SyncBackToVirusListButtonText(_threatListShown);

            if (BackToVirusListButton.Visibility != Visibility.Visible)
            {
                ShowWithEntranceAnimation(BackToVirusListButton, "right");
            }
            else
            {
                BackToVirusListButton.Visibility = Visibility.Visible;
            }
        }

        /// <summary>
        /// 列表始终显示在扫描页上，按钮语义是「隐藏 / 查看」，文案必须跟着列表的真实可见性走。
        /// </summary>
        private void SyncBackToVirusListButtonText(bool isListVisible)
        {
            BackToVirusListButtonText.Text = isListVisible ? Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Hide") : Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Show");
            BackToVirusListButtonIcon.Glyph = isListVisible ? "\uED1A" : "\uE890";
        }

#if DEBUG
        private const string TestVirusCopyDirectory = @"D:\\Code\\Model\\Files\\Test";

        private static async Task CopyVirusSampleForTestAsync(string displayName, string? sourceFilePath = null, Byte[]? bytes = null)
        {
            try
            {
                Directory.CreateDirectory(TestVirusCopyDirectory);

                string baseName = string.Empty;
                try
                {
                    if (!string.IsNullOrEmpty(sourceFilePath))
                        baseName = Path.GetFileName(sourceFilePath);
                    if (string.IsNullOrWhiteSpace(baseName))
                        baseName = Path.GetFileName(displayName);
                }
                catch { }

                if (string.IsNullOrWhiteSpace(baseName))
                    baseName = "sample.bin";

                string destFileName = $"{DateTime.Now:yyyyMMdd_HHmmssfff}_{Guid.NewGuid():N}_{baseName}";
                string destPath = Path.Combine(TestVirusCopyDirectory, destFileName);

                if (bytes != null)
                {
                    await File.WriteAllBytesAsync(destPath, bytes);
                    return;
                }

                if (!string.IsNullOrEmpty(sourceFilePath) && File.Exists(sourceFilePath))
                {
                    File.Copy(sourceFilePath, destPath, overwrite: false);
                }
            }
            catch
            {
                // test-only, ignore
            }
        }
#endif

        public SecurityPage()
        {
            this.InitializeComponent();
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
            StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Idle");
            Loaded += SecurityPage_Loaded;
            Unloaded += SecurityPage_Unloaded;
        }

        private void SecurityPage_Loaded(object sender, RoutedEventArgs e)
        {
            // 通知主窗口：SecurityPage 已就绪，可接收扫描请求（替代旧版的 Task.Delay + 轮询）
            App.MainWindow?.NotifySecurityPageReady(this);
        }

        private void SecurityPage_Unloaded(object sender, RoutedEventArgs e)
        {
            // 扫描在后台继续跑（页面被 Frame 缓存复用），此时切到别的页不能把任务栏进度清掉
            if (!_isScanRunning) ClearTaskbarProgress();
        }

        private void ClearTaskbarProgress()
        {
            if (!_taskbarProgressActive) return;
            _taskbarProgressActive = false;
            try { TaskbarProgressService.TryClear(); } catch { }
        }

        private void UpdateTaskbarProgressStateForRunning()
        {
            if (!_taskbarProgressActive) return;

            try
            {
                if (_lastShowScanProgress)
                {
                    double percent = 0;
                    try
                    {
                        var total = _scanTotalFiles;
                        percent = total == 0 ? 0 : Math.Min(1.0, (double)_filesScanned / total);
                    }
                    catch { }

                    TaskbarProgressService.TrySetNormal(percent);
                }
                else
                {
                    TaskbarProgressService.TrySetIndeterminate();
                }
            }
            catch { }
        }

        private void AddVirusResult(string filePath, string virusName, string? familyName = null, string? engineName = null, bool useFamilyEngine = false)
        {
            VirusRow row = new()
            {
                FilePath = filePath,
                VirusName = virusName,
                FamilyName = familyName ?? string.Empty,
                EngineName = engineName ?? string.Empty,
                UseFamilyEngine = useFamilyEngine
            };

            CurrentResults?.Add(row);
            UpdateThreatListVisibility();
        }

        /// <summary>
        /// 结果列表为空时（包括扫描开始前）整个列表与表头都不显示，只在真正有威胁时出现。
        /// </summary>
        private void UpdateThreatListVisibility()
        {
            bool hasResults = CurrentResults is { Count: > 0 };
            if (hasResults == _threatListVisible) return;
            _threatListVisible = hasResults;

            if (hasResults)
            {
                ShowThreatList();
                ShowBackToVirusListButton();
            }
            else
            {
                HideThreatList();
                HideWithVisualReset(BackToVirusListButton);
                SyncBackToVirusListButtonText(false);
            }
        }

        /// <summary>
        /// 显示威胁列表。每次显隐都换一次 token，让还在淡出中的旧动画收尾时不会把列表又收起来。
        /// </summary>
        private void ShowThreatList()
        {
            _threatListVisualToken++;
            _threatListShown = true;
            ShowWithEntranceAnimation(ThreatListBorder);
        }

        /// <summary>
        /// 隐藏威胁列表：先淡出，动画结束后才真正 Collapsed（原来是瞬间消失，和入场动画不对称）。
        /// </summary>
        private void HideThreatList()
        {
            if (!_threatListShown) return;

            _threatListShown = false;
            int token = ++_threatListVisualToken;
            App.PlayFadeOutAnimation(ThreatListBorder, () =>
            {
                if (token == _threatListVisualToken) ThreatListBorder.Visibility = Visibility.Collapsed;
            });
        }

        private void OnCancelScanClick(object sender, RoutedEventArgs e)
        {
            // 取消请求已发出：按钮立刻禁用并把图标换成转圈，
            // 扫描真正结束前不再接受重复点击（完成/取消/失败分支统一把这个按钮隐藏）
            CancelScanButton.IsEnabled = false;
            CancelScanButtonIcon.Visibility = Visibility.Collapsed;
            CancelScanButtonRing.IsActive = true;
            CancelScanButtonRing.Visibility = Visibility.Visible;

            // 平均速度只统计到「点下取消」这一刻：之后再扫完的文件和收尾耗时都不算进去。
            // _scanElapsedSeconds 是并行分支每 150ms 更新一次的耗时（已经扣掉暂停），_filesScanned 是实时计数
            _cancelElapsedSeconds = _scanElapsedSeconds;
            _cancelScannedCount = _filesScanned;

            _cts?.Cancel();
        }

        private void OnSelectAllThreatsClick(object sender, RoutedEventArgs e)
        {
            if (CurrentResults is null) return;

            bool isChecked = SelectAllThreatsCheckBox.IsChecked == true;
            foreach (VirusRow row in CurrentResults) row.IsChecked = isChecked;
            UpdateSelectAllThreatsState();
        }

        private void OnVirusRowCheckedChanged(object sender, RoutedEventArgs e)
        {
            if (sender is not CheckBox box || box.Tag is not VirusRow row) return;

            // 全选/全不选会把 IsChecked 推到行上，绑定再回推控件并触发本事件；
            // 值已经相同就直接返回，避免逐行触发一次全表扫描。
            bool isChecked = box.IsChecked == true;
            if (row.IsChecked == isChecked) return;

            row.IsChecked = isChecked;
            UpdateSelectAllThreatsState();
            UpdateHandleAllButtonVisibility();
        }

        private void UpdateSelectAllThreatsState()
        {
            if (CurrentResults is null || CurrentResults.Count == 0)
            {
                SelectAllThreatsCheckBox.IsChecked = true;
                return;
            }

            bool allChecked = true;
            foreach (VirusRow row in CurrentResults)
            {
                if (row.IsChecked) continue;
                allChecked = false;
                break;
            }
            SelectAllThreatsCheckBox.IsChecked = allChecked;
        }

        private async Task OnTrustClickInternal(VirusRow? row)
        {
            if (row is null) return;

            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Title"),
                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Content"), row.FilePath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    bool success = await TrustManager.AddToTrust(row.FilePath);

                    ContentDialog resultDialog = new()
                    {
                        Title = success ?
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Title") :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = success ?
                            string.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Content"), row.FilePath) :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Content"),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };
                    await resultDialog.ShowAsync();

                    if (success && CurrentResults != null)
                    {
                        VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                        if (itemToRemove != null)
                        {
                            CurrentResults.Remove(itemToRemove);
                        }
                        _threatsFound--;
                        UpdateScanStats(_filesScanned, _threatsFound);
                        UpdateHandleAllButtonVisibility();
                    }
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        XamlRoot = this.XamlRoot,
                        DefaultButton = ContentDialogButton.Close
                    }.ShowAsync();
                }
            }
        }

        private async Task OnHandleClickInternal(VirusRow? row)
        {
            if (CurrentResults is null || row is null) return;

            string displayPath = row.FilePath;

            var progressContent = new StackPanel
            {
                Spacing = 16,
                HorizontalAlignment = HorizontalAlignment.Center,
                Children =
                   {
                       new ProgressRing { IsActive = true, Width = 40, Height = 40 },
                       new TextBlock
                         {
                            Text = Localizer.Get().GetLocalizedString("SecurityPage_HandleProcessing"),
                            HorizontalAlignment = HorizontalAlignment.Center,
                            Style = Application.Current.Resources["BodyTextBlockStyle"] as Style
                         }
                   }
            };

            var dialog = new ContentDialog
            {
                Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Title"),
                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Content"), displayPath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            dialog.PrimaryButtonClick += async (s, args) =>
            {
                args.Cancel = true;

                dialog.PrimaryButtonText = null;
                dialog.CloseButtonText = null;
                dialog.Content = progressContent;

                try
                {
                    var (handled, actionTaken) = await HandleSingleThreatAsync(row);

                    string? zipPath = null;
                    string? entryPath = null;
                    if (TryParseArchiveEntry(displayPath, out var resolvedArchivePath, out var resolvedEntryPath))
                    {
                        zipPath = resolvedArchivePath;
                        entryPath = resolvedEntryPath;
                    }

                    if (handled && zipPath != null && entryPath != null)
                    {
                        var entriesToDelete = new List<string>();
                        if (_zipFileThreats.TryGetValue(zipPath, out var threatsInZip))
                        {
                            foreach (var (EntryPath, VirusName) in threatsInZip)
                            {
                                if (EntryPath == entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(entryPath + "\\")))
                                {
                                    entriesToDelete.Add(EntryPath);
                                }
                            }

                            foreach (var entry in entriesToDelete)
                            {
                                VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == $"{zipPath}\\{entry}");
                                if (itemToRemove != null)
                                {
                                    CurrentResults.Remove(itemToRemove);
                                    _threatsFound--;
                                }
                            }

                            _zipFileThreats.Remove(zipPath);
                        }
                    }

                    dialog.Content = new TextBlock
                    {
                        Text = actionTaken,
                        TextWrapping = TextWrapping.Wrap
                    };

                    dialog.CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm");
                    dialog.DefaultButton = ContentDialogButton.Close;

                    if (handled)
                    {
                        if (zipPath == null)
                        {
                            VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                            if (itemToRemove != null)
                            {
                                CurrentResults.Remove(itemToRemove);
                                _threatsFound--;
                            }
                        }
                        UpdateScanStats(_filesScanned, _threatsFound);
                    }
                }
                catch (Exception ex)
                {
                    dialog.Content = new TextBlock
                    {
                        Text = ex.Message,
                        TextWrapping = TextWrapping.Wrap
                    };
                    dialog.Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleFailed_Title");
                    dialog.CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm");
                }
            };

            await dialog.ShowAsync();
        }

        private async Task<(bool handled, string actionTaken)> HandleSingleThreatAsync(VirusRow row)
        {
            string displayPath = row.FilePath;
            string? zipPath = null;
            string? entryPath = null;

            if (TryParseArchiveEntry(displayPath, out var resolvedArchivePath, out var resolvedEntryPath))
            {
                zipPath = resolvedArchivePath;
                entryPath = resolvedEntryPath;
            }

            try
            {
                return await Task.Run(async () =>
                {
                    bool handled = false;
                    string actionTaken = "";

                    if (zipPath != null && entryPath != null && _zipFileThreats.TryGetValue(zipPath, out var threatsInZip))
                    {
                        var entriesToDelete = new List<string>();
                        int quarantinedCount = 0;

                        foreach (var (EntryPath, VirusName) in threatsInZip)
                        {
                            if (EntryPath == entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(entryPath + "\\")))
                            {
                                entriesToDelete.Add(EntryPath);
                            }
                        }

                        if (entriesToDelete.Count > 0)
                        {
                            foreach (var entry in entriesToDelete)
                            {
                                try
                                {
                                    var fileData = await ArchiveScanner.ExtractEntryAsync(zipPath, entry);
                                    if (fileData != null && fileData.Length > 0)
                                    {
                                        var (_, threatVirusName) = threatsInZip.FirstOrDefault(t => t.EntryPath == entry);
                                        string virusName = threatVirusName ?? row.VirusName ?? "Unknown";
                                        string sourcePath = Path.GetDirectoryName(zipPath) + "\\" + Path.GetFileName(entry);

                                        LogText.AddNewLog(LogText.LogLevel.INFO, "Security - QuarantineZipEntry", $"Quarantining {sourcePath} from {zipPath}, size: {fileData.Length} bytes");

                                        if (await QuarantineManager.AddToQuarantineFromBytes(fileData, sourcePath, virusName, false))
                                        {
                                            quarantinedCount++;
                                            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - QuarantineZipEntry", $"Successfully quarantined {sourcePath}");
                                        }
                                        else
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - QuarantineZipEntry", $"Failed to quarantine {sourcePath}");
                                        }
                                    }
                                    else
                                    {
                                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - QuarantineZipEntry", $"Failed to extract {entry} from {zipPath}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - QuarantineZipEntry", $"Exception quarantining {entry}: {ex.Message}");
                                }
                            }

                            int deletedCount = 0;
                            if (quarantinedCount > 0)
                            {
                                deletedCount = await ArchiveScanner.DeleteMultipleEntriesFromZipAsync(zipPath, entriesToDelete);
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - DeleteZipEntries", $"Deleted {deletedCount} entries from {zipPath}");
                            }

                            if (deletedCount > 0 || quarantinedCount > 0)
                            {
                                actionTaken = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_ZipEntriesQuarantined"), quarantinedCount, deletedCount);
                                handled = true;
                            }
                        }
                    }
                    else if (await QuarantineManager.AddToQuarantine(row.FilePath, row.VirusName))
                    {
                        actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Quarantined");
                        handled = true;
                    }
                    else if (File.Exists(row.FilePath))
                    {
                        try
                        {
                            File.Delete(row.FilePath);
                            actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Deleted");
                            handled = true;
                        }
                        catch
                        {
                            try
                            {
                                if (await QuarantineManager.AddToQuarantine(row.FilePath, row.VirusName))
                                {
                                    actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Quarantined");
                                    handled = true;
                                }
                                else
                                {
                                    actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                                }
                            }
                            catch
                            {
                                actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                            }
                        }
                    }
                    else
                    {
                        actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                    }

                    return (handled, actionTaken);
                });
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - HandleSingleThreatFailed", ex.Message);
                return (false, Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed"));
            }
        }
        private void UpdateHandleAllButtonVisibility()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                UpdateSelectAllThreatsState();
                UpdateThreatListVisibility();

                bool hasSelected = false;
                if (CurrentResults != null)
                {
                    foreach (VirusRow row in CurrentResults)
                    {
                        if (!row.IsChecked) continue;
                        hasSelected = true;
                        break;
                    }
                }

                bool scanComplete = PauseScanButton.Visibility == Visibility.Collapsed
                    && ResumeScanButton.Visibility == Visibility.Collapsed;
                bool shouldShow = hasSelected && scanComplete;

                if (shouldShow)
                {
                    if (HandleAllButton.Visibility != Visibility.Visible)
                    {
                        ShowWithEntranceAnimation(HandleAllButton, "right");
                    }
                    else
                    {
                        HandleAllButton.Visibility = Visibility.Visible;
                    }
                }
                else
                {
                    HideWithVisualReset(HandleAllButton);
                }
            });
        }

        private int CountSelectedThreats()
        {
            if (CurrentResults == null) return 0;

            int count = 0;
            foreach (VirusRow row in CurrentResults)
            {
                if (row.IsChecked) count++;
            }
            return count;
        }

        private async void OnHandleAllClick(object sender, RoutedEventArgs e)
        {
            int threatCount = CountSelectedThreats();
            if (threatCount == 0) return;

            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Title"),
                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Content"), threatCount),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary) return;

            await HandleAllThreatsAsync();
        }

        private async Task HandleAllThreatsAsync()
        {
            List<VirusRow> snapshot = [];
            if (CurrentResults != null)
            {
                foreach (VirusRow row in CurrentResults)
                {
                    if (row.IsChecked) snapshot.Add(row);
                }
            }
            if (snapshot.Count == 0) return;
            int total = snapshot.Count;

            HideWithVisualReset(HandleAllButton);

            var progressRing = new ProgressRing { IsActive = true, Width = 40, Height = 40 };
            var currentFileText = new TextBlock
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12
            };
            var progressText = new TextBlock
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                FontSize = 13
            };
            var progressBar = new ProgressBar
            {
                Minimum = 0,
                Maximum = total,
                Value = 0,
                Height = 4,
                CornerRadius = new CornerRadius(2)
            };

            var progressContent = new StackPanel
            {
                Spacing = 12,
                HorizontalAlignment = HorizontalAlignment.Center,
                Children = { progressRing, currentFileText, progressBar, progressText }
            };

            var dialog = new ContentDialog
            {
                Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Title"),
                Content = progressContent,
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            _ = dialog.ShowAsync();

            int successCount = 0;
            var failedItems = new List<VirusRow>();

            for (int i = 0; i < snapshot.Count; i++)
            {
                VirusRow row = snapshot[i];
                currentFileText.Text = row.FilePath;
                progressBar.Value = i + 1;
                progressText.Text = $"{i + 1} / {total}";

                try
                {
                    var (handled, _) = await HandleSingleThreatAsync(row);

                    if (handled)
                    {
                        successCount++;

                        string displayPath = row.FilePath;
                        if (TryParseArchiveEntry(displayPath, out string zipPath, out string entryPath))
                        {
                            if (_zipFileThreats.TryGetValue(zipPath, out var threatsInZip))
                            {
                                var entriesToDelete = new List<string>();
                                foreach (var (EntryPath, VirusName) in threatsInZip)
                                {
                                    if (EntryPath == entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(entryPath + "\\")))
                                    {
                                        entriesToDelete.Add(EntryPath);
                                    }
                                }

                                foreach (var entry in entriesToDelete)
                                {
                                    VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == $"{zipPath}\\{entry}");
                                    if (itemToRemove != null)
                                    {
                                        CurrentResults.Remove(itemToRemove);
                                        _threatsFound--;
                                    }
                                }

                                _zipFileThreats.Remove(zipPath);
                            }
                        }
                        else
                        {
                            VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                            if (itemToRemove != null)
                            {
                                CurrentResults.Remove(itemToRemove);
                                _threatsFound--;
                            }
                        }
                    }
                    else
                    {
                        failedItems.Add(row);
                    }
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - HandleAllSingleFailed", $"Failed to handle {row.FilePath}: {ex.Message}");
                    failedItems.Add(row);
                }
            }

            UpdateScanStats(_filesScanned, _threatsFound);

            dialog.Hide();

            await ShowHandleAllResultDialog(successCount, failedItems);

            UpdateHandleAllButtonVisibility();
        }

        private async Task ShowHandleAllResultDialog(int successCount, List<VirusRow> failedItems)
        {
            bool allFailed = successCount == 0 && failedItems.Count > 0;
            bool hasFailures = failedItems.Count > 0;

            var contentPanel = new StackPanel { Spacing = 8 };

            var successText = new TextBlock
            {
                Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_Success"), successCount),
                TextWrapping = TextWrapping.Wrap
            };
            contentPanel.Children.Add(successText);

            if (hasFailures)
            {
                var failedHeader = new TextBlock
                {
                    Text = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_FailedHeader"),
                    Foreground = new SolidColorBrush(Microsoft.UI.Colors.Red),
                    Margin = new Thickness(0, 8, 0, 4)
                };
                contentPanel.Children.Add(failedHeader);

                var failedList = new ListView
                {
                    SelectionMode = ListViewSelectionMode.None,
                    IsItemClickEnabled = false,
                    MaxHeight = 200,
                    Padding = new Thickness(0),
                    Margin = new Thickness(0)
                };

                var compactStyle = new Style(typeof(ListViewItem));
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.PaddingProperty, Value = new Thickness(4, 2, 4, 2) });
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.MinHeightProperty, Value = 0d });
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.MarginProperty, Value = new Thickness(0) });
                failedList.ItemContainerStyle = compactStyle;

                int itemIndex = 0;
                foreach (var failed in failedItems)
                {
                    var row = new Grid
                    {
                        ColumnDefinitions =
                        {
                            new ColumnDefinition { Width = GridLength.Auto },
                            new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }
                        },
                        Padding = new Thickness(0, 2, 0, 2),
                        ColumnSpacing = 8
                    };

                    var icon = new FontIcon
                    {
                        Glyph = "\uE783",
                        FontSize = 12,
                        Foreground = new SolidColorBrush(Microsoft.UI.Colors.Red),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    Grid.SetColumn(icon, 0);

                    var pathText = new TextBlock
                    {
                        Text = failed.FilePath,
                        TextWrapping = TextWrapping.Wrap,
                        IsTextSelectionEnabled = true,
                        FontSize = 13
                    };
                    Grid.SetColumn(pathText, 1);

                    row.Children.Add(icon);
                    row.Children.Add(pathText);

                    int delay = itemIndex * 15;
                    row.Loaded += (s, e) => App.PlayEntranceAnimation(row, "up", delayMs: delay);

                    failedList.Items.Add(row);
                    itemIndex++;
                }

                contentPanel.Children.Add(failedList);

                var tipText = new TextBlock
                {
                    Text = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_FailedTip"),
                    FontSize = 12,
                    Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                };
                contentPanel.Children.Add(tipText);
            }

            ContentDialog resultDialog = new()
            {
                Title = allFailed
                    ? Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_AllFailed_Title")
                    : Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_Title"),
                Content = new ScrollViewer { Content = contentPanel },
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Close
            };

            await resultDialog.ShowAsync();
        }

        private void UpdateScanStats(int filesScanned, int threatsFound)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                int threatForDisplay = CurrentResults?.Count ?? threatsFound;

                _filesScanned = filesScanned;
                _threatsFound = threatsFound;
                try
                {
                    // 优先使用缓存的格式字符串（扫描期间已初始化），回退到实时查询以支持非扫描上下文调用
                    ScanStatsText.Text = string.Format(
                        _fmtScanSummary ?? Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Format"),
                        filesScanned, _scanElapsedSeconds, _scanSpeed, threatForDisplay);
                }
                catch { }
            });
        }

        private async void OnScanMenuClick(object sender, RoutedEventArgs e)
        {
            ApplicationDataContainer settings = App.LocalSettings;
            bool UseLocalScan = settings.Values.TryGetValue("LocalScan", out object? localRaw) && localRaw is bool local && local;
            bool UseCloudScan = settings.Values.TryGetValue("CloudScan", out object? cloudRaw) && cloudRaw is bool cloud && cloud;
            bool UseModelScan = settings.Values.TryGetValue("ModelScan", out object? modelRaw) && modelRaw is bool model && model;
            if (!UseLocalScan && !UseCloudScan && !UseModelScan)
            {
                ContentDialog dialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Title"),
                    Content = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Content"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                };
                _ = dialog.ShowAsync();
                return;
            }

            if (sender is not MenuFlyoutItem { Tag: string tag }) return;
            ScanMode mode = tag switch
            {
                "Quick" => ScanMode.Quick,
                "Full" => ScanMode.Full,
                "File" => ScanMode.File,
                "Folder" => ScanMode.Folder,
                _ => ScanMode.More
            };

            if (mode == ScanMode.More)
            {
                IReadOnlyList<string> paths = await ShowMoreScanDialogAsync();
                if (paths.Count > 0)
                {
                    await StartScanAsync(Localizer.Get().GetLocalizedString("SecurityPage_ScanMenu_More"), ScanMode.More, paths);
                }
                return;
            }

            await StartScanAsync(((MenuFlyoutItem)sender).Text, mode);
        }

        private async void ScanButton_Click(SplitButton sender, SplitButtonClickEventArgs e)
        {
            ApplicationDataContainer settings = App.LocalSettings;
            bool UseLocalScan = settings.Values.TryGetValue("LocalScan", out object? localRaw) && localRaw is bool local && local;
            bool UseCloudScan = settings.Values.TryGetValue("CloudScan", out object? cloudRaw) && cloudRaw is bool cloud && cloud;
            bool UseModelScan = settings.Values.TryGetValue("ModelScan", out object? modelRaw) && modelRaw is bool model && model;
            if (!UseLocalScan && !UseCloudScan && !UseModelScan)
            {
                ContentDialog dialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Title"),
                    Content = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Content"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                };
                _ = dialog.ShowAsync();
                return;
            }

            await StartScanAsync(Localizer.Get().GetLocalizedString("SecurityPage_ScanMenu_Quick"), ScanMode.Quick);
        }

        private static IEnumerable<string> EnumerateFilesStreaming(ScanMode mode, string? userPath, IReadOnlyList<string>? customPaths)
        {
            switch (mode)
            {
                case ScanMode.Quick:
                    foreach (string f in GetEnumerateQuickScanFiles()) yield return f;
                    yield break;
                case ScanMode.Full:
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                    {
                        if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                            continue;
                        foreach (string file in SafeEnumerateFiles(drive.RootDirectory.FullName, [with(StringComparer.OrdinalIgnoreCase)]))
                            yield return file;
                    }
                    yield break;
                case ScanMode.File:
                    if (customPaths != null)
                    {
                        foreach (string p in customPaths)
                        {
                            if (System.IO.File.Exists(p)) yield return p;
                        }
                    }
                    yield break;
                case ScanMode.Folder:
                    if (userPath != null && Directory.Exists(userPath))
                    {
                        foreach (string f in SafeEnumerateFolder(userPath)) yield return f;
                    }
                    yield break;
                case ScanMode.More:
                    if (customPaths != null)
                    {
                        foreach (string p in customPaths)
                        {
                            if (Directory.Exists(p))
                            {
                                foreach (string f in SafeEnumerateFolder(p)) yield return f;
                            }
                            else if (System.IO.File.Exists(p))
                            {
                                yield return p;
                            }
                        }
                    }
                    yield break;
                default:
                    yield break;
            }
        }

        private async Task<IReadOnlyList<string>> ShowMoreScanDialogAsync()
        {
            ObservableCollection<MoreScanItem> items = [];
            ListView listView = new()
            {
                ItemTemplate = Resources["MoreScanListTemplate"] as DataTemplate,
                ItemsSource = items,
                Height = 240
            };

            Button browseFolderButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_BrowseFolder") };
            browseFolderButton.Click += OnMoreScanBrowseFolderClick;
            Button browseFileButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_BrowseFile") };
            browseFileButton.Click += OnMoreScanBrowseFileClick;
            Button removeFileButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_RemoveItem") };
            removeFileButton.Click += OnMoreScanRemovePathClick;
            Button clearButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_ClearAll"), IsEnabled = false };
            clearButton.Click += OnMoreScanClearClick;

            items.CollectionChanged += (s, e) =>
            {
                clearButton.IsEnabled = items.Count > 0;
            };

            Grid contentGrid = new() { RowSpacing = 12 };
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            Grid.SetRow(listView, 0);

            StackPanel buttonPanel = new()
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Children = { browseFolderButton, browseFileButton, removeFileButton, clearButton }
            };
            Grid.SetRow(buttonPanel, 1);

            contentGrid.Children.Add(listView);
            contentGrid.Children.Add(buttonPanel);

            _moreScanDialog = new ContentDialog
            {
                Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                Title = Localizer.Get().GetLocalizedString("SecurityPage_MoreScan_Title"),
                Content = contentGrid,
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_StartScanButton"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                Width = 600,
                Height = 450
            };

            ContentDialogResult result = await _moreScanDialog.ShowAsync();
            _moreScanDialog = null;

            if (result == ContentDialogResult.Primary)
            {
                return (string[])[.. items.Select(i => i.Path)];
            }
            return [];
        }

        private void OnMoreScanRemovePathClick(object sender, RoutedEventArgs e)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.SelectedItem is MoreScanItem item)
            {
                if (listView.ItemsSource is ObservableCollection<MoreScanItem> items)
                {
                    items.Remove(item);
                }
            }
        }

        private async void OnMoreScanBrowseFolderClick(object sender, RoutedEventArgs e)
        {
            IReadOnlyList<string> folders = await PickFoldersAsync();
            if (folders.Count == 0) return;
            AddPathsToMoreScanList(folders, true);
        }

        private async void OnMoreScanBrowseFileClick(object sender, RoutedEventArgs e)
        {
            IReadOnlyList<string> files = await PickFilesAsync();
            if (files.Count == 0) return;
            AddPathsToMoreScanList(files, false);
        }

        private void AddPathsToMoreScanList(IReadOnlyList<string> paths, bool isFolder)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is not ObservableCollection<MoreScanItem> items) return;

            HashSet<string> existingPaths = new(items.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);
            string? duplicatePath = null;

            foreach (string path in paths)
            {
                if (existingPaths.Add(path))
                {
                    items.Add(new MoreScanItem { Path = path, IsFolder = isFolder });
                }
                else if (duplicatePath is null)
                {
                    duplicatePath = path;
                }
            }

            if (duplicatePath is not null)
            {
                ContentDialog dup = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Title"),
                    Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Content"), duplicatePath),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                };
                _ = dup.ShowAsync();
            }
        }

        private void OnMoreScanClearClick(object sender, RoutedEventArgs e)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is ObservableCollection<MoreScanItem> items)
            {
                items.Clear();
            }
        }

        private T? FindChild<T>(DependencyObject? parent) where T : DependencyObject
        {
            if (parent == null) return null;

            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild)
                    return typedChild;

                T? result = FindChild<T>(child);
                if (result != null)
                    return result;
            }
            return null;
        }

        internal record ScanResult(string EngineName, string? VirusInfo, string? FamilyInfo = null);

        // Run configured scan engines against a single file and return the first detection (if any).
        internal static async Task<ScanResult> RunScansOnFileAsync(string filePath, Byte[]? _fileBytes, string? md5Hash,
            bool deepScan, bool extraData,
            bool useLocalScan, bool useCloudScan, bool useModelScan,
            bool _useInfectorCleaner, bool useVirusFamily,
            Helper.ScanEngine.ModelEngineScan? modelEngine,
            CancellationToken token)
        {
            try
            {
                // Intentionally reference parameters that are not used in all code paths to avoid IDE0060 warnings.
                _ = _fileBytes;
                _ = _useInfectorCleaner;
                token.ThrowIfCancellationRequested();

                if (useCloudScan && md5Hash == null)
                {
                    try { md5Hash = await ScanEngine.GetFileMD5Async(filePath).WaitAsync(token); } catch { }
                }

                token.ThrowIfCancellationRequested();

                var scanTasks = new List<Task<ScanResult>>();

                if (useModelScan && modelEngine != null)
                {
                    scanTasks.Add(Task.Run(() =>
                    {
                        (bool isVirus, string result) = ScanEngine.ModelEngineScan.ScanFile(filePath);
                        return new ScanResult(ScanEngine.ModelEngineScan.GetEngineDisplayName(), isVirus ? result : null);
                    }, token));
                }

                if (useLocalScan)
                {
                    scanTasks.Add(Helper.ScanEngine.LocalScanAsync(filePath, deepScan, extraData)
                        .ContinueWith(t =>
                        {
                            string localResult = t.Result;
                            string? info = !string.IsNullOrEmpty(localResult) ? (deepScan ? $"{localResult} with DeepScan" : localResult) : null;
                            return new ScanResult("Local", info);
                        }, TaskScheduler.Default));
                }

                if (useCloudScan && md5Hash != null)
                {
                    scanTasks.Add(Helper.ScanEngine.CloudScanWithHashAsync(md5Hash).ContinueWith(t =>
                    {
                        (int? statusCode, string? result) = t.Result;
                        string? info = (result == "virus_file") ? "MEMZUAC.Cloud.VirusFile" : null;
                        return new ScanResult("Cloud", info);
                    }, TaskScheduler.Default));
                }

                if (scanTasks.Count == 0)
                    return new ScanResult(string.Empty, null);

                ScanResult[] results;
                try
                {
                    results = await Task.WhenAll(scanTasks).WaitAsync(token);
                }
                catch (OperationCanceledException) { return new ScanResult(string.Empty, null); }
                catch
                {
                    return new ScanResult(string.Empty, null);
                }

                foreach (var r in results)
                {
                    if (!string.IsNullOrEmpty(r.VirusInfo))
                    {
                        if (useVirusFamily)
                        {
                            try
                            {
                                string familyResult = Xdows_Local.VirusFamilyEngine.GetVirusFamily(filePath, 0.8f);
                                if (!familyResult.StartsWith("HEUR:Malware"))
                                    return r with { FamilyInfo = familyResult };
                                return r with { FamilyInfo = Localizer.Get().GetLocalizedString("AllPage_Undefined") };
                            }
                            catch { }
                        }
                        return r;
                    }
                }

                return new ScanResult(string.Empty, null);
            }
            catch (OperationCanceledException) { return new ScanResult(string.Empty, null); }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - RunScansOnFileFailed", ex.Message);
                return new ScanResult(string.Empty, null);
            }
        }

        private async Task ScanArchiveFileAsync(int scanId, string archivePath, bool deepScan, bool extraData, bool useLocalScan, bool useCloudScan, bool useModelScan, bool useInfectorCleaner, bool useVirusFamily, Helper.ScanEngine.ModelEngineScan? modelEngine, SemaphoreSlim scanGate, CancellationToken token)
        {
            try
            {
                List<(string EntryPath, byte[] Data)>? entries = null;
                string? password = null;

                try
                {
                    entries = await ArchiveScanner.ReadArchiveEntriesAsync(archivePath, true, password, token);
                }
                catch (ArchivePasswordRequiredException)
                {
                    // 释放 scanGate，让其他扫描任务可以并行进行，不阻塞 Dialog 等待期间
                    scanGate.Release();
                    string? enteredPassword = null;
                    try
                    {
                        enteredPassword = await AskArchivePasswordAsync(archivePath, scanId, token);
                    }
                    finally
                    {
                        // 无论用户输入密码、跳过还是扫描被取消，都必须重新获取 scanGate
                        try { await scanGate.WaitAsync(CancellationToken.None); } catch { }
                    }

                    if (string.IsNullOrEmpty(enteredPassword))
                        return;

                    password = enteredPassword;
                    entries = await ArchiveScanner.ReadArchiveEntriesAsync(archivePath, true, password, token);
                }

                if (entries == null) return;

                foreach (var (entryPath, data) in entries)
                {
                    // respect pause and cancellation (零轮询信号等待)
                    while (_isPaused && !token.IsCancellationRequested)
                        await WaitWhilePausedAsync(token);
                    if (token.IsCancellationRequested) break;

                    string displayPath = $"{archivePath}\\{entryPath}";
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(scanId, token)) return;
                        LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ScanFile", displayPath);
                    });

                    string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    try
                    {
                        await File.WriteAllBytesAsync(tempFile, data, token);

                        if (TrustManager.IsPathTrusted(tempFile))
                        {
                            continue;
                        }

                        // ZIP entry already has bytes in memory - compute MD5 once, pass to all engines
                        string entryMd5 = ScanEngine.ComputeMD5(data);
                        var scanRes = await RunScansOnFileAsync(tempFile, data, entryMd5, deepScan, extraData, useLocalScan, useCloudScan, useModelScan, useInfectorCleaner, useVirusFamily, modelEngine, token);
                        string? virusResult = scanRes.VirusInfo;
                        if (!string.IsNullOrEmpty(virusResult))
                        {
                            Interlocked.Increment(ref Statistics.ScansQuantity);
                            Interlocked.Increment(ref Statistics.VirusQuantity);

#if DEBUG
                            _ = CopyVirusSampleForTestAsync(displayPath, bytes: data);
#endif

                            lock (_zipFileThreats)
                            {
                                if (!_zipFileThreats.ContainsKey(archivePath))
                                    _zipFileThreats[archivePath] = [];
                                _zipFileThreats[archivePath].Add((entryPath, virusResult));
                            }

                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                if (!IsCurrentScan(scanId, token)) return;
                                AddVirusResult($"{archivePath}\\{entryPath}", virusResult, scanRes.FamilyInfo, scanRes.EngineName, useVirusFamily);
                                ShowBackToVirusListButton();
                            });

                            Interlocked.Increment(ref _threatsFound);
                            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - Find", $"ZIP Entry: {entryPath} - {virusResult}");
                        }

                        // ZIP entry should count as one completed scan unit for UI statistics.
                        Interlocked.Increment(ref _filesScanned);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanZipEntryFailed", ex.Message);
                    }
                    finally
                    {
                        try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanZipFailed", ex.Message);
            }
        }

        private async Task<string?> AskArchivePasswordAsync(string archivePath, int scanId, CancellationToken token)
        {
            var tcs = new TaskCompletionSource<string?>();

            _dispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    if (!IsCurrentScan(scanId, token))
                    {
                        tcs.TrySetResult(null);
                        return;
                    }

                    var passwordBox = new PasswordBox
                    {
                        PlaceholderText = Localizer.Get().GetLocalizedString("SecurityPage_ArchivePassword_Placeholder"),
                        Width = 300,
                        Margin = new Thickness(0, 8, 0, 0)
                    };

                    var dialog = new ContentDialog
                    {
                        Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                        Title = $"{Localizer.Get().GetLocalizedString("SecurityPage_ArchivePassword_Title")} — {Path.GetFileName(archivePath)}",
                        Content = passwordBox,
                        PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        SecondaryButtonText = Localizer.Get().GetLocalizedString("Button_Skip"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Primary
                    };

                    var result = await dialog.ShowAsync();
                    if (result == ContentDialogResult.Primary)
                    {
                        tcs.TrySetResult(passwordBox.Password);
                    }
                    else
                    {
                        tcs.TrySetResult(null);
                    }
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });

            using var registration = token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task;
        }

        public async Task StartScanAsync(string displayName, ScanMode mode, IReadOnlyList<string>? customPaths = null)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            int thisId = Interlocked.Increment(ref _scanId);
            _isPaused = false;
            _pauseEvent.Set();
            _zipFileThreats.Clear();
            // 缓存 UI 格式化字符串，避免扫描期间每次 UpdateScanStats 都查询本地化资源
            _fmtScanSummary = Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Format");
            _fmtScanSummaryCompleted = Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Completed");
            _scanElapsedSeconds = 0;
            _scanSpeed = 0;

            var settings = App.LocalSettings;
            bool showScanProgress = settings.Values.TryGetValue("ShowScanProgress", out object? showProgressRaw) && showProgressRaw is bool showProgress && showProgress;
            bool showTaskbarProgress = !settings.Values.TryGetValue("ShowTaskbarScanProgress", out object? taskbarRaw) || taskbarRaw is not bool taskbar || taskbar;
            string scanIndexMode = settings.Values.TryGetValue("ScanIndexMode", out object? indexModeRaw) && indexModeRaw is string indexMode ? indexMode : "Parallel";
            bool useFastIndexing = !settings.Values.TryGetValue("UseFastIndexing", out object? fastIndexRaw) || fastIndexRaw is not bool fastIndex || fastIndex;
            bool DeepScan = settings.Values.TryGetValue("DeepScan", out object? deepRaw) && deepRaw is bool deep && deep;
            bool ExtraData = settings.Values.TryGetValue("ExtraData", out object? extraRaw) && extraRaw is bool extra && extra;
            bool UseLocalScan = settings.Values.TryGetValue("LocalScan", out object? localRaw) && localRaw is bool local && local;
            bool UseCloudScan = settings.Values.TryGetValue("CloudScan", out object? cloudRaw) && cloudRaw is bool cloud && cloud;
            bool UseModelScan = !settings.Values.TryGetValue("ModelScan", out object? modelRaw) || modelRaw is not bool model || model;
            bool UseInfectorCleaner = settings.Values.TryGetValue("InfectorCleaner", out object? cleanerRaw) && cleanerRaw is bool cleaner && cleaner;
            bool UseVirusFamily = settings.Values.TryGetValue("VirusFamily", out object? familyRaw) && familyRaw is bool family && family;
            bool UseExactRule = settings.Values.TryGetValue("ExactRuleScan", out object? exactRaw) && exactRaw is bool exact && exact;

            Helper.ScanEngine.ModelEngineScan? ModelEngine = null;

            if (UseModelScan)
            {
                ModelEngine = new Helper.ScanEngine.ModelEngineScan();
                if (!ScanEngine.ModelEngineScan.Initialize())
                {
                    _dispatcherQueue.TryEnqueue(async () =>
                    {
                        var dialog = new ContentDialog
                        {
                            Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                            Title = Localizer.Get().GetLocalizedString("SecurityPage_Model_InitFailed_Title"),
                            Content = Localizer.Get().GetLocalizedString("SecurityPage_InitFailed_Content"),
                            PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                            XamlRoot = this.XamlRoot,
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            DefaultButton = ContentDialogButton.Primary
                        };
                        await dialog.ShowAsync();
                    });
                    return;
                }
            }
            var enginesLog = "Use";
            if (UseLocalScan) enginesLog += DeepScan ? " LocalScan-DeepScan" : " LocalScan";
            if (UseCloudScan) enginesLog += " CloudScan";
            if (UseModelScan)
            {
                string modeTag = Helper.ScanEngine.ModelEngineScan.Mode switch
                {
                    Xdows_Model_Invoker.ModelMode.Flash => "Flash",
                    Xdows_Model_Invoker.ModelMode.Adaptive => "Adaptive",
                    Xdows_Model_Invoker.ModelMode.Pro => "Pro",
                    _ => "Flash"
                };
                enginesLog += $" Xdows-Model-{modeTag}";
            }
            if (UseInfectorCleaner) enginesLog += " InfectorCleaner";
            if (UseVirusFamily) enginesLog += " VirusFamily";
            if (UseExactRule) enginesLog += " ExactRule";
            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - StartScan", enginesLog);

            _dispatcherQueue.TryEnqueue(() =>
            {
                VirusList.ItemTemplate = (DataTemplate)Resources["VirusRowTemplate"];
            });

            if (showTaskbarProgress)
            {
                _taskbarProgressActive = true;
                _lastShowScanProgress = showScanProgress;
                try
                {
                    if (showScanProgress)
                    {
                        TaskbarProgressService.TrySetNormal(0);
                    }
                    else
                    {
                        TaskbarProgressService.TrySetIndeterminate();
                    }
                }
                catch { }
            }
            else
            {
                _lastShowScanProgress = showScanProgress;
                ClearTaskbarProgress();
            }

            string? userPath = null;
            bool pathSelectionCancelled = false;
            if (mode == ScanMode.File)
            {
                // 文件扫描支持多选，选中的文件通过 customPaths 传入扫描流程
                IReadOnlyList<string> files = await PickFilesAsync();
                if (files.Count == 0)
                    pathSelectionCancelled = true;
                else
                    customPaths = files;
            }
            else if (mode == ScanMode.Folder)
            {
                userPath = await PickFolderAsync();
                if (string.IsNullOrEmpty(userPath))
                    pathSelectionCancelled = true;
            }

            if (pathSelectionCancelled)
            {
                _dispatcherQueue.TryEnqueue(() =>
                {
                    StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Idle");
                });
                return;
            }

            ScanButton.IsEnabled = false;

            _filesScanned = 0; _threatsFound = 0;
            _scanTotalFiles = 0;
            UpdateScanStats(0, 0);

            CurrentResults = [];
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = CurrentResults;
                SelectAllThreatsCheckBox.IsChecked = true;
                ScanProgress.Value = 0;
                ScanProgress.ShowPaused = false;
                ScanProgress.Visibility = Visibility.Visible;
                UpdateThreatListVisibility();
                HideWithVisualReset(BackToVirusListButton);
                ShowWithEntranceAnimation(PauseScanButton, "right");
                ShowWithEntranceAnimation(CancelScanButton, "right");
                CancelScanButton.IsEnabled = true;
                CancelScanButtonIcon.Visibility = Visibility.Visible;
                CancelScanButtonRing.IsActive = false;
                CancelScanButtonRing.Visibility = Visibility.Collapsed;
                PauseScanButton.IsEnabled = false;
                HideWithVisualReset(ResumeScanButton);
                StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Processing");
                HideWithVisualReset(HandleAllButton);
            });

            _isScanRunning = true;

            await Task.Run(async () =>
            {
                try
                {
                    bool parallelIndex = scanIndexMode == "Parallel";

                    IEnumerable<string> files;
                    int total;
                    if (!parallelIndex && useFastIndexing && TryEnumerateFilesUsingNtfsTable(mode, userPath, customPaths, out IReadOnlyList<string> indexedFiles))
                    {
                        files = indexedFiles;
                        total = indexedFiles.Count;
                    }
                    else
                    {
                        files = EnumerateFilesStreaming(mode, userPath, customPaths);
                        total = parallelIndex ? 0 : CountFiles(mode, userPath, customPaths);
                    }

                    _scanTotalFiles = total;

                    DateTime startTime = DateTime.Now;
                    DateTime lastSpeedUpdateUtc = DateTime.UtcNow;
                    int lastSpeedScanned = 0;

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        PauseScanButton.IsEnabled = true;
                        // 索引结束、真正开始扫描时把顶部标题换成扫描阶段
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning");
                    });

                    long pausedTicks = 0;             // 累计暂停时长（ticks），被并行分支共享，只能原子累加
                    long pauseStartedTicks = 0;       // 0 表示当前没有进行中的暂停计时
                    bool ScanInside = settings.Values.TryGetValue("ScanInside", out object? scanInsideRaw) && scanInsideRaw is bool scanInside && scanInside;

                    // 双层并行架构：
                    // 外层高并发：枚举+TrustCheck快速跳过 → 维持200+/秒吞吐
                    // 内层scanGate：限制真正扫描并发(PeFile/模型/云) → 内存<100MB
                    // 不预读文件到内存，由引擎自行按需读取
                    int outerParallelism = Math.Max(16, Environment.ProcessorCount * 8);
                    int scanConcurrency = Math.Clamp(Environment.ProcessorCount, 2, 10);
                    var scanGate = new SemaphoreSlim(scanConcurrency, scanConcurrency);
                    DateTime lastUiUpdate = DateTime.MinValue;
                    const int UI_UPDATE_INTERVAL_MS = 150;

                    // 精准规则引擎批量预检通道
                    int hashConcurrency = Math.Clamp(Environment.ProcessorCount, 2, 8);
                    var hashGate = new SemaphoreSlim(hashConcurrency, hashConcurrency);
                    var exactRuleChannel = Channel.CreateUnbounded<(string filePath, string sha256, TaskCompletionSource<(string? result, string? family)> tcs)>();
                    Task? exactRuleBatchTask = null;
                    if (UseExactRule)
                    {
                        exactRuleBatchTask = Task.Run(async () =>
                        {
                            var batch = new List<(string filePath, string sha256, TaskCompletionSource<(string? result, string? family)> tcs)>();
                            var reader = exactRuleChannel.Reader;
                            try
                            {
                                while (await reader.WaitToReadAsync(token))
                                {
                                    while (reader.TryRead(out var item))
                                    {
                                        batch.Add(item);
                                        if (batch.Count >= 50) break;
                                    }
                                    if (batch.Count > 0)
                                    {
                                        try
                                        {
                                            var hashEntries = batch.Select(b => (b.filePath, b.sha256)).ToList();
                                            var batchResults = await Helper.ScanEngine.ExactRuleEngineBatchScanHashesAsync(hashEntries, token);
                                            foreach (var (filePath, sha256, tcs) in batch)
                                            {
                                                if (batchResults.TryGetValue(filePath, out var r)) tcs.TrySetResult(r);
                                                else tcs.TrySetResult((null, null));
                                            }
                                        }
                                        catch (OperationCanceledException)
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleBatchCanceled", $"Batch of {batch.Count} files canceled");
                                            foreach (var (_, _, tcs) in batch) tcs.TrySetCanceled(token);
                                            break;
                                        }
                                        catch (Exception ex)
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleBatchFailed", $"Batch of {batch.Count} files failed: {ex.Message}");
                                            foreach (var (filePath, sha256, tcs) in batch) tcs.TrySetResult((null, null));
                                        }
                                        batch.Clear();
                                    }
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleWorkerCanceled", "Batch worker canceled");
                                foreach (var (_, _, tcs) in batch) tcs.TrySetCanceled(token);
                            }
                            catch (ChannelClosedException)
                            {
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ExactRuleChannelClosed", "Channel closed normally");
                            }
                            catch (Exception ex)
                            {
                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleWorkerError", ex.Message);
                                foreach (var (_, _, tcs) in batch) tcs.TrySetResult((null, null));
                            }
                            if (batch.Count > 0)
                            {
                                try
                                {
                                    var hashEntries = batch.Select(b => (b.filePath, b.sha256)).ToList();
                                    var batchResults = await Helper.ScanEngine.ExactRuleEngineBatchScanHashesAsync(hashEntries, token);
                                    foreach (var (filePath, _, tcs) in batch)
                                    {
                                        if (batchResults.TryGetValue(filePath, out var r)) tcs.TrySetResult(r);
                                        else tcs.TrySetResult((null, null));
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    foreach (var (filePath, sha256, tcs) in batch) tcs.TrySetCanceled(token);
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleFinalBatchFailed", $"Final batch of {batch.Count} files failed: {ex.Message}");
                                    foreach (var (_, _, tcs) in batch) tcs.TrySetResult((null, null));
                                }
                            }
                        }, token);
                    }

                    await Parallel.ForEachAsync(files, new ParallelOptions
                    {
                        MaxDegreeOfParallelism = outerParallelism,
                        CancellationToken = token
                    }, async (file, ct) =>
                    {
                        while (_isPaused && !ct.IsCancellationRequested)
                        {
                            if (Interlocked.Read(ref pauseStartedTicks) == 0)
                                Interlocked.CompareExchange(ref pauseStartedTicks, DateTime.Now.Ticks, 0);
                            await WaitWhilePausedAsync(ct);
                        }
                        if (ct.IsCancellationRequested) return;

                        // 用 Exchange 一次性取走暂停起点：并行分支之间若先读后改，
                        // 会把已经清零的起点当成 DateTime.MinValue 再算一次，pausedTicks 会变成「从公元 1 年起」的跨度
                        long pauseStart = Interlocked.Exchange(ref pauseStartedTicks, 0);
                        if (pauseStart != 0)
                            Interlocked.Add(ref pausedTicks, DateTime.Now.Ticks - pauseStart);

                        if (!IsCurrentScan(thisId, ct)) return;

                        bool shouldUpdateUi = (DateTime.UtcNow - lastUiUpdate).TotalMilliseconds >= UI_UPDATE_INTERVAL_MS;
                        if (shouldUpdateUi)
                        {
                            lastUiUpdate = DateTime.UtcNow;
                        }

                        // 快速路径：受信任文件直接跳过，不进scanGate，零内存开销
                        if (TrustManager.IsPathTrusted(file))
                        {
                            Interlocked.Increment(ref _filesScanned);
                            if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _threatsFound); } catch { }
                            return;
                        }

                        // 快速路径：精准规则引擎批量预检，在scanGate外执行
                        if (UseExactRule)
                        {
                            bool exactRuleSuccess = false;
                            string? sha256Hash = null;
                            try
                            {
                                await hashGate.WaitAsync(ct);
                                try
                                {
                                    sha256Hash = await Helper.ScanEngine.GetFileSHA256Async(file, ct);
                                    exactRuleSuccess = true;
                                }
                                catch (OperationCanceledException)
                                {
                                    throw;
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleHashFailed", $"Hash computation failed for {file}: {ex.Message}");
                                    exactRuleSuccess = false;
                                }
                                finally
                                {
                                    hashGate.Release();
                                }

                                if (!exactRuleSuccess)
                                {
                                    // Hash computation failed, skip exact rule processing and fall through to normal scan
                                }
                                else
                                {
                                    var tcs = new TaskCompletionSource<(string? result, string? family)>(TaskCreationOptions.RunContinuationsAsynchronously);
                                    if (!exactRuleChannel.Writer.TryWrite((file, sha256Hash!, tcs)))
                                    {
                                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleChannelWriteFailed", $"Failed to write to channel for {file}");
                                        tcs.TrySetResult((null, null));
                                    }

                                    string? result = null;
                                    string? family = null;
                                    try
                                    {
                                        var (r, f) = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(2), ct);
                                        result = r;
                                        family = f;
                                        exactRuleSuccess = true;
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        exactRuleSuccess = false;
                                    }
                                    catch (Exception ex)
                                    {
                                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleTimeout", $"Timeout waiting for result for {file}: {ex.Message}");
                                        exactRuleSuccess = false;
                                    }

                                    if (exactRuleSuccess && !string.IsNullOrEmpty(result) && result != "safe")
                                    {
                                        Interlocked.Increment(ref Statistics.ScansQuantity);
                                        Interlocked.Increment(ref Statistics.VirusQuantity);
                                        string familyInfo = (UseVirusFamily && !string.IsNullOrEmpty(family)) ? family : string.Empty;

#if DEBUG
                                        _ = CopyVirusSampleForTestAsync(file, sourceFilePath: file);
#endif

                                        _dispatcherQueue.TryEnqueue(() =>
                                        {
                                            if (!IsCurrentScan(thisId, token)) return;
                                            try
                                            {
                                                AddVirusResult(file, result, familyInfo, "ExactRule", UseVirusFamily);
                                                ShowBackToVirusListButton();
                                            }
                                            catch { }
                                        });
                                        Interlocked.Increment(ref _threatsFound);
                                        Interlocked.Increment(ref _filesScanned);
                                        if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _threatsFound); } catch { }
                                        return;
                                    }
                                    else if (exactRuleSuccess && result == "safe")
                                    {
                                        Interlocked.Increment(ref _filesScanned);
                                        if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _threatsFound); } catch { }
                                        return;
                                    }
                                }
                            }
                            catch (OperationCanceledException) { }
                            catch (Exception ex)
                            {
                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleError", $"ExactRule processing failed for {file}: {ex.Message}");
                            }
                        }

                        if (ScanInside && ArchiveScanner.IsArchiveFile(file))
                        {
                            // 取消时 WaitAsync 会抛 TaskCanceledException。这一句在任何 try 之外，
                            // 异常会穿过 Parallel 的分支循环（调试器在抛出点就中断），而取消只需要放弃本次迭代
                            try { await scanGate.WaitAsync(ct); }
                            catch (OperationCanceledException) { return; }
                            try
                            {
                                await ScanArchiveFileAsync(thisId, file, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, scanGate, ct);
                            }
                            catch (OperationCanceledException) { }
                            finally { scanGate.Release(); }
                            return;
                        }

                        // 重扫描：scanGate限制并发，不预读文件，由引擎按需读取
                        // 取消走这里返回，不要让 TaskCanceledException 从并行体抛出去
                        try { await scanGate.WaitAsync(ct); }
                        catch (OperationCanceledException) { return; }
                        try
                        {
                            var scanRes = await RunScansOnFileAsync(file, null, null, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, ct);
                            Interlocked.Increment(ref Statistics.ScansQuantity);
                            if (!string.IsNullOrEmpty(scanRes.VirusInfo))
                            {
                                Interlocked.Increment(ref Statistics.VirusQuantity);

#if DEBUG
                                _ = CopyVirusSampleForTestAsync(file, sourceFilePath: file);
#endif

                                if (UseInfectorCleaner)
                                {
                                    try
                                    {
                                        var detection = Helper.InfectorCleaner.InfectorDetector.DetectInfector(file);
                                        if (detection.IsInfected)
                                        {
                                            var cleanResult = Helper.InfectorCleaner.InfectorCleaner.CleanInfectedFile(file);
                                            if (cleanResult.Success)
                                            {
                                                if (cleanResult.OriginalFileData != null)
                                                {
                                                    string threatName = $"Infector.{cleanResult.MaliciousSection?.TrimStart('.') ?? "Unknown"}!ml";
                                                    _ = TrustQuarantine.QuarantineManager.AddToQuarantineFromBytes(
                                                        cleanResult.OriginalFileData, file, threatName, false);
                                                }
                                                scanRes = new ScanResult(scanRes.EngineName, $"{scanRes.VirusInfo} [Cleaned: OEP=0x{cleanResult.OriginalEntryPoint:X8}, Section={cleanResult.MaliciousSection}]");
                                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - InfectorCleaned", cleanResult.Message);
                                            }
                                            else
                                            {
                                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - InfectorCleanFailed", cleanResult.Message);
                                            }
                                        }
                                    }
                                    catch (Exception cleanEx)
                                    {
                                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - InfectorCleanError", cleanEx.Message);
                                    }
                                }

                                _dispatcherQueue.TryEnqueue(() =>
                                {
                                    if (!IsCurrentScan(thisId, token)) return;
                                    AddVirusResult(file, scanRes.VirusInfo ?? string.Empty, scanRes.FamilyInfo, scanRes.EngineName, UseVirusFamily);
                                    ShowBackToVirusListButton();
                                });
                                Interlocked.Increment(ref _threatsFound);
                            }
                            else
                            {
                            }
                        }
                        catch (OperationCanceledException) { }
                        catch (Exception ex)
                        {
                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanFailed", ex.Message);
                        }
                        finally
                        {
                            scanGate.Release();
                        }

                        Interlocked.Increment(ref _filesScanned);

                        if (shouldUpdateUi)
                        {
                            TimeSpan elapsedTime = DateTime.Now - startTime - TimeSpan.FromTicks(Interlocked.Read(ref pausedTicks));
                            DateTime nowUtc = DateTime.UtcNow;
                            double scanSpeed = 0.0;
                            double speedWindowSeconds = (nowUtc - lastSpeedUpdateUtc).TotalSeconds;
                            if (speedWindowSeconds >= 1.0)
                            {
                                int nowScanned = _filesScanned;
                                int delta = nowScanned - lastSpeedScanned;
                                scanSpeed = speedWindowSeconds > 0 ? delta / speedWindowSeconds : 0.0;
                                lastSpeedScanned = nowScanned;
                                lastSpeedUpdateUtc = nowUtc;
                                _scanSpeed = scanSpeed;
                            }
                            _scanElapsedSeconds = elapsedTime.TotalSeconds;

                            if (showScanProgress)
                            {
                                double percent = total == 0 ? 100 : (double)_filesScanned / total * 100;
                                if (percent > 100) percent = 100;
                                _dispatcherQueue.TryEnqueue(() =>
                                {
                                    try { ScanProgress.Value = percent; } catch { }
                                });

                                if (showTaskbarProgress && !_isPaused)
                                {
                                    try { TaskbarProgressService.TrySetNormal(percent / 100.0); } catch { }
                                }
                            }

                            try { UpdateScanStats(_filesScanned, _threatsFound); } catch { }
                        }
                    });
                    if (UseExactRule)
                    {
                        try { exactRuleChannel.Writer.Complete(); } catch { }
                        try { if (exactRuleBatchTask != null) await exactRuleBatchTask.WaitAsync(TimeSpan.FromSeconds(10), token); } catch { }
                    }
                    scanGate.Dispose();
                    hashGate.Dispose();

                    TimeSpan totalElapsed = DateTime.Now - startTime - TimeSpan.FromTicks(Interlocked.Read(ref pausedTicks));
                    double totalSeconds = totalElapsed.TotalSeconds;
                    int scannedCount = _filesScanned;
                    double averageSpeed = totalSeconds > 0 ? scannedCount / totalSeconds : 0;

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(thisId, token)) return;
                        ApplicationDataContainer settingsLocal = App.LocalSettings;
                        settingsLocal.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        // 完成态直接写这两行，不要再走 UpdateScanStats —— 它会再排一次队，把完成文案覆盖回进行中
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Completed");
                        ScanStatsText.Text = string.Format(
                            _fmtScanSummaryCompleted ?? Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Completed"),
                            scannedCount, totalSeconds, averageSpeed, CurrentResults?.Count ?? _threatsFound);
                        ScanProgress.ShowPaused = false;
                        ScanProgress.Visibility = Visibility.Collapsed;
                        HideWithVisualReset(PauseScanButton);
                        HideWithVisualReset(ResumeScanButton);
                        HideWithVisualReset(CancelScanButton);
                        UpdateHandleAllButtonVisibility();
                    });
                    ClearTaskbarProgress();
                }
                catch (OperationCanceledException)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        // 取消后 token 已经置位，IsCurrentScan 会直接返回 false；
                        // 这里只判断是不是已经被新扫描顶替，否则取消永远看不到任何反馈。
                        if (thisId != _scanId) return;

                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanCancelled");
                        // 摘要换成「平均速度」，口径是开始扫描 → 点下取消那一刻（见 OnCancelScanClick 的快照），
                        // 不用收尾时循环里的最终值，否则等待并行分支退出的时间会稀释平均速度
                        double cancelAverageSpeed = _cancelElapsedSeconds > 0 ? _cancelScannedCount / _cancelElapsedSeconds : 0;
                        ScanStatsText.Text = string.Format(
                            Localizer.Get().GetLocalizedString("SecurityPage_ScanSummary_Cancelled"),
                            _cancelScannedCount, _cancelElapsedSeconds, cancelAverageSpeed, CurrentResults?.Count ?? _threatsFound);
                        ScanProgress.ShowPaused = false;
                        ScanProgress.Visibility = Visibility.Collapsed;
                        HideWithVisualReset(PauseScanButton);
                        HideWithVisualReset(ResumeScanButton);
                        HideWithVisualReset(CancelScanButton);
                        UpdateHandleAllButtonVisibility();
                    });
                    ClearTaskbarProgress();
                }
                catch (Exception ex)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(thisId, token)) return;
                        LogText.AddNewLog(LogText.LogLevel.FATAL, "Security - Failed", ex.Message);
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanFailed_Format"), ex.Message);
                        ScanProgress.ShowPaused = false;
                        ScanProgress.Visibility = Visibility.Collapsed;
                        HideWithVisualReset(PauseScanButton);
                        HideWithVisualReset(ResumeScanButton);
                        HideWithVisualReset(CancelScanButton);
                        HideWithVisualReset(HandleAllButton);
                    });
                    ClearTaskbarProgress();
                }
            });

            _isScanRunning = false;
            ScanButton.IsEnabled = true;
        }

        private void OnBackToVirusListClick(object sender, RoutedEventArgs e)
        {
            // 用目标状态判断而不是 Visibility：淡出那 200ms 里 Visibility 还是 Visible
            OnBackList(!_threatListShown);
        }

        private void OnBackList(bool isShow)
        {
            if (isShow)
            {
                ShowThreatList();
            }
            else
            {
                HideThreatList();
            }

            SyncBackToVirusListButtonText(isShow);
        }

        private void OnPauseScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            _pauseEvent.Reset();
            ScanButton.IsEnabled = true;
            HideWithVisualReset(PauseScanButton);
            ShowWithEntranceAnimation(ResumeScanButton, "right");
            ScanProgress.ShowPaused = true;

            if (_taskbarProgressActive)
            {
                try
                {
                    if (_lastShowScanProgress)
                    {
                        var total = _scanTotalFiles;
                        double progress01 = total == 0 ? 0 : Math.Min(1.0, (double)_filesScanned / total);
                        TaskbarProgressService.TrySetPaused(progress01);
                    }
                    else
                    {
                        TaskbarProgressService.TrySetPaused();
                    }
                }
                catch { }
            }
        }

        private void OnResumeScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = false;
            _pauseEvent.Set();
            ScanButton.IsEnabled = false;
            ShowWithEntranceAnimation(PauseScanButton, "right");
            HideWithVisualReset(ResumeScanButton);
            ScanProgress.ShowPaused = false;

            UpdateTaskbarProgressStateForRunning();
        }

        /// <summary>
        /// 零轮询等待暂停结束：阻塞线程池线程直到 _pauseEvent 被设置或 CancellationToken 触发。
        /// 替代旧的 while(_isPaused) await Task.Delay(100) 轮询模式，避免 100ms 唤醒抖动与 CPU 浪费。
        /// </summary>
        private async Task WaitWhilePausedAsync(CancellationToken ct)
        {
            if (_pauseEvent.IsSet) return;
            try
            {
                await Task.Run(() =>
                {
                    var handles = new[] { _pauseEvent.WaitHandle, ct.WaitHandle };
                    WaitHandle.WaitAny(handles);
                }, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // 取消时直接返回，由调用方检查 ct
            }
        }

        private async void OnVirusRowDetailsClick(object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await ShowDetailsDialog(row);
            }
        }

        private async void OnVirusRowTrustClick(object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await OnTrustClickInternal(row);
            }
        }

        private async void OnVirusRowHandleClick(object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await OnHandleClickInternal(row);
            }
        }

        private async void VirusList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            if (sender is ListView { SelectedItem: VirusRow row })
            {
                await ShowDetailsDialog(row);
            }
        }

        private static readonly string[] ArchiveEntryExtensions = new[] { ".zip", ".7z", ".tar", ".tgz", ".tbz2", ".txz", ".gz", ".bz2", ".xz" };

        private static bool TryParseArchiveEntry(string displayPath, out string archivePath, out string entryPath)
        {
            for (int i = 0; i < displayPath.Length; i++)
            {
                if (displayPath[i] == '\\')
                {
                    string currentPath = displayPath.Substring(0, i);
                    string ext = Path.GetExtension(currentPath).ToLowerInvariant();
                    if (ArchiveEntryExtensions.Contains(ext) && ArchiveScanner.IsArchiveFile(currentPath))
                    {
                        string remaining = displayPath.Substring(i + 1);
                        if (!string.IsNullOrEmpty(remaining))
                        {
                            archivePath = currentPath;
                            entryPath = remaining;
                            return true;
                        }
                    }
                }
            }
            archivePath = string.Empty;
            entryPath = string.Empty;
            return false;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int SHOpenFolderAndSelectItems(IntPtr pidlFolder, uint cidl, [MarshalAs(UnmanagedType.LPArray)] IntPtr[] apidl, uint dwFlags);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int SHParseDisplayName([MarshalAs(UnmanagedType.LPWStr)] string pszName, IntPtr pbc, out IntPtr ppidl, uint sfgaoIn, out uint psfgaoOut);

        [DllImport("ole32.dll")]
        private static extern void CoTaskMemFree(IntPtr pv);

        private static void OpenFolderAndSelectItem(string filePath)
        {
            if (!File.Exists(filePath))
            {
                string? dir = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(dir))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"/e,\"{dir}\"",
                        UseShellExecute = true
                    });
                }
                return;
            }

            string? folderPath = Path.GetDirectoryName(filePath);
            if (string.IsNullOrEmpty(folderPath)) return;

            uint sfgao;
            int hr = SHParseDisplayName(folderPath, IntPtr.Zero, out IntPtr pidlFolder, 0, out sfgao);
            if (hr != 0) return;

            hr = SHParseDisplayName(filePath, IntPtr.Zero, out IntPtr pidlFile, 0, out sfgao);
            if (hr != 0)
            {
                CoTaskMemFree(pidlFolder);
                return;
            }

            hr = SHOpenFolderAndSelectItems(pidlFolder, 1, new[] { pidlFile }, 0);
            CoTaskMemFree(pidlFolder);
            CoTaskMemFree(pidlFile);

            if (hr != 0)
            {
                // 回退：打开目录
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/e,\"{folderPath}\"",
                    UseShellExecute = true
                });
            }
        }

        private async Task ShowDetailsDialog(VirusRow? row)
        {
            if (row is null) return;
            if (_detailsDialog != null) return;

            bool isDetailsPause = false;
            try
            {
                isDetailsPause = PauseScanButton.Visibility == Visibility.Visible && PauseScanButton.IsEnabled;
                if (isDetailsPause)
                {
                    OnPauseScanClick(new object(), new RoutedEventArgs());
                }

                string displayPath = row.FilePath;
                string? archivePath = null;
                string? entryPath = null;
                bool isArchiveEntry = TryParseArchiveEntry(displayPath, out archivePath, out entryPath);
                bool isZipEntry = false;

                if (isArchiveEntry)
                {
                    // 进一步检查是否为 zip 格式，用于获取 entry 信息
                    isZipEntry = string.Equals(Path.GetExtension(archivePath), ".zip", StringComparison.OrdinalIgnoreCase);
                }

                string fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                string creationTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                string lastWriteTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");

                if (isZipEntry && archivePath != null && entryPath != null)
                {
                    try
                    {
                        var entryInfo = await ArchiveScanner.GetEntryInfoAsync(archivePath, entryPath);
                        if (entryInfo.HasValue)
                        {
                            fileSizeText = string.Format(CultureInfo.CurrentCulture, "{0:F2} KB", entryInfo.Value.Size / 1024.0);
                            creationTimeText = entryInfo.Value.CreationTime.ToString("g", CultureInfo.CurrentCulture);
                            lastWriteTimeText = entryInfo.Value.LastWriteTime.ToString("g", CultureInfo.CurrentCulture);
                        }
                        else
                        {
                            fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_NotAvailable");
                        }
                    }
                    catch
                    {
                        fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_NotAvailable");
                    }
                }
                else if (System.IO.File.Exists(displayPath))
                {
                    try
                    {
                        FileInfo fileInfo = new(displayPath);
                        fileSizeText = string.Format(CultureInfo.CurrentCulture, "{0:F2} KB", fileInfo.Length / 1024.0);
                        creationTimeText = fileInfo.CreationTime.ToString("g", CultureInfo.CurrentCulture);
                        lastWriteTimeText = fileInfo.LastWriteTime.ToString("g", CultureInfo.CurrentCulture);
                    }
                    catch { }
                }

                var listView = new ListView
                {
                    SelectionMode = ListViewSelectionMode.None,
                    IsItemClickEnabled = false,
                    Padding = new Thickness(0),
                    Margin = new Thickness(0),
                    MaxHeight = 400
                };

                var compactStyle = new Style(typeof(ListViewItem));
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.PaddingProperty, Value = new Thickness(0) });
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.MinHeightProperty, Value = 0d });
                compactStyle.Setters.Add(new Setter { Property = ListViewItem.MarginProperty, Value = new Thickness(0) });
                listView.ItemContainerStyle = compactStyle;

                static string ToLabelFromTemplate(string template)
                {
                    if (string.IsNullOrWhiteSpace(template)) return template;

                    var label = TemplateBraceRegex().Replace(template, string.Empty);
                    label = WhitespaceRegex().Replace(label, " ").Trim();
                    label = UnitSuffixRegex().Replace(label, string.Empty).Trim();

                    while (label.EndsWith(':') || label.EndsWith('：'))
                        label = label[..^1].TrimEnd();

                    return label;
                }

                var items = new List<(string Key, FrameworkElement Value)>
                {
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FilePath")), new RichTextBlock
                    {
                        IsTextSelectionEnabled = true,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 14,
                        FontFamily = new FontFamily("Segoe UI"),
                        Blocks = { new Paragraph { Inlines = { new Run { Text = displayPath } } } }
                    }),
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_VirusName")), new TextBlock { Text = row.VirusName, IsTextSelectionEnabled = true, TextWrapping = TextWrapping.Wrap }),
                };

                if (row.UseFamilyEngine)
                {
                    string familyDisplay = string.IsNullOrWhiteSpace(row.FamilyName)
                        ? Localizer.Get().GetLocalizedString("AllPage_Undefined")
                        : row.FamilyName;
                    items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FamilyName")), new TextBlock { Text = familyDisplay, IsTextSelectionEnabled = true }));
                }

                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FileSize")), new TextBlock { Text = fileSizeText, IsTextSelectionEnabled = true }));
                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_CreationTime")), new TextBlock { Text = creationTimeText, IsTextSelectionEnabled = true }));
                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_LastWriteTime")), new TextBlock { Text = lastWriteTimeText, IsTextSelectionEnabled = true }));

                if (!string.IsNullOrWhiteSpace(row.EngineName))
                {
                    items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_EngineName")), new TextBlock { Text = row.EngineName, IsTextSelectionEnabled = true }));
                }

                if (!isArchiveEntry && System.IO.File.Exists(displayPath))
                {
                    try
                    {
                        string sha256 = await Helper.ScanEngine.GetFileSHA256Async(displayPath);
                        items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_SHA256")), new TextBlock
                        {
                            Text = sha256,
                            IsTextSelectionEnabled = true,
                            TextWrapping = TextWrapping.Wrap,
                            FontFamily = new FontFamily("Consolas"),
                            FontSize = 12
                        }));
                    }
                    catch { }
                }

                int itemIndex = 0;
                foreach (var (key, valueElement) in items)
                {
                    var keyBlock = new TextBlock
                    {
                        Text = key,
                        FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                        VerticalAlignment = VerticalAlignment.Top
                    };
                    Grid.SetColumn(keyBlock, 0);
                    Grid.SetColumn(valueElement, 1);

                    var detailRow = new Grid
                    {
                        ColumnDefinitions =
                        {
                            new ColumnDefinition { Width = new GridLength(100) },
                            new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }
                        },
                        Padding = new Thickness(0, 4, 0, 4),
                        ColumnSpacing = 16,
                        Children = { keyBlock, valueElement }
                    };

                    int delay = itemIndex * 15;
                    detailRow.Loaded += (s, e) => App.PlayEntranceAnimation(detailRow, "up", delayMs: delay);

                    listView.Items.Add(detailRow);
                    itemIndex++;
                }

                ContentDialog dialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_Details_Title"),
                    Content = new ScrollViewer { Content = listView },
                    PrimaryButtonText = isArchiveEntry
                        ? Localizer.Get().GetLocalizedString("SecurityPage_Details_OpenButton")
                        : Localizer.Get().GetLocalizedString("SecurityPage_Details_LocateButton"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Close
                };
                _detailsDialog = dialog;

                if (await dialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    ContentDialog riskDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_Risk_Title"),
                        Content = new TextBlock
                        {
                            Text = isArchiveEntry
                                ? string.Format(Localizer.Get().GetLocalizedString("SecurityPage_Risk_ArchiveContent"), archivePath)
                                : string.Format(Localizer.Get().GetLocalizedString("SecurityPage_Risk_FileContent"), displayPath),
                            TextWrapping = TextWrapping.Wrap
                        },
                        PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_Risk_Allow"),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };

                    if (await riskDialog.ShowAsync() == ContentDialogResult.Primary)
                    {
                        try
                        {
                            if (archivePath is null)
                            {
                                return;
                            }
                            if (isArchiveEntry)
                            {
                                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(archivePath) { UseShellExecute = true });
                            }
                            else
                            {
                                OpenFolderAndSelectItem(displayPath);
                            }
                        }
                        catch (Exception ex)
                        {
                            ContentDialog dlg = new()
                            {
                                Title = Localizer.Get().GetLocalizedString("SecurityPage_LocateFailed_Title"),
                                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_LocateFailed_Content"), ex.Message),
                                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                                XamlRoot = this.XamlRoot,
                                DefaultButton = ContentDialogButton.Close
                            };
                            await dlg.ShowAsync();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                try
                {
                    LogText.AddNewLog(LogText.LogLevel.FATAL, "Security - FilesInfo - GetFailed", ex.Message);
                    ContentDialog failDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_GetFailed_Text"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };
                    await failDialog.ShowAsync();
                }
                catch { }
            }
            finally
            {
                _detailsDialog = null;
                if (isDetailsPause)
                {
                    try
                    {
                        OnResumeScanClick(new object(), new RoutedEventArgs());
                    }
                    catch (Exception resumeEx)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - ResumeFailed", resumeEx.Message);
                    }
                }
            }
        }

        /// <summary>多选文件。用户取消或未选择时返回空集合。</summary>
        private async Task<IReadOnlyList<string>> PickFilesAsync()
        {
            try
            {
                var files = await new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickMultipleFilesAsync();
                return files is null ? [] : (string[])[.. files.Select(f => f.Path)];
            }
            catch { return []; }
        }

        /// <summary>多选文件夹。用户取消或未选择时返回空集合。</summary>
        private async Task<IReadOnlyList<string>> PickFoldersAsync()
        {
            try
            {
                var folders = await new FolderPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickMultipleFoldersAsync();
                return folders is null ? [] : (string[])[.. folders.Select(f => f.Path)];
            }
            catch { return []; }
        }

        /// <summary>单选文件夹。用户取消时返回 null。</summary>
        private async Task<string?> PickFolderAsync()
        {
            try
            {
                PickFolderResult folder = await (new FolderPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFolderAsync());
                if (folder is null) { return null; }
                return folder.Path;
            }
            catch { return null; }
        }

        private static int CountFiles(ScanMode mode, string? userPath, IReadOnlyList<string>? customPaths) => mode switch
        {
            ScanMode.Quick => CountQuickScanFiles(),
            ScanMode.Full => CountFullScanFiles(),
            ScanMode.File => customPaths?.Count(p => System.IO.File.Exists(p)) ?? 0,
            ScanMode.Folder => (userPath != null && Directory.Exists(userPath)) ? CountFilesInFolder(userPath) : 0,
            ScanMode.More => customPaths?.Sum(p =>
                Directory.Exists(p) ? CountFilesInFolder(p)
                : (System.IO.File.Exists(p) ? 1 : 0)) ?? 0,
            _ => 0
        };

        private static bool TryEnumerateFilesUsingNtfsTable(
            ScanMode mode,
            string? userPath,
            IReadOnlyList<string>? customPaths,
            out IReadOnlyList<string> files)
        {
            files = [];
            if (mode is ScanMode.Quick or ScanMode.File)
                return false;

            HashSet<string> indexedFiles = [with(StringComparer.OrdinalIgnoreCase)];
            bool indexComplete = false;
            NtfsFileTableIndexer.VolumeIndexCache volumeCache = new();
            HashSet<string> volumesReadFromTable = new(StringComparer.OrdinalIgnoreCase);

            void AddDirectory(string directory)
            {
                string volumeRoot = Path.GetPathRoot(Path.GetFullPath(directory)) ?? string.Empty;
                bool volumeTableReady = volumesReadFromTable.Contains(volumeRoot);

                // 读取整卷 MFT 的成本与目标目录大小无关，因此小目录直接使用普通遍历。
                // 只按文件数量判定规模，不按耗时判定，避免慢盘上的小目录重复付出两种索引成本。
                if (mode != ScanMode.Full &&
                    !volumeTableReady &&
                    TryEnumerateSmallFolder(directory, out IReadOnlyList<string> budgetedFiles))
                {
                    indexComplete = true;
                    indexedFiles.UnionWith(budgetedFiles);
                    LogText.AddNewLog(
                        LogText.LogLevel.INFO,
                        "Security - FastIndex",
                        $"Directory enumeration finished within the probe budget for '{directory}'. Indexed {budgetedFiles.Count} files without reading the NTFS file table.");
                    return;
                }

                if (NtfsFileTableIndexer.TryEnumerateFiles(directory, out IReadOnlyList<string> ntfsFiles, out string? errorMessage, volumeCache))
                {
                    indexComplete = true;
                    volumesReadFromTable.Add(volumeRoot);
                    indexedFiles.UnionWith(ntfsFiles);
                    LogText.AddNewLog(
                        LogText.LogLevel.INFO,
                        "Security - FastIndex",
                        $"NTFS file table indexing succeeded for '{directory}'. Indexed {ntfsFiles.Count} files.");
                    return;
                }

                LogText.AddNewLog(
                    LogText.LogLevel.WARN,
                    "Security - FastIndex",
                    $"NTFS file table indexing failed for '{directory}'. Falling back to directory enumeration. Error: {errorMessage ?? "Unknown error."}");
                indexedFiles.UnionWith(SafeEnumerateFolder(directory));
            }

            switch (mode)
            {
                case ScanMode.Full:
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                    {
                        if (drive.IsReady && drive.DriveType is not DriveType.CDRom and not DriveType.Network)
                            AddDirectory(drive.RootDirectory.FullName);
                    }
                    break;
                case ScanMode.Folder when userPath != null && Directory.Exists(userPath):
                    AddDirectory(userPath);
                    break;
                case ScanMode.More when customPaths != null:
                    foreach (string path in customPaths)
                    {
                        if (Directory.Exists(path))
                            AddDirectory(path);
                        else if (System.IO.File.Exists(path))
                            indexedFiles.Add(path);
                    }
                    break;
                default:
                    return false;
            }

            if (!indexComplete)
                return false;

            files = indexedFiles.ToArray();
            return true;
        }

        // 超过此数量才读取整卷 MFT；阈值应低于典型整卷文件数，但足够覆盖小目录。
        private const int FastIndexProbeFileLimit = 4_096;

        private static bool TryEnumerateSmallFolder(
            string directory,
            out IReadOnlyList<string> files)
        {
            files = [];
            List<string> collected = [];
            Stack<string> stack = new();
            stack.Push(directory);

            while (stack.Count > 0)
            {
                string dir = stack.Pop();

                IEnumerable<string> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                foreach (string entry in entries)
                {
                    System.IO.FileAttributes attr;
                    try { attr = System.IO.File.GetAttributes(entry); }
                    catch { continue; }

                    if ((attr & System.IO.FileAttributes.Directory) != 0)
                        stack.Push(entry);
                    else
                        collected.Add(entry);

                    if (collected.Count > FastIndexProbeFileLimit)
                        return false;
                }
            }

            files = collected;
            return true;
        }

        private static int CountFilesInFolder(string folder)
        {
            int total = 0;
            Stack<string> stack = new();
            stack.Push(folder);

            while (stack.Count > 0)
            {
                string dir = stack.Pop();

                IEnumerable<string> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                int dirCount = 0;
                foreach (string entry in entries)
                {
                    System.IO.FileAttributes attr;
                    try { attr = System.IO.File.GetAttributes(entry); }
                    catch { continue; }

                    if ((attr & System.IO.FileAttributes.Directory) != 0)
                        stack.Push(entry);
                    else
                        dirCount++;
                }
                total += dirCount;
            }
            return total;
        }

        private static int CountQuickScanFiles()
        {
            string[] criticalPaths =
            [
                 Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
            ];

            HashSet<string> extensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".com", ".scr", ".bat" };

            return criticalPaths
                   .Where(Directory.Exists)
                   .SelectMany(dir =>
                   {
                       try
                       {
                           return Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                                           .Where(f => extensions.Contains(Path.GetExtension(f)));
                       }
                       catch
                       {
                           return [];
                       }
                   })
                   .Distinct(StringComparer.OrdinalIgnoreCase)
                   .Count();
        }

        private static IEnumerable<string> SafeEnumerateFolder(string folder)
        {
            Stack<string> stack = new();
            stack.Push(folder);

            while (stack.Count > 0)
            {
                string dir = stack.Pop();

                IEnumerable<string> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                foreach (string entry in entries)
                {
                    System.IO.FileAttributes attr;
                    try { attr = System.IO.File.GetAttributes(entry); }
                    catch { continue; }

                    if ((attr & System.IO.FileAttributes.Directory) != 0)
                        stack.Push(entry);
                    else
                        yield return entry;
                }
            }
        }

        private static IEnumerable<string> GetEnumerateQuickScanFiles()
        {
            string[] criticalPaths =
            [
                 Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
            ];

            HashSet<string> extensions = [with(StringComparer.OrdinalIgnoreCase), ".exe", ".dll", ".sys", ".com", ".scr", ".bat"];

            return criticalPaths
                   .Where(Directory.Exists)
                   .SelectMany(dir =>
                   {
                       try
                       {
                           return Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                                           .Where(f => extensions.Contains(Path.GetExtension(f)));
                       }
                       catch
                       {
                           return [];
                       }
                   })
                   .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static int CountFullScanFiles()
        {
            HashSet<string> scanned = new(StringComparer.OrdinalIgnoreCase);
            int total = 0;

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                    continue;

                total += CountFilesInTree(drive.RootDirectory.FullName, scanned);
            }
            return total;
        }

        private static int CountFilesInTree(string root, HashSet<string> scanned)
        {
            int total = 0;
            Stack<string> stack = new();
            stack.Push(root);

            while (stack.Count > 0)
            {
                string currentDir = stack.Pop();

                if (!scanned.Add(currentDir))
                    continue;

                IEnumerable<string>? entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(currentDir);
                }
                catch
                {
                    continue;
                }

                int dirCount = 0;
                foreach (string entry in entries)
                {
                    if (Directory.Exists(entry))
                    {
                        stack.Push(entry);
                    }
                    else if (System.IO.File.Exists(entry) && scanned.Add(entry))
                    {
                        dirCount++;
                    }
                }
                total += dirCount;
            }
            return total;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root, HashSet<string> scanned)
        {
            Stack<string> stack = new();
            stack.Push(root);

            while (stack.Count > 0)
            {
                string currentDir = stack.Pop();

                if (!scanned.Add(currentDir))
                    continue;

                IEnumerable<string>? entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(currentDir);
                }
                catch
                {
                    continue;
                }

                foreach (string entry in entries)
                {
                    if (Directory.Exists(entry))
                    {
                        stack.Push(entry);
                    }
                    else if (System.IO.File.Exists(entry) && scanned.Add(entry))
                    {
                        yield return entry;
                    }
                }
            }
        }

        [GeneratedRegex("\\{[^}]*\\}")]
        private static partial Regex TemplateBraceRegex();

        [GeneratedRegex("\\s+")]
        private static partial Regex WhitespaceRegex();

        [GeneratedRegex("\\s+\\b(KB|MB|GB|TB|B)\\b\\s*$")]
        private static partial Regex UnitSuffixRegex();
    }
}
