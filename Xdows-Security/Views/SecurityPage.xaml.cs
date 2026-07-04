using Helper;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
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
        private String _filePath = String.Empty;
        private String _virusName = String.Empty;
        private String _familyName = String.Empty;
        private String _engineName = String.Empty;
        private bool _useFamilyEngine;

        public String FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); }
        }

        public String VirusName
        {
            get => _virusName;
            set { _virusName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public String FamilyName
        {
            get => _familyName;
            set { _familyName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public String EngineName
        {
            get => _engineName;
            set { _engineName = value; OnPropertyChanged(); }
        }

        public bool UseFamilyEngine
        {
            get => _useFamilyEngine;
            set { _useFamilyEngine = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); }
        }

        public String DisplayName => _useFamilyEngine && !String.IsNullOrWhiteSpace(_familyName) && _familyName != Localizer.Get().GetLocalizedString("AllPage_Undefined") ? _familyName : _virusName;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] String name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public record ScanItem
    {
        public String ItemName { get; set; } = String.Empty;
        public String IconGlyph { get; set; } = "&#xE721;";
        public SolidColorBrush IconColor { get; set; } = new SolidColorBrush(Colors.Gray);
        public String StatusText { get; set; } = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting");
        public Int32 ThreatCount { get; set; } = 0;
        public Visibility ThreatCountVisibility { get; set; } = Visibility.Collapsed;
        public SolidColorBrush ThreatCountBackground { get; set; } = new SolidColorBrush(Colors.Red);
    }

    public partial class MoreScanItem : INotifyPropertyChanged
    {
        private String _path = String.Empty;
        private Boolean _isFolder;

        public String Path
        {
            get => _path;
            set { _path = value; OnPropertyChanged(); }
        }

        public Boolean IsFolder
        {
            get => _isFolder;
            set { _isFolder = value; OnPropertyChanged(); OnPropertyChanged(nameof(IconGlyph)); }
        }

        public String IconGlyph => _isFolder ? "\uE8B7" : "\uE8A5";

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] String name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public sealed partial class SecurityPage : Page
    {
        private readonly DispatcherQueue _dispatcherQueue;
        private CancellationTokenSource? _cts;
        private bool _isPaused = false;
        private bool _taskbarProgressActive = false;
        private bool _lastShowScanProgress = false;
        private bool _lastShowTaskbarProgress = true;
        private Int32 _filesScanned = 0;
        private Int32 _filesSafe = 0;
        private Int32 _threatsFound = 0;
        private Int32 _scanId = 0;
        private ContentDialog? _moreScanDialog;
        private ContentDialog? _detailsDialog;
        private readonly Dictionary<String, List<(String EntryPath, String VirusName)>> _zipFileThreats = [];
        private ObservableCollection<VirusRow>? CurrentResults;
        private List<ScanItem>? _scanItems;

        private Compositor? _radarCompositor;
        private Visual? _scanLineVisual;
        private Visual? _pulseVisual;
        private ScalarKeyFrameAnimation? _rotationAnimation;
        private ScalarKeyFrameAnimation? _pulseScaleAnimation;
        private ScalarKeyFrameAnimation? _pulseOpacityAnimation;
        private bool _radarRunning;
        private float _radarPausedAngle;

        private Boolean IsCurrentScan(Int32 scanId, CancellationToken token)
        {
            if (token.IsCancellationRequested) return false;
            if (MainWindow.NowPage != "Security")
            {
                ClearTaskbarProgress();
                return false;
            }
            return scanId == _scanId;
        }

        private static void ShowWithEntranceAnimation(UIElement element, String kind = "up", Int32 delayMs = 0)
        {
            element.Visibility = Visibility.Visible;
            App.PlayEntranceAnimation(element, kind, delayMs: delayMs);
        }

        private void ShowBackToVirusListButton()
        {
            if (BackToVirusListButton.Visibility != Visibility.Visible)
            {
                ShowWithEntranceAnimation(BackToVirusListButton, "right");
            }
            else
            {
                BackToVirusListButton.Visibility = Visibility.Visible;
            }
        }

#if DEBUG
        private const String TestVirusCopyDirectory = @"D:\\Code\\Model\\Files\\Test";

        private static async Task CopyVirusSampleForTestAsync(String displayName, String? sourceFilePath = null, Byte[]? bytes = null)
        {
            try
            {
                Directory.CreateDirectory(TestVirusCopyDirectory);

                String baseName = String.Empty;
                try
                {
                    if (!String.IsNullOrEmpty(sourceFilePath))
                        baseName = Path.GetFileName(sourceFilePath);
                    if (String.IsNullOrWhiteSpace(baseName))
                        baseName = Path.GetFileName(displayName);
                }
                catch { }

                if (String.IsNullOrWhiteSpace(baseName))
                    baseName = "sample.bin";

                String destFileName = $"{DateTime.Now:yyyyMMdd_HHmmssfff}_{Guid.NewGuid():N}_{baseName}";
                String destPath = Path.Combine(TestVirusCopyDirectory, destFileName);

                if (bytes != null)
                {
                    await File.WriteAllBytesAsync(destPath, bytes);
                    return;
                }

                if (!String.IsNullOrEmpty(sourceFilePath) && File.Exists(sourceFilePath))
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
            PathText.Text = Localizer.Get().GetLocalizedString("SecurityPage_PathText_Default");
            ScanSpeedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanSpeed_Format"), 0.0);
            FilesScannedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesScanned_Format"), 0);
            FilesSafeText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesSafe_Format"), 0);
            ThreatsFoundText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ThreatsFound_Format"), 0);
            InitializeScanItems();
            Loaded += SecurityPage_Loaded;
            Unloaded += SecurityPage_Unloaded;
        }

        private void SecurityPage_Loaded(object sender, RoutedEventArgs e)
        {
            SetupRadarAnimations();
            // 通知主窗口：SecurityPage 已就绪，可接收扫描请求（替代旧版的 Task.Delay + 轮询）
            App.MainWindow?.NotifySecurityPageReady(this);
        }

        private void SecurityPage_Unloaded(object sender, RoutedEventArgs e)
        {
            StopRadar();
            ClearTaskbarProgress();
        }

        private void SetupRadarAnimations()
        {
            var rootVisual = ElementCompositionPreview.GetElementVisual(this);
            _radarCompositor = rootVisual.Compositor;

            _scanLineVisual = ElementCompositionPreview.GetElementVisual(ScanLineContainer);
            _scanLineVisual.CenterPoint = new Vector3(90f, 90f, 0f);

            _pulseVisual = ElementCompositionPreview.GetElementVisual(PulseEllipse);
            _pulseVisual.CenterPoint = new Vector3(10f, 10f, 0f);

            _rotationAnimation = _radarCompositor.CreateScalarKeyFrameAnimation();
            _rotationAnimation.InsertKeyFrame(0.0f, 0.0f);
            _rotationAnimation.InsertKeyFrame(1.0f, 360.0f);
            _rotationAnimation.Duration = TimeSpan.FromSeconds(3);
            _rotationAnimation.IterationBehavior = AnimationIterationBehavior.Forever;

            _pulseScaleAnimation = _radarCompositor.CreateScalarKeyFrameAnimation();
            _pulseScaleAnimation.InsertKeyFrame(0.0f, 1.0f);
            _pulseScaleAnimation.InsertKeyFrame(1.0f, 3.0f);
            _pulseScaleAnimation.Duration = TimeSpan.FromSeconds(1.5);
            _pulseScaleAnimation.IterationBehavior = AnimationIterationBehavior.Forever;

            _pulseOpacityAnimation = _radarCompositor.CreateScalarKeyFrameAnimation();
            _pulseOpacityAnimation.InsertKeyFrame(0.0f, 0.6f);
            _pulseOpacityAnimation.InsertKeyFrame(1.0f, 0.0f);
            _pulseOpacityAnimation.Duration = TimeSpan.FromSeconds(1.5);
            _pulseOpacityAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        }

        private void StartRadar()
        {
            if (_radarRunning || _radarCompositor == null) return;
            _radarRunning = true;

            _scanLineVisual!.RotationAngleInDegrees = 0f;
            _scanLineVisual.Opacity = 0f;

            var fadeIn = _radarCompositor.CreateScalarKeyFrameAnimation();
            fadeIn.InsertKeyFrame(1.0f, 1.0f);
            fadeIn.Duration = TimeSpan.FromSeconds(0.3);

            _scanLineVisual.StartAnimation("Opacity", fadeIn);
            _scanLineVisual.StartAnimation("RotationAngleInDegrees", _rotationAnimation!);

            _pulseVisual!.StartAnimation("Scale.X", _pulseScaleAnimation!);
            _pulseVisual.StartAnimation("Scale.Y", _pulseScaleAnimation);
            _pulseVisual.StartAnimation("Opacity", _pulseOpacityAnimation!);
        }

        private void StopRadar()
        {
            if (!_radarRunning || _radarCompositor == null) return;
            _radarRunning = false;

            _scanLineVisual!.StopAnimation("RotationAngleInDegrees");

            var fadeOut = _radarCompositor.CreateScalarKeyFrameAnimation();
            fadeOut.InsertKeyFrame(1.0f, 0.0f);
            fadeOut.Duration = TimeSpan.FromSeconds(0.2);
            _scanLineVisual.StartAnimation("Opacity", fadeOut);

            _pulseVisual!.StopAnimation("Scale.X");
            _pulseVisual.StopAnimation("Scale.Y");
            _pulseVisual.StopAnimation("Opacity");
            _pulseVisual.Opacity = 0f;
        }

        private void PauseRadar()
        {
            if (!_radarRunning || _radarCompositor == null) return;

            _radarPausedAngle = _scanLineVisual!.RotationAngleInDegrees;
            _scanLineVisual.StopAnimation("RotationAngleInDegrees");

            _pulseVisual!.StopAnimation("Scale.X");
            _pulseVisual.StopAnimation("Scale.Y");
            _pulseVisual.StopAnimation("Opacity");
        }

        private void ResumeRadar()
        {
            if (!_radarRunning || _radarCompositor == null) return;

            float startAngle = _radarPausedAngle % 360;
            var resumeAnimation = _radarCompositor.CreateScalarKeyFrameAnimation();
            resumeAnimation.InsertKeyFrame(0.0f, startAngle);
            resumeAnimation.InsertKeyFrame(1.0f, startAngle + 360.0f);
            resumeAnimation.Duration = TimeSpan.FromSeconds(3);
            resumeAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
            _scanLineVisual!.StartAnimation("RotationAngleInDegrees", resumeAnimation);

            _pulseVisual!.StartAnimation("Scale.X", _pulseScaleAnimation!);
            _pulseVisual.StartAnimation("Scale.Y", _pulseScaleAnimation);
            _pulseVisual.StartAnimation("Opacity", _pulseOpacityAnimation!);
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
                        var total = _scanItems?.Count ?? 0;
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

        private void AddVirusResult(String filePath, String virusName, String? familyName = null, String? engineName = null, bool useFamilyEngine = false)
        {
            VirusRow row = new()
            {
                FilePath = filePath,
                VirusName = virusName,
                FamilyName = familyName ?? String.Empty,
                EngineName = engineName ?? String.Empty,
                UseFamilyEngine = useFamilyEngine
            };

            CurrentResults?.Add(row);
        }

        private async Task OnTrustClickInternal(VirusRow? row)
        {
            if (row is null) return;

            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Title"),
                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Content"), row.FilePath),
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
                    Boolean success = await TrustManager.AddToTrust(row.FilePath);

                    ContentDialog resultDialog = new()
                    {
                        Title = success ?
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Title") :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = success ?
                            String.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Content"), row.FilePath) :
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
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);
                        UpdateHandleAllButtonVisibility();
                    }
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
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

            String displayPath = row.FilePath;

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
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Title"),
                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Content"), displayPath),
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

                    String? zipPath = null;
                    String? entryPath = null;
                    Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
                    if (zipIndex > 0)
                    {
                        zipPath = displayPath[..(zipIndex + 4)];
                        entryPath = displayPath[(zipIndex + 5)..];
                    }

                    if (handled && zipPath != null && entryPath != null)
                    {
                        var entriesToDelete = new List<String>();
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
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults.Count);
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

        private async Task<(Boolean handled, String actionTaken)> HandleSingleThreatAsync(VirusRow row)
        {
            String displayPath = row.FilePath;
            String? zipPath = null;
            String? entryPath = null;

            Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
            if (zipIndex > 0)
            {
                zipPath = displayPath[..(zipIndex + 4)];
                entryPath = displayPath[(zipIndex + 5)..];
            }

            try
            {
                return await Task.Run(async () =>
                {
                    Boolean handled = false;
                    String actionTaken = "";

                    if (zipPath != null && entryPath != null && _zipFileThreats.TryGetValue(zipPath, out var threatsInZip))
                    {
                        var entriesToDelete = new List<String>();
                        Int32 quarantinedCount = 0;

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
                                    var fileData = await ZipScanner.ExtractEntryAsync(zipPath, entry);
                                    if (fileData != null && fileData.Length > 0)
                                    {
                                        var (_, threatVirusName) = threatsInZip.FirstOrDefault(t => t.EntryPath == entry);
                                        String virusName = threatVirusName ?? row.VirusName ?? "Unknown";
                                        String sourcePath = Path.GetDirectoryName(zipPath) + "\\" + Path.GetFileName(entry);

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

                            Int32 deletedCount = 0;
                            if (quarantinedCount > 0)
                            {
                                deletedCount = await ZipScanner.DeleteMultipleEntriesFromZipAsync(zipPath, entriesToDelete);
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - DeleteZipEntries", $"Deleted {deletedCount} entries from {zipPath}");
                            }

                            if (deletedCount > 0 || quarantinedCount > 0)
                            {
                                actionTaken = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_ZipEntriesQuarantined"), quarantinedCount, deletedCount);
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
                bool hasResults = CurrentResults != null && CurrentResults.Count > 0;
                bool scanComplete = PauseScanButton.Visibility == Visibility.Collapsed
                    && ResumeScanButton.Visibility == Visibility.Collapsed;
                bool shouldShow = hasResults && scanComplete;

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
                    HandleAllButton.Visibility = Visibility.Collapsed;
                }
            });
        }

        private async void OnHandleAllClick(Object sender, RoutedEventArgs e)
        {
            if (CurrentResults == null || CurrentResults.Count == 0) return;

            Int32 threatCount = CurrentResults.Count;

            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Title"),
                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Content"), threatCount),
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
            if (CurrentResults == null || CurrentResults.Count == 0) return;

            List<VirusRow> snapshot = [.. CurrentResults];
            Int32 total = snapshot.Count;

            HandleAllButton.Visibility = Visibility.Collapsed;

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
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleAllConfirm_Title"),
                Content = progressContent,
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            _ = dialog.ShowAsync();

            Int32 successCount = 0;
            var failedItems = new List<VirusRow>();

            for (Int32 i = 0; i < snapshot.Count; i++)
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

                        String displayPath = row.FilePath;
                        Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
                        if (zipIndex > 0)
                        {
                            String zipPath = displayPath[..(zipIndex + 4)];
                            String entryPath = displayPath[(zipIndex + 5)..];

                            if (_zipFileThreats.TryGetValue(zipPath, out var threatsInZip))
                            {
                                var entriesToDelete = new List<String>();
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

            UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
            StatusText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);

            dialog.Hide();

            await ShowHandleAllResultDialog(successCount, failedItems);

            UpdateHandleAllButtonVisibility();
        }

        private async Task ShowHandleAllResultDialog(Int32 successCount, List<VirusRow> failedItems)
        {
            Boolean allFailed = successCount == 0 && failedItems.Count > 0;
            Boolean hasFailures = failedItems.Count > 0;

            var contentPanel = new StackPanel { Spacing = 8 };

            var successText = new TextBlock
            {
                Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAllResult_Success"), successCount),
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

                Int32 itemIndex = 0;
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

                    Int32 delay = itemIndex * 15;
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
        private void InitializeScanItems()
        {
            _scanItems =
            [
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_System"), IconGlyph = "&#xE721;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_Memory"), IconGlyph = "&#xE896;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_Startup"), IconGlyph = "&#xE812;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_UserDocs"), IconGlyph = "&#xE8A5;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") }
            ];
        }

        private void UpdateScanItemStatus(Int32 itemIndex, String status, Boolean isActive, Int32 threatCount = 0)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    if (_scanItems != null && itemIndex < _scanItems.Count)
                    {
                        ScanItem item = _scanItems[itemIndex];
                        item.StatusText = status;
                        item.IconColor = new SolidColorBrush(isActive ? Colors.DodgerBlue : Colors.Gray);
                        item.ThreatCount = threatCount;
                        item.ThreatCountVisibility = threatCount > 0 ? Visibility.Visible : Visibility.Collapsed;
                    }
                }
                catch { }
            });
        }

        private void UpdateScanStats(Int32 filesScanned, Int32 _, Int32 threatsFound)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                Int32 threatForDisplay = CurrentResults?.Count ?? threatsFound;

                // Keep UI counters consistent even under parallel scanning:
                // safe + threats should match scanned (treat failures/unknown as safe for display).
                Int32 safeForDisplay = filesScanned - threatForDisplay;
                if (safeForDisplay < 0) safeForDisplay = 0;

                _filesScanned = filesScanned;
                _filesSafe = safeForDisplay;
                _threatsFound = threatsFound;
                try
                {
                    FilesScannedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesScanned_Format"), filesScanned);
                    FilesSafeText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesSafe_Format"), safeForDisplay);
                    ThreatsFoundText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ThreatsFound_Format"), threatForDisplay);
                }
                catch { }
            });
        }

        private async void OnScanMenuClick(Object sender, RoutedEventArgs e)
        {
            ApplicationDataContainer settings = App.LocalSettings;
            Boolean UseLocalScan = settings.Values.TryGetValue("LocalScan", out object? localRaw) && localRaw is bool local && local;
            Boolean UseCloudScan = settings.Values.TryGetValue("CloudScan", out object? cloudRaw) && cloudRaw is bool cloud && cloud;
            Boolean UseModelScan = settings.Values.TryGetValue("ModelScan", out object? modelRaw) && modelRaw is bool model && model;
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

            if (sender is not MenuFlyoutItem { Tag: String tag }) return;
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
                IReadOnlyList<String> paths = await ShowMoreScanDialogAsync();
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
            Boolean UseLocalScan = settings.Values.TryGetValue("LocalScan", out object? localRaw) && localRaw is bool local && local;
            Boolean UseCloudScan = settings.Values.TryGetValue("CloudScan", out object? cloudRaw) && cloudRaw is bool cloud && cloud;
            Boolean UseModelScan = settings.Values.TryGetValue("ModelScan", out object? modelRaw) && modelRaw is bool model && model;
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

        private static IEnumerable<String> EnumerateFilesStreaming(ScanMode mode, String? userPath, IReadOnlyList<String>? customPaths)
        {
            switch (mode)
            {
                case ScanMode.Quick:
                    foreach (String f in GetEnumerateQuickScanFiles()) yield return f;
                    yield break;
                case ScanMode.Full:
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                    {
                        if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                            continue;
                        foreach (String file in SafeEnumerateFiles(drive.RootDirectory.FullName, [with(StringComparer.OrdinalIgnoreCase)]))
                            yield return file;
                    }
                    yield break;
                case ScanMode.File:
                    if (userPath != null && System.IO.File.Exists(userPath)) yield return userPath;
                    yield break;
                case ScanMode.Folder:
                    if (userPath != null && Directory.Exists(userPath))
                    {
                        foreach (String f in SafeEnumerateFolder(userPath)) yield return f;
                    }
                    yield break;
                case ScanMode.More:
                    if (customPaths != null)
                    {
                        foreach (String p in customPaths)
                        {
                            if (Directory.Exists(p))
                            {
                                foreach (String f in SafeEnumerateFolder(p)) yield return f;
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

        private async Task<IReadOnlyList<String>> ShowMoreScanDialogAsync()
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
                return [.. items.Select(i => i.Path)];
            }
            return [];
        }

        private void OnMoreScanRemovePathClick(Object sender, RoutedEventArgs e)
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

        private async void OnMoreScanBrowseFolderClick(Object sender, RoutedEventArgs e)
        {
            string? folder = await PickPathAsync(ScanMode.Folder);
            if (folder is null) return;
            await AddPathToMoreScanList(folder, true);
        }

        private async void OnMoreScanBrowseFileClick(Object sender, RoutedEventArgs e)
        {
            string? file = await PickPathAsync(ScanMode.File);
            if (file is null) return;
            await AddPathToMoreScanList(file, false);
        }

        private async Task AddPathToMoreScanList(String path, Boolean isFolder)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is not ObservableCollection<MoreScanItem> items) return;

            HashSet<String> existingPaths = new(items.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);

            if (existingPaths.Contains(path))
            {
                ContentDialog dup = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Content"), path),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                };
                _ = dup.ShowAsync();
                return;
            }

            items.Add(new MoreScanItem { Path = path, IsFolder = isFolder });
        }

        private void OnMoreScanClearClick(Object sender, RoutedEventArgs e)
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

            for (Int32 i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
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

        internal record ScanResult(String EngineName, String? VirusInfo, String? FamilyInfo = null);

        // Run configured scan engines against a single file and return the first detection (if any).
        internal static async Task<ScanResult> RunScansOnFileAsync(String filePath, Byte[]? _fileBytes, String? md5Hash,
            Boolean deepScan, Boolean extraData,
            Boolean useLocalScan, Boolean useCloudScan, Boolean useModelScan,
            Boolean _useInfectorCleaner, Boolean useVirusFamily,
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
                        (Boolean isVirus, String result) = ScanEngine.ModelEngineScan.ScanFile(filePath);
                        return new ScanResult(ScanEngine.ModelEngineScan.GetEngineDisplayName(), isVirus ? result : null);
                    }, token));
                }

                if (useLocalScan)
                {
                    scanTasks.Add(Helper.ScanEngine.LocalScanAsync(filePath, deepScan, extraData)
                        .ContinueWith(t =>
                        {
                            String localResult = t.Result;
                            String? info = !String.IsNullOrEmpty(localResult) ? (deepScan ? $"{localResult} with DeepScan" : localResult) : null;
                            return new ScanResult("Local", info);
                        }, TaskScheduler.Default));
                }

                if (useCloudScan && md5Hash != null)
                {
                    scanTasks.Add(Helper.ScanEngine.CloudScanWithHashAsync(md5Hash).ContinueWith(t =>
                    {
                        (Int32? statusCode, String? result) = t.Result;
                        String? info = (result == "virus_file") ? "MEMZUAC.Cloud.VirusFile" : null;
                        return new ScanResult("Cloud", info);
                    }, TaskScheduler.Default));
                }

                if (scanTasks.Count == 0)
                    return new ScanResult(String.Empty, null);

                ScanResult[] results;
                try
                {
                    results = await Task.WhenAll(scanTasks).WaitAsync(token);
                }
                catch (OperationCanceledException) { return new ScanResult(String.Empty, null); }
                catch
                {
                    return new ScanResult(String.Empty, null);
                }

                foreach (var r in results)
                {
                    if (!String.IsNullOrEmpty(r.VirusInfo))
                    {
                        if (useVirusFamily)
                        {
                            try
                            {
                                String familyResult = Xdows_Local.VirusFamilyEngine.GetVirusFamily(filePath, 0.8f);
                                if (!familyResult.StartsWith("HEUR:Malware"))
                                    return r with { FamilyInfo = familyResult };
                                return r with { FamilyInfo = Localizer.Get().GetLocalizedString("AllPage_Undefined") };
                            }
                            catch { }
                        }
                        return r;
                    }
                }

                return new ScanResult(String.Empty, null);
            }
            catch (OperationCanceledException) { return new ScanResult(String.Empty, null); }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - RunScansOnFileFailed", ex.Message);
                return new ScanResult(String.Empty, null);
            }
        }

        private async Task ScanArchiveFileAsync(Int32 scanId, String archivePath, Boolean deepScan, Boolean extraData, Boolean useLocalScan, Boolean useCloudScan, Boolean useModelScan, Boolean useInfectorCleaner, Boolean useVirusFamily, Helper.ScanEngine.ModelEngineScan? modelEngine, SemaphoreSlim scanGate, CancellationToken token)
        {
            try
            {
                List<(string EntryPath, byte[] Data)>? entries = null;
                string? password = null;

                try
                {
                    entries = await ArchiveScanner.ReadArchiveEntriesAsync(archivePath, true, password, token);
                }
                catch (Exception ex)
                {
                    bool isPasswordError = ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("密码", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("encrypted", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("crypt", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("解密", StringComparison.OrdinalIgnoreCase) ||
                                           ex.Message.Contains("加密", StringComparison.OrdinalIgnoreCase) ||
                                           (ex.InnerException != null && (
                                               ex.InnerException.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("密码", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("encrypted", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("crypt", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("解密", StringComparison.OrdinalIgnoreCase) ||
                                               ex.InnerException.Message.Contains("加密", StringComparison.OrdinalIgnoreCase)));

                    if (isPasswordError)
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
                    else
                    {
                        throw;
                    }
                }

                if (entries == null) return;

                foreach (var (entryPath, data) in entries)
                {
                    // respect pause and cancellation
                    while (_isPaused && !token.IsCancellationRequested)
                        await Task.Delay(100, token);
                    if (token.IsCancellationRequested) break;

                    string displayPath = $"{archivePath}\\{entryPath}";
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(scanId, token)) return;
                        LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ScanFile", displayPath);
                        try { StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning"), displayPath); } catch { }
                    });

                    string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    try
                    {
                        await File.WriteAllBytesAsync(tempFile, data, token);

                        if (TrustManager.IsPathTrusted(tempFile))
                        {
                            Interlocked.Increment(ref _filesSafe);
                            continue;
                        }

                        // ZIP entry already has bytes in memory - compute MD5 once, pass to all engines
                        string entryMd5 = ScanEngine.ComputeMD5(data);
                        var scanRes = await RunScansOnFileAsync(tempFile, data, entryMd5, deepScan, extraData, useLocalScan, useCloudScan, useModelScan, useInfectorCleaner, useVirusFamily, modelEngine, token);
                        string? virusResult = scanRes.VirusInfo;
                        if (!String.IsNullOrEmpty(virusResult))
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
                        else
                        {
                            Interlocked.Increment(ref _filesSafe);
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

        private async Task<String?> AskArchivePasswordAsync(String archivePath, Int32 scanId, CancellationToken token)
        {
            var tcs = new TaskCompletionSource<String?>();

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

            using (var registration = token.Register(() => tcs.TrySetCanceled()))
            {
                return await tcs.Task;
            }
        }

        public async Task StartScanAsync(String displayName, ScanMode mode, IReadOnlyList<String>? customPaths = null)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            Int32 thisId = Interlocked.Increment(ref _scanId);
            _isPaused = false;
            _zipFileThreats.Clear();

            var settings = App.LocalSettings;
            bool showScanProgress = settings.Values.TryGetValue("ShowScanProgress", out object? showProgressRaw) && showProgressRaw is bool showProgress && showProgress;
            bool showTaskbarProgress = !settings.Values.TryGetValue("ShowTaskbarScanProgress", out object? taskbarRaw) || taskbarRaw is not bool taskbar || taskbar;
            string scanIndexMode = settings.Values.TryGetValue("ScanIndexMode", out object? indexModeRaw) && indexModeRaw is string indexMode ? indexMode : "Parallel";
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
                    Xdows_Model_Invoker.ModelMode.Pro => "Pro",
                    _ => "Standard"
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
                _lastShowTaskbarProgress = showTaskbarProgress;
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
                _lastShowTaskbarProgress = showTaskbarProgress;
                ClearTaskbarProgress();
            }

            string? userPath = null;
            if (mode is ScanMode.File or ScanMode.Folder)
            {
                userPath = await PickPathAsync(mode);
                if (string.IsNullOrEmpty(userPath))
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Cancelled");
                        StopRadar();
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            _filesScanned = 0; _filesSafe = 0; _threatsFound = 0;
            UpdateScanStats(0, 0, 0);

            for (int i = 0; i < _scanItems!.Count; i++)
                UpdateScanItemStatus(i, Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting"), false, 0);

            CurrentResults = [];
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = CurrentResults;
                ScanProgress.Value = 0;
                ScanProgress.ShowPaused = false;
                ScanProgress.Visibility = Visibility.Visible;
                ProgressPercentText.Text = showScanProgress ? "0%" : string.Empty;
                PathText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_PathText_Format"), displayName);
                BackToVirusListButton.Visibility = Visibility.Collapsed;
                PauseScanButton.Visibility = Visibility.Visible;
                PauseScanButton.IsEnabled = false;
                ResumeScanButton.Visibility = Visibility.Collapsed;
                StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Processing");
                OnBackList(false);
                HandleAllButton.Visibility = Visibility.Collapsed;
                StartRadar();
            });

            await Task.Run(async () =>
            {
                try
                {
                    bool parallelIndex = scanIndexMode == "Parallel";

                    IEnumerable<string> files;
                    int total;

                    if (parallelIndex)
                    {
                        files = EnumerateFilesStreaming(mode, userPath, customPaths);
                        total = 0;
                    }
                    else
                    {
                        var filesList = EnumerateFiles(mode, userPath, customPaths);
                        files = filesList;
                        total = filesList.Count;
                    }

                    DateTime startTime = DateTime.Now;
                    DateTime lastSpeedUpdateUtc = DateTime.UtcNow;
                    Int32 lastSpeedScanned = 0;

                    int currentItemIndex = mode switch
                    {
                        ScanMode.Quick => 0,
                        ScanMode.Full => 1,
                        ScanMode.File => 2,
                        ScanMode.Folder => 3,
                        ScanMode.More => 0,
                        _ => 0
                    };

                    UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning"), true);
                    _dispatcherQueue.TryEnqueue(() => PauseScanButton.IsEnabled = true);

                    string tStatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning");
                    TimeSpan pausedTime = TimeSpan.Zero;
                    DateTime lastPauseTime = DateTime.MinValue;
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
                    int heavyScanCount = 0;

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
                            if (lastPauseTime == DateTime.MinValue) lastPauseTime = DateTime.Now;
                            try { await Task.Delay(100, ct); }
                            catch (OperationCanceledException) { return; }
                        }

                        if (lastPauseTime != DateTime.MinValue)
                        {
                            pausedTime += DateTime.Now - lastPauseTime;
                            lastPauseTime = DateTime.MinValue;
                        }

                        if (!IsCurrentScan(thisId, ct)) return;

                        bool shouldUpdateUi = (DateTime.UtcNow - lastUiUpdate).TotalMilliseconds >= UI_UPDATE_INTERVAL_MS;
                        if (shouldUpdateUi)
                        {
                            lastUiUpdate = DateTime.UtcNow;
                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                if (!IsCurrentScan(thisId, token)) return;
                                try { StatusText.Text = string.Format(tStatusText, file); } catch { }
                            });
                        }

                        // 快速路径：受信任文件直接跳过，不进scanGate，零内存开销
                        if (TrustManager.IsPathTrusted(file))
                        {
                            Interlocked.Increment(ref _filesSafe);
                            Interlocked.Increment(ref _filesScanned);
                            if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _filesSafe, _threatsFound); } catch { }
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

                                    if (exactRuleSuccess && !String.IsNullOrEmpty(result) && result != "safe")
                                    {
                                        Interlocked.Increment(ref Statistics.ScansQuantity);
                                        Interlocked.Increment(ref Statistics.VirusQuantity);
                                        string familyInfo = (UseVirusFamily && !String.IsNullOrEmpty(family)) ? family : String.Empty;

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
                                        int newThreats = Interlocked.Increment(ref _threatsFound);
                                        UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_FoundThreat"), true, newThreats);
                                        Interlocked.Increment(ref _filesScanned);
                                        if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _filesSafe, _threatsFound); } catch { }
                                        return;
                                    }
                                    else if (exactRuleSuccess && result == "safe")
                                    {
                                        Interlocked.Increment(ref _filesSafe);
                                        Interlocked.Increment(ref _filesScanned);
                                        if (shouldUpdateUi) try { UpdateScanStats(_filesScanned, _filesSafe, _threatsFound); } catch { }
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
                            await scanGate.WaitAsync(ct);
                            try
                            {
                                await ScanArchiveFileAsync(thisId, file, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, scanGate, ct);
                            }
                            finally { scanGate.Release(); }
                            return;
                        }

                        // 重扫描：scanGate限制并发，不预读文件，由引擎按需读取
                        await scanGate.WaitAsync(ct);
                        try
                        {
                            var scanRes = await RunScansOnFileAsync(file, null, null, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, ct);
                            Interlocked.Increment(ref Statistics.ScansQuantity);
                            if (!String.IsNullOrEmpty(scanRes.VirusInfo))
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
                                                    String threatName = $"Infector.{cleanResult.MaliciousSection?.TrimStart('.') ?? "Unknown"}!ml";
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
                                    AddVirusResult(file, scanRes.VirusInfo ?? String.Empty, scanRes.FamilyInfo, scanRes.EngineName, UseVirusFamily);
                                    ShowBackToVirusListButton();
                                });
                                int newThreats = Interlocked.Increment(ref _threatsFound);
                                UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_FoundThreat"), true, newThreats);
                            }
                            else
                            {
                                Interlocked.Increment(ref _filesSafe);
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
                            // 每200个重扫描触发GC回收，防止内存堆积
                            if (Interlocked.Increment(ref heavyScanCount) % 200 == 0)
                                GC.Collect(0, GCCollectionMode.Optimized, false);
                        }

                        Interlocked.Increment(ref _filesScanned);

                        if (shouldUpdateUi)
                        {
                            TimeSpan elapsedTime = DateTime.Now - startTime - pausedTime;
                            DateTime nowUtc = DateTime.UtcNow;
                            double scanSpeed = 0.0;
                            double speedWindowSeconds = (nowUtc - lastSpeedUpdateUtc).TotalSeconds;
                            if (speedWindowSeconds >= 1.0)
                            {
                                Int32 nowScanned = _filesScanned;
                                Int32 delta = nowScanned - lastSpeedScanned;
                                scanSpeed = speedWindowSeconds > 0 ? delta / speedWindowSeconds : 0.0;
                                lastSpeedScanned = nowScanned;
                                lastSpeedUpdateUtc = nowUtc;
                            }
                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                if (!IsCurrentScan(thisId, token)) return;
                                try
                                {
                                    if (speedWindowSeconds >= 1.0)
                                        ScanSpeedText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanSpeed_Format"), scanSpeed);
                                }
                                catch { }
                            });

                            if (showScanProgress)
                            {
                                double percent = total == 0 ? 100 : (double)_filesScanned / total * 100;
                                if (percent > 100) percent = 100;
                                _dispatcherQueue.TryEnqueue(() =>
                                {
                                    try { ScanProgress.Value = percent; ProgressPercentText.Text = $"{percent:F0}%"; } catch { }
                                });

                                if (showTaskbarProgress && !_isPaused)
                                {
                                    try { TaskbarProgressService.TrySetNormal(percent / 100.0); } catch { }
                                }
                            }

                            try { UpdateScanStats(_filesScanned, _filesSafe, _threatsFound); } catch { }
                        }
                    });
                    if (UseExactRule)
                    {
                        try { exactRuleChannel.Writer.Complete(); } catch { }
                        try { if (exactRuleBatchTask != null) await exactRuleBatchTask.WaitAsync(TimeSpan.FromSeconds(10), token); } catch { }
                    }
                    scanGate.Dispose();
                    hashGate.Dispose();

                    UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_Completed"), false, _threatsFound);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(thisId, token)) return;
                        ApplicationDataContainer settingsLocal = App.LocalSettings;
                        settingsLocal.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);
                        ScanProgress.ShowPaused = false;
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadar();
                        UpdateHandleAllButtonVisibility();
                    });
                    ClearTaskbarProgress();
                }
                catch (OperationCanceledException)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(thisId, token)) return;
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanCancelled");
                        ScanProgress.ShowPaused = false;
                        ScanProgress.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadar();
                        HandleAllButton.Visibility = Visibility.Collapsed;
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
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadar();
                        HandleAllButton.Visibility = Visibility.Collapsed;
                    });
                    ClearTaskbarProgress();
                }
            });

            ScanButton.IsEnabled = true;
        }

        private void OnBackToVirusListClick(Object sender, RoutedEventArgs e)
        {
            OnBackList(VirusList.Visibility != Visibility.Visible);
        }

        private void OnBackList(Boolean isShow)
        {
            if (isShow)
            {
                ShowWithEntranceAnimation(VirusList);
            }
            else
            {
                VirusList.Visibility = Visibility.Collapsed;
            }

            BackToVirusListButtonText.Text = isShow ? Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Hide") : Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Show");
            BackToVirusListButtonIcon.Glyph = isShow ? "\uED1A" : "\uE890";
        }

        private void OnPauseScanClick(Object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            ScanButton.IsEnabled = true;
            PauseScanButton.Visibility = Visibility.Collapsed;
            ShowWithEntranceAnimation(ResumeScanButton, "right");
            PauseRadar();
            ScanProgress.ShowPaused = true;

            if (_taskbarProgressActive)
            {
                try
                {
                    if (_lastShowScanProgress)
                    {
                        var total = _scanItems?.Count ?? 0;
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

        private void OnResumeScanClick(Object sender, RoutedEventArgs e)
        {
            _isPaused = false;
            ScanButton.IsEnabled = false;
            ShowWithEntranceAnimation(PauseScanButton, "right");
            ResumeScanButton.Visibility = Visibility.Collapsed;
            ResumeRadar();
            ScanProgress.ShowPaused = false;

            UpdateTaskbarProgressStateForRunning();
        }

        private async void OnVirusRowDetailsClick(Object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await ShowDetailsDialog(row);
            }
        }

        private async void OnVirusRowTrustClick(Object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await OnTrustClickInternal(row);
            }
        }

        private async void OnVirusRowHandleClick(Object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem { Tag: VirusRow row })
            {
                await OnHandleClickInternal(row);
            }
        }

        private async void VirusList_DoubleTapped(Object sender, DoubleTappedRoutedEventArgs e)
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

            Boolean isDetailsPause = false;
            try
            {
                isDetailsPause = PauseScanButton.Visibility == Visibility.Visible && PauseScanButton.IsEnabled;
                if (isDetailsPause)
                {
                    OnPauseScanClick(new Object(), new RoutedEventArgs());
                }

                String displayPath = row.FilePath;
                String? archivePath = null;
                String? entryPath = null;
                Boolean isArchiveEntry = TryParseArchiveEntry(displayPath, out archivePath, out entryPath);
                Boolean isZipEntry = false;

                if (isArchiveEntry)
                {
                    // 进一步检查是否为 zip 格式，用于获取 entry 信息
                    isZipEntry = String.Equals(Path.GetExtension(archivePath), ".zip", StringComparison.OrdinalIgnoreCase);
                }

                String fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String creationTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String lastWriteTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");

                if (isZipEntry && archivePath != null && entryPath != null)
                {
                    try
                    {
                        var entryInfo = await ZipScanner.GetEntryInfoAsync(archivePath, entryPath);
                        if (entryInfo.HasValue)
                        {
                            fileSizeText = String.Format(CultureInfo.CurrentCulture, "{0:F2} KB", entryInfo.Value.Size / 1024.0);
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
                        fileSizeText = String.Format(CultureInfo.CurrentCulture, "{0:F2} KB", fileInfo.Length / 1024.0);
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

                static String ToLabelFromTemplate(String template)
                {
                    if (String.IsNullOrWhiteSpace(template)) return template;

                    var label = TemplateBraceRegex().Replace(template, String.Empty);
                    label = WhitespaceRegex().Replace(label, " ").Trim();
                    label = UnitSuffixRegex().Replace(label, String.Empty).Trim();

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
                    String familyDisplay = String.IsNullOrWhiteSpace(row.FamilyName)
                        ? Localizer.Get().GetLocalizedString("AllPage_Undefined")
                        : row.FamilyName;
                    items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FamilyName")), new TextBlock { Text = familyDisplay, IsTextSelectionEnabled = true }));
                }

                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FileSize")), new TextBlock { Text = fileSizeText, IsTextSelectionEnabled = true }));
                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_CreationTime")), new TextBlock { Text = creationTimeText, IsTextSelectionEnabled = true }));
                items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_LastWriteTime")), new TextBlock { Text = lastWriteTimeText, IsTextSelectionEnabled = true }));

                if (!String.IsNullOrWhiteSpace(row.EngineName))
                {
                    items.Add((ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_EngineName")), new TextBlock { Text = row.EngineName, IsTextSelectionEnabled = true }));
                }

                if (!isArchiveEntry && System.IO.File.Exists(displayPath))
                {
                    try
                    {
                        String sha256 = await Helper.ScanEngine.GetFileSHA256Async(displayPath);
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
                                ? String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Risk_ArchiveContent"), archivePath)
                                : String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Risk_FileContent"), displayPath),
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
                                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_LocateFailed_Content"), ex.Message),
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
                    ContentDialog failDlg = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_GetFailed_Text"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };
                    await failDlg.ShowAsync();
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
                        OnResumeScanClick(new Object(), new RoutedEventArgs());
                    }
                    catch (Exception resumeEx)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - ResumeFailed", resumeEx.Message);
                    }
                }
            }
        }

        private async Task<String?> PickPathAsync(ScanMode mode)
        {
            try
            {
                if (mode == ScanMode.File)
                {
                    PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
                    if (file is null) { return null; }
                    return file.Path;
                }
                else
                {
                    PickFolderResult folder = await (new FolderPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFolderAsync());
                    if (folder is null) { return null; }
                    return folder.Path;
                }
            }
            catch { return null; }
        }

        private static List<String> EnumerateFiles(ScanMode mode, String? userPath, IReadOnlyList<String>? customPaths) => mode switch
        {
            ScanMode.Quick => [.. GetEnumerateQuickScanFiles()],
            ScanMode.Full => [.. EnumerateFullScanFiles()],
            ScanMode.File => (userPath != null && System.IO.File.Exists(userPath))
                              ? [userPath]
                              : [],
            ScanMode.Folder => (userPath != null && Directory.Exists(userPath))
                              ? [.. SafeEnumerateFolder(userPath)]
                              : [],
            ScanMode.More => customPaths?.SelectMany(p =>
            {
                if (Directory.Exists(p))
                    return SafeEnumerateFolder(p);
                else if (System.IO.File.Exists(p))
                    return [p];
                return [];
            }).ToList() ?? [],
            _ => []
        };

        private static IEnumerable<String> SafeEnumerateFolder(String folder)
        {
            Stack<String> stack = new();
            stack.Push(folder);

            while (stack.Count > 0)
            {
                String dir = stack.Pop();

                IEnumerable<String> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                foreach (String entry in entries)
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
            String[] criticalPaths =
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

            HashSet<String> extensions = [with(StringComparer.OrdinalIgnoreCase), ".exe", ".dll", ".sys", ".com", ".scr", ".bat"];

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

        private static IEnumerable<String> EnumerateFullScanFiles()
        {
            HashSet<String> scanned = [with(StringComparer.OrdinalIgnoreCase)];

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                    continue;

                foreach (String file in SafeEnumerateFiles(drive.RootDirectory.FullName, scanned))
                    yield return file;
            }
        }

        private static IEnumerable<String> SafeEnumerateFiles(String root, HashSet<String> scanned)
        {
            Stack<String> stack = new();
            stack.Push(root);

            while (stack.Count > 0)
            {
                String currentDir = stack.Pop();

                if (!scanned.Add(currentDir))
                    continue;

                IEnumerable<String>? entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(currentDir);
                }
                catch
                {
                    continue;
                }

                foreach (String entry in entries)
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
