using Compatibility.Windows.Storage;
using Helper;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;
using Xdows_Security.Services;

namespace Xdows_Security.Views
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public class VirusRow : INotifyPropertyChanged
    {
        private String _filePath = String.Empty;
        private String _virusName = String.Empty;
        private String _familyName = String.Empty;

        public String FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); }
        }

        public String VirusName
        {
            get => _virusName;
            set { _virusName = value; OnPropertyChanged(); }
        }

        public String FamilyName
        {
            get => _familyName;
            set { _familyName = value; OnPropertyChanged(); OnPropertyChanged(nameof(FamilyNameVisibility)); }
        }

        public Visibility FamilyNameVisibility => String.IsNullOrWhiteSpace(_familyName) ? Visibility.Collapsed : Visibility.Visible;

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
        private DispatcherQueue _dispatcherQueue;
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
        private readonly Dictionary<String, List<(String EntryPath, String VirusName)>> _zipFileThreats = [];
        private ObservableCollection<VirusRow>? CurrentResults;
        private List<ScanItem>? _scanItems;

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
            Unloaded += SecurityPage_Unloaded;
        }

        private void SecurityPage_Unloaded(object sender, RoutedEventArgs e)
        {
            ClearTaskbarProgress();
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

        private void AddVirusResult(String filePath, String virusName, String? familyName = null)
        {
            VirusRow row = new()
            {
                FilePath = filePath,
                VirusName = virusName,
                FamilyName = familyName ?? String.Empty
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
            String? zipPath = null;
            String? entryPath = null;

            Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
            if (zipIndex > 0)
            {
                zipPath = displayPath[..(zipIndex + 4)];
                entryPath = displayPath[(zipIndex + 5)..];
            }

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
                    var result = await Task.Run(async () =>
                    {
                        Boolean handled = false;
                        String actionTaken = "";

                        if (zipPath != null && entryPath != null && _zipFileThreats.ContainsKey(zipPath))
                        {
                            var threatsInZip = _zipFileThreats[zipPath];
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
                                            var threatInfo = threatsInZip.FirstOrDefault(t => t.EntryPath == entry);
                                            String virusName = threatInfo.VirusName ?? row.VirusName ?? "Unknown";
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

                        return (handled, actionTaken, zipPath, entryPath);
                    });

                    if (result.handled && result.zipPath != null && result.entryPath != null)
                    {
                        var entriesToDelete = new List<String>();
                        if (_zipFileThreats.ContainsKey(result.zipPath))
                        {
                            var threatsInZip = _zipFileThreats[result.zipPath];
                            foreach (var (EntryPath, VirusName) in threatsInZip)
                            {
                                if (EntryPath == result.entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(result.entryPath + "\\")))
                                {
                                    entriesToDelete.Add(EntryPath);
                                }
                            }

                            foreach (var entry in entriesToDelete)
                            {
                                VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == $"{result.zipPath}\\{entry}");
                                if (itemToRemove != null)
                                {
                                    CurrentResults.Remove(itemToRemove);
                                    _threatsFound--;
                                }
                            }

                            _zipFileThreats.Remove(result.zipPath);
                        }
                    }

                    dialog.Content = new TextBlock
                    {
                        Text = result.actionTaken,
                        TextWrapping = TextWrapping.Wrap
                    };

                    dialog.CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm");
                    dialog.DefaultButton = ContentDialogButton.Close;

                    if (result.handled)
                    {
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

        private void StartRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                if (RadarScanLine == null) return;
                RadarLineAppearStoryboard.Begin();
                RadarScanStoryboard.Begin();
            });
        }

        private void StopRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                if (RadarScanLine == null) return;
                RadarLineDisappearStoryboard.Begin();
                RadarScanStoryboard.Stop();
            });
        }

        private void PauseRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                RadarScanStoryboard.Pause();
            });
        }

        private void ResumeRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                RadarScanStoryboard.Resume();
            });
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

        private void UpdateScanStats(Int32 filesScanned, Int32 filesSafe, Int32 threatsFound)
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
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            Boolean UseLocalScan = (settings.Values["LocalScan"] as Boolean?).GetValueOrDefault();
            Boolean UseCzkCloudScan = (settings.Values["CzkCloudScan"] as Boolean?).GetValueOrDefault();
            Boolean UseCloudScan = (settings.Values["CloudScan"] as Boolean?).GetValueOrDefault();
            Boolean UseModelScan = (settings.Values["ModelScan"] as Boolean?).GetValueOrDefault();
            if (!UseLocalScan && !UseCzkCloudScan && !UseCloudScan && !UseModelScan)
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
                        foreach (String file in SafeEnumerateFiles(drive.RootDirectory.FullName, new HashSet<String>(StringComparer.OrdinalIgnoreCase)))
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

        private record ScanResult(String EngineName, String? VirusInfo, String? FamilyInfo = null);

        // Run configured scan engines against a single file and return the first detection (if any).
        private async Task<ScanResult> RunScansOnFileAsync(String filePath, Byte[]? fileBytes, String? md5Hash,
            Boolean deepScan, Boolean extraData,
            Boolean useLocalScan, Boolean useCloudScan, Boolean useCzkCloudScan, Boolean useModelScan,
            Boolean useInfectorCleaner, Boolean useVirusFamily,
            Helper.ScanEngine.ModelEngineScan? modelEngine,
            String czkApiKey, CancellationToken token)
        {
            try
            {
                // 流式计算MD5一次，两个云引擎共享（128KB缓冲，不加载整个文件）
                if ((useCloudScan || useCzkCloudScan) && md5Hash == null)
                {
                    try { md5Hash = await ScanEngine.GetFileMD5Async(filePath); } catch { }
                }

                var scanTasks = new List<Task<ScanResult>>();

                if (useModelScan && modelEngine != null)
                {
                    scanTasks.Add(Task.Run(() =>
                    {
                        (Boolean isVirus, String result) = ScanEngine.ModelEngineScan.ScanFile(filePath);
                        return new ScanResult("Xdows-Model", isVirus ? result : null);
                    }));
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

                if (useCzkCloudScan && md5Hash != null)
                {
                    scanTasks.Add(Helper.ScanEngine.CzkCloudScanWithHashAsync(md5Hash, czkApiKey).ContinueWith(t =>
                    {
                        (Int32? statusCode, String? result) = t.Result;
                        String? info = (result != "safe") ? (result ?? String.Empty) : null;
                        return new ScanResult("CzkCloud", info);
                    }, TaskScheduler.Default));
                }

                if (scanTasks.Count == 0)
                    return new ScanResult(String.Empty, null);

                ScanResult[] results;
                try
                {
                    results = await Task.WhenAll(scanTasks);
                }
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

        private async Task ScanZipFileAsync(Int32 scanId, String zipPath, Boolean deepScan, Boolean extraData, Boolean useLocalScan, Boolean useCloudScan, Boolean useCzkCloudScan, Boolean useModelScan, Boolean useInfectorCleaner, Boolean useVirusFamily, Helper.ScanEngine.ModelEngineScan? modelEngine, String czkApiKey, CancellationToken token)
        {
            try
            {
                var entries = await ZipScanner.ReadZipEntriesAsync(zipPath, true);

                foreach (var (entryPath, data) in entries)
                {
                    // respect pause and cancellation
                    while (_isPaused && !token.IsCancellationRequested)
                        await Task.Delay(100, token);
                    if (token.IsCancellationRequested) break;

                    string displayPath = $"{zipPath}\\{entryPath}";
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
                        var scanRes = await RunScansOnFileAsync(tempFile, data, entryMd5, deepScan, extraData, useLocalScan, useCloudScan, useCzkCloudScan, useModelScan, useInfectorCleaner, useVirusFamily, modelEngine, czkApiKey, token);
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
                                if (!_zipFileThreats.ContainsKey(zipPath))
                                    _zipFileThreats[zipPath] = new List<(string, string)>();
                                _zipFileThreats[zipPath].Add((entryPath, virusResult));
                            }

                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                if (!IsCurrentScan(scanId, token)) return;
                                AddVirusResult($"{zipPath}\\{entryPath}", virusResult, scanRes.FamilyInfo);
                                BackToVirusListButton.Visibility = Visibility.Visible;
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

        public async Task StartScanAsync(String displayName, ScanMode mode, IReadOnlyList<String>? customPaths = null)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            Int32 thisId = Interlocked.Increment(ref _scanId);
            _isPaused = false;
            _zipFileThreats.Clear();

            var settings = ApplicationData.Current.LocalSettings;
            bool showScanProgress = settings.Values["ShowScanProgress"] as bool? ?? false;
            bool showTaskbarProgress = settings.Values["ShowTaskbarScanProgress"] as bool? ?? true;
            string scanIndexMode = settings.Values["ScanIndexMode"] as string ?? "Parallel";
            bool DeepScan = settings.Values["DeepScan"] as bool? ?? false;
            bool ExtraData = settings.Values["ExtraData"] as bool? ?? false;
            bool UseLocalScan = settings.Values["LocalScan"] as bool? ?? false;
            bool UseCzkCloudScan = settings.Values["CzkCloudScan"] as bool? ?? false;
            bool UseCloudScan = settings.Values["CloudScan"] as bool? ?? false;
            bool UseModelScan = settings.Values["ModelScan"] as bool? ?? false;
            bool UseInfectorCleaner = settings.Values["InfectorCleaner"] as bool? ?? false;
            bool UseVirusFamily = settings.Values["VirusFamily"] as bool? ?? false;
            bool UseExactRule = settings.Values["ExactRuleScan"] as bool? ?? false;

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
            if (UseCzkCloudScan) enginesLog += " CzkCloudScan";
            if (UseCloudScan) enginesLog += " CloudScan";
            if (UseModelScan) enginesLog += " Xdows-Model";
            if (UseInfectorCleaner) enginesLog += " InfectorCleaner";
            if (UseVirusFamily) enginesLog += " VirusFamily";
            if (UseExactRule) enginesLog += " ExactRule";
            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - StartScan", enginesLog);

            _dispatcherQueue.TryEnqueue(() =>
            {
                VirusList.ItemTemplate = UseVirusFamily
                    ? (DataTemplate)Resources["VirusRowWithFamilyTemplate"]
                    : (DataTemplate)Resources["VirusRowTemplate"];
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
                        StopRadarAnimation();
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            _filesScanned = 0; _filesSafe = 0; _threatsFound = 0;
            UpdateScanStats(0, 0, 0);

            for (int i = 0; i < _scanItems!.Count; i++)
                UpdateScanItemStatus(i, Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting"), false, 0);

            CurrentResults = new ObservableCollection<VirusRow>();
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = CurrentResults;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                ProgressPercentText.Text = showScanProgress ? "0%" : string.Empty;
                PathText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_PathText_Format"), displayName);
                BackToVirusListButton.Visibility = Visibility.Collapsed;
                PauseScanButton.Visibility = Visibility.Visible;
                PauseScanButton.IsEnabled = false;
                ResumeScanButton.Visibility = Visibility.Collapsed;
                StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Processing");
                OnBackList(false);
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
                    string czkApiKey = App.GetCzkCloudApiKey();
                    bool ScanInside = settings.Values["ScanInside"] as bool? ?? false;

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
                                            foreach (var b in batch)
                                            {
                                                if (batchResults.TryGetValue(b.filePath, out var r)) b.tcs.TrySetResult(r);
                                                else b.tcs.TrySetResult((null, null));
                                            }
                                        }
                                        catch (OperationCanceledException)
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleBatchCanceled", $"Batch of {batch.Count} files canceled");
                                            foreach (var b in batch) b.tcs.TrySetCanceled(token);
                                            break;
                                        }
                                        catch (Exception ex)
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleBatchFailed", $"Batch of {batch.Count} files failed: {ex.Message}");
                                            foreach (var b in batch) b.tcs.TrySetResult((null, null));
                                        }
                                        batch.Clear();
                                    }
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleWorkerCanceled", "Batch worker canceled");
                                foreach (var b in batch) b.tcs.TrySetCanceled(token);
                            }
                            catch (ChannelClosedException)
                            {
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ExactRuleChannelClosed", "Channel closed normally");
                            }
                            catch (Exception ex)
                            {
                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleWorkerError", ex.Message);
                                foreach (var b in batch) b.tcs.TrySetResult((null, null));
                            }
                            if (batch.Count > 0)
                            {
                                try
                                {
                                    var hashEntries = batch.Select(b => (b.filePath, b.sha256)).ToList();
                                    var batchResults = await Helper.ScanEngine.ExactRuleEngineBatchScanHashesAsync(hashEntries, token);
                                    foreach (var b in batch)
                                    {
                                        if (batchResults.TryGetValue(b.filePath, out var r)) b.tcs.TrySetResult(r);
                                        else b.tcs.TrySetResult((null, null));
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    foreach (var b in batch) b.tcs.TrySetCanceled(token);
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ExactRuleFinalBatchFailed", $"Final batch of {batch.Count} files failed: {ex.Message}");
                                    foreach (var b in batch) b.tcs.TrySetResult((null, null));
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
                                                AddVirusResult(file, result, familyInfo);
                                                BackToVirusListButton.Visibility = Visibility.Visible;
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

                        if (ScanInside && ZipScanner.IsZipFile(file))
                        {
                            await scanGate.WaitAsync(ct);
                            try
                            {
                                await ScanZipFileAsync(thisId, file, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseCzkCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, czkApiKey, ct);
                            }
                            finally { scanGate.Release(); }
                            return;
                        }

                        // 重扫描：scanGate限制并发，不预读文件，由引擎按需读取
                        await scanGate.WaitAsync(ct);
                        try
                        {
                            var scanRes = await RunScansOnFileAsync(file, null, null, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseCzkCloudScan, UseModelScan, UseInfectorCleaner, UseVirusFamily, ModelEngine, czkApiKey, ct);
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
                                    AddVirusResult(file, scanRes.VirusInfo ?? String.Empty, scanRes.FamilyInfo);
                                    BackToVirusListButton.Visibility = Visibility.Visible;
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

                                if (showTaskbarProgress)
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
                        ApplicationDataContainer settingsLocal = ApplicationData.Current.LocalSettings;
                        settingsLocal.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
                    });
                    ClearTaskbarProgress();
                }
                catch (OperationCanceledException)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        if (!IsCurrentScan(thisId, token)) return;
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanCancelled");
                        ScanProgress.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
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
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
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
            VirusList.Visibility = isShow ? Visibility.Visible : Visibility.Collapsed;
            BackToVirusListButtonText.Text = isShow ? Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Hide") : Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Show");
            BackToVirusListButtonIcon.Glyph = isShow ? "\uED1A" : "\uE890";
        }

        private void OnPauseScanClick(Object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            ScanButton.IsEnabled = true;
            PauseScanButton.Visibility = Visibility.Collapsed;
            ResumeScanButton.Visibility = Visibility.Visible;
            PauseRadarAnimation();

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
            PauseScanButton.Visibility = Visibility.Visible;
            ResumeScanButton.Visibility = Visibility.Collapsed;
            ResumeRadarAnimation();

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

        private async Task ShowDetailsDialog(VirusRow? row)
        {
            Boolean isDetailsPause = false;
            Boolean scanWasResumed = false;
            try
            {
                if (row is null) return;
                isDetailsPause = PauseScanButton.Visibility == Visibility.Visible && PauseScanButton.IsEnabled;
                if (isDetailsPause)
                {
                    OnPauseScanClick(new Object(), new RoutedEventArgs());
                }

                String displayPath = row.FilePath;
                String? zipPath = null;
                String? entryPath = null;
                Boolean isZipEntry = false;

                Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
                if (zipIndex > 0)
                {
                    zipPath = displayPath.Substring(0, zipIndex + 4);
                    entryPath = displayPath.Substring(zipIndex + 5);
                    isZipEntry = true;
                }

                String fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String creationTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String lastWriteTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");

                if (isZipEntry && zipPath != null && entryPath != null)
                {
                    try
                    {
                        var entryInfo = await ZipScanner.GetEntryInfoAsync(zipPath, entryPath);
                        if (entryInfo.HasValue)
                        {
                            fileSizeText = String.Format("{0:F2} KB", entryInfo.Value.Size / 1024.0);
                            creationTimeText = entryInfo.Value.CreationTime.ToString();
                            lastWriteTimeText = entryInfo.Value.LastWriteTime.ToString();
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
                        fileSizeText = String.Format("{0:F2} KB", fileInfo.Length / 1024.0);
                        creationTimeText = fileInfo.CreationTime.ToString();
                        lastWriteTimeText = fileInfo.LastWriteTime.ToString();
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

                    var label = System.Text.RegularExpressions.Regex.Replace(template, "\\{[^}]*\\}", String.Empty);
                    label = System.Text.RegularExpressions.Regex.Replace(label, "\\s+", " ").Trim();
                    label = System.Text.RegularExpressions.Regex.Replace(label, "\\s+\\b(KB|MB|GB|TB|B)\\b\\s*$", String.Empty).Trim();

                    while (label.EndsWith(":", StringComparison.Ordinal) || label.EndsWith("：", StringComparison.Ordinal))
                        label = label.Substring(0, label.Length - 1).TrimEnd();

                    return label;
                }

                var items = new List<(string Key, FrameworkElement Value)>
                {
                    (Localizer.Get().GetLocalizedString("SecurityPage_Details_FilePath"), new RichTextBlock
                    {
                        IsTextSelectionEnabled = true,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 14,
                        FontFamily = new FontFamily("Segoe UI"),
                        Blocks = { new Paragraph { Inlines = { new Run { Text = displayPath } } } }
                    }),
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_VirusName")), new TextBlock { Text = row.VirusName, IsTextSelectionEnabled = true, TextWrapping = TextWrapping.Wrap }),
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_FileSize")), new TextBlock { Text = fileSizeText, IsTextSelectionEnabled = true }),
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_CreationTime")), new TextBlock { Text = creationTimeText, IsTextSelectionEnabled = true }),
                    (ToLabelFromTemplate(Localizer.Get().GetLocalizedString("SecurityPage_Details_LastWriteTime")), new TextBlock { Text = lastWriteTimeText, IsTextSelectionEnabled = true })
                };

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
                    PrimaryButtonText = isZipEntry ? null : Localizer.Get().GetLocalizedString("SecurityPage_Details_LocateButton"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Close
                };
                if (!isZipEntry && await dialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    try
                    {
                        String filePath = displayPath;
                        String? directoryPath = Path.GetDirectoryName(filePath);
                        String fileName = Path.GetFileName(filePath);

                        System.Diagnostics.ProcessStartInfo psi = new()
                        {
                            FileName = "explorer.exe",
                        };
                        String safeFilePath = filePath.Replace("\"", "\\\"");
                        psi.Arguments = $"/select,\"{safeFilePath}\"";
                        System.Diagnostics.Process.Start(psi);
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
                else if (isZipEntry)
                {
                    await dialog.ShowAsync();
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
                if (isDetailsPause && !scanWasResumed)
                {
                    try
                    {
                        OnResumeScanClick(new Object(), new RoutedEventArgs());
                        scanWasResumed = true;
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

            HashSet<String> extensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".com", ".scr", ".bat" };

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
            HashSet<String> scanned = new(StringComparer.OrdinalIgnoreCase);

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
    }
}
