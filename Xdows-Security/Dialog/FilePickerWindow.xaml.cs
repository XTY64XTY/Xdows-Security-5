using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.Graphics;
using Windows.System;
using Windows.UI.Core;
using WinRT.Interop;
using WinUI3Localizer;
using WinUIEx;
using Xdows_Security.Services;

namespace Xdows_Security;

/// <summary>
/// 应用内文件选择器窗口。外观与交互全部由 WinUI 控件实现，不依赖 shell 通用对话框。
/// 通过 owner 关系 + 禁用父窗口实现模态。
/// </summary>
public sealed partial class FilePickerWindow : Window
{
    private readonly FilePickerOptions _options;
    private readonly TaskCompletionSource<IReadOnlyList<string>> _result =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ObservableCollection<FilePickerEntry> _entries = [];
    private readonly List<string> _history = [];
    private readonly List<FilePickerTypeGroup> _typeGroups = [];

    private int _historyIndex = -1;
    private int _loadVersion;
    private string _currentDirectory = string.Empty;
    private bool _suppressLocationChanged;
    private bool _suppressFilterChanged;
    private bool _completed;
    private CancellationTokenSource? _loadingCts;
    private nint _ownerHwnd;
    private bool _ownerDisabled;

    /// <summary>以模态方式显示选择器；用户取消或关闭时返回空集合。</summary>
    internal static async Task<IReadOnlyList<string>> ShowAsync(nint ownerHwnd, FilePickerOptions options)
    {
        try
        {
            var window = new FilePickerWindow(options);
            window._ownerHwnd = ownerHwnd;
            nint hwnd = WindowNative.GetWindowHandle(window);
            SetWindowLongPtr(hwnd, GWLP_HWNDPARENT, ownerHwnd);

            window._ownerDisabled = true;
            EnableWindow(ownerHwnd, false);
            try
            {
                window.Activate();
                return await window._result.Task;
            }
            finally
            {
                window.RestoreOwner();
                SetForegroundWindow(ownerHwnd);
            }
        }
        catch (Exception ex)
        {
            LogText.AddNewLog(LogText.LogLevel.ERROR, "FilePicker", ex.ToString());
            throw;
        }
    }

    private FilePickerWindow(FilePickerOptions options)
    {
        _options = options;
        InitializeComponent();

        var manager = WindowManager.Get(this);
        manager.MinWidth = 760;
        manager.MinHeight = 480;
        manager.Width = 960;
        manager.Height = 640;
        manager.IsMinimizable = false;

        // 自绘 TitleBar 只有配合 ExtendsContentIntoTitleBar 才是可拖动区域。
        // WinUIEx 的 IsTitleBarVisible=false 会直接剥掉 WS_CAPTION，窗口便无法拖动。
        ExtendsContentIntoTitleBar = true;
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

        SystemBackdrop = new MicaBackdrop();
        if (App.Theme != ElementTheme.Default)
        {
            RootGrid.RequestedTheme = App.Theme;
        }

        PickerTitleBar.Title = options.Mode switch
        {
            FilePickerMode.Save => Localizer.Get().GetLocalizedString("FilePicker_Title_Save"),
            FilePickerMode.Folder => Localizer.Get().GetLocalizedString("FilePicker_Title_Folder"),
            _ => Localizer.Get().GetLocalizedString("FilePicker_Title_Open")
        };

        CancelButton.Content = Localizer.Get().GetLocalizedString("Button_Cancel");
        ToolTipService.SetToolTip(BackButton, Localizer.Get().GetLocalizedString("FilePicker_Nav_Back"));
        ToolTipService.SetToolTip(ForwardButton, Localizer.Get().GetLocalizedString("FilePicker_Nav_Forward"));
        ToolTipService.SetToolTip(UpButton, Localizer.Get().GetLocalizedString("FilePicker_Nav_Up"));

        BuildTypeGroups();
        ApplyModeChrome();

        Closed += FilePickerWindow_Closed;
        RootGrid.Loaded += RootGrid_Loaded;
        ContentHost.SizeChanged += ContentHost_SizeChanged;
        AppWindow.Changed += FilePickerWindow_AppWindowChanged;
        CenterOnWorkArea();
    }

    /// <summary>
    /// 根容器在测量时拿不到客户区高度，内容一多就按内容撑高，`*` 行跟着长高，
    /// 列表于是越过底栏。这里把根容器上限钉在客户区高度上，让 `*` 行按真实剩余空间分配。
    /// </summary>
    private void UpdateRootHeightConstraint()
    {
        XamlRoot? xamlRoot = RootGrid.XamlRoot;
        if (xamlRoot is null)
        {
            return;
        }

        SizeInt32 client = AppWindow.ClientSize;
        if (client.Height <= 0)
        {
            return;
        }

        double scale = xamlRoot.RasterizationScale;
        if (scale <= 0)
        {
            scale = 1;
        }

        RootGrid.MaxHeight = client.Height / scale;
    }

    private void FilePickerWindow_AppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (args.DidSizeChange)
        {
            UpdateRootHeightConstraint();
        }
    }

    /// <summary>
    /// WinUI 的 Grid 默认不做 ClipToBounds，子元素测量结果一旦超出所在行就会直接画到行外
    /// （表现为文件列表压到底栏上）。在内容区这一层按实际尺寸裁剪，把溢出从源头挡住，
    /// 这样底栏保持半透明也不会透出列表。
    /// </summary>
    private void ContentHost_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        ApplyContentClip();
    }

    private void ApplyContentClip()
    {
        double width = ContentHost.ActualWidth;
        double height = ContentHost.ActualHeight;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        ContentHost.Clip = new RectangleGeometry
        {
            Rect = new Windows.Foundation.Rect(0, 0, width, height)
        };

        // Clip 对这个组合不可靠（列表仍会画到底栏上），改用硬上限：
        // 内容区高 - 底部 padding(8) - 表头(28) - RowSpacing(2)。
        double listHeight = height - 8 - 28 - 2;
        if (listHeight > 0 && Math.Abs(EntryList.MaxHeight - listHeight) > 0.5)
        {
            EntryList.MaxHeight = listHeight;
        }

        // 临时诊断：确认各行实际高度与客户区是否对得上。定位后删除。
        try
        {
            SizeInt32 client = AppWindow.ClientSize;
            double entryTop = EntryList.TransformToVisual(RootGrid)
                .TransformPoint(new Windows.Foundation.Point(0, 0)).Y;
            double footerTop = FooterHost.TransformToVisual(RootGrid)
                .TransformPoint(new Windows.Foundation.Point(0, 0)).Y;
            File.AppendAllText(
                Path.Combine(Path.GetTempPath(), "picker-metrics.log"),
                $"client={client.Height} root={RootGrid.ActualHeight:0.#} " +
                $"contentH={ContentHost.ActualHeight:0.#} listHostH={ListHost.ActualHeight:0.#} " +
                $"entryH={EntryList.ActualHeight:0.#} entryMax={EntryList.MaxHeight:0.#} " +
                $"entryTop={entryTop:0.#} entryBottom={entryTop + EntryList.ActualHeight:0.#} " +
                $"footerTop={footerTop:0.#} footerH={FooterHost.ActualHeight:0.#} " +
                $"clip={(ContentHost.Clip is null ? "null" : "set")}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    private void RootGrid_Loaded(object sender, RoutedEventArgs e)
    {
        RootGrid.Loaded -= RootGrid_Loaded;

        string start = _options.InitialDirectory is { Length: > 0 } initial && Directory.Exists(initial)
            ? initial
            : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        NavigateTo(start, recordHistory: true);
        UpdateRootHeightConstraint();
        ApplyContentClip();

        // 侧栏要枚举 shell 快速访问并读取各盘卷标（磁盘 IO），放到窗口可见之后再做，
        // 否则这些同步调用会把窗口弹出拖慢几百毫秒。
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, BuildLocations);
    }

    private void FilePickerWindow_Closed(object sender, WindowEventArgs args)
    {
        Closed -= FilePickerWindow_Closed;
        AppWindow.Changed -= FilePickerWindow_AppWindowChanged;
        RestoreOwner();
        Complete(Array.Empty<string>());
    }

    private void CenterOnWorkArea()
    {
        DisplayArea? displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Nearest);
        if (displayArea is null)
        {
            return;
        }

        RectInt32 workArea = displayArea.WorkArea;
        SizeInt32 size = AppWindow.Size;
        AppWindow.Move(new PointInt32(
            workArea.X + ((workArea.Width - size.Width) / 2),
            workArea.Y + ((workArea.Height - size.Height) / 2)));
    }

    private void ApplyModeChrome()
    {
        bool isSave = _options.Mode == FilePickerMode.Save;

        FileNamePanel.Visibility = isSave ? Visibility.Visible : Visibility.Collapsed;
        NewFolderButton.Visibility = isSave ? Visibility.Visible : Visibility.Collapsed;
        FileTypePanel.Visibility = _options.Mode == FilePickerMode.Folder
            ? Visibility.Collapsed
            : Visibility.Visible;

        EntryList.SelectionMode = _options.AllowMultiple && _options.Mode == FilePickerMode.Open
            ? ListViewSelectionMode.Extended
            : ListViewSelectionMode.Single;

        AcceptButton.Content = _options.Mode switch
        {
            FilePickerMode.Save => Localizer.Get().GetLocalizedString("FilePicker_Button_Save"),
            FilePickerMode.Folder => Localizer.Get().GetLocalizedString("FilePicker_Button_SelectFolder"),
            _ => Localizer.Get().GetLocalizedString("FilePicker_Button_Open")
        };

        if (_options.SuggestedFileName is { Length: > 0 } suggestedName)
        {
            FileNameBox.Text = suggestedName;
        }

        AcceptButton.IsEnabled = _options.Mode switch
        {
            FilePickerMode.Folder => true,
            FilePickerMode.Save => FileNameBox.Text.Trim().Length > 0,
            _ => false
        };
    }

    private void BuildTypeGroups()
    {
        // 文件夹选择器没有类型概念，不建组；其余模式至少要有「所有文件」，
        // 与系统对话框一致（即使调用方没传任何过滤）。
        if (_options.Mode != FilePickerMode.Folder)
        {
            if (_options.FileTypes.Count > 0)
            {
                if (_options.FileTypes.Count > 1)
                {
                    string[] all = _options.FileTypes
                        .SelectMany(group => group.Extensions)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    if (all.Length > 0)
                    {
                        _typeGroups.Add(new FilePickerTypeGroup(
                            Localizer.Get().GetLocalizedString("FilePicker_Filter_AllSupported"),
                            all));
                    }
                }

                _typeGroups.AddRange(_options.FileTypes);
            }

            _typeGroups.Add(new FilePickerTypeGroup(
                Localizer.Get().GetLocalizedString("FilePicker_Filter_AllFiles"),
                Array.Empty<string>()));
        }

        _suppressFilterChanged = true;
        foreach (FilePickerTypeGroup group in _typeGroups)
        {
            FileTypeCombo.Items.Add(new ComboBoxItem { Content = group.Label, Tag = group });
        }

        if (FileTypeCombo.Items.Count > 0)
        {
            FileTypeCombo.SelectedIndex = 0;
        }

        _suppressFilterChanged = false;
        FileTypeCombo.SelectionChanged += FileTypeCombo_SelectionChanged;
    }

    private void BuildLocations()
    {
        var quickAccess = new List<FilePickerLocation>();
        foreach ((string name, string path) in QuickAccessReader.GetPinnedFolders())
        {
            quickAccess.Add(new FilePickerLocation("\uE8B7", name, path));
        }

        QuickAccessList.ItemsSource = quickAccess;

        var drives = new List<FilePickerLocation>();
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            string root = drive.Name.TrimEnd('\\');
            string label;
            try
            {
                if (!drive.IsReady)
                {
                    continue;
                }

                label = drive.VolumeLabel;
            }
            catch (IOException)
            {
                // 断开的网络驱动器或已移除的介质：GetVolumeInformation 返回
                // ERROR_FILE_NOT_FOUND，DriveInfo 会把它包成 FileNotFoundException。
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            drives.Add(new FilePickerLocation(
                "\uEDA2",
                string.IsNullOrWhiteSpace(label) ? root : $"{label} ({root})",
                drive.RootDirectory.FullName));
        }

        DriveList.ItemsSource = drives;
    }

    private void NavigateTo(string path, bool recordHistory)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception)
        {
            return;
        }

        if (recordHistory)
        {
            if (_historyIndex < _history.Count - 1)
            {
                _history.RemoveRange(_historyIndex + 1, _history.Count - _historyIndex - 1);
            }

            _history.Add(fullPath);
            _historyIndex = _history.Count - 1;
        }

        _currentDirectory = fullPath;
        RebuildBreadcrumb();
        UpdateNavigationState();
        SyncLocationSelection(fullPath);
        _ = LoadEntriesAsync(fullPath);
    }

    private void UpdateNavigationState()
    {
        BackButton.IsEnabled = _historyIndex > 0;
        ForwardButton.IsEnabled = _historyIndex < _history.Count - 1;
        UpButton.IsEnabled = Directory.GetParent(_currentDirectory) is not null;
    }

    private async Task LoadEntriesAsync(string path)
    {
        int version = ++_loadVersion;
        string[] allowedExtensions = CurrentExtensions();
        EnterLoading();

        try
        {
            List<FilePickerEntry> entries;
            try
            {
                entries = await Task.Run(() => Enumerate(path, allowedExtensions));
            }
            catch (UnauthorizedAccessException)
            {
                ShowEmptyState("FilePicker_AccessDenied");
                return;
            }
            catch (IOException)
            {
                ShowEmptyState("FilePicker_AccessDenied");
                return;
            }

            if (version != _loadVersion)
            {
                return;
            }

            _entries.Clear();
            foreach (FilePickerEntry entry in entries)
            {
                _entries.Add(entry);
            }

            EntryList.ItemsSource = _entries;
            if (_entries.Count == 0)
            {
                ShowEmptyState("FilePicker_EmptyFolder");
                return;
            }

            EmptyText.Visibility = Visibility.Collapsed;
            EntryList.Visibility = Visibility.Visible;
            EntryList.SelectedItem = null;
            OnSelectionChanged();
        }
        finally
        {
            if (version == _loadVersion)
            {
                ExitLoading();
            }
        }
    }

    /// <summary>进入加载态：先清空旧内容，加载界面延迟 50ms 才出现，避免快目录闪一下。</summary>
    private void EnterLoading()
    {
        _loadingCts?.Cancel();
        var cts = new CancellationTokenSource();
        _loadingCts = cts;

        _entries.Clear();
        EntryList.ItemsSource = null;
        EntryList.Visibility = Visibility.Collapsed;
        EmptyText.Visibility = Visibility.Collapsed;
        LoadingPanel.Visibility = Visibility.Collapsed;

        _ = LoadingDelay.ShowAsync(cts.Token, () => LoadingPanel.Visibility = Visibility.Visible);
    }

    private void ExitLoading()
    {
        _loadingCts?.Cancel();
        LoadingPanel.Visibility = Visibility.Collapsed;
    }

    private void ShowEmptyState(string key)
    {
        EntryList.ItemsSource = null;
        _entries.Clear();
        EmptyText.Text = Localizer.Get().GetLocalizedString(key);
        EmptyText.Visibility = Visibility.Visible;
        EntryList.Visibility = Visibility.Collapsed;
        OnSelectionChanged();
    }

    private List<FilePickerEntry> Enumerate(string path, string[] allowedExtensions)
    {
        var enumerationOptions = new EnumerationOptions
        {
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.Hidden | FileAttributes.System
        };

        var directory = new DirectoryInfo(path);
        var result = new List<FilePickerEntry>();

        foreach (DirectoryInfo subDirectory in directory.EnumerateDirectories("*", enumerationOptions))
        {
            result.Add(FilePickerEntry.FromDirectory(subDirectory));
        }

        if (_options.Mode != FilePickerMode.Folder)
        {
            var allowed = new HashSet<string>(allowedExtensions, StringComparer.OrdinalIgnoreCase);
            foreach (FileInfo file in directory.EnumerateFiles("*", enumerationOptions))
            {
                if (allowed.Count > 0 && !allowed.Contains(file.Extension))
                {
                    continue;
                }

                result.Add(FilePickerEntry.FromFile(file));
            }
        }

        result.Sort(CompareEntries);
        return result;
    }

    private static int CompareEntries(FilePickerEntry left, FilePickerEntry right)
    {
        if (left.IsFolder != right.IsFolder)
        {
            return left.IsFolder ? -1 : 1;
        }

        return string.Compare(left.Name, right.Name, StringComparison.CurrentCultureIgnoreCase);
    }

    private string[] CurrentExtensions()
    {
        return FileTypeCombo.SelectedItem is ComboBoxItem { Tag: FilePickerTypeGroup group }
            ? group.Extensions.ToArray()
            : Array.Empty<string>();
    }

    private void SyncLocationSelection(string path)
    {
        _suppressLocationChanged = true;
        QuickAccessList.SelectedItem = FindLocation(QuickAccessList, path);
        DriveList.SelectedItem = FindLocation(DriveList, path);
        _suppressLocationChanged = false;
    }

    private static FilePickerLocation? FindLocation(ListView listView, string path)
    {
        if (listView.ItemsSource is not IEnumerable<FilePickerLocation> items)
        {
            return null;
        }

        string normalized = path.TrimEnd('\\');
        return items.FirstOrDefault(item =>
            string.Equals(item.Path.TrimEnd('\\'), normalized, StringComparison.OrdinalIgnoreCase));
    }

    private void OnSelectionChanged()
    {
        var selected = EntryList.SelectedItems.Cast<FilePickerEntry>().ToList();

        if (_options.Mode == FilePickerMode.Save)
        {
            if (selected.FirstOrDefault(entry => !entry.IsFolder) is { } file)
            {
                FileNameBox.Text = file.Name;
            }

            AcceptButton.IsEnabled = FileNameBox.Text.Trim().Length > 0;
            return;
        }

        if (_options.Mode == FilePickerMode.Folder)
        {
            AcceptButton.IsEnabled = true;
            return;
        }

        AcceptButton.IsEnabled = selected.Any(entry => !entry.IsFolder);
    }

    /// <summary>侧栏分组可折叠：标题行点击切换对应列表与箭头方向。</summary>
    private void QuickAccessHeader_Click(object sender, RoutedEventArgs e) =>
        ToggleLocationGroup(QuickAccessList, QuickAccessChevron);

    private void DriveHeader_Click(object sender, RoutedEventArgs e) =>
        ToggleLocationGroup(DriveList, DriveChevron);

    private static void ToggleLocationGroup(ListView list, FontIcon chevron)
    {
        bool expand = list.Visibility == Visibility.Collapsed;
        list.Visibility = expand ? Visibility.Visible : Visibility.Collapsed;
        chevron.Glyph = expand ? "\uE70D" : "\uE76C";
    }

    private void LocationList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLocationChanged || sender is not ListView listView)
        {
            return;
        }

        if (listView.SelectedItem is not FilePickerLocation location)
        {
            return;
        }

        ListView other = ReferenceEquals(listView, QuickAccessList) ? DriveList : QuickAccessList;
        _suppressLocationChanged = true;
        other.SelectedItem = null;
        _suppressLocationChanged = false;

        NavigateTo(location.Path, recordHistory: true);
    }

    private void EntryList_SelectionChanged(object sender, SelectionChangedEventArgs e) => OnSelectionChanged();

    private void EntryList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (EntryList.SelectedItem is not FilePickerEntry entry)
        {
            return;
        }

        if (entry.IsFolder)
        {
            NavigateTo(entry.FullPath, recordHistory: true);
            return;
        }

        if (_options.Mode == FilePickerMode.Open)
        {
            _ = AcceptAsync();
        }
    }

    private void EntryList_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            e.Handled = true;
            _ = AcceptAsync();
        }
        else if (e.Key == VirtualKey.Back)
        {
            e.Handled = true;
            GoUp();
        }
    }

    private void FileNameBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            e.Handled = true;
            _ = AcceptAsync();
        }
    }

    private void FileTypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressFilterChanged || _currentDirectory.Length == 0)
        {
            return;
        }

        _ = LoadEntriesAsync(_currentDirectory);
    }

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (_historyIndex <= 0)
        {
            return;
        }

        _historyIndex--;
        NavigateTo(_history[_historyIndex], recordHistory: false);
    }

    private void ForwardButton_Click(object sender, RoutedEventArgs e)
    {
        if (_historyIndex >= _history.Count - 1)
        {
            return;
        }

        _historyIndex++;
        NavigateTo(_history[_historyIndex], recordHistory: false);
    }

    private void UpButton_Click(object sender, RoutedEventArgs e) => GoUp();

    private void GoUp()
    {
        if (Directory.GetParent(_currentDirectory) is { } parent)
        {
            NavigateTo(parent.FullName, recordHistory: true);
        }
    }

    private void RootGrid_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            Finish([]);
            return;
        }

        // Alt+↑ 上移一级。用普通按键判断而不是 KeyboardAccelerator，
        // 后者会让 WinUI 在界面上浮出「Alt+向上键」提示。
        if (e.Key == VirtualKey.Up &&
            InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Menu)
                .HasFlag(CoreVirtualKeyStates.Down))
        {
            e.Handled = true;
            GoUp();
        }
    }

    /// <summary>点击地址栏空白处进入编辑态，并把当前路径全选（与系统文件对话框一致）。</summary>
    private void AddressBar_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if (PathEditBox.Visibility == Visibility.Visible)
        {
            return;
        }

        PathEditBox.Text = _currentDirectory;
        PathEditBox.Visibility = Visibility.Visible;
        BreadcrumbHost.Visibility = Visibility.Collapsed;
        PathEditBox.Focus(FocusState.Programmatic);
        PathEditBox.SelectAll();
    }

    private void ExitPathEdit()
    {
        PathEditBox.Visibility = Visibility.Collapsed;
        BreadcrumbHost.Visibility = Visibility.Visible;
    }

    private void PathEditBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            e.Handled = true;
            string text = PathEditBox.Text.Trim();
            if (text.Length == 0)
            {
                ExitPathEdit();
                return;
            }

            if (NavigateToInput(text))
            {
                ExitPathEdit();
                return;
            }

            _ = ShowMessageAsync(string.Format(
                CultureInfo.CurrentCulture,
                Localizer.Get().GetLocalizedString("FilePicker_InvalidPath"),
                text));
            return;
        }

        if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            ExitPathEdit();
        }
    }

    private void PathEditBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (PathEditBox.Visibility == Visibility.Visible)
        {
            ExitPathEdit();
        }
    }

    private bool NavigateToInput(string text)
    {
        if (Directory.Exists(text))
        {
            NavigateTo(text, recordHistory: true);
            return true;
        }

        if (File.Exists(text))
        {
            string? directory = Path.GetDirectoryName(text);
            if (directory is not null)
            {
                NavigateTo(directory, recordHistory: true);
                FileNameBox.Text = Path.GetFileName(text);
                return true;
            }
        }

        return false;
    }

    /// <summary>按当前路径重建「C: › Users › 用户名 › 文件夹」形式的面包屑。</summary>
    private void RebuildBreadcrumb()
    {
        BreadcrumbPanel.Children.Clear();
        if (_currentDirectory.Length == 0)
        {
            return;
        }

        var segments = new List<(string Label, string Path)>();
        DirectoryInfo? directory = new(_currentDirectory);
        while (directory is not null)
        {
            string label = directory.Parent is null ? directory.Name.TrimEnd('\\') : directory.Name;
            segments.Insert(0, (label, directory.FullName));
            directory = directory.Parent;
        }

        for (int i = 0; i < segments.Count; i++)
        {
            if (i > 0)
            {
                BreadcrumbPanel.Children.Add(new TextBlock
                {
                    Text = "\u203A",
                    Opacity = 0.6,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(2, 0, 2, 0)
                });
            }

            var segmentButton = new Button
            {
                Content = segments[i].Label,
                Background = new SolidColorBrush(Colors.Transparent),
                BorderThickness = new Thickness(0),
                Padding = new Thickness(4, 0, 4, 0),
                Height = 24,
                MinHeight = 0,
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center
            };

            string target = segments[i].Path;
            segmentButton.Click += (_, _) => NavigateTo(target, recordHistory: true);
            segmentButton.Tapped += (_, args) => args.Handled = true;
            BreadcrumbPanel.Children.Add(segmentButton);
        }
    }

    private void NewFolderButton_Click(object sender, RoutedEventArgs e)
    {
        string name = Localizer.Get().GetLocalizedString("FilePicker_NewFolder_DefaultName");
        string path = Path.Combine(_currentDirectory, name);
        int index = 1;
        while (Directory.Exists(path) || File.Exists(path))
        {
            path = Path.Combine(_currentDirectory, string.Format(
                CultureInfo.CurrentCulture, "{0} ({1})", name, index++));
        }

        try
        {
            Directory.CreateDirectory(path);
        }
        catch (Exception)
        {
            return;
        }

        FileNameBox.Text = Path.GetFileName(path);
        NavigateTo(_currentDirectory, recordHistory: false);
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => Finish(Array.Empty<string>());

    private void AcceptButton_Click(object sender, RoutedEventArgs e) => _ = AcceptAsync();

    private async Task AcceptAsync()
    {
        if (!AcceptButton.IsEnabled)
        {
            return;
        }

        switch (_options.Mode)
        {
            case FilePickerMode.Folder:
                Finish([_currentDirectory]);
                return;

            case FilePickerMode.Open:
                {
                    string[] files = EntryList.SelectedItems
                        .Cast<FilePickerEntry>()
                        .Where(entry => !entry.IsFolder)
                        .Select(entry => entry.FullPath)
                        .ToArray();
                    if (files.Length == 0)
                    {
                        return;
                    }

                    Finish(files);
                    return;
                }

            case FilePickerMode.Save:
                {
                    string name = FileNameBox.Text.Trim();
                    if (name.Length == 0)
                    {
                        await ShowMessageAsync(Localizer.Get().GetLocalizedString("FilePicker_FileNameRequired"));
                        return;
                    }

                    string target = Path.Combine(_currentDirectory, name);
                    if (Path.GetExtension(name).Length == 0)
                    {
                        string extension = PreferredExtension();
                        if (extension.Length > 0)
                        {
                            target += extension;
                        }
                    }

                    if (File.Exists(target) && !await ConfirmOverwriteAsync(Path.GetFileName(target)))
                    {
                        return;
                    }

                    Finish([target]);
                    return;
                }
        }
    }

    private string PreferredExtension()
    {
        if (CurrentExtensions() is { Length: > 0 } extensions)
        {
            return extensions[0];
        }

        return _options.DefaultExtension ?? string.Empty;
    }

    private async Task<bool> ConfirmOverwriteAsync(string fileName)
    {
        var dialog = new ContentDialog
        {
            Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
            XamlRoot = RootGrid.XamlRoot,
            RequestedTheme = RootGrid.RequestedTheme,
            Title = Localizer.Get().GetLocalizedString("FilePicker_Overwrite_Title"),
            Content = string.Format(
                CultureInfo.CurrentCulture,
                Localizer.Get().GetLocalizedString("FilePicker_Overwrite_Message"),
                fileName),
            PrimaryButtonText = Localizer.Get().GetLocalizedString("FilePicker_Overwrite_Replace"),
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
            DefaultButton = ContentDialogButton.Primary
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ShowMessageAsync(string message)
    {
        var dialog = new ContentDialog
        {
            Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
            XamlRoot = RootGrid.XamlRoot,
            RequestedTheme = RootGrid.RequestedTheme,
            Content = message,
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close"),
            DefaultButton = ContentDialogButton.Close
        };

        await dialog.ShowAsync();
    }

    private void Complete(IReadOnlyList<string> paths)
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        _result.TrySetResult(paths);
    }

    /// <summary>交付结果并关闭窗口。所有正常结束路径都必须走这里。</summary>
    private void Finish(IReadOnlyList<string> paths)
    {
        // 先恢复主窗口再关自己：否则主窗口要等窗口真正销毁后才从禁用态恢复，
        // 表现为关闭瞬间主窗口"消失一下再出现"。
        RestoreOwner();
        Complete(paths);
        Close();
    }

    private void RestoreOwner()
    {
        if (_ownerDisabled && _ownerHwnd != 0)
        {
            _ownerDisabled = false;
            EnableWindow(_ownerHwnd, true);
        }
    }

    private const int GWLP_HWNDPARENT = -8;

    [LibraryImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static partial nint SetWindowLongPtr(nint hWnd, int nIndex, nint dwNewLong);

    [LibraryImport("user32.dll", EntryPoint = "EnableWindow")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EnableWindow(nint hWnd, [MarshalAs(UnmanagedType.Bool)] bool bEnable);

    [LibraryImport("user32.dll", EntryPoint = "SetForegroundWindow")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(nint hWnd);
}
