using Helper.PInvoke.Comctl32;
using Helper.PInvoke.User32;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.Windows.Storage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;
using WinUI3Localizer;
using WinUIEx;
using Xdows_Security.Services;
using Xdows_Security.Views;
using Xdows_Security.Views.OOBE;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage { get; set; } = "Home";
        public WinUIEx.WindowManager? Manager { get; private set; }

        private bool _isOOBEShown;
        private bool _allowCloseFromTray;
        private readonly Stack<string> _navigationHistory = new();
        private readonly SUBCLASSPROC? _deviceChangeSubClassProc;

        // 事件驱动的 SecurityPage 就绪通知，替代旧的 Task.Delay + 轮询
        private TaskCompletionSource<SecurityPage?>? _securityPageReadyTcs;
        private static readonly TimeSpan SecurityPageWaitTimeout = TimeSpan.FromSeconds(5);

        public MainWindow()
        {
            InitializeComponent();
            Manager = WinUIEx.WindowManager.Get(this);
            this.ExtendsContentIntoTitleBar = true;
            AppWindow.SetIcon("logo.ico");
            this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

            _deviceChangeSubClassProc = new SUBCLASSPROC(DeviceChangeSubClassProc);
            Comctl32Library.SetWindowSubclass((nint)this.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(_deviceChangeSubClassProc), 1, 0);

            nav.SelectedItem = nav.MenuItems.OfType<NavigationViewItem>().First();
            Activated += MainWindow_Activated_FirstTime;
            Title = AppInfo.AppName;
            TitleText.Text = AppInfo.AppName;

            Manager.AppWindow.Closing += MainWindow_Closing;
            Manager.MinWidth = 650;
            Manager.MinHeight = 530;
            CenterWindow();
            Closed += delegate { Window_Closed(); };
            Localizer.Get().LanguageChanged += OnLangChanged;
            Manager.TrayIconSelected += (w, e) =>
            {
                this.Activate();
            };
            Manager.TrayIconContextMenu += (w, e) =>
            {
                var flyout = new MenuFlyout();
                flyout.Items.Add(new MenuFlyoutItem()
                {
                    Text = Localizer.Get().GetLocalizedString("TrayMenu_Open"),
                    Icon = new FontIcon() { Glyph = "\uE8A7" }
                });
                flyout.Items.Add(new MenuFlyoutItem()
                {
                    Text = Localizer.Get().GetLocalizedString("TrayMenu_Settings"),
                    Icon = new FontIcon() { Glyph = "\uE713" }
                });
                flyout.Items.Add(new MenuFlyoutSeparator());
                flyout.Items.Add(new MenuFlyoutItem()
                {
                    Text = Localizer.Get().GetLocalizedString("TrayMenu_Quit"),
                    Icon = new FontIcon() { Glyph = "\uE7E8" }
                });
                ((MenuFlyoutItem)flyout.Items[0]).Click += (s, e) => this.Activate();
                ((MenuFlyoutItem)flyout.Items[1]).Click += (s, e) =>
                {
                    this.Activate();
                    this.GoToPage("Settings");
                };
                ((MenuFlyoutItem)flyout.Items[3]).Click += async (s, e) =>
                {
                    bool disabledVerify = false;
                    if (App.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify) && isDisabledVerify is bool boolValue)
                    {
                        disabledVerify = boolValue;
                    }
                    if (disabledVerify)
                    {
                        _allowCloseFromTray = true;
                        this.Close();
                    }
                    else
                    {
                        var verifyTask = UserConsentVerifier.RequestVerificationAsync(string.Empty);
                        var result = verifyTask.AsTask().ConfigureAwait(false).GetAwaiter().GetResult();

                        if (result is UserConsentVerificationResult.DeviceNotPresent or
                        UserConsentVerificationResult.DisabledByPolicy or
                        UserConsentVerificationResult.NotConfiguredForUser or
                        UserConsentVerificationResult.Verified)
                        {
                            _allowCloseFromTray = true;
                            this.Close();
                        }
                        return;
                    }
                };
                e.Flyout = flyout;
            };

            // 处理启动时的扫描请求：直接 enqueue，等待 SecurityPage 就绪由 WaitForSecurityPageAsync 内部处理
            if (App.ScanTargetPaths.Count > 0)
            {
                _ = DispatcherQueue.TryEnqueue(() =>
                {
                    var scanPaths = App.ScanTargetPaths.ToList();
                    if (scanPaths.Count > 0)
                    {
                        LogText.AddNewLog(LogText.LogLevel.INFO, "MainWindow", $"Starting startup scan for {scanPaths.Count} items");
                        App.ClearScanTargetPaths();
                        TriggerScanForPaths(scanPaths);
                    }
                });
            }
            LogText.AddNewLog(LogText.LogLevel.INFO, "UI Interface", "MainWindow loaded successfully");
        }

        private async void MainWindow_Activated_FirstTime(object sender, WindowActivatedEventArgs args)
        {
            var settings = App.LocalSettings;

            if (settings.Values.TryGetValue("AppTheme", out object? theme))
            {
                string themeString = theme as string ?? "";
                if (Enum.TryParse(themeString, out ElementTheme themeValue))
                {
                    if (this.Content is FrameworkElement rootElement)
                    {
                        rootElement.RequestedTheme = themeValue;
                    }
                    UpdateTheme(themeValue);
                }
            }
            this.SystemBackdrop = null;

            var backdrop = settings.Values.TryGetValue("AppBackdrop", out object? backdropRaw) && backdropRaw is string backdropValue
                ? backdropValue
                : "Mica";

            var dq = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
            dq?.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
                {
                    try
                    {
                        ApplyBackdrop(backdrop, false);
                    }
                    catch { }
                });

            Activated -= MainWindow_Activated_FirstTime;
            //if (!App.IsRunAsAdmin())
            //{
            //    TitleText.Text += " (受限模式)";
            //}
            UpdateNavTheme(
                settings.Values.TryGetValue("AppNavTheme", out var raw) && raw is double d ?
                (int)d : 0
            );
            UpdatePaneToggleButtonPosition();
            UpdateBackButtonPosition();
            bool isTrayVisible = !settings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle) || (trayVisibleToggle is bool trayVal && trayVal);
            Manager?.IsVisibleInTray = isTrayVisible;
            App.PlayEntranceAnimation(navContainer, "up");

            if (isTrayVisible && StartupService.IsMinimizedStart())
            {
                this.Hide();
                return;
            }

            if (App.GetRunOOBE())
            {
                _ = DispatcherQueue.TryEnqueue(async () => await ShowOOBEAsync());
            }
        }

        public void TriggerScanForPath(string scanPath)
        {
            if (string.IsNullOrWhiteSpace(scanPath))
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", "Invalid scan path");
                return;
            }

            if (!System.IO.Directory.Exists(scanPath) && !System.IO.File.Exists(scanPath))
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", $"Path does not exist: {scanPath}");
                return;
            }

            _ = DispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    GoToPage("Security");
                    SecurityPage? securityPage = await WaitForSecurityPageAsync();

                    if (securityPage != null)
                    {
                        string displayName = System.IO.Path.GetFileName(scanPath);
                        if (string.IsNullOrEmpty(displayName))
                            displayName = scanPath;
                        await securityPage.StartScanAsync(displayName, ScanMode.More, [scanPath]);
                    }
                    else
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", "Failed to get SecurityPage for scanning");
                    }
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", $"TriggerScanForPath failed: {ex.Message}");
                }
            });
        }

        public void TriggerScanForPaths(IReadOnlyList<string> scanPaths)
        {
            if (scanPaths == null || scanPaths.Count == 0)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", "Invalid scan paths");
                return;
            }

            var validPaths = scanPaths.Where(p => System.IO.Directory.Exists(p) || System.IO.File.Exists(p)).ToList();
            if (validPaths.Count == 0)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", "No valid paths to scan");
                return;
            }

            _ = DispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    GoToPage("Security");
                    SecurityPage? securityPage = await WaitForSecurityPageAsync();

                    if (securityPage != null)
                    {
                        string displayName = validPaths.Count == 1
                            ? System.IO.Path.GetFileName(validPaths[0]) ?? validPaths[0]
                            : $"{validPaths.Count} items";
                        await securityPage.StartScanAsync(displayName, ScanMode.More, validPaths);
                    }
                    else
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", "Failed to get SecurityPage for scanning");
                    }
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "MainWindow", $"TriggerScanForPaths failed: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// 等待 SecurityPage 就绪（Loaded 已触发）。优先复用已 Loaded 的当前实例；
        /// 否则订阅由 SecurityPage.Loaded 触发的就绪通知，带超时兜底避免永久阻塞。
        /// 并发调用时复用同一等待者，避免相互取消。
        /// </summary>
        private async Task<SecurityPage?> WaitForSecurityPageAsync()
        {
            // 仅在 SecurityPage 已 Loaded 时直接复用；Frame.Navigate 同步设置 Content 但 Loaded 异步触发，
            // 若不检查 IsLoaded 会拿到尚未完成 Loaded 的实例，导致 StartScanAsync 在 SetupRadarAnimations 之前运行
            if (navContainer.Content is SecurityPage { IsLoaded: true } loadedPage)
                return loadedPage;

            // 复用尚未完成的等待者，避免并发 TriggerScanForPaths 相互取消
            var existing = _securityPageReadyTcs;
            if (existing is { Task.IsCompleted: false })
                return await existing.Task;

            var tcs = new TaskCompletionSource<SecurityPage?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _securityPageReadyTcs = tcs;

            using var cts = new CancellationTokenSource(SecurityPageWaitTimeout);
            cts.Token.Register(() => tcs.TrySetResult(null));

            return await tcs.Task;
        }

        /// <summary>
        /// 由 SecurityPage.Loaded 调用，通知主窗口页面已就绪。
        /// </summary>
        internal void NotifySecurityPageReady(SecurityPage page)
        {
            var tcs = _securityPageReadyTcs;
            _securityPageReadyTcs = null;
            tcs?.TrySetResult(page);
        }

        public async Task ShowOOBEAsync()
        {
            if (_isOOBEShown) return;
            _isOOBEShown = true;

            OOBEOverlay.Opacity = 1;
            OOBEOverlay.Visibility = Visibility.Visible;
            OOBEOverlay.IsHitTestVisible = true;

            OOBEFrame.Navigate(typeof(OOBEShellPage));
        }

        public async Task CloseOOBEAsync(bool markCompleted)
        {
            if (!_isOOBEShown) return;

            if (markCompleted)
            {
                App.SetRunOOBE(false);
            }

            App.PlayExitDownFadeAnimation(OOBEOverlay);
            await Task.Delay(420);

            OOBEFrame.Content = null;
            OOBEOverlay.Visibility = Visibility.Collapsed;
            OOBEOverlay.IsHitTestVisible = false;
            OOBEOverlay.Opacity = 1;
            _isOOBEShown = false;
        }
        public void UpdateNavTheme(int index)
        {
            nav.PaneDisplayMode = index == 0 ? NavigationViewPaneDisplayMode.LeftCompact : NavigationViewPaneDisplayMode.Top;
        }
        private void OnLangChanged(object? sender, LanguageChangedEventArgs e) => LoadLocalizerData();
        private void LoadLocalizerData()
        {
            var settings = App.LocalSettings;
            int navTheme = settings.Values.TryGetValue("AppNavTheme", out var raw) && raw is double d ?
                (int)d : 0;
            if (navTheme == 0)
            {
                if (nav.SettingsItem is NavigationViewItem setting)
                {
                    setting.Content = Localizer.Get().GetLocalizedString("MainWindow_Nav_Settings");
                    nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
                }
            }
        }
        public void GoToPage(string PageName, bool pushHistory = true)
        {
            if (PageName == "BugReport")
            {
                GoToBugReportPage(null);
                return;
            }
            var selectedItem = nav.SelectedItem as NavigationViewItem;

            string currentTag = selectedItem?.Tag as string ?? "";

            if (currentTag != PageName)
            {
                var targetItem = FindNavigationItemByTag(nav.MenuItems, PageName);

                if (targetItem == null && nav.SettingsItem != null &&
                    nav.SettingsItem is NavigationViewItem settingsItem &&
                    settingsItem.Tag as string == PageName)
                {
                    targetItem = settingsItem;
                }

                if (targetItem != null)
                {
                    if (pushHistory && !string.IsNullOrEmpty(currentTag) && currentTag != PageName)
                    {
                        _navigationHistory.Push(currentTag);
                        UpdateBackEnabled();
                    }
                    nav.SelectedItem = targetItem;
                    return;
                }
            }

            if (pushHistory && !string.IsNullOrEmpty(NowPage) && NowPage != PageName)
            {
                _navigationHistory.Push(NowPage);
                UpdateBackEnabled();
            }

            if (PageName == "Settings")
            {
                nav.Header = Localizer.Get().GetLocalizedString("MainWindow_Nav_Settings");
            }
            else
            {
                nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
            }
            NowPage = PageName;
            var pageType = PageName switch
            {
                "Home" => typeof(HomePage),
                "Security" => typeof(SecurityPage),
                "Xdows-Tools" => typeof(XdowsToolsPage),
                "Settings" => typeof(SettingsPage),
                _ => typeof(HomePage)
            };
            navContainer.Navigate(pageType, null, App.GetNavigationTransitionInfo());
        }
        public void GoToBugReportPage(string? PageName)
        {
            _navigationHistory.Clear();
            UpdateBackEnabled();
            NowPage = "BugReport";
            nav.Header = PageName;
            nav.SelectedItem = null;
            navContainer.Navigate(typeof(BugReportPage), null, App.GetNavigationTransitionInfo());
        }
        private static NavigationViewItem? FindNavigationItemByTag(IList<object> items, string targetTag)
        {
            foreach (var item in items)
            {
                if (item is NavigationViewItem navItem)
                {
                    if (navItem.Tag?.ToString() == targetTag)
                        return navItem;

                    if (navItem.MenuItems.Count > 0)
                    {
                        var childResult = FindNavigationItemByTag(navItem.MenuItems, targetTag);
                        if (childResult != null) return childResult;
                    }
                }
            }
            return null;
        }
        private void NavigationSelectionChanged()
        {
            if (nav.SelectedItem is NavigationViewItem item)
            {
                string pageName = item.Tag as string ?? string.Empty;
                GoToPage(pageName);
            }
        }

        private void Window_Closed()
        {
            UnregisterSystemThemeListener();
            if (_controller == null) return;
            _controller.Dispose();
            _controller = null;
        }
        private void MainWindow_Closing(object sender, AppWindowClosingEventArgs e)
        {
            bool trayVisible = !App.LocalSettings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle) || (trayVisibleToggle is bool trayVisibleValue && trayVisibleValue);
            if (trayVisible && !_allowCloseFromTray)
            {
                e.Cancel = true;
                this.Hide();
                return;
            }
            if (_allowCloseFromTray)
            {
                ProtectionStatus.PrepareVoluntaryExit();
                App.ReleaseResources();
                _allowCloseFromTray = false;
                return;
            }
            bool disabledVerify = false;
            if (App.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify) && isDisabledVerify is bool disabledVerifyValue)
            {
                disabledVerify = disabledVerifyValue;
            }
            if (!disabledVerify)
            {
                var verifyTask = UserConsentVerifier.RequestVerificationAsync(string.Empty);
                var result = verifyTask.AsTask().ConfigureAwait(false).GetAwaiter().GetResult();
                e.Cancel = true;

                if (result is UserConsentVerificationResult.DeviceNotPresent or
                UserConsentVerificationResult.DisabledByPolicy or
                UserConsentVerificationResult.NotConfiguredForUser or
                UserConsentVerificationResult.Verified)
                {
                    ProtectionStatus.PrepareVoluntaryExit();
                    App.ReleaseResources();
                    e.Cancel = false;
                    _allowCloseFromTray = false;
                }
                return;
            }

            ProtectionStatus.PrepareVoluntaryExit();
            App.ReleaseResources();
            _allowCloseFromTray = false;
        }
        private void Nav_Loaded(object sender, RoutedEventArgs e)
        {
            LoadLocalizerData();
        }

        private void AppTitleBar_PaneToggleRequested(Microsoft.UI.Xaml.Controls.TitleBar sender, object args)
        {
            nav.IsPaneOpen = !nav.IsPaneOpen;
        }

        // 标题栏图标双击关闭窗口（与点击标题栏 X 按钮一致，走托盘隐藏/关闭验证流程）
        private void AppIcon_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            User32Library.SendMessage(
                (nint)this.AppWindow.Id.Value,
                WindowMessage.WM_SYSCOMMAND,
                (int)SYSTEMCOMMAND.SC_CLOSE,
                0);
            e.Handled = true;
        }

        // 右键标题栏图标，打开自定义标题栏菜单
        private void AppIcon_RightTapped(object sender, RightTappedRoutedEventArgs e)
        {
            titleBarMenu?.ShowMenuAtPoint(e.GetPosition(titleBarMenu));
            e.Handled = true;
        }

        // 右键标题栏区域（交互区），打开自定义标题栏菜单；
        // 非交互区由 WM_NCRBUTTONUP 子类化处理，两者共同覆盖整个标题栏
        private void AppTitleBar_RightTapped(object sender, RightTappedRoutedEventArgs e)
        {
            titleBarMenu?.ShowMenuAtPoint(e.GetPosition(titleBarMenu));
            e.Handled = true;
        }

        public void UpdateBackButtonPosition()
        {
            var settings = App.LocalSettings;
            Int32 navTheme = settings.Values.TryGetValue("AppNavTheme", out var navRaw) && navRaw is double d ? (int)d : 0;
            bool isCompactMode = navTheme == 0 &&
                settings.Values.TryGetValue("IsPaneToggleButtonInTitleBar", out var isItInTitleBar) &&
                isItInTitleBar is bool bv && bv;
            bool isBackButtonVisible = !settings.Values.TryGetValue("IsBackButtonVisible", out var backVisRaw) || backVisRaw is not false;

            if (!isBackButtonVisible)
            {
                AppTitleBar.IsBackButtonVisible = false;
                nav.IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed;
            }
            else if (isCompactMode)
            {
                AppTitleBar.IsBackButtonVisible = true;
                nav.IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed;
            }
            else
            {
                AppTitleBar.IsBackButtonVisible = false;
                nav.IsBackButtonVisible = NavigationViewBackButtonVisible.Auto;
            }

            UpdateBackEnabled();
        }

        private void UpdateBackEnabled()
        {
            bool canGoBack = _navigationHistory.Count > 0;
            nav.IsBackEnabled = canGoBack;
            AppTitleBar.IsBackButtonEnabled = canGoBack;
        }

        private void OnBackRequested(Microsoft.UI.Xaml.Controls.TitleBar sender, object args)
        {
            GoBack();
        }

        private void OnNavBackRequested(NavigationView sender, NavigationViewBackRequestedEventArgs args)
        {
            GoBack();
        }

        private void GoBack()
        {
            if (_navigationHistory.Count == 0) return;
            string previousPage = _navigationHistory.Pop();
            UpdateBackEnabled();
            GoToPage(previousPage, false);
        }

        private void CenterWindow()
        {
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea == null) return;

            var windowSize = this.AppWindow.Size;
            int centerX = (displayArea.WorkArea.Width - windowSize.Width) / 2;
            int centerY = (displayArea.WorkArea.Height - windowSize.Height) / 2;
            this.AppWindow.Move(new Windows.Graphics.PointInt32(centerX, centerY));
        }

        private nint DeviceChangeSubClassProc(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam, uint uIdSubclass, nint dwRefData)
        {
            if (Msg == WindowMessage.WM_DEVICECHANGE)
            {
                const int DBT_DEVICEARRIVAL = 0x8000;
                if (wParam == DBT_DEVICEARRIVAL)
                {
                    try
                    {
                        var hdr = Marshal.PtrToStructure<DEV_BROADCAST_HDR>(lParam);
                        if (hdr.dbch_devicetype == DeviceType.DBT_DEVTYP_VOLUME)
                        {
                            var vol = Marshal.PtrToStructure<DEV_BROADCAST_VOLUME>(lParam);
                            if ((vol.dbcv_flags & VolumeFlags.DBTF_NET) == 0)
                            {
                                char driveLetter = DriveMaskToLetter(vol.dbcv_unitmask);
                                if (driveLetter != '\0')
                                {
                                    DispatcherQueue.TryEnqueue(() =>
                                    {
                                        var scanWindow = new UsbScanWindow(
                                            driveLetter.ToString(),
                                            UsbScanService.GetDriveLabel(driveLetter.ToString()));
                                        scanWindow.Activate();

                                        UsbScanService.Instance.EnqueueDrive(driveLetter.ToString());
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                }
            }

            return Comctl32Library.DefSubclassProc(hWnd, Msg, wParam, lParam);
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
    }
}
