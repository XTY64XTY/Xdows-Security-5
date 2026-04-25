using Compatibility.Windows.Storage;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;
using WinUI3Localizer;
using WinUIEx;
using Xdows_Security.Views;
using Xdows_Security.Views.OOBE;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage { get; set; } = "Home";
        public WinUIEx.WindowManager? Manager { get; private set; }

        private bool _isOobeShown;

        public MainWindow()
        {
            InitializeComponent();
            Manager = WinUIEx.WindowManager.Get(this);
            this.ExtendsContentIntoTitleBar = true;
            AppWindow.SetIcon("logo.ico");
            this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

            nav.SelectedItem = nav.MenuItems.OfType<NavigationViewItem>().First();
            Activated += MainWindow_Activated_FirstTime;
            Title = AppInfo.AppName;
            TitleText.Text = AppInfo.AppName;
            Manager.AppWindow.Closing += MainWindow_Closing;
            Manager.MinWidth = 650;
            Manager.MinHeight = 530;
            Closed += delegate { Window_Closed(); };
            Localizer.Get().LanguageChanged += OnLangChanged;
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
                    if (Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify) && isDisabledVerify is bool boolValue)
                    {
                        disabledVerify = boolValue;
                    }
                    if (disabledVerify)
                    {
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
                            this.Close();
                        }
                        return;
                    }
                };
                e.Flyout = flyout;
            };
            LogText.AddNewLog(LogText.LogLevel.INFO, "UI Interface", "MainWindow loaded successfully");
        }

        private async void MainWindow_Activated_FirstTime(object sender, WindowActivatedEventArgs args)
        {
            var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;

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

            var backdrop = settings.Values["AppBackdrop"] as string ?? "Mica";

            var dq = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
            dq?.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, async () =>
                {
                    try
                    {
                        ApplyBackdrop(backdrop, false);

                        if (Compatibility.Windows.Storage.ApplicationData.HasFile("background_image"))
                        {
                            var backgroundImagePath = await Compatibility.Windows.Storage.ApplicationData.ReadFileAsync("background_image");
                            if (backgroundImagePath != null)
                            {
                                _ = ApplyBackgroundImageAsync(backgroundImagePath);
                            }
                        }
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
            if (settings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle) && trayVisibleToggle is bool boolValue)
            {
                Manager?.IsVisibleInTray = boolValue;
            }
            App.PlayEntranceAnimation(navContainer, "up");

            if (App.GetRunOobe())
            {
                _ = DispatcherQueue.TryEnqueue(async () => await ShowOobeAsync());
            }
        }

        public async Task ShowOobeAsync()
        {
            if (_isOobeShown) return;
            _isOobeShown = true;

            OobeOverlay.Opacity = 1;
            OobeOverlay.Visibility = Visibility.Visible;
            OobeOverlay.IsHitTestVisible = true;

            OobeFrame.Navigate(typeof(OobeShellPage));
        }

        public async Task CloseOobeAsync(bool markCompleted)
        {
            if (!_isOobeShown) return;

            if (markCompleted)
            {
                App.SetRunOobe(false);
            }

            App.PlayExitDownFadeAnimation(OobeOverlay);
            await Task.Delay(420);

            OobeFrame.Content = null;
            OobeOverlay.Visibility = Visibility.Collapsed;
            OobeOverlay.IsHitTestVisible = false;
            OobeOverlay.Opacity = 1;
            _isOobeShown = false;
        }
        public void UpdateNavTheme(int index)
        {
            nav.PaneDisplayMode = index == 0 ? NavigationViewPaneDisplayMode.LeftCompact : NavigationViewPaneDisplayMode.Top;
        }
        private void OnLangChanged(object? sender, LanguageChangedEventArgs e) => LoadLocalizerData();
        private void LoadLocalizerData()
        {
            var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;
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
        public void GoToPage(string PageName)
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
                    nav.SelectedItem = targetItem;
                    return;
                }
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
            navContainer.Navigate(pageType);
        }
        public void GoToBugReportPage(string? PageName)
        {
            NowPage = "BugReport";
            nav.Header = PageName;
            nav.SelectedItem = null;
            navContainer.Navigate(typeof(BugReportPage));
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
            if (_controller == null) return;
            _controller.Dispose();
            _controller = null;
        }
        private void MainWindow_Closing(object sender, AppWindowClosingEventArgs e)
        {
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle) && trayVisibleToggle is bool trayVisibleValue)
            {
                if (trayVisibleValue)
                {
                    e.Cancel = true;
                    this.Hide();
                    return;
                }
            }
            bool disabledVerify = false;
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify) && isDisabledVerify is bool disabledVerifyValue)
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
                    e.Cancel = false;
                }
                return;
            }
        }
        private void Nav_Loaded(object sender, RoutedEventArgs e)
        {
            LoadLocalizerData();
        }

        private void AppTitleBar_PaneToggleRequested(Microsoft.UI.Xaml.Controls.TitleBar sender, object args)
        {
            nav.IsPaneOpen = !nav.IsPaneOpen;
        }
    }
}
