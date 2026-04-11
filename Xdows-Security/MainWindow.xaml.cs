// using Windows.ApplicationModel.Resources;//多语言调用
using Compatibility.Windows.Storage;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using Windows.Security.Credentials.UI;
using Windows.UI.WindowManagement;
using WinUI3Localizer;
using WinUIEx;
using Xdows_Security.Views;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage = "Home";
        public WinUIEx.WindowManager? manager;

        public MainWindow()
        {
            InitializeComponent();
            manager = WinUIEx.WindowManager.Get(this);
            this.ExtendsContentIntoTitleBar = true;
            AppWindow.SetIcon("logo.ico");
            this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
            nav.SelectedItem = nav.MenuItems.OfType<NavigationViewItem>().First();
            Activated += MainWindow_Activated_FirstTime;
            Title = AppInfo.AppName;
            TitleText.Text = AppInfo.AppName;
            manager.AppWindow.Closing += MainWindow_Closing;
            manager.MinWidth = 650;
            manager.MinHeight = 530;
            Closed += delegate { Window_Closed(); };
            Localizer.Get().LanguageChanged += OnLangChanged;
            manager.TrayIconContextMenu += (w, e) =>
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
                    if (ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify))
                    {
                        disabledVerify = (bool)isDisabledVerify;
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
            var settings = ApplicationData.Current.LocalSettings;

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

                        if (ApplicationData.HasFile("background_image"))
                        {
                            var backgroundImagePath = await ApplicationData.ReadFileAsync("background_image");
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
                settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
                (int)d : 0
            );
            UpdatePaneToggleButtonPosition();
            if (settings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle))
            {
                manager?.IsVisibleInTray = (bool)trayVisibleToggle;
            }
            App.PlayEntranceAnimation(navContainer, "up");
        }
        public void UpdateNavTheme(int index)
        {
            nav.PaneDisplayMode = index == 0 ? NavigationViewPaneDisplayMode.LeftCompact : NavigationViewPaneDisplayMode.Top;
        }
        private void OnLangChanged(object? sender, LanguageChangedEventArgs e) => LoadLocalizerData();
        private void LoadLocalizerData()
        {
            var settings = ApplicationData.Current.LocalSettings;
            int navTheme = settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
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
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle))
            {
                if ((bool)trayVisibleToggle)
                {
                    e.Cancel = true;
                    this.Hide();
                    return;
                }
            }
            bool disabledVerify = false;
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? isDisabledVerify))
            {
                disabledVerify = (bool)isDisabledVerify;
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
