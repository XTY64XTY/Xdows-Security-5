using CommunityToolkit.WinUI.Controls;
using CommunityToolkit.WinUI.UI.Controls;
using Helper;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.Windows.Storage.Pickers;
using Protection;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using Windows.Security.Credentials.UI;
using WinUI3Localizer;
using Xdows_Security.Services;
using static Xdows_Security.LogText;
using ApplicationDataContainer = Microsoft.Windows.Storage.ApplicationDataContainer;

namespace Xdows_Security.Views
{
    public sealed partial class SettingsPage : Page
    {
        private Boolean IsInitialize = true;
        private DispatcherTimer? ProtectionStatusTimer;
        private const string DriverProtectionDisclaimerAcceptedSetting = "DriverProtectionDisclaimerAccepted";
        private bool _driverProtectionOperationInProgress;
        private bool _bootOperationInProgress;
        private bool _bootProtectionOperationInProgress;

        private sealed record BootDiskChoice(PhysicalDiskInfo Disk, String Title);

        public SettingsPage()
        {
            this.InitializeComponent();
            _ = InitializeAsync();
            InitializeProtectionStatusTimer();
        }

        private void InitializeProtectionStatusTimer()
        {
            ProtectionStatusTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            ProtectionStatusTimer.Tick += ProtectionStatusTimer_Tick;
            ProtectionStatusTimer.Start();
        }

        private void ProtectionStatusTimer_Tick(object? sender, object? e)
        {
            if (IsInitialize) return;
            if (_driverProtectionOperationInProgress) return;

            UpdateDriverProtectionState();
            UpdateProtectionToggleState(ProcessToggle, 0);
            UpdateProtectionToggleState(FilesToggle, 1);
            UpdateBootProtectionToggleState();
            UpdateProtectionToggleState(RegistryToggle, 4);
            ApplyDriverProtectionControlState();
            UpdateRegistryCategoryControlState();
        }

        private void UpdateProtectionToggleState(ToggleSwitch toggle, Int32 runId)
        {
            if (toggle == null) return;
            toggle.Toggled -= RunProtection;
            toggle.IsOn = ProtectionStatus.IsRun(runId);
            toggle.Toggled += RunProtection;
        }

        private void UpdateBootProtectionToggleState()
        {
            if (BootProtectionToggle == null) return;
            BootProtectionToggle.Toggled -= BootProtectionToggle_Toggled;
            BootProtectionToggle.IsOn = ProtectionStatus.IsRun(2);
            BootProtectionToggle.Toggled += BootProtectionToggle_Toggled;
        }

        private async Task InitializeAsync()
        {
            this.DispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    Settings_About_Name.Text = AppInfo.AppName;
                    Settings_About_Version.Text = AppInfo.AppVersion;
                    Settings_About_Feedback.NavigateUri = new Uri(AppInfo.AppFeedback);
                    Settings_About_Website.NavigateUri = new Uri(AppInfo.AppWebsite);

                    if (!App.IsRunAsAdmin())
                    {
                        BootProtectionToggle?.IsEnabled = false;
                        BootProtectionToggle?.IsOn = false;
                        RegistryToggle?.IsEnabled = false;
                        RegistryToggle?.IsOn = false;
                    }

                    await Task.WhenAll(
                        LoadScanSettingAsync,
                        LoadLanguageSettingAsync,
                        LoadThemeSettingAsync,
                        LoadBackdropSettingAsync,
                        LoadSoundSettingAsync,
                        LoadTransitionSettingAsync,
                        LoadThreatNotificationSettingAsync
                    );
                    WinUI3Localizer.Localizer.Get().LanguageChanged += (s, e) => UpdateAppText();
                    UpdateAppText();
                }
                catch { }
                finally
                {
                    IsInitialize = false;
                }
            });
        }
        private void UpdateAppText()
        {
            SettingsPage_Protection_Registry.Header += " (Beta)";
            SettingsPage_Scan_Xdows_Model.Header += " (Beta)";
            UpdateDriverProtectionState();
        }

        private void UpdateDriverProtectionState()
        {
            if (DriverProtectionToggle == null || DriverProtectionStatusText == null) return;

            if (!_driverProtectionOperationInProgress)
            {
                DriverProtectionToggle.Toggled -= DriverProtectionToggle_Toggled;
                DriverProtectionToggle.IsOn = ProtectionStatus.IsRun(5);
                DriverProtectionToggle.Toggled += DriverProtectionToggle_Toggled;
            }

            string statusKey = _driverProtectionOperationInProgress
                ? "SettingsPage_Protection_Driver_Setup_Status"
                : ProtectionStatus.GetDriverStatusKey();
            string status = Localizer.Get().GetLocalizedString(statusKey);
            DriverProtectionStatusText.Text = string.IsNullOrWhiteSpace(status) ? statusKey : status;
        }

        private void ApplyDriverProtectionControlState()
        {
            if (_driverProtectionOperationInProgress)
            {
                DriverProtectionToggle.IsEnabled = false;
                ProcessToggle.IsEnabled = false;
                FilesToggle.IsEnabled = false;
                BootProtectionToggle.IsEnabled = false;
                RegistryToggle.IsEnabled = false;
                Process_CompatibilityMode.IsOn = true;
                Files_CompatibilityMode.IsOn = true;
                Process_CompatibilityMode.IsEnabled = false;
                Files_CompatibilityMode.IsEnabled = false;
                UpdateRegistryCategoryControlState();
                return;
            }

            bool driverRunning = ProtectionStatus.IsRun(5);

            DriverProtectionToggle.IsEnabled = true;
            ProcessToggle.IsEnabled = !driverRunning;
            FilesToggle.IsEnabled = !driverRunning;
            BootProtectionToggle.IsEnabled = !driverRunning &&
                !_bootProtectionOperationInProgress &&
                App.IsRunAsAdmin();
            RegistryToggle.IsEnabled = !driverRunning && App.IsRunAsAdmin();
            Process_CompatibilityMode.IsOn = true;
            Files_CompatibilityMode.IsOn = true;
            Process_CompatibilityMode.IsEnabled = false;
            Files_CompatibilityMode.IsEnabled = false;
            UpdateRegistryCategoryControlState();
        }

        private void UpdateRegistryCategoryControlState()
        {
            if (RegistrySecondaryCard == null || RegistryOtherCard == null || RegistryToggle == null)
                return;

            Boolean enabled = RegistryToggle.IsEnabled && RegistryToggle.IsOn;
            RegistrySecondaryCard.IsEnabled = enabled;
            RegistryOtherCard.IsEnabled = enabled;
        }

        private async Task ShowDriverEnvironmentDialogAsync()
        {
            try
            {
                DriverEnvironmentDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                };

                await dialog.ShowAsync();
            }
            catch { }
        }

        private Task LoadScanSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadScanSetting);
            }
        }

        private Task LoadLanguageSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadLanguageSetting);
            }
        }

        private Task LoadThemeSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadThemeSetting);
            }
        }

        private Task LoadBackdropSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadBackdropSetting);
            }
        }

        private Task LoadSoundSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadSoundSetting);
            }
        }

        private Task LoadTransitionSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadTransitionSetting);
            }
        }

        private Task LoadThreatNotificationSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadThreatNotificationSetting);
            }
        }

        private Task<object?> RunOnDispatcher(Action action)
        {
            TaskCompletionSource<Object?> tcs = new();
            this.DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    action();
                    tcs.SetResult(null);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
            });
            return tcs.Task;
        }

        private void RunProtectionWithToggle(ToggleSwitch toggle, Int32 runId)
        {
            if (runId == 5)
            {
                _ = RunDriverProtectionToggleAsync(toggle);
                return;
            }

            toggle.Toggled -= RunProtection;
            if (!ProtectionStatus.Run(runId))
                toggle.IsOn = !toggle.IsOn;
            toggle.IsOn = ProtectionStatus.IsRun(runId);
            toggle.Toggled += RunProtection;
            if (runId == 4)
                UpdateRegistryCategoryControlState();
            if (runId == 5)
            {
                UpdateDriverProtectionState();
                ApplyDriverProtectionControlState();
            }
        }

        private void Settings_Feedback_Click(Object sender, RoutedEventArgs e)
        {
            App.MainWindow?.GoToBugReportPage(SettingsPage_Other_Feedback.Header.ToString());
        }

        private void RunProtection(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;
            String tag = toggle.Tag as String ?? String.Empty;
            Int32 runId = tag switch
            {
                "Driver" => 5,
                "Process" => 0,
                "Files" => 1,
                "Registry" => 4,
                _ => 0
            };
            RunProtectionWithToggle(toggle, runId);
        }

        private void RegistryCategoryToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
        }

        private async void BootProtectionToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;
            await RunBootProtectionToggleAsync(toggle);
        }

        private async Task RunBootProtectionToggleAsync(ToggleSwitch toggle)
        {
            if (_bootProtectionOperationInProgress)
            {
                SetBootProtectionToggleSilently(ProtectionStatus.IsRun(2));
                return;
            }

            Boolean requestedOn = toggle.IsOn;
            _bootProtectionOperationInProgress = true;
            ApplyDriverProtectionControlState();
            Boolean operationSucceeded = false;
            Boolean failureShown = false;

            try
            {
                if (requestedOn)
                {
                    BootProtectionPreparation preparation = await Task.Run(
                        ProtectionStatus.InspectBootProtectionPreparation);
                    if (!preparation.HasTrustedBaseline)
                    {
                        Boolean accepted = await ConfirmBootProtectionBaselineAsync(preparation);
                        if (!accepted)
                            return;

                        await Task.Run(ProtectionStatus.CreateBootProtectionBaseline);
                    }
                }

                operationSucceeded = await Task.Run(() =>
                {
                    if (ProtectionStatus.IsRun(2) == requestedOn)
                        return true;
                    return ProtectionStatus.Run(2);
                });
            }
            catch (Exception ex)
            {
                failureShown = true;
                AddNewLog(LogLevel.ERROR, "R3BootProtection", ex.Message);
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_ProtectionFailed_Title"),
                    BootFormat(
                        "SettingsPage_Protection_Boot_ProtectionFailed_Message",
                        $"0x{ex.HResult:X8}"));
            }
            finally
            {
                _bootProtectionOperationInProgress = false;
                SetBootProtectionToggleSilently(ProtectionStatus.IsRun(2));
                ApplyDriverProtectionControlState();
            }

            if (!operationSucceeded && requestedOn && !failureShown)
            {
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_ProtectionFailed_Title"),
                    BootText("SettingsPage_Protection_Boot_ProtectionStartFailed_Message"));
            }
        }

        private void SetBootProtectionToggleSilently(Boolean isOn)
        {
            if (BootProtectionToggle == null) return;
            BootProtectionToggle.Toggled -= BootProtectionToggle_Toggled;
            BootProtectionToggle.IsOn = isOn;
            BootProtectionToggle.Toggled += BootProtectionToggle_Toggled;
        }

        private async void DriverProtectionToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;

            await RunDriverProtectionToggleAsync(toggle);
        }

        private async Task RunDriverProtectionToggleAsync(ToggleSwitch toggle)
        {
            if (_driverProtectionOperationInProgress)
            {
                SetDriverProtectionToggleSilently(ProtectionStatus.IsRun(5));
                return;
            }

            bool requestedOn = toggle.IsOn;
            if (requestedOn && !await EnsureDriverProtectionDisclaimerAcceptedAsync())
            {
                SetDriverProtectionToggleSilently(false);
                return;
            }

            _driverProtectionOperationInProgress = true;
            UpdateDriverProtectionState();
            ApplyDriverProtectionControlState();

            bool operationSucceeded = false;
            try
            {
                operationSucceeded = requestedOn
                    ? await ShowDriverProtectionSetupDialogAsync(() => Task.Run(() => ProtectionStatus.Run(5)))
                    : await Task.Run(() => ProtectionStatus.Run(5));
            }
            catch (Exception ex)
            {
                AddNewLog(LogLevel.ERROR, "DriverProtection", ex.Message);
            }
            finally
            {
                _driverProtectionOperationInProgress = false;
                UpdateDriverProtectionState();
                ApplyDriverProtectionControlState();
            }

            SetDriverProtectionToggleSilently(ProtectionStatus.IsRun(5));

            if (requestedOn && (!operationSucceeded || !ProtectionStatus.IsRun(5)))
            {
                await ShowDriverEnvironmentDialogAsync();
            }
        }

        private void SetDriverProtectionToggleSilently(bool isOn)
        {
            if (DriverProtectionToggle == null) return;

            DriverProtectionToggle.Toggled -= DriverProtectionToggle_Toggled;
            DriverProtectionToggle.IsOn = isOn;
            DriverProtectionToggle.Toggled += DriverProtectionToggle_Toggled;
        }

        private async Task<bool> EnsureDriverProtectionDisclaimerAcceptedAsync()
        {
            ApplicationDataContainer settings = App.LocalSettings;
            if (settings.Values.TryGetValue(DriverProtectionDisclaimerAcceptedSetting, out object? raw) &&
                raw is bool accepted &&
                accepted)
            {
                return true;
            }

            try
            {
                ContentDialogResult result = await new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Disclaimer_Title"),
                    Content = Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Disclaimer_Text"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Close
                }.ShowAsync();

                if (result != ContentDialogResult.Primary)
                    return false;

                settings.Values[DriverProtectionDisclaimerAcceptedSetting] = true;
                return true;
            }
            catch (Exception ex)
            {
                AddNewLog(LogLevel.ERROR, "DriverProtection", ex.Message);
                return false;
            }
        }

        private async Task<bool> ShowDriverProtectionSetupDialogAsync(Func<Task<bool>> configureAsync)
        {
            DriverProtectionSetupDialog dialog = new(configureAsync)
            {
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            await dialog.ShowAsync();
            return dialog.SetupSucceeded;
        }

        private async void Toggled_SaveToggleData(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;

            String key = toggle.Tag as String ?? toggle.Name;
            if (String.IsNullOrWhiteSpace(key)) return;
            if (key is "Process_CompatibilityMode" or "Files_CompatibilityMode")
            {
                toggle.IsOn = true;
                App.LocalSettings.Values[key] = true;
                return;
            }
            if (toggle.IsOn && (key == "CloudScan" || key == "ExactRuleScan"))
            {
                _ = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Title"),
                    Content = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Text"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                }.ShowAsync();
            }
            var settings = App.LocalSettings;
            settings.Values[key] = toggle.IsOn;
        }

        private void VirusFamilyToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);

            if (sender is not ToggleSwitch virusToggle) return;

            if (virusToggle.IsOn)
            {
                InfectorCleanerToggle.IsEnabled = true;
            }
            else
            {
                if (InfectorCleanerToggle.IsOn)
                {
                    InfectorCleanerToggle.IsOn = false;
                    var settings = App.LocalSettings;
                    settings.Values["InfectorCleaner"] = false;
                }
                InfectorCleanerToggle.IsEnabled = false;
            }
        }

        private void LoadScanSetting()
        {
            var settings = App.LocalSettings;

            if (!settings.Values.ContainsKey("TrayVisibleToggle"))
            {
                settings.Values["TrayVisibleToggle"] = true;
            }
            if (!settings.Values.ContainsKey("ModelScan"))
            {
                settings.Values["ModelScan"] = true;
            }
            if (!settings.Values.ContainsKey("ShowTaskbarScanProgress"))
            {
                settings.Values["ShowTaskbarScanProgress"] = true;
            }
            if (!settings.Values.ContainsKey("UseFastIndexing"))
            {
                settings.Values["UseFastIndexing"] = true;
            }
            if (!settings.Values.ContainsKey("UsbAutoScan"))
            {
                settings.Values["UsbAutoScan"] = true;
            }
            if (!settings.Values.ContainsKey("RegistryProtectionSecondary"))
            {
                settings.Values["RegistryProtectionSecondary"] = true;
            }
            if (!settings.Values.ContainsKey("RegistryProtectionOther"))
            {
                settings.Values["RegistryProtectionOther"] = false;
            }

            List<ToggleSwitch> toggles =
            [
                ScanProgressToggle,
                TaskbarScanProgressToggle,
                FastIndexToggle,
                DeepScanToggle,
                ExtraDataToggle,
                ScanInsideToggle,
                VirusFamilyToggle,
                InfectorCleanerToggle,
                ExactRuleToggle,
                LocalScanToggle,
                ModelScanToggle,
                CloudScanToggle,
                TrayVisibleToggle,
                ContextMenuScanToggle,
                DisabledVerifyToggle,
                Process_CompatibilityMode,
                Files_CompatibilityMode,
                DriverProtectionToggle,
                SettingsPage_Appearance_Nav_IsPaneToggleButtonInTitleBar,
                SettingsPage_Appearance_Nav_IsBackButtonVisible,
                SoundEffectsToggle,
                SpatialAudioToggle,
                UsbAutoScanToggle,
                RegistrySecondaryToggle,
                RegistryOtherToggle
            ];

            foreach (ToggleSwitch toggle in toggles)
            {
                if (toggle == null) continue;

                String key = toggle.Tag as String ?? "";
                if (!String.IsNullOrWhiteSpace(key) && settings.Values.TryGetValue(key, out var raw) && raw is Boolean isOn)
                {
                    toggle.IsOn = isOn;
                }
            }

            if (!settings.Values.ContainsKey("ModelMode"))
            {
                settings.Values["ModelMode"] = "Standard";
            }

            try
            {
                string modelMode = settings.Values.TryGetValue("ModelMode", out object? modeRaw) && modeRaw is string ms ? ms : "Standard";
                ComboBox modelCombo = this.FindName("ModelModeComboBox") as ComboBox ?? new();
                if (modelCombo != null)
                {
                    foreach (Object obj in modelCombo.Items)
                    {
                        if (obj is ComboBoxItem item && (item.Tag as String) == modelMode)
                        {
                            modelCombo.SelectedItem = item;
                            break;
                        }
                    }
                }
            }
            catch { }

            if (!settings.Values.ContainsKey("ModelModeForProtection"))
            {
                settings.Values["ModelModeForProtection"] = false;
                ModelModeForProtectionToggle.IsOn = false;
            }
            else if (settings.Values.TryGetValue("ModelModeForProtection", out var mfpRaw) && mfpRaw is bool mfpOn)
            {
                ModelModeForProtectionToggle.IsOn = mfpOn;
            }

            if (!settings.Values.ContainsKey("Process_CompatibilityMode"))
            {
                settings.Values["Process_CompatibilityMode"] = true;
            }
            Process_CompatibilityMode.IsOn = true;
            Process_CompatibilityMode.IsEnabled = false;

            if (!settings.Values.ContainsKey("Files_CompatibilityMode"))
            {
                settings.Values["Files_CompatibilityMode"] = true;
            }
            Files_CompatibilityMode.IsOn = true;
            Files_CompatibilityMode.IsEnabled = false;

            if (!settings.Values.ContainsKey("IsBackButtonVisible"))
            {
                settings.Values["IsBackButtonVisible"] = true;
                SettingsPage_Appearance_Nav_IsBackButtonVisible.IsOn = true;
            }

            InfectorCleanerToggle.IsEnabled = VirusFamilyToggle.IsOn;

            if (settings.Values.TryGetValue("AppBackdropOpacity", out object? opacityRaw) && opacityRaw is double opacity)
            {
                Appearance_Backdrop_Opacity.Value = opacity;
            }
            else
            {
                Appearance_Backdrop_Opacity.Value = 100;
            }

            ProcessToggle.IsOn = ProtectionStatus.IsRun(0);
            FilesToggle.IsOn = ProtectionStatus.IsRun(1);
            BootProtectionToggle.IsOn = ProtectionStatus.IsRun(2);
            RegistryToggle.IsOn = ProtectionStatus.IsRun(4);
            DriverProtectionToggle.IsOn = ProtectionStatus.IsRun(5);
            UpdateDriverProtectionState();
            ApplyDriverProtectionControlState();
            ContextMenuScanToggle.IsOn = ContextMenuService.IsEnabled();
            StartupToggle.IsOn = StartupService.IsStartupEnabled();

            // Load scan index mode setting (default Parallel) without direct XAML field access
            try
            {
                string mode = settings.Values.TryGetValue("ScanIndexMode", out object? raw) && raw is string s ? s : "Parallel";
                ComboBox combo = this.FindName("ScanIndexModeComboBox") as ComboBox ?? new();
                if (combo != null)
                {
                    foreach (Object obj in combo.Items)
                    {
                        if (obj is ComboBoxItem item && (item.Tag as String) == mode)
                        {
                            combo.SelectedItem = item;
                            break;
                        }
                    }
                    // Options that require a separate indexing pass are only available in Independent mode.
                    try
                    {
                        ToggleSwitch toggle = this.FindName("ScanProgressToggle") as ToggleSwitch ?? new();
                        if (toggle != null)
                        {
                            if (mode == "Parallel")
                            {
                                toggle.IsOn = false;
                                toggle.IsEnabled = false;
                            }
                            else
                            {
                                toggle.IsEnabled = true;
                            }
                        }

                        FastIndexToggle.IsEnabled = mode == "After";
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanIndexModeComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is String tag)
            {
                ApplicationDataContainer settings = App.LocalSettings;
                settings.Values["ScanIndexMode"] = tag;
                try
                {
                    ToggleSwitch toggle = this.FindName("ScanProgressToggle") as ToggleSwitch ?? new();
                    if (toggle != null)
                    {
                        if (tag == "Parallel")
                        {
                            toggle.IsOn = false;
                            toggle.IsEnabled = false;
                            settings.Values["ShowScanProgress"] = false;
                        }
                        else
                        {
                            toggle.IsEnabled = true;
                        }

                        FastIndexToggle.IsEnabled = tag == "After";
                    }
                }
                catch { }
            }
        }

        private void ModelModeComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is String tag)
            {
                ApplicationDataContainer settings = App.LocalSettings;
                settings.Values["ModelMode"] = tag;
            }
        }

        private void ModelModeForProtectionToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ToggleSwitch toggle)
            {
                ApplicationDataContainer settings = App.LocalSettings;
                settings.Values["ModelModeForProtection"] = toggle.IsOn;
            }
        }

        private void LoadLanguageSetting()
        {
            ApplicationDataContainer settings = App.LocalSettings;
            if (!settings.Values.TryGetValue("AppLanguage", out object? langRaw) || langRaw is not string savedLanguage)
            {
                savedLanguage = "en-US";
            }

            foreach (ComboBoxItem item in LanguageComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as string == savedLanguage)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }
        }

        private async void RestartOOBEButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                App.SetRunOOBE(true);
                var currentProcess = Process.GetCurrentProcess();
                string executablePath = currentProcess.MainModule?.FileName ?? currentProcess.ProcessName;
                App.MainWindow?.RestartVoluntarily(executablePath);
            }
            catch { }
        }

        private void LoadThemeSetting()
        {
            ApplicationDataContainer settings = App.LocalSettings;
            ElementTheme themeValue = ElementTheme.Default;
            if (settings.Values.TryGetValue("AppTheme", out object? themeRaw) && themeRaw is string themeString && Enum.TryParse(themeString, out ElementTheme parsedTheme))
            {
                themeValue = parsedTheme;
            }

            ThemeComboBox.SelectedIndex = themeValue switch
            {
                ElementTheme.Light => 1,
                ElementTheme.Dark => 2,
                _ => 0
            };

            int navIndex = settings.Values.TryGetValue("AppNavTheme", out object? raw) && raw is double d ? (int)d : 0;
            NavComboBox.SelectedIndex = navIndex;

            // 当导航栏在顶部时，禁用紧凑导航栏选项
            SettingsPage_Appearance_Nav_IsPaneToggleButtonInTitleBar.IsEnabled = navIndex == 0;
        }

        private async void LanguageComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                String currentLanguage = Localizer.Get().GetCurrentLanguage();
                if (selectedItem.Tag is not String newLanguage) return;
                if (newLanguage != currentLanguage)
                {
                    App.LocalSettings.Values["AppLanguage"] = newLanguage;
                    await Localizer.Get().SetLanguage(newLanguage);
                    ContextMenuService.UpdateMenuText();
                }
            }
        }

        private async void UpdateButtonClick(Object sender, RoutedEventArgs e)
        {
            try
            {
                UpdateButton.IsEnabled = false;
                UpdateProgressRing.IsActive = true;
                UpdateProgressRing.Visibility = Visibility.Visible;

                UpdateInfo? update = await Updater.CheckUpdateAsync();
                if (update == null)
                {
                    UpdateButton.IsEnabled = true;
                    UpdateProgressRing.IsActive = false;
                    UpdateProgressRing.Visibility = Visibility.Collapsed;
                    UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
                    UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
                    return;
                }
                MarkdownTextBlock box = new()
                {
                    Text = update.Content,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(12),
                };
                ScrollViewer scrollViewer = new()
                {
                    Content = box,
                    MaxHeight = 320,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                };

                ContentDialog dialog = new()
                {
                    Title = update.Title,
                    Content = scrollViewer,
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Download"),
                    SecondaryButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                };

                ContentDialogResult result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    await Windows.System.Launcher.LaunchUriAsync(new Uri(update.DownloadUrl));
                }
            }
            catch
            {
                try
                {
                    UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
                    UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
                }
                catch { }
            }
            finally
            {
                UpdateButton.IsEnabled = true;
                UpdateProgressRing.IsActive = false;
                UpdateProgressRing.Visibility = Visibility.Collapsed;
            }
        }

        private void UpdateTeachingTipClose(TeachingTip sender, Object args)
        {
            UpdateTeachingTip.IsOpen = false;
        }

        private void ThemeComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize || ThemeComboBox.SelectedIndex == -1) return;

            ElementTheme selectedTheme = ThemeComboBox.SelectedIndex switch
            {
                0 => ElementTheme.Default,
                1 => ElementTheme.Light,
                2 => ElementTheme.Dark,
                _ => ElementTheme.Default
            };

            ApplicationDataContainer settings = App.LocalSettings;
            settings.Values["AppTheme"] = selectedTheme.ToString();
            if (App.MainWindow == null) return;
            if (App.MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = selectedTheme;
            }
            MainWindow.UpdateTheme(selectedTheme);
        }

        public static void UpdateThemeforLoad(ElementTheme Theme)
        {
            MainWindow.UpdateTheme(Theme);
        }

        private void LoadBackdropSetting()
        {
            ApplicationDataContainer settings = App.LocalSettings;
            String savedBackdrop = settings.Values.TryGetValue("AppBackdrop", out object? backdropRaw) && backdropRaw is string backdrop
                ? backdrop
                : "";

            Appearance_Backdrop_Opacity.IsEnabled = !(savedBackdrop == "Solid");
            MicaOption.IsEnabled = MicaController.IsSupported();
            MicaAltOption.IsEnabled = MicaController.IsSupported();

            Boolean found = false;
            foreach (ComboBoxItem item in BackdropComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as String == savedBackdrop)
                {
                    BackdropComboBox.SelectedItem = item;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                BackdropComboBox.SelectedIndex = MicaController.IsSupported() ? 1 : 3;
            }
        }

        private void BackdropComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (BackdropComboBox.SelectedItem is ComboBoxItem selected)
            {
                try
                {
                    String backdropType = selected.Tag as String ?? ElementTheme.Default.ToString();
                    ApplicationDataContainer settings = App.LocalSettings;
                    settings.Values["AppBackdrop"] = backdropType;
                    App.MainWindow?.ApplyBackdrop(backdropType, false);
                    Appearance_Backdrop_Opacity.IsEnabled = !(backdropType == "Solid");
                }
                catch { }
            }
        }

        private void OpacitySlider_ValueChanged(Object sender, RangeBaseValueChangedEventArgs e)
        {
            if (IsInitialize || sender is not Slider slider) return;
            ApplicationDataContainer settings = App.LocalSettings;
            settings.Values["AppBackdropOpacity"] = slider.Value;
            if (App.MainWindow == null) return;
            string backdrop = settings.Values.TryGetValue("AppBackdrop", out object? backdropRaw) && backdropRaw is string backdropValue
                ? backdropValue
                : "Mica";
            App.MainWindow.ApplyBackdrop(backdrop, false);
        }

        private void NavComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            try
            {
                Int32 index = NavComboBox.SelectedIndex;
                ApplicationDataContainer settings = App.LocalSettings;
                settings.Values["AppNavTheme"] = index;
                App.MainWindow?.UpdateNavTheme(index);

                // 当导航栏在顶部时，禁用紧凑导航栏选项；在左侧时启用
                SettingsPage_Appearance_Nav_IsPaneToggleButtonInTitleBar.IsEnabled = index == 0;

                // 如果切换到顶部导航栏，重置紧凑导航栏设置为 false
                if (index == 1)
                {
                    SettingsPage_Appearance_Nav_IsPaneToggleButtonInTitleBar.IsOn = false;
                    settings.Values["IsPaneToggleButtonInTitleBar"] = false;
                    App.MainWindow?.UpdatePaneToggleButtonPosition();
                }
            }
            catch { }
        }

        private async void Quarantine_ViewButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                QuarantineDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };
                await dialog.ShowAsync();
            }
            catch { }
        }

        private async void Quarantine_ClearButton_Click(Object sender, RoutedEventArgs e)
        {
            _ = QuarantineManager.ClearQuarantine();
        }

        private async void Trust_ViewButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                TrustDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };
                _ = dialog.ShowAsync();
            }
            catch { }
        }

        private async void Trust_AddButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
                if (file is null) { return; }
                await TrustManager.AddToTrust(file.Path);
            }
            catch { }
        }

        private void TrayVisibleToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.Manager?.IsVisibleInTray = TrayVisibleToggle.IsOn;
        }

        private void StartupToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (IsInitialize || sender is not ToggleSwitch toggle) return;

            bool success;
            if (toggle.IsOn)
            {
                success = StartupService.EnableStartup();
            }
            else
            {
                success = StartupService.DisableStartup();
            }

            if (!success)
            {
                toggle.Toggled -= StartupToggle_Toggled;
                toggle.IsOn = !toggle.IsOn;
                toggle.Toggled += StartupToggle_Toggled;
                LogText.AddNewLog(LogText.LogLevel.ERROR, "Settings", "Failed to change startup setting");
                return;
            }

            try
            {
                var settings = App.LocalSettings;
                settings.Values["AutoEnableStartup"] = toggle.IsOn;
            }
            catch { }
        }

        private void ContextMenuScanToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (IsInitialize) return;
            if (ContextMenuScanToggle.IsOn)
            {
                bool success = ContextMenuService.Register();
                if (!success)
                {
                    ContextMenuScanToggle.IsOn = false;
                }
            }
            else
            {
                ContextMenuService.Unregister();
            }
        }


        private void SettingsSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                String searchText = sender.Text.ToLowerInvariant();
                if (String.IsNullOrWhiteSpace(searchText))
                {
                    ShowAllSettingsItems();
                    return;
                }
                FilterSettingsItems(searchText);
            }
        }

        private void ShowAllSettingsItems()
        {
            if (SettingsContentPanel == null) return;

            foreach (UIElement child in SettingsContentPanel.Children)
            {
                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Visible;
                    if (element is SettingsExpander expander)
                    {
                        foreach (Object expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Visible;
                            }
                        }
                    }
                }
            }
            App.PlayEntranceAnimation(SettingsContentPanel, "up", 40);
        }

        private void FilterSettingsItems(String searchText)
        {
            if (SettingsContentPanel == null) return;

            foreach (UIElement child in SettingsContentPanel.Children)
            {
                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Collapsed;
                    if (element is SettingsExpander expander)
                    {
                        foreach (Object expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Collapsed;
                            }
                        }
                    }
                }
            }

            Boolean currentHeaderMatched = false;
            for (Int32 i = 0; i < SettingsContentPanel.Children.Count; i++)
            {
                UIElement child = SettingsContentPanel.Children[i];
                if (child is FrameworkElement element)
                {
                    if (element is TextBlock textBlock)
                    {
                        currentHeaderMatched = IsSettingsItemMatched(textBlock, searchText);
                        if (currentHeaderMatched)
                        {
                            textBlock.Visibility = Visibility.Visible;
                        }
                    }
                    else if (element is SettingsCard or SettingsExpander)
                    {
                        Boolean shouldShow = false;
                        if (IsSettingsItemMatched(element, searchText))
                        {
                            shouldShow = true;
                        }
                        if (!shouldShow && currentHeaderMatched)
                        {
                            shouldShow = true;
                        }
                        if (element is SettingsExpander expander)
                        {
                            foreach (Object expanderChild in expander.Items)
                            {
                                if (expanderChild is SettingsCard card)
                                {
                                    if (IsSettingsItemMatched(card, searchText) || currentHeaderMatched)
                                    {
                                        shouldShow = true;
                                        card.Visibility = Visibility.Visible;
                                    }
                                }
                            }
                        }
                        if (shouldShow)
                        {
                            element.Visibility = Visibility.Visible;
                        }
                    }
                }
            }
            App.PlayEntranceAnimation(SettingsContentPanel, "up", 40);
        }

        private static Boolean IsSettingsItemMatched(FrameworkElement item, String searchText)
        {
            String itemText = GetSettingsItemText(item);
            if (String.IsNullOrEmpty(itemText))
                return false;
            return itemText.Contains(searchText, StringComparison.InvariantCultureIgnoreCase);
        }

        private static String GetSettingsItemText(FrameworkElement item)
        {
            if (item is TextBlock textBlock)
            {
                return textBlock.Text;
            }
            else if (item is SettingsCard card)
            {
                return card.Header?.ToString() ?? String.Empty;
            }
            else if (item is SettingsExpander expander)
            {
                return expander.Header?.ToString() ?? String.Empty;
            }
            return String.Empty;
        }

        private Boolean DisabledVerifyToggleVerify = true;

        private async void DisabledVerifyToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (!DisabledVerifyToggleVerify || IsInitialize) return;

            if (DisabledVerifyToggle.IsOn)
            {
                DisabledVerifyToggleVerify = false;
                DisabledVerifyToggle.IsOn = false;
                UserConsentVerificationResult result = await UserConsentVerifier.RequestVerificationAsync(String.Empty);
                if (result is UserConsentVerificationResult.DeviceNotPresent or
                    UserConsentVerificationResult.DisabledByPolicy or
                    UserConsentVerificationResult.NotConfiguredForUser or
                    UserConsentVerificationResult.Verified)
                {
                    DisabledVerifyToggle.IsOn = true;
                    Toggled_SaveToggleData(sender, e);
                }
                DisabledVerifyToggleVerify = true;
            }
            else
            {
                Toggled_SaveToggleData(sender, e);
            }
        }

        private async void OpenConfigLocationButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                String path = App.AppData.LocalPath;
                Directory.CreateDirectory(path);
                await Windows.System.Launcher.LaunchFolderPathAsync(path);
            }
            catch (Exception ex)
            {
                ContentDialog errorDialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void ResetConfigButton_Click(Object sender, RoutedEventArgs e)
        {
            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Title"),
                Content = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Content"),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                DefaultButton = ContentDialogButton.Close
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    String path = App.AppData.LocalPath;
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                    }
                }
                catch (Exception ex)
                {
                    ContentDialog errorDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Title"),
                        Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Content"), ex.Message),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                    return;
                }

                try
                {
                    String? current = Process.GetCurrentProcess().MainModule?.FileName;
                    if (!String.IsNullOrEmpty(current))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = current,
                            UseShellExecute = true
                        });
                    }
                }
                catch { }

                App.MainWindow?.CloseVoluntarily();
            }
        }

        private async void Boot_Save_Button_Click(Object sender, RoutedEventArgs e)
        {
            await RunBootOperationAsync(async () =>
            {
                BootDiskChoice? selected = await SelectBootDiskAsync(
                    BootText("SettingsPage_Protection_Boot_DiskDialog_BackupInstruction"));
                if (selected is null)
                    return;

                Byte[] bootSector = await Task.Run(() => DiskOperator.ReadBootSector(selected.Disk.Index));
                if (!DiskOperator.IsValidBootSector(bootSector))
                {
                    await ShowBootMessageAsync(
                        BootText("SettingsPage_Protection_Boot_InvalidSource_Title"),
                        BootText("SettingsPage_Protection_Boot_InvalidSource_Message"));
                    return;
                }

                FileSavePicker picker = new(XamlRoot.ContentIslandEnvironment.AppWindowId)
                {
                    SuggestedFileName = $"Xdows-Boot-Disk{selected.Disk.Index}-{DateTime.Now:yyyyMMdd-HHmmss}",
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                    SuggestedFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };
                picker.FileTypeChoices.Add(
                    BootText("SettingsPage_Protection_Boot_BackupFileType"),
                    [".bin"]);

                PickFileResult? file = await picker.PickSaveFileAsync();
                if (file is null)
                    return;

                await File.WriteAllBytesAsync(file.Path, bootSector);
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_BackupSuccess_Title"),
                    BootFormat(
                        "SettingsPage_Protection_Boot_BackupSuccess_Message",
                        selected.Title,
                        file.Path));
            });
        }

        private async void Boot_Restore_Button_Click(Object sender, RoutedEventArgs e)
        {
            await RunBootOperationAsync(async () =>
            {
                FileOpenPicker picker = new(XamlRoot.ContentIslandEnvironment.AppWindowId)
                {
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary
                };
                picker.FileTypeFilter.Add(".bin");

                PickFileResult? file = await picker.PickSingleFileAsync();
                if (file is null)
                    return;

                Byte[] bootSector = await File.ReadAllBytesAsync(file.Path);
                if (!DiskOperator.IsValidBootSector(bootSector))
                {
                    await ShowBootMessageAsync(
                        BootText("SettingsPage_Protection_Boot_InvalidBackup_Title"),
                        BootText("SettingsPage_Protection_Boot_InvalidBackup_Message"));
                    return;
                }

                BootDiskChoice? selected = await SelectBootDiskAsync(
                    BootText("SettingsPage_Protection_Boot_DiskDialog_RestoreInstruction"));
                if (selected is null ||
                    !await ConfirmBootRestoreAsync(file.Path, selected))
                {
                    return;
                }

                await Task.Run(() => DiskOperator.WriteBootSector(selected.Disk.Index, bootSector));
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_RestoreSuccess_Title"),
                    BootFormat(
                        "SettingsPage_Protection_Boot_RestoreSuccess_Message",
                        selected.Title));
            });
        }

        private async Task RunBootOperationAsync(Func<Task> operation)
        {
            if (_bootOperationInProgress)
                return;

            _bootOperationInProgress = true;
            BootSaveButton.IsEnabled = false;
            BootRestoreButton.IsEnabled = false;
            try
            {
                await operation();
            }
            catch (Exception ex)
            {
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_OperationFailed_Title"),
                    BootFormat(
                        "SettingsPage_Protection_Boot_OperationFailed_Message",
                        $"0x{ex.HResult:X8}"));
            }
            finally
            {
                BootSaveButton.IsEnabled = true;
                BootRestoreButton.IsEnabled = true;
                _bootOperationInProgress = false;
            }
        }

        private async Task<BootDiskChoice?> SelectBootDiskAsync(String instruction)
        {
            IReadOnlyList<PhysicalDiskInfo> disks = await Task.Run(DiskOperator.GetPhysicalDisks);
            if (disks.Count == 0)
            {
                await ShowBootMessageAsync(
                    BootText("SettingsPage_Protection_Boot_NoDisks_Title"),
                    BootText("SettingsPage_Protection_Boot_NoDisks_Message"));
                return null;
            }

            List<BootDiskChoice> choices = disks
                .Select(disk => new BootDiskChoice(disk, FormatDiskTitle(disk)))
                .ToList();
            ComboBox diskSelector = new()
            {
                Header = BootText("SettingsPage_Protection_Boot_DiskDialog_ComboHeader"),
                ItemsSource = choices,
                DisplayMemberPath = nameof(BootDiskChoice.Title),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                MinWidth = 440,
                SelectedIndex = Math.Max(0, choices.FindIndex(choice => choice.Disk.IsSystemDisk))
            };
            AutomationProperties.SetAutomationId(diskSelector, "BootPhysicalDiskSelector");

            TextBlock details = new()
            {
                TextWrapping = TextWrapping.Wrap,
                Style = Application.Current.Resources["CaptionTextBlockStyle"] as Style
            };
            void UpdateDetails()
            {
                details.Text = diskSelector.SelectedItem is BootDiskChoice choice
                    ? FormatDiskDetails(choice.Disk)
                    : String.Empty;
            }
            diskSelector.SelectionChanged += (_, _) => UpdateDetails();
            UpdateDetails();

            StackPanel content = new()
            {
                Spacing = 12,
                MinWidth = 440
            };
            content.Children.Add(new TextBlock
            {
                Text = instruction,
                TextWrapping = TextWrapping.Wrap
            });
            content.Children.Add(diskSelector);
            content.Children.Add(details);

            ContentDialog dialog = new()
            {
                Title = BootText("SettingsPage_Protection_Boot_DiskDialog_Title"),
                Content = content,
                PrimaryButtonText = BootText("SettingsPage_Protection_Boot_Dialog_Continue"),
                CloseButtonText = BootText("SettingsPage_Protection_Boot_Dialog_Cancel"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            return await dialog.ShowAsync() == ContentDialogResult.Primary
                ? diskSelector.SelectedItem as BootDiskChoice
                : null;
        }

        private async Task<Boolean> ConfirmBootProtectionBaselineAsync(
            BootProtectionPreparation preparation)
        {
            StackPanel content = new()
            {
                Spacing = 12,
                MinWidth = 440
            };
            content.Children.Add(new TextBlock
            {
                Text = BootText("SettingsPage_Protection_Boot_Baseline_Message"),
                TextWrapping = TextWrapping.Wrap
            });
            content.Children.Add(new TextBlock
            {
                Text = FormatDiskDetails(preparation.Disk),
                TextWrapping = TextWrapping.Wrap,
                Style = Application.Current.Resources["CaptionTextBlockStyle"] as Style
            });
            content.Children.Add(new TextBlock
            {
                Text = BootText(
                    preparation.Disk.PartitionStyle == PhysicalDiskPartitionStyle.Gpt
                        ? "SettingsPage_Protection_Boot_Baseline_Scope_Gpt"
                        : "SettingsPage_Protection_Boot_Baseline_Scope_Mbr"),
                TextWrapping = TextWrapping.Wrap
            });
            content.Children.Add(new InfoBar
            {
                IsOpen = true,
                IsClosable = false,
                Severity = InfoBarSeverity.Warning,
                Message = BootText("SettingsPage_Protection_Boot_Baseline_Warning")
            });

            ContentDialog dialog = new()
            {
                Title = BootText("SettingsPage_Protection_Boot_Baseline_Title"),
                Content = content,
                PrimaryButtonText = BootText("SettingsPage_Protection_Boot_Baseline_Primary"),
                CloseButtonText = BootText("SettingsPage_Protection_Boot_Dialog_Cancel"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };
            AutomationProperties.SetAutomationId(dialog, "BootProtectionBaselineDialog");
            AutomationProperties.SetName(
                dialog,
                BootText("SettingsPage_Protection_Boot_Baseline_Title"));

            return await dialog.ShowAsync() == ContentDialogResult.Primary;
        }

        private async Task<Boolean> ConfirmBootRestoreAsync(
            String backupPath,
            BootDiskChoice selected)
        {
            StackPanel content = new()
            {
                Spacing = 12,
                MinWidth = 440
            };
            content.Children.Add(new TextBlock
            {
                Text = BootFormat(
                    "SettingsPage_Protection_Boot_RestoreConfirm_Summary",
                    Path.GetFileName(backupPath),
                    selected.Title),
                TextWrapping = TextWrapping.Wrap
            });
            content.Children.Add(new TextBlock
            {
                Text = FormatDiskDetails(selected.Disk),
                TextWrapping = TextWrapping.Wrap,
                Style = Application.Current.Resources["CaptionTextBlockStyle"] as Style
            });
            content.Children.Add(new InfoBar
            {
                IsOpen = true,
                IsClosable = false,
                Severity = InfoBarSeverity.Warning,
                Message = BootText("SettingsPage_Protection_Boot_RestoreConfirm_Warning")
            });

            ContentDialog dialog = new()
            {
                Title = BootText("SettingsPage_Protection_Boot_RestoreConfirm_Title"),
                Content = content,
                PrimaryButtonText = BootText("SettingsPage_Protection_Boot_RestoreConfirm_Primary"),
                CloseButtonText = BootText("SettingsPage_Protection_Boot_Dialog_Cancel"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            return await dialog.ShowAsync() == ContentDialogResult.Primary;
        }

        private async Task ShowBootMessageAsync(String title, String message)
        {
            ContentDialog dialog = new()
            {
                Title = title,
                Content = new TextBlock
                {
                    Text = message,
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = BootText("SettingsPage_Protection_Boot_Dialog_Close"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };
            await dialog.ShowAsync();
        }

        private static String FormatDiskTitle(PhysicalDiskInfo disk)
        {
            String model = String.IsNullOrWhiteSpace(disk.Model)
                ? BootText("SettingsPage_Protection_Boot_Disk_UnknownModel")
                : disk.Model;
            if (model.Length > 60)
                model = model[..59] + "…";

            String systemSuffix = disk.IsSystemDisk
                ? BootText("SettingsPage_Protection_Boot_Disk_SystemSuffix")
                : String.Empty;
            return BootFormat(
                "SettingsPage_Protection_Boot_Disk_TitleFormat",
                disk.Index,
                model,
                systemSuffix);
        }

        private static String FormatDiskDetails(PhysicalDiskInfo disk)
        {
            String unknown = BootText("SettingsPage_Protection_Boot_Disk_UnknownValue");
            String serial = String.IsNullOrWhiteSpace(disk.SerialNumber) ? unknown : disk.SerialNumber;
            String busType = String.Equals(disk.BusType, "Unknown", StringComparison.Ordinal)
                ? unknown
                : disk.BusType;
            String size = disk.SizeBytes > 0
                ? BootFormat(
                    "SettingsPage_Protection_Boot_Disk_SizeFormat",
                    disk.SizeBytes / 1024d / 1024d / 1024d)
                : unknown;

            return BootFormat(
                "SettingsPage_Protection_Boot_Disk_DetailsFormat",
                disk.DevicePath,
                serial,
                size,
                PartitionStyleText(disk.PartitionStyle),
                busType);
        }

        private static String PartitionStyleText(PhysicalDiskPartitionStyle style)
        {
            String suffix = style switch
            {
                PhysicalDiskPartitionStyle.Mbr => "Mbr",
                PhysicalDiskPartitionStyle.Gpt => "Gpt",
                PhysicalDiskPartitionStyle.Raw => "Raw",
                _ => "Unknown"
            };
            return BootText($"SettingsPage_Protection_Boot_Disk_Partition_{suffix}");
        }

        private static String BootText(String key)
        {
            return Localizer.Get().GetLocalizedString(key);
        }

        private static String BootFormat(String key, params Object[] values)
        {
            return String.Format(CultureInfo.CurrentCulture, BootText(key), values);
        }

        private async void SettingsPage_Appearance_Nav_IsPaneToggleButtonInTitleBar_Toggled(object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.UpdatePaneToggleButtonPosition();
        }

        private void SettingsPage_Appearance_Nav_IsBackButtonVisible_Toggled(object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.UpdateBackButtonPosition();
        }

        private void LoadSoundSetting()
        {
            var settings = App.LocalSettings;

            SoundEffectsToggle.IsOn = settings.Values.TryGetValue("SoundEffects", out var s) && s is true;
            SpatialAudioToggle.IsOn = settings.Values.TryGetValue("SpatialAudio", out var sp) && sp is true || !(settings.Values.ContainsKey("SpatialAudio"));
            SpatialAudioToggle.IsEnabled = SoundEffectsToggle.IsOn;

            ApplySoundSettings();
        }

        private void SoundEffectsToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (IsInitialize) return;
            Toggled_SaveToggleData(sender, e);
            SpatialAudioToggle.IsEnabled = SoundEffectsToggle.IsOn;
            ApplySoundSettings();
        }

        private void SpatialAudioToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (IsInitialize) return;
            Toggled_SaveToggleData(sender, e);
            ApplySoundSettings();
        }

        private void TransitionComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                ApplicationDataContainer settings = App.LocalSettings;
                settings.Values["PageTransition"] = tag;
            }
        }

        private void LoadTransitionSetting()
        {
            var settings = App.LocalSettings;
            string savedTransition = settings.Values.TryGetValue("PageTransition", out var raw) && raw is string s ? s : "Default";

            if (!settings.Values.ContainsKey("PageTransition"))
            {
                settings.Values["PageTransition"] = savedTransition;
            }

            foreach (ComboBoxItem item in TransitionComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as string == savedTransition)
                {
                    TransitionComboBox.SelectedItem = item;
                    break;
                }
            }
        }

        private void LoadThreatNotificationSetting()
        {
            var settings = App.LocalSettings;
            string savedMode = settings.Values.TryGetValue(
                ThreatNotificationModeService.NotificationModeSetting,
                out object? modeRaw) && modeRaw is string mode
                    ? mode
                    : ThreatNotificationModeService.NormalMode;
            bool onlyWhenGaming = settings.Values.TryGetValue(
                ThreatNotificationModeService.UseCompactWhenGamingSetting,
                out object? gamingRaw) && gamingRaw is bool gaming && gaming;

            if (!settings.Values.ContainsKey(ThreatNotificationModeService.NotificationModeSetting))
                settings.Values[ThreatNotificationModeService.NotificationModeSetting] = ThreatNotificationModeService.NormalMode;
            if (!settings.Values.ContainsKey(ThreatNotificationModeService.UseCompactWhenGamingSetting))
                settings.Values[ThreatNotificationModeService.UseCompactWhenGamingSetting] = false;

            foreach (ComboBoxItem item in ThreatNotificationModeComboBox.Items.Cast<ComboBoxItem>())
            {
                if (string.Equals(item.Tag as string, savedMode, StringComparison.Ordinal))
                {
                    ThreatNotificationModeComboBox.SelectedItem = item;
                    break;
                }
            }

            if (ThreatNotificationModeComboBox.SelectedItem is null)
                ThreatNotificationModeComboBox.SelectedIndex = 0;

            CompactNotificationWhenGamingToggle.IsOn = onlyWhenGaming;
            ThreatNotificationModeComboBox.IsEnabled = !onlyWhenGaming;
        }

        private async void GamePathsViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                GamePathsDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };
                _ = await dialog.ShowAsync();
            }
            catch { }
        }

        private void ThreatNotificationModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize || sender is not ComboBox { SelectedItem: ComboBoxItem item } || item.Tag is not string mode)
                return;

            App.LocalSettings.Values[ThreatNotificationModeService.NotificationModeSetting] = mode;
        }

        private void CompactNotificationWhenGamingToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle)
                return;

            ThreatNotificationModeComboBox.IsEnabled = !toggle.IsOn;
            if (!IsInitialize)
                App.LocalSettings.Values[ThreatNotificationModeService.UseCompactWhenGamingSetting] = toggle.IsOn;
        }

        private static void ApplySoundSettings()
        {
            var s = App.LocalSettings;
            bool sound = s.Values.TryGetValue("SoundEffects", out var sr) && sr is bool sb && sb;
            bool spatial = s.Values.TryGetValue("SpatialAudio", out var spr) && spr is bool spb && spb;

            ElementSoundPlayer.State = sound ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
            if (sound) ElementSoundPlayer.SpatialAudioMode = spatial ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;
        }

        protected override void OnNavigatedFrom(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            if (ProtectionStatusTimer != null)
            {
                ProtectionStatusTimer.Stop();
                ProtectionStatusTimer.Tick -= ProtectionStatusTimer_Tick;
            }
            base.OnNavigatedFrom(e);
        }
    }
}
