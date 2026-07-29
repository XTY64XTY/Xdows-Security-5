using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using TrustQuarantine;
using Helper;
using WinUI3Localizer;
using static Helper.InterceptWindowHelper;

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private readonly string? _originalFilePath;
        private readonly Helper.ProtectionModule _protectionModule;
        private readonly Helper.ProtectionBackend _protectionBackend;
        private readonly DateTimeOffset? _decisionDeadline;
        private DispatcherTimer? _decisionTimer;
        private bool _decisionTimeoutHandled;
        public string? ButtonPressedName { get; private set; }

        public static async Task<string> ShowOrActivate(
            InterceptWindowSetting interceptWindowSetting,
            CancellationToken cancellationToken = default)
        {
            if (cancellationToken.IsCancellationRequested)
                return "Timeout";

            var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var w = new InterceptWindow(interceptWindowSetting);
            w.Closed += (s, e) => tcs.TrySetResult(w.ButtonPressedName ?? "Unknown");
            using CancellationTokenRegistration registration = cancellationToken.Register(() =>
            {
                if (!w.DispatcherQueue.TryEnqueue(w.HandleDecisionTimeout))
                    tcs.TrySetResult("Timeout");
            });

            if (!tcs.Task.IsCompleted)
                w.Activate();

            return await tcs.Task;
        }

        private InterceptWindow(InterceptWindowSetting setting)
        {
            this.InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 350;
            manager.MinHeight = 330;
            manager.Width = 400;
            manager.Height = 486;
            manager.IsMaximizable = false;
            manager.IsMinimizable = true;
            manager.IsResizable = false;
            manager.IsTitleBarVisible = false;
            manager.IsAlwaysOnTop = true;
            this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();
            _originalFilePath = setting.Path;
            _protectionModule = setting.Module;
            _protectionBackend = setting.Backend;
            _decisionDeadline = setting.DecisionDeadline;

            RootPanel.Loaded += (_, _) =>
            {
                // Wait for layout to settle, then measure and resize
                DispatcherQueue.TryEnqueue(() =>
                {
                    UpdateWindowHeightAndPosition();
                });
            };

            WinUI3Localizer.Localizer.Get().LanguageChanged += OnLanguageChanged;
            Closed += InterceptWindow_Closed;
            ProgramNameText.Text = Path.GetFileName(_originalFilePath);
            FilePathText.Text = _originalFilePath;
            DetectionTimeText.Text = DateTime.Now.ToString("G", CultureInfo.CurrentCulture);
            ThreatTypeText.Text = NormalizeDetectionName(setting.DetectionName);
            ProtectionModuleText.Text = FormatProtectionModule(_protectionModule, _protectionBackend);
            UpdateConfirmButtonContent();
            if (setting.InterceptWindowButtonType == InterceptWindowButtonType.RestoreOrTrust)
            {
                ReleaseButton.Visibility = Visibility.Collapsed;
            }
            else
            {
                TrustButton.Visibility = Visibility.Collapsed;
            }
            if (setting.InterceptWindowButtonType == InterceptWindowButtonType.ReminderOnly)
            {
                ReleaseButton.Visibility = Visibility.Collapsed;
            }
            if (setting.InterceptWindowButtonType == InterceptWindowButtonType.InterceptOrRelease &&
                _decisionDeadline.HasValue)
            {
                _decisionTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(250)
                };
                _decisionTimer.Tick += DecisionTimer_Tick;
                _decisionTimer.Start();
            }
            PositionWindowAtBottomRight();
            App.PlayEntranceAnimation(RootPanel, "right");
        }

        private void OnLanguageChanged(object? sender, LanguageChangedEventArgs e)
        {
            UpdateConfirmButtonContent();
            ProtectionModuleText.Text = FormatProtectionModule(_protectionModule, _protectionBackend);
            DispatcherQueue.TryEnqueue(UpdateWindowHeightAndPosition);
        }

        private void InterceptWindow_Closed(object sender, WindowEventArgs args)
        {
            _decisionTimer?.Stop();
            if (_decisionTimer is not null)
                _decisionTimer.Tick -= DecisionTimer_Tick;
            WinUI3Localizer.Localizer.Get().LanguageChanged -= OnLanguageChanged;
            Closed -= InterceptWindow_Closed;
        }

        private void DecisionTimer_Tick(object? sender, object e)
        {
            UpdateConfirmButtonContent();
        }

        private void UpdateConfirmButtonContent()
        {
            if (!_decisionDeadline.HasValue)
            {
                ConfirmButton.Content = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Confirm");
                return;
            }

            TimeSpan remaining = _decisionDeadline.Value - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                _ = DispatcherQueue.TryEnqueue(HandleDecisionTimeout);
                return;
            }

            int remainingSeconds = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
            string format = WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_ConfirmCountdown");
            ConfirmButton.Content = string.Format(CultureInfo.CurrentCulture, format, remainingSeconds);
        }

        private void HandleDecisionTimeout()
        {
            if (_decisionTimeoutHandled || ButtonPressedName is not null)
                return;

            _decisionTimeoutHandled = true;
            ButtonPressedName = "Timeout";
            _decisionTimer?.Stop();
            try
            {
                Close();
            }
            catch
            {
            }
        }

        private static string NormalizeDetectionName(string? detectionName)
        {
            string normalized = string.IsNullOrWhiteSpace(detectionName)
                ? "Xdows.Model.Threat"
                : detectionName.Replace("Xdows.Model.Native.", "Xdows.Model.", StringComparison.Ordinal);
            return normalized.Replace(".", ".\u200B", StringComparison.Ordinal);
        }

        private static string FormatProtectionModule(
            Helper.ProtectionModule module,
            Helper.ProtectionBackend backend)
        {
            var localizer = WinUI3Localizer.Localizer.Get();
            string moduleKey = module switch
            {
                Helper.ProtectionModule.Process => "InterceptWindow_Module_Process",
                Helper.ProtectionModule.File => "InterceptWindow_Module_File",
                Helper.ProtectionModule.Injection => "InterceptWindow_Module_Injection",
                Helper.ProtectionModule.Behavior => "InterceptWindow_Module_Behavior",
                Helper.ProtectionModule.Boot => "InterceptWindow_Module_Boot",
                Helper.ProtectionModule.Registry => "InterceptWindow_Module_Registry",
                Helper.ProtectionModule.SelfProtection => "InterceptWindow_Module_SelfProtection",
                _ => "InterceptWindow_Module_Unknown"
            };
            string backendKey = backend == Helper.ProtectionBackend.Driver
                ? "InterceptWindow_Backend_Driver"
                : "InterceptWindow_Backend_Compatibility";
            string format = localizer.GetLocalizedString("InterceptWindow_ProtectionModule_Format");
            return string.Format(CultureInfo.CurrentCulture, format, localizer.GetLocalizedString(moduleKey), localizer.GetLocalizedString(backendKey));
        }

        private void UpdateWindowHeightAndPosition()
        {
            try
            {
                var manager = WinUIEx.WindowManager.Get(this);
                var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
                if (displayArea == null)
                {
                    return;
                }

                var workArea = displayArea.WorkArea;

                double desiredHeight = RootPanel.ActualHeight;
                double minHeight = manager.MinHeight;

                // Keep a small margin so we never touch screen edges
                double maxHeight = Math.Max(minHeight, workArea.Height - 16);
                double newHeight = Math.Clamp(desiredHeight, minHeight, maxHeight);

                int newHeightInt = (int)Math.Ceiling(newHeight);
                if (manager.Height != newHeightInt)
                {
                    manager.Height = newHeightInt;
                }

                PositionWindowAtBottomRight();
            }
            catch
            {
                // Intentionally ignored: sizing/positioning should never crash the app
            }
        }

        private void PositionWindowAtBottomRight()
        {
            try
            {
                var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
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
        private async void RestoreTrustButton_Click(object sender, SplitButtonClickEventArgs e)
        {
            ButtonPressedName = "RestoreTrust";
            await AddToTrust();
        }

        private async void TrustOnlyMenuItem_Click(object sender, RoutedEventArgs e)
        {
            ButtonPressedName = "TrustOnly";
            await TrustOnly();
        }

        private async void RestoreOnlyMenuItem_Click(object sender, RoutedEventArgs e)
        {
            ButtonPressedName = "RestoreOnly";
            await RestoreOnly();
        }

        private void ConfirmButton_Click(object sender, RoutedEventArgs e)
        {
            ButtonPressedName = "Confirm";
            this.Close();
        }

        private void ReleaseButton_Click(object sender, RoutedEventArgs e)
        {
            ButtonPressedName = "Release";
            this.Close();
        }

        private async Task TrustOnly()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_originalFilePath))
                {
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                    );
                    return;
                }

                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var qi = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (qi != null)
                {
                    bool added = await TrustManager.AddToTrustByHash(_originalFilePath, qi.FileHash);
                    if (added)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Title"),
                            string.Format(
                                WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Body"),
                                _originalFilePath
                            )
                        );
                        this.Close();
                        return;
                    }
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                    );
                    return;
                }

                if (File.Exists(_originalFilePath))
                {
                    bool success = await TrustManager.AddToTrust(_originalFilePath);
                    if (success)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Title"),
                            string.Format(
                                WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Body"),
                                _originalFilePath
                            )
                        );
                        this.Close();
                        return;
                    }
                }

                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                );
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                );
                LogText.AddNewLog(LogText.LogLevel.ERROR, "InterceptWindow - TrustOnly - Failed", ex.ToString());
            }
        }

        private async Task RestoreOnly()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_originalFilePath))
                {
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Body")
                    );
                    return;
                }

                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var qi = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (qi != null)
                {
                    bool restored = await QuarantineManager.RestoreFile(qi.FileHash);
                    if (restored)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Restored_Title"),
                            string.Format(
                                WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Restored_Body"),
                                _originalFilePath
                            )
                        );
                        this.Close();
                        return;
                    }
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Body")
                    );
                    return;
                }

                if (File.Exists(_originalFilePath))
                {
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Exists_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Exists_Body")
                    );
                    return;
                }

                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Body")
                );
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_RestoreFailed_Body")
                );
                LogText.AddNewLog(LogText.LogLevel.ERROR, "InterceptWindow - RestoreOnly - Failed", ex.ToString());
            }
        }

        private async Task AddToTrust()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_originalFilePath))
                {
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                    );
                    return;
                }
                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var qi = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (qi != null)
                {
                    bool added = await TrustManager.AddToTrustByHash(_originalFilePath, qi.FileHash);
                    if (!added)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                        );
                        return;
                    }
                    bool restored = await QuarantineManager.RestoreFile(qi.FileHash);
                    if (restored)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Title"),
                            string.Format(
                                WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Body"),
                                _originalFilePath
                            )
                        );
                        this.Close();
                        return;
                    }
                    await TrustManager.RemoveFromTrust(_originalFilePath);
                    await ShowMessageDialog(
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                        WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                    );
                    return;
                }

                if (File.Exists(_originalFilePath))
                {
                    bool success = await TrustManager.AddToTrust(_originalFilePath);
                    if (success)
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Title"),
                            string.Format(
                                WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_Trusted_Body"),
                                _originalFilePath
                            )
                        );
                        this.Close();
                        return;
                    }
                    else
                    {
                        await ShowMessageDialog(
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                            WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                        );
                        return;
                    }
                }

                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                );
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Title"),
                    WinUI3Localizer.Localizer.Get().GetLocalizedString("InterceptWindow_Message_TrustFailed_Body")
                );
                LogText.AddNewLog(LogText.LogLevel.ERROR, "InterceptWindow - AddToTrust - Failed", ex.ToString());
            }
        }
        private async Task ShowMessageDialog(string title, string message)
        {
            ContentDialog dialog = new()
            {
                Title = title,
                Content = message,
                PrimaryButtonText = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Confirm"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}
