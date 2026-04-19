using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;
using System.Threading.Tasks;
using TrustQuarantine;
using Helper;
using static Helper.InterceptWindowHelper;

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private readonly string? _originalFilePath;
        public string? ButtonPressedName { get; private set; }

        public static async Task<string> ShowOrActivate(InterceptWindowSetting interceptWindowSetting)
        {
            var tcs = new TaskCompletionSource<string>();
            var w = new InterceptWindow(interceptWindowSetting);
            w.Closed += (s, e) => tcs.TrySetResult(w.ButtonPressedName ?? "Unknown");
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
            _originalFilePath = setting.path;

            WinUI3Localizer.Localizer.Get().LanguageChanged += (sender, e) =>
            {
                ConfirmButton.Content = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Confirm");
            };
            ProgramNameText.Text = Path.GetFileName(_originalFilePath);
            FilePathText.Text = _originalFilePath;
            DetectionTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            ConfirmButton.Content = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Confirm");
            if (setting.interceptWindowButtonType == InterceptWindowButtonType.RestoreOrTrust)
            {
                ReleaseButton.Visibility = Visibility.Collapsed;
            }
            else
            {
                TrustButton.Visibility = Visibility.Collapsed;
            }
            if (setting.interceptWindowButtonType == InterceptWindowButtonType.ReminderOnly)
            {
                ReleaseButton.Visibility = Visibility.Collapsed;
            }
            PositionWindowAtBottomRight();
            App.PlayEntranceAnimation(RootPanel, "right");
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

        private async void ConfirmButton_Click(object sender, RoutedEventArgs e)
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
