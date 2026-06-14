using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class DriverProtectionSetupDialog : ContentDialog
    {
        private readonly Func<Task<bool>> _configureAsync;
        private readonly DispatcherQueueTimer _progressTimer;
        private int _targetProgress;
        private bool _completed;

        public DriverProtectionSetupDialog(Func<Task<bool>> configureAsync)
        {
            InitializeComponent();
            _configureAsync = configureAsync;
            Title = Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Setup_Title");
            CloseButtonText = string.Empty;
            IsPrimaryButtonEnabled = false;
            Loaded += DriverProtectionSetupDialog_Loaded;
            Closing += DriverProtectionSetupDialog_Closing;

            _progressTimer = DispatcherQueue.CreateTimer();
            _progressTimer.Interval = TimeSpan.FromMilliseconds(120);
            _progressTimer.Tick += ProgressTimer_Tick;
        }

        public bool SetupSucceeded { get; private set; }

        private async void DriverProtectionSetupDialog_Loaded(object sender, RoutedEventArgs e)
        {
            await RunSetupAsync();
        }

        private void DriverProtectionSetupDialog_Closing(ContentDialog sender, ContentDialogClosingEventArgs args)
        {
            if (!_completed)
                args.Cancel = true;
        }

        private async Task RunSetupAsync()
        {
            _progressTimer.Start();
            try
            {
                SetStage(12, "SettingsPage_Protection_Driver_Setup_Preparing", "SettingsPage_Protection_Driver_Setup_Preparing_Detail");
                await Task.Delay(220);
                SetStage(34, "SettingsPage_Protection_Driver_Setup_Checking", "SettingsPage_Protection_Driver_Setup_Checking_Detail");
                await Task.Delay(220);
                SetStage(58, "SettingsPage_Protection_Driver_Setup_Configuring", "SettingsPage_Protection_Driver_Setup_Configuring_Detail");

                bool success = await _configureAsync();

                SetStage(92, "SettingsPage_Protection_Driver_Setup_Finalizing", "SettingsPage_Protection_Driver_Setup_Finalizing_Detail");
                await Task.Delay(260);
                SetupProgressBar.Value = 100;
                SetupSucceeded = success;
                _completed = true;
                _progressTimer.Stop();

                ResultInfoBar.IsOpen = true;
                ResultInfoBar.Severity = success ? InfoBarSeverity.Success : InfoBarSeverity.Warning;
                ResultInfoBar.Message = Localizer.Get().GetLocalizedString(success
                    ? "SettingsPage_Protection_Driver_Setup_Success"
                    : "SettingsPage_Protection_Driver_Setup_Failed");

                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
                await Task.Delay(success ? 450 : 900);
                Hide();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "DriverProtection", ex.Message);
                SetupSucceeded = false;
                _completed = true;
                _progressTimer.Stop();
                ResultInfoBar.IsOpen = true;
                ResultInfoBar.Severity = InfoBarSeverity.Error;
                ResultInfoBar.Message = ex.Message;
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
            }
        }

        private void SetStage(int targetProgress, string messageKey, string detailKey)
        {
            _targetProgress = Math.Clamp(targetProgress, 0, 100);
            MessageText.Text = Localizer.Get().GetLocalizedString(messageKey);
            DetailText.Text = Localizer.Get().GetLocalizedString(detailKey);
        }

        private void ProgressTimer_Tick(DispatcherQueueTimer sender, object args)
        {
            if (SetupProgressBar.Value < _targetProgress)
                SetupProgressBar.Value = Math.Min(_targetProgress, SetupProgressBar.Value + 2);
        }
    }
}
