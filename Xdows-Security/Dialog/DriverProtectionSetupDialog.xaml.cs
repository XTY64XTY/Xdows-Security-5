using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Protection;
using System;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security
{
    /// <summary>
    /// 驱动防护启用进度。七个步骤与 <see cref="DriverLoadStage"/> 一一对应，
    /// 由驱动启动流程实时上报，不再用定时器假装进度。
    /// </summary>
    public sealed partial class DriverProtectionSetupDialog : ContentDialog
    {
        private enum StepState
        {
            Pending,
            Active,
            Done,
            Failed
        }

        private const string PendingGlyph = "\uE91F";
        private const string ActiveGlyph = "\uE895";
        private const string DoneGlyph = "\uE73E";
        private const string FailedGlyph = "\uE711";

        // 每阶段点亮时进度条的目标值，最后一步完成才到 100。
        private static readonly int[] StageProgress = [10, 26, 38, 55, 72, 86, 96];

        private readonly Func<Action<DriverLoadProgress>, Task<bool>> _configureAsync;
        private readonly DispatcherQueueTimer _progressTimer;
        private readonly (FontIcon Icon, TextBlock Title)[] _steps;
        private int _targetProgress;
        private string? _failureMessage;
        private bool _completed;

        public DriverProtectionSetupDialog(Func<Action<DriverLoadProgress>, Task<bool>> configureAsync)
        {
            InitializeComponent();
            _configureAsync = configureAsync;
            Title = Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Setup_Title");
            CloseButtonText = string.Empty;
            IsPrimaryButtonEnabled = false;
            Loaded += DriverProtectionSetupDialog_Loaded;
            Closing += DriverProtectionSetupDialog_Closing;

            _steps =
            [
                (StepPreparingIcon, StepPreparingText),
                (StepInstallingIcon, StepInstallingText),
                (StepSnapshotIcon, StepSnapshotText),
                (StepConnectingIcon, StepConnectingText),
                (StepConfiguringIcon, StepConfiguringText),
                (StepStartupIcon, StepStartupText),
                (StepMonitoringIcon, StepMonitoringText)
            ];

            LocalizeStep(StepPreparingText, StepPreparingDetail, "Preparing");
            LocalizeStep(StepInstallingText, StepInstallingDetail, "Installing");
            LocalizeStep(StepSnapshotText, StepSnapshotDetail, "Snapshot");
            LocalizeStep(StepConnectingText, StepConnectingDetail, "Connecting");
            LocalizeStep(StepConfiguringText, StepConfiguringDetail, "Configuring");
            LocalizeStep(StepStartupText, StepStartupDetail, "Startup");
            LocalizeStep(StepMonitoringText, StepMonitoringDetail, "Monitoring");

            for (int i = 0; i < _steps.Length; i++)
                SetStepState(i, StepState.Pending);

            _progressTimer = DispatcherQueue.CreateTimer();
            _progressTimer.Interval = TimeSpan.FromMilliseconds(120);
            _progressTimer.Tick += ProgressTimer_Tick;
        }

        public bool SetupSucceeded { get; private set; }

        private static void LocalizeStep(TextBlock title, TextBlock detail, string stage)
        {
            title.Text = Localizer.Get().GetLocalizedString($"SettingsPage_Protection_Driver_Setup_Stage_{stage}");
            detail.Text = Localizer.Get().GetLocalizedString($"SettingsPage_Protection_Driver_Setup_Stage_{stage}_Detail");
        }

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
                bool success = await _configureAsync(ReportProgress);

                if (success)
                {
                    for (int i = 0; i < _steps.Length; i++)
                        SetStepState(i, StepState.Done);

                    SetupProgressBar.Value = 100;
                }

                SetupSucceeded = success;
                _completed = true;
                _progressTimer.Stop();

                ResultInfoBar.IsOpen = true;
                ResultInfoBar.Severity = success ? InfoBarSeverity.Success : InfoBarSeverity.Warning;
                ResultInfoBar.Message = success
                    ? Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Setup_Success")
                    : _failureMessage ?? Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Setup_Failed");

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

        /// <summary>进度来自驱动启动线程，切回 UI 线程再改控件。</summary>
        private void ReportProgress(DriverLoadProgress progress)
        {
            if (DispatcherQueue is null)
                return;

            DispatcherQueue.TryEnqueue(() => ApplyProgress(progress));
        }

        private void ApplyProgress(DriverLoadProgress progress)
        {
            int index = (int)progress.Stage;
            if (index < 0 || index >= _steps.Length)
                return;

            switch (progress.Status)
            {
                case DriverLoadStageStatus.Started:
                    for (int i = 0; i < index; i++)
                        SetStepState(i, StepState.Done);

                    SetStepState(index, StepState.Active);
                    _targetProgress = StageProgress[index];
                    break;

                case DriverLoadStageStatus.Completed:
                    SetStepState(index, StepState.Done);
                    break;

                case DriverLoadStageStatus.Failed:
                    SetStepState(index, StepState.Failed);
                    _failureMessage = progress.Message;
                    break;
            }
        }

        private void SetStepState(int index, StepState state)
        {
            (FontIcon icon, TextBlock title) = _steps[index];

            icon.Glyph = state switch
            {
                StepState.Active => ActiveGlyph,
                StepState.Done => DoneGlyph,
                StepState.Failed => FailedGlyph,
                _ => PendingGlyph
            };

            icon.Foreground = (Brush)Application.Current.Resources[state switch
            {
                StepState.Active => "AccentTextFillColorPrimaryBrush",
                StepState.Done => "SystemFillColorSuccessBrush",
                StepState.Failed => "SystemFillColorCriticalBrush",
                _ => "TextFillColorTertiaryBrush"
            }];

            title.Foreground = (Brush)Application.Current.Resources[
                state == StepState.Pending ? "TextFillColorTertiaryBrush" : "TextFillColorPrimaryBrush"];
        }

        private void ProgressTimer_Tick(DispatcherQueueTimer sender, object args)
        {
            if (SetupProgressBar.Value < _targetProgress)
                SetupProgressBar.Value = Math.Min(_targetProgress, SetupProgressBar.Value + 2);
        }
    }
}
