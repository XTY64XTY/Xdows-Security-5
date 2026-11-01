using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Protection;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    /// <summary>
    /// 驱动环境检测页。四项检查：管理员权限、测试模式、文件完整性、驱动是否正常启动。
    /// 只有测试模式可以自动修复，其余不满足项统一给出「重装或改用兼容防护」的提示。
    /// </summary>
    public sealed partial class DriverEnvironmentPage : Page
    {
        private CancellationTokenSource? _checkCts;

        public DriverEnvironmentPage()
        {
            InitializeComponent();
            RecheckButton.Content = Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Recheck");
            Loaded += DriverEnvironmentPage_Loaded;
            Unloaded += DriverEnvironmentPage_Unloaded;
        }

        private async void DriverEnvironmentPage_Loaded(object sender, RoutedEventArgs e)
        {
            await RefreshAsync();
        }

        private void DriverEnvironmentPage_Unloaded(object sender, RoutedEventArgs e)
        {
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            _checkCts = null;
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshAsync();
        }

        private async Task RefreshAsync()
        {
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            _checkCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            SetBusy(true, Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Checking"));
            try
            {
                DriverEnvironmentReport report = await DriverEnvironmentChecker.CheckAsync(_checkCts.Token);
                LogReport(report);
                Render(report);
                ShowResult(report.IsHealthy, SummaryBar.Title);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                CheckItems.ItemsSource = null;
                ApplySummary(
                    InfoBarSeverity.Error,
                    Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Headline_Blocked"),
                    ex.Message);
                ShowResult(false, ex.Message);
                LogText.AddNewLog(LogText.LogLevel.ERROR, "DriverEnvironment", ex.Message);
            }
            finally
            {
                SetBusy(false, null);
            }
        }

        /// <summary>
        /// 每次检测都留一条记录，便于事后对时间线：通过记 INFO，未通过记 WARN 并带上失败项与技术细节。
        /// </summary>
        private static void LogReport(DriverEnvironmentReport report)
        {
            if (report.IsHealthy)
            {
                LogText.AddNewLog(
                    LogText.LogLevel.INFO,
                    "DriverEnvironment",
                    $"Environment check passed: {report.Items.Count}/{report.Items.Count}.");
                return;
            }

            string failed = string.Join("; ", report.Items
                .Where(i => !i.Passed)
                .Select(i => $"{i.Id}=Failed ({i.Diagnostic ?? "no detail"})"));

            LogText.AddNewLog(
                LogText.LogLevel.WARN,
                "DriverEnvironment",
                $"Environment check: {report.FailedCount}/{report.Items.Count} not passed. {failed}");
        }

        private void Render(DriverEnvironmentReport report)
        {
            CheckItems.ItemsSource = report.Items.Select(CreateItemView).ToList();

            if (report.IsHealthy)
            {
                ApplySummary(
                    InfoBarSeverity.Success,
                    Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Headline_Ready"),
                    Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Summary_Ready"));
                return;
            }

            ApplySummary(
                InfoBarSeverity.Error,
                Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Headline_Blocked"),
                string.Format(
                    Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Summary_Blocked"),
                    report.FailedCount));
        }

        private void ApplySummary(InfoBarSeverity severity, string title, string detail)
        {
            SummaryBar.Severity = severity;
            SummaryBar.Title = title;
            SummaryBar.Message = detail;
        }

        private static DriverEnvironmentItemView CreateItemView(DriverEnvironmentCheckItem item)
        {
            string message;
            if (item.Passed)
            {
                message = Localizer.Get().GetLocalizedString($"DriverEnvironmentPage_Ok_{item.Id}");
            }
            else if (item.Id == DriverEnvironmentCheckId.TestSigning)
            {
                message = Localizer.Get().GetLocalizedString(
                    item.Hint == DriverEnvironmentCheckHint.TestSigningPendingRestart
                        ? "DriverEnvironmentPage_Fail_TestSigningPendingRestart"
                        : "DriverEnvironmentPage_Fail_TestSigning");
            }
            else if (item.Hint == DriverEnvironmentCheckHint.DriverNotStarted)
            {
                // 驱动只是没启动，能让用户自己解决，不该给“重装”这种结论。
                message = Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Fail_DriverNotStarted");
            }
            else
            {
                // 其余不满足项都不可修复，统一给一句结论，不把技术细节铺在正文里。
                message = Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Fail_Unrepairable");
            }

            string repairText = item.CanRepair && !item.Passed
                ? Localizer.Get().GetLocalizedString(
                    item.Hint == DriverEnvironmentCheckHint.TestSigningPendingRestart
                        ? "DriverEnvironmentPage_Repair_DisableTestSigning"
                        : "DriverEnvironmentPage_Repair_TestSigning")
                : string.Empty;

            string diagnostic = item.Diagnostic ?? string.Empty;

            return new DriverEnvironmentItemView
            {
                Title = Localizer.Get().GetLocalizedString($"DriverEnvironmentPage_Check_{item.Id}"),
                StatusText = Localizer.Get().GetLocalizedString(item.Passed
                    ? "DriverEnvironmentPage_Status_Passed"
                    : "DriverEnvironmentPage_Status_Failed"),
                StatusBrush = GetStatusBrush(item.Passed),
                Glyph = item.Passed ? "\uE73E" : "\uE711",
                Message = message,
                Diagnostic = diagnostic,
                RepairText = repairText,
                RepairVisibility = repairText.Length > 0 ? Visibility.Visible : Visibility.Collapsed,
                DetailVisibility = diagnostic.Length > 0 ? Visibility.Visible : Visibility.Collapsed,
                Source = item
            };
        }

        private async void ItemRepairButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: DriverEnvironmentCheckItem item })
                return;

            bool undoing = item.Id == DriverEnvironmentCheckId.TestSigning &&
                item.Hint == DriverEnvironmentCheckHint.TestSigningPendingRestart;

            // 开启测试模式会放宽内核代码完整性校验，必须先让用户明确确认；撤销是恢复安全状态，不需要。
            if (item.Id == DriverEnvironmentCheckId.TestSigning && !undoing &&
                !await ConfirmEnableTestSigningAsync())
            {
                return;
            }

            SetBusy(true, Localizer.Get().GetLocalizedString("DriverEnvironmentPage_Repairing"));

            DriverRepairResult result;
            try
            {
                result = await DriverInstaller.RepairAsync(item);
            }
            catch (Exception ex)
            {
                result = new DriverRepairResult(false, ex.Message);
            }

            LogText.AddNewLog(
                result.Success ? LogText.LogLevel.INFO : LogText.LogLevel.WARN,
                "DriverEnvironment",
                $"Repair {item.Id}: {result.Message}");

            await RefreshAsync();

            // 同一个按钮在“待重启”状态下是撤销，提示语也跟着换。
            ShowResult(
                result.Success,
                result.Success
                    ? Localizer.Get().GetLocalizedString(undoing
                        ? "DriverEnvironmentPage_RepairUndone"
                        : "DriverEnvironmentPage_RepairDone")
                    : result.Message);
        }

        /// <summary>
        /// 开启测试模式前的安全性警告与免责声明。用户不确认就不改 BCD。
        /// </summary>
        private async Task<bool> ConfirmEnableTestSigningAsync()
        {
            try
            {
                ContentDialogResult result = await new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("DriverEnvironmentPage_TestSigning_Warning_Title"),
                    Content = Localizer.Get().GetLocalizedString("DriverEnvironmentPage_TestSigning_Warning_Text"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    DefaultButton = ContentDialogButton.Close,
                    // 不显式指定样式时这里的弹出动画会缺失，必须用默认对话框样式。
                    Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                }.ShowAsync();

                return result == ContentDialogResult.Primary;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "DriverEnvironment", ex.Message);
                return false;
            }
        }

        private static Brush GetStatusBrush(bool passed) => (Brush)Application.Current.Resources[
            passed ? "SystemFillColorSuccessBrush" : "SystemFillColorCriticalBrush"];

        private void SetBusy(bool busy, string? message)
        {
            RecheckButton.IsEnabled = !busy;
            if (!string.IsNullOrWhiteSpace(message))
            {
                ResultInfoBar.IsOpen = true;
                ResultInfoBar.Severity = InfoBarSeverity.Informational;
                ResultInfoBar.Message = message;
            }
        }

        private void ShowResult(bool success, string message)
        {
            ResultInfoBar.IsOpen = true;
            ResultInfoBar.Severity = success ? InfoBarSeverity.Success : InfoBarSeverity.Warning;
            ResultInfoBar.Message = message;
        }
    }

    /// <summary>一项检查的显示数据。<see cref="Source"/> 回指原始结果，供修复按钮使用。</summary>
    public sealed class DriverEnvironmentItemView
    {
        public string Title { get; init; } = string.Empty;
        public string StatusText { get; init; } = string.Empty;
        public Brush StatusBrush { get; init; } = null!;
        public string Glyph { get; init; } = string.Empty;
        public string Message { get; init; } = string.Empty;
        public string Diagnostic { get; init; } = string.Empty;
        public string RepairText { get; init; } = string.Empty;
        public Visibility RepairVisibility { get; init; }
        public Visibility DetailVisibility { get; init; }
        public DriverEnvironmentCheckItem? Source { get; init; }
    }
}
