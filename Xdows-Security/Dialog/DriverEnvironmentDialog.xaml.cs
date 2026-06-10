using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Protection;
using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class DriverEnvironmentDialog : ContentDialog
    {
        private readonly ObservableCollection<DriverEnvironmentCheckItem> _items = [];
        private CancellationTokenSource? _refreshCts;

        public DriverEnvironmentDialog()
        {
            InitializeComponent();
            Title = Localizer.Get().GetLocalizedString("SettingsPage_Protection_Driver_Dialog_Title");
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
            ChecksListView.ItemsSource = _items;
            Loaded += DriverEnvironmentDialog_Loaded;
            Closed += DriverEnvironmentDialog_Closed;
        }

        private async void DriverEnvironmentDialog_Loaded(object sender, RoutedEventArgs e)
        {
            await RefreshAsync();
        }

        private void DriverEnvironmentDialog_Closed(ContentDialog sender, ContentDialogClosedEventArgs args)
        {
            _refreshCts?.Cancel();
            _refreshCts?.Dispose();
            _refreshCts = null;
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshAsync();
        }

        private async void RepairButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { DataContext: DriverEnvironmentCheckItem item })
                return;

            SetBusy(true, $"Repairing {item.Title}...");
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

            ShowResult(result.Success, result.Message);
            await RefreshAsync();
        }

        private async Task RefreshAsync()
        {
            _refreshCts?.Cancel();
            _refreshCts?.Dispose();
            _refreshCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            SetBusy(true, "Checking driver protection environment...");
            try
            {
                DriverEnvironmentReport report = await DriverEnvironmentChecker.CheckAsync(_refreshCts.Token);
                _items.Clear();
                foreach (DriverEnvironmentCheckItem item in report.Items)
                {
                    _items.Add(item);
                    LogText.AddNewLog(
                        item.Passed ? LogText.LogLevel.INFO : LogText.LogLevel.WARN,
                        "DriverEnvironment",
                        $"{item.Id}: {item.StatusText} - {item.Detail}");
                }

                SummaryText.Text = report.IsHealthy
                    ? "Driver protection environment is ready."
                    : "Driver protection needs attention. Use the repair actions below, or keep compatibility protection enabled until the driver is healthy.";

                ShowResult(report.IsHealthy, report.IsHealthy ? "Environment check passed." : "Environment check found items to repair.");
            }
            catch (Exception ex)
            {
                SummaryText.Text = "Unable to complete the driver environment check. Keep compatibility protection enabled and inspect the logs.";
                ShowResult(false, ex.Message);
                LogText.AddNewLog(LogText.LogLevel.ERROR, "DriverEnvironment", ex.Message);
            }
            finally
            {
                SetBusy(false, null);
            }
        }

        private void SetBusy(bool busy, string? message)
        {
            RefreshButton.IsEnabled = !busy;
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
}
