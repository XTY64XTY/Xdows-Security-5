using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Protection;
using System;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class DriverEnvironmentDialog : ContentDialog
    {
        private CancellationTokenSource? _refreshCts;

        public DriverEnvironmentDialog()
        {
            InitializeComponent();
            Title = Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Title");
            CloseButtonText = Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Close");
            RefreshText.Text = Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Refresh");
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

        private async Task RefreshAsync()
        {
            _refreshCts?.Cancel();
            _refreshCts?.Dispose();
            _refreshCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            SetBusy(true, Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Checking"));
            try
            {
                DriverEnvironmentReport report = await DriverEnvironmentChecker.CheckAsync(_refreshCts.Token);
                RenderGroups(report);
                string summaryKey = report.IsHealthy
                    ? "DriverEnvironmentDialog_Summary_Healthy"
                    : "DriverEnvironmentDialog_Summary_NeedsAttention";
                SummaryText.Text = Localizer.Get().GetLocalizedString(summaryKey);
                ShowResult(report.IsHealthy, report.IsHealthy
                    ? Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Summary_Healthy")
                    : Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Summary_NeedsAttention"));
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                SummaryText.Text = Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Summary_Error");
                ShowResult(false, ex.Message);
                LogText.AddNewLog(LogText.LogLevel.ERROR, "DriverEnvironment", ex.Message);
            }
            finally
            {
                SetBusy(false, null);
            }
        }

        private void RenderGroups(DriverEnvironmentReport report)
        {
            GroupsPanel.Children.Clear();
            foreach (DriverEnvironmentCheckGroup group in report.Groups)
            {
                GroupsPanel.Children.Add(CreateGroupCard(group));
            }
        }

        private UIElement CreateGroupCard(DriverEnvironmentCheckGroup group)
        {
            string groupTitleKey = $"DriverEnvironmentDialog_Group_{Capitalize(group.Id)}_Title";
            string groupTitle = Localizer.Get().GetLocalizedString(groupTitleKey);

            var card = new Border
            {
                Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
                BorderBrush = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
                BorderThickness = new Thickness(1),
                CornerRadius = (CornerRadius)Application.Current.Resources["ControlCornerRadius"],
                Padding = new Thickness(12)
            };

            var stack = new StackPanel { Spacing = 8 };

            // Group header row
            var headerPanel = new Grid();
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titlePanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            var statusIcon = new FontIcon
            {
                Glyph = GetStatusGlyph(group.Status),
                FontSize = 16,
                Foreground = GetStatusBrush(group.Status)
            };
            var titleText = new TextBlock
            {
                Text = groupTitle,
                Style = (Style)Application.Current.Resources["SubtitleTextBlockStyle"],
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap
            };
            titlePanel.Children.Add(statusIcon);
            titlePanel.Children.Add(titleText);
            Grid.SetColumn(titlePanel, 0);
            headerPanel.Children.Add(titlePanel);

            var statusText = new TextBlock
            {
                Text = GetLocalizedStatus(group.Status),
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = GetStatusBrush(group.Status),
                Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"]
            };
            Grid.SetColumn(statusText, 1);
            headerPanel.Children.Add(statusText);

            if (group.CanRepair)
            {
                var repairButton = new Button
                {
                    Content = group.PrimaryRepairAction,
                    Tag = group,
                    Margin = new Thickness(8, 0, 0, 0)
                };
                AutomationProperties.SetName(repairButton, groupTitle);
                AutomationProperties.SetAutomationId(repairButton, $"Repair_{group.Id}");
                repairButton.Click += GroupRepairButton_Click;
                Grid.SetColumn(repairButton, 2);
                headerPanel.Children.Add(repairButton);
            }

            stack.Children.Add(headerPanel);

            // Items
            foreach (DriverEnvironmentCheckItem item in group.Items)
            {
                stack.Children.Add(CreateItemRow(item));
            }

            card.Child = stack;
            return card;
        }

        private UIElement CreateItemRow(DriverEnvironmentCheckItem item)
        {
            string itemTitleKey = $"DriverEnvironmentDialog_Item_{item.Id}_Title";
            string itemTitle = Localizer.Get().GetLocalizedString(itemTitleKey);
            if (string.IsNullOrEmpty(itemTitle))
                itemTitle = item.Title;

            var panel = new StackPanel
            {
                Padding = new Thickness(24, 4, 0, 4),
                Spacing = 2
            };

            var titleRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
            var dot = new FontIcon
            {
                Glyph = GetStatusGlyph(item.Status),
                FontSize = 12,
                Foreground = GetStatusBrush(item.Status)
            };
            var title = new TextBlock
            {
                Text = itemTitle,
                Style = (Style)Application.Current.Resources["BodyTextBlockStyle"],
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap
            };
            titleRow.Children.Add(dot);
            titleRow.Children.Add(title);
            panel.Children.Add(titleRow);

            var detail = new TextBlock
            {
                Text = item.Detail,
                Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
                Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(18, 0, 0, 0)
            };
            panel.Children.Add(detail);

            return panel;
        }

        private async void GroupRepairButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: DriverEnvironmentCheckGroup group })
                return;

            string groupTitleKey = $"DriverEnvironmentDialog_Group_{Capitalize(group.Id)}_Title";
            string groupTitle = Localizer.Get().GetLocalizedString(groupTitleKey);
            string repairingFormat = Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Repairing");
            string repairingMsg = string.Format(repairingFormat, groupTitle);

            SetBusy(true, repairingMsg);
            bool anySuccess = false;
            string lastMessage = string.Empty;

            foreach (DriverEnvironmentCheckItem item in group.Items)
            {
                if (!item.CanRepair)
                    continue;

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

                if (result.Success)
                    anySuccess = true;
                lastMessage = result.Message;
            }

            ShowResult(anySuccess, lastMessage);
            await RefreshAsync();
        }

        private static string GetStatusGlyph(DriverEnvironmentCheckStatus status) => status switch
        {
            DriverEnvironmentCheckStatus.Passed => "\uE73E",
            DriverEnvironmentCheckStatus.Warning => "\uE7BA",
            _ => "\uE711"
        };

        private static Brush GetStatusBrush(DriverEnvironmentCheckStatus status) => status switch
        {
            DriverEnvironmentCheckStatus.Passed => (Brush)Application.Current.Resources["SystemFillColorSuccessBrush"],
            DriverEnvironmentCheckStatus.Warning => (Brush)Application.Current.Resources["SystemFillColorCautionBrush"],
            _ => (Brush)Application.Current.Resources["SystemFillColorCriticalBrush"]
        };

        private static string GetLocalizedStatus(DriverEnvironmentCheckStatus status) => status switch
        {
            DriverEnvironmentCheckStatus.Passed => Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Status_Passed"),
            DriverEnvironmentCheckStatus.Warning => Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Status_Warning"),
            _ => Localizer.Get().GetLocalizedString("DriverEnvironmentDialog_Status_Failed")
        };

        private static string Capitalize(string value) =>
            string.IsNullOrEmpty(value) ? value : char.ToUpperInvariant(value[0]) + value[1..];

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
