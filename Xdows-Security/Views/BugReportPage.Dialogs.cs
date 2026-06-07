using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class BugReportPage
    {
        private async void ReconnectBtn_Click(Object sender, RoutedEventArgs e)
        {
            _isAutoRefresh = false;
            await InitializeTCPClientAsync();
        }

        private async void SettingsBtn_Click(Object sender, RoutedEventArgs e)
        {
            ContentDialog dialog = new()
            {
                Title = L("BugReportPage_SettingsDialog_Title"),
                CloseButtonText = L("Button_Cancel"),
                PrimaryButtonText = L("Button_Confirm"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = XamlRoot
            };

            StackPanel stackPanel = new()
            {
                Spacing = 12
            };

            TextBox usernameBox = CreateDialogTextBox("BugReportUsernameBox", _tcpClient?.Username ?? "");
            TextBox hostBox = CreateDialogTextBox("BugReportHostBox", _tcpClient?.ServerHost ?? "");
            TextBox portBox = CreateDialogTextBox("BugReportPortBox", _tcpClient?.ServerPort.ToString() ?? "");

            stackPanel.Children.Add(CreateDialogField("BugReportPage_UsernameLabel", usernameBox));
            stackPanel.Children.Add(CreateDialogField("BugReportPage_HostLabel", hostBox));
            stackPanel.Children.Add(CreateDialogField("BugReportPage_PortLabel", portBox));

            dialog.Content = stackPanel;
            dialog.PrimaryButtonClick += async (_, args) =>
            {
                if (!Int32.TryParse(portBox.Text, out Int32 port))
                {
                    AddSystemMessage(LF("BugReportPage_SettingSaveFailed", L("BugReportPage_PortInvalid")));
                    args.Cancel = true;
                    return;
                }

                try
                {
                    await SaveFeedbackSettingsAsync(usernameBox.Text, hostBox.Text, port);
                }
                catch (Exception ex)
                {
                    AddSystemMessage(LF("BugReportPage_SettingSaveFailed", ex.Message));
                    args.Cancel = true;
                }
            };

            await dialog.ShowAsync();
        }

        private async Task SaveFeedbackSettingsAsync(String username, String host, Int32 port)
        {
            await _clientGate.WaitAsync();

            try
            {
                FeedbackTCPClient client;
                if (_tcpClient == null)
                {
                    client = new FeedbackTCPClient();
                    Int32 generation = ++_clientGeneration;
                    _tcpClient = client;
                    AttachClientEvents(client, generation);
                }
                else
                {
                    client = _tcpClient;
                }

                if (client.IsConnected)
                {
                    await client.DisconnectAsync();
                }

                await client.SetUsernameAsync(username);
                await client.SetServerAsync(host, port);

                AddSystemMessage(L("BugReportPage_SettingSaved"));
                Boolean connected = await client.ConnectAsync();
                if (!connected)
                {
                    SetConnectionStatus("BugReportPage_ConnectionFailed");
                }
            }
            finally
            {
                _clientGate.Release();
            }
        }

        private static StackPanel CreateDialogField(String labelResourceKey, TextBox textBox)
        {
            StackPanel panel = new()
            {
                Spacing = 4
            };

            panel.Children.Add(new TextBlock
            {
                Text = L(labelResourceKey),
                Style = ResourceStyle("BodyStrongTextBlockStyle")
            });
            panel.Children.Add(textBox);

            return panel;
        }

        private static TextBox CreateDialogTextBox(String automationId, String text)
        {
            TextBox textBox = new()
            {
                Text = text,
                MinWidth = 320
            };

            AutomationProperties.SetAutomationId(textBox, automationId);
            return textBox;
        }
    }
}
