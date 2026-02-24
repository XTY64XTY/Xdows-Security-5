using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.System;

namespace Xdows_Security.Views
{
    public sealed partial class BugReportPage : Page
    {
        private FeedbackTCPClient? _tcpClient;
        private readonly Dictionary<String, String> _userAvatars = [];
        private String _currentUsername = "";
        private DispatcherTimer? _refreshTimer;
        private Boolean _isAutoRefresh = false;
        private DateTime _lastServerMessageTime = DateTime.Now;
        private readonly Queue<String> _pendingMessages = new();

        public BugReportPage()
        {
            InitializeComponent();

            try
            {
                StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_NotConnected");
            }
            catch { }

            Loaded += async (_, __) =>
            {
                try
                {
                    await InitializeTCPClientAsync();
                    InitializeRefreshTimer();
                }
                catch (Exception ex)
                {
                    AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_FailedInit"), ex.Message));
                }
            };
            Unloaded += (_, __) => Cleanup();
        }

        #region TCP客户端
        private async Task InitializeTCPClientAsync()
        {
            Cleanup();
            _tcpClient = new FeedbackTCPClient();

            // 使用系统账户名作为用户名
            String systemUsername = Environment.UserName;
            if (_tcpClient != null && (String.IsNullOrEmpty(_tcpClient.Username) || _tcpClient.Username != systemUsername))
            {
                try
                {
                    await _tcpClient.SetUsernameAsync(systemUsername);
                }
                catch (Exception ex)
                {
                    AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_SetUsernameFailed"), ex.Message));
                    StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_NotConnected");
                    return;
                }
            }

            // 订阅事件
            if (_tcpClient != null)
            {
                _tcpClient.OnConnected += (sender, message) =>
                {
                    // 自动刷新时不显示连接状态
                };

                _tcpClient.OnDisconnected += (sender, message) =>
                {
                    // 自动刷新时不显示断开连接状态
                };

                _tcpClient.OnMessageReceived += async (sender, messageDict) =>
                {
                    await HandleReceivedMessageAsync(messageDict);
                };

                _tcpClient.OnError += async (sender, error) =>
                {
                    if (!_isAutoRefresh)
                    {
                        if (error.Contains("解码消息异常"))
                        {
                            return;
                        }

                        if (error.Contains("线程退出") || error.Contains("应用程序请求") || error.Contains("已中止 I/O 操作"))
                        {
                            return;
                        }

                        if (error.Contains("未连接到服务器，重连失败"))
                        {
                            DispatcherQueue.TryEnqueue(() =>
                            {
                                AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_Reconnecting"));
                            });
                            return;
                        }

                        DispatcherQueue.TryEnqueue(() =>
                        {
                            StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ConnectionFailed");
                            AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ConnectionFailedMessage") + error);
                        });

                        if (error.Contains("连接") || error.Contains("断开"))
                        {
                            await Task.Delay(600);
                        }
                    }
                };
            }

            if (_tcpClient != null)
            {
                await _tcpClient.ConnectAsync();
            }
        }

        private async Task HandleReceivedMessageAsync(Dictionary<String, Object> messageDict)
        {
            try
            {
                if (messageDict == null)
                {
                    return;
                }

                if (!messageDict.TryGetValue("type", out Object? typeObj))
                {
                    return;
                }

                String type = typeObj?.ToString() ?? "";
                if (String.IsNullOrEmpty(type))
                {
                    return;
                }

                // 更新最后收到服务器消息的时间
                _lastServerMessageTime = DateTime.Now;

                DispatcherQueue.TryEnqueue(() =>
                {
                    switch (type)
                    {
                        case "register_success":
                            HandleRegisterSuccess(messageDict);
                            break;

                        case "new_message":
                            HandleNewMessage(messageDict);
                            break;

                        case "user_online":
                            HandleUserOnline(messageDict);
                            break;

                        case "user_offline":
                            HandleUserOffline(messageDict);
                            break;

                        case "read_status_update":
                            HandleReadStatusUpdate(messageDict);
                            break;

                        case "system_message":
                            HandleSystemMessage(messageDict);
                            break;

                        case "refresh_trigger":
                            HandleRefreshTrigger();
                            break;

                        case "error":
                            HandleErrorMessage(messageDict);
                            break;

                        default:
                            // 未知消息类型，忽略
                            break;
                    }
                });
            }
            catch (Exception)
            {
                // 不向用户显示处理错误
            }
        }

        private void HandleRegisterSuccess(Dictionary<String, Object> messageDict)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => HandleRegisterSuccess(messageDict));
                return;
            }

            try
            {
                StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_Connected");
                AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_JoinedChannel"));

                if (messageDict.TryGetValue("user", out Object? userObj) &&
                    userObj is JsonElement userElement)
                {
                    if (userElement.TryGetProperty("username", out JsonElement usernameElement))
                    {
                        _currentUsername = usernameElement.GetString() ?? "";
                    }

                    if (userElement.TryGetProperty("avatar", out JsonElement avatarElement))
                    {
                        String avatar = avatarElement.GetString() ?? "";
                        if (!String.IsNullOrEmpty(avatar) && !String.IsNullOrEmpty(_currentUsername))
                        {
                            _userAvatars[_currentUsername] = avatar;
                        }
                    }
                }

                if (messageDict.TryGetValue("recent_messages", out Object? messagesObj) &&
                    messagesObj is JsonElement messagesElement &&
                    messagesElement.ValueKind == JsonValueKind.Array)
                {
                    MessagesPanel.Children.Clear();

                    foreach (JsonElement msgElement in messagesElement.EnumerateArray())
                    {
                        try
                        {
                            Dictionary<String, Object>? msgDict = JsonSerializer.Deserialize(msgElement.GetRawText(), BugReportJsonContext.Default.DictionaryStringObject);
                            if (msgDict != null)
                            {
                                if (msgDict.TryGetValue("type", out Object? _))
                                {
                                    // do nothing
                                }

                                HandleNewMessage(msgDict, isHistory: true);
                            }
                        }
                        catch (Exception)
                        {
                            // 忽略单条历史消息错误
                        }
                    }

                    ScrollToBottom();
                }
                else
                {
                    AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_NoHistoryMessages"));
                }

                if (_pendingMessages.Count > 0)
                {
                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(500);
                        await ProcessPendingMessagesAsync();
                    });
                }
            }
            catch (Exception ex)
            {
                AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_HandleRegisterFailed"), ex.Message));
            }
        }

        private void HandleNewMessage(Dictionary<String, Object> messageDict, Boolean isHistory = false)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => HandleNewMessage(messageDict, isHistory));
                return;
            }

            try
            {
                if (!messageDict.TryGetValue("username", out Object? usernameObj) ||
                    !messageDict.TryGetValue("type", out Object? typeObj))
                    return;

                String username = usernameObj.ToString() ?? "";
                String type = typeObj.ToString() ?? "";

                if (type != "text" && type != "new_message")
                {
                    // 仅处理文本类型消息
                }

                if (!messageDict.TryGetValue("content", out Object? contentObj))
                    return;

                String content = contentObj.ToString() ?? "";

                if (messageDict.TryGetValue("user_info", out Object? textUserInfoObj) &&
                    textUserInfoObj is JsonElement textUserInfoElement)
                {
                    if (textUserInfoElement.TryGetProperty("username", out JsonElement infoUsernameElement) &&
                        textUserInfoElement.TryGetProperty("avatar", out JsonElement avatarElement))
                    {
                        String infoUsername = infoUsernameElement.GetString() ?? "";
                        String avatar = avatarElement.GetString() ?? "";

                        if (!String.IsNullOrEmpty(infoUsername) && !String.IsNullOrEmpty(avatar))
                        {
                            _userAvatars[infoUsername] = avatar;
                        }
                    }
                }

                Boolean textIsMe = username == _currentUsername;

                if (textIsMe && !isHistory)
                {
                    return;
                }

                Int32 readByCount = 0;
                Int32 totalUsers = 0;

                if (messageDict.TryGetValue("read_by_count", out Object? readByObj) &&
                    Int32.TryParse(readByObj.ToString(), out Int32 readCount))
                {
                    readByCount = readCount;
                }

                if (messageDict.TryGetValue("total_users", out Object? totalUsersObj) &&
                    Int32.TryParse(totalUsersObj.ToString(), out Int32 totalCount))
                {
                    totalUsers = totalCount;
                }

                AddMessageWithUser(content, username, textIsMe, isHistory, readByCount, totalUsers);

                if (!isHistory && messageDict.TryGetValue("id", out Object? idObj))
                {
                    String messageId = idObj.ToString() ?? "";
                    if (!String.IsNullOrEmpty(messageId))
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _tcpClient?.MarkMessageReadAsync(messageId)!;
                            }
                            catch { }
                        });
                    }
                }
            }
            catch (Exception)
            {
                // 忽略单条消息处理错误
            }
        }

        private void HandleUserOnline(Dictionary<String, Object> messageDict)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => HandleUserOnline(messageDict));
                return;
            }

            if (!messageDict.TryGetValue("username", out Object? usernameObj))
                return;

            String username = usernameObj.ToString() ?? "";
            AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UserOnline"), username));
        }

        private void HandleUserOffline(Dictionary<String, Object> messageDict)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => HandleUserOffline(messageDict));
                return;
            }

            if (!messageDict.TryGetValue("username", out Object? usernameObj))
                return;

            String username = usernameObj.ToString() ?? "";
            AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UserOffline"), username));
        }

        private static void HandleReadStatusUpdate(Dictionary<String, Object> messageDict)
        {
            if (messageDict.TryGetValue("message_id", out Object? idObj) &&
                messageDict.TryGetValue("read_by_count", out Object? readCountObj) &&
                messageDict.TryGetValue("total_users", out Object? totalUsersObj))
            {
                _ = idObj.ToString() ?? "";
                _ = Int32.TryParse(readCountObj.ToString(), out Int32 rc) ? rc : 0;
                _ = Int32.TryParse(totalUsersObj.ToString(), out Int32 tu) ? tu : 0;
            }
        }

        private void HandleSystemMessage(Dictionary<String, Object> messageDict)
        {
            if (messageDict.TryGetValue("content", out Object? contentObj))
            {
                String content = contentObj.ToString() ?? "";
                String sender = "System";

                if (messageDict.TryGetValue("sender", out Object? senderObj))
                {
                    sender = senderObj.ToString() ?? "System";
                }

                if (sender == "Server")
                {
                    AddSystemMessage($"[Server] {content}");
                }
                else
                {
                    AddSystemMessage(content);
                }
            }
        }

        private void HandleRefreshTrigger()
        {
            _isAutoRefresh = true;

            _ = Task.Run(async () =>
            {
                try
                {
                    if (_tcpClient != null)
                    {
                        await _tcpClient.DisconnectAsync();
                        await Task.Delay(600);
                        await _tcpClient.ConnectAsync();
                    }
                }
                catch (Exception)
                {
                    // 忽略
                }
                finally
                {
                    DispatcherQueue.TryEnqueue(() => _isAutoRefresh = false);
                }
            });

            Dictionary<String, Object> refreshMessageDict = new()
            {
                ["type"] = "register_success",
                ["users"] = new List<Dictionary<String, Object>>(),
                ["messages"] = new List<Dictionary<String, Object>>()
            };

            HandleRegisterSuccess(refreshMessageDict);
        }

        private void HandleErrorMessage(Dictionary<String, Object> messageDict)
        {
            if (messageDict.TryGetValue("content", out Object? msgObj))
            {
                String errorMessage = msgObj.ToString() ?? "";
                AddSystemMessage(errorMessage);
            }
            else if (messageDict.TryGetValue("message", out Object? msgObj2))
            {
                String errorMessage = msgObj2.ToString() ?? "";
                AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ErrorFormat"), errorMessage));
            }
        }

        #endregion

        #region UI消息处理
        private async Task<Boolean> ShowUsernameDialogAsync()
        {
            ContentDialog dialog = new()
            {
                Title = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameDialog_Title"),
                Content = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameDialog_Content"),
                CloseButtonText = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Cancel"),
                PrimaryButtonText = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameDialog_Connect"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot
            };

            StackPanel stackPanel = new() { Spacing = 12 };
            stackPanel.Children.Add(new TextBlock { Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameLabel") });
            TextBox usernameBox = new() { PlaceholderText = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernamePlaceholder") };
            stackPanel.Children.Add(usernameBox);

            dialog.Content = stackPanel;

            Boolean result = false;
            dialog.PrimaryButtonClick += async (_, __) =>
            {
                String username = usernameBox.Text.Trim();
                if (String.IsNullOrEmpty(username))
                {
                    usernameBox.PlaceholderText = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameEmpty");
                    return;
                }

                try
                {
                    if (_tcpClient != null)
                    {
                        await _tcpClient.SetUsernameAsync(username);
                        result = true;
                    }
                }
                catch (Exception ex)
                {
                    AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_SetUsernameFailed"), ex.Message));
                }
            };

            await dialog.ShowAsync();
            return result;
        }

        private void AddMessageWithUser(String content, String username, Boolean isMe, Boolean isHistory = false, Int32 readByCount = 0, Int32 totalUsers = 0)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => AddMessageWithUser(content, username, isMe, isHistory));
                return;
            }

            StackPanel container = new()
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Margin = new Thickness(0, 4, 0, 4),
                HorizontalAlignment = isMe ? HorizontalAlignment.Right : HorizontalAlignment.Left
            };

            Border avatar = new()
            {
                Width = 32,
                Height = 32,
                CornerRadius = new CornerRadius(16),
                Background = (Brush)Application.Current.Resources["SystemControlBackgroundAccentBrush"],
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 0, 0, 8)
            };
            TextBlock avatarText = new()
            {
                Text = username.Length > 0 ? username[0].ToString().ToUpper() : "?",
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 16,
                Foreground = (Brush)Application.Current.Resources["SystemControlForegroundChromeWhiteBrush"]
            };

            avatar.Child = avatarText;

            Border messageBubble = new()
            {
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12, 8, 12, 8),
                MaxWidth = 400,
                Background = (Brush)Application.Current.Resources["LayerOnMicaBaseAltFillColorDefaultBrush"],
                BorderBrush = (Brush)Application.Current.Resources["ControlElevationBorderBrush"],
                BorderThickness = new Thickness(1)
            };

            StackPanel messageStack = new() { Spacing = 4 };

            TextBlock usernameText = new()
            {
                Text = username,
                FontSize = 12,
                Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
            };
            messageStack.Children.Add(usernameText);

            TextBlock contentText = new()
            {
                Text = content,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                Foreground = (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
            };
            messageStack.Children.Add(contentText);

            if (totalUsers > 0)
            {
                TextBlock readStatusText = new()
                {
                    Text = readByCount >= totalUsers ? WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_AllRead") : String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ReadCountFormat"), readByCount),
                    FontSize = 10,
                    Foreground = (Brush)Application.Current.Resources["TextFillColorDisabledBrush"],
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Margin = new Thickness(0, 4, 0, 0)
                };
                messageStack.Children.Add(readStatusText);
            }

            messageBubble.Child = messageStack;

            if (isMe)
            {
                container.Children.Add(messageBubble);
                container.Children.Add(avatar);
            }
            else
            {
                container.Children.Add(avatar);
                container.Children.Add(messageBubble);
            }

            MessagesPanel.Children.Add(container);

            ScrollToBottom();
        }

        private void AddSystemMessage(String message)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => AddSystemMessage(message));
                return;
            }

            StackPanel container = new()
            {
                Margin = new Thickness(0, 4, 0, 4),
                HorizontalAlignment = HorizontalAlignment.Center
            };

            Border systemMessage = new()
            {
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12, 6, 12, 6),
                Background = (Brush)Application.Current.Resources["ControlFillColorSecondaryBrush"]
            };

            TextBlock text = new()
            {
                Text = message,
                FontSize = 12,
                Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
            };

            systemMessage.Child = text;
            container.Children.Add(systemMessage);

            MessagesPanel.Children.Add(container);
            ScrollToBottom();
        }

        private void ScrollToBottom(Boolean force = false)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(() => ScrollToBottom(force));
                return;
            }

            ChatScroll.ChangeView(null, ChatScroll.ScrollableHeight, null);
        }

        private void RemoveLastMessage()
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                DispatcherQueue.TryEnqueue(RemoveLastMessage);
                return;
            }

            if (MessagesPanel.Children.Count > 0)
            {
                MessagesPanel.Children.RemoveAt(MessagesPanel.Children.Count - 1);
            }
        }
        #endregion

        #region 事件处理
        private async void SendBtn_Click(Object sender, RoutedEventArgs e)
        {
            await SendBtn_ClickAsync();
        }

        private async Task SendBtn_ClickAsync()
        {
            if (_tcpClient == null)
            {
                AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_TcpNotInitialized"));
                return;
            }

            String text = InputBox.Text.Trim();
            if (String.IsNullOrEmpty(text))
                return;

            InputBox.Text = "";
            String displayUsername = !String.IsNullOrEmpty(_currentUsername) ? _currentUsername : WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_Me");
            AddMessageWithUser(text, displayUsername, isMe: true, readByCount: 1, totalUsers: 1);

            _pendingMessages.Enqueue(text);

            await ProcessPendingMessagesAsync();
        }

        private async Task ProcessPendingMessagesAsync()
        {
            if (_tcpClient == null || !_tcpClient.IsConnected)
            {
                return;
            }

            while (_pendingMessages.Count > 0)
            {
                String message = _pendingMessages.Peek();
                try
                {
                    await _tcpClient.SendMessageAsync(message);
                    _pendingMessages.Dequeue();
                }
                catch (Exception)
                {
                    break;
                }
            }
        }

        private void InputBox_KeyDown(Object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == VirtualKey.Enter && !e.KeyStatus.IsMenuKeyDown)
            {
                e.Handled = true;
                _ = SendBtn_ClickAsync();
            }
        }

        private async void ReconnectBtn_Click(Object sender, RoutedEventArgs e)
        {
            if (_tcpClient != null)
            {
                await _tcpClient.DisconnectAsync();
            }

            _isAutoRefresh = false;
            await InitializeTCPClientAsync();
        }

        private async void SettingsBtn_Click(Object sender, RoutedEventArgs e)
        {
            ContentDialog dialog = new()
            {
                Title = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_SettingsDialog_Title"),
                CloseButtonText = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Cancel"),
                PrimaryButtonText = WinUI3Localizer.Localizer.Get().GetLocalizedString("Button_Confirm"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot
            };

            StackPanel stackPanel = new() { Spacing = 12 };

            StackPanel usernamePanel = new() { Spacing = 4 };
            usernamePanel.Children.Add(new TextBlock { Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_UsernameLabel") });
            TextBox usernameBox = new() { Text = _tcpClient?.Username ?? "" };
            usernamePanel.Children.Add(usernameBox);

            StackPanel hostPanel = new() { Spacing = 4 };
            hostPanel.Children.Add(new TextBlock { Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_HostLabel") });
            TextBox hostBox = new() { Text = _tcpClient?.ServerHost ?? "" };
            hostPanel.Children.Add(hostBox);

            StackPanel portPanel = new() { Spacing = 4 };
            portPanel.Children.Add(new TextBlock { Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_PortLabel") });
            TextBox portBox = new() { Text = _tcpClient?.ServerPort.ToString() ?? "" };
            portPanel.Children.Add(portBox);

            stackPanel.Children.Add(usernamePanel);
            stackPanel.Children.Add(hostPanel);
            stackPanel.Children.Add(portPanel);

            dialog.Content = stackPanel;

            dialog.PrimaryButtonClick += async (_, __) =>
            {
                try
                {
                    if (_tcpClient != null)
                    {
                        if (_tcpClient.IsConnected)
                        {
                            await _tcpClient.DisconnectAsync();
                        }

                        await _tcpClient.SetUsernameAsync(usernameBox.Text);

                        if (Int32.TryParse(portBox.Text, out Int32 port))
                        {
                            await _tcpClient.SetServerAsync(hostBox.Text, port);
                        }

                        AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_SettingSaved"));

                        await _tcpClient.ConnectAsync();
                    }
                }
                catch (Exception ex)
                {
                    AddSystemMessage(String.Format(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_SettingSaveFailed"), ex.Message));
                }
                return;
            };

            await dialog.ShowAsync();
        }
        #endregion

        #region 自动刷新
        private void InitializeRefreshTimer()
        {
            _refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(4)
            };

            _refreshTimer.Tick += async (sender, e) =>
            {
                try
                {
                    if (_tcpClient != null)
                    {
                        _isAutoRefresh = true;

                        await _tcpClient.ConnectAsync();

                        if (_tcpClient.IsConnected && _pendingMessages.Count > 0)
                        {
                            await ProcessPendingMessagesAsync();
                        }

                        _isAutoRefresh = false;
                    }
                }
                catch (Exception)
                {
                    _isAutoRefresh = false;
                }
            };

            _refreshTimer.Start();

            DispatcherTimer connectionCheckTimer = new()
            {
                Interval = TimeSpan.FromMilliseconds(3000)
            };

            Int32 connectionFailureCount = 0;
            Boolean isUpdatingStatus = false;

            connectionCheckTimer.Tick += (sender, e) =>
            {
                if (isUpdatingStatus)
                    return;

                if (_tcpClient != null)
                {
                    isUpdatingStatus = true;

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await _tcpClient.DisconnectAsync();
                            await Task.Delay(1000);
                            await _tcpClient.ConnectAsync();

                            connectionFailureCount = 0;

                            if (_pendingMessages.Count > 0)
                            {
                                await ProcessPendingMessagesAsync();
                            }

                            DispatcherQueue.TryEnqueue(() =>
                            {
                                StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_Connected");
                                isUpdatingStatus = false;
                            });
                        }
                        catch (Exception)
                        {
                            connectionFailureCount++;

                            if (connectionFailureCount >= 3)
                            {
                                DispatcherQueue.TryEnqueue(() =>
                                {
                                    StatusTxt.Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ConnectionFailed");
                                    AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_ConnectionFailedAlert"));
                                    isUpdatingStatus = false;
                                });
                            }
                            else
                            {
                                isUpdatingStatus = false;
                            }
                        }
                    });
                }
            };

            connectionCheckTimer.Start();
        }
        #endregion

        #region 清理
        private void Cleanup()
        {
            try
            {
                _refreshTimer?.Stop();

                if (_tcpClient != null && _tcpClient.IsConnected)
                {
                    AddSystemMessage(WinUI3Localizer.Localizer.Get().GetLocalizedString("BugReportPage_LeavingChannel"));
                }

                _tcpClient?.DisconnectAsync().Wait(1000);
            }
            catch { }

            _tcpClient = null;
        }
        #endregion

    }
}