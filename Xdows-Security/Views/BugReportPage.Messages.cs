using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.System;

namespace Xdows_Security.Views
{
    public sealed partial class BugReportPage
    {
        private async Task HandleReceivedMessageAsync(Dictionary<String, Object> messageDict)
        {
            try
            {
                if (!messageDict.TryGetValue("type", out Object? typeObj))
                {
                    return;
                }

                String type = GetString(typeObj);
                if (String.IsNullOrWhiteSpace(type))
                {
                    return;
                }

                _ = TryEnqueueUi(() =>
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
                    }
                });

                await Task.CompletedTask;
            }
            catch
            {
            }
        }

        private void HandleRegisterSuccess(Dictionary<String, Object> messageDict)
        {
            SetConnectionStatus("BugReportPage_Connected");
            AddSystemMessage(L("BugReportPage_JoinedChannel"));
            UpdateCurrentUser(messageDict);

            if (messageDict.TryGetValue("recent_messages", out Object? messagesObj) &&
                messagesObj is JsonElement messagesElement &&
                messagesElement.ValueKind == JsonValueKind.Array)
            {
                MessagesPanel.Children.Clear();

                foreach (JsonElement msgElement in messagesElement.EnumerateArray())
                {
                    try
                    {
                        Dictionary<String, Object>? msgDict = JsonSerializer.Deserialize(
                            msgElement.GetRawText(),
                            BugReportJsonContext.Default.DictionaryStringObject);

                        if (msgDict != null)
                        {
                            HandleNewMessage(msgDict, isHistory: true);
                        }
                    }
                    catch
                    {
                    }
                }

                ScrollToBottomAfterLayout();
            }
            else
            {
                AddSystemMessage(L("BugReportPage_NoHistoryMessages"));
                ScrollToBottomAfterLayout();
            }

            _ = ProcessPendingMessagesAsync();
        }

        private void UpdateCurrentUser(Dictionary<String, Object> messageDict)
        {
            if (!messageDict.TryGetValue("user", out Object? userObj) ||
                userObj is not JsonElement userElement)
            {
                return;
            }

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

        private void HandleNewMessage(Dictionary<String, Object> messageDict, Boolean isHistory = false)
        {
            if (!messageDict.TryGetValue("username", out Object? usernameObj) ||
                !messageDict.TryGetValue("type", out Object? typeObj) ||
                !messageDict.TryGetValue("content", out Object? contentObj))
            {
                return;
            }

            String username = GetString(usernameObj);
            String type = GetString(typeObj);
            String content = GetString(contentObj);

            if (type != "text" && type != "new_message" && type != "message")
            {
                return;
            }

            UpdateAvatarCache(messageDict);

            Boolean textIsMe = username == _currentUsername;
            if (textIsMe && !isHistory)
            {
                return;
            }

            Int32 readByCount = GetInt32(messageDict, "read_by_count");
            Int32 totalUsers = GetInt32(messageDict, "total_users");

            AddMessageWithUser(content, username, textIsMe, isHistory, readByCount, totalUsers);

            String messageId = GetString(messageDict, "id");
            if (!isHistory && !String.IsNullOrWhiteSpace(messageId))
            {
                _ = MarkMessageReadAsync(messageId);
            }
        }

        private void UpdateAvatarCache(Dictionary<String, Object> messageDict)
        {
            if (!messageDict.TryGetValue("user_info", out Object? userInfoObj) ||
                userInfoObj is not JsonElement userInfoElement)
            {
                return;
            }

            if (userInfoElement.TryGetProperty("username", out JsonElement usernameElement) &&
                userInfoElement.TryGetProperty("avatar", out JsonElement avatarElement))
            {
                String username = usernameElement.GetString() ?? "";
                String avatar = avatarElement.GetString() ?? "";

                if (!String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(avatar))
                {
                    _userAvatars[username] = avatar;
                }
            }
        }

        private async Task MarkMessageReadAsync(String messageId)
        {
            FeedbackTCPClient? client = _tcpClient;
            if (client == null || !client.IsConnected)
            {
                return;
            }

            try
            {
                await client.MarkMessageReadAsync(messageId);
            }
            catch
            {
            }
        }

        private void HandleUserOnline(Dictionary<String, Object> messageDict)
        {
            String username = GetString(messageDict, "username");
            if (!String.IsNullOrWhiteSpace(username))
            {
                AddSystemMessage(LF("BugReportPage_UserOnline", username));
            }
        }

        private void HandleUserOffline(Dictionary<String, Object> messageDict)
        {
            String username = GetString(messageDict, "username");
            if (!String.IsNullOrWhiteSpace(username))
            {
                AddSystemMessage(LF("BugReportPage_UserOffline", username));
            }
        }

        private static void HandleReadStatusUpdate(Dictionary<String, Object> messageDict)
        {
            _ = GetString(messageDict, "message_id");
            _ = GetInt32(messageDict, "read_by_count");
            _ = GetInt32(messageDict, "total_users");
        }

        private void HandleSystemMessage(Dictionary<String, Object> messageDict)
        {
            String content = GetString(messageDict, "content");
            if (String.IsNullOrEmpty(content))
            {
                return;
            }

            String sender = GetString(messageDict, "sender");
            AddSystemMessage(sender == "Server" ? $"[Server] {content}" : content);
        }

        private void HandleRefreshTrigger()
        {
            _ = HandleRefreshTriggerAsync();
        }

        private async Task HandleRefreshTriggerAsync()
        {
            _isAutoRefresh = true;

            try
            {
                await RefreshCurrentClientAsync();
            }
            finally
            {
                _isAutoRefresh = false;
            }
        }

        private void HandleErrorMessage(Dictionary<String, Object> messageDict)
        {
            String errorMessage = GetString(messageDict, "content");
            if (!String.IsNullOrEmpty(errorMessage))
            {
                AddSystemMessage(errorMessage);
                return;
            }

            errorMessage = GetString(messageDict, "message");
            if (!String.IsNullOrEmpty(errorMessage))
            {
                AddSystemMessage(LF("BugReportPage_ErrorFormat", errorMessage));
            }
        }

        private void AddMessageWithUser(
            String content,
            String username,
            Boolean isMe,
            Boolean isHistory = false,
            Int32 readByCount = 0,
            Int32 totalUsers = 0)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                _ = TryEnqueueUi(() => AddMessageWithUser(content, username, isMe, isHistory, readByCount, totalUsers));
                return;
            }

            StackPanel container = new()
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Margin = new Thickness(0, 4, 0, 4),
                HorizontalAlignment = isMe ? HorizontalAlignment.Right : HorizontalAlignment.Left
            };

            Border avatar = CreateAvatar(username);
            Border messageBubble = CreateMessageBubble(content, username, readByCount, totalUsers);

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
            if (!isHistory)
            {
                ScrollToBottom();
            }
        }

        private static Border CreateAvatar(String username)
        {
            TextBlock avatarText = new()
            {
                Text = GetInitial(username),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Style = ResourceStyle("BodyStrongTextBlockStyle"),
                Foreground = ResourceBrush("SystemControlForegroundChromeWhiteBrush")
            };

            return new Border
            {
                Width = 32,
                Height = 32,
                CornerRadius = new CornerRadius(16),
                Background = ResourceBrush("SystemControlBackgroundAccentBrush"),
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 0, 0, 8),
                Child = avatarText
            };
        }

        private static Border CreateMessageBubble(String content, String username, Int32 readByCount, Int32 totalUsers)
        {
            StackPanel messageStack = new()
            {
                Spacing = 4
            };

            messageStack.Children.Add(new TextBlock
            {
                Text = username,
                Style = ResourceStyle("CaptionTextBlockStyle"),
                Foreground = ResourceBrush("TextFillColorSecondaryBrush")
            });

            messageStack.Children.Add(new TextBlock
            {
                Text = content,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                Style = ResourceStyle("BodyTextBlockStyle")
            });

            if (totalUsers > 0)
            {
                messageStack.Children.Add(new TextBlock
                {
                    Text = readByCount >= totalUsers
                        ? L("BugReportPage_AllRead")
                        : LF("BugReportPage_ReadCountFormat", readByCount),
                    Style = ResourceStyle("CaptionTextBlockStyle"),
                    Foreground = ResourceBrush("TextFillColorDisabledBrush"),
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }

            return new Border
            {
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12, 8, 12, 8),
                MaxWidth = 520,
                Background = ResourceBrush("LayerOnMicaBaseAltFillColorDefaultBrush"),
                BorderBrush = ResourceBrush("ControlElevationBorderBrush"),
                BorderThickness = new Thickness(1),
                Child = messageStack
            };
        }

        private void AddSystemMessage(String message)
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                _ = TryEnqueueUi(() => AddSystemMessage(message));
                return;
            }

            Border systemMessage = new()
            {
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12, 6, 12, 6),
                Background = ResourceBrush("ControlFillColorSecondaryBrush"),
                Child = new TextBlock
                {
                    Text = message,
                    Style = ResourceStyle("CaptionTextBlockStyle"),
                    Foreground = ResourceBrush("TextFillColorSecondaryBrush")
                }
            };

            MessagesPanel.Children.Add(new StackPanel
            {
                Margin = new Thickness(0, 4, 0, 4),
                HorizontalAlignment = HorizontalAlignment.Center,
                Children =
                {
                    systemMessage
                }
            });

            ScrollToBottom();
        }

        private void ScrollToBottom()
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                _ = TryEnqueueUi(ScrollToBottom);
                return;
            }

            ChatScroll.ChangeView(null, ChatScroll.ScrollableHeight, null);
        }

        private void ScrollToBottomAfterLayout()
        {
            if (!DispatcherQueue.HasThreadAccess)
            {
                _ = TryEnqueueUi(ScrollToBottomAfterLayout);
                return;
            }

            _ = ScrollToBottomAfterLayoutAsync();
        }

        private async Task ScrollToBottomAfterLayoutAsync()
        {
            await Task.Yield();
            if (_isUnloaded)
            {
                return;
            }

            ChatScroll.UpdateLayout();
            ScrollToBottom();

            await Task.Delay(50);
            if (_isUnloaded)
            {
                return;
            }

            ChatScroll.UpdateLayout();
            ScrollToBottom();
        }

        private async void SendBtn_Click(Object sender, RoutedEventArgs e)
        {
            await SendBtn_ClickAsync();
        }

        private async Task SendBtn_ClickAsync()
        {
            if (_tcpClient == null)
            {
                AddSystemMessage(L("BugReportPage_TcpNotInitialized"));
                return;
            }

            String text = InputBox.Text.Trim();
            if (String.IsNullOrEmpty(text))
            {
                return;
            }

            InputBox.Text = "";
            String displayUsername = !String.IsNullOrEmpty(_currentUsername)
                ? _currentUsername
                : L("BugReportPage_Me");

            AddMessageWithUser(text, displayUsername, isMe: true, readByCount: 1, totalUsers: 1);
            await EnqueuePendingMessageAsync(text);
            await ProcessPendingMessagesAsync();
        }

        private async Task EnqueuePendingMessageAsync(String message)
        {
            await _pendingMessagesGate.WaitAsync();

            try
            {
                _pendingMessages.Enqueue(message);
            }
            finally
            {
                _pendingMessagesGate.Release();
            }
        }

        private async Task ProcessPendingMessagesAsync()
        {
            FeedbackTCPClient? client = _tcpClient;
            if (client == null || !client.IsConnected)
            {
                return;
            }

            await _pendingMessagesGate.WaitAsync();

            try
            {
                while (_pendingMessages.Count > 0)
                {
                    if (_isUnloaded || !ReferenceEquals(client, _tcpClient) || !client.IsConnected)
                    {
                        return;
                    }

                    String message = _pendingMessages.Peek();
                    try
                    {
                        await client.SendMessageAsync(message);
                        _pendingMessages.Dequeue();
                    }
                    catch
                    {
                        return;
                    }
                }
            }
            finally
            {
                _pendingMessagesGate.Release();
            }
        }

        private void InputBox_KeyDown(Object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
        {
            if (e.Key == VirtualKey.Enter && !e.KeyStatus.IsMenuKeyDown)
            {
                e.Handled = true;
                _ = SendBtn_ClickAsync();
            }
        }

        private static String GetString(Dictionary<String, Object> messageDict, String key)
        {
            return messageDict.TryGetValue(key, out Object? value) ? GetString(value) : "";
        }

        private static String GetString(Object? value)
        {
            return value switch
            {
                null => "",
                JsonElement { ValueKind: JsonValueKind.String } element => element.GetString() ?? "",
                JsonElement element => element.ToString(),
                _ => value.ToString() ?? ""
            };
        }

        private static Int32 GetInt32(Dictionary<String, Object> messageDict, String key)
        {
            if (!messageDict.TryGetValue(key, out Object? value))
            {
                return 0;
            }

            if (value is JsonElement element && element.ValueKind == JsonValueKind.Number)
            {
                return element.TryGetInt32(out Int32 jsonValue) ? jsonValue : 0;
            }

            return Int32.TryParse(GetString(value), out Int32 result) ? result : 0;
        }

        private static String GetInitial(String username)
        {
            return username.Length > 0 ? username[0].ToString().ToUpper() : "?";
        }

        private static Brush ResourceBrush(String key)
        {
            return (Brush)Application.Current.Resources[key];
        }

        private static Style ResourceStyle(String key)
        {
            return (Style)Application.Current.Resources[key];
        }
    }
}
