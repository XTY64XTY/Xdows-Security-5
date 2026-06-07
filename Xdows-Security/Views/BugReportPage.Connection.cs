using Microsoft.UI.Xaml;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class BugReportPage
    {
        private async Task InitializeTCPClientAsync()
        {
            await _clientGate.WaitAsync();

            try
            {
                await DisposeCurrentClientAsync(showLeavingMessage: false);

                if (_isUnloaded)
                {
                    return;
                }

                FeedbackTCPClient client = new();
                Int32 generation = ++_clientGeneration;
                _tcpClient = client;
                AttachClientEvents(client, generation);

                if (String.IsNullOrWhiteSpace(client.Username))
                {
                    await client.SetUsernameAsync(Environment.UserName);
                }

                Boolean connected = await client.ConnectAsync();
                if (!connected && IsCurrentClient(client, generation))
                {
                    SetConnectionStatus("BugReportPage_ConnectionFailed");
                }
            }
            finally
            {
                _clientGate.Release();
            }
        }

        private void AttachClientEvents(FeedbackTCPClient client, Int32 generation)
        {
            _connectedHandler = (_, _) =>
            {
            };

            _disconnectedHandler = (_, _) =>
            {
            };

            _messageReceivedHandler = async (_, messageDict) =>
            {
                if (IsCurrentClient(client, generation))
                {
                    await HandleReceivedMessageAsync(messageDict);
                }
            };

            _errorHandler = async (_, error) =>
            {
                if (IsCurrentClient(client, generation))
                {
                    await HandleClientErrorAsync(error);
                }
            };

            client.OnConnected += _connectedHandler;
            client.OnDisconnected += _disconnectedHandler;
            client.OnMessageReceived += _messageReceivedHandler;
            client.OnError += _errorHandler;
        }

        private void DetachClientEvents(FeedbackTCPClient client)
        {
            if (_connectedHandler != null)
            {
                client.OnConnected -= _connectedHandler;
            }

            if (_disconnectedHandler != null)
            {
                client.OnDisconnected -= _disconnectedHandler;
            }

            if (_messageReceivedHandler != null)
            {
                client.OnMessageReceived -= _messageReceivedHandler;
            }

            if (_errorHandler != null)
            {
                client.OnError -= _errorHandler;
            }

            _connectedHandler = null;
            _disconnectedHandler = null;
            _messageReceivedHandler = null;
            _errorHandler = null;
        }

        private Boolean IsCurrentClient(FeedbackTCPClient client, Int32 generation)
        {
            return !_isUnloaded &&
                   _clientGeneration == generation &&
                   ReferenceEquals(_tcpClient, client);
        }

        private async Task HandleClientErrorAsync(String error)
        {
            if (_isAutoRefresh || IsIgnoredClientError(error))
            {
                return;
            }

            if (error.Contains("未连接到服务器，重连失败"))
            {
                AddSystemMessage(L("BugReportPage_Reconnecting"));
                return;
            }

            SetConnectionStatus("BugReportPage_ConnectionFailed");
            AddSystemMessage(L("BugReportPage_ConnectionFailedMessage") + error);

            if (error.Contains("连接") || error.Contains("断开"))
            {
                await Task.Delay(600);
            }
        }

        private static Boolean IsIgnoredClientError(String error)
        {
            return error.Contains("解码消息异常") ||
                   error.Contains("线程退出") ||
                   error.Contains("应用程序请求") ||
                   error.Contains("已中止 I/O 操作");
        }

        private void InitializeRefreshTimer()
        {
            StopRefreshTimers();

            _refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(4)
            };
            _refreshTimer.Tick += RefreshTimer_Tick;
            _refreshTimer.Start();

            _connectionCheckTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(3)
            };
            _connectionCheckTimer.Tick += ConnectionCheckTimer_Tick;
            _connectionCheckTimer.Start();
        }

        private async void RefreshTimer_Tick(Object? sender, Object e)
        {
            if (_isUnloaded || _isAutoRefresh)
            {
                return;
            }

            _isAutoRefresh = true;

            try
            {
                await EnsureConnectedAsync();
                await ProcessPendingMessagesAsync();
            }
            finally
            {
                _isAutoRefresh = false;
            }
        }

        private async void ConnectionCheckTimer_Tick(Object? sender, Object e)
        {
            if (_isUnloaded || _isConnectionCheckRunning)
            {
                return;
            }

            _isConnectionCheckRunning = true;

            try
            {
                FeedbackTCPClient? client = _tcpClient;
                if (client == null)
                {
                    return;
                }

                if (client.IsConnected)
                {
                    _connectionFailureCount = 0;
                    SetConnectionStatus("BugReportPage_Connected");
                    return;
                }

                Boolean connected = await EnsureConnectedAsync();
                if (connected)
                {
                    _connectionFailureCount = 0;
                    SetConnectionStatus("BugReportPage_Connected");
                    await ProcessPendingMessagesAsync();
                    return;
                }

                _connectionFailureCount++;
                if (_connectionFailureCount >= 3)
                {
                    SetConnectionStatus("BugReportPage_ConnectionFailed");
                    AddSystemMessage(L("BugReportPage_ConnectionFailedAlert"));
                }
            }
            finally
            {
                _isConnectionCheckRunning = false;
            }
        }

        private async Task<Boolean> EnsureConnectedAsync()
        {
            await _clientGate.WaitAsync();

            try
            {
                FeedbackTCPClient? client = _tcpClient;
                if (_isUnloaded || client == null)
                {
                    return false;
                }

                if (client.IsConnected)
                {
                    return true;
                }

                return await client.ConnectAsync();
            }
            finally
            {
                _clientGate.Release();
            }
        }

        private async Task RefreshCurrentClientAsync()
        {
            await _clientGate.WaitAsync();

            try
            {
                FeedbackTCPClient? client = _tcpClient;
                if (_isUnloaded || client == null)
                {
                    return;
                }

                if (client.IsConnected)
                {
                    await client.DisconnectAsync();
                    await Task.Delay(600);
                }

                await client.ConnectAsync();
            }
            finally
            {
                _clientGate.Release();
            }

            await ProcessPendingMessagesAsync();
        }

        private void StopRefreshTimers()
        {
            if (_refreshTimer != null)
            {
                _refreshTimer.Tick -= RefreshTimer_Tick;
                _refreshTimer.Stop();
                _refreshTimer = null;
            }

            if (_connectionCheckTimer != null)
            {
                _connectionCheckTimer.Tick -= ConnectionCheckTimer_Tick;
                _connectionCheckTimer.Stop();
                _connectionCheckTimer = null;
            }
        }

        private async Task CleanupAsync()
        {
            _isUnloaded = true;
            _lifetimeCts.Cancel();
            StopRefreshTimers();

            await _clientGate.WaitAsync();

            try
            {
                await DisposeCurrentClientAsync(showLeavingMessage: true);
            }
            finally
            {
                _clientGate.Release();
            }
        }

        private async Task DisposeCurrentClientAsync(Boolean showLeavingMessage)
        {
            FeedbackTCPClient? client = _tcpClient;
            if (client == null)
            {
                return;
            }

            _tcpClient = null;
            _clientGeneration++;
            DetachClientEvents(client);

            if (showLeavingMessage && client.IsConnected)
            {
                AddSystemMessage(L("BugReportPage_LeavingChannel"));
            }

            try
            {
                await client.DisconnectAsync();
            }
            catch
            {
            }
        }
    }
}
