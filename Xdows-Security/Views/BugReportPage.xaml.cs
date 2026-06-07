using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class BugReportPage : Page
    {
        private FeedbackTCPClient? _tcpClient;
        private readonly Dictionary<String, String> _userAvatars = [];
        private readonly Queue<String> _pendingMessages = new();
        private readonly SemaphoreSlim _clientGate = new(1, 1);
        private readonly SemaphoreSlim _pendingMessagesGate = new(1, 1);

        private DispatcherTimer? _refreshTimer;
        private DispatcherTimer? _connectionCheckTimer;
        private CancellationTokenSource _lifetimeCts = new();

        private EventHandler<String>? _connectedHandler;
        private EventHandler<String>? _disconnectedHandler;
        private EventHandler<Dictionary<String, Object>>? _messageReceivedHandler;
        private EventHandler<String>? _errorHandler;

        private String _currentUsername = "";
        private Boolean _isAutoRefresh;
        private Boolean _isUnloaded;
        private Boolean _isConnectionCheckRunning;
        private Int32 _clientGeneration;
        private Int32 _connectionFailureCount;

        public BugReportPage()
        {
            InitializeComponent();
            SetConnectionStatus("BugReportPage_NotConnected");

            Loaded += BugReportPage_Loaded;
            Unloaded += BugReportPage_Unloaded;
        }

        private async void BugReportPage_Loaded(Object sender, RoutedEventArgs e)
        {
            _isUnloaded = false;

            if (_lifetimeCts.IsCancellationRequested)
            {
                _lifetimeCts.Dispose();
                _lifetimeCts = new CancellationTokenSource();
            }

            try
            {
                await InitializeTCPClientAsync();
                InitializeRefreshTimer();
            }
            catch (Exception ex)
            {
                AddSystemMessage(LF("BugReportPage_FailedInit", ex.Message));
            }
        }

        private async void BugReportPage_Unloaded(Object sender, RoutedEventArgs e)
        {
            await CleanupAsync();
        }

        private static String L(String key)
        {
            try
            {
                return WinUI3Localizer.Localizer.Get().GetLocalizedString(key);
            }
            catch
            {
                return key;
            }
        }

        private static String LF(String key, params Object[] args)
        {
            return String.Format(L(key), args);
        }

        private Boolean TryEnqueueUi(Action action)
        {
            if (_isUnloaded)
            {
                return false;
            }

            if (DispatcherQueue.HasThreadAccess)
            {
                action();
                return true;
            }

            return DispatcherQueue.TryEnqueue(() =>
            {
                if (!_isUnloaded)
                {
                    action();
                }
            });
        }

        private void SetConnectionStatus(String resourceKey)
        {
            String status = L(resourceKey);
            _ = TryEnqueueUi(() => StatusTxt.Text = status);
        }
    }
}
