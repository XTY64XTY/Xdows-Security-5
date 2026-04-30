using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class PopupBlockerView : UserControl
    {
        private List<PopupRule> _rules = [];
        private readonly PopupBlockerEngine _blocker = new();
        private bool _isMonitoring;

        public PopupBlockerView()
        {
            InitializeComponent();
        }

        private void MasterToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (MasterToggle.IsOn)
                StartMonitoring();
            else
                StopMonitoring();
        }

        private void StartMonitoring()
        {
            var enabledRules = _rules.Where(r => r.IsEnabled).ToList();
            if (enabledRules.Count == 0)
            {
                MasterToggle.IsOn = false;
                return;
            }

            _blocker.Start(enabledRules);
            _isMonitoring = true;
        }

        private void StopMonitoring()
        {
            _blocker.Stop();
            _isMonitoring = false;
        }

        private void UpdateMonitoring()
        {
            if (!_isMonitoring) return;

            var enabledRules = _rules.Where(r => r.IsEnabled).ToList();
            if (enabledRules.Count == 0)
            {
                StopMonitoring();
                MasterToggle.IsOn = false;
            }
            else
            {
                _blocker.UpdateRules(enabledRules);
            }
        }

        private void PopupSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
            => ApplyFilter();

        private void ApplyFilter()
        {
            var keyword = PopupSearchBox.Text?.Trim() ?? "";
            IEnumerable<PopupRule> filtered = _rules;

            if (!string.IsNullOrEmpty(keyword))
            {
                filtered = _rules.Where(p =>
                    p.Title.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    p.ProcessName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
            }

            PopupRuleList.ItemsSource = filtered.ToList();
        }

        private async void AddPopupRule_Click(object sender, RoutedEventArgs e)
        {
            var titleBox = new TextBox { PlaceholderText = "输入要拦截的弹窗标题" };
            var processBox = new TextBox { PlaceholderText = "输入进程名称（* 表示所有进程）", Text = "*" };
            var enabledToggle = new ToggleSwitch { IsOn = true };

            var dialog = new ContentDialog
            {
                Title = "添加弹窗拦截规则",
                Content = new StackPanel
                {
                    Spacing = 12,
                    Children =
                    {
                        new TextBlock { Text = "弹窗标题", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        titleBox,
                        new TextBlock { Text = "进程名称", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        processBox,
                        new TextBlock { Text = "是否启用", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        enabledToggle
                    }
                },
                PrimaryButtonText = "添加",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme()
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
            if (string.IsNullOrWhiteSpace(titleBox.Text)) return;

            var rule = new PopupRule
            {
                Title = titleBox.Text.Trim(),
                ProcessName = string.IsNullOrWhiteSpace(processBox.Text) ? "*" : processBox.Text.Trim(),
                IsEnabled = enabledToggle.IsOn
            };

            _rules.Add(rule);
            ApplyFilter();
            UpdateMonitoring();

            if (MasterToggle.IsOn && !_isMonitoring)
                StartMonitoring();
        }

        private async void DeletePopupRule_Click(object sender, RoutedEventArgs e)
        {
            var rule = GetRuleFromSender(sender);
            if (rule == null) return;

            var confirm = new ContentDialog
            {
                Title = "删除规则",
                Content = $"确定要删除规则 \"{rule.Title}\" 吗？",
                PrimaryButtonText = "删除",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme()
            };

            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

            _rules.Remove(rule);
            ApplyFilter();
            UpdateMonitoring();
        }

        private async void EditPopupRule_Click(object sender, RoutedEventArgs e)
        {
            var rule = GetRuleFromSender(sender);
            if (rule == null) return;

            var titleBox = new TextBox { Text = rule.Title };
            var processBox = new TextBox { Text = rule.ProcessName };
            var enabledToggle = new ToggleSwitch { IsOn = rule.IsEnabled };

            var dialog = new ContentDialog
            {
                Title = "编辑弹窗拦截规则",
                Content = new StackPanel
                {
                    Spacing = 12,
                    Children =
                    {
                        new TextBlock { Text = "弹窗标题", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        titleBox,
                        new TextBlock { Text = "进程名称", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        processBox,
                        new TextBlock { Text = "是否启用", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        enabledToggle
                    }
                },
                PrimaryButtonText = "保存",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = GetDialogTheme()
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
            if (string.IsNullOrWhiteSpace(titleBox.Text)) return;

            rule.Title = titleBox.Text.Trim();
            rule.ProcessName = string.IsNullOrWhiteSpace(processBox.Text) ? "*" : processBox.Text.Trim();
            rule.IsEnabled = enabledToggle.IsOn;

            ApplyFilter();
            UpdateMonitoring();
        }

        private void PopupRuleToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggle && toggle.DataContext is PopupRule rule)
            {
                rule.IsEnabled = toggle.IsOn;
                UpdateMonitoring();
            }
        }

        private PopupRule? GetRuleFromSender(object sender)
        {
            if (sender is MenuFlyoutItem menuItem)
                return menuItem.DataContext as PopupRule;
            return PopupRuleList.SelectedItem as PopupRule;
        }

        private ElementTheme GetDialogTheme()
            => (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default;
    }

    public sealed class PopupRule
    {
        public string Title { get; set; } = "";
        public string ProcessName { get; set; } = "*";
        public bool IsEnabled { get; set; } = true;
        public string Status => IsEnabled ? "已启用" : "已禁用";
    }

    public sealed class PopupBlockerEngine
    {
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private volatile List<PopupRule> _activeRules = [];

        public void Start(List<PopupRule> rules)
        {
            Stop();
            _activeRules = new List<PopupRule>(rules);
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
        }

        public void Stop()
        {
            if (_cts == null) return;

            _cts.Cancel();
            _monitorTask?.Wait(2000);
            _cts.Dispose();
            _cts = null;
            _monitorTask = null;
        }

        public void UpdateRules(List<PopupRule> rules)
            => _activeRules = new List<PopupRule>(rules);

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var currentRules = _activeRules;

                    await Task.Run(() =>
                    {
                        EnumWindows((hWnd, _) =>
                        {
                            if (!IsWindowVisible(hWnd) || IsIconic(hWnd))
                                return true;

                            var title = GetWindowText(hWnd);
                            if (string.IsNullOrEmpty(title))
                                return true;

                            var processName = GetWindowProcessName(hWnd);

                            foreach (var rule in currentRules)
                            {
                                if (title.Contains(rule.Title, StringComparison.OrdinalIgnoreCase) &&
                                    (rule.ProcessName == "*" || processName.Contains(rule.ProcessName, StringComparison.OrdinalIgnoreCase)))
                                {
                                    PostMessage(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                                    break;
                                }
                            }

                            return true;
                        }, IntPtr.Zero);
                    }, token);
                }
                catch (OperationCanceledException) { break; }
                catch { }

                try
                {
                    await Task.Delay(500, token);
                }
                catch (OperationCanceledException) { break; }
            }
        }

        private static string GetWindowText(IntPtr hWnd)
        {
            int length = GetWindowTextLength(hWnd);
            if (length == 0) return string.Empty;

            var builder = new StringBuilder(length + 1);
            GetWindowText(hWnd, builder, builder.Capacity);
            return builder.ToString();
        }

        private static string GetWindowProcessName(IntPtr hWnd)
        {
            GetWindowThreadProcessId(hWnd, out uint pid);
            try
            {
                using var process = Process.GetProcessById((int)pid);
                return process.ProcessName + ".exe";
            }
            catch
            {
                return "unknown.exe";
            }
        }

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private const uint WM_CLOSE = 0x0010;
    }
}
