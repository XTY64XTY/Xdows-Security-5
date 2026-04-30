using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Xdows_Security.Views
{
    public sealed partial class CommandPromptView : UserControl
    {
        private readonly StringBuilder _outputBuilder = new();
        private Process? _cmdProcess;
        private bool _isRunning;
        private readonly List<string> _commandHistory = [];
        private int _historyIndex = -1;
        private string _currentInput = "";

        public CommandPromptView()
        {
            InitializeComponent();
        }

        private void EnsureCmdStarted()
        {
            if (_cmdProcess != null && !_cmdProcess.HasExited) return;

            _outputBuilder.Clear();
            CmdOutput.Text = "命令提示符已就绪，请输入命令。";

            _cmdProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/k chcp 65001 >nul",
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                },
                EnableRaisingEvents = true
            };

            _cmdProcess.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) AppendOutput(e.Data);
            };

            _cmdProcess.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null) AppendOutput(e.Data);
            };

            _cmdProcess.Exited += (_, _) =>
            {
                _isRunning = false;
                AppendOutput("\r\n[进程已退出]");
            };

            _cmdProcess.Start();
            _cmdProcess.BeginOutputReadLine();
            _cmdProcess.BeginErrorReadLine();
            _isRunning = true;
        }

        private void AppendOutput(string text)
        {
            _ = DispatcherQueue.TryEnqueue(() =>
            {
                _outputBuilder.AppendLine(text);
                CmdOutput.Text = _outputBuilder.ToString();
                OutputScrollViewer.ChangeView(null, OutputScrollViewer.ScrollableHeight, null);
            });
        }

        private void ExecuteCommand()
        {
            var cmd = CmdInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(cmd)) return;

            if (!_isRunning || _cmdProcess?.HasExited != false)
                EnsureCmdStarted();

            if (_commandHistory.Count == 0 || _commandHistory[^1] != cmd)
                _commandHistory.Add(cmd);

            _historyIndex = -1;
            _currentInput = "";

            try
            {
                _cmdProcess!.StandardInput.WriteLine(cmd);
            }
            catch { }

            CmdInput.Text = string.Empty;
        }

        private void ExecuteButton_Click(object sender, RoutedEventArgs e)
            => ExecuteCommand();

        private void CmdInput_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                e.Handled = true;
                ExecuteCommand();
            }
            else if (e.Key == Windows.System.VirtualKey.Up)
            {
                e.Handled = true;
                NavigateHistory(-1);
            }
            else if (e.Key == Windows.System.VirtualKey.Down)
            {
                e.Handled = true;
                NavigateHistory(1);
            }
        }

        private void NavigateHistory(int direction)
        {
            if (_commandHistory.Count == 0) return;

            if (_historyIndex == -1)
                _currentInput = CmdInput.Text;

            var newIndex = _historyIndex + direction;

            if (newIndex < -1 || newIndex >= _commandHistory.Count) return;

            _historyIndex = newIndex;

            CmdInput.Text = _historyIndex == -1
                ? _currentInput
                : _commandHistory[_commandHistory.Count - 1 - _historyIndex];

            CmdInput.Select(CmdInput.Text.Length, 0);
        }

        private void ClearOutput_Click(object sender, RoutedEventArgs e)
        {
            _outputBuilder.Clear();
            CmdOutput.Text = string.Empty;
        }

        private void CopyOutput_Click(object sender, RoutedEventArgs e)
        {
            var dp = new Windows.ApplicationModel.DataTransfer.DataPackage();
            dp.SetText(CmdOutput.Text);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dp);
        }

        private void RestartCmd_Click(object sender, RoutedEventArgs e)
        {
            if (_cmdProcess != null && !_cmdProcess.HasExited)
            {
                try
                {
                    _cmdProcess.Kill();
                }
                catch { }
            }

            _isRunning = false;
            EnsureCmdStarted();
        }
    }
}
