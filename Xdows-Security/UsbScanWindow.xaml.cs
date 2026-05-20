using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using System;
using System.Collections.Generic;
using System.IO;
using Xdows_Security.Services;
using WinUI3Localizer;

namespace Xdows_Security;

public sealed partial class UsbScanWindow : Window
{
    private readonly string _driveLetter;
    private readonly string _driveLabel;
    private readonly DispatcherQueueTimer _autoCloseTimer;
    private List<UsbScanThreatInfo>? _threats;

    public UsbScanWindow(string driveLetter, string driveLabel)
    {
        this.InitializeComponent();
        _driveLetter = driveLetter;
        _driveLabel = driveLabel;

        var manager = WinUIEx.WindowManager.Get(this);
        manager.MinWidth = 340;
        manager.MinHeight = 260;
        manager.Width = 380;
        manager.IsMaximizable = false;
        manager.IsMinimizable = false;
        manager.IsResizable = false;
        manager.IsTitleBarVisible = false;
        manager.IsAlwaysOnTop = true;
        this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();

        DeviceNameText.Text = driveLabel;
        StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Scanning");
        FilesScannedText.Text = "0";
        ThreatsFoundText.Text = "0";

        _autoCloseTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _autoCloseTimer.Interval = TimeSpan.FromSeconds(5);
        _autoCloseTimer.Tick += (_, _) =>
        {
            _autoCloseTimer.Stop();
            this.Close();
        };

        UsbScanService.Instance.ProgressChanged += OnProgressChanged;
        UsbScanService.Instance.ScanCompleted += OnScanCompleted;

        this.Closed += OnWindowClosed;

        RootPanel.Loaded += (_, _) =>
        {
            DispatcherQueue.TryEnqueue(() => UpdateWindowHeightAndPosition());
        };

        PositionWindowAtBottomRight();
        App.PlayEntranceAnimation(RootPanel, "right");
    }

    private void OnWindowClosed(object sender, WindowEventArgs args)
    {
        UsbScanService.Instance.ProgressChanged -= OnProgressChanged;
        UsbScanService.Instance.ScanCompleted -= OnScanCompleted;

        if (UsbScanService.Instance.IsScanning && !UsbScanService.Instance.IsPaused)
        {
            UsbScanService.Instance.CancelDrive(_driveLetter);
        }

        _autoCloseTimer.Stop();
    }

    private void OnProgressChanged(object? sender, UsbScanProgressEventArgs e)
    {
        if (e.DriveLetter != _driveLetter) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            FilesScannedText.Text = e.FilesScanned.ToString();
            ThreatsFoundText.Text = e.ThreatsFound.ToString();
            if (e.TotalFiles > 0)
            {
                ScanProgressBar.IsIndeterminate = false;
                ScanProgressBar.Value = e.TotalFiles > 0 ? (double)e.FilesScanned / e.TotalFiles * 100 : 0;
            }
            if (e.IsPaused)
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Paused");
                PauseButton.Content = Localizer.Get().GetLocalizedString("UsbScanWindow_Resume");
            }
            else
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Scanning");
                PauseButton.Content = Localizer.Get().GetLocalizedString("UsbScanWindow_Pause");
            }
        });
    }

    private void OnScanCompleted(object? sender, UsbScanProgressEventArgs e)
    {
        if (e.DriveLetter != _driveLetter) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            UsbScanService.Instance.ProgressChanged -= OnProgressChanged;
            UsbScanService.Instance.ScanCompleted -= OnScanCompleted;

            ScanControlPanel.Visibility = Visibility.Collapsed;
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;

            _threats = e.Threats;

            if (e.IsCancelled)
            {
                StatusIcon.Glyph = "\uE711";
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Cancelled");
                ResultBorder.Visibility = Visibility.Visible;
                ResultBorder.Background =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCautionBackgroundBrush"];
                ResultBorder.BorderBrush =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCautionBrush"];
                ResultTitleText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Cancelled");
                _autoCloseTimer.Start();
                return;
            }

            if (e.ThreatsFound > 0)
            {
                StatusIcon.Glyph = "\uE7BA";
                StatusIcon.Foreground =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBrush"];
                StatusText.Text = string.Format(
                    Localizer.Get().GetLocalizedString("UsbScanWindow_Status_ThreatsFound"),
                    e.ThreatsFound);
                ResultBorder.Visibility = Visibility.Visible;
                ResultBorder.Background =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBackgroundBrush"];
                ResultBorder.BorderBrush =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorCriticalBrush"];
                ResultTitleText.Text = string.Format(
                    Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Threats"),
                    e.ThreatsFound);
                ResultDetailText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_ThreatsDetail");
                ViewThreatsButton.Visibility = Visibility.Visible;
            }
            else
            {
                StatusIcon.Glyph = "\uE73E";
                StatusIcon.Foreground =
                    (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SystemFillColorSuccessBrush"];
                StatusText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Status_Safe");
                ResultBorder.Visibility = Visibility.Visible;
                ResultTitleText.Text = Localizer.Get().GetLocalizedString("UsbScanWindow_Result_Safe");
                _autoCloseTimer.Start();
            }

            UpdateWindowHeightAndPosition();
        });
    }

    private void PauseButton_Click(object sender, RoutedEventArgs e)
    {
        if (UsbScanService.Instance.IsPaused)
            UsbScanService.Instance.Resume();
        else
            UsbScanService.Instance.Pause();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        UsbScanService.Instance.Cancel();
    }

    private void OpenDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"{_driveLetter}:\\",
                UseShellExecute = true
            });
        }
        catch { }
    }

    private void ViewThreatsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (App.MainWindow != null)
            {
                App.MainWindow.Activate();
                App.MainWindow.GoToPage("Security");
            }
        }
        catch { }
    }

    private void UpdateWindowHeightAndPosition()
    {
        try
        {
            var manager = WinUIEx.WindowManager.Get(this);
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea == null) return;

            var workArea = displayArea.WorkArea;
            double desiredHeight = RootPanel.ActualHeight;
            double minHeight = manager.MinHeight;
            double maxHeight = Math.Max(minHeight, workArea.Height - 16);
            double newHeight = Math.Clamp(desiredHeight, minHeight, maxHeight);
            int newHeightInt = (int)Math.Ceiling(newHeight);
            if (manager.Height != newHeightInt) manager.Height = newHeightInt;
            PositionWindowAtBottomRight();
        }
        catch { }
    }

    private void PositionWindowAtBottomRight()
    {
        try
        {
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea != null)
            {
                var workArea = displayArea.WorkArea;
                var windowWidth = AppWindow.Size.Width;
                var windowHeight = AppWindow.Size.Height;
                var x = workArea.Width - windowWidth - 20;
                var y = workArea.Height - windowHeight - 8;
                this.AppWindow.Move(new Windows.Graphics.PointInt32(x, y));
            }
        }
        catch { }
    }
}
