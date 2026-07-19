using Helper;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using Windows.Graphics;
using WinUI3Localizer;
using static Helper.InterceptWindowHelper;

namespace Xdows_Security;

public sealed partial class SmallThreatNotificationWindow : Window
{
    private const int ExtendedWindowStyleIndex = -20;
    private const int NoActivateStyle = 0x08000000;
    private const int ToolWindowStyle = 0x00000080;
    private const int ShowWithoutActivation = 4;
    private const uint NoActivatePosition = 0x0010;
    private const uint ShowWindowPosition = 0x0040;
    private const int AutoDismissSeconds = 8;
    private static readonly IntPtr TopMostWindow = new(-1);

    private static SmallThreatNotificationWindow? _current;
    private readonly DispatcherTimer _dismissTimer;
    private readonly SystemBackdropConfiguration _backdropConfiguration = new() { IsInputActive = true };
    private MicaController? _micaController;
    private ICompositionSupportsSystemBackdrop? _backdropTarget;
    private InterceptWindowSetting _setting;

    private SmallThreatNotificationWindow(InterceptWindowSetting setting)
    {
        InitializeComponent();
        _setting = setting;

        var manager = WinUIEx.WindowManager.Get(this);
        manager.Width = 360;
        manager.Height = 104;
        manager.MinWidth = 360;
        manager.MinHeight = 104;
        manager.IsMaximizable = false;
        manager.IsMinimizable = false;
        manager.IsResizable = false;
        manager.IsTitleBarVisible = false;
        manager.IsAlwaysOnTop = true;

        ApplyNonActivatingWindowStyles();
        ApplyAlwaysActiveMica();
        UpdateContent(setting);

        _dismissTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(AutoDismissSeconds) };
        _dismissTimer.Tick += DismissTimer_Tick;
        Closed += SmallThreatNotificationWindow_Closed;
        Localizer.Get().LanguageChanged += OnLanguageChanged;
    }

    internal static void ShowOrUpdate(InterceptWindowSetting setting)
    {
        if (_current is not null)
        {
            _current.UpdateContent(setting);
            _current.ShowWithoutTakingFocus();
            return;
        }

        _current = new SmallThreatNotificationWindow(setting);
        _current.ShowWithoutTakingFocus();
    }

    private void UpdateContent(InterceptWindowSetting setting)
    {
        _setting = setting;
        var localizer = Localizer.Get();
        string titleKey = setting.IsSucceed
            ? "SmallThreatNotification_Handled_Title"
            : "SmallThreatNotification_Failed_Title";
        string programName = Path.GetFileName(setting.Path);
        if (string.IsNullOrWhiteSpace(programName))
            programName = setting.Path;
        string detectionName = string.IsNullOrWhiteSpace(setting.DetectionName)
            ? "Xdows.Model.Threat"
            : setting.DetectionName;

        TitleText.Text = localizer.GetLocalizedString(titleKey);
        DetailText.Text = string.Format(
            CultureInfo.CurrentCulture,
            localizer.GetLocalizedString("SmallThreatNotification_Detail_Format"),
            programName,
            detectionName);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            NotificationButton,
            localizer.GetLocalizedString("SmallThreatNotification_AutomationName"));
    }

    private void ShowWithoutTakingFocus()
    {
        PositionAtBottomRight();
        IntPtr hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        _ = ShowWindow(hwnd, ShowWithoutActivation);
        _ = SetWindowPos(
            hwnd,
            TopMostWindow,
            AppWindow.Position.X,
            AppWindow.Position.Y,
            AppWindow.Size.Width,
            AppWindow.Size.Height,
            NoActivatePosition | ShowWindowPosition);
        _dismissTimer.Stop();
        _dismissTimer.Start();
    }

    private void ApplyNonActivatingWindowStyles()
    {
        IntPtr hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        int styles = GetWindowLong(hwnd, ExtendedWindowStyleIndex);
        _ = SetWindowLong(hwnd, ExtendedWindowStyleIndex, styles | NoActivateStyle | ToolWindowStyle);
    }

    private void ApplyAlwaysActiveMica()
    {
        if (!MicaController.IsSupported())
        {
            SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();
            return;
        }

        _backdropConfiguration.Theme = App.Theme switch
        {
            ElementTheme.Light => SystemBackdropTheme.Light,
            ElementTheme.Dark => SystemBackdropTheme.Dark,
            _ => SystemBackdropTheme.Default
        };
        _backdropTarget = (ICompositionSupportsSystemBackdrop)(object)this;
        _micaController = new MicaController();
        _micaController.AddSystemBackdropTarget(_backdropTarget);
        _micaController.SetSystemBackdropConfiguration(_backdropConfiguration);
    }

    private void PositionAtBottomRight()
    {
        try
        {
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                AppWindow.Id,
                Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            if (displayArea is null)
                return;

            var workArea = displayArea.WorkArea;
            int x = workArea.X + workArea.Width - AppWindow.Size.Width - 16;
            int y = workArea.Y + workArea.Height - AppWindow.Size.Height - 16;
            AppWindow.Move(new PointInt32(x, y));
        }
        catch
        {
        }
    }

    private void OnLanguageChanged(object? sender, LanguageChangedEventArgs e)
    {
        DispatcherQueue.TryEnqueue(() => UpdateContent(_setting));
    }

    private void DismissTimer_Tick(object? sender, object e)
    {
        _dismissTimer.Stop();
        Close();
    }

    private void SmallThreatNotificationWindow_Closed(object sender, WindowEventArgs args)
    {
        _dismissTimer.Stop();
        _dismissTimer.Tick -= DismissTimer_Tick;
        Localizer.Get().LanguageChanged -= OnLanguageChanged;
        if (_micaController is not null && _backdropTarget is not null)
            _micaController.RemoveSystemBackdropTarget(_backdropTarget);
        _micaController?.Dispose();
        _micaController = null;
        _backdropTarget = null;
        Closed -= SmallThreatNotificationWindow_Closed;
        if (ReferenceEquals(_current, this))
            _current = null;
    }

    private void NotificationButton_Click(object sender, RoutedEventArgs e)
    {
        InterceptWindowSetting setting = _setting;
        _dismissTimer.Stop();
        Close();
        _ = InterceptWindow.ShowOrActivate(setting);
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hwnd, int index);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int SetWindowLong(IntPtr hwnd, int index, int newStyle);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hwnd, int command);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(
        IntPtr hwnd,
        IntPtr insertAfter,
        int x,
        int y,
        int width,
        int height,
        uint flags);
}
