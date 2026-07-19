using Helper;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using System;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using Windows.Graphics;
using Windows.UI.ViewManagement;
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
    private static readonly TimeSpan EntranceAnimationDuration = TimeSpan.FromMilliseconds(220);
    private static readonly TimeSpan ExitAnimationDuration = TimeSpan.FromMilliseconds(160);
    private static readonly IntPtr TopMostWindow = new(-1);

    private static SmallThreatNotificationWindow? _current;
    private readonly DispatcherTimer _dismissTimer;
    private readonly SystemBackdropConfiguration _backdropConfiguration = new() { IsInputActive = true };
    private MicaController? _micaController;
    private ICompositionSupportsSystemBackdrop? _backdropTarget;
    private InterceptWindowSetting _setting;
    private int _animationGeneration;
    private bool _isClosing;

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
        _isClosing = false;
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
        PlayEntranceAnimation();
        _dismissTimer.Stop();
        _dismissTimer.Start();
    }

    private void PlayEntranceAnimation()
    {
        int generation = ++_animationGeneration;
        Visual visual = ElementCompositionPreview.GetElementVisual(RootGrid);
        visual.StopAnimation("Offset");
        visual.StopAnimation("Opacity");
        visual.Offset = Vector3.Zero;
        visual.Opacity = 1;

        if (!AreAnimationsEnabled())
            return;

        Compositor compositor = visual.Compositor;
        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));
        Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
        offsetAnimation.InsertKeyFrame(0, new Vector3(32, 0, 0));
        offsetAnimation.InsertKeyFrame(1, Vector3.Zero, easing);
        offsetAnimation.Duration = EntranceAnimationDuration;

        ScalarKeyFrameAnimation opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
        opacityAnimation.InsertKeyFrame(0, 0);
        opacityAnimation.InsertKeyFrame(1, 1, easing);
        opacityAnimation.Duration = EntranceAnimationDuration;

        CompositionScopedBatch batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        visual.StartAnimation("Offset", offsetAnimation);
        visual.StartAnimation("Opacity", opacityAnimation);
        batch.End();
        batch.Completed += OnEntranceCompleted;

        void OnEntranceCompleted(object sender, CompositionBatchCompletedEventArgs args)
        {
            batch.Completed -= OnEntranceCompleted;
            if (generation != _animationGeneration || _isClosing)
                return;

            visual.Offset = Vector3.Zero;
            visual.Opacity = 1;
        }
    }

    private void BeginExitAnimation(bool openNormalNotification)
    {
        if (_isClosing)
            return;

        _isClosing = true;
        _dismissTimer.Stop();
        int generation = ++_animationGeneration;

        if (!AreAnimationsEnabled())
        {
            CompleteExit(generation, openNormalNotification);
            return;
        }

        Visual visual = ElementCompositionPreview.GetElementVisual(RootGrid);
        visual.StopAnimation("Offset");
        visual.StopAnimation("Opacity");
        visual.Offset = Vector3.Zero;
        visual.Opacity = 1;

        Compositor compositor = visual.Compositor;
        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.7f, 0),
            new Vector2(1f, 0.5f));
        Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
        offsetAnimation.InsertKeyFrame(0, Vector3.Zero);
        offsetAnimation.InsertKeyFrame(1, new Vector3(24, 0, 0), easing);
        offsetAnimation.Duration = ExitAnimationDuration;

        ScalarKeyFrameAnimation opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
        opacityAnimation.InsertKeyFrame(0, 1);
        opacityAnimation.InsertKeyFrame(1, 0, easing);
        opacityAnimation.Duration = ExitAnimationDuration;

        CompositionScopedBatch batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        visual.StartAnimation("Offset", offsetAnimation);
        visual.StartAnimation("Opacity", opacityAnimation);
        batch.End();
        batch.Completed += OnExitCompleted;

        void OnExitCompleted(object sender, CompositionBatchCompletedEventArgs args)
        {
            batch.Completed -= OnExitCompleted;
            CompleteExit(generation, openNormalNotification);
        }
    }

    private void CompleteExit(int generation, bool openNormalNotification)
    {
        if (!_isClosing || generation != _animationGeneration)
            return;

        InterceptWindowSetting setting = _setting;
        Close();
        if (openNormalNotification)
            _ = InterceptWindow.ShowOrActivate(setting);
    }

    private static bool AreAnimationsEnabled()
    {
        try
        {
            return new UISettings().AnimationsEnabled;
        }
        catch
        {
            return true;
        }
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
        BeginExitAnimation(false);
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
        BeginExitAnimation(true);
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
