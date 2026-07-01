using Helper.PInvoke.Comctl32;
using Helper.PInvoke.User32;
using Microsoft.UI.Content;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Foundation;
using Windows.Graphics;

namespace Xdows_Security
{
    public sealed partial class TitleBarMenu : UserControl, INotifyPropertyChanged
    {
        private SUBCLASSPROC? mainWindowSubClassProc;
        private SUBCLASSPROC? inputNonClientPointerSourceSubClassProc;
        private ContentCoordinateConverter? contentCoordinateConverter;
        private OverlappedPresenter? overlappedPresenter;

        private bool _isWindowMaximized;

        public bool IsWindowMaximized
        {
            get { return _isWindowMaximized; }
            set
            {
                if (!Equals(_isWindowMaximized, value))
                {
                    _isWindowMaximized = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsWindowMaximized)));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public static readonly DependencyProperty OwnerWindowProperty =
            DependencyProperty.Register("OwnerWindow", typeof(Window), typeof(TitleBarMenu), new PropertyMetadata(null!, OnOwnerWindowChanged));

        public Window OwnerWindow
        {
            get { return (Window)GetValue(OwnerWindowProperty); }
            set { SetValue(OwnerWindowProperty, value); }
        }

        public MenuFlyout? MenuFlyout { get; private set; }

        /// <summary>
        /// 标题栏图标元素，用于 NC 双击关闭窗口的命中测试。
        /// </summary>
        public FrameworkElement? IconElement { get; set; }

        public TitleBarMenu()
        {
            this.InitializeComponent();
            this.Loaded += (s, e) =>
            {
                MenuFlyout = FindName("TitlebarMenuFlyout") as MenuFlyout;
            };
        }

        /// <summary>
        /// 在指定本地坐标处显示自定义标题栏菜单。用于标题栏区域的右键交互。
        /// </summary>
        public void ShowMenuAtPoint(Point localPoint)
        {
            if (MenuFlyout is null)
                return;

            if (MenuFlyout.IsOpen)
            {
                MenuFlyout.Hide();
                return;
            }

            FlyoutShowOptions options = new()
            {
                Position = localPoint,
                ShowMode = FlyoutShowMode.Standard
            };
            MenuFlyout.ShowAt(this, options);
        }

        private static void OnOwnerWindowChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var menu = (TitleBarMenu)d;
            if (e.NewValue is Window window)
            {
                menu.Initialize(window);
            }
        }

        private void Initialize(Window ownerWindow)
        {
            overlappedPresenter = ownerWindow.AppWindow.Presenter as OverlappedPresenter;
            IsWindowMaximized = overlappedPresenter!.State is OverlappedPresenterState.Maximized;
            contentCoordinateConverter = ContentCoordinateConverter.CreateForWindowId(ownerWindow.AppWindow.Id);

            mainWindowSubClassProc = new SUBCLASSPROC(MainWindowSubClassProc);
            Comctl32Library.SetWindowSubclass((nint)ownerWindow.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(mainWindowSubClassProc), 0, 0);

            nint inputNonClientPointerSourceHandle = User32Library.FindWindowEx((nint)ownerWindow.AppWindow.Id.Value, 0, "InputNonClientPointerSource", lpszWindow: null!);
            if (inputNonClientPointerSourceHandle != 0)
            {
                inputNonClientPointerSourceSubClassProc = new SUBCLASSPROC(InputNonClientPointerSourceSubClassProc);
                Comctl32Library.SetWindowSubclass((nint)ownerWindow.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(inputNonClientPointerSourceSubClassProc), 0, 0);
            }

            ownerWindow.AppWindow.Changed += OnAppWindowChanged;
            ownerWindow.Activated += OnOwnerWindowActivated;
        }

        private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
        {
            if (args.DidPositionChange)
            {
                if (MenuFlyout is not null && MenuFlyout.IsOpen)
                {
                    MenuFlyout.Hide();
                }

                if (overlappedPresenter is not null)
                {
                    IsWindowMaximized = overlappedPresenter.State is OverlappedPresenterState.Maximized;
                }
            }
        }

        private void OnOwnerWindowActivated(object sender, WindowActivatedEventArgs args)
        {
            if (args.WindowActivationState != WindowActivationState.Deactivated)
            {
                DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
                {
                    nint hwnd = (nint)OwnerWindow.AppWindow.Id.Value;
                    var pos = OwnerWindow.AppWindow.Position;
                    var size = OwnerWindow.AppWindow.Size;
                    int x = pos.X + size.Width / 2;
                    int y = pos.Y + 24;
                    nint lParam = (nint)((y << 16) | (x & 0xFFFF));
                    User32Library.SendMessage(hwnd, WindowMessage.WM_NCMOUSEMOVE, 2, lParam);
                });
            }
        }

        internal void OnRestoreClicked(object _, RoutedEventArgs __)
        {
            overlappedPresenter!.Restore();
        }

        internal void OnMoveClicked(object sender, RoutedEventArgs _)
        {
            var menuItem = sender as MenuFlyoutItem;
            if (menuItem?.Tag is not null)
            {
                (menuItem?.Tag as MenuFlyout)?.Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF010, 0);
            }
        }

        internal void OnSizeClicked(object sender, RoutedEventArgs _)
        {
            var menuItem = sender as MenuFlyoutItem;
            if (menuItem?.Tag is not null)
            {
                (menuItem?.Tag as MenuFlyout)?.Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF000, 0);
            }
        }

        internal void OnMinimizeClicked(object _, RoutedEventArgs __)
        {
            overlappedPresenter!.Minimize();
        }

        internal void OnMaximizeClicked(object _, RoutedEventArgs __)
        {
            overlappedPresenter!.Maximize();
        }

        internal void OnCloseClicked(object _, RoutedEventArgs __)
        {
            // 发送 SC_CLOSE 系统命令，与点击标题栏 X 按钮一致，
            // 触发 AppWindow.Closing 事件以走托盘隐藏/关闭验证流程
            User32Library.SendMessage(
                (nint)OwnerWindow.AppWindow.Id.Value,
                WindowMessage.WM_SYSCOMMAND,
                (int)SYSTEMCOMMAND.SC_CLOSE,
                0);
        }

        private nint MainWindowSubClassProc(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam, uint uIdSubclass, nint dwRefData)
        {
            if (Msg is WindowMessage.WM_SYSCOMMAND)
            {
                SYSTEMCOMMAND sysCommand = (SYSTEMCOMMAND)(wParam.ToUInt32() & 0xFFF0);

                if (sysCommand is SYSTEMCOMMAND.SC_MOUSEMENU)
                {
                    if (MenuFlyout is not null)
                    {
                        FlyoutShowOptions options = new()
                        {
                            Position = new Point(0, 15),
                            ShowMode = FlyoutShowMode.Standard
                        };
                        MenuFlyout.ShowAt(this, options);
                    }
                    return 0;
                }
                else if (sysCommand is SYSTEMCOMMAND.SC_KEYMENU)
                {
                    if (MenuFlyout is not null)
                    {
                        FlyoutShowOptions options = new()
                        {
                            Position = new Point(0, 45),
                            ShowMode = FlyoutShowMode.Standard
                        };
                        MenuFlyout.ShowAt(this, options);
                    }
                    return 0;
                }
            }

            return Comctl32Library.DefSubclassProc(hWnd, Msg, wParam, lParam);
        }

        private nint InputNonClientPointerSourceSubClassProc(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam, uint uIdSubclass, nint dwRefData)
        {
            switch (Msg)
            {
                case WindowMessage.WM_NCLBUTTONDOWN:
                    {
                        if (MenuFlyout is not null && MenuFlyout.IsOpen)
                        {
                            MenuFlyout.Hide();
                        }
                        break;
                    }
                case WindowMessage.WM_NCRBUTTONUP:
                    {
                        if (wParam.ToUInt32() is 2 && OwnerWindow.Content is not null && OwnerWindow.Content.XamlRoot is not null)
                        {
                            PointInt32 screenPoint = new(lParam.ToInt32() & 0xFFFF, lParam.ToInt32() >> 16);
                            Point localPoint = contentCoordinateConverter!.ConvertScreenToLocal(screenPoint);

                            if (MenuFlyout is not null)
                            {
                                FlyoutShowOptions options = new()
                                {
                                    ShowMode = FlyoutShowMode.Standard,
                                    Position = Helper.InfoHelper.SystemVersion.Build >= 22000 ? new Point(localPoint.X / OwnerWindow.Content.XamlRoot.RasterizationScale, localPoint.Y / OwnerWindow.Content.XamlRoot.RasterizationScale) : new Point(localPoint.X, localPoint.Y)
                                };

                                MenuFlyout.ShowAt(this, options);
                            }
                        }
                        return 0;
                    }
                case WindowMessage.WM_NCLBUTTONDBLCLK:
                    {
                        // 双击标题栏图标区域 → 关闭窗口（走托盘隐藏/关闭验证流程）
                        if (IconElement is not null && OwnerWindow.Content?.XamlRoot is not null && contentCoordinateConverter is not null)
                        {
                            PointInt32 screenPoint = new(lParam.ToInt32() & 0xFFFF, lParam.ToInt32() >> 16);
                            Point localPoint = contentCoordinateConverter.ConvertScreenToLocal(screenPoint);
                            double scale = OwnerWindow.Content.XamlRoot.RasterizationScale;
                            Point xamlPoint = Helper.InfoHelper.SystemVersion.Build >= 22000
                                ? new Point(localPoint.X / scale, localPoint.Y / scale)
                                : new Point(localPoint.X, localPoint.Y);

                            GeneralTransform transform = IconElement.TransformToVisual(null);
                            Rect iconRect = transform.TransformBounds(new Rect(0, 0, IconElement.ActualWidth, IconElement.ActualHeight));

                            if (xamlPoint.X >= iconRect.X && xamlPoint.X <= iconRect.X + iconRect.Width &&
                                xamlPoint.Y >= iconRect.Y && xamlPoint.Y <= iconRect.Y + iconRect.Height)
                            {
                                User32Library.SendMessage(
                                    (nint)OwnerWindow.AppWindow.Id.Value,
                                    WindowMessage.WM_SYSCOMMAND,
                                    (int)SYSTEMCOMMAND.SC_CLOSE,
                                    0);
                                return 0;
                            }
                        }
                        break;
                    }
            }
            return Comctl32Library.DefSubclassProc(hWnd, Msg, wParam, lParam);
        }
    }
}
