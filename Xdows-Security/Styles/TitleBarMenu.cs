using Microsoft.UI.Content;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Foundation;
using Windows.Graphics;
using Helper.PInvoke.Comctl32;
using Helper.PInvoke.User32;

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
            DependencyProperty.Register("OwnerWindow", typeof(Window), typeof(TitleBarMenu), new PropertyMetadata(null, OnOwnerWindowChanged));

        public Window OwnerWindow
        {
            get { return (Window)GetValue(OwnerWindowProperty); }
            set { SetValue(OwnerWindowProperty, value); }
        }

        public MenuFlyout MenuFlyout { get; private set; }

        public TitleBarMenu()
        {
            this.InitializeComponent();
            this.Loaded += (s, e) =>
            {
                MenuFlyout = FindName("TitlebarMenuFlyout") as MenuFlyout;
            };
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

            nint inputNonClientPointerSourceHandle = User32Library.FindWindowEx((nint)ownerWindow.AppWindow.Id.Value, 0, "InputNonClientPointerSource", null);
            if (inputNonClientPointerSourceHandle != 0)
            {
                inputNonClientPointerSourceSubClassProc = new SUBCLASSPROC(InputNonClientPointerSourceSubClassProc);
                Comctl32Library.SetWindowSubclass((nint)ownerWindow.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(inputNonClientPointerSourceSubClassProc), 0, 0);
            }

            ownerWindow.AppWindow.Changed += OnAppWindowChanged;
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

        internal void OnRestoreClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter!.Restore();
        }

        internal void OnMoveClicked(object sender, RoutedEventArgs args)
        {
            var menuItem = sender as MenuFlyoutItem;
            if (menuItem.Tag is not null)
            {
                ((MenuFlyout)menuItem.Tag).Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF010, 0);
            }
        }

        internal void OnSizeClicked(object sender, RoutedEventArgs args)
        {
            var menuItem = sender as MenuFlyoutItem;
            if (menuItem.Tag is not null)
            {
                ((MenuFlyout)menuItem.Tag).Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF000, 0);
            }
        }

        internal void OnMinimizeClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter!.Minimize();
        }

        internal void OnMaximizeClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter!.Maximize();
        }

        internal void OnCloseClicked(object sender, RoutedEventArgs args)
        {
            OwnerWindow.Close();
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
            }
            return Comctl32Library.DefSubclassProc(hWnd, Msg, wParam, lParam);
        }
    }
}
