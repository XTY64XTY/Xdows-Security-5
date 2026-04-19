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
    public class TitleBarMenuHelper : INotifyPropertyChanged
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

        public MenuFlyout? MenuFlyout { get; private set; }

        public Window? OwnerWindow { get; private set; }

        public static TitleBarMenuHelper Create(Window ownerWindow, MenuFlyout menuFlyout)
        {
            var helper = new TitleBarMenuHelper();
            helper.OwnerWindow = ownerWindow;
            helper.MenuFlyout = menuFlyout;
            helper.Initialize();
            return helper;
        }

        private void Initialize()
        {
            overlappedPresenter = OwnerWindow!.AppWindow.Presenter as OverlappedPresenter;
            IsWindowMaximized = overlappedPresenter!.State is OverlappedPresenterState.Maximized;
            contentCoordinateConverter = ContentCoordinateConverter.CreateForWindowId(OwnerWindow.AppWindow.Id);

            mainWindowSubClassProc = new SUBCLASSPROC(MainWindowSubClassProc);
            Comctl32Library.SetWindowSubclass((nint)OwnerWindow.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(mainWindowSubClassProc), 0, 0);

            nint inputNonClientPointerSourceHandle = User32Library.FindWindowEx((nint)OwnerWindow.AppWindow.Id.Value, 0, "InputNonClientPointerSource", null);
            if (inputNonClientPointerSourceHandle != 0)
            {
                inputNonClientPointerSourceSubClassProc = new SUBCLASSPROC(InputNonClientPointerSourceSubClassProc);
                Comctl32Library.SetWindowSubclass((nint)OwnerWindow.AppWindow.Id.Value, Marshal.GetFunctionPointerForDelegate(inputNonClientPointerSourceSubClassProc), 0, 0);
            }

            OwnerWindow.AppWindow.Changed += OnAppWindowChanged;
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

        public void OnRestoreClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter.Restore();
        }

        public void OnMoveClicked(object sender, RoutedEventArgs args)
        {
            MenuFlyoutItem menuItem = sender as MenuFlyoutItem;
            if (menuItem.Tag is not null)
            {
                ((MenuFlyout)menuItem.Tag).Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF010, 0);
            }
        }

        public void OnSizeClicked(object sender, RoutedEventArgs args)
        {
            MenuFlyoutItem menuItem = sender as MenuFlyoutItem;
            if (menuItem.Tag is not null)
            {
                ((MenuFlyout)menuItem.Tag).Hide();
                User32Library.SendMessage((nint)OwnerWindow.AppWindow.Id.Value, WindowMessage.WM_SYSCOMMAND, 0xF000, 0);
            }
        }

        public void OnMinimizeClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter.Minimize();
        }

        public void OnMaximizeClicked(object sender, RoutedEventArgs args)
        {
            overlappedPresenter.Maximize();
        }

        public void OnCloseClicked(object sender, RoutedEventArgs args)
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
                    FlyoutShowOptions options = new()
                    {
                        Position = new Point(0, 15),
                        ShowMode = FlyoutShowMode.Standard
                    };
                    MenuFlyout.ShowAt(null, options);
                    return 0;
                }
                else if (sysCommand is SYSTEMCOMMAND.SC_KEYMENU)
                {
                    FlyoutShowOptions options = new()
                    {
                        Position = new Point(0, 45),
                        ShowMode = FlyoutShowMode.Standard
                    };
                    MenuFlyout.ShowAt(null, options);
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
                            Point localPoint = contentCoordinateConverter.ConvertScreenToLocal(screenPoint);

                            FlyoutShowOptions options = new()
                            {
                                ShowMode = FlyoutShowMode.Standard,
                                Position = Helper.InfoHelper.SystemVersion.Build >= 22000 ? new Point(localPoint.X / OwnerWindow.Content.XamlRoot.RasterizationScale, localPoint.Y / OwnerWindow.Content.XamlRoot.RasterizationScale) : new Point(localPoint.X, localPoint.Y)
                            };

                            MenuFlyout.ShowAt(null, options);
                        }
                        return 0;
                    }
            }
            return Comctl32Library.DefSubclassProc(hWnd, Msg, wParam, lParam);
        }
    }
}
