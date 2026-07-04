// MainWindow backdrop and theme management (partial class)
using Microsoft.Windows.Storage;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using System;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace Xdows_Security
{
    public sealed partial class MainWindow
    {
        private string _lastBackdrop = "";
        private double _lastOpacity = 100;
        private ISystemBackdropControllerWithTargets? _controller;
        private ICompositionSupportsSystemBackdrop? _target;
        private static readonly SystemBackdropConfiguration _config = new()
        {
            IsInputActive = true
        };

        private UISettings? _uiSettings;

        public static void UpdateTheme(ElementTheme selectedTheme)
        {
            App.Theme = selectedTheme;
            var window = App.MainWindow;
            if (window is not null)
            {
                _ = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(
                    Microsoft.UI.Win32Interop.GetWindowIdFromWindow(
                         WinRT.Interop.WindowNative.GetWindowHandle(window)
                    )
                );

                var titleBar = window.AppWindow.TitleBar;
                titleBar?.ButtonForegroundColor = selectedTheme switch
                {
                    ElementTheme.Dark => Windows.UI.Color.FromArgb(255, 255, 255, 255),
                    ElementTheme.Light => Windows.UI.Color.FromArgb(255, 0, 0, 0),
                    _ => GetSystemTheme() == ApplicationTheme.Light
                        ? Windows.UI.Color.FromArgb(255, 0, 0, 0)
                        : Windows.UI.Color.FromArgb(255, 255, 255, 255)
                };
            }
            var settings = App.LocalSettings;
            string backdrop = settings.Values.TryGetValue("AppBackdrop", out object? backdropRaw) && backdropRaw is string backdropValue
                ? backdropValue
                : "Mica";
            App.MainWindow?.ApplyBackdrop(backdrop, true);
        }

        public static ApplicationTheme GetSystemTheme()
        {
            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);
            return IsLightColor(systemBackground) ? ApplicationTheme.Light : ApplicationTheme.Dark;
        }

        private static bool IsLightColor(Windows.UI.Color color)
        {
            double luminance = (0.2126 * color.R + 0.7152 * color.G + 0.0722 * color.B) / 255;
            return luminance > 0.5;
        }

        private ElementTheme GetCurrentTheme()
        {
            if (RootGrid.RequestedTheme != ElementTheme.Default)
                return RootGrid.RequestedTheme;

            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);
            return IsLightColor(systemBackground) ? ElementTheme.Light : ElementTheme.Dark;
        }

        public void ApplyBackdrop(string backdropType, bool compulsory)
        {
            try
            {
                if (RootGrid == null) return;
                var settings = App.LocalSettings;
                double opacity = settings.Values.TryGetValue("AppBackdropOpacity", out object? opacityRaw) && opacityRaw is double v ? v :
                                (opacityRaw is int i ? i : 100);
                if (!compulsory && _lastBackdrop == backdropType && _lastOpacity.Equals(opacity))
                    return;

                // 属性热更新路径：仅 opacity / Kind 等属性变化时直接更新现有 controller，
                // 避免销毁重建。这对透明度滑块频繁拖动场景尤其关键（每次值变化都会调用本方法）。
                if (TryHotUpdateBackdrop(backdropType, opacity))
                {
                    _lastBackdrop = backdropType;
                    _lastOpacity = opacity;
                    return;
                }

                CleanupBackdropResources();
                _lastBackdrop = backdropType;
                _lastOpacity = opacity;

                if (backdropType == "Solid")
                {
                    this.SystemBackdrop = null;

                    RootGrid.Background = GetCurrentTheme() == ElementTheme.Dark
                         ? new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20))
                         : new SolidColorBrush(Colors.White);
                    return;
                }

                if (backdropType is "Mica" or "MicaAlt" && !MicaController.IsSupported())
                    backdropType = "Acrylic";

                RootGrid.Background = new SolidColorBrush(Colors.Transparent);

                _target = (ICompositionSupportsSystemBackdrop)(object)this;

                switch (backdropType)
                {
                    case "Mica":
                        _controller = new MicaController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.95),
                            TintColor = GetBackgroundColor()
                        };
                        break;
                    case "MicaAlt":
                        _controller = new MicaController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.85),
                            TintColor = GetBackgroundColor(),
                            Kind = MicaKind.BaseAlt
                        };
                        break;
                    case "Acrylic":
                        _controller = new DesktopAcrylicController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.95),
                            TintColor = GetBackgroundColor()
                        };
                        break;
                    default:
                        ApplyBackdrop("Solid", compulsory);
                        return;
                }

                if (_controller != null && _target != null)
                {
                    _controller.AddSystemBackdropTarget(_target);
                    UpdateBackdropTheme();
                    _controller.SetSystemBackdropConfiguration(_config);
                }

                RegisterSystemThemeListener();
            }
            catch
            {
                ApplyBackdrop("Solid", true);
            }
        }

        /// <summary>
        /// 尝试热更新现有 controller 的属性（LuminosityOpacity / Kind），避免销毁重建。
        /// 仅当旧/新 backdrop 都是系统 backdrop 类型（非 Solid）、controller 仍存活且类型系列一致（Mica↔MicaAlt 或 Acrylic→Acrylic）时适用。
        /// 跨系列切换（Mica↔Acrylic）或涉及 Solid 时返回 false，由调用方走完整重建路径。
        /// </summary>
        private bool TryHotUpdateBackdrop(string backdropType, double opacity)
        {
            if (_controller == null || _target == null) return false;
            if (backdropType == "Solid" || _lastBackdrop == "Solid") return false;

            // 跨系列切换（Mica ↔ Acrylic）需要重建 controller
            bool lastIsMica = _lastBackdrop is "Mica" or "MicaAlt";
            bool newIsMica = backdropType is "Mica" or "MicaAlt";
            if (lastIsMica != newIsMica) return false;

            switch (_controller)
            {
                case MicaController mica when backdropType is "Mica" or "MicaAlt":
                    // 主题切换时（compulsory=true 进入此处）需同步 _config.Theme 与 TintColor，否则 Mica 背景会保留旧主题色
                    UpdateBackdropTheme();
                    mica.TintColor = GetBackgroundColor();
                    mica.LuminosityOpacity = backdropType == "MicaAlt"
                        ? (float)(opacity / 100 * 0.85)
                        : (float)(opacity / 100 * 0.95);
                    MicaKind desiredKind = backdropType == "MicaAlt" ? MicaKind.BaseAlt : MicaKind.Base;
                    if (mica.Kind != desiredKind)
                    {
                        mica.Kind = desiredKind;
                    }
                    return true;
                case DesktopAcrylicController acrylic when backdropType == "Acrylic":
                    UpdateBackdropTheme();
                    acrylic.TintColor = GetBackgroundColor();
                    acrylic.LuminosityOpacity = (float)(opacity / 100 * 0.95);
                    return true;
                default:
                    return false;
            }
        }

        private Color GetBackgroundColor()
        {
            return GetCurrentTheme() == ElementTheme.Dark
                ? Color.FromArgb(0xFF, 0x20, 0x20, 0x20)
                : Colors.White;
        }

        private void CleanupBackdropResources()
        {
            if (_controller != null)
            {
                if (_target != null)
                    _controller.RemoveSystemBackdropTarget(_target);

                _controller.Dispose();
                _controller = null;
            }
            _target = null;
        }

        private void UpdateBackdropTheme()
        {
            var currentTheme = GetCurrentTheme();
            _config.Theme = currentTheme switch
            {
                ElementTheme.Dark => SystemBackdropTheme.Dark,
                ElementTheme.Light => SystemBackdropTheme.Light,
                _ => SystemBackdropTheme.Default
            };
        }

        private void RegisterSystemThemeListener()
        {
            if (_uiSettings != null) return;
            _uiSettings = new UISettings();
            _uiSettings.ColorValuesChanged += OnSystemThemeChanged;
        }

        private void UnregisterSystemThemeListener()
        {
            _uiSettings?.ColorValuesChanged -= OnSystemThemeChanged;
            _uiSettings = null;
        }

        private void OnSystemThemeChanged(UISettings sender, object args)
        {
            var dq = DispatcherQueue;
            if (dq == null) return;
            dq.TryEnqueue(() =>
            {
                if (App.Theme != ElementTheme.Default) return;

                if (this.Content is FrameworkElement rootElement)
                {
                    rootElement.RequestedTheme = ElementTheme.Default;
                }

                UpdateBackdropTheme();

                _controller?.SetSystemBackdropConfiguration(_config);

                var settings = App.LocalSettings;
                var backdropType = settings.Values.TryGetValue("AppBackdrop", out object? backdropRaw) && backdropRaw is string backdropValue
                    ? backdropValue
                    : "Mica";
                if (backdropType == "Solid")
                {
                    RootGrid.Background = GetCurrentTheme() == ElementTheme.Dark
                         ? new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20))
                         : new SolidColorBrush(Colors.White);
                }
                else
                {
                    if (_controller is MicaController micaController)
                    {
                        micaController.TintColor = GetBackgroundColor();
                    }
                    else if (_controller is DesktopAcrylicController acrylicController)
                    {
                        acrylicController.TintColor = GetBackgroundColor();
                    }
                }

                if (App.MainWindow?.AppWindow.TitleBar is { } titleBar)
                {
                    titleBar.ButtonForegroundColor = GetSystemTheme() == ApplicationTheme.Light
                        ? Windows.UI.Color.FromArgb(255, 0, 0, 0)
                        : Windows.UI.Color.FromArgb(255, 255, 255, 255);
                }
            });
        }

        public void UpdatePaneToggleButtonPosition()
        {
            var settings = App.LocalSettings;

            // 检查导航栏位置，如果在顶部则不应用紧凑导航栏设置
            Int32 navTheme = settings.Values.TryGetValue("AppNavTheme", out var navRaw) && navRaw is double d ? (int)d : 0;
            if (navTheme == 1) // 顶部导航栏
            {
                AppTitleBar.IsPaneToggleButtonVisible = false;
                nav.IsPaneToggleButtonVisible = true;
                UpdateBackButtonPosition();
                return;
            }

            if (settings.Values.TryGetValue("IsPaneToggleButtonInTitleBar", out var isItInTitleBar) && isItInTitleBar is bool boolValue)
            {
                AppTitleBar.IsPaneToggleButtonVisible = boolValue;
                nav.IsPaneToggleButtonVisible = !AppTitleBar.IsPaneToggleButtonVisible;
            }
            else
            {
                AppTitleBar.IsPaneToggleButtonVisible = false;
                nav.IsPaneToggleButtonVisible = true;

            }
            UpdateBackButtonPosition();
        }
    }
}
