using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using System;
using System.Numerics;
using Windows.Graphics;
using WinUI3Localizer;
using Xdows_Security.Services;

namespace Xdows_Security.Views
{
    public sealed partial class XdowsToolsPage : Page
    {
        private int _previousTabIndex = -1;

        public XdowsToolsPage()
        {
            InitializeComponent();

            TabView.TabItems.Add(new TabViewItem
            {
                Header = CreateTabHeader("XdowsTools_Tab_ProcessManager"),
                IconSource = new FontIconSource { Glyph = "\uE9D9" },
                IsClosable = false,
                Content = new ProcessManagerView()
            });

            TabView.TabItems.Add(new TabViewItem
            {
                Header = CreateTabHeader("XdowsTools_Tab_ContextMenuManager"),
                IconSource = new FontIconSource { Glyph = "\uE8FD" },
                IsClosable = false,
                Content = new ContextMenuManagerView()
            });

            TabView.SelectionChanged += TabView_SelectionChanged;
            Loaded += XdowsToolsPage_Loaded;
            SizeChanged += (_, _) => RestoreTitleBarDragRegion();
        }

        private void XdowsToolsPage_Loaded(object sender, RoutedEventArgs e)
        {
            // WinUI 缺陷（microsoft-ui-xaml#11119）：TabView 在加载 / 尺寸变化时会把自己读到的窗口
            // Caption（拖拽）区域原样写回，而框架默认的标题栏拖拽区域不会由 GetRegionRects 返回，
            // 于是被写成空集合，窗口标题栏随之无法拖动（仅有最小化/最大化/关闭按钮仍可用）。
            // 待 TabView 完成首轮布局后显式写回标题栏拖拽区域；该区域一旦非空，TabView 的读改写会保留它。
            _ = DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, RestoreTitleBarDragRegion);
        }

        /// <summary>把窗口顶部标题栏条带重新登记为 Caption（可拖拽）区域。</summary>
        private void RestoreTitleBarDragRegion()
        {
            try
            {
                if (XamlRoot is not { } xamlRoot) return;

                Microsoft.UI.WindowId windowId = xamlRoot.ContentIslandEnvironment.AppWindowId;
                if (windowId.Value == 0) return;

                AppWindow appWindow = AppWindow.GetFromWindowId(windowId);
                int width = appWindow.ClientSize.Width;
                int height = appWindow.TitleBar.Height;
                if (width <= 0 || height <= 0) return;

                InputNonClientPointerSource
                    .GetForWindowId(windowId)
                    .SetRegionRects(NonClientRegionKind.Caption, [new RectInt32(0, 0, width, height)]);
            }
            catch
            {
                // 恢复失败不影响页面本身的功能
            }
        }

        // 代码创建的文本不会经过 XAML 的 {ThemeResource} 求值，
        // 需显式套用当前默认字体以跟随"使用 Noto 字体"设置。
        private static TextBlock CreateTabHeader(string uid)
        {
            var header = new TextBlock
            {
                Text = Localizer.Get().GetLocalizedString(uid),
                FontSize = 14,
                Style = (Style)App.Current.Resources["CaptionTextBlockStyle"]
            };

            FontFamily? font = FontService.CurrentFontFamily;
            if (font != null)
                header.FontFamily = font;

            return header;
        }

        private void TabView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TabView.SelectedItem is not TabViewItem selectedItem) return;

            int newIndex = TabView.TabItems.IndexOf(selectedItem);
            if (_previousTabIndex < 0 || newIndex == _previousTabIndex)
            {
                _previousTabIndex = newIndex;
                return;
            }

            float direction = newIndex > _previousTabIndex ? 1f : -1f;
            _previousTabIndex = newIndex;

            if (selectedItem.Content is not UIElement contentElement) return;

            var visual = ElementCompositionPreview.GetElementVisual(contentElement);
            var compositor = visual.Compositor;

            visual.StopAnimation("Offset");
            visual.StopAnimation("Opacity");

            float slideDistance = 60f;
            visual.Offset = new Vector3(direction * slideDistance, 0, 0);
            visual.Opacity = 0f;

            var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0.1f, 0.9f), new Vector2(0.2f, 1.0f));

            var offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
            offsetAnimation.Target = "Offset";
            offsetAnimation.InsertKeyFrame(1.0f, Vector3.Zero, easing);
            offsetAnimation.Duration = TimeSpan.FromMilliseconds(250);

            var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
            opacityAnimation.Target = "Opacity";
            opacityAnimation.InsertKeyFrame(1.0f, 1.0f, easing);
            opacityAnimation.Duration = TimeSpan.FromMilliseconds(250);

            visual.StartAnimation("Offset", offsetAnimation);
            visual.StartAnimation("Opacity", opacityAnimation);
        }
    }
}
