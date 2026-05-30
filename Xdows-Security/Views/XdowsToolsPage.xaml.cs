using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using System;
using System.Numerics;

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
                Header = new TextBlock { Text = "进程管理器", FontSize = 14, Style = (Style)App.Current.Resources["CaptionTextBlockStyle"] },
                IconSource = new FontIconSource { Glyph = "\uE9D9" },
                IsClosable = false,
                Content = new ProcessManagerView()
            });

            TabView.TabItems.Add(new TabViewItem
            {
                Header = new TextBlock { Text = "命令提示符", FontSize = 14, Style = (Style)App.Current.Resources["CaptionTextBlockStyle"] },
                IconSource = new FontIconSource { Glyph = "\uE756" },
                IsClosable = false,
                Content = new CommandPromptView()
            });

            TabView.TabItems.Add(new TabViewItem
            {
                Header = new TextBlock { Text = "弹窗拦截器", FontSize = 14, Style = (Style)App.Current.Resources["CaptionTextBlockStyle"] },
                IconSource = new FontIconSource { Glyph = "\uEA0D" },
                IsClosable = false,
                Content = new PopupBlockerView()
            });

            TabView.SelectionChanged += TabView_SelectionChanged;
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
