using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class XdowsToolsPage : Page
    {
        public XdowsToolsPage()
        {
            InitializeComponent();
        }
        private void Page_Loaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            TabView.TabItems.Add(new TabViewItem
            {
                Header = new TextBlock { Text = "进程管理器", FontSize = 14 },
                IconSource = new FontIconSource { Glyph = "\uE9D9" },
                IsClosable = false,
                Content = new ProcessManagerView()
            });

            TabView.TabItems.Add(new TabViewItem
            {
                Header = new TextBlock { Text = "命令提示符", FontSize = 14 },
                IconSource = new FontIconSource { Glyph = "\uE756" },
                IsClosable = false,
                Content = new CommandPromptView()
            });

            TabView.TabItems.Add(new TabViewItem
            {
                Header = new TextBlock { Text = "弹窗拦截器", FontSize = 14 },
                IconSource = new FontIconSource { Glyph = "\uEA0D" },
                IsClosable = false,
                Content = new PopupBlockerView()
            });
        }
    }
}
