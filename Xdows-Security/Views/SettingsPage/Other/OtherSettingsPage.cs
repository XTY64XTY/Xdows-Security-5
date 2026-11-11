using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class OtherSettingsPage : Page
    {
        public OtherSettingsPage()
        {
            InitializeComponent();
            SettingsContentHost.Content = new SettingsContentView(SettingsCategories.GetByPageType(GetType()));
        }
    }
}
