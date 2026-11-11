using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class AppearanceSettingsPage : Page
    {
        public AppearanceSettingsPage()
        {
            InitializeComponent();
            SettingsContentHost.Content = new SettingsContentView(SettingsCategories.GetByPageType(GetType()));
        }
    }
}
