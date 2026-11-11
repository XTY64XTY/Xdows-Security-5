using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class ProtectionSettingsPage : Page
    {
        public ProtectionSettingsPage()
        {
            InitializeComponent();
            SettingsContentHost.Content = new SettingsContentView(SettingsCategories.GetByPageType(GetType()));
        }
    }
}
