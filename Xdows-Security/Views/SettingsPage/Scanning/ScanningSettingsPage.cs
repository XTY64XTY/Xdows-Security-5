using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class ScanningSettingsPage : Page
    {
        public ScanningSettingsPage()
        {
            InitializeComponent();
            SettingsContentHost.Content = new SettingsContentView(SettingsCategories.GetByPageType(GetType()));
        }
    }
}
