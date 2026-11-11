using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views
{
    public sealed partial class QuarantineSettingsPage : Page
    {
        public QuarantineSettingsPage()
        {
            InitializeComponent();
            SettingsContentHost.Content = new SettingsContentView(SettingsCategories.GetByPageType(GetType()));
        }
    }
}
