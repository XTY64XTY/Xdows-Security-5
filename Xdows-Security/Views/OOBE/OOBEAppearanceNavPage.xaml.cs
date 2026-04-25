using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEAppearanceNavPage : OOBEStepPageBase
    {
        private bool _isInitialize = true;

        public OOBEAppearanceNavPage()
        {
            InitializeComponent();
            Loaded += OOBEAppearanceNavPage_Loaded;
        }

        private async void OOBEAppearanceNavPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEAppearanceNavPage_Loaded;

            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                int saved = settings.Values.TryGetValue("AppNavTheme", out object? raw) && raw is double d ? (int)d : 0;

                foreach (ComboBoxItem item in NavComboBox.Items)
                {
                    if (item.Tag is string tag && int.TryParse(tag, out int val) && val == saved)
                    {
                        NavComboBox.SelectedItem = item;
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                _isInitialize = false;
            }

            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void NavComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                if (int.TryParse(tag, out int index))
                {
                    ApplicationData.Current.LocalSettings.Values["AppNavTheme"] = (double)index;
                    App.MainWindow?.UpdateNavTheme(index);
                }
            }
        }
    }
}
