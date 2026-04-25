using Compatibility.Windows.Storage;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEAppearanceBackdropPage : OOBEStepPageBase
    {
        private bool _isInitialize = true;

        public OOBEAppearanceBackdropPage()
        {
            InitializeComponent();
            Loaded += OOBEAppearanceBackdropPage_Loaded;
        }

        private async void OOBEAppearanceBackdropPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEAppearanceBackdropPage_Loaded;

            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                string saved = settings.Values["AppBackdrop"] as string ?? "Mica";

                // Disable Mica options if not supported
                foreach (ComboBoxItem item in BackdropComboBox.Items)
                {
                    if (item.Tag as string is "Mica" or "MicaAlt")
                    {
                        item.IsEnabled = MicaController.IsSupported();
                    }
                }

                foreach (ComboBoxItem item in BackdropComboBox.Items)
                {
                    if ((item.Tag as string) == saved && item.IsEnabled)
                    {
                        BackdropComboBox.SelectedItem = item;
                        break;
                    }
                }

                // Fallback if saved option is disabled or not found
                if (BackdropComboBox.SelectedItem == null)
                {
                    BackdropComboBox.SelectedIndex = MicaController.IsSupported() ? 1 : 0;
                }
            }
            catch { }
            finally
            {
                _isInitialize = false;
            }

            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void BackdropComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                ApplicationData.Current.LocalSettings.Values["AppBackdrop"] = tag;
                App.MainWindow?.ApplyBackdrop(tag, false);
            }
        }
    }
}
