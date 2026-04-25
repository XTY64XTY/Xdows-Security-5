using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Linq;
using Windows.Globalization;
using WinUI3Localizer;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OobeLanguagePage : OobeStepPageBase
    {
        private bool _isInitialize = true;

        public OobeLanguagePage()
        {
            InitializeComponent();
            Loaded += OobeLanguagePage_Loaded;
        }

        private async void OobeLanguagePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OobeLanguagePage_Loaded;

            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                string savedLanguage = settings.Values.TryGetValue("AppLanguage", out object? langRaw) && langRaw is string s ? s : "en-US";

                foreach (ComboBoxItem item in LanguageComboBox.Items.OfType<ComboBoxItem>())
                {
                    if ((item.Tag as string) == savedLanguage)
                    {
                        LanguageComboBox.SelectedItem = item;
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

        private async void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitialize) return;

            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem selectedItem)
            {
                string currentLanguage = Localizer.Get().GetCurrentLanguage();
                if (selectedItem.Tag is not string newLanguage) return;
                if (newLanguage != currentLanguage)
                {
                    ApplicationData.Current.LocalSettings.Values["AppLanguage"] = newLanguage;
                    await Localizer.Get().SetLanguage(newLanguage);
                }
            }
        }
    }
}
