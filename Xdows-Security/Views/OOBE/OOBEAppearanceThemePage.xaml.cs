using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEAppearanceThemePage : OOBEStepPageBase
    {
        private bool _isInitialize = true;

        public OOBEAppearanceThemePage()
        {
            InitializeComponent();
            Loaded += OOBEAppearanceThemePage_Loaded;
        }

        private async void OOBEAppearanceThemePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEAppearanceThemePage_Loaded;

            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                string saved = settings.Values["AppTheme"] as string ?? "Default";

                foreach (ComboBoxItem item in ThemeComboBox.Items)
                {
                    if ((item.Tag as string) == saved)
                    {
                        ThemeComboBox.SelectedItem = item;
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

        private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                ApplicationData.Current.LocalSettings.Values["AppTheme"] = tag;
                ApplyTheme(tag);
            }
        }

        private static void ApplyTheme(string themeTag)
        {
            if (App.MainWindow == null) return;

            ElementTheme theme = themeTag switch
            {
                "Light" => ElementTheme.Light,
                "Dark" => ElementTheme.Dark,
                _ => ElementTheme.Default
            };

            if (App.MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = theme;
            }
            MainWindow.UpdateTheme(theme);
        }
    }
}
