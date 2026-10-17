using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using ApplicationDataContainer = Microsoft.Windows.Storage.ApplicationDataContainer;

namespace Xdows_Security.Views
{
    public sealed partial class ModelPage : Page
    {
        private bool IsInitialize = true;

        public ModelPage()
        {
            this.InitializeComponent();
            LoadModelSetting();
            IsInitialize = false;
        }

        private void LoadModelSetting()
        {
            ApplicationDataContainer settings = App.LocalSettings;

            if (!settings.Values.ContainsKey("ModelScan"))
            {
                settings.Values["ModelScan"] = true;
            }
            if (settings.Values.TryGetValue("ModelScan", out var scanRaw) && scanRaw is bool scanOn)
            {
                ModelScanToggle.IsOn = scanOn;
            }

            SelectModelMode(ModelModeComboBox, settings, "ModelMode");
            SelectModelMode(ProtectionModeComboBox, settings, "ProtectionModelMode");
        }

        private static void SelectModelMode(ComboBox combo, ApplicationDataContainer settings, string key)
        {
            if (!settings.Values.ContainsKey(key))
            {
                settings.Values[key] = "Flash";
            }
            string mode = settings.Values.TryGetValue(key, out object? modeRaw) && modeRaw is string ms ? ms : "Flash";
            foreach (object obj in combo.Items)
            {
                if (obj is ComboBoxItem item && (item.Tag as string) == mode)
                {
                    combo.SelectedItem = item;
                    break;
                }
            }
        }

        private void ModelScanToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (IsInitialize || sender is not ToggleSwitch toggle) return;
            App.LocalSettings.Values["ModelScan"] = toggle.IsOn;
        }

        private void ModelModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.Tag is string key &&
                combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                App.LocalSettings.Values[key] = tag;
            }
        }
    }
}
