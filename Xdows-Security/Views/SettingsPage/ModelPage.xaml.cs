using Helper;
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

            SelectThresholdPreset(ScanThresholdComboBox, settings, "ModelThreshold");
            SelectThresholdPreset(ProtectionThresholdComboBox, settings, "ProtectionModelThreshold");
            ScanThresholdNumberBox.Value = ReadCustomThreshold(settings, "ModelThresholdValue");
            ProtectionThresholdNumberBox.Value = ReadCustomThreshold(settings, "ProtectionModelThresholdValue");
            UpdateThresholdCustomState();
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

        private static void SelectThresholdPreset(ComboBox combo, ApplicationDataContainer settings, string key)
        {
            if (!settings.Values.ContainsKey(key))
            {
                settings.Values[key] = ModelThresholdPresets.Medium;
            }
            string preset = settings.Values.TryGetValue(key, out object? presetRaw) && presetRaw is string p
                ? p
                : ModelThresholdPresets.Medium;
            foreach (object obj in combo.Items)
            {
                if (obj is ComboBoxItem item && (item.Tag as string) == preset)
                {
                    combo.SelectedItem = item;
                    break;
                }
            }
        }

        private static double ReadCustomThreshold(ApplicationDataContainer settings, string key)
        {
            if (!settings.Values.ContainsKey(key))
            {
                settings.Values[key] = (double)ModelThresholdPresets.DefaultCustom;
            }
            return settings.Values.TryGetValue(key, out object? valueRaw) && valueRaw is double v
                ? v
                : ModelThresholdPresets.DefaultCustom;
        }

        /// <summary>「自定义阈值」子项只在阈值选为「自定义」时启用。</summary>
        private void UpdateThresholdCustomState()
        {
            ScanThresholdCustomCard.IsEnabled = IsCustomThreshold(ScanThresholdComboBox);
            ProtectionThresholdCustomCard.IsEnabled = IsCustomThreshold(ProtectionThresholdComboBox);
        }

        private static bool IsCustomThreshold(ComboBox combo)
            => combo.SelectedItem is ComboBoxItem item && (item.Tag as string) == ModelThresholdPresets.Custom;

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

        private void ThresholdComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.Tag is string key &&
                combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                App.LocalSettings.Values[key] = tag;
                UpdateThresholdCustomState();
            }
        }

        private void ThresholdNumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
        {
            if (IsInitialize || sender.Tag is not string key) return;
            if (double.IsNaN(args.NewValue)) return;
            App.LocalSettings.Values[key] = Math.Clamp(Math.Round(args.NewValue), 80, 100);
        }
    }
}
