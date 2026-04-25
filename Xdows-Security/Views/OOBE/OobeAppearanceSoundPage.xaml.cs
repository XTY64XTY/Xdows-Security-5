using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OobeAppearanceSoundPage : OobeStepPageBase
    {
        private bool _isInitialize = true;

        public OobeAppearanceSoundPage()
        {
            InitializeComponent();
            Loaded += OobeAppearanceSoundPage_Loaded;
        }

        private async void OobeAppearanceSoundPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OobeAppearanceSoundPage_Loaded;

            try
            {
                var settings = ApplicationData.Current.LocalSettings;

                bool soundEffects = settings.Values.TryGetValue("SoundEffects", out object? se) && se is bool b && b;
                bool spatialAudio = settings.Values.TryGetValue("SpatialAudio", out object? sa) && sa is bool sb ? sb : !settings.Values.ContainsKey("SpatialAudio");

                SoundEffectsToggle.IsOn = soundEffects;
                SpatialAudioToggle.IsOn = spatialAudio;
                SpatialAudioToggle.IsEnabled = soundEffects;

                ApplySoundSettings();
            }
            catch { }
            finally
            {
                _isInitialize = false;
            }

            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void SoundEffectsToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (_isInitialize) return;
            ApplicationData.Current.LocalSettings.Values["SoundEffects"] = SoundEffectsToggle.IsOn;
            SpatialAudioToggle.IsEnabled = SoundEffectsToggle.IsOn;
            ApplySoundSettings();
        }

        private void SpatialAudioToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (_isInitialize) return;
            ApplicationData.Current.LocalSettings.Values["SpatialAudio"] = SpatialAudioToggle.IsOn;
            ApplySoundSettings();
        }

        private void ApplySoundSettings()
        {
            // Apply sound settings through App.MainWindow or similar mechanism
            // This mirrors the SettingsPage implementation
            try
            {
                bool soundEffects = SoundEffectsToggle.IsOn;
                bool spatialAudio = SpatialAudioToggle.IsOn;

                // SoundEffectHelper is typically used here to configure sound playback
                // Since this is a minimal implementation, we rely on the settings being saved
                // The actual sound playback will use these settings when playing sounds
            }
            catch { }
        }
    }
}
