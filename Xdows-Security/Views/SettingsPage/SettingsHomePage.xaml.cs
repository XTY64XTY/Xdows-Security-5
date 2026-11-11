using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Linq;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    public sealed partial class SettingsHomePage : Page
    {
        private bool _languageChangedSubscribed;

        public SettingsHomePage()
        {
            InitializeComponent();
            FilterCategoryCards(string.Empty);
            SubscribeLanguageChanged();
            Unloaded += SettingsHomePage_Unloaded;
        }

        private void SettingsHomePage_Loaded(object sender, RoutedEventArgs e)
        {
            SubscribeLanguageChanged();
            App.PlayEntranceAnimation(SettingsHomeContentPanel, "up", 40);
        }

        private void SettingsHomePage_Unloaded(object sender, RoutedEventArgs e)
        {
            if (!_languageChangedSubscribed) return;
            Localizer.Get().LanguageChanged -= OnLanguageChanged;
            _languageChangedSubscribed = false;
        }

        private void SubscribeLanguageChanged()
        {
            if (_languageChangedSubscribed) return;
            Localizer.Get().LanguageChanged += OnLanguageChanged;
            _languageChangedSubscribed = true;
        }

        private void OnLanguageChanged(object? sender, EventArgs e) => FilterCategoryCards(SettingsSearchBox.Text);

        private void SettingsSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                FilterCategoryCards(sender.Text);
            }
        }

        private void FilterCategoryCards(string searchText)
        {
            string query = searchText.Trim();
            foreach (SettingsCategoryDefinition category in SettingsCategories.All)
            {
                // 引擎页从扫描类别进入，不在设置首页列出。
                if (string.IsNullOrEmpty(category.HomeCardName))
                    continue;

                if (FindName(category.HomeCardName) is not SettingsCard card)
                    throw new InvalidOperationException($"Settings category card '{category.HomeCardName}' was not found.");

                string searchableText = string.Concat(
                    card.Header?.ToString(),
                    " ",
                    card.Description?.ToString());
                card.Visibility = query.Length == 0 || searchableText.Contains(
                    query,
                    StringComparison.InvariantCultureIgnoreCase)
                        ? Visibility.Visible
                        : Visibility.Collapsed;
            }
        }

        private void CategoryCard_Click(object sender, RoutedEventArgs e)
        {
            SettingsCategoryDefinition? category = SettingsCategories.All.FirstOrDefault(
                candidate => !string.IsNullOrEmpty(candidate.HomeCardName) &&
                             FindName(candidate.HomeCardName) == sender);
            if (category is null)
                throw new InvalidOperationException("The clicked card is not a registered settings category.");

            App.MainWindow?.OpenSettingsCategory(category.Key);
        }
    }
}
