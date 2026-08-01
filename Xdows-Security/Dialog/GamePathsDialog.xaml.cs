using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using WinUI3Localizer;
using Xdows_Security.Services;

namespace Xdows_Security
{
    public sealed partial class GamePathsDialog : ContentDialog
    {
        private ObservableCollection<string> _items = [];

        public GamePathsDialog()
        {
            this.InitializeComponent();
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
            _ = ReloadAsync();
        }

        private Task ReloadAsync()
        {
            _items = new ObservableCollection<string>(ThreatNotificationModeService.GetGameExecutablePaths());
            GamePathsListView.ItemsSource = _items;
            UpdateEmptyState();
            return Task.CompletedTask;
        }

        private void UpdateEmptyState()
        {
            bool isEmpty = _items.Count == 0;
            EmptyStatePanel.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
            GamePathsListView.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
            EmptyStateText.Text = Localizer.Get().GetLocalizedString("GamePathsDialog_EmptyState");
            ClearGamePathsButton.IsEnabled = !isEmpty;
            DeleteGamePathButton.IsEnabled = GamePathsListView.SelectedItems.Count > 0;
        }

        private void GamePathsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => DeleteGamePathButton.IsEnabled = GamePathsListView.SelectedItems.Count > 0;

        private async void AddMenuItem_Click(object sender, RoutedEventArgs e)
            => await AddGamePathAsync();

        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
            => await DeleteSelectedAsync();

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            _items.Clear();
            ThreatNotificationModeService.SaveGameExecutablePaths(_items);
            await ReloadAsync();
        }

        private async Task AddGamePathAsync()
        {
            try
            {
                FileOpenPicker picker = new(XamlRoot.ContentIslandEnvironment.AppWindowId)
                {
                    SuggestedStartLocation = PickerLocationId.ComputerFolder
                };
                picker.FileTypeFilter.Add(".exe");

                PickFileResult? file = await picker.PickSingleFileAsync();
                if (file is null) return;

                foreach (string existing in _items)
                {
                    if (string.Equals(existing, file.Path, StringComparison.OrdinalIgnoreCase))
                        return;
                }

                _items.Add(file.Path);
                ThreatNotificationModeService.SaveGameExecutablePaths(_items);
                await ReloadAsync();
            }
            catch { }
        }

        private async Task DeleteSelectedAsync()
        {
            var selected = GamePathsListView.SelectedItems.Cast<string>().ToList();
            if (selected.Count == 0) return;
            foreach (var item in selected)
                _items.Remove(item);
            ThreatNotificationModeService.SaveGameExecutablePaths(_items);
            await ReloadAsync();
        }
    }
}
