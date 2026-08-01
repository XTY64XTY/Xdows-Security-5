using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class QuarantineDialog : ContentDialog
    {
        private ObservableCollection<QuarantineItemModel> _items = [];
        public QuarantineDialog()
        {
            InitializeComponent();
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
            _ = ReloadAsync();
        }
        private Task ReloadAsync()
        {
            _items = new ObservableCollection<QuarantineItemModel>(QuarantineManager.GetQuarantineItems());
            QuarantineListView.ItemsSource = _items;
            UpdateEmptyState();
            return Task.CompletedTask;
        }

        private void UpdateEmptyState()
        {
            bool isEmpty = _items.Count == 0;
            EmptyStatePanel.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
            QuarantineListView.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
            EmptyStateText.Text = Localizer.Get().GetLocalizedString("QuarantineDialog_EmptyState");
            ClearQuarantineButton.IsEnabled = !isEmpty;
            UpdateSelectionActions();
        }

        private void QuarantineListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => UpdateSelectionActions();

        private void UpdateSelectionActions()
        {
            bool hasSelection = QuarantineListView.SelectedItems.Count > 0;
            RestoreQuarantineButton.IsEnabled = hasSelection;
            RestoreQuarantineToButton.IsEnabled = hasSelection;
            DeleteQuarantineButton.IsEnabled = hasSelection;
        }

        private async void RestoreMenuItem_Click(object sender, RoutedEventArgs e)
            => await RestoreSelectedAsync();

        private async void RestoreToMenuItem_Click(object sender, RoutedEventArgs e)
            => await RestoreSelectedToDirectoryAsync();

        private async Task RestoreSelectedAsync()
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0) return;

            foreach (var item in selected)
            {
                bool ok = await QuarantineManager.RestoreFile(item.FileHash);
                if (ok) _items.Remove(item);
            }

            await ReloadAsync();
        }

        private async Task RestoreSelectedToDirectoryAsync()
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0)
                return;

            PickFolderResult? folder;
            try
            {
                folder = await new FolderPicker(
                    XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFolderAsync();
            }
            catch
            {
                return;
            }

            if (folder is null)
                return;

            foreach (var item in selected)
            {
                bool restored = await QuarantineManager.RestoreFileToDirectory(item.FileHash, folder.Path);
                if (restored)
                    _items.Remove(item);
            }

            await ReloadAsync();
        }

        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0) return;
            await QuarantineManager.DeleteItems(selected.Select(x => x.FileHash));
            foreach (var item in selected) _items.Remove(item);
            await ReloadAsync();
        }

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await QuarantineManager.ClearQuarantine();
            await ReloadAsync();
        }

    }
}
