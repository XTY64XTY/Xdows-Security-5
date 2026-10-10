using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Xdows_Security.Services;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    public sealed partial class TrustPage : Page
    {
        private ObservableCollection<TrustItemModel> _items = [];

        public TrustPage()
        {
            InitializeComponent();
            _ = ReloadAsync();
        }

        private Task ReloadAsync()
        {
            try
            {
                var items = TrustManager.GetTrustItems();
                if (items != null)
                {
                    _items = new ObservableCollection<TrustItemModel>(items);
                    TrustListView.ItemsSource = _items;
                }
            }
            catch
            {
            }
            UpdateEmptyState();
            return Task.CompletedTask;
        }

        private void UpdateEmptyState()
        {
            bool isEmpty = _items.Count == 0;
            EmptyStatePanel.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
            TrustListView.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
            EmptyStateText.Text = Localizer.Get().GetLocalizedString("TrustPage_EmptyState");
            ClearTrustButton.IsEnabled = !isEmpty;
            DeleteTrustButton.IsEnabled = TrustListView.SelectedItems.Count > 0;
        }

        private void TrustListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => DeleteTrustButton.IsEnabled = TrustListView.SelectedItems.Count > 0;

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            _ = ReloadAsync();
        }

        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = TrustListView.SelectedItems.Cast<TrustItemModel>().ToList();
            if (selectedItems.Count == 0) return;

            foreach (var item in selectedItems)
            {
                await TrustManager.RemoveFromTrust(item.SourcePath);
                _items.Remove(item);
            }

            await ReloadAsync();
        }

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await TrustManager.ClearTrust();
            await ReloadAsync();
        }

        private async void AddMenuItem_Click(object sender, RoutedEventArgs e)
        {
            PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
            if (file is null) { return; }
            await TrustManager.AddToTrust(file.Path);
            _ = ReloadAsync();
        }
    }
}