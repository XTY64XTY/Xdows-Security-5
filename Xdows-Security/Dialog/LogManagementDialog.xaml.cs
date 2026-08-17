using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Xdows_Security.Services;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class LogManagementDialog : ContentDialog
    {
        private ObservableCollection<LogDateStats> _stats = [];

        public LogManagementDialog()
        {
            InitializeComponent();
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
            Loaded += OnLoaded;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            await LoadStatsAsync();
        }

        private async Task LoadStatsAsync()
        {
            LoadingPanel.Visibility = Visibility.Visible;
            ContentPanel.Visibility = Visibility.Collapsed;

            var stats = await Task.Run(() => LogService.GetDateStats());

            _stats = new ObservableCollection<LogDateStats>(stats);
            DateStatsListView.ItemsSource = _stats;

            LoadingPanel.Visibility = Visibility.Collapsed;
            ContentPanel.Visibility = Visibility.Visible;
        }

        private void DeleteSelected_Click(object sender, RoutedEventArgs e)
        {
            var selected = DateStatsListView.SelectedItems.Cast<LogDateStats>().ToList();
            if (selected.Count == 0) return;

            foreach (var item in selected)
            {
                LogService.DeleteLogsByDate(item.Date);
                _stats.Remove(item);
            }
        }

        private void DeleteAll_Click(object sender, RoutedEventArgs e)
        {
            LogService.ClearAll();
            _stats.Clear();
        }
    }
}
