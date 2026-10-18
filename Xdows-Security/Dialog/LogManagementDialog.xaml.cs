using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using WinUI3Localizer;
using Xdows_Security.Services;

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
            UpdateEmptyState();

            LoadingPanel.Visibility = Visibility.Collapsed;
            ContentPanel.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// 没有日志时显示占位提示，并禁掉两个删除按钮——空列表上点删除没有意义。
        /// </summary>
        private void UpdateEmptyState()
        {
            bool isEmpty = _stats.Count == 0;

            EmptyStatePanel.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;
            DateStatsListView.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
            DeleteSelectedButton.IsEnabled = !isEmpty;
            DeleteAllButton.IsEnabled = !isEmpty;

            EmptyStateText.Text = Localizer.Get().GetLocalizedString("HomePage_LogEmptyState");
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

            UpdateEmptyState();
        }

        private void DeleteAll_Click(object sender, RoutedEventArgs e)
        {
            LogService.ClearAll();
            _stats.Clear();
            UpdateEmptyState();
        }
    }
}
