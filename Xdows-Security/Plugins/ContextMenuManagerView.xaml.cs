using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using WinUI3Localizer;
using Xdows_Security.Services;

namespace Xdows_Security.Views
{
    public sealed partial class ContextMenuManagerView : UserControl
    {
        private List<ContextMenuEntry> _all = [];
        private bool _suppressToggle;

        public ContextMenuManagerView()
        {
            InitializeComponent();

            ScopeCombo.ItemsSource = ShellContextMenuService.ScopeNames;
            ScopeCombo.SelectedIndex = 0;

            Loaded += ContextMenuManagerView_Loaded;
        }

        private async void ContextMenuManagerView_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= ContextMenuManagerView_Loaded;

            ClassicMenuToggle.IsChecked = ShellContextMenuService.IsClassicMenuEnabled();
            await LoadAsync();
        }

        private async Task LoadAsync()
        {
            LoadingBar.Visibility = Visibility.Visible;

            try
            {
                _all = await Task.Run(ShellContextMenuService.Enumerate);
                ApplyFilter();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_ScanFailed_Title"), ex.Message);
            }
            finally
            {
                LoadingBar.Visibility = Visibility.Collapsed;
            }
        }

        private void ApplyFilter()
        {
            string keyword = SearchBox.Text?.Trim() ?? "";
            string scope = ScopeCombo.SelectedItem as string ?? Localizer.Get().GetLocalizedString("ContextMenuManager_Scope_All");
            bool thirdPartyOnly = ThirdPartyToggle.IsOn;

            IEnumerable<ContextMenuEntry> query = _all;

            if (!string.Equals(scope, Localizer.Get().GetLocalizedString("ContextMenuManager_Scope_All"), StringComparison.Ordinal))
                query = query.Where(x => x.Scope == scope);

            if (thirdPartyOnly)
                query = query.Where(x => !x.IsSystem);

            if (keyword.Length > 0)
            {
                query = query.Where(x =>
                    x.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    x.Kind.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    x.Target.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    x.RegistryPath.Contains(keyword, StringComparison.OrdinalIgnoreCase));
            }

            MenuList.ItemsSource = query.ToList();
        }

        private void ScopeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyFilter();

        private void ThirdPartyToggle_Toggled(object sender, RoutedEventArgs e)
            => ApplyFilter();

        private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
            => ApplyFilter();

        private async void Refresh_Click(object sender, RoutedEventArgs e)
            => await LoadAsync();

        private void MenuToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (_suppressToggle) return;
            if (sender is not ToggleSwitch toggle) return;
            if (toggle.DataContext is not ContextMenuEntry entry) return;

            // 列表项初始化或容器复用时也会触发 Toggled，此状态下开关取值与模型一致，直接忽略。
            if (toggle.IsOn == entry.IsEnabled) return;

            ApplyToggle(entry, toggle.IsOn);
        }

        private void MenuList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            var entry = (e.OriginalSource as FrameworkElement)?.DataContext as ContextMenuEntry
                        ?? MenuList.SelectedItem as ContextMenuEntry;
            if (entry == null) return;

            ApplyToggle(entry, !entry.IsEnabled);
        }

        private void ToggleSelected_Click(object sender, RoutedEventArgs e)
        {
            var entry = GetEntryFromSender(sender);
            if (entry == null) return;

            ApplyToggle(entry, !entry.IsEnabled);
        }

        private async void ApplyToggle(ContextMenuEntry entry, bool enabled)
        {
            _suppressToggle = true;
            bool succeeded;
            try
            {
                succeeded = ShellContextMenuService.SetEnabled(entry, enabled);
                if (succeeded) entry.IsEnabled = enabled;
            }
            finally
            {
                _suppressToggle = false;
            }

            // 成功时开关已处于目标状态；失败时 IsEnabled 没有变化，绑定不会刷新，需要手动同步回真实值。
            if (succeeded) return;

            entry.ResyncIsEnabled();

            await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_ToggleFailed_Title"),
                string.Format(CultureInfo.CurrentCulture, Localizer.Get().GetLocalizedString("ContextMenuManager_ToggleFailed_Text"), entry.Name, entry.RegistryPath));
        }

        private async void Delete_Click(object sender, RoutedEventArgs e)
        {
            var entry = GetEntryFromSender(sender);
            if (entry == null) return;

            var dialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("ContextMenuManager_DeleteConfirm_Title"),
                Content = new StackPanel
                {
                    Spacing = 8,
                    Children =
                    {
                        new TextBlock
                        {
                            Text = string.Format(CultureInfo.CurrentCulture, Localizer.Get().GetLocalizedString("ContextMenuManager_DeleteConfirm_Text"), entry.Name),
                            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                            TextWrapping = TextWrapping.Wrap
                        },
                        new TextBlock
                        {
                            Text = entry.RegistryPath,
                            FontSize = 12,
                            TextWrapping = TextWrapping.Wrap
                        },
                        new TextBlock
                        {
                            Text = string.Format(CultureInfo.CurrentCulture, Localizer.Get().GetLocalizedString("ContextMenuManager_DeleteBackup_Text"), ShellContextMenuService.BackupDirectory),
                            TextWrapping = TextWrapping.Wrap
                        }
                    }
                },
                PrimaryButtonText = Localizer.Get().GetLocalizedString("ContextMenuManager_DeleteConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("ContextMenuManager_Cancel"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
                RequestedTheme = GetDialogTheme()
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            if (ShellContextMenuService.TryDelete(entry, out string message))
            {
                _all.Remove(entry);
                ApplyFilter();
                return;
            }

            await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_DeleteFailed_Title"), message);
        }

        private async void OpenRegedit_Click(object sender, RoutedEventArgs e)
        {
            var entry = GetEntryFromSender(sender);
            if (entry == null) return;

            if (!ShellContextMenuService.OpenInRegedit(entry))
                await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_OpenRegeditFailed_Title"),
                    Localizer.Get().GetLocalizedString("ContextMenuManager_OpenRegeditFailed_Text"));
        }

        private void CopyTarget_Click(object sender, RoutedEventArgs e)
        {
            var entry = GetEntryFromSender(sender);
            if (entry == null) return;

            var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
            data.SetText(entry.Target);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
        }

        private async void ClassicMenuToggle_Click(object sender, RoutedEventArgs e)
        {
            bool enabled = ClassicMenuToggle.IsChecked == true;

            if (!ShellContextMenuService.SetClassicMenuEnabled(enabled))
            {
                ClassicMenuToggle.IsChecked = !enabled;
                await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_ToggleClassicFailed_Title"),
                    Localizer.Get().GetLocalizedString("ContextMenuManager_ToggleClassicFailed_Text"));
                return;
            }

            // 该设置需要重启资源管理器才生效，必须让用户知道。
            await ShowMessageAsync(Localizer.Get().GetLocalizedString("ContextMenuManager_ClassicMenu_Title"), enabled
                ? Localizer.Get().GetLocalizedString("ContextMenuManager_ClassicEnabled_Text")
                : Localizer.Get().GetLocalizedString("ContextMenuManager_ClassicDisabled_Text"));
        }

        private ContextMenuEntry? GetEntryFromSender(object sender)
        {
            if (sender is MenuFlyoutItem menuItem)
                return menuItem.DataContext as ContextMenuEntry;

            return MenuList.SelectedItem as ContextMenuEntry;
        }

        private async Task ShowMessageAsync(string title, string message)
        {
            var dialog = new ContentDialog
            {
                Title = title,
                Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
                CloseButtonText = Localizer.Get().GetLocalizedString("ContextMenuManager_OK"),
                XamlRoot = XamlRoot,
                RequestedTheme = GetDialogTheme(),
                DefaultButton = ContentDialogButton.Close
            };

            try
            {
                await dialog.ShowAsync();
            }
            catch (Exception)
            {
                // 同一时刻只允许一个 ContentDialog，并发调用时忽略即可（失败详情已由服务层写入日志）。
            }
        }

        private ElementTheme GetDialogTheme()
            => (XamlRoot?.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default;
    }
}
