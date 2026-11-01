using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading.Tasks;

namespace Xdows_Security.Services
{
    /// <summary>
    /// 破坏性操作的二次确认。
    ///
    /// 统一走默认对话框样式（缺少 Style 时对话框没有弹出动画），
    /// 并且默认焦点放在「取消」上——回车不会误删。
    /// </summary>
    internal static class ConfirmDialog
    {
        public static async Task<bool> ShowAsync(
            XamlRoot xamlRoot,
            ElementTheme requestedTheme,
            string title,
            string message,
            string confirmText,
            string cancelText)
        {
            ContentDialogResult result = await new ContentDialog
            {
                Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                Title = title,
                Content = message,
                PrimaryButtonText = confirmText,
                CloseButtonText = cancelText,
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = xamlRoot,
                RequestedTheme = requestedTheme
            }.ShowAsync();

            return result == ContentDialogResult.Primary;
        }
    }
}
