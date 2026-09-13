using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using System;

namespace Xdows_Security.Services
{
    /// <summary>
    /// 应用级默认字体服务：按设置决定是否使用内置的 Noto Sans 作为界面默认字体。
    ///
    /// 实现方式是覆盖 WinUI 的字体主题资源（ContentControlThemeFontFamily / XamlAutoFontFamily 等），
    /// 因此未显式指定 FontFamily 的控件与文本都会改用 Noto Sans；
    /// SymbolThemeFontFamily（Segoe Fluent Icons 等图标字体）刻意不改动，图标字形不受影响。
    ///
    /// 字体族使用回退列表：拉丁、希腊、西里尔字形取自 Noto Sans，
    /// 汉字等 CJK 字形由 Noto Sans SC 补足（Noto Sans 本体不含 CJK 字形）。
    ///
    /// 字体许可：两款字体均以 SIL Open Font License 1.1 发布，允许随软件一同分发。
    /// 许可证全文见 Assets/Fonts/NotoSans-OFL.txt 与 Assets/Fonts/NotoSansSC-OFL.txt，
    /// 第三方组件声明见仓库根目录 THIRD-PARTY-NOTICES.md。
    /// </summary>
    internal static class FontService
    {
        /// <summary>设置项键名，存储于 App.LocalSettings，缺省为启用。</summary>
        public const String UseNotoSansSettingKey = "UseNotoSansFont";

        /// <summary>随应用分发的拉丁字形字体（可变字重，覆盖 Regular 到 Black）。</summary>
        public const String LatinFontAssetRelativePath = "Assets/Fonts/NotoSans-Variable.ttf";

        /// <summary>随应用分发的简体中文字形字体（可变字重，覆盖 Thin 到 Black）。</summary>
        public const String CjkFontAssetRelativePath = "Assets/Fonts/NotoSansSC-Variable.ttf";

        /// <summary>字体族名称，取自字体文件 name 表的 nameID 1。</summary>
        public const String LatinFontFamilyName = "Noto Sans";

        /// <summary>字体族名称，取自字体文件 name 表的 nameID 16（Typographic Family）。</summary>
        public const String CjkFontFamilyName = "Noto Sans SC";

        /// <summary>
        /// 需要覆盖的 WinUI 字体资源键。除了主键，还包含日历控件（DatePicker 的
        /// CalendarView）与旧版兼容键，保证字体切换在各处表现一致。
        /// 刻意不包含 SymbolThemeFontFamily，以免把图标字体一并替换掉。
        /// </summary>
        private static readonly String[] FontResourceKeys =
        {
            "ContentControlThemeFontFamily",
            "XamlAutoFontFamily",
            "AutoFontFamily",
            "DayItemFontFamily",
            "FirstOfMonthLabelFontFamily",
            "FirstOfYearDecadeLabelFontFamily",
            "MonthYearItemFontFamily"
        };

        private static FontFamily? _notoSansFontFamily;

        /// <summary>当前是否已应用 Noto Sans 作为默认字体。</summary>
        public static Boolean IsEnabled { get; private set; }

        /// <summary>
        /// 读取设置。未写入过该设置时视为启用，以满足“默认启用该设置”的需求。
        /// </summary>
        public static Boolean ReadSetting()
        {
            if (!App.LocalSettings.Values.TryGetValue(UseNotoSansSettingKey, out Object? raw))
                return true;

            return raw is Boolean value ? value : true;
        }

        /// <summary>按当前设置应用字体，用于应用启动阶段。</summary>
        public static void ApplyFromSetting() => SetEnabled(ReadSetting(), false);

        /// <summary>
        /// 应用或撤销 Noto Sans 默认字体。
        /// </summary>
        /// <param name="enabled">是否使用 Noto Sans。</param>
        /// <param name="refreshLoadedUi">是否刷新已经加载的界面。</param>
        public static void SetEnabled(Boolean enabled, Boolean refreshLoadedUi = true)
        {
            IsEnabled = enabled;

            if (Application.Current?.Resources is not ResourceDictionary resources)
                return;

            if (enabled)
            {
                FontFamily fontFamily = _notoSansFontFamily ??= CreateNotoSansFontFamily();
                foreach (String key in FontResourceKeys)
                    resources[key] = fontFamily;
            }
            else
            {
                // 移除本地覆盖后，资源查找回落至 XamlControlsResources 提供的系统默认字体。
                foreach (String key in FontResourceKeys)
                    resources.Remove(key);
            }

            if (refreshLoadedUi)
                RequestThemeResourceRefresh();
        }

        private static FontFamily CreateNotoSansFontFamily()
        {
            // ms-appx 指向应用目录，打包与未打包（WindowsPackageType=None）两种形态均适用。
            // 逗号分隔即回退列表：单个字符在前一个字体里找不到字形时，会继续往后找。
            String source = String.Concat(
                "ms-appx:///", LatinFontAssetRelativePath, "#", LatinFontFamilyName,
                ",ms-appx:///", CjkFontAssetRelativePath, "#", CjkFontFamilyName);

            return new FontFamily(source);
        }

        /// <summary>
        /// 字体资源是通过 {ThemeResource} 被默认样式引用的，只在主题变化时才会重新求值。
        /// 这里把根元素的 RequestedTheme 切换到相反值，再跨一个调度周期还原，
        /// 强制 WinUI 完成一次真实的主题求值。注意不能在同一调用栈内连续赋值两次——
        /// 那样会被合并为一次变更，ThemeResource 不会重新解析，导致已渲染的文本
        /// （例如 ComboBox 的内容）保持旧字体。
        /// </summary>
        private static void RequestThemeResourceRefresh()
        {
            try
            {
                if (App.MainWindow?.Content is not FrameworkElement root)
                    return;

                ElementTheme original = root.RequestedTheme;
                ElementTheme temporary = original switch
                {
                    ElementTheme.Light => ElementTheme.Dark,
                    ElementTheme.Dark => ElementTheme.Light,
                    _ => MainWindow.GetSystemTheme() == ApplicationTheme.Light
                        ? ElementTheme.Dark
                        : ElementTheme.Light
                };

                root.RequestedTheme = temporary;
                DispatcherQueue dispatcher = root.DispatcherQueue;
                // 用低优先级还原：保证"临时主题"先经过一次完整的求值与渲染批次，
                // 再切回原主题，形成两次真实的 ThemeResource 重新解析。
                Boolean enqueued = dispatcher != null && dispatcher.TryEnqueue(DispatcherQueuePriority.Low, () =>
                {
                    try
                    {
                        // 还原为切换前的主题；窗口可能已在关闭过程中，忽略异常。
                        root.RequestedTheme = original;
                    }
                    catch
                    {
                    }
                });
                if (!enqueued)
                {
                    root.RequestedTheme = original;
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "UI Interface",
                    $"Refresh font resources failed: {ex.Message}");
            }
        }
    }
}
