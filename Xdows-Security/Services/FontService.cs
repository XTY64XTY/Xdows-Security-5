using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Xdows_Security.Services
{
    /// <summary>
    /// 应用级默认字体服务：按设置决定是否使用内置的 Noto Sans 作为界面默认字体。
    ///
    /// 实现方式是覆盖 WinUI 的字体主题资源（ContentControlThemeFontFamily / XamlAutoFontFamily 等），
    /// 因此未显式指定 FontFamily 的控件与文本都会改用 Noto Sans；
    /// SymbolThemeFontFamily（Segoe Fluent Icons 等图标字体）刻意不改动，图标字形不受影响。
    ///
    /// 字体族使用回退列表：拉丁、希腊、西里尔字形优先使用 Noto Sans，
    /// 汉字等 CJK 字形由 Noto Sans SC 补足。
    ///
    /// 字体许可：两款字体均以 SIL Open Font License 1.1 发布，允许随软件一同分发。
    /// 许可证全文见 Assets/Fonts/NotoSans-OFL.txt 与 Assets/Fonts/NotoSansSC-OFL.txt，
    /// 第三方组件声明见仓库根目录 THIRD-PARTY-NOTICES.md。
    /// </summary>
    internal static class FontService
    {
        /// <summary>设置项键名，存储于 App.LocalSettings，缺省为启用。</summary>
        public const string UseNotoSansSettingKey = "UseNotoSansFont";

        /// <summary>随应用分发的拉丁字形字体（可变字重，覆盖 Regular 到 Black）。</summary>
        public const string LatinFontAssetRelativePath = "Assets/Fonts/NotoSans-Variable.ttf";

        /// <summary>随应用分发的简体中文字形字体（可变字重，覆盖 Thin 到 Black）。</summary>
        public const string CjkFontAssetRelativePath = "Assets/Fonts/NotoSansSC-Variable.ttf";

        /// <summary>字体族名称，取自字体文件 name 表的 nameID 1。</summary>
        public const string LatinFontFamilyName = "Noto Sans";

        /// <summary>字体族名称，取自字体文件 name 表的 nameID 16（Typographic Family）。</summary>
        public const string CjkFontFamilyName = "Noto Sans SC";

        /// <summary>
        /// 需要覆盖的 WinUI 字体资源键。除了主键，还包含日历控件（DatePicker 的
        /// CalendarView）与旧版兼容键，保证字体切换在各处表现一致。
        /// 刻意不包含 SymbolThemeFontFamily，以免把图标字体一并替换掉。
        /// </summary>
        private static readonly string[] FontResourceKeys =
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
        public static bool IsEnabled { get; private set; }

        /// <summary>
        /// 启用时返回当前使用的 Noto 字体族，未启用时返回 null。
        /// 供代码动态创建的文本控件显式设置 FontFamily——
        /// 这类控件不经过 XAML 的 {ThemeResource} 求值，无法自动跟随设置。
        /// </summary>
        public static FontFamily? CurrentFontFamily
            => IsEnabled ? (_notoSansFontFamily ??= CreateNotoSansFontFamily()) : null;

        /// <summary>
        /// 读取设置。未写入过该设置时视为启用，以满足“默认启用该设置”的需求。
        /// </summary>
        public static bool ReadSetting()
        {
            if (!App.LocalSettings.Values.TryGetValue(UseNotoSansSettingKey, out object? raw))
                return true;

            return raw is not bool value || value;
        }

        /// <summary>按当前设置应用字体，用于应用启动阶段。</summary>
        public static void ApplyFromSetting() => SetEnabled(ReadSetting());

        /// <summary>
        /// 应用或撤销 Noto Sans 默认字体。
        /// 注意：字体资源通过 {ThemeResource} 被默认样式引用，已渲染的控件不会
        /// 重新求值，调用方需要在变更后重载受影响的页面（见 SettingsPage 的开关逻辑）。
        /// </summary>
        /// <param name="enabled">是否使用 Noto Sans。</param>
        public static void SetEnabled(bool enabled)
        {
            IsEnabled = enabled;

            if (Application.Current?.Resources is not ResourceDictionary resources)
                return;

            if (enabled)
            {
                FontFamily fontFamily = _notoSansFontFamily ??= CreateNotoSansFontFamily();
                foreach (string key in FontResourceKeys)
                    resources[key] = fontFamily;
            }
            else
            {
                // 移除本地覆盖后，资源查找回落至 XamlControlsResources 提供的系统默认字体。
                foreach (string key in FontResourceKeys)
                    resources.Remove(key);
            }
        }

        private static FontFamily CreateNotoSansFontFamily()
        {
            // ms-appx 指向应用目录，打包与未打包（WindowsPackageType=None）两种形态均适用。
            // 每个字体都使用独立的完整 URI；空格是 FontFamily 回退项的分隔格式。
            string source = string.Concat(
                "ms-appx:///", LatinFontAssetRelativePath, "#", LatinFontFamilyName,
                ", ms-appx:///", CjkFontAssetRelativePath, "#", CjkFontFamilyName);

            return new FontFamily(source);
        }
    }
}
