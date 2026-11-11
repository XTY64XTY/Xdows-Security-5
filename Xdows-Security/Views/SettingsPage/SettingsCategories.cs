using System;
using System.Collections.Generic;
using System.Linq;

namespace Xdows_Security.Views
{
    internal sealed record SettingsCategoryDefinition(
        string Key,
        string PageName,
        Type PageType,
        string TitleResourceKey,
        string PanelName,
        string HomeCardName,
        string[] ToolPageNames);

    internal static class SettingsCategories
    {
        private static readonly IReadOnlyList<SettingsCategoryDefinition> Categories = Array.AsReadOnly(
            new[]
            {
                new SettingsCategoryDefinition("personalization", "SettingsAppearance", typeof(AppearanceSettingsPage), "SettingsHome_Personalization_Title", "Category_Personalization", "PersonalizationCategoryCard", []),
                new SettingsCategoryDefinition("scanning", "SettingsScanning", typeof(ScanningSettingsPage), "SettingsHome_Scanning_Title", "Category_Scanning", "ScanningCategoryCard", ["Engines"]),
                new SettingsCategoryDefinition("engines", "Engines", typeof(EnginesSettingsPage), "EnginesPage_Title", "Category_Engines", string.Empty, ["Model"]),
                new SettingsCategoryDefinition("protection", "SettingsProtection", typeof(ProtectionSettingsPage), "SettingsHome_Protection_Title", "Category_Protection", "ProtectionCategoryCard", ["DriverEnvironment"]),
                new SettingsCategoryDefinition("features", "SettingsFeatures", typeof(FeaturesSettingsPage), "SettingsHome_Features_Title", "Category_Features", "FeaturesCategoryCard", []),
                new SettingsCategoryDefinition("quarantine", "SettingsQuarantine", typeof(QuarantineSettingsPage), "SettingsHome_Quarantine_Title", "Category_Quarantine", "QuarantineCategoryCard", ["Quarantine", "Trust"]),
                new SettingsCategoryDefinition("general", "SettingsOther", typeof(OtherSettingsPage), "SettingsHome_General_Title", "Category_General", "GeneralCategoryCard", []),
            });

        public static IReadOnlyList<SettingsCategoryDefinition> All => Categories;

        public static SettingsCategoryDefinition GetByKey(string key) =>
            Categories.FirstOrDefault(category => string.Equals(category.Key, key, StringComparison.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(key), key, "Unknown settings category.");

        /// <summary>按页面名取类别：先精确匹配类别页名，再匹配其下的工具页。</summary>
        public static SettingsCategoryDefinition GetByPageName(string pageName) =>
            Categories.FirstOrDefault(category => string.Equals(category.PageName, pageName, StringComparison.Ordinal))
            ?? Categories.FirstOrDefault(category => category.ToolPageNames.Contains(pageName, StringComparer.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(pageName), pageName, "Unknown settings page.");

        /// <summary>取某个工具页所属的类别（工具页名可与类别页名重名，例如「引擎」）。</summary>
        public static SettingsCategoryDefinition GetByToolPageName(string pageName) =>
            Categories.FirstOrDefault(category => category.ToolPageNames.Contains(pageName, StringComparer.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(pageName), pageName, "Unknown settings tool page.");

        public static SettingsCategoryDefinition GetByPageType(Type pageType) =>
            Categories.FirstOrDefault(category => category.PageType == pageType)
            ?? throw new ArgumentOutOfRangeException(nameof(pageType), pageType, "Unknown settings category page type.");

        public static bool IsCategoryPageName(string pageName) =>
            Categories.Any(category => string.Equals(category.PageName, pageName, StringComparison.Ordinal));

        public static bool IsToolPageName(string pageName) =>
            Categories.Any(category => category.ToolPageNames.Contains(pageName, StringComparer.Ordinal));

        public static bool IsSettingsSubPageName(string pageName) =>
            IsCategoryPageName(pageName) || IsToolPageName(pageName);
    }
}
