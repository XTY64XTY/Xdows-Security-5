using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class LogExportDialog : ContentDialog
    {
        public LogText.LogLevel[] SelectedLevels => GetSelectedLevels();
        public string? SearchKeyword => string.IsNullOrWhiteSpace(KeywordBox.Text) ? null : KeywordBox.Text.Trim();
        public string? FromDate => FromDatePicker.Date?.ToString("yyyy-MM-dd");
        public string? ToDate => ToDatePicker.Date?.ToString("yyyy-MM-dd");

        public LogExportDialog()
        {
            InitializeComponent();
            PrimaryButtonText = Localizer.Get().GetLocalizedString("LogExportDialog_Export");
            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Close");
        }

        private LogText.LogLevel[] GetSelectedLevels()
        {
            var levels = new List<LogText.LogLevel>();
            if (LevelDebug.IsChecked == true) levels.Add(LogText.LogLevel.DEBUG);
            if (LevelInfo.IsChecked == true) levels.Add(LogText.LogLevel.INFO);
            if (LevelWarn.IsChecked == true) levels.Add(LogText.LogLevel.WARN);
            if (LevelError.IsChecked == true) levels.Add(LogText.LogLevel.ERROR);
            if (LevelFatal.IsChecked == true) levels.Add(LogText.LogLevel.FATAL);
            return levels.ToArray();
        }
    }
}
