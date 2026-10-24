using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using WinUI3Localizer;

namespace Xdows_Security.Services;

/// <summary>应用内文件选择器的工作模式。</summary>
public enum FilePickerMode
{
    Open,
    Save,
    Folder
}

/// <summary>「文件类型」下拉里的一组过滤项。</summary>
public sealed class FilePickerTypeGroup
{
    public FilePickerTypeGroup(string label, IReadOnlyList<string> extensions)
    {
        Label = label;
        Extensions = extensions;
    }

    public string Label { get; }

    /// <summary>已带前导点的扩展名，如 ".exe"；空集合表示不过滤。</summary>
    public IReadOnlyList<string> Extensions { get; }
}

/// <summary>一次文件选择请求的参数。</summary>
public sealed class FilePickerOptions
{
    public FilePickerMode Mode { get; init; }

    public bool AllowMultiple { get; init; }

    public string? InitialDirectory { get; init; }

    public string? SuggestedFileName { get; init; }

    public string? DefaultExtension { get; init; }

    public IReadOnlyList<FilePickerTypeGroup> FileTypes { get; init; } = Array.Empty<FilePickerTypeGroup>();
}

/// <summary>文件列表里的一行。</summary>
public sealed class FilePickerEntry
{
    private FilePickerEntry(string name, string fullPath, bool isFolder, long size, DateTime modified)
    {
        Name = name;
        FullPath = fullPath;
        IsFolder = isFolder;
        Size = size;
        Modified = modified;
    }

    public string Name { get; }

    public string FullPath { get; }

    public bool IsFolder { get; }

    public long Size { get; }

    public DateTime Modified { get; }

    public string Glyph => IsFolder ? "\uE8B7" : "\uE7C3";

    public string TypeText
    {
        get
        {
            if (IsFolder)
            {
                return Localizer.Get().GetLocalizedString("FilePicker_Type_Folder");
            }

            string extension = Path.GetExtension(Name).TrimStart('.');
            return extension.Length == 0
                ? Localizer.Get().GetLocalizedString("FilePicker_Type_File")
                : string.Format(
                    CultureInfo.CurrentCulture,
                    Localizer.Get().GetLocalizedString("FilePicker_Type_FileFormat"),
                    extension.ToUpperInvariant());
        }
    }

    public string SizeText => IsFolder ? string.Empty : FormatSize(Size);

    public string DateText => Modified.ToString("yyyy/MM/dd HH:mm", CultureInfo.CurrentCulture);

    public static FilePickerEntry FromDirectory(DirectoryInfo info) =>
        new(info.Name, info.FullName, true, 0, info.LastWriteTime);

    public static FilePickerEntry FromFile(FileInfo info) =>
        new(info.Name, info.FullName, false, info.Length, info.LastWriteTime);

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0} B", bytes);
        }

        double value = bytes / 1024d;
        if (value < 1024)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0:0.#} KB", value);
        }

        value /= 1024d;
        if (value < 1024)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0:0.#} MB", value);
        }

        value /= 1024d;
        return string.Format(CultureInfo.CurrentCulture, "{0:0.#} GB", value);
    }
}

/// <summary>左侧导航栏的一项。</summary>
public sealed class FilePickerLocation
{
    public FilePickerLocation(string glyph, string label, string path)
    {
        Glyph = glyph;
        Label = label;
        Path = path;
    }

    public string Glyph { get; }

    public string Label { get; }

    public string Path { get; }
}
