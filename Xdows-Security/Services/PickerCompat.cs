using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI;

namespace Xdows_Security.Services;

/// <summary>WinAppSDK PickerLocationId 的兼容枚举。</summary>
public enum PickerLocationId
{
    DocumentsLibrary,
    ComputerFolder,
    Desktop,
    Downloads,
    MusicLibrary,
    PicturesLibrary,
    VideosLibrary,
    Unspecified
}

/// <summary>WinAppSDK PickFileResult 的兼容类型。</summary>
public sealed class PickFileResult
{
    public string Path { get; }

    public PickFileResult(string path)
    {
        Path = path;
    }
}

/// <summary>WinAppSDK PickFolderResult 的兼容类型。</summary>
public sealed class PickFolderResult
{
    public string Path { get; }

    public PickFolderResult(string path)
    {
        Path = path;
    }
}

/// <summary>
/// WinAppSDK <c>Microsoft.Windows.Storage.Pickers.FileSavePicker</c> 的
/// API 兼容实现，内部改用进程内 Win32 IFileDialog。
///
/// 背景：WinAppSDK 选择器在提权（requireAdministrator）进程与部分环境下
/// 依赖的激活机制不可用，会静默返回 null。调用方式与 WinAppSDK 完全一致，
/// 仅需把 using 从 <c>Microsoft.Windows.Storage.Pickers</c> 换到本命名空间。
///
/// 线程模型：直接在调用线程（WinUI 的 XAML UI 线程）上执行。该线程本身是
/// STA，满足 IFileDialog 文档对套间的要求；模态对话框由它自己的消息泵驱动，
/// 窗口能正常激活并前置。**不要**把对话框搬到自定义线程：那样窗口不会被
/// 激活/置前，且 Show() 卡住时会占住线程池线程，最终拖垮整个应用。
/// </summary>
public sealed class FileSavePicker
{
    private readonly nint _ownerHwnd;

    public string SuggestedFileName { get; set; } = string.Empty;

    public string DefaultFileExtension { get; set; } = string.Empty;

    public PickerLocationId SuggestedStartLocation { get; set; } = PickerLocationId.Unspecified;

    public string? SuggestedFolder { get; set; }

    public IDictionary<string, IList<string>> FileTypeChoices { get; } =
        new Dictionary<string, IList<string>>();

    public FileSavePicker(Microsoft.UI.WindowId appWindowId)
    {
        _ownerHwnd = (nint)appWindowId.Value;
    }

    public Task<PickFileResult> PickSaveFileAsync()
    {
        string filter = PickerCompat.BuildChoicesFilter(
            FileTypeChoices.SelectMany(kv => kv.Value.Select(ext => (Name: kv.Key, Ext: ext))));

        string? path = FileDialogService.PickSaveFile(
            _ownerHwnd,
            SuggestedFileName,
            DefaultFileExtension,
            filter,
            PickerCompat.ResolveInitialDirectory(SuggestedFolder, SuggestedStartLocation));

        return Task.FromResult(
            path is null ? null! : new PickFileResult(path));
    }
}

/// <summary>
/// WinAppSDK <c>Microsoft.Windows.Storage.Pickers.FileOpenPicker</c> 的
/// API 兼容实现（见 <see cref="FileSavePicker"/> 的说明）。
/// </summary>
public sealed class FileOpenPicker
{
    private readonly nint _ownerHwnd;

    public PickerLocationId SuggestedStartLocation { get; set; } = PickerLocationId.Unspecified;

    public IList<string> FileTypeFilter { get; } = new List<string>();

    public FileOpenPicker(Microsoft.UI.WindowId appWindowId)
    {
        _ownerHwnd = (nint)appWindowId.Value;
    }

    public Task<PickFileResult> PickSingleFileAsync()
    {
        string filter = PickerCompat.BuildFilterFilter(FileTypeFilter);

        string? path = FileDialogService.PickOpenFile(
            _ownerHwnd,
            filter,
            PickerCompat.ResolveInitialDirectory(null, SuggestedStartLocation));

        return Task.FromResult(
            path is null ? null! : new PickFileResult(path));
    }

    public Task<IReadOnlyList<PickFileResult>> PickMultipleFilesAsync()
    {
        string filter = PickerCompat.BuildFilterFilter(FileTypeFilter);

        IReadOnlyList<string> paths = FileDialogService.PickOpenFiles(
            _ownerHwnd,
            filter,
            PickerCompat.ResolveInitialDirectory(null, SuggestedStartLocation));

        return Task.FromResult<IReadOnlyList<PickFileResult>>(
            paths.Select(p => new PickFileResult(p)).ToArray());
    }
}

/// <summary>
/// WinAppSDK <c>Microsoft.Windows.Storage.Pickers.FolderPicker</c> 的
/// API 兼容实现（见 <see cref="FileSavePicker"/> 的说明）。
/// </summary>
public sealed class FolderPicker
{
    private readonly nint _ownerHwnd;

    public PickerLocationId SuggestedStartLocation { get; set; } = PickerLocationId.Unspecified;

    public FolderPicker(Microsoft.UI.WindowId appWindowId)
    {
        _ownerHwnd = (nint)appWindowId.Value;
    }

    public Task<PickFolderResult> PickSingleFolderAsync()
    {
        string? path = FileDialogService.PickFolder(
            _ownerHwnd,
            PickerCompat.ResolveInitialDirectory(null, SuggestedStartLocation));

        return Task.FromResult(
            path is null ? null! : new PickFolderResult(path));
    }

    public Task<IReadOnlyList<PickFolderResult>> PickMultipleFoldersAsync()
    {
        string? path = FileDialogService.PickFolder(
            _ownerHwnd,
            PickerCompat.ResolveInitialDirectory(null, SuggestedStartLocation));

        IReadOnlyList<PickFolderResult> results =
            path is null ? Array.Empty<PickFolderResult>() : new[] { new PickFolderResult(path) };

        return Task.FromResult(results);
    }
}

/// <summary>选择器兼容层的共享内部逻辑。</summary>
internal static class PickerCompat
{
    /// <summary>把 FileTypeChoices（名称 → 扩展名集合）拼成 IFileDialog 过滤串。</summary>
    public static string BuildChoicesFilter(
        IEnumerable<(string Name, string Ext)> choices)
    {
        var parts = new List<string>();
        foreach (var (name, ext) in choices)
        {
            string spec = EnsureDot(ext);
            parts.Add($"{name} ({spec})|{spec}");
        }

        if (parts.Count == 0)
        {
            parts.Add("All files (*.*)|*.*");
        }

        return string.Join("|", parts);
    }

    /// <summary>把 FileTypeFilter（扩展名列表）拼成 IFileDialog 过滤串。</summary>
    public static string BuildFilterFilter(IEnumerable<string> extensions)
    {
        var exts = extensions
            .Select(EnsureDot)
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (exts.Count == 0)
        {
            return "All files (*.*)|*.*";
        }

        string spec = string.Join(";", exts);
        return $"Files ({spec})|{spec}";
    }

    /// <summary>SuggestedFolder 优先，其次按 SuggestedStartLocation 映射到已知目录。</summary>
    public static string? ResolveInitialDirectory(
        string? suggestedFolder, PickerLocationId location)
    {
        if (!string.IsNullOrWhiteSpace(suggestedFolder) &&
            System.IO.Directory.Exists(suggestedFolder))
        {
            return suggestedFolder;
        }

        return location switch
        {
            PickerLocationId.DocumentsLibrary =>
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            PickerLocationId.Desktop =>
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            PickerLocationId.Downloads =>
                System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads"),
            PickerLocationId.MusicLibrary =>
                Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
            PickerLocationId.PicturesLibrary =>
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            PickerLocationId.VideosLibrary =>
                Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            _ => null
        };
    }

    private static string EnsureDot(string ext)
    {
        ext = ext.Trim();
        if (ext.Length == 0)
        {
            return ext;
        }

        return ext.StartsWith('.') ? ext : "." + ext;
    }
}
