using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Xdows_Security.Services;

/// <summary>
/// 经典 Win32 通用文件对话框（IFileDialog COM）封装。
///
/// 为什么不用 WinAppSDK 的 FileSavePicker / FileOpenPicker / FolderPicker：
/// 它们在提权（requireAdministrator）进程与部分环境下依赖的激活机制不可用，
/// 会静默返回 null（实测：导出日志、启动盘备份、信任区添加、隔离区还原、
/// 游戏路径添加全部失效，且关闭防护也无法恢复）。
///
/// 为什么是手工 vtable 调用而不是 [ComImport]：本应用以 NativeAOT 发布，
/// ComImport coclass 激活（new）在 AOT 下不被支持，会抛
/// InvalidProgramException（FileSaveDialogRCW..ctor is invalid，00:56 日志实锤）。
/// 这里全部走 CoCreateInstance P/Invoke + delegate* unmanaged 函数指针 +
/// blittable 签名，NativeAOT 明确支持。
///
/// 必须在 STA 线程（WinUI UI 线程）上调用。
/// </summary>
internal static unsafe partial class FileDialogService
{
    private const uint CLSCTX_INPROC_SERVER = 1;
    private const uint SIGDN_FILESYSPATH = 0x80058000;

    private static readonly Guid CLSID_FileSaveDialog = new("C0B4E2F3-BA21-4773-8DBA-335EC946EB8B");
    private static readonly Guid CLSID_FileOpenDialog = new("DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7");
    //
    // IID 取自注册表 HKEY_CLASSES_ROOT\Interface（IID_IFileDialog
    // = {42F85136-DB7E-439C-85F1-E4075D135FC8}）。写错会得到 E_NOINTERFACE
    // （0x80004002）：CLSID 能实例化、但 QI 不到请求的接口。
    //
    private static readonly Guid IID_IFileDialog = new("42F85136-DB7E-439C-85F1-E4075D135FC8");
    private static readonly Guid IID_IShellItem = new("43826D1E-E718-42EE-BC55-A1E261C37BFE");

    // IFileDialog vtable 槽位（IUnknown 0-2 之后）。
    private const int SlotShow = 3;
    private const int SlotSetFileTypes = 4;
    private const int SlotSetOptions = 9;
    private const int SlotSetFileName = 15;
    private const int SlotGetResult = 20;
    private const int SlotSetDefaultExtension = 22;
    private const int SlotSetDefaultFolder = 11;
    private const int SlotRelease = 2;

    // IFileOpenDialog 附加槽位（IFileDialog 全部槽位之后）。
    private const int SlotOpenGetResults = 27;

    // IShellItem vtable 槽位。
    private const int SlotItemGetDisplayName = 5;

    // IShellItemArray vtable 槽位。
    private const int SlotArrayGetCount = 7;
    private const int SlotArrayGetItemAt = 8;

    [LibraryImport("ole32.dll")]
    private static partial int CoCreateInstance(
        in Guid rclsid,
        IntPtr pUnkOuter,
        uint dwClsContext,
        in Guid riid,
        out IntPtr ppv);

    [LibraryImport("ole32.dll")]
    private static partial void CoTaskMemFree(IntPtr pv);

    [LibraryImport("shell32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHCreateItemFromParsingName(
        string pszPath,
        IntPtr pbc,
        in Guid riid,
        out IntPtr ppv);

    /// <summary>保存文件对话框。用户取消或失败时返回 null。</summary>
    public static string? PickSaveFile(
        nint ownerHwnd,
        string suggestedFileName,
        string defaultExtension,
        string filter,
        string? initialDirectory = null)
    {
        return ShowCore(
            ownerHwnd,
            saveMode: true,
            multiSelect: false,
            pickFolders: false,
            suggestedFileName,
            defaultExtension,
            filter,
            initialDirectory) is { Count: > 0 } results ? results[0] : null;
    }

    /// <summary>单选打开文件对话框。用户取消或失败时返回 null。</summary>
    public static string? PickOpenFile(
        nint ownerHwnd,
        string filter,
        string? initialDirectory = null)
    {
        return ShowCore(
            ownerHwnd,
            saveMode: false,
            multiSelect: false,
            pickFolders: false,
            suggestedFileName: null,
            defaultExtension: null,
            filter,
            initialDirectory) is { Count: > 0 } results ? results[0] : null;
    }

    /// <summary>多选打开文件对话框。用户取消或失败时返回空集合。</summary>
    public static IReadOnlyList<string> PickOpenFiles(
        nint ownerHwnd,
        string filter,
        string? initialDirectory = null)
    {
        return ShowCore(
            ownerHwnd,
            saveMode: false,
            multiSelect: true,
            pickFolders: false,
            suggestedFileName: null,
            defaultExtension: null,
            filter,
            initialDirectory) ?? Array.Empty<string>();
    }

    /// <summary>选择文件夹对话框。用户取消或失败时返回 null。</summary>
    public static string? PickFolder(
        nint ownerHwnd,
        string? initialDirectory = null)
    {
        return ShowCore(
            ownerHwnd,
            saveMode: false,
            multiSelect: false,
            pickFolders: true,
            suggestedFileName: null,
            defaultExtension: null,
            filter: null,
            initialDirectory) is { Count: > 0 } results ? results[0] : null;
    }

    private static IReadOnlyList<string>? ShowCore(
        nint ownerHwnd,
        bool saveMode,
        bool multiSelect,
        bool pickFolders,
        string? suggestedFileName,
        string? defaultExtension,
        string? filter,
        string? initialDirectory)
    {
        int hr = CoCreateInstance(
            saveMode ? CLSID_FileSaveDialog : CLSID_FileOpenDialog,
            IntPtr.Zero,
            CLSCTX_INPROC_SERVER,
            IID_IFileDialog,
            out IntPtr dialog);
        if (hr != 0 || dialog == IntPtr.Zero)
        {
            LogDialogFailure($"CoCreateInstance failed hr=0x{hr:X8}");
            return null;
        }

        try
        {
            void** vtable = *(void***)dialog;

            uint options = (uint)FOS.ForceFilesystem;
            options |= pickFolders ? (uint)FOS.PickFolders : (uint)FOS.PathMustExist;
            if (saveMode)
            {
                options |= (uint)FOS.OverwritePrompt;
            }
            else if (!pickFolders)
            {
                options |= (uint)FOS.FileMustExist;
            }
            if (multiSelect)
            {
                options |= (uint)FOS.AllowMultiSelect;
            }

            var setOptions = (delegate* unmanaged[Stdcall]<IntPtr, uint, int>)vtable[SlotSetOptions];
            int optionsHr = setOptions(dialog, options);
            if (optionsHr != 0)
            {
                LogDialogFailure($"IFileDialog::SetOptions failed hr=0x{optionsHr:X8}");
                return null;
            }

            if (!string.IsNullOrEmpty(suggestedFileName))
            {
                IntPtr namePtr = Marshal.StringToCoTaskMemUni(suggestedFileName);
                if (namePtr == IntPtr.Zero)
                {
                    return null;
                }
                try
                {
                    var setFileName = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)vtable[SlotSetFileName];
                    if (setFileName(dialog, namePtr) != 0)
                    {
                        return null;
                    }
                }
                finally
                {
                    CoTaskMemFree(namePtr);
                }
            }

            if (!string.IsNullOrEmpty(defaultExtension))
            {
                IntPtr extPtr = Marshal.StringToCoTaskMemUni(defaultExtension);
                if (extPtr == IntPtr.Zero)
                {
                    return null;
                }
                try
                {
                    var setDefaultExtension = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)vtable[SlotSetDefaultExtension];
                    if (setDefaultExtension(dialog, extPtr) != 0)
                    {
                        return null;
                    }
                }
                finally
                {
                    CoTaskMemFree(extPtr);
                }
            }

            FilterSpec* filterSpecs = null;
            uint filterCount = 0;
            try
            {
                filterSpecs = BuildNativeFilter(filter, out filterCount);
                if (filterCount > 0)
                {
                    var setFileTypes = (delegate* unmanaged[Stdcall]<IntPtr, uint, FilterSpec*, int>)vtable[SlotSetFileTypes];
                    setFileTypes(dialog, filterCount, filterSpecs);
                }
            }
            finally
            {
                FreeNativeFilter(filterSpecs, filterCount);
            }

            if (!string.IsNullOrEmpty(initialDirectory) &&
                System.IO.Directory.Exists(initialDirectory))
            {
                if (SHCreateItemFromParsingName(
                        initialDirectory, IntPtr.Zero, IID_IShellItem, out IntPtr folder) == 0 &&
                    folder != IntPtr.Zero)
                {
                    try
                    {
                        var setDefaultFolder = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)vtable[SlotSetDefaultFolder];
                        setDefaultFolder(dialog, folder);
                    }
                    finally
                    {
                        ReleaseComObject(folder);
                    }
                }
            }

            var show = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)vtable[SlotShow];
            int showHr = show(dialog, ownerHwnd);
            if (showHr != 0)
            {
                // 0x800704C7 = ERROR_CANCELLED（用户取消，正常静默）；其余必留痕。
                if (showHr != unchecked((int)0x800704C7))
                {
                    LogDialogFailure($"IFileDialog::Show failed hr=0x{showHr:X8}");
                }
                return null;
            }

            var getResult = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)vtable[SlotGetResult];
            IntPtr resultItemPtr;
            int resultHr = getResult(dialog, &resultItemPtr);
            if (resultHr != 0 || resultItemPtr == IntPtr.Zero)
            {
                LogDialogFailure($"IFileDialog::GetResult failed hr=0x{resultHr:X8}");
                return null;
            }
            IntPtr resultItem = resultItemPtr;

            try
            {
                if (multiSelect)
                {
                    //
                    // 多选必须经 IFileOpenDialog::GetResults（IFileDialog::GetResult
                    // 只返回单条）。IFileOpenDialog 的 vtable 前缀与 IFileDialog 完全
                    // 一致（同一 COM 对象），直接用对象指针取第 27 槽。
                    //
                    void** openVtable = *(void***)dialog;
                    var getResults = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)openVtable[SlotOpenGetResults];
                    IntPtr arrayPtr;
                    if (getResults(dialog, &arrayPtr) != 0 || arrayPtr == IntPtr.Zero)
                    {
                        return Array.Empty<string>();
                    }

                    try
                    {
                        void** arrayVtable = *(void***)arrayPtr;
                        var getCount = (delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)arrayVtable[SlotArrayGetCount];
                        var getItemAt = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)arrayVtable[SlotArrayGetItemAt];
                        uint count;
                        if (getCount(arrayPtr, &count) != 0)
                        {
                            return Array.Empty<string>();
                        }

                        var paths = new List<string>((int)count);
                        for (uint i = 0; i < count; i++)
                        {
                            IntPtr item;
                            if (getItemAt(arrayPtr, i, &item) == 0 && item != IntPtr.Zero)
                            {
                                try
                                {
                                    void** itemVtable = *(void***)item;
                                    var getDisplayName = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)itemVtable[SlotItemGetDisplayName];
                                    IntPtr pathPtr;
                                    if (getDisplayName(item, SIGDN_FILESYSPATH, &pathPtr) == 0 &&
                                        pathPtr != IntPtr.Zero)
                                    {
                                        paths.Add(Marshal.PtrToStringUni(pathPtr) ?? string.Empty);
                                    }
                                }
                                finally
                                {
                                    ReleaseComObject(item);
                                }
                            }
                        }
                        return paths;
                    }
                    finally
                    {
                        ReleaseComObject(arrayPtr);
                    }
                }

                void** resultVtable = *(void***)resultItem;
                var resultGetDisplayName = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)resultVtable[SlotItemGetDisplayName];
                IntPtr resultPath;
                if (resultGetDisplayName(resultItem, SIGDN_FILESYSPATH, &resultPath) != 0 ||
                    resultPath == IntPtr.Zero)
                {
                    return null;
                }

                string selected = Marshal.PtrToStringUni(resultPath) ?? string.Empty;
                return new List<string> { selected };
            }
            finally
            {
                ReleaseComObject(resultItem);
            }
        }
        finally
        {
            ReleaseComObject(dialog);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct FilterSpec
    {
        public readonly IntPtr Name;
        public readonly IntPtr Spec;

        public FilterSpec(IntPtr name, IntPtr spec)
        {
            Name = name;
            Spec = spec;
        }
    }

    private static FilterSpec* BuildNativeFilter(string? filter, out uint count)
    {
        count = 0;
        if (string.IsNullOrWhiteSpace(filter))
        {
            return null;
        }

        string[] parts = filter.Split('|');
        if (parts.Length < 2)
        {
            return null;
        }

        var specs = new List<(IntPtr Name, IntPtr Spec)>();
        for (int i = 0; i + 1 < parts.Length; i += 2)
        {
            IntPtr name = Marshal.StringToCoTaskMemUni(parts[i]);
            IntPtr spec = Marshal.StringToCoTaskMemUni(parts[i + 1]);
            if (name == IntPtr.Zero || spec == IntPtr.Zero)
            {
                FreeSpecList(specs);
                return null;
            }
            specs.Add((name, spec));
        }

        if (specs.Count == 0)
        {
            return null;
        }

        count = (uint)specs.Count;
        FilterSpec* native = (FilterSpec*)Marshal.AllocCoTaskMem(
            sizeof(FilterSpec) * specs.Count);
        for (int i = 0; i < specs.Count; i++)
        {
            native[i] = new FilterSpec(specs[i].Name, specs[i].Spec);
        }
        return native;
    }

    private static void FreeNativeFilter(FilterSpec* native, uint count)
    {
        if (native == null)
        {
            return;
        }

        for (uint i = 0; i < count; i++)
        {
            CoTaskMemFree(native[i].Name);
            CoTaskMemFree(native[i].Spec);
        }
        Marshal.FreeCoTaskMem((IntPtr)native);
    }

    private static void FreeSpecList(List<(IntPtr Name, IntPtr Spec)> specs)
    {
        foreach (var (name, spec) in specs)
        {
            CoTaskMemFree(name);
            CoTaskMemFree(spec);
        }
    }

    private static void ReleaseComObject(IntPtr comObject)
    {
        if (comObject != IntPtr.Zero)
        {
            ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(void***)comObject)[SlotRelease])(comObject);
        }
    }

    /// <summary>
    /// 对话框失败必须留痕：过去所有失败都被静默吞掉（返回 null），用户侧
    /// 表现为「点击导出后没有任何反应」且日志里找不到原因。
    /// </summary>
    private static void LogDialogFailure(string message)
    {
        try
        {
            LogText.AddNewLog(LogText.LogLevel.WARN, "FileDialog", message);
        }
        catch
        {
            // 日志系统本身不可用时不应让对话框代码崩溃。
        }
    }

    private enum FOS : uint
    {
        OverwritePrompt = 0x2,
        PickFolders = 0x20,
        ForceFilesystem = 0x40,
        AllowMultiSelect = 0x200,
        PathMustExist = 0x800,
        FileMustExist = 0x1000
    }
}
