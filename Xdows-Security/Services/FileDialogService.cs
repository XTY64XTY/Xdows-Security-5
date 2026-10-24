using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.UI.Xaml;

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

    //
    // 主题跟随：IFileDialog 没有公开的"深色模式"开关，只能在对话框窗口创建后
    // 对它的 HWND 应用 DWM 深色属性与深色视觉样式。HWND 只在 Show 之后才存在，
    // 而 Show 是模态阻塞的，因此唯一正规的切入点是在 IFileDialogEvents 回调里
    // 通过 IOleWindow::GetWindow 拿到窗口。
    //
    // IFileDialogEvents vtable 顺序（Windows SDK 10.0.28000.0，shobjidl_core.h）：
    // 3 OnFileOk / 4 OnFolderChanging / 5 OnFolderChange / 6 OnSelectionChange
    // 7 OnShareViolation / 8 OnTypeChange / 9 OnOverwrite
    //
    private static readonly Guid IID_IFileDialogEvents = new("973510DB-7D7F-452B-8975-74A85828D354");
    private static readonly Guid IID_IOleWindow = new("00000114-0000-0000-C000-000000000046");
    private static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");

    private const uint DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int S_OK = 0;
    private const int E_NOINTERFACE = unchecked((int)0x80004002);
    private const int E_POINTER = unchecked((int)0x80004003);

    private static nint s_eventsVtable;
    private static int s_themeApplied;
    private static bool s_useDarkTheme;

    // IFileDialog vtable 槽位（IUnknown 0-2 之后）。
    private const int SlotShow = 3;
    private const int SlotSetFileTypes = 4;
    private const int SlotAdvise = 7;
    private const int SlotUnadvise = 8;
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

    // IOleWindow vtable 槽位。
    private const int SlotOleWindowGetWindow = 3;

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

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(
        nint hwnd,
        uint dwAttribute,
        int* pvAttribute,
        uint cbAttribute);

    [LibraryImport("uxtheme.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SetWindowTheme(
        nint hwnd,
        string? pszSubAppName,
        string? pszSubIdList);

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

        uint themeCookie = 0;
        IntPtr eventsObject = IntPtr.Zero;

        try
        {
            void** vtable = *(void***)dialog;

            s_useDarkTheme = ShouldUseDarkTheme();
            Volatile.Write(ref s_themeApplied, 0);
            eventsObject = CreateDialogEvents();
            var advise = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint*, int>)vtable[SlotAdvise];
            if (advise(dialog, eventsObject, &themeCookie) != S_OK)
            {
                themeCookie = 0;
            }

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
            if (themeCookie != 0)
            {
                var unadvise = (delegate* unmanaged[Stdcall]<IntPtr, uint, int>)(*(void***)dialog)[SlotUnadvise];
                unadvise(dialog, themeCookie);
            }

            if (eventsObject != IntPtr.Zero)
            {
                ReleaseDialogEvents(eventsObject);
            }

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

    private static bool ShouldUseDarkTheme()
    {
        return App.MainWindow?.Content is FrameworkElement root && root.ActualTheme == ElementTheme.Dark;
    }

    /// <summary>
    /// 对通用文件对话框的 HWND 应用深色外观。DWM 属性自 Windows 11 22000 起支持；
    /// <c>DarkMode_Explorer</c> 是 shell 用于深色视觉样式的主题名（未文档化，
    /// 与资源管理器深色模式同一套）。
    /// </summary>
    private static unsafe void ApplyDialogTheme(IntPtr dialog)
    {
        if (Volatile.Read(ref s_themeApplied) != 0)
        {
            return;
        }

        Guid iidOleWindow = IID_IOleWindow;
        var queryInterface = (delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)(*(void***)dialog)[0];
        IntPtr oleWindow;
        if (queryInterface(dialog, &iidOleWindow, &oleWindow) != S_OK || oleWindow == IntPtr.Zero)
        {
            return;
        }

        try
        {
            IntPtr hwnd;
            var getWindow = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)(*(void***)oleWindow)[SlotOleWindowGetWindow];
            if (getWindow(oleWindow, &hwnd) != S_OK || hwnd == IntPtr.Zero)
            {
                return;
            }

            int useDark = s_useDarkTheme ? 1 : 0;
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(int));
            SetWindowTheme(hwnd, s_useDarkTheme ? "DarkMode_Explorer" : null, null);
            Volatile.Write(ref s_themeApplied, 1);
        }
        finally
        {
            ReleaseComObject(oleWindow);
        }
    }

    private static unsafe IntPtr EnsureEventsVtable()
    {
        if (s_eventsVtable != IntPtr.Zero)
        {
            return s_eventsVtable;
        }

        IntPtr* table = (IntPtr*)NativeMemory.Alloc(10 * (nuint)sizeof(IntPtr));
        table[0] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)&EventsQueryInterface;
        table[1] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&EventsAddRef;
        table[2] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&EventsRelease;
        table[3] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)&EventsOnFileOk;
        table[4] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, int>)&EventsOnFolderChanging;
        table[5] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)&EventsOnFolderChange;
        table[6] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)&EventsOnSelectionChange;
        table[7] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, int*, int>)&EventsOnShareViolation;
        table[8] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)&EventsOnTypeChange;
        table[9] = (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, int*, int>)&EventsOnOverwrite;

        s_eventsVtable = (IntPtr)table;
        return s_eventsVtable;
    }

    /// <summary>分配一个 IFileDialogEvents 实现对象：首字段为 vtable，其后为引用计数。</summary>
    private static unsafe IntPtr CreateDialogEvents()
    {
        byte* memory = (byte*)NativeMemory.Alloc(16);
        *(IntPtr*)memory = EnsureEventsVtable();
        *(int*)(memory + sizeof(IntPtr)) = 1;
        return (IntPtr)memory;
    }

    private static unsafe int AddRefCore(IntPtr eventsObject)
    {
        int* count = (int*)((byte*)eventsObject + sizeof(IntPtr));
        return Interlocked.Increment(ref *count);
    }

    private static unsafe void ReleaseDialogEvents(IntPtr eventsObject)
    {
        int* count = (int*)((byte*)eventsObject + sizeof(IntPtr));
        if (Interlocked.Decrement(ref *count) == 0)
        {
            NativeMemory.Free((void*)eventsObject);
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static unsafe int EventsQueryInterface(IntPtr thisPtr, Guid* riid, IntPtr* ppvObject)
    {
        if (ppvObject is null)
        {
            return E_POINTER;
        }

        if (*riid == IID_IUnknown || *riid == IID_IFileDialogEvents)
        {
            *ppvObject = thisPtr;
            AddRefCore(thisPtr);
            return S_OK;
        }

        *ppvObject = IntPtr.Zero;
        return E_NOINTERFACE;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint EventsAddRef(IntPtr thisPtr) => (uint)AddRefCore(thisPtr);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint EventsRelease(IntPtr thisPtr)
    {
        ReleaseDialogEvents(thisPtr);
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EventsOnFileOk(IntPtr thisPtr, IntPtr dialog) => S_OK;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EventsOnFolderChanging(IntPtr thisPtr, IntPtr dialog, IntPtr folder)
    {
        ApplyDialogTheme(dialog);
        return S_OK;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EventsOnFolderChange(IntPtr thisPtr, IntPtr dialog) => S_OK;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EventsOnSelectionChange(IntPtr thisPtr, IntPtr dialog) => S_OK;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int EventsOnTypeChange(IntPtr thisPtr, IntPtr dialog)
    {
        ApplyDialogTheme(dialog);
        return S_OK;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static unsafe int EventsOnShareViolation(IntPtr thisPtr, IntPtr dialog, IntPtr item, int* response)
    {
        if (response is not null)
        {
            *response = 0;
        }

        return S_OK;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static unsafe int EventsOnOverwrite(IntPtr thisPtr, IntPtr dialog, IntPtr item, int* response)
    {
        if (response is not null)
        {
            *response = 0;
        }

        return S_OK;
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
