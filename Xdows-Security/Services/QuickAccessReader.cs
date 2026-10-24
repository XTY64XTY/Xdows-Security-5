using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Xdows_Security.Services;

/// <summary>
/// 读取 shell「快速访问 / 主文件夹」命名空间里的固定项。
///
/// 用户自己在资源管理器里 pin 的文件夹就存在这里，注册表和磁盘上都没有可读的
/// 明文清单（实际落在 AutomaticDestinations 复合文档里），所以只能枚举 shell 命名空间：
/// SHCreateItemFromParsingName → IShellItem::BindToHandler(BHID_SFObject) 拿 IShellFolder
/// → IShellFolder::EnumObjects → IEnumIDList::Next → SHCreateItemWithParent 取回真实路径。
///
/// vtable 槽位对照 Windows SDK 10.0.28000.0（ShObjIdl_core.h）：
/// IShellItem  3 BindToHandler / 5 GetDisplayName
/// IShellFolder 4 EnumObjects
/// IEnumIDList  3 Next
/// 必须在已初始化 COM 的线程（WinUI UI 线程）上调用。
/// </summary>
internal static unsafe partial class QuickAccessReader
{
    private const uint SIGDN_NORMALDISPLAY = 0;
    private const uint SIGDN_FILESYSPATH = 0x80058000;
    private const uint SHCONTF_FOLDERS = 0x20;

    private const int SlotRelease = 2;
    private const int SlotShellItemBindToHandler = 3;
    private const int SlotShellItemGetDisplayName = 5;
    private const int SlotShellFolderEnumObjects = 4;
    private const int SlotEnumIdListNext = 3;

    private static readonly Guid IID_IShellItem = new("43826D1E-E718-42EE-BC55-A1E261C37BFE");
    private static readonly Guid IID_IShellFolder = new("000214E6-0000-0000-C000-000000000046");
    private static readonly Guid BHID_SFObject = new("3981E224-F559-11D3-8E3A-00C04F6837D5");

    // Windows 10 的「快速访问」与 Windows 11 的「主文件夹」是同一个命名空间的两种外壳，
    // 任一可用即返回；两者在 Win11 上返回同一份固定项。
    private static readonly string[] NamespacePaths =
    [
        "shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}",
        "shell:::{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
    ];

    [LibraryImport("shell32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHCreateItemFromParsingName(
        string pszPath,
        IntPtr pbc,
        in Guid riid,
        out IntPtr ppv);

    [LibraryImport("shell32.dll")]
    private static partial int SHCreateItemWithParent(
        IntPtr pidlParent,
        IntPtr psfParent,
        IntPtr pidl,
        in Guid riid,
        out IntPtr ppvItem);

    [LibraryImport("shell32.dll", EntryPoint = "ILFree")]
    private static partial void ILFree(IntPtr pidl);

    [LibraryImport("ole32.dll")]
    private static partial void CoTaskMemFree(IntPtr pv);

    /// <summary>返回固定项的显示名与完整路径；取不到文件系统路径的项（如"此电脑"）会被跳过。</summary>
    public static IReadOnlyList<(string Name, string Path)> GetPinnedFolders()
    {
        foreach (string namespacePath in NamespacePaths)
        {
            List<(string Name, string Path)> items = Enumerate(namespacePath);
            if (items.Count > 0)
            {
                return items;
            }
        }

        return Array.Empty<(string Name, string Path)>();
    }

    private static List<(string Name, string Path)> Enumerate(string namespacePath)
    {
        var result = new List<(string Name, string Path)>();

        if (SHCreateItemFromParsingName(namespacePath, IntPtr.Zero, IID_IShellItem, out IntPtr item) != 0 ||
            item == IntPtr.Zero)
        {
            return result;
        }

        try
        {
            Guid iidFolder = IID_IShellFolder;
            Guid bhid = BHID_SFObject;
            var bindToHandler =
                (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, Guid*, Guid*, IntPtr*, int>)(*(void***)item)[SlotShellItemBindToHandler];

            IntPtr folder;
            if (bindToHandler(item, IntPtr.Zero, &bhid, &iidFolder, &folder) != 0 || folder == IntPtr.Zero)
            {
                return result;
            }

            try
            {
                var enumObjects =
                    (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, IntPtr*, int>)(*(void***)folder)[SlotShellFolderEnumObjects];

                IntPtr enumIdList;
                if (enumObjects(folder, IntPtr.Zero, SHCONTF_FOLDERS, &enumIdList) != 0 || enumIdList == IntPtr.Zero)
                {
                    return result;
                }

                try
                {
                    var next =
                        (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, uint*, int>)(*(void***)enumIdList)[SlotEnumIdListNext];

                    while (true)
                    {
                        IntPtr pidl;
                        uint fetched;
                        if (next(enumIdList, 1, &pidl, &fetched) != 0 || fetched == 0 || pidl == IntPtr.Zero)
                        {
                            break;
                        }

                        try
                        {
                            if (SHCreateItemWithParent(IntPtr.Zero, folder, pidl, IID_IShellItem, out IntPtr child) == 0 &&
                                child != IntPtr.Zero)
                            {
                                try
                                {
                                    string? path = GetDisplayName(child, SIGDN_FILESYSPATH);
                                    if (!string.IsNullOrEmpty(path))
                                    {
                                        string name = GetDisplayName(child, SIGDN_NORMALDISPLAY) ?? path!;
                                        result.Add((name, path!));
                                    }
                                }
                                finally
                                {
                                    ReleaseComObject(child);
                                }
                            }
                        }
                        finally
                        {
                            ILFree(pidl);
                        }
                    }
                }
                finally
                {
                    ReleaseComObject(enumIdList);
                }
            }
            finally
            {
                ReleaseComObject(folder);
            }
        }
        finally
        {
            ReleaseComObject(item);
        }

        return result;
    }

    private static string? GetDisplayName(IntPtr item, uint sigdn)
    {
        var getDisplayName =
            (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)(*(void***)item)[SlotShellItemGetDisplayName];

        IntPtr buffer;
        if (getDisplayName(item, sigdn, &buffer) != 0 || buffer == IntPtr.Zero)
        {
            return null;
        }

        string? value = Marshal.PtrToStringUni(buffer);
        CoTaskMemFree(buffer);
        return value;
    }

    private static void ReleaseComObject(IntPtr comObject)
    {
        if (comObject != IntPtr.Zero)
        {
            ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(void***)comObject)[SlotRelease])(comObject);
        }
    }
}
