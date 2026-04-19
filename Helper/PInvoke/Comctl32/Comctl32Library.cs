using Helper.PInvoke.User32;
using System;
using System.Runtime.InteropServices;

namespace Helper.PInvoke.Comctl32
{
    public static partial class Comctl32Library
    {
        private const string Comctl32 = "comctl32.dll";

        [LibraryImport(Comctl32, EntryPoint = "SetWindowSubclass", SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool SetWindowSubclass(nint hWnd, nint pfnSubclass, uint uIdSubclass, nint dwRefData);

        [LibraryImport(Comctl32, EntryPoint = "DefSubclassProc", SetLastError = false)]
        public static partial nint DefSubclassProc(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam);
    }
}
