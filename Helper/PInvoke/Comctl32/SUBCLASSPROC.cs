using Helper.PInvoke.User32;
using System;

namespace Helper.PInvoke.Comctl32
{
    public delegate nint SUBCLASSPROC(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam, uint uIdSubclass, nint dwRefData);
}
