using Helper.PInvoke.User32;

namespace Helper.PInvoke.Comctl32
{
    public delegate nint SUBCLASSPROC(nint hWnd, WindowMessage Msg, UIntPtr wParam, nint lParam, uint uIdSubclass, nint dwRefData);
}
