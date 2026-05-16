using System.Runtime.InteropServices;

namespace Helper.PInvoke.User32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct TRACKMOUSEEVENT
    {
        public uint cbSize;
        public uint dwFlags;
        public nint hwndTrack;
        public uint dwHoverTime;
    }
}
