using System.Runtime.InteropServices;

namespace Helper.PInvoke.User32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct DEV_BROADCAST_HDR
    {
        public uint dbch_size;
        public uint dbch_devicetype;
        public uint dbch_reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEV_BROADCAST_VOLUME
    {
        public uint dbcv_size;
        public uint dbcv_devicetype;
        public uint dbcv_reserved;
        public uint dbcv_unitmask;
        public ushort dbcv_flags;
    }

    public static class DeviceType
    {
        public const uint DBT_DEVTYP_VOLUME = 2;
    }

    public static class DeviceEvent
    {
        public const int DBT_DEVICEARRIVAL = 0x8000;
        public const int DBT_DEVICEREMOVECOMPLETE = 0x8004;
    }

    public static class VolumeFlags
    {
        public const ushort DBTF_MEDIA = 0x0001;
        public const ushort DBTF_NET = 0x0002;
    }
}
