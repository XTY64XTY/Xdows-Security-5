using static Xdows_Local.Core;

namespace Xdows_Local
{
    public static class DllScan
    {
        public static bool Scan(PEInfo info)
        {
            return Native_DllScanner.ScanManaged(info.ExportsName ?? []);
        }
    }
}
