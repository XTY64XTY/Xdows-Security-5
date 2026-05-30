using System;
using Windows.ApplicationModel;
using Windows.System.Profile;

namespace Helper
{
    public static class InfoHelper
    {
        public static Version SystemVersion { get; }

        static InfoHelper()
        {
            try
            {
                string systemVersion = AnalyticsInfo.VersionInfo.DeviceFamilyVersion;
                if (!string.IsNullOrEmpty(systemVersion) && ulong.TryParse(systemVersion, out ulong version))
                {
                    SystemVersion = new Version((int)((version & 0xFFFF000000000000L) >> 48), (int)((version & 0x0000FFFF00000000L) >> 32), (int)((version & 0x00000000FFFF0000L) >> 16), (int)(version & 0x000000000000FFFFL));
                }
                else
                {
                    SystemVersion = new Version(10, 0);
                }
            }
            catch
            {
                SystemVersion = new Version(10, 0);
            }
        }
    }
}
