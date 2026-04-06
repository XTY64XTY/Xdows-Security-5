using static Xdows_Local.Core;

namespace Xdows_Local
{
    public static class DllScan
    {
        private static readonly string[] WhitelistPatterns = { "Py", "Scan", "chromium", "blink", "Qt" };
        private static readonly string[] BlacklistPatterns = { "Hook", "Virus", "Bypass" };

        public static bool Scan(PEInfo info)
        {
            if (info.ExportsName == null || info.ExportsName.Length == 0)
                return false;

            foreach (var exportName in info.ExportsName)
            {
                if (string.IsNullOrEmpty(exportName))
                    continue;

                string exportNameLower = exportName.ToLowerInvariant();

                // 检查白名单
                bool isWhitelisted = false;
                foreach (var pattern in WhitelistPatterns)
                {
                    if (exportNameLower.Contains(pattern.ToLowerInvariant()))
                    {
                        isWhitelisted = true;
                        break;
                    }
                }

                if (isWhitelisted)
                    continue;

                // 检查黑名单
                foreach (var pattern in BlacklistPatterns)
                {
                    if (exportNameLower.Contains(pattern.ToLowerInvariant()))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
