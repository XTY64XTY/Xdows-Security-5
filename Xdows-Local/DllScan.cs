using static Xdows_Local.Core;

namespace Xdows_Local
{
    public static class DllScan
    {
        private static readonly string[] WhitelistPatterns = { "Py", "Scan", "chromium", "blink", "Qt" };
        private static readonly string[] BlacklistPatterns = { "Hook", "Virus", "Bypass" };
        private static readonly string[] WhitelistPatternsLower = WhitelistPatterns.Select(p => p.ToLowerInvariant()).ToArray();
        private static readonly string[] BlacklistPatternsLower = BlacklistPatterns.Select(p => p.ToLowerInvariant()).ToArray();

        public static bool Scan(PEInfo info)
        {
            ArgumentNullException.ThrowIfNull(info);

            if (info.ExportsName == null || info.ExportsName.Length == 0)
                return false;

            foreach (var exportName in info.ExportsName)
            {
                if (string.IsNullOrEmpty(exportName))
                    continue;

                string exportNameLower = exportName.ToLowerInvariant();

                bool isWhitelisted = false;
                foreach (var pattern in WhitelistPatternsLower)
                {
                    if (exportNameLower.Contains(pattern))
                    {
                        isWhitelisted = true;
                        break;
                    }
                }

                if (isWhitelisted)
                    continue;

                foreach (var pattern in BlacklistPatternsLower)
                {
                    if (exportNameLower.Contains(pattern))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
