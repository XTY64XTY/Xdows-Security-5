namespace Xdows_Local
{
    public class RegistryScan
    {
        private static readonly string[] SuspiciousKeys = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            @"SOFTWARE\Policies\Microsoft\Windows\System",
            @"SOFTWARE\Policies\Microsoft\MMC",
            @"SOFTWARE\Classes",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            @"Software\Classes\ms-settings\Shell\Open\command"
        };

        public string Scan(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return string.Empty;

            string keyLower = key.ToLowerInvariant();

            foreach (var suspiciousKey in SuspiciousKeys)
            {
                if (keyLower.Contains(suspiciousKey.ToLowerInvariant()))
                {
                    return "Xdows.Local.RegistryScan";
                }
            }

            return string.Empty;
        }
    }
}
