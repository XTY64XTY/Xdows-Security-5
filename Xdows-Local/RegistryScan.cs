namespace Xdows_Local;

public enum RegistryRuleCategory
{
    Primary,
    Secondary,
    Other
}

public enum RegistryRuleRoot
{
    LocalMachine,
    CurrentUser
}

public sealed record RegistryProtectionRule(
    RegistryRuleRoot Root,
    string KeyPath,
    RegistryRuleCategory Category)
{
    public string CanonicalPath => Root == RegistryRuleRoot.LocalMachine
        ? $@"HKEY_LOCAL_MACHINE\{KeyPath}"
        : $@"HKEY_CURRENT_USER\{KeyPath}";
}

public sealed record RegistryProtectionOptions(
    bool IncludeSecondary,
    bool IncludeOther)
{
    public static RegistryProtectionOptions Recommended { get; } = new(true, false);
    public static RegistryProtectionOptions All { get; } = new(true, true);

    public bool Includes(RegistryRuleCategory category) => category switch
    {
        RegistryRuleCategory.Primary => true,
        RegistryRuleCategory.Secondary => IncludeSecondary,
        RegistryRuleCategory.Other => IncludeOther,
        _ => false
    };
}

public static class RegistryScan
{
    public const string DetectionName = "Xdows.Local.RegistryScan";
    public const string DiagnosticTestPath = @"SOFTWARE\Xdows-Security\Tests\RegistryProtection";

    private static readonly RegistryProtectionRule[] ProtectionRules =
    [
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Classes\ms-settings\Shell\Open\command", RegistryRuleCategory.Primary),
        new(RegistryRuleRoot.CurrentUser, DiagnosticTestPath, RegistryRuleCategory.Primary),

        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\MMC", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies", RegistryRuleCategory.Secondary),

        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Classes", RegistryRuleCategory.Other),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Classes", RegistryRuleCategory.Other),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", RegistryRuleCategory.Other),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", RegistryRuleCategory.Other)
    ];

    public static IReadOnlyList<RegistryProtectionRule> Rules => ProtectionRules;

    public static string Scan(string key) => Scan(key, RegistryProtectionOptions.All);

    public static string Scan(string key, RegistryProtectionOptions options) =>
        TryMatch(key, options, out _) ? DetectionName : string.Empty;

    public static bool TryMatch(
        string key,
        RegistryProtectionOptions options,
        out RegistryProtectionRule? matchedRule)
    {
        ArgumentNullException.ThrowIfNull(options);
        matchedRule = null;
        if (string.IsNullOrWhiteSpace(key))
            return false;

        string normalized = NormalizeSeparators(key);
        RegistryRuleRoot? root = TryExtractRoot(normalized, out string relativePath);

        foreach (RegistryProtectionRule rule in ProtectionRules)
        {
            if (!options.Includes(rule.Category) || (root is not null && root != rule.Root))
                continue;

            string candidate = root is null ? normalized : relativePath;
            if (!IsRulePrefix(candidate, rule.KeyPath) &&
                (root is not null || candidate.IndexOf(rule.KeyPath, StringComparison.OrdinalIgnoreCase) < 0))
            {
                continue;
            }

            matchedRule = rule;
            return true;
        }

        return false;
    }

    private static string NormalizeSeparators(string value)
    {
        string normalized = value.Replace('/', '\\').Trim();
        while (normalized.Contains(@"\\", StringComparison.Ordinal))
            normalized = normalized.Replace(@"\\", @"\", StringComparison.Ordinal);
        return normalized.TrimEnd('\\');
    }

    private static RegistryRuleRoot? TryExtractRoot(string path, out string relativePath)
    {
        string[] machinePrefixes = [@"\REGISTRY\MACHINE\", @"HKEY_LOCAL_MACHINE\", @"HKLM\"];
        foreach (string prefix in machinePrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                relativePath = path[prefix.Length..];
                return RegistryRuleRoot.LocalMachine;
            }
        }

        string[] userPrefixes = [@"HKEY_CURRENT_USER\", @"HKCU\"];
        foreach (string prefix in userPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                relativePath = path[prefix.Length..];
                return RegistryRuleRoot.CurrentUser;
            }
        }

        const string registryUserPrefix = @"\REGISTRY\USER\";
        if (path.StartsWith(registryUserPrefix, StringComparison.OrdinalIgnoreCase))
        {
            int hiveSeparator = path.IndexOf('\\', registryUserPrefix.Length);
            relativePath = hiveSeparator >= 0 && hiveSeparator + 1 < path.Length
                ? path[(hiveSeparator + 1)..]
                : string.Empty;
            return RegistryRuleRoot.CurrentUser;
        }

        relativePath = path;
        return null;
    }

    private static bool IsRulePrefix(string candidate, string rulePath)
    {
        if (!candidate.StartsWith(rulePath, StringComparison.OrdinalIgnoreCase))
            return false;
        return candidate.Length == rulePath.Length || candidate[rulePath.Length] == '\\';
    }
}
