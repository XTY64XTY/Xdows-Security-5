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

/// <summary>
/// A protected registry key or key subtree.
/// </summary>
/// <param name="Root">Hive the rule lives in.</param>
/// <param name="KeyPath">Key path relative to the hive root.</param>
/// <param name="Category">Deployment category (see <see cref="RegistryProtectionOptions"/>).</param>
/// <param name="KillActor">
/// When true, a confirmed Block verdict for a mutation under this key also
/// requests the kernel to counter-terminate the acting process
/// (<c>DriverProtocol.KillActorResultCode</c>). Reserved for subtrees where
/// every mutation is hostile: safe-mode autostart and boot-execute
/// configuration. Value-level critical keys use
/// <see cref="RegistryScan.CriticalValueNames"/> instead.
/// </param>
public sealed record RegistryProtectionRule(
    RegistryRuleRoot Root,
    string KeyPath,
    RegistryRuleCategory Category,
    bool KillActor = false)
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

        //
        // File-association hijack. Both hives are protected: a per-user
        // HKCU\Software\Classes entry silently overrides the machine-wide
        // HKLM association, so protecting only one hive is trivially bypassed.
        // A whole-subtree rule is used instead of one rule per extension so
        // the deployment stays inside the driver's 32-rule budget while still
        // covering .exe/.com/.bat/.cmd plus the exefile/comfile/batfile/
        // cmdfile shell-verb keys.
        //
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Classes", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Classes", RegistryRuleCategory.Secondary),

        //
        // Safe-mode autostart. Safe mode loads a minimal driver/service set
        // from SafeBoot\Minimal/Network, so persistence written here survives
        // the recovery boot that is supposed to remove the threat.
        //
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SafeBoot", RegistryRuleCategory.Secondary, KillActor: true),

        //
        // Boot-execute and native subsystem start-up configuration. These
        // values run kernel code at every boot (BootExecute, SubSystems,
        // FirmwareBootDevice...).
        //
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", RegistryRuleCategory.Secondary, KillActor: true),

        //
        // Input-capture class filters, Defender policy, and credential
        // autologon. Rewriting the mouclass/kbdclass service keys turns the
        // driver stack into an in-kernel keylogger under a different name;
        // the Defender policy keys disable real-time protection before an
        // attack runs. AutoAdminLogon/DefaultPassword are covered by the
        // Winlogon primary rule above.
        //
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mouclass", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Services\kbdclass", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", RegistryRuleCategory.Secondary),

        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\MMC", RegistryRuleCategory.Secondary),
        new(RegistryRuleRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies", RegistryRuleCategory.Secondary),

        new(RegistryRuleRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", RegistryRuleCategory.Other),
        new(RegistryRuleRoot.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", RegistryRuleCategory.Other)
    ];

    /// <summary>
    /// Value names whose modification inside an otherwise legitimate policy
    /// key is itself the attack. The owning key (<c>Policies\System</c>,
    /// <c>Policies\Explorer</c>, <c>Winlogon</c>) carries plenty of benign
    /// values, so a whole-key rule cannot justify counter-killing the actor;
    /// matching the value name can. A confirmed Block on one of these values
    /// is therefore escalated to a counter-kill request.
    /// </summary>
    public static readonly IReadOnlySet<string> CriticalValueNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Security posture / UAC.
            "EnableLUA",
            "ConsentPromptBehaviorAdmin",
            "ConsentPromptBehaviorUser",
            "EnableSecureUIAPaths",
            // Logon and shell bootstrap.
            "Userinit",
            "UIHost",
            "Shell",
            "AutoAdminLogon",
            "DefaultPassword",
            "AutoReboot",
            "ShutdownWithoutLogon",
            "DisableCAD",
            // Boot and native subsystem start-up.
            "BootExecute",
            "SubSystems",
            "FirmwareBootDevice",
            "BootDriverFlags",
            "SystemStartOptions",
            // Administrative lockdown / destructive policy.
            "RestrictRun",
            "Restrict_Run",
            "DisableTaskMgr",
            "DisableCMD",
            "DisableRegistryTools",
            "DisableLockWorkstation",
            "DisableChangePassword",
            "NoControlPanel",
            "NoFolderOptions",
            "NoRun",
            "NoDrives",
            "DisableAntiSpyware"
        };

    public static IReadOnlyList<RegistryProtectionRule> Rules => ProtectionRules;

    /// <summary>
    /// Number of rule paths downloaded to the driver. Keep this inside the
    /// kernel's <c>XDOWS_SECURITY_MAX_REGISTRY_RULES</c> budget (32); the
    /// primary, secondary, and other categories are deliberately sized to fit.
    /// </summary>
    public static int RuleCount => ProtectionRules.Length;

    /// <summary>
    /// True when a confirmed Block on this mutation justifies escalating the
    /// verdict to a counter-kill request. Matches either a rule flagged
    /// <see cref="RegistryProtectionRule.KillActor"/> (whole subtree is
    /// hostile) or a <see cref="CriticalValueNames"/> match inside an
    /// otherwise legitimate policy key.
    /// </summary>
    public static bool IsCriticalMutation(string? registryPath, string? valueName)
    {
        if (!string.IsNullOrWhiteSpace(valueName) &&
            CriticalValueNames.Contains(valueName.Trim()))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(registryPath) &&
            TryMatch(registryPath, RegistryProtectionOptions.Recommended, out RegistryProtectionRule? rule) &&
            rule is { KillActor: true };
    }

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
