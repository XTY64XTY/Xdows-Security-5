using System.Text.Json;

namespace Protection;

//
// Loads the declarative behaviour-rule configuration
// (Config\BehaviorRules.json) and turns it into the fixed-size structures the
// kernel rule interpreter expects.
//
// The kernel validates the whole set and rejects it as a unit on any
// malformed entry, so this loader mirrors those checks up front: a
// configuration mistake surfaces in the app log instead of silently
// disabling declared rules.
//
// Schema (all fields optional except id, behaviorType and operations):
//
//   {
//     "rules": [
//       {
//         "id": 1,
//         "name": "RecoveryDisabled",            // label only, never sent
//         "behaviorType": 15,                    // number or enum name
//         "flags": ["failClosed", "killActor"],
//         "operations": ["processCreate", "fileWrite"],
//         "threshold": 5,                        // 0 = fire on every match
//         "windowMs": 3000,
//         "targetMatchKind": "any",
//         "initiator": ["cmd.exe", "\\Downloads\\"],
//         "commandLine": ["bcdedit", "recoveryenabled"],
//         "target": [".locked"]
//       }
//     ],
//     "initiatorExclusions": [
//       { "scopes": ["handle", "file"], "pattern": "steam.exe" }
//     ]
//   }
//
internal sealed class DriverBehaviorRuleCatalog
{
    private static readonly IReadOnlyList<XdowsBehaviorRule> NoRules = Array.Empty<XdowsBehaviorRule>();
    private static readonly IReadOnlyList<XdowsInitiatorExclusion> NoExclusions = Array.Empty<XdowsInitiatorExclusion>();

    private DriverBehaviorRuleCatalog(
        IReadOnlyList<XdowsBehaviorRule> rules,
        IReadOnlyList<XdowsInitiatorExclusion> exclusions)
    {
        Rules = rules;
        Exclusions = exclusions;
    }

    public IReadOnlyList<XdowsBehaviorRule> Rules { get; }

    public IReadOnlyList<XdowsInitiatorExclusion> Exclusions { get; }

    public static DriverBehaviorRuleCatalog Empty { get; } = new(NoRules, NoExclusions);

    public static string DefaultPath =>
        Path.Combine(AppContext.BaseDirectory, "Config", "BehaviorRules.json");

    //
    // Load and validate the configuration. Returns null when the file is
    // absent (an absent file is a valid "no declarative rules" state); throws
    // InvalidDataException when the file exists but is malformed, so the
    // caller can log a precise reason.
    //
    public static DriverBehaviorRuleCatalog? TryLoad(string path)
    {
        if (!File.Exists(path))
            return null;

        using FileStream stream = File.OpenRead(path);
        BehaviorRuleConfigFile? file = JsonSerializer.Deserialize<BehaviorRuleConfigFile>(
            stream,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip });

        if (file is null)
            throw new InvalidDataException("BehaviorRules.json is empty or not a JSON object.");

        var rules = new List<XdowsBehaviorRule>();
        var seenIds = new HashSet<uint>();

        foreach (BehaviorRuleEntry entry in file.Rules ?? [])
        {
            XdowsBehaviorRule rule = BuildRule(entry);
            if (!seenIds.Add(rule.RuleId))
                throw new InvalidDataException($"Duplicate declarative rule id {rule.RuleId}.");
            rules.Add(rule);
        }

        if (rules.Count > DriverProtocol.MaxBehaviorRules)
            throw new InvalidDataException(
                $"BehaviorRules.json declares {rules.Count} rules; the driver accepts at most {DriverProtocol.MaxBehaviorRules}.");

        var exclusions = new List<XdowsInitiatorExclusion>();
        foreach (InitiatorExclusionEntry entry in file.InitiatorExclusions ?? [])
        {
            if (string.IsNullOrWhiteSpace(entry.Pattern))
                throw new InvalidDataException("An initiator exclusion entry has an empty pattern.");
            if (entry.Pattern.Length > DriverProtocol.MaxExclusionChars - 1)
                throw new InvalidDataException(
                    $"Initiator exclusion \"{entry.Pattern}\" exceeds {DriverProtocol.MaxExclusionChars - 1} characters.");

            uint scopes = ParseScopes(entry.Scopes);
            exclusions.Add(new XdowsInitiatorExclusion
            {
                ScopeMask = scopes,
                Pattern = entry.Pattern
            });
        }

        if (exclusions.Count > DriverProtocol.MaxInitiatorExclusions)
            throw new InvalidDataException(
                $"BehaviorRules.json declares {exclusions.Count} exclusions; the driver accepts at most {DriverProtocol.MaxInitiatorExclusions}.");

        return new DriverBehaviorRuleCatalog(rules, exclusions);
    }

    private static XdowsBehaviorRule BuildRule(BehaviorRuleEntry entry)
    {
        if (entry.Id == 0)
            throw new InvalidDataException("A declarative rule is missing a non-zero id.");

        uint behaviorType = ParseBehaviorType(entry.BehaviorType);
        uint operations = ParseOperations(entry.Operations);
        uint flags = ParseFlags(entry.Flags);
        uint matchKind = ParseMatchKind(entry.TargetMatchKind);

        if (entry.Threshold < 0 || entry.Threshold > 10000)
            throw new InvalidDataException($"Rule {entry.Id}: threshold must be between 0 and 10000.");
        if (entry.WindowMs < 0 || entry.WindowMs > 60000)
            throw new InvalidDataException($"Rule {entry.Id}: windowMs must be between 0 and 60000.");

        return new XdowsBehaviorRule
        {
            RuleId = entry.Id,
            BehaviorType = behaviorType,
            Flags = flags,
            Operations = operations,
            Threshold = (uint)entry.Threshold,
            WindowMs = (uint)entry.WindowMs,
            TargetMatchKind = matchKind,
            Reserved = 0,
            Initiator = BuildAxis(entry.Id, "initiator", entry.Initiator),
            Target = BuildAxis(entry.Id, "target", entry.Target),
            CommandLine = BuildAxis(entry.Id, "commandLine", entry.CommandLine)
        };
    }

    private static XdowsRuleTermAxis BuildAxis(uint ruleId, string axisName, string[]? terms)
    {
        terms ??= [];
        if (terms.Length > DriverProtocol.MaxRuleTerms)
            throw new InvalidDataException(
                $"Rule {ruleId}: {axisName} declares {terms.Length} terms; at most {DriverProtocol.MaxRuleTerms} are supported.");

        var axisTerms = new XdowsRuleTerm[DriverProtocol.MaxRuleTerms];
        for (int i = 0; i < DriverProtocol.MaxRuleTerms; i++)
        {
            string value = i < terms.Length ? terms[i] ?? string.Empty : string.Empty;
            if (value.Length > DriverProtocol.MaxRuleTermChars - 1)
                throw new InvalidDataException(
                    $"Rule {ruleId}: {axisName} term \"{value}\" exceeds {DriverProtocol.MaxRuleTermChars - 1} characters.");
            if (i < terms.Length && string.IsNullOrWhiteSpace(value))
                throw new InvalidDataException($"Rule {ruleId}: {axisName} contains an empty term.");
            if (value.Contains('*') || value.Contains('?'))
                throw new InvalidDataException(
                    $"Rule {ruleId}: {axisName} term \"{value}\" uses a wildcard; the interpreter matches literals only.");

            axisTerms[i] = new XdowsRuleTerm { Value = value };
        }

        return new XdowsRuleTermAxis
        {
            TermCount = (uint)terms.Length,
            Reserved = 0,
            Terms = axisTerms
        };
    }

    private static uint ParseBehaviorType(JsonElement element)
    {
        //
        // A missing "behaviorType" property yields JsonValueKind.Undefined, and
        // GetString() throws InvalidOperationException on Undefined - which the
        // caller's exception filter would not catch. Report it as a
        // configuration error instead.
        //
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            throw new InvalidDataException("A declarative rule is missing a behaviour type.");

        if (element.ValueKind == JsonValueKind.Number)
        {
            uint value = element.GetUInt32();
            if (value == 0)
                throw new InvalidDataException("A declarative rule is missing a behaviour type.");
            return value;
        }

        if (element.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("A behaviour type must be a number or an enum name.");

        string name = element.GetString() ?? string.Empty;
        if (Enum.TryParse(name, ignoreCase: true, out XdowsSecurityBehaviorType parsed) && parsed != XdowsSecurityBehaviorType.None)
            return (uint)parsed;

        throw new InvalidDataException($"Unknown behaviour type \"{name}\".");
    }

    private static uint ParseOperations(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Array || element.GetArrayLength() == 0)
            throw new InvalidDataException("Every declarative rule needs at least one operation.");

        uint mask = 0;
        foreach (JsonElement item in element.EnumerateArray())
        {
            string name = item.GetString() ?? string.Empty;
            mask |= name.ToLowerInvariant() switch
            {
                "processcreate" => DriverProtocol.RuleOperationProcessCreate,
                "filecreate" => DriverProtocol.RuleOperationFileCreate,
                "filewrite" => DriverProtocol.RuleOperationFileWrite,
                "filedelete" => DriverProtocol.RuleOperationFileDelete,
                "filerename" => DriverProtocol.RuleOperationFileRename,
                _ => throw new InvalidDataException($"Unknown rule operation \"{name}\".")
            };
        }
        return mask;
    }

    private static uint ParseFlags(string[]? flags)
    {
        if (flags is null)
            return 0;

        uint result = 0;
        foreach (string flag in flags)
        {
            result |= flag.ToLowerInvariant() switch
            {
                "killactor" => DriverProtocol.RuleFlagKillActor,
                "failclosed" => DriverProtocol.RuleFlagFailClosed,
                _ => throw new InvalidDataException($"Unknown rule flag \"{flag}\".")
            };
        }
        return result;
    }

    private static uint ParseMatchKind(JsonElement element)
    {
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return 0;

        string name = element.GetString() ?? string.Empty;
        return name.ToLowerInvariant() switch
        {
            "any" => 0u,
            "suffix" => 1u,
            "segment" => 2u,
            "prefix" => 3u,
            "contains" => 4u,
            _ => throw new InvalidDataException($"Unknown targetMatchKind \"{name}\".")
        };
    }

    private static uint ParseScopes(string[]? scopes)
    {
        if (scopes is null || scopes.Length == 0)
            throw new InvalidDataException("An initiator exclusion needs at least one scope.");

        uint mask = 0;
        foreach (string scope in scopes)
        {
            mask |= scope.ToLowerInvariant() switch
            {
                "process" => DriverProtocol.ExclusionScopeProcess,
                "file" => DriverProtocol.ExclusionScopeFile,
                "handle" => DriverProtocol.ExclusionScopeHandle,
                "registry" => DriverProtocol.ExclusionScopeRegistry,
                _ => throw new InvalidDataException($"Unknown exclusion scope \"{scope}\".")
            };
        }
        return mask;
    }

    private sealed class BehaviorRuleConfigFile
    {
        public int Version { get; set; }

        public BehaviorRuleEntry[]? Rules { get; set; }

        public InitiatorExclusionEntry[]? InitiatorExclusions { get; set; }
    }

    private sealed class BehaviorRuleEntry
    {
        public uint Id { get; set; }

        public string? Name { get; set; }

        public JsonElement BehaviorType { get; set; }

        public string[]? Flags { get; set; }

        public JsonElement Operations { get; set; }

        public int Threshold { get; set; }

        public int WindowMs { get; set; }

        public JsonElement TargetMatchKind { get; set; }

        public string[]? Initiator { get; set; }

        public string[]? CommandLine { get; set; }

        public string[]? Target { get; set; }
    }

    private sealed class InitiatorExclusionEntry
    {
        public string[]? Scopes { get; set; }

        public string? Pattern { get; set; }
    }
}
