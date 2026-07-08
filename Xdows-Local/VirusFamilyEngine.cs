using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Xdows_Local
{
    public enum VirusFamily
    {
        RemcosRAT, AsyncRAT, DcRat, NJRat, DarkComet, QuasarRAT, NanoCoreRAT,
        CobaltStrike, Metasploit, WarzoneRAT, BlackShades, PlasmaRAT, PandoraRAT,
        WannaCry, Locky, Cerber, Ryuk, Maze, Sodinokibi, Conti, BlackMatter,
        DarkSide, Petya, BadRabbit,
        XMRig, NiceHash, MinerGate,
        Stuxnet, Conficker,
        AgentTesla, Formbook, Lokibot, RedLine, Raccoon, Vidar, AZORult,
        Taurus, Khalesi, MarsStealer,
        PoisonIvy, Gh0stRAT, BeastDoor, PlugX, ShadowPad,
        Emotet, TrickBot, Dridex, Qakbot, Ursnif, Zloader, IcedID,
        SilverFox,
        AVKill,
        Rootkit, TDLRootkit, ZeroAccess,
        JokeVirus, MEMZ, BonziBuddy,
        Keylogger, Botnet, Adware, PUP,
        Generic
    }

    public static class VirusFamilyFormatter
    {
        public static String ToString(VirusFamily family, Single probability)
        {
            var (category, name) = family switch
            {
                VirusFamily.RemcosRAT => ("Trojan-RAT", "Remcos"),
                VirusFamily.AsyncRAT => ("Trojan-RAT", "AsyncRAT"),
                VirusFamily.DcRat => ("Trojan-RAT", "DcRat"),
                VirusFamily.NJRat => ("Trojan-RAT", "NJRat"),
                VirusFamily.DarkComet => ("Trojan-RAT", "DarkComet"),
                VirusFamily.QuasarRAT => ("Trojan-RAT", "Quasar"),
                VirusFamily.NanoCoreRAT => ("Trojan-RAT", "NanoCore"),
                VirusFamily.CobaltStrike => ("Trojan-RAT", "CobaltStrike"),
                VirusFamily.Metasploit => ("Exploit", "Metasploit"),
                VirusFamily.WarzoneRAT => ("Trojan-RAT", "Warzone"),
                VirusFamily.BlackShades => ("Trojan-RAT", "BlackShades"),
                VirusFamily.PlasmaRAT => ("Trojan-RAT", "Plasma"),
                VirusFamily.PandoraRAT => ("Trojan-RAT", "Pandora"),
                VirusFamily.WannaCry => ("Ransom", "WannaCry"),
                VirusFamily.Locky => ("Ransom", "Locky"),
                VirusFamily.Cerber => ("Ransom", "Cerber"),
                VirusFamily.Ryuk => ("Ransom", "Ryuk"),
                VirusFamily.Maze => ("Ransom", "Maze"),
                VirusFamily.Sodinokibi => ("Ransom", "Sodinokibi"),
                VirusFamily.Conti => ("Ransom", "Conti"),
                VirusFamily.BlackMatter => ("Ransom", "BlackMatter"),
                VirusFamily.DarkSide => ("Ransom", "DarkSide"),
                VirusFamily.Petya => ("Ransom", "Petya"),
                VirusFamily.BadRabbit => ("Ransom", "BadRabbit"),
                VirusFamily.XMRig => ("Miner", "XMRig"),
                VirusFamily.NiceHash => ("Miner", "NiceHash"),
                VirusFamily.MinerGate => ("Miner", "MinerGate"),
                VirusFamily.Stuxnet => ("Worm", "Stuxnet"),
                VirusFamily.Conficker => ("Worm", "Conficker"),
                VirusFamily.AgentTesla => ("Spy", "AgentTesla"),
                VirusFamily.Formbook => ("Spy", "Formbook"),
                VirusFamily.Lokibot => ("Spy", "Lokibot"),
                VirusFamily.RedLine => ("Spy", "RedLine"),
                VirusFamily.Raccoon => ("Spy", "Raccoon"),
                VirusFamily.Vidar => ("Spy", "Vidar"),
                VirusFamily.AZORult => ("Spy", "AZORult"),
                VirusFamily.Taurus => ("Spy", "Taurus"),
                VirusFamily.Khalesi => ("Spy", "Khalesi"),
                VirusFamily.MarsStealer => ("Spy", "MarsStealer"),
                VirusFamily.PoisonIvy => ("Backdoor", "PoisonIvy"),
                VirusFamily.Gh0stRAT => ("Backdoor", "Gh0stRAT"),
                VirusFamily.BeastDoor => ("Backdoor", "BeastDoor"),
                VirusFamily.PlugX => ("Backdoor", "PlugX"),
                VirusFamily.ShadowPad => ("Backdoor", "ShadowPad"),
                VirusFamily.Emotet => ("Downloader", "Emotet"),
                VirusFamily.TrickBot => ("Downloader", "TrickBot"),
                VirusFamily.Dridex => ("Downloader", "Dridex"),
                VirusFamily.Qakbot => ("Downloader", "Qakbot"),
                VirusFamily.Ursnif => ("Downloader", "Ursnif"),
                VirusFamily.Zloader => ("Downloader", "Zloader"),
                VirusFamily.IcedID => ("Downloader", "IcedID"),
                VirusFamily.SilverFox => ("Trojan", "SilverFox"),
                VirusFamily.AVKill => ("HackTool", "AVKill"),
                VirusFamily.Rootkit => ("Rootkit", ""),
                VirusFamily.TDLRootkit => ("Rootkit", "TDL"),
                VirusFamily.ZeroAccess => ("Rootkit", "ZeroAccess"),
                VirusFamily.JokeVirus => ("Joke", "Virus"),
                VirusFamily.MEMZ => ("Joke", "MEMZ"),
                VirusFamily.BonziBuddy => ("Adware", "BonziBuddy"),
                VirusFamily.Keylogger => ("Keylogger", ""),
                VirusFamily.Botnet => ("Botnet", ""),
                VirusFamily.Adware => ("Adware", ""),
                VirusFamily.PUP => ("PUP", ""),
                _ => ("Malware", "")
            };

            if (String.IsNullOrEmpty(name))
                return $"HEUR:{category}!ml ({probability * 100.0f:F1}%)";
            return $"HEUR:{category}.{name}!ml ({probability * 100.0f:F1}%)";
        }
    }

    // ============================================================
    // JSON 规则文件数据模型 (v3 外部 JSON 驱动)
    // ============================================================

    internal sealed class VirusFamilyRuleFile
    {
        public Int32 Version { get; set; }
        public List<SignatureRule>? Signatures { get; set; }
        public SilverFoxHeuristicConfig? SilverfoxHeuristic { get; set; }
        public AVKillHeuristicConfig? AvkillHeuristic { get; set; }
    }

    internal sealed class SignatureRule
    {
        public String Family { get; set; } = String.Empty;
        public String DetectionName { get; set; } = String.Empty;
        public List<String>? Patterns { get; set; }
        public Int32 MinMatches { get; set; } = 1;
        public Int32 Priority { get; set; } = 100;
    }

    internal sealed class SilverFoxHeuristicConfig
    {
        public Boolean Enabled { get; set; } = true;
        public Int32 MaxSizeMb { get; set; } = 50;
        public Int32 RandomNameMinLen { get; set; } = 6;
        public Int32 RandomNameMaxLen { get; set; } = 16;
        public Double MinEntropy { get; set; } = 2.2;
        public Double MaxCharFrequency { get; set; } = 0.45;
        public Int32 MinLetters { get; set; } = 2;
        public Int32 MinDigits { get; set; } = 1;
        public Single MinProbability { get; set; } = 0.5f;
        public List<String>? SuspiciousPaths { get; set; }
        public List<String>? TrustedPathKeywords { get; set; }
    }

    internal sealed class AVKillHeuristicConfig
    {
        public Boolean Enabled { get; set; } = true;
        public Int32 MinToolStringHits { get; set; } = 1;
        public Int32 MinTargetProcessHits { get; set; } = 2;
        public List<String>? ToolStrings { get; set; }
        public List<String>? TargetProcessesAscii { get; set; }
        public List<String>? TargetProcessesWide { get; set; }
    }

    /// <summary>AOT 友好的 JSON 序列化上下文。</summary>
    [JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(VirusFamilyRuleFile))]
    internal sealed partial class VirusFamilyRulesJsonContext : JsonSerializerContext
    {
    }

    // ============================================================
    // 预编译签名 (规则加载时把字符串编码为字节, 扫描时直接 IndexOf)
    // ============================================================

    internal sealed class CompiledSignature
    {
        public VirusFamily Family { get; init; }
        public String DetectionName { get; init; } = String.Empty;
        public Byte[][] Patterns { get; init; } = [];
        public Int32 MinMatches { get; init; }
        public Int32 Priority { get; init; }
    }

    public static class VirusFamilyEngine
    {
        private const String RulesFileName = "XdowsVirusFamilyRules.json";
        private const Int32 ScanSize = 512 * 1024;

        private static readonly CompiledSignature[] s_signatures;
        private static readonly SilverFoxHeuristicConfig s_silverFoxConfig;

        // SilverFox 预编译
        private static readonly String[] s_silverFoxSuspiciousPaths;
        private static readonly String[] s_silverFoxTrustedKeywords;

        // AVKill 预编译字节模式
        private static readonly Byte[][] s_avkillToolAscii;
        private static readonly Byte[][] s_avkillTargetAscii;
        private static readonly Byte[][] s_avkillTargetWide;
        private static readonly Int32 s_avkillMinToolHits;
        private static readonly Int32 s_avkillMinTargetHits;
        private static readonly Boolean s_avkillEnabled;

        private static readonly FrozenDictionary<String, VirusFamily> s_familyLookup;

        private static readonly ConcurrentDictionary<String, (VirusFamily family, Single probability)> s_cache = new();

        static VirusFamilyEngine()
        {
            VirusFamilyRuleFile ruleFile = LoadRuleFile();

            s_familyLookup = BuildFamilyLookup();
            s_signatures = CompileSignatures(ruleFile.Signatures);

            s_silverFoxConfig = ruleFile.SilverfoxHeuristic ?? new SilverFoxHeuristicConfig();
            s_silverFoxSuspiciousPaths = s_silverFoxConfig.SuspiciousPaths?.ToArray() ?? [];
            s_silverFoxTrustedKeywords = s_silverFoxConfig.TrustedPathKeywords?.ToArray() ?? [];

            AVKillHeuristicConfig avkill = ruleFile.AvkillHeuristic ?? new AVKillHeuristicConfig();
            s_avkillEnabled = avkill.Enabled;
            s_avkillMinToolHits = avkill.MinToolStringHits;
            s_avkillMinTargetHits = avkill.MinTargetProcessHits;
            s_avkillToolAscii = EncodeAsciiLower(avkill.ToolStrings);
            s_avkillTargetAscii = EncodeAsciiLower(avkill.TargetProcessesAscii);
            s_avkillTargetWide = EncodeUtf16WideLower(avkill.TargetProcessesWide);
        }

        // ============================================================
        // 规则加载 - 外部文件优先, 回退内嵌资源
        // ============================================================

        private static VirusFamilyRuleFile LoadRuleFile()
        {
            // 1. 外部文件覆盖 (运行目录同名文件)
            String externalPath = Path.Combine(AppContext.BaseDirectory, RulesFileName);
            if (TryLoadFromFile(externalPath, out VirusFamilyRuleFile? external) && external != null)
                return external;

            // 2. 内嵌默认资源
            try
            {
                Assembly asm = typeof(VirusFamilyEngine).Assembly;
                String resourceName = $"Xdows_Local.{RulesFileName}";
                using Stream? stream = asm.GetManifestResourceStream(resourceName);
                if (stream != null)
                {
                    VirusFamilyRuleFile? embedded = JsonSerializer.Deserialize(stream, VirusFamilyRulesJsonContext.Default.VirusFamilyRuleFile);
                    if (embedded != null)
                        return embedded;
                }
            }
            catch (Exception) { }

            // 3. 全部失败: 返回空规则集 (优雅降级)
            return new VirusFamilyRuleFile { Version = 3, Signatures = new List<SignatureRule>() };
        }

        private static Boolean TryLoadFromFile(String path, [NotNullWhen(true)] out VirusFamilyRuleFile? result)
        {
            result = null;
            if (!File.Exists(path))
                return false;
            try
            {
                String json = File.ReadAllText(path);
                result = JsonSerializer.Deserialize(json, VirusFamilyRulesJsonContext.Default.VirusFamilyRuleFile);
                return result != null;
            }
            catch (Exception) { return false; }
        }

        private static CompiledSignature[] CompileSignatures(List<SignatureRule>? signatures)
        {
            if (signatures == null || signatures.Count == 0)
                return [];

            List<CompiledSignature> compiled = new(signatures.Count);
            foreach (SignatureRule sig in signatures)
            {
                if (!s_familyLookup.TryGetValue(sig.Family, out VirusFamily family))
                    continue;
                if (sig.Patterns == null || sig.Patterns.Count == 0)
                    continue;

                Byte[][] patterns = new Byte[sig.Patterns.Count][];
                Boolean valid = true;
                for (Int32 i = 0; i < sig.Patterns.Count; i++)
                {
                    if (String.IsNullOrEmpty(sig.Patterns[i]))
                    {
                        valid = false;
                        break;
                    }
                    patterns[i] = Encoding.UTF8.GetBytes(sig.Patterns[i]);
                }
                if (!valid)
                    continue;

                compiled.Add(new CompiledSignature
                {
                    Family = family,
                    DetectionName = String.IsNullOrEmpty(sig.DetectionName) ? sig.Family : sig.DetectionName,
                    Patterns = patterns,
                    MinMatches = Math.Max(1, sig.MinMatches),
                    Priority = sig.Priority
                });
            }
            return compiled.ToArray();
        }

        private static FrozenDictionary<String, VirusFamily> BuildFamilyLookup()
        {
            Dictionary<String, VirusFamily> dict = new(StringComparer.Ordinal);
            foreach (VirusFamily f in Enum.GetValues<VirusFamily>())
                dict[f.ToString()] = f;
            return dict.ToFrozenDictionary(StringComparer.Ordinal);
        }

        // 小写化后编码为 UTF-8 字节, 用于大小写不敏感匹配 (搜索时对数据也做同样小写化)
        private static Byte[][] EncodeAsciiLower(List<String>? strings)
        {
            if (strings == null || strings.Count == 0)
                return [];
            Byte[][] result = new Byte[strings.Count][];
            for (Int32 i = 0; i < strings.Count; i++)
                result[i] = Encoding.UTF8.GetBytes(strings[i].ToLowerInvariant());
            return result;
        }

        // 小写化后编码为 UTF-16 LE 字节序列, 用于大小写不敏感宽字符匹配
        private static Byte[][] EncodeUtf16WideLower(List<String>? strings)
        {
            if (strings == null || strings.Count == 0)
                return [];
            Byte[][] result = new Byte[strings.Count][];
            for (Int32 i = 0; i < strings.Count; i++)
                result[i] = Encoding.Unicode.GetBytes(strings[i].ToLowerInvariant());
            return result;
        }

        // ============================================================
        // 公共 API (保持向后兼容)
        // ============================================================

        public static (VirusFamily family, Single probability) Analyze(String filePath, Single modelProbability)
        {
            if (s_cache.TryGetValue(filePath, out var cached))
                return cached;

            Byte[] data;
            Int64 fileSize;
            try
            {
                FileInfo fi = new(filePath);
                fileSize = fi.Length;
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                Int32 toRead = (Int32)Math.Min(fs.Length, ScanSize);
                data = new Byte[toRead];
                Int32 bytesRead = 0;
                while (bytesRead < toRead)
                {
                    Int32 n = fs.Read(data, bytesRead, toRead - bytesRead);
                    if (n == 0) break;
                    bytesRead += n;
                }
                if (bytesRead < toRead)
                    Array.Resize(ref data, bytesRead);
            }
            catch (Exception)
            {
                return (VirusFamily.Generic, modelProbability);
            }

            VirusFamily family = VirusFamily.Generic;
            Single probability = modelProbability;

            // 1. SilverFox 专项启发式 (随机文件名 + 可疑路径 + PE + 体积 + 概率门控)
            if (s_silverFoxConfig.Enabled && modelProbability >= s_silverFoxConfig.MinProbability &&
                DetectSilverFox(filePath, data, fileSize, s_silverFoxConfig))
            {
                family = VirusFamily.SilverFox;
                probability = 0.95f;
            }
            // 2. AVKill 专项启发式 (工具字符串 / 目标 AV 进程名)
            else if (s_avkillEnabled && DetectAVKill(data))
            {
                family = VirusFamily.AVKill;
                probability = 0.95f;
            }
            // 3. JSON 签名规则匹配
            else
            {
                family = MatchSignatures(data);
            }

            var result = (family, probability);

            if (s_cache.Count > 5000)
            {
                foreach (var key in s_cache.Keys.Take(s_cache.Count - 2500).ToList())
                    s_cache.TryRemove(key, out _);
            }

            s_cache[filePath] = result;
            return result;
        }

        public static String GetVirusFamily(String filePath, Single modelProbability)
        {
            var (family, probability) = Analyze(filePath, modelProbability);
            return VirusFamilyFormatter.ToString(family, probability);
        }

        // ============================================================
        // SilverFox 专项启发式
        // ============================================================

        private static Boolean DetectSilverFox(String filePath, Byte[] data, Int64 fileSize, SilverFoxHeuristicConfig cfg)
        {
            // 必须为 PE 文件
            if (data.Length < 2 || data[0] != 0x4D || data[1] != 0x5A)
                return false;

            // 体积约束 (银狐木马通常较小)
            Int64 maxSizeBytes = (Int64)cfg.MaxSizeMb * 1024 * 1024;
            if (fileSize > maxSizeBytes || fileSize < 1024)
                return false;

            String fileName = Path.GetFileNameWithoutExtension(filePath);
            if (!IsRandomFileName(fileName, cfg))
                return false;

            if (!IsSuspiciousPath(filePath, s_silverFoxSuspiciousPaths, s_silverFoxTrustedKeywords))
                return false;

            return true;
        }

        private static Boolean IsRandomFileName(String name, SilverFoxHeuristicConfig cfg)
        {
            if (String.IsNullOrEmpty(name))
                return false;

            Int32 len = name.Length;
            if (len < cfg.RandomNameMinLen || len > cfg.RandomNameMaxLen)
                return false;

            // 必须仅含字母数字
            Int32 letterCount = 0;
            Int32 digitCount = 0;
            foreach (Char c in name)
            {
                if (Char.IsAsciiLetter(c))
                    letterCount++;
                else if (Char.IsAsciiDigit(c))
                    digitCount++;
                else
                    return false;
            }

            if (letterCount < cfg.MinLetters || digitCount < cfg.MinDigits)
                return false;

            // 排除常见正常软件名 (避免误报)
            if (IsCommonSoftwareName(name))
                return false;

            // Shannon 熵
            Double entropy = ShannonEntropy(name);
            if (entropy < cfg.MinEntropy)
                return false;

            // 最大字符出现频率
            Dictionary<Char, Int32> freq = new();
            foreach (Char c in name)
            {
                freq.TryGetValue(c, out Int32 v);
                freq[c] = v + 1;
            }
            Double maxFreq = (Double)freq.Values.Max() / len;
            if (maxFreq > cfg.MaxCharFrequency)
                return false;

            return true;
        }

        // 常见合法软件名片段 (小写比较), 用于排除 SilverFox 误报
        private static readonly String[] s_commonSoftwareNames =
        [
            "setup", "install", "update", "upgrade", "uninstall",
            "helper", "service", "monitor", "config", "setting",
            "loader", "runner", "launcher", "manager", "control",
            "driver", "agent", "client", "server", "host",
            "plugin", "module", "version", "release",
            "chrome", "firefox", "edge", "opera", "brave",
            "office", "word", "excel", "power", "outlook",
            "team", "zoom", "skype", "discord", "slack",
            "wechat", "qq", "ding", "lark", "feishu",
            "python", "java", "dotnet", "node", "golang",
            "visual", "code", "studio", "eclipse", "intellij"
        ];

        private static Boolean IsCommonSoftwareName(String name)
        {
            String lower = name.ToLowerInvariant();
            foreach (String c in s_commonSoftwareNames)
            {
                if (lower.Contains(c, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static Double ShannonEntropy(String s)
        {
            if (s.Length == 0)
                return 0.0;
            Dictionary<Char, Int32> freq = new();
            foreach (Char c in s)
            {
                freq.TryGetValue(c, out Int32 v);
                freq[c] = v + 1;
            }
            Double entropy = 0.0;
            Double len = s.Length;
            foreach (Int32 count in freq.Values)
            {
                Double p = count / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private static Boolean IsSuspiciousPath(String path, String[] suspiciousPaths, String[] trustedKeywords)
        {
            if (String.IsNullOrEmpty(path))
                return false;

            // 信任路径白名单优先
            String lowerPath = path.ToLowerInvariant();
            foreach (String trusted in trustedKeywords)
            {
                if (lowerPath.Contains(trusted, StringComparison.Ordinal))
                    return false;
            }

            foreach (String suspicious in suspiciousPaths)
            {
                if (path.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        // ============================================================
        // AVKill 专项启发式
        // ============================================================

        private static Boolean DetectAVKill(Byte[] data)
        {
            if (data.Length == 0)
                return false;

            // 对数据做 ASCII 小写化 (仅 A-Z→a-z), 用于大小写不敏感匹配
            // 对 UTF-16 LE 同样有效: ASCII 字符的低字节被小写, 高字节 (0x00) 不变
            Byte[] lower = new Byte[data.Length];
            for (Int32 i = 0; i < data.Length; i++)
            {
                Byte b = data[i];
                lower[i] = (Byte)(b >= 0x41 && b <= 0x5A ? b + 32 : b);
            }

            // 1. 工具字符串 (ASCII, 大小写不敏感) - 任一命中即足够 (defendnot/defenderkiller 等)
            Int32 toolHits = 0;
            foreach (Byte[] pattern in s_avkillToolAscii)
            {
                if (SimpleSearch(lower, pattern))
                {
                    toolHits++;
                    if (toolHits >= s_avkillMinToolHits)
                        return true;
                }
            }

            // 2. 目标 AV 进程名 (ASCII + UTF-16, 大小写不敏感) - 需要足够多命中避免单个 "avp.exe" 误报
            Int32 targetHits = 0;
            foreach (Byte[] pattern in s_avkillTargetAscii)
            {
                if (SimpleSearch(lower, pattern))
                    targetHits++;
            }
            foreach (Byte[] pattern in s_avkillTargetWide)
            {
                if (SimpleSearch(lower, pattern))
                    targetHits++;
            }

            return targetHits >= s_avkillMinTargetHits;
        }

        // ============================================================
        // 签名规则匹配 (JSON 驱动)
        // ============================================================

        private static VirusFamily MatchSignatures(Byte[] data)
        {
            if (s_signatures.Length == 0 || data.Length == 0)
                return VirusFamily.Generic;

            VirusFamily bestFamily = VirusFamily.Generic;
            Int32 bestPriority = 0;

            foreach (CompiledSignature sig in s_signatures)
            {
                Int32 matchCount = 0;
                foreach (Byte[] pattern in sig.Patterns)
                {
                    if (SimpleSearch(data, pattern))
                    {
                        matchCount++;
                        if (matchCount >= sig.MinMatches)
                            break;
                    }
                }

                if (matchCount >= sig.MinMatches && sig.Priority > bestPriority)
                {
                    bestFamily = sig.Family;
                    bestPriority = sig.Priority;
                }
            }

            return bestFamily;
        }

        // ============================================================
        // 辅助
        // ============================================================

        private static Boolean SimpleSearch(Byte[] text, Byte[] pattern)
        {
            if (pattern.Length == 0 || pattern.Length > text.Length)
                return false;
            return text.AsSpan().IndexOf(pattern) >= 0;
        }
    }
}
