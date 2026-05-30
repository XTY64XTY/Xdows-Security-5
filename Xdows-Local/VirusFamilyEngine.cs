using System.Collections.Concurrent;
using System.Linq;

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
        YinFox,
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
                VirusFamily.YinFox => ("Trojan", "YinFox"),
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

    internal sealed class VirusFamilyRule
    {
        public VirusFamily Family { get; }
        public Byte[][] Patterns { get; }
        public Int32 MinMatches { get; }
        public Int32 Priority { get; }

        public VirusFamilyRule(VirusFamily family, Byte[][] patterns, Int32 minMatches, Int32 priority)
        {
            Family = family;
            Patterns = patterns;
            MinMatches = minMatches;
            Priority = priority;
        }
    }

    public static class VirusFamilyEngine
    {
        private static readonly VirusFamilyRule[] s_rules;
        private static readonly ConcurrentDictionary<String, (VirusFamily family, Single probability)> s_cache = new();

        static VirusFamilyEngine()
        {
            s_rules = BuildRules();
        }

        private static VirusFamilyRule[] BuildRules()
        {
            return
            [
                R(VirusFamily.RemcosRAT, 1, 100,
                    "Remcos", "remcos", "Breaking-Security", "remcos_mutex"),
                R(VirusFamily.AsyncRAT, 1, 100,
                    "AsyncRAT", "asyncrat", "NYAN_x_CAT", "AsyncClient"),
                R(VirusFamily.DcRat, 1, 100,
                    "DcRat", "dcrat", "qwqdanchun"),
                R(VirusFamily.NJRat, 1, 100,
                    "NJrat", "njrat", "njw0rm"),
                R(VirusFamily.DarkComet, 1, 100,
                    "DarkComet", "darkcomet", "#KCMDDC"),
                R(VirusFamily.QuasarRAT, 1, 100,
                    "QuasarRAT", "Quasar.Client", "xClient"),
                R(VirusFamily.NanoCoreRAT, 1, 100,
                    "NanoCore", "nanocore", "NanoCore.Client"),
                R(VirusFamily.CobaltStrike, 1, 100,
                    "cobaltstrike", "Cobalt Strike", "beacon", "Beacon"),
                R(VirusFamily.Metasploit, 1, 100,
                    "metasploit", "Metasploit", "meterpreter", "Meterpreter", "msfvenom", "reverse_tcp"),
                R(VirusFamily.WannaCry, 1, 100,
                    "WannaCry", "wannacry", "Wana Decrypt0r", "@Please_Read_Me@"),
                R(VirusFamily.Locky, 1, 100,
                    "Locky", ".locky", "_Locky_recover"),
                R(VirusFamily.Cerber, 1, 100,
                    "Cerber", ".cerber", "_HELP_HELP_HELP"),
                R(VirusFamily.Ryuk, 1, 100,
                    "Ryuk", ".ryk", "RyukReadMe"),
                R(VirusFamily.Conti, 1, 100,
                    "Conti", "CONTi", ".conti"),
                R(VirusFamily.XMRig, 1, 100,
                    "xmrig", "XMRig", "stratum+tcp", "stratum+ssl", "cryptonight", "randomx"),
                R(VirusFamily.AgentTesla, 1, 100,
                    "AgentTesla", "agenttesla", "Agent Tesla"),
                R(VirusFamily.Formbook, 1, 100,
                    "Formbook", "formbook", "Xloader", "xloader"),
                R(VirusFamily.RedLine, 1, 100,
                    "RedLine", "redline", "RedLine Stealer"),
                R(VirusFamily.YinFox, 1, 100,
                    "yinhu", "YinHu", "yinfox", "YinFox",
                    "\u94F6\u72D0", "SilverFox", "silverfox", "svch0st", "csrsss", "lsasss"),
                R(VirusFamily.AVKill, 2, 90,
                    "MsMpEng", "avp", "AvP", "AVP",
                    "avast", "Avast", "AVAST",
                    "360", "360tray", "360sd", "360rp",
                    "QQPCRTP", "QQProtect",
                    "kxetray", "baidusd",
                    "\u706B\u7ED2",
                    "taskkill", "TASKKILL",
                    "/F /IM", "/f /im",
                    "sc stop", "sc delete",
                    "net stop", "reg delete",
                    "DisableAntiSpyware", "DisableAntiVirus"),
                R(VirusFamily.Rootkit, 1, 90,
                    "rootkit", "Rootkit",
                    "SSDT", "KiServiceTable",
                    "DKOM", "hide process",
                    "NtQuerySystemInformation",
                    "PsSetCreateProcessNotifyRoutine"),
                R(VirusFamily.TDLRootkit, 1, 100,
                    "TDL4", "tdl4", "Alureon", "alureon"),
                R(VirusFamily.MEMZ, 1, 100,
                    "MEMZ", "memz", "Leurak", "Nyan Cat", "You are an idiot"),
            ];
        }

        private static VirusFamilyRule R(VirusFamily family, Int32 minMatches, Int32 priority, params String[] patterns)
        {
            Byte[][] encoded = new Byte[patterns.Length][];
            for (Int32 i = 0; i < patterns.Length; i++)
                encoded[i] = System.Text.Encoding.UTF8.GetBytes(patterns[i]);
            return new VirusFamilyRule(family, encoded, minMatches, priority);
        }

        public static (VirusFamily family, Single probability) Analyze(String filePath, Single modelProbability)
        {
            if (s_cache.TryGetValue(filePath, out var cached))
                return cached;

            const Int32 scanSize = 512 * 1024;
            Byte[] data;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                Int32 toRead = (Int32)Math.Min(fs.Length, scanSize);
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

            VirusFamily bestFamily = VirusFamily.Generic;
            Int32 bestPriority = 0;

            foreach (var rule in s_rules)
            {
                Int32 matchCount = 0;
                foreach (var pattern in rule.Patterns)
                {
                    if (SimpleSearch(data, pattern))
                    {
                        matchCount++;
                        if (matchCount >= rule.MinMatches)
                            break;
                    }
                }

                if (matchCount >= rule.MinMatches && rule.Priority > bestPriority)
                {
                    bestFamily = rule.Family;
                    bestPriority = rule.Priority;
                }
            }

            var result = (bestFamily, modelProbability);

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

        private static Boolean SimpleSearch(Byte[] text, Byte[] pattern)
        {
            if (pattern.Length == 0 || pattern.Length > text.Length)
                return false;
            return text.AsSpan().IndexOf(pattern) >= 0;
        }
    }
}
