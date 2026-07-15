using Microsoft.Windows.Storage;
using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace Helper
{
    public static class ScanEngine
    {
        private const string CloudScanBaseUrl = "http://103.118.245.82:5000";
        private const string CloudScanApiKey = "my_virus_key_2024";
        private const string ExactRuleBaseUrl = "http://103.118.245.82:7050";

        public static async Task<string> LocalScanAsync(string path, bool deep, bool ExtraData)
        {
            return await Task.Run(() => Xdows_Local.Core.ScanAsync(path, deep, ExtraData));
        }

        public static async Task<string> LocalScanFromBytesAsync(byte[] fileBytes, string path, bool deep, bool ExtraData)
        {
            return await Task.Run(() => Xdows_Local.Core.ScanFromBytes(path, fileBytes, deep, ExtraData));
        }

        public static async Task<(bool IsInfected, string? Result)> InfectorScanAsync(string path)
        {
            return await Task.Run<(bool IsInfected, string? Result)>(() =>
            {
                try
                {
                    var detection = InfectorCleaner.InfectorDetector.DetectInfector(path);
                    if (detection.IsInfected)
                    {
                        return (true, "HEUR:Infector.EP_Hijack!ml");
                    }
                }
                catch (Exception) { }
                return (false, null);
            });
        }

        public static async Task<InfectorCleaner.CleaningResult?> InfectorCleanAsync(string path)
        {
            return await Task.Run(() =>
            {
                try
                {
                    return InfectorCleaner.InfectorCleaner.CleanInfectedFile(path);
                }
                catch (Exception) { return null; }
            });
        }

        public class ModelEngineScan
        {
            // 缓存 LocalSettings，避免每次 SyncModeFromSettings 都调用 ApplicationData.GetForUnpackaged
            // PublicationOnly 模式：失败不缓存异常，避免单次失败导致整个类永久不可用
            private static readonly Lazy<ApplicationDataContainer> s_settingsLazy = new(
                () => ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security").LocalSettings,
                LazyThreadSafetyMode.PublicationOnly);
            private static ApplicationDataContainer Settings => s_settingsLazy.Value;

            private static Xdows_Model_Invoker.ModelMode _mode = Xdows_Model_Invoker.ModelMode.Standard;

            public static Xdows_Model_Invoker.ModelMode Mode
            {
                get => _mode;
                set
                {
                    if (_mode != value)
                    {
                        _mode = value;
                        Xdows_Model_Invoker.ModelInvoker.UnloadModel();
                    }
                }
            }

            private static void SyncModeFromSettings()
            {
                try
                {
                    var settings = Settings;
                    if (settings.Values.TryGetValue("ModelMode", out var raw) && raw is string modeStr)
                    {
                        _mode = modeStr switch
                        {
                            "Flash" => Xdows_Model_Invoker.ModelMode.Flash,
                            "Adaptive" => Xdows_Model_Invoker.ModelMode.Adaptive,
                            "Pro" => Xdows_Model_Invoker.ModelMode.Pro,
                            _ => Xdows_Model_Invoker.ModelMode.Standard
                        };
                    }
                }
                catch (Exception) { }
            }

            public static bool Initialize()
            {
                try
                {
                    SyncModeFromSettings();
                    InitializeWithMode(_mode);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            public static bool InitializeForProtection()
            {
                try
                {
                    SyncModeFromSettings();
                    bool applyToProtection = false;
                    try
                    {
                        var settings = Settings;
                        if (settings.Values.TryGetValue("ModelModeForProtection", out var raw) && raw is bool enabled)
                        {
                            applyToProtection = enabled;
                        }
                    }
                    catch (Exception) { }

                    var mode = applyToProtection ? _mode : Xdows_Model_Invoker.ModelMode.Standard;
                    InitializeWithMode(mode);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            private static void InitializeWithMode(Xdows_Model_Invoker.ModelMode mode)
            {
                switch (mode)
                {
                    case Xdows_Model_Invoker.ModelMode.Flash:
                        Xdows_Model_Invoker.ModelInvoker.InitializeFlash();
                        break;
                    case Xdows_Model_Invoker.ModelMode.Pro:
                        Xdows_Model_Invoker.ModelInvoker.InitializePro();
                        break;
                    case Xdows_Model_Invoker.ModelMode.Adaptive:
                        Xdows_Model_Invoker.ModelInvoker.InitializeAdaptive();
                        break;
                    default:
                        Xdows_Model_Invoker.ModelInvoker.Initialize();
                        break;
                }
            }

            public static (bool IsVirus, string Result) ScanFile(string path)
            {
                try
                {
                    var (isVirus, probability) = Xdows_Model_Invoker.ModelInvoker.ScanFile(path);
                    if (isVirus)
                    {
                        string modeTag = _mode switch
                        {
                            Xdows_Model_Invoker.ModelMode.Flash => "Flash",
                            Xdows_Model_Invoker.ModelMode.Adaptive => "Adaptive",
                            Xdows_Model_Invoker.ModelMode.Pro => "Pro",
                            _ => "Standard"
                        };
                        return (true, $"Xdows.Model.{modeTag}.Probability{(int)probability}");
                    }
                }
                catch (Exception) { }
                return (false, string.Empty);
            }

            public static string GetEngineDisplayName()
            {
                string modeTag = _mode switch
                {
                    Xdows_Model_Invoker.ModelMode.Flash => "Flash",
                    Xdows_Model_Invoker.ModelMode.Adaptive => "Adaptive",
                    Xdows_Model_Invoker.ModelMode.Pro => "Pro",
                    _ => "Standard"
                };
                return $"Xdows-Model ({modeTag})";
            }
        }

        // 配置连接池与生命周期：SocketsHttpHandler 是 .NET 10 默认主处理器，显式配置可控制连接池行为
        // - PooledConnectionLifetime: 连接最长存活 2 分钟，避免长时间复用导致 DNS 变化失效
        // - MaxConnectionsPerServer: 单服务器最大并发连接数，防止突发请求耗尽端口
        // - AutomaticDecompression: 自动解压响应（gzip/deflate/br），减少带宽消耗
        // 注：自建服务（103.118.245.82）走 HTTP 明文，保持 HTTP/1.1 以兼容未知的服务端 h2c 支持情况
        private static readonly System.Net.Http.HttpClient s_httpClient = BuildHttpClient(TimeSpan.FromSeconds(30));

        private static System.Net.Http.HttpClient BuildHttpClient(TimeSpan timeout)
        {
            SocketsHttpHandler handler = new()
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                MaxConnectionsPerServer = 16,
                AutomaticDecompression = System.Net.DecompressionMethods.All
            };
            return new System.Net.Http.HttpClient(handler) { Timeout = timeout };
        }

        public static async Task<(int statusCode, string? result)> CloudScanAsync(string path)
        {
            string hash = await GetFileMD5Async(path);
            return await CloudScanWithHashAsync(hash);
        }

        public static async Task<(int statusCode, string? result)> CloudScanWithHashAsync(string hash)
        {
            var client = s_httpClient;
            string url = $"{CloudScanBaseUrl}/scan/md5?key={CloudScanApiKey}&md5={hash}";
            try
            {
                var resp = await client.GetAsync(url);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("scan_result", out JsonElement prop))
                {
                    return (200, prop.GetString());
                }
            }
            catch (HttpRequestException ex)
            {
                return ((int?)ex.StatusCode ?? -1, string.Empty);
            }

            return (-1, string.Empty);
        }

        public static async Task<string> GetFileMD5Async(string path)
        {
            using var md5 = MD5.Create();
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 131072, useAsync: true);
            var hash = await md5.ComputeHashAsync(stream);
            return Convert.ToHexString(hash);
        }

        public static string ComputeMD5(byte[] data)
        {
            byte[] hash = MD5.HashData(data);
            return Convert.ToHexString(hash);
        }

        public static async Task<string> GetFileSHA256Async(string path, CancellationToken token = default)
        {
            using var sha256 = SHA256.Create();
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 131072, useAsync: true);
            var hash = await sha256.ComputeHashAsync(stream, token);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static string ComputeSHA256(byte[] data)
        {
            byte[] hash = SHA256.HashData(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static async Task<Dictionary<string, (string? result, string? family)>> ExactRuleEngineBatchScanAsync(List<string> filePaths, CancellationToken token = default)
        {
            var results = new Dictionary<string, (string? result, string? family)>(StringComparer.OrdinalIgnoreCase);
            if (filePaths.Count == 0) return results;

            var hashEntries = new List<(string filePath, string hash)>();
            foreach (var path in filePaths)
            {
                try
                {
                    string hash = await GetFileSHA256Async(path, token);
                    hashEntries.Add((path, hash));
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception)
                {
                }
            }

            if (hashEntries.Count == 0) return results;

            return await ExactRuleEngineBatchScanHashesAsync(hashEntries, token);
        }

        public static async Task<Dictionary<string, (string? result, string? family)>> ExactRuleEngineBatchScanHashesAsync(List<(string filePath, string hash)> hashEntries, CancellationToken token = default)
        {
            var results = new Dictionary<string, (string? result, string? family)>(StringComparer.OrdinalIgnoreCase);
            if (hashEntries.Count == 0) return results;

            var client = s_httpClient;
            string url = $"{ExactRuleBaseUrl}/api/batch_check";
            try
            {
                var hashes = hashEntries.Select(e => e.hash).ToList();
                // 使用 Utf8JsonWriter 构造 JSON，避免手动拼接字符串带来的注入风险与转义错误
                var bufferWriter = new System.Buffers.ArrayBufferWriter<byte>();
                using (var jsonWriter = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = false }))
                {
                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteStartArray("hashes");
                    foreach (var hash in hashes)
                    {
                        jsonWriter.WriteStringValue(hash);
                    }
                    jsonWriter.WriteEndArray();
                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();
                }
                var content = new ByteArrayContent(bufferWriter.WrittenSpan.ToArray());
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                var resp = await client.PostAsync(url, content, token);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync(token);
                if (String.IsNullOrWhiteSpace(json)) return results;
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("results", out JsonElement resultsArray) && resultsArray.ValueKind == JsonValueKind.Array)
                {
                    int i = 0;
                    foreach (JsonElement item in resultsArray.EnumerateArray())
                    {
                        if (i >= hashEntries.Count) break;
                        var (filePath, _) = hashEntries[i];
                        string result = item.TryGetProperty("result", out JsonElement rProp) && rProp.ValueKind == JsonValueKind.String ? (rProp.GetString() ?? "unknown") : "unknown";
                        if (result == "black")
                        {
                            string? family = item.TryGetProperty("family", out JsonElement fProp) && fProp.ValueKind == JsonValueKind.String ? fProp.GetString() : null;
                            results[filePath] = (family ?? "ExactRule.Malware", family);
                        }
                        else if (result == "white")
                        {
                            results[filePath] = ("safe", null);
                        }
                        else
                        {
                            results[filePath] = (null, null);
                        }
                        i++;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
            }
            return results;
        }
    }
}
