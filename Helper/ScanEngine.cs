using Microsoft.Windows.Storage;
using System.Security.Cryptography;
using System.Text.Json;
using Xdows_Model_Config;
using Xdows_Model_Invoker;

namespace Helper
{
    public sealed record CloudHealthInfo(string Engine, int FeatureDim, int Threshold, long UptimeSeconds);

    public enum CloudScanMode
    {
        Adaptive,
        Quick,
        FullUpload
    }

    public static class ScanEngine
    {
        // 缓存 LocalSettings，避免每次读取配置都调用 ApplicationData.GetForUnpackaged
        // PublicationOnly 模式：失败不缓存异常，避免单次失败导致整个类永久不可用
        private static readonly Lazy<ApplicationDataContainer> _settingsLazy = new(
            () => ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security").LocalSettings,
            LazyThreadSafetyMode.PublicationOnly);
        private static ApplicationDataContainer Settings => _settingsLazy.Value;

        private const string DefaultCloudScanBaseUrl = "https://sevenengine-cloud.onrender.com";
        private const string DefaultExactRuleBaseUrl = "http://103.118.245.82:7050";

        // 云端端点可经 LocalSettings 覆盖（键名 CloudScanBaseUrl / ExactRuleBaseUrl），未设置时回退到默认值。
        private static string CloudScanBaseUrl => ReadSetting("CloudScanBaseUrl", DefaultCloudScanBaseUrl);
        private static string ExactRuleBaseUrl => ReadSetting("ExactRuleBaseUrl", DefaultExactRuleBaseUrl);

        private static string ReadSetting(string key, string fallback)
        {
            try
            {
                var settings = Settings;
                if (settings.Values.TryGetValue(key, out var raw) && raw is string value && !string.IsNullOrEmpty(value))
                {
                    return value;
                }
            }
            catch (Exception) { }
            return fallback;
        }

        public static async Task<string> LocalScanAsync(string path, bool deep, bool ExtraData)
        {
            return await Task.Run(() => Xdows_Local.Core.Scan(path, deep, ExtraData));
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
            private static readonly Lazy<ApplicationDataContainer> _settingsLazy = new(
                () => ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security").LocalSettings,
                LazyThreadSafetyMode.PublicationOnly);
            private static ApplicationDataContainer Settings => _settingsLazy.Value;

            private static Xdows_Model_Invoker.ModelMode _mode = Xdows_Model_Invoker.ModelMode.Flash;

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
                    if (settings.Values.TryGetValue("ModelMode", out var raw) && raw is string mode)
                    {
                        _mode = mode switch
                        {
                            "Flash" => Xdows_Model_Invoker.ModelMode.Flash,
                            "Adaptive" => Xdows_Model_Invoker.ModelMode.Adaptive,
                            "Pro" => Xdows_Model_Invoker.ModelMode.Pro,
                            _ => Xdows_Model_Invoker.ModelMode.Flash
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
                    ApplyThresholdFromSettings("ModelThreshold", "ModelThresholdValue");
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
                    var settings = Settings;
                    string mode = settings.Values.TryGetValue("ProtectionModelMode", out var raw) && raw is string ms
                        ? ms
                        : "Flash";
                    ApplyThresholdFromSettings("ProtectionModelThreshold", "ProtectionModelThresholdValue");
                    InitializeWithMode(mode switch
                    {
                        "Standard" => Xdows_Model_Invoker.ModelMode.Standard,
                        "Adaptive" => Xdows_Model_Invoker.ModelMode.Adaptive,
                        "Pro" => Xdows_Model_Invoker.ModelMode.Pro,
                        _ => Xdows_Model_Invoker.ModelMode.Flash
                    });
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            /// <summary>
            /// 按设置里的阈值预设（宽松 / 中等 / 严格 / 自定义）配置固定判毒阈值。
            /// 固定阈值是 Malware 判定的下限；推荐阈值（Suspicious 区间）在加载模型时仍由模型旁的 *.threshold.json 填充。
            /// </summary>
            private static void ApplyThresholdFromSettings(string presetKey, string valueKey)
            {
                var settings = Settings;
                string preset = settings.Values.TryGetValue(presetKey, out var presetRaw) && presetRaw is string p
                    ? p
                    : ModelThresholdPresets.Medium;
                double customValue = settings.Values.TryGetValue(valueKey, out var valueRaw) && valueRaw is double v
                    ? v
                    : ModelThresholdPresets.DefaultCustom;

                (float standard, float flash, float pro) = ModelThresholdPresets.Resolve(preset, customValue);
                ModelInvoker.ConfigureThresholds(new TrainingConfig
                {
                    StandardThreshold = standard,
                    FlashThreshold = flash,
                    ProThreshold = pro
                });
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
                    var (scanVerdict, probability) = Xdows_Model_Invoker.ModelInvoker.ScanFile(path);
                    if (scanVerdict == ScanVerdict.Malware)
                    {
                        string modeTag = _mode switch
                        {
                            Xdows_Model_Invoker.ModelMode.Flash => "Flash",
                            Xdows_Model_Invoker.ModelMode.Adaptive => "Adaptive",
                            Xdows_Model_Invoker.ModelMode.Pro => "Pro",
                            _ => "Flash"
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
                    _ => "Flash"
                };
                return $"Xdows-Model ({modeTag})";
            }
        }

        // 配置连接池与生命周期：SocketsHttpHandler 是 .NET 10 默认主处理器，显式配置可控制连接池行为
        // - PooledConnectionLifetime: 连接最长存活 2 分钟，避免长时间复用导致 DNS 变化失效
        // - MaxConnectionsPerServer: 单服务器最大并发连接数，防止突发请求耗尽端口
        // - AutomaticDecompression: 自动解压响应（gzip/deflate/br），减少带宽消耗
        // 注：自建服务（103.118.245.82）走 HTTP 明文，保持 HTTP/1.1 以兼容未知的服务端 h2c 支持情况
        private static readonly System.Net.Http.HttpClient _httpClient = BuildHttpClient(TimeSpan.FromSeconds(30));
        private static readonly System.Net.Http.HttpClient _uploadHttpClient = BuildHttpClient(Timeout.InfiniteTimeSpan);
        private const long MaxCloudUploadBytes = 300L * 1024 * 1024;
        private static readonly TimeSpan CloudUploadTimeout = TimeSpan.FromMinutes(10);

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

        public static async Task<CloudHealthInfo?> GetCloudHealthAsync()
        {
            try
            {
                using var resp = await _httpClient.GetAsync($"{CloudScanBaseUrl}/api/health");
                if (!resp.IsSuccessStatusCode) return null;

                string json = await resp.Content.ReadAsStringAsync();
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
                if (!root.TryGetProperty("ok", out JsonElement ok) || ok.ValueKind != JsonValueKind.True) return null;
                if (!root.TryGetProperty("engine", out JsonElement engineProp) || engineProp.ValueKind != JsonValueKind.String) return null;
                string? engine = engineProp.GetString();
                if (string.IsNullOrWhiteSpace(engine)) return null;
                if (!root.TryGetProperty("feature_dim", out JsonElement featureProp) || !featureProp.TryGetInt32(out int featureDim)) return null;
                if (!root.TryGetProperty("threshold", out JsonElement thresholdProp) || !thresholdProp.TryGetInt32(out int threshold)) return null;
                if (!root.TryGetProperty("uptime_sec", out JsonElement uptimeProp) || !uptimeProp.TryGetInt64(out long uptimeSeconds)) return null;

                return new CloudHealthInfo(engine, featureDim, threshold, uptimeSeconds);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static async Task<(int statusCode, string? result)> CloudScanAsync(string path)
        {
            string hash = await GetFileMD5Async(path);
            return await CloudScanWithHashAsync(hash, path);
        }

        public static async Task<(int statusCode, string? result)> CloudScanWithHashAsync(
            string hash,
            string? filePath = null,
            CancellationToken token = default)
        {
            CloudScanMode mode = GetCloudScanMode();
            if (mode != CloudScanMode.FullUpload)
            {
                (bool succeeded, bool found, string? status) = await QueryCloudHashAsync(hash, token);
                if (!succeeded) return (-1, string.Empty);
                if (found) return (200, MapCloudStatus(status));
                if (mode == CloudScanMode.Quick) return (-1, string.Empty);
            }

            if (string.IsNullOrEmpty(filePath)) return (-1, string.Empty);
            return await UploadCloudScanAsync(filePath, token);
        }

        private static CloudScanMode GetCloudScanMode()
        {
            return ReadSetting("CloudScanMode", "Quick") switch
            {
                "Adaptive" => CloudScanMode.Adaptive,
                "FullUpload" => CloudScanMode.FullUpload,
                _ => CloudScanMode.Quick
            };
        }

        private static async Task<(bool succeeded, bool found, string? status)> QueryCloudHashAsync(
            string hash,
            CancellationToken token)
        {
            string url = $"{CloudScanBaseUrl}/api/scan/hash";
            try
            {
                var bufferWriter = new System.Buffers.ArrayBufferWriter<byte>();
                using (var jsonWriter = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = false }))
                {
                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteString("md5", hash);
                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();
                }
                using var content = new ByteArrayContent(bufferWriter.WrittenSpan.ToArray());
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                using var resp = await _httpClient.PostAsync(url, content, token);
                if (!resp.IsSuccessStatusCode) return (false, false, null);

                string json = await resp.Content.ReadAsStringAsync(token);
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
                if (!root.TryGetProperty("ok", out JsonElement ok) || ok.ValueKind != JsonValueKind.True) return (false, false, null);
                if (root.TryGetProperty("found", out JsonElement foundProp) && foundProp.ValueKind == JsonValueKind.False) return (true, false, null);
                if (root.TryGetProperty("status", out JsonElement statusProp) && statusProp.ValueKind == JsonValueKind.String)
                {
                    return (true, true, statusProp.GetString());
                }

                return (false, false, null);
            }
            catch (OperationCanceledException)
            {
                if (token.IsCancellationRequested) throw;
                return (false, false, null);
            }
            catch (Exception)
            {
                return (false, false, null);
            }
        }

        private static async Task<(int statusCode, string? result)> UploadCloudScanAsync(
            string filePath,
            CancellationToken token)
        {
            try
            {
                FileInfo fileInfo = new(filePath);
                if (!fileInfo.Exists || fileInfo.Length > MaxCloudUploadBytes) return (-1, string.Empty);

                await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 131072, useAsync: true);
                using var form = new System.Net.Http.MultipartFormDataContent();
                using var fileContent = new System.Net.Http.StreamContent(stream);
                fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                form.Add(fileContent, "file", Path.GetFileName(filePath));

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(CloudUploadTimeout);
                string url = $"{CloudScanBaseUrl}/api/scan";
                using var resp = await _uploadHttpClient.PostAsync(url, form, cts.Token);
                if (!resp.IsSuccessStatusCode) return ((int)resp.StatusCode, string.Empty);

                string json = await resp.Content.ReadAsStringAsync(cts.Token);
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
                if (!root.TryGetProperty("ok", out JsonElement ok) || ok.ValueKind != JsonValueKind.True) return (-1, string.Empty);
                if (!root.TryGetProperty("status", out JsonElement statusProp) || statusProp.ValueKind != JsonValueKind.String) return (-1, string.Empty);
                return (200, MapCloudStatus(statusProp.GetString()));
            }
            catch (OperationCanceledException)
            {
                if (token.IsCancellationRequested) throw;
                return (-1, string.Empty);
            }
            catch (Exception)
            {
                return (-1, string.Empty);
            }
        }

        private static string? MapCloudStatus(string? status)
        {
            return status == "malware" ? "virus_file" : status;
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

            var client = _httpClient;
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
                if (string.IsNullOrWhiteSpace(json)) return results;
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
