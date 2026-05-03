using System.Security.Cryptography;
using System.Text.Json;

namespace Helper
{
    public static class ScanEngine
    {
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
            return await Task.Run(() =>
            {
                try
                {
                    var detection = InfectorCleaner.InfectorDetector.DetectInfector(path);
                    if (detection.IsInfected)
                    {
                        return (true, "HEUR:Infector.EP_Hijack!ml");
                    }
                }
                catch { }
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
                catch { return null; }
            });
        }

        public class ModelEngineScan
        {
            public static bool Initialize()
            {
                try
                {
                    Xdows_Model_Invoker.ModelInvoker.Initialize();
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            public static (bool IsVirus, string Result) ScanFile(string path)
            {
                try
                {
                    var r = Xdows_Model_Invoker.ModelInvoker.ScanFile(path);
                    if (r.isVirus)
                    {
                        return (true, $"Xdows.Model.Probability{(int)r.probability}");
                    }
                }
                catch { }
                return (false, string.Empty);
            }
        }

        private static readonly System.Net.Http.HttpClient s_httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };

        public static async Task<(int statusCode, string? result)> CzkCloudScanAsync(string path, string apiKey)
        {
            string hash = await GetFileMD5Async(path);
            return await CzkCloudScanWithHashAsync(hash, apiKey);
        }

        public static async Task<(int statusCode, string? result)> CzkCloudScanWithHashAsync(string hash, string apiKey)
        {
            var client = s_httpClient;
            string url = $"https://cv.szczk.top/scan/{apiKey}/{hash}";
            try
            {
                var resp = await client.GetAsync(url);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("result", out JsonElement prop))
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

        public static async Task<(int statusCode, string? result)> CloudScanAsync(string path)
        {
            string hash = await GetFileMD5Async(path);
            return await CloudScanWithHashAsync(hash);
        }

        public static async Task<(int statusCode, string? result)> CloudScanWithHashAsync(string hash)
        {
            var client = s_httpClient;
            string url = $"http://103.118.245.82:5000/scan/md5?key=my_virus_key_2024&md5={hash}";
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

        public static async Task<string> GetFileSHA256Async(string path)
        {
            using var sha256 = SHA256.Create();
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 131072, useAsync: true);
            var hash = await sha256.ComputeHashAsync(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static string ComputeSHA256(byte[] data)
        {
            byte[] hash = SHA256.HashData(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static async Task<(int statusCode, string? result, string? family)> ExactRuleEngineScanAsync(string path)
        {
            string hash = await GetFileSHA256Async(path);
            return await ExactRuleEngineScanWithHashAsync(hash);
        }

        public static async Task<(int statusCode, string? result, string? family)> ExactRuleEngineScanWithHashAsync(string hash)
        {
            var client = s_httpClient;
            string url = "http://103.118.245.82:7050/api/check";
            try
            {
                string jsonBody = $"{{\"hash\":\"{hash}\"}}";
                var content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
                var resp = await client.PostAsync(url, content);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();
                using JsonDocument doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("result", out JsonElement resultProp))
                {
                    string result = resultProp.GetString() ?? "unknown";
                    if (result == "black")
                    {
                        string? family = root.TryGetProperty("family", out JsonElement familyProp) ? familyProp.GetString() : null;
                        return (200, family ?? "ExactRule.Malware", family);
                    }
                    else if (result == "white")
                    {
                        return (200, "safe", null);
                    }
                    else
                    {
                        return (200, null, null);
                    }
                }
            }
            catch
            {
                return (-1, null, null);
            }
            return (-1, null, null);
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
                    string hash = await GetFileSHA256Async(path);
                    hashEntries.Add((path, hash));
                }
                catch { }
            }

            if (hashEntries.Count == 0) return results;

            return await ExactRuleEngineBatchScanHashesAsync(hashEntries, token);
        }

        public static async Task<Dictionary<string, (string? result, string? family)>> ExactRuleEngineBatchScanHashesAsync(List<(string filePath, string hash)> hashEntries, CancellationToken token = default)
        {
            var results = new Dictionary<string, (string? result, string? family)>(StringComparer.OrdinalIgnoreCase);
            if (hashEntries.Count == 0) return results;

            var client = s_httpClient;
            string url = "http://103.118.245.82:7050/api/batch_check";
            try
            {
                var hashes = hashEntries.Select(e => e.hash).ToList();
                var sb = new System.Text.StringBuilder();
                sb.Append("{\"hashes\":[");
                for (int h = 0; h < hashes.Count; h++)
                {
                    if (h > 0) sb.Append(',');
                    sb.Append('\"');
                    sb.Append(hashes[h]);
                    sb.Append('\"');
                }
                sb.Append("]}");
                string jsonBody = sb.ToString();
                var content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
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
            catch { }
            return results;
        }
    }
}
