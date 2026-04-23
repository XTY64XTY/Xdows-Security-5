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
    }
}
