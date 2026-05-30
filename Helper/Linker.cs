using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Web;
using static Helper.Linker.CallBack;

namespace Helper
{
    public class Linker
    {
        public static class CallBack
        {
            public delegate Task<string> InterceptCallBack(InterceptWindowHelper.InterceptWindowSetting interceptWindowSetting);
        }

        private static TcpListener? s_listener;
        private static CancellationTokenSource? s_cts;

        public static async Task Start(InterceptCallBack interceptCallBack)
        {
            s_cts = new CancellationTokenSource();
            s_listener = new TcpListener(IPAddress.Any, 20000);
            s_listener.Start();
            try
            {
                while (!s_cts.IsCancellationRequested)
                {
                    var client = await s_listener.AcceptTcpClientAsync(s_cts.Token);
                    _ = HandleClientAsync(client, interceptCallBack);
                }
            }
            catch (OperationCanceledException) { }
        }

        public static void Stop()
        {
            s_cts?.Cancel();
            s_listener?.Stop();
        }

        private static async Task HandleClientAsync(TcpClient client, InterceptCallBack interceptCallBack)
        {
            using (client)
            using (var stream = client.GetStream())
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                var requestLine = await reader.ReadLineAsync();
                if (string.IsNullOrEmpty(requestLine)) return;

                string line;
                while (!string.IsNullOrEmpty(line = (await reader.ReadLineAsync()) ?? String.Empty)) { }

                var parts = requestLine.Split(' ');
                if (parts.Length == 0) return;
                var method = parts[0];
                var fullPath = parts.Length > 1 ? parts[1] : "/";

                string path;
                string queryString = "";
                int queryIndex = fullPath.IndexOf('?');
                if (queryIndex >= 0)
                {
                    path = fullPath[..queryIndex];
                    queryString = fullPath.Substring(queryIndex + 1);
                }
                else
                {
                    path = fullPath;
                }

                int statusCode;
                string statusText;
                string jsonBody;
                string? buttonName = null;

                if (path.Equals("/InterceptWindow/", StringComparison.OrdinalIgnoreCase))
                {
                    var queryParams = HttpUtility.ParseQueryString(queryString);
                    string? pathParam = queryParams["path"];

                    if (String.IsNullOrEmpty(pathParam) || pathParam.Contains(".."))
                    {
                        statusCode = 400;
                        statusText = "Invalid path parameter";
                    }
                    else
                    {
                        statusCode = 200;
                        statusText = "OK";
                        buttonName = await interceptCallBack.Invoke(new InterceptWindowHelper.InterceptWindowSetting
                        {
                            Path = pathParam,
                            IsSucceed = true,
                            InterceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.InterceptOrRelease
                        });
                    }
                }
                else
                {
                    statusCode = 404;
                    statusText = "Not Found";
                }

                statusText = statusText.Replace("\r", "").Replace("\n", "");
                jsonBody = GetJsonBody(statusCode, statusText, buttonName);

                var response = $@"
HTTP/1.1 {statusCode} {statusText}
Content-Type: application/json; charset=utf-8
Content-Length: {Encoding.UTF8.GetByteCount(jsonBody)}
Connection: close

{jsonBody}";

                var responseBytes = Encoding.UTF8.GetBytes(response);
                await stream.WriteAsync(responseBytes);
            }
        }

        private static string GetJsonBody(int statusCode, string statusText, string? buttonName = null)
        {
            using var ms = new MemoryStream();
            using var writer = new Utf8JsonWriter(ms);
            writer.WriteStartObject();
            writer.WriteNumber("statusCode", statusCode);
            writer.WriteString("statusText", statusText);
            writer.WriteString("timestamp", DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            if (buttonName != null)
                writer.WriteString("ButtonReturn", buttonName);
            writer.WriteEndObject();
            writer.Flush();
            return Encoding.UTF8.GetString(ms.ToArray());
        }
    }
}