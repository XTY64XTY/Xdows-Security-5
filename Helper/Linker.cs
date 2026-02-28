using System.Net;
using System.Net.Sockets;
using System.Text;
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
        public static async void Start(InterceptCallBack interceptCallBack)
        {
            var listener = new TcpListener(IPAddress.Any, 20000);
            listener.Start();
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client, interceptCallBack);
            }
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

                    if (String.IsNullOrEmpty(pathParam))
                    {
                        statusCode = 400;
                        statusText = "Missing required parameter";
                    }
                    else
                    {
                        statusCode = 200;
                        statusText = "OK";
                        buttonName = await interceptCallBack.Invoke(new InterceptWindowHelper.InterceptWindowSetting
                        {
                            path = pathParam,
                            isSucceed = true,
                            interceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.InterceptOrRelease
                        });
                    }
                }
                else
                {
                    statusCode = 404;
                    statusText = "Not Found";
                }
                jsonBody = GetJsonBody(statusCode, statusText, buttonName);

                // 发送HTTP响应
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
            string buttonJson = buttonName is null ? string.Empty : $",\n    \"ButtonReturn\": \"{buttonName}\"";
            return $@"
{{
    ""statusCode"": {statusCode},
    ""statusText"": ""{statusText}"",
    ""timestamp"": ""{DateTime.Now:yyyy-MM-ddTHH:mm:ss.fffZ}""{buttonJson}
}}";
        }
    }
}