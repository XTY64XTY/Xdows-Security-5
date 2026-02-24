using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Xdows_Security.Views
{

    [JsonSerializable(typeof(Dictionary<string, object>))]
    public partial class BugReportJsonContext : JsonSerializerContext
    {
    }
}