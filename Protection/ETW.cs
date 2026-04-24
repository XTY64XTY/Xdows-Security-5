using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using static Protection.CallBack;

namespace Protection
{
    public partial class ETW
    {
        public delegate void MonitoringCallback(ProcessTraceData data, InterceptCallBack interceptCallBack);
    }
}
