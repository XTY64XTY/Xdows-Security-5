using static Protection.CallBack;

namespace Protection
{
    public static class CallBack
    {
        public delegate void InterceptCallBack(ProtectionInterceptEvent interceptEvent);
    }

    public sealed record ProtectionInterceptEvent(
        string Path,
        bool IsSucceed,
        string DetectionName,
        double Probability,
        Helper.ProtectionModule Module,
        Helper.ProtectionBackend Backend);

    public enum ProtectionUserDecision
    {
        Allow,
        Block,
        Timeout
    }

    public sealed record ProtectionDecisionRequest(
        string Path,
        string ProtectionType,
        string DetectionName,
        double Probability,
        int ProcessId,
        int ParentProcessId,
        string? CommandLine,
        string? ActorPath = null,
        string? ActorTrust = null,
        ulong CorrelationId = 0,
        string? ActorDetectionName = null,
        double ActorProbability = 0,
        Helper.ProtectionModule Module = Helper.ProtectionModule.Unknown,
        Helper.ProtectionBackend Backend = Helper.ProtectionBackend.Driver);

    public interface IProtectionModel
    {
        string Name { get; }
        bool Stop() { return false; }
        bool Run(InterceptCallBack interceptCallBack) { return false; }
        bool IsRun() { return false; }
    }
}
