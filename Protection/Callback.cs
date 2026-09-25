using static Protection.Callback;

namespace Protection
{
    public static class Callback
    {
        public delegate void InterceptCallback(ProtectionInterceptEvent interceptEvent);
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
        ulong EventId = 0,
        ulong CorrelationId = 0,
        string? ActorDetectionName = null,
        double ActorProbability = 0,
        Helper.ProtectionModule Module = Helper.ProtectionModule.Unknown,
        Helper.ProtectionBackend Backend = Helper.ProtectionBackend.Driver,
        DateTimeOffset DecisionDeadline = default);

    public interface IProtectionModel
    {
        string Name { get; }
        bool Stop() { return false; }
        bool Run(InterceptCallback interceptCallback) { return false; }
        bool IsRun() { return false; }
    }
}
