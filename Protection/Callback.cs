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
        Timeout,
        //
        // A parallel event for the same file / same eventId arrived while the
        // user decision for the first one is still pending. It must never be
        // treated as a verdict: no quarantine, no cached block, otherwise a
        // file the user later releases is deleted behind their back by the
        // duplicates that raced the dialog.
        //
        Deferred
    }

    /// <summary>
    /// 决策弹窗提供的按钮组。与兼容模式一致的处理方式是 RestoreOrTrust：
    /// 威胁已经隔离，弹窗只给「恢复 / 信任并恢复」，不再提供放行。
    /// </summary>
    public enum ProtectionInterceptButtons
    {
        /// 拦截 / 放行（默认，用于行为、启动保护、注册表等非文件类事件）。
        InterceptOrRelease,

        /// 恢复文件 / 信任并恢复（文件与进程威胁：已隔离，弹窗只提供恢复入口）。
        RestoreOrTrust
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
        DateTimeOffset DecisionDeadline = default,
        ProtectionInterceptButtons Buttons = ProtectionInterceptButtons.InterceptOrRelease);

    public interface IProtectionModel
    {
        string Name { get; }
        bool Stop() { return false; }
        bool Run(InterceptCallback interceptCallback) { return false; }
        bool IsRun() { return false; }
    }
}
