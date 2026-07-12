namespace Helper
{
    public enum ProtectionModule
    {
        Unknown,
        Process,
        File,
        Injection,
        Behavior,
        SelfProtection
    }

    public enum ProtectionBackend
    {
        Compatibility,
        Driver
    }

    public class InterceptWindowHelper
    {
        public class InterceptWindowSetting
        {
            public InterceptWindowButtonType InterceptWindowButtonType { get; set; }
            public required string Path { get; set; }
            public bool IsSucceed { get; set; }
            public string? ButtonName { get; set; }
            public string? ProtectionType { get; set; }
            public string? DetectionName { get; set; }
            public double Probability { get; set; }
            public string? ActorPath { get; set; }
            public string? ActorTrust { get; set; }
            public string? ActorDetectionName { get; set; }
            public double ActorProbability { get; set; }
            public string? CommandLine { get; set; }
            public ulong CorrelationId { get; set; }
            public ProtectionModule Module { get; set; } = ProtectionModule.Unknown;
            public ProtectionBackend Backend { get; set; } = ProtectionBackend.Compatibility;
        }
        public enum InterceptWindowButtonType
        {
            ReminderOnly,
            RestoreOrTrust,
            InterceptOrRelease
        }
    }
}
