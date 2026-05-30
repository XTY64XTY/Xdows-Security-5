namespace Helper
{
    public class InterceptWindowHelper
    {
        public class InterceptWindowSetting
        {
            public InterceptWindowButtonType InterceptWindowButtonType { get; set; }
            public required string Path { get; set; }
            public bool IsSucceed { get; set; }
            public string? ButtonName { get; set; }
        }
        public enum InterceptWindowButtonType
        {
            ReminderOnly,
            RestoreOrTrust,
            InterceptOrRelease
        }
    }
}
