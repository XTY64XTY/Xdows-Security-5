namespace Helper
{
    public class InterceptWindowHelper
    {
        public class InterceptWindowSetting
        {
            public InterceptWindowButtonType interceptWindowButtonType;
            public required string path;
            public bool isSucceed;
            public string? buttonName;
        }
        public enum InterceptWindowButtonType
        {
            ReminderOnly,
            RestoreOrTrust,
            InterceptOrRelease
        }
    }
}
