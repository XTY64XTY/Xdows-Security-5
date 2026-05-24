using Compatibility.Windows.Storage;
using Helper;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.Windows.AppLifecycle;
using Microsoft.Windows.Globalization;
using Protection;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;
using Xdows_Security.Services;
using static Protection.CallBack;

namespace Xdows_Security
{
    public record UpdateInfo
    {
        public required string Title { get; set; }
        public required string Content { get; set; }
        public required string DownloadUrl { get; set; }
    }

    public static class Updater
    {
        private static readonly HttpClient _httpClient = new();

        static Updater()
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppInfo.AppId}/{AppInfo.AppVersion}");
        }

        public static async Task<UpdateInfo?> CheckUpdateAsync()
        {
            try
            {
                const string url = "https://api.github.com/repositories/1032964256/releases/latest";
                string json = await _httpClient.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string? title = root.GetProperty("name").GetString()
                               ?? root.GetProperty("tag_name").GetString();

                string? content = root.GetProperty("body").GetString();

                string? downloadUrl = null;
                if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var asset in assets.EnumerateArray())
                    {
                        if (asset.TryGetProperty("browser_download_url", out var urlProp))
                        {
                            downloadUrl = urlProp.GetString();
                            break;
                        }
                    }
                }

                downloadUrl ??= root.GetProperty("html_url").GetString();

                return new UpdateInfo
                {
                    Title = title ?? string.Empty,
                    Content = content ?? string.Empty,
                    DownloadUrl = downloadUrl ?? string.Empty
                };
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "Updater", $"Failed to check update: {ex.Message}");
                return null; // 或可抛出异常，依需求而定
            }
        }
    }
    public class AppInfo
    {
        public static readonly string AppName = "Xdows Security";
        public static readonly string AppId = "Xdows-Security";
        public static readonly string AppVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? string.Empty;
        public static readonly string AppFeedback = "https://github.com/XTY64XTY/Xdows-Security-5/issues/new/choose";
        public static readonly string AppWebsite = "https://docs.xiguastudio.top/";
        // 修改 开发团队、Xdows Tools 名称请修改本地化资源文件
    }
    public static class ProtectionStatus
    {
        public static event EventHandler? StateChanged;

        public static bool IsOpen()
        {
            return IsRun(0) || IsRun(1) || IsRun(4);
        }

        private static readonly InterceptCallBack interceptCallBack = (isSucceed, path, type) =>
        {
            LogText.AddNewLog(LogText.LogLevel.WARN, "Protection", isSucceed
                ? $"InterceptProcess：{path}"
                : $"Cannot InterceptProcess：{path}");
            // string content = isSucceed ? "已发现威胁" : "无法处理威胁";
            // content = $"{AppInfo.AppName} {content}.{Environment.NewLine}相关数据：{Path.GetFileName(path)}{Environment.NewLine}单击此通知以查看详细信息";
            _ = (App.MainWindow?.DispatcherQueue?.TryEnqueue(() =>
            {
                _ = InterceptWindow.ShowOrActivate(new InterceptWindowHelper.InterceptWindowSetting
                {
                    path = path,
                    isSucceed = isSucceed,
                    interceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.RestoreOrTrust
                });
            }));
            // Notifications.ShowNotification("发现威胁", content, path);
        };
        private static readonly IProtectionModel LegacyProcessProtection = new LegacyProcessProtection();
        private static readonly IProtectionModel LegacyFilesProtection = new LegacyFilesProtection();

        private static readonly IProtectionModel ETWProcessProtection = new ETW.ProcessProtection();
        private static readonly IProtectionModel ETWFilesProtection = new ETW.FilesProtection();
        private static readonly IProtectionModel ETWRegistryProtection = new ETW.RegistryProtection();
        public static bool Run(int RunID)
        {
            IProtectionModel? protection = RunIdToProtection(RunID);

            if (protection is null) { return false; }

            bool result;
            if (protection.IsRun())
            {
                result = protection.Stop();
            }
            else
            {
                result = protection.Run(interceptCallBack);
            }

            if (result)
            {
                SaveProtectionState(RunID, IsRun(RunID));
                StateChanged?.Invoke(null, EventArgs.Empty);
            }

            return result;
        }

        private static void SaveProtectionState(int runId, bool enabled)
        {
            ApplicationData.Current.LocalSettings.Values[$"Protection_Enabled_{runId}"] = enabled;
        }

        public static void RestoreProtections()
        {
            RestoreProtection(0);
            RestoreProtection(1);

            if (App.IsRunAsAdmin())
            {
                RestoreProtection(4);
            }
        }

        private static void RestoreProtection(int runId)
        {
            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                string key = $"Protection_Enabled_{runId}";

                if (!settings.Values.TryGetValue(key, out var raw) || raw is not bool shouldEnable)
                    return;

                var protection = RunIdToProtection(runId);
                if (protection is null) return;

                bool changed = false;
                if (shouldEnable && !protection.IsRun())
                {
                    changed = protection.Run(interceptCallBack);
                }
                else if (!shouldEnable && protection.IsRun())
                {
                    changed = protection.Stop();
                }

                if (changed)
                {
                    StateChanged?.Invoke(null, EventArgs.Empty);
                }
            }
            catch { }
        }

        public static bool IsRun(int RunID)
        {
            return RunIdToProtection(RunID)?.IsRun() ?? false;
        }
        private static IProtectionModel? RunIdToProtection(int RunID)
        {
            IProtectionModel? protection = RunID switch
            {
                0 => ETWProcessProtection,
                1 => ETWFilesProtection,
                4 => ETWRegistryProtection,
                _ => null,
            };
            if (protection is null) { return null; }

            bool isCompatibilityMode = ApplicationData.Current.LocalSettings.Values[protection.Name + "_CompatibilityMode"] as bool? ?? (RunID is 0 or 1);

            if (isCompatibilityMode)
            {
                protection = RunID switch
                {
                    0 => LegacyProcessProtection,
                    1 => LegacyFilesProtection,
                    _ => null,
                };
            }

            return protection;
        }
    }

    public static class Statistics
    {
        public static int ScansQuantity = 0;
        public static int VirusQuantity = 0;
    }
    public static class LogText
    {
        public static event EventHandler? TextChanged;

        public static void AddNewLog(LogLevel level, string source, string info)
        {
            Services.LogService.AddLog(level, source, info);
            TextChanged?.Invoke(null, EventArgs.Empty);
        }

        public static void ClearLog()
        {
            Services.LogService.ClearAll();
            TextChanged?.Invoke(null, EventArgs.Empty);
        }

        [Obsolete("Use LogService for structured log access.")]
        public static string Text => "";

        public enum LogLevel
        {
            DEBUG = 0,
            INFO = 1,
            WARN = 2,
            ERROR = 3,
            FATAL = 4
        }
    }
    public partial class App : Application
    {
        public static MainWindow? MainWindow { get; private set; }

        private static List<string> _scanTargetPaths = [];
        private static readonly Lock _scanPathLock = new();
        private const string PathSeparator = "\t";

        public static IReadOnlyList<string> ScanTargetPaths
        {
            get
            {
                lock (_scanPathLock)
                {
                    return _scanTargetPaths.AsReadOnly();
                }
            }
        }

        public static void SetScanTargetPaths(IEnumerable<string> paths)
        {
            lock (_scanPathLock)
            {
                _scanTargetPaths = [.. paths];
            }
        }

        public static void ClearScanTargetPaths()
        {
            lock (_scanPathLock)
            {
                _scanTargetPaths.Clear();
            }
        }

        private static readonly Lock _settingsLock = new();
        private const string RunOOBESettingKey = "RunOOBE";

        private static Mutex? _singleInstanceMutex;
        private static bool _ownsMutex;
        private const string MutexName = "Xdows_Security_SingleInstance";
        private const string PipeName = "Xdows_Security_IPC";

        private static CancellationTokenSource? _pipeListenerCts;

        public static void ReleaseResources()
        {
            _pipeListenerCts?.Cancel();
            _pipeListenerCts?.Dispose();
            _pipeListenerCts = null;

            if (_ownsMutex && _singleInstanceMutex != null)
            {
                try
                {
                    _singleInstanceMutex.ReleaseMutex();
                }
                catch { }
                _singleInstanceMutex.Dispose();
                _singleInstanceMutex = null;
            }
        }

        public App()
        {
            LogText.AddNewLog(LogText.LogLevel.INFO, "UI Interface", "Attempting to load the MainWindow...");
            this.InitializeComponent();
        }
        protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                ParseCommandLineArgs();

                if (!TryAcquireSingleInstance())
                {
                    // 即使主进程还没完全启动监听，SendScanPathsToExistingInstanceAsync 内部的重试机制也会等待。
                    if (await SendScanPathsToExistingInstanceAsync())
                    {
                        System.Diagnostics.Process.GetCurrentProcess().Kill();
                        return;
                    }
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "App", "Failed to communicate with existing instance. Exit.");
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    return;
                }

                StartPipeListener();

                await InitializeLocalizer();
                Services.ContextMenuService.ValidateOnStartup();
                EnsureDefaultStartup();
                InitializeMainWindow();
                ProtectionStatus.RestoreProtections();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Error in OnLaunched: {ex.Message}");
            }
        }

        private static bool TryAcquireSingleInstance()
        {
            try
            {
                _singleInstanceMutex = new Mutex(true, MutexName, out _ownsMutex);
                if (!_ownsMutex)
                {
                    _singleInstanceMutex.Dispose();
                    _singleInstanceMutex = null;
                }
                return _ownsMutex;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Failed to create mutex: {ex.Message}");
                return false;
            }
        }

        private static async Task<bool> SendScanPathsToExistingInstanceAsync()
        {
            List<string> pathsToSend;
            lock (_scanPathLock)
            {
                pathsToSend = [.. _scanTargetPaths];
            }

            if (pathsToSend.Count == 0) return false;

            int retryCount = 0;
            const int maxRetries = 20;
            const int retryDelayMs = 200;

            while (retryCount < maxRetries)
            {
                try
                {
                    using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
                    await client.ConnectAsync(500);
                    using var writer = new StreamWriter(client) { AutoFlush = true };
                    string pathsLine = string.Join(PathSeparator, pathsToSend);
                    await writer.WriteLineAsync(pathsLine);
                    return true;
                }
                catch (Exception)
                {
                    retryCount++;
                    if (retryCount < maxRetries)
                    {
                        await Task.Delay(retryDelayMs);
                    }
                }
            }

            return false;
        }

        private static void StartPipeListener()
        {
            _pipeListenerCts = new CancellationTokenSource();
            var token = _pipeListenerCts.Token;

            _ = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        var server = new NamedPipeServerStream(PipeName, PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                        await server.WaitForConnectionAsync(token);

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                using (server)
                                using (var reader = new StreamReader(server))
                                {
                                    string? pathsLine = await reader.ReadLineAsync();
                                    if (!string.IsNullOrEmpty(pathsLine))
                                    {
                                        string[] paths = pathsLine.Split(PathSeparator, StringSplitOptions.RemoveEmptyEntries);
                                        if (paths.Length > 0)
                                        {
                                            MainWindow?.DispatcherQueue?.TryEnqueue(() =>
                                            {
                                                try
                                                {
                                                    MainWindow?.Activate();
                                                    MainWindow?.TriggerScanForPaths(paths);
                                                }
                                                catch { }
                                            });
                                        }
                                    }
                                }
                            }
                            catch { }
                        }, token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Pipe listener error: {ex.Message}");
                        await Task.Delay(100, token);
                    }
                }
            }, token);
        }

        private static void ParseCommandLineArgs()
        {
            string[] cmdArgs = Environment.GetCommandLineArgs();

            if (cmdArgs.Length <= 1)
            {
                var activatedArgs = AppInstance.GetCurrent().GetActivatedEventArgs();
                if (activatedArgs.Kind == ExtendedActivationKind.Launch)
                {
                    if (activatedArgs.Data is Windows.ApplicationModel.Activation.LaunchActivatedEventArgs launchArgs)
                    {
                        string argStr = launchArgs.Arguments;
                        if (!string.IsNullOrWhiteSpace(argStr))
                        {
                            cmdArgs = argStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        }
                    }
                }
            }

            LogText.AddNewLog(LogText.LogLevel.DEBUG, "App", $"Raw CommandLine: {string.Join(" ", cmdArgs)}");

            var paths = new List<string>();
            for (int i = 1; i < cmdArgs.Length; i++)
            {
                string path = cmdArgs[i].Trim('\"');
                if (!string.IsNullOrWhiteSpace(path) &&
                    (System.IO.File.Exists(path) || System.IO.Directory.Exists(path)))
                {
                    paths.Add(path);
                    LogText.AddNewLog(LogText.LogLevel.INFO, "App", $"Parsed scan path: {path}");
                }
            }

            if (paths.Count > 0)
            {
                SetScanTargetPaths(paths);
            }
        }

        public static bool GetRunOOBE()
        {
            lock (_settingsLock)
            {
                var settings = ApplicationData.Current.LocalSettings;
                if (settings.Values.TryGetValue(RunOOBESettingKey, out var raw) && raw is bool b)
                {
                    return b;
                }
                return true;
            }
        }

        public static void SetRunOOBE(bool value)
        {
            lock (_settingsLock)
            {
                ApplicationData.Current.LocalSettings.Values[RunOOBESettingKey] = value;
            }
        }

        private static void EnsureDefaultStartup()
        {
            try
            {
                if (!StartupService.IsStartupEnabled())
                {
                    StartupService.EnableStartup();
                }
            }
            catch { }
        }

        public static void PlayExitDownFadeAnimation(UIElement uIElement, float verticalOffset = 40f)
        {
            var visual = ElementCompositionPreview.GetElementVisual(uIElement);
            var compositor = visual.Compositor;

            Vector3 startOffset = visual.Offset;
            Vector3 endOffset = startOffset + new Vector3(0, verticalOffset, 0);

            var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));

            var offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
            offsetAnimation.Target = "Offset";
            offsetAnimation.InsertKeyFrame(1.0f, endOffset, easing);
            offsetAnimation.Duration = TimeSpan.FromMilliseconds(400);

            var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
            opacityAnimation.Target = "Opacity";
            opacityAnimation.InsertKeyFrame(1.0f, 0.0f, easing);
            opacityAnimation.Duration = TimeSpan.FromMilliseconds(400);

            visual.StartAnimation("Offset", offsetAnimation);
            visual.StartAnimation("Opacity", opacityAnimation);
        }
        private static void InitializeMainWindow()
        {
            try
            {
                //_ = InterceptWindow.ShowOrActivate(new InterceptWindowHelper.InterceptWindowSetting
                //{
                //    path = "This is a file",
                //    isSucceed = true,
                //});// 测试用的捏（By Shiyi）

                // Initialize sound effects
                var settings = ApplicationData.Current.LocalSettings;
                bool sound = settings.Values.TryGetValue("SoundEffects", out var sr) && sr is bool sb && sb;
                bool spatial = !settings.Values.TryGetValue("SpatialAudio", out var spr) || spr is not bool spb || spb;
                ElementSoundPlayer.State = sound ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
                if (sound) ElementSoundPlayer.SpatialAudioMode = spatial ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;

                MainWindow ??= new MainWindow();
                MainWindow.Activate();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Error initializing MainWindow: {ex.Message}");
            }
        }
        public static ElementTheme Theme { get; set; } = ElementTheme.Default;
        public static bool IsRunAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static async Task InitializeLocalizer()
        {
            string stringsPath = Path.Combine(AppContext.BaseDirectory, "Strings");

            var settings = ApplicationData.Current.LocalSettings;
            string lastLang = settings.Values["AppLanguage"] as string ?? "en-US";

            ApplicationLanguages.PrimaryLanguageOverride = lastLang;
            ILocalizer localizer = await new LocalizerBuilder()
                .AddStringResourcesFolderForLanguageDictionaries(stringsPath)
                .SetOptions(o => o.DefaultLanguage = lastLang)
                .Build();
            await localizer.SetLanguage(lastLang);
        }
        public static string OsName => RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? (Environment.OSVersion.Version.Build >= 22000 ? "Windows 11" : "Windows 10")
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macOS" : "Linux";

        public static string OsVersion => RuntimeInformation.OSDescription;
        public static void PlayEntranceAnimation(UIElement uIElement, string kind, float finalVerticalOffset = 0f, int delayMs = 0)
        {
            var visual = ElementCompositionPreview.GetElementVisual(uIElement);
            var compositor = visual.Compositor;
            const float amplitude = 40f;
            Vector3 directionOffset = kind.ToLowerInvariant() switch
            {
                "left" => new Vector3(-amplitude, 0, 0),
                "right" => new Vector3(amplitude, 0, 0),
                "up" => new Vector3(0, amplitude, 0),
                _ => new Vector3(0, amplitude, 0),
            };
            Vector3 finalOffset = new(0, finalVerticalOffset, 0);

            visual.Opacity = 0;
            visual.Offset = directionOffset + finalOffset;

            var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));
            var delay = TimeSpan.FromMilliseconds(delayMs);

            var offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
            offsetAnimation.Target = "Offset";
            offsetAnimation.InsertKeyFrame(1.0f, finalOffset, easing);
            offsetAnimation.Duration = TimeSpan.FromMilliseconds(400);
            offsetAnimation.DelayTime = delay;

            var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
            opacityAnimation.Target = "Opacity";
            opacityAnimation.InsertKeyFrame(1.0f, 1.0f, easing);
            opacityAnimation.Duration = TimeSpan.FromMilliseconds(400);
            opacityAnimation.DelayTime = delay;

            visual.StartAnimation("Offset", offsetAnimation);
            visual.StartAnimation("Opacity", opacityAnimation);
        }
    }
}
