using Microsoft.Windows.Storage;
using Helper;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Settings;
using Microsoft.Windows.AppLifecycle;
using Microsoft.Windows.Globalization;
using Microsoft.Win32.SafeHandles;
using Protection;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using WinUI3Localizer;
using Xdows_Security.Services;
using Xdows_Security.Views;
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
        // GitHub API 走 HTTPS，更新检查频率低（每次启动一次），连接可保持较久生命周期
        // - PooledConnectionLifetime: 5 分钟，平衡 DNS 缓存与连接复用
        // - MaxConnectionsPerServer: 4 足够单次更新检查
        // - AutomaticDecompression: GitHub API 默认 gzip 压缩响应，开启自动解压
        // - DefaultRequestVersion: HTTP/2，TLS ALPN 自动协商升级，GitHub API 已支持
        private static readonly HttpClient _httpClient = BuildUpdaterHttpClient();

        private static HttpClient BuildUpdaterHttpClient()
        {
            SocketsHttpHandler handler = new()
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                MaxConnectionsPerServer = 4,
                AutomaticDecompression = System.Net.DecompressionMethods.All
            };
            return new HttpClient(handler) { DefaultRequestVersion = HttpVersion.Version20 };
        }

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
            return IsRun(0) || IsRun(1) || IsRun(2) || IsRun(4) || IsRun(5);
        }

        private static readonly InterceptCallBack interceptCallBack = interceptEvent =>
        {
            LogText.AddNewLog(LogText.LogLevel.WARN, "Protection", interceptEvent.IsSucceed
                ? $"Intercepted：{interceptEvent.Path}"
                : $"Could not intercept：{interceptEvent.Path}");
            _ = ShowProcessedThreatNotificationAsync(new InterceptWindowHelper.InterceptWindowSetting
            {
                Path = interceptEvent.Path,
                IsSucceed = interceptEvent.IsSucceed,
                InterceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.RestoreOrTrust,
                DetectionName = interceptEvent.DetectionName,
                Probability = interceptEvent.Probability,
                Module = interceptEvent.Module,
                Backend = interceptEvent.Backend
            });
        };
        private static readonly IProtectionModel LegacyProcessProtection = new LegacyProcessProtection();
        private static readonly IProtectionModel LegacyFilesProtection = new LegacyFilesProtection();
        private static readonly LegacyBootProtection LegacyBootProtection = CreateLegacyBootProtection();
        private static readonly LegacyRegistryProtection LegacyRegistryProtection = CreateLegacyRegistryProtection();
        private static readonly SemaphoreSlim BootDecisionDialogGate = new(1, 1);

        private static readonly DriverProtection DriverProtection = CreateDriverProtection();

        private static LegacyBootProtection CreateLegacyBootProtection()
        {
            String baselineDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Xdows-Software",
                "Xdows-Security",
                "BootProtection");
            return new LegacyBootProtection(baselineDirectory)
            {
                DecisionCallback = BootProtectionDecisionCallbackAsync,
                LogCallback = message => LogText.AddNewLog(
                    LogText.LogLevel.INFO,
                    "R3BootProtection",
                    message)
            };
        }

        private static DriverProtection CreateDriverProtection()
        {
            DriverProtection protection = new()
            {
                DecisionCallback = DriverDecisionCallbackAsync,
                LogCallback = DriverLogCallback,
                StartupProtectionStateProvider = StartupService.IsStartupEnabled
            };
            ApplyDriverProtectionModelMode(protection);
            return protection;
        }

        private static LegacyRegistryProtection CreateLegacyRegistryProtection()
        {
            return new LegacyRegistryProtection
            {
                DecisionCallback = DriverDecisionCallbackAsync,
                OptionsProvider = GetRegistryProtectionOptions,
                LogCallback = message => LogText.AddNewLog(
                    LogText.LogLevel.INFO,
                    "R3RegistryProtection",
                    message)
            };
        }

        private static Xdows_Local.RegistryProtectionOptions GetRegistryProtectionOptions()
        {
            var settings = App.LocalSettings;
            Boolean includeSecondary = !settings.Values.TryGetValue(
                "RegistryProtectionSecondary",
                out Object? secondaryRaw) || secondaryRaw is not Boolean secondary || secondary;
            Boolean includeOther = settings.Values.TryGetValue(
                "RegistryProtectionOther",
                out Object? otherRaw) && otherRaw is Boolean other && other;
            return new Xdows_Local.RegistryProtectionOptions(includeSecondary, includeOther);
        }

        /// <summary>
        /// 璇诲彇 UI 璁剧疆鐨勬壂鎻忔ā寮忓苟搴旂敤鍒伴┍鍔ㄩ槻鎶ゃ€傚綋鐢ㄦ埛寮€鍚?灏嗘壂鎻忔ā寮忓簲鐢ㄥ埌闃叉姢"鏃讹紝
        /// 浣跨敤 UI 閫夋嫨鐨勬ā鍨嬫ā寮?Flash/Pro/Standard)锛涘惁鍒欎繚鎸侀粯璁?Standard銆?        /// </summary>
        private static void ApplyDriverProtectionModelMode(DriverProtection protection)
        {
            try
            {
                var settings = App.LocalSettings;

                if (settings.Values.TryGetValue("ModelModeForProtection", out var mfpRaw) &&
                    mfpRaw is bool mfpOn && mfpOn)
                {
                    string modeStr = settings.Values.TryGetValue("ModelMode", out var modeRaw) && modeRaw is string ms
                        ? ms : "Standard";
                    protection.ModelMode = modeStr switch
                    {
                        "Flash" => NativeModelScannerMode.Flash,
                        "Adaptive" => NativeModelScannerMode.Adaptive,
                        "Pro" => NativeModelScannerMode.Pro,
                        _ => NativeModelScannerMode.Standard
                    };
                }
            }
            catch
            {
                // 璁剧疆璇诲彇澶辫触鏃朵繚鎸侀粯璁?Standard
            }
        }

        private static void DriverLogCallback(DriverProtectionLogEntry entry)
        {
            LogText.LogLevel level = entry.Severity switch
            {
                DriverProtectionLogSeverity.Debug => LogText.LogLevel.DEBUG,
                DriverProtectionLogSeverity.Info => LogText.LogLevel.INFO,
                DriverProtectionLogSeverity.Warning => LogText.LogLevel.WARN,
                DriverProtectionLogSeverity.Error => LogText.LogLevel.ERROR,
                DriverProtectionLogSeverity.Fatal => LogText.LogLevel.FATAL,
                _ => LogText.LogLevel.INFO
            };

            string module = string.IsNullOrWhiteSpace(entry.Module) ? "Driver" : entry.Module;
            string message = $"eventId:{entry.EventId} correlationId:{entry.CorrelationId} dropped:{entry.DroppedCount} driverTime:{entry.Timestamp:O} {entry.Message}";
            LogText.AddNewLog(level, $"Driver/{module}", message);
        }

        private static async Task<ProtectionUserDecision> DriverDecisionCallbackAsync(ProtectionDecisionRequest request, CancellationToken token)
        {
            LogText.AddNewLog(
                LogText.LogLevel.WARN,
                "DriverProtection",
                $"Threat intercepted: {request.ProtectionType} {request.Path} ({request.DetectionName}, {request.Probability:F2}%, cid:{request.CorrelationId})");

            if (App.MainWindow?.DispatcherQueue is null)
                return ProtectionUserDecision.Block;

            if (request.Module is not Helper.ProtectionModule.Behavior and
                not Helper.ProtectionModule.Boot and
                not Helper.ProtectionModule.Registry &&
                await ThreatNotificationModeService.ShouldUseCompactAsync().ConfigureAwait(false))
            {
                bool compactNotificationQueued = App.MainWindow.DispatcherQueue.TryEnqueue(() =>
                {
                    SmallThreatNotificationWindow.ShowOrUpdate(new InterceptWindowHelper.InterceptWindowSetting
                    {
                        Path = request.Path,
                        IsSucceed = true,
                        InterceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.ReminderOnly,
                        ProtectionType = request.ProtectionType,
                        DetectionName = request.DetectionName,
                        Probability = request.Probability,
                        ActorPath = request.ActorPath,
                        ActorTrust = request.ActorTrust,
                        ActorDetectionName = request.ActorDetectionName,
                        ActorProbability = request.ActorProbability,
                        CommandLine = request.CommandLine,
                        CorrelationId = request.CorrelationId,
                        Module = request.Module,
                        Backend = request.Backend
                    });
                });

                LogText.AddNewLog(
                    compactNotificationQueued ? LogText.LogLevel.INFO : LogText.LogLevel.WARN,
                    "DriverProtection",
                    compactNotificationQueued
                        ? $"Threat automatically blocked with compact notification cid:{request.CorrelationId}"
                        : $"Threat automatically blocked; compact notification queue unavailable cid:{request.CorrelationId}");
                return ProtectionUserDecision.Block;
            }

            TaskCompletionSource<ProtectionUserDecision> tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            using CancellationTokenRegistration registration = token.Register(() => tcs.TrySetResult(ProtectionUserDecision.Timeout));

            bool queued = App.MainWindow.DispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    string button = await InterceptWindow.ShowOrActivate(new InterceptWindowHelper.InterceptWindowSetting
                    {
                        Path = request.Path,
                        IsSucceed = true,
                        InterceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.InterceptOrRelease,
                        ProtectionType = request.ProtectionType,
                        DetectionName = request.DetectionName,
                        Probability = request.Probability,
                        ActorPath = request.ActorPath,
                        ActorTrust = request.ActorTrust,
                        ActorDetectionName = request.ActorDetectionName,
                        ActorProbability = request.ActorProbability,
                        CommandLine = request.CommandLine,
                        CorrelationId = request.CorrelationId,
                        Module = request.Module,
                        Backend = request.Backend,
                        DecisionDeadline = request.DecisionDeadline
                    }, token);

                    ProtectionUserDecision userDecision = button switch
                    {
                        "Release" => ProtectionUserDecision.Allow,
                        "Timeout" => ProtectionUserDecision.Timeout,
                        _ => ProtectionUserDecision.Block
                    };
                    bool submitted = tcs.TrySetResult(userDecision);
                    if (userDecision == ProtectionUserDecision.Timeout)
                    {
                        LogText.AddNewLog(
                            LogText.LogLevel.WARN,
                            "DriverProtection",
                            $"user-decision-timeout-blocked eventId:{request.EventId} cid:{request.CorrelationId} module:{request.Module} path:{request.Path}");
                    }
                    else if (submitted)
                    {
                        LogText.AddNewLog(
                            LogText.LogLevel.INFO,
                            "DriverProtection",
                            $"User decision submitted: {userDecision} cid:{request.CorrelationId}");
                    }
                }
                catch
                {
                    tcs.TrySetResult(ProtectionUserDecision.Block);
                }
            });

            if (!queued)
                return ProtectionUserDecision.Block;

            return await tcs.Task;
        }

        private static async Task<BootProtectionUserDecision> BootProtectionDecisionCallbackAsync(
            BootProtectionDecisionRequest request,
            CancellationToken token)
        {
            if (App.MainWindow?.DispatcherQueue is null)
                return BootProtectionUserDecision.KeepRepair;

            var completion = new TaskCompletionSource<BootProtectionUserDecision>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            using CancellationTokenRegistration registration = token.Register(
                () => completion.TrySetResult(BootProtectionUserDecision.KeepRepair));

            Boolean queued = App.MainWindow.DispatcherQueue.TryEnqueue(async () =>
            {
                Boolean gateEntered = false;
                try
                {
                    await BootDecisionDialogGate.WaitAsync(token);
                    gateEntered = true;

                    String title = Localizer.Get().GetLocalizedString(
                        "SettingsPage_Protection_Boot_Detection_Title");
                    String disk = String.IsNullOrWhiteSpace(request.DiskModel)
                        ? $"PhysicalDrive{request.DiskIndex}"
                        : $"PhysicalDrive{request.DiskIndex} - {request.DiskModel}";
                    String changedItems = String.Join(
                        Environment.NewLine,
                        request.ChangedItems.Select(item => $"• {item}"));
                    String messageKey = request.RepairSucceeded
                        ? "SettingsPage_Protection_Boot_Detection_Repaired_Message"
                        : "SettingsPage_Protection_Boot_Detection_RepairFailed_Message";
                    String messageFormat = Localizer.Get().GetLocalizedString(messageKey);
                    String message = String.Format(
                        System.Globalization.CultureInfo.CurrentCulture,
                        messageFormat,
                        disk,
                        changedItems);

                    var content = new TextBlock
                    {
                        Text = message,
                        TextWrapping = TextWrapping.Wrap,
                        MaxWidth = 560
                    };
                    var dialog = new ContentDialog
                    {
                        XamlRoot = App.MainWindow.Content.XamlRoot,
                        Style = Application.Current.Resources["DefaultContentDialogStyle"] as Style,
                        Title = title,
                        Content = content,
                        PrimaryButtonText = Localizer.Get().GetLocalizedString(
                            "SettingsPage_Protection_Boot_Detection_KeepRepair"),
                        CloseButtonText = Localizer.Get().GetLocalizedString(
                            "SettingsPage_Protection_Boot_Dialog_Close"),
                        DefaultButton = ContentDialogButton.Primary
                    };
                    AutomationProperties.SetAutomationId(dialog, "BootProtectionDecisionDialog");
                    AutomationProperties.SetName(dialog, title);

                    if (request.RepairSucceeded)
                    {
                        dialog.SecondaryButtonText = Localizer.Get().GetLocalizedString(
                            "SettingsPage_Protection_Boot_Detection_AllowChange");
                    }

                    ContentDialogResult result = await dialog.ShowAsync();
                    completion.TrySetResult(
                        result == ContentDialogResult.Secondary && request.RepairSucceeded
                            ? BootProtectionUserDecision.AllowChange
                            : BootProtectionUserDecision.KeepRepair);
                }
                catch (OperationCanceledException)
                {
                    completion.TrySetResult(BootProtectionUserDecision.KeepRepair);
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(
                        LogText.LogLevel.ERROR,
                        "R3BootProtection",
                        $"Failed to show the boot decision dialog: {ex.Message}");
                    completion.TrySetResult(BootProtectionUserDecision.KeepRepair);
                }
                finally
                {
                    if (gateEntered)
                        BootDecisionDialogGate.Release();
                }
            });

            if (!queued)
                return BootProtectionUserDecision.KeepRepair;

            return await completion.Task.ConfigureAwait(false);
        }

        private static async Task ShowProcessedThreatNotificationAsync(InterceptWindowHelper.InterceptWindowSetting setting)
        {
            try
            {
                bool useCompact = await ThreatNotificationModeService.ShouldUseCompactAsync().ConfigureAwait(false);
                App.MainWindow?.DispatcherQueue?.TryEnqueue(() =>
                {
                    if (useCompact)
                        SmallThreatNotificationWindow.ShowOrUpdate(setting);
                    else
                        _ = InterceptWindow.ShowOrActivate(setting);
                });
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "Protection", $"Failed to show threat notification: {ex.Message}");
            }
        }

        public static bool Run(int RunID)
        {
            IProtectionModel? protection = RunIdToProtection(RunID);

            if (protection is null) { return false; }

            // Refresh ModelMode from settings before each start
            if (protection is DriverProtection driverProt)
            {
                ApplyDriverProtectionModelMode(driverProt);
            }

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
            App.LocalSettings.Values[$"Protection_Enabled_{runId}"] = enabled;
        }

        public static void RestoreProtections()
        {
            RestoreDriverProtection();
            RestoreLegacyProtections();
        }

        public static void RestoreDriverProtection()
        {
            RestoreProtection(5);
        }

        public static void RestoreLegacyProtections()
        {
            if (!IsRun(5))
            {
                RestoreProtection(0);
                RestoreProtection(1);
                RestoreProtection(2);
                RestoreProtection(4);
            }
        }

        public static BootProtectionPreparation InspectBootProtectionPreparation()
        {
            return LegacyBootProtection.InspectPreparation();
        }

        public static void CreateBootProtectionBaseline()
        {
            LegacyBootProtection.CreateTrustedBaseline();
        }

        private static void RestoreProtection(int runId)
        {
            try
            {
                var settings = App.LocalSettings;
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

        public static void PrepareVoluntaryExit()
        {
            DriverProtection.TrySetVoluntaryExit(true);
        }

        public static bool SynchronizeStartupProtection(bool enabled)
        {
            return DriverProtection.TrySetStartupProtection(enabled);
        }

        public static IReadOnlyList<DriverProcessInfo> GetDriverProcesses()
        {
            return DriverProtection.GetProcesses();
        }

        public static void OperateDriverProcess(uint processId, DriverProcessOperation operation)
        {
            DriverProtection.OperateProcess(processId, operation);
        }

        public static string GetDriverStatusKey()
        {
            if (DriverProtection.IsRun())
                return "SettingsPage_Protection_Driver_Status_Protected";

            return DriverProtection.QueryRuntimeStatus() switch
            {
                DriverProtectionRuntimeStatus.NotInstalled => "SettingsPage_Protection_Driver_Status_NotInstalled",
                DriverProtectionRuntimeStatus.NotRunning => "SettingsPage_Protection_Driver_Status_NotRunning",
                DriverProtectionRuntimeStatus.Loading => "SettingsPage_Protection_Driver_Status_Loading",
                DriverProtectionRuntimeStatus.Protected => "SettingsPage_Protection_Driver_Status_Protected",
                DriverProtectionRuntimeStatus.NeedsRepair => "SettingsPage_Protection_Driver_Status_NeedsRepair",
                _ => "SettingsPage_Protection_Driver_Status_Error"
            };
        }

        private static IProtectionModel? RunIdToProtection(int RunID)
        {
            IProtectionModel? protection = RunID switch
            {
                0 => LegacyProcessProtection,
                1 => LegacyFilesProtection,
                2 => LegacyBootProtection,
                4 => LegacyRegistryProtection,
                5 => DriverProtection,
                _ => null,
            };
            if (protection is null) { return null; }
            return protection;
        }
    }

    public static class Statistics
    {
        internal static int ScansQuantity = 0;
        internal static int VirusQuantity = 0;
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

        // 缓存 ApplicationData 与 LocalSettings，避免每次访问都做路径解析与容器查找
        // 使用 PublicationOnly 模式：失败不缓存异常，允许下次访问重试，避免单次瞬时失败导致永久不可用
        private static readonly Lazy<ApplicationData> _appDataLazy = new(
            () => ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security"),
            LazyThreadSafetyMode.PublicationOnly);
        public static ApplicationData AppData => _appDataLazy.Value;
        public static ApplicationDataContainer LocalSettings => AppData.LocalSettings;

        private static List<string> _scanTargetPaths = [];
        private static readonly Lock _scanPathLock = new();

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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(
            SafePipeHandle pipe,
            out uint serverProcessId);

        [DllImport("user32.dll")]
        private static extern bool AllowSetForegroundWindow(uint processId);

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
            EnableXamlOptionalChanges();
            this.InitializeComponent();
        }

        /// <summary>
        /// 启用 Windows App SDK 2.3.1 引入的可选 XAML 性能优化。
        /// 必须在 InitializeComponent（XAML 初始化）之前调用，否则不会生效。
        /// </summary>
        private static void EnableXamlOptionalChanges()
        {
            // 以下优化需通过 XamlOptionalChanges API 显式选择启用（见 2.3.1 发行说明）：
            //  - DefaultStyleOptimizations: 优化 XamlControlsResources 样式，含 ScrollBar 模板
            //  - IconNoGridOptimization: FontIcon/BitmapIcon 不再插入额外 Grid
            //  - OptimizeApplyStyles: 跳过不应用值的样式设置器，并延迟应用样式到元素入树后
            //  - DeferContextFlyoutInit: 延迟 TextBlock/RichTextBlock 默认 ContextFlyout 初始化
            XamlChangeId[] changes =
            [
                XamlChangeId.DefaultStyleOptimizations,
                XamlChangeId.IconNoGridOptimization,
                XamlChangeId.OptimizeApplyStyles,
                XamlChangeId.DeferContextFlyoutInit
            ];

            foreach (XamlChangeId change in changes)
            {
                try
                {
                    XamlOptionalChanges.EnableChange(change);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Failed to enable XamlChangeId {change}: {ex.Message}");
                }
            }
        }
        protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                ParseCommandLineArgs();

                if (ProcessManagerView.TryRunDebugKillOnExitHelper(Environment.GetCommandLineArgs()))
                    return;

                if (!TryAcquireSingleInstance())
                {
                    // 即使主进程还没完全启动监听，SendRequestToExistingInstanceAsync 内部的重试机制也会等待。
                    if (await SendRequestToExistingInstanceAsync())
                    {
                        System.Diagnostics.Process.GetCurrentProcess().Kill();
                        return;
                    }
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "App", "Failed to communicate with existing instance. Exit.");
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    return;
                }

                StartPipeListener();
                // 单实例确认后立即恢复驱动防护，避免本地化和启动项检查期间出现驱动桥接空档。
                Task restoreDriverProtectionTask = Task.Run(() =>
                {
                    try
                    {
                        ProtectionStatus.RestoreDriverProtection();
                    }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Async restore driver protection failed: {ex.Message}");
                    }
                });

                await InitializeLocalizer();
                // 并行执行注册表/启动项检查，避免串行 IO 等待
                await Task.WhenAll(
                    Task.Run(() => Services.ContextMenuService.ValidateOnStartup()),
                    Task.Run(() => EnsureDefaultStartup())
                );
                InitializeMainWindow();

                // 兼容防护会初始化用户态模型，等待窗口和启动资源就绪后再恢复。
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await restoreDriverProtectionTask.ConfigureAwait(false);
                        ProtectionStatus.RestoreLegacyProtections();
                    }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Async restore legacy protections failed: {ex.Message}");
                    }
                });
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

        private static async Task<bool> SendRequestToExistingInstanceAsync()
        {
            List<string> pathsToSend;
            lock (_scanPathLock)
            {
                pathsToSend = [.. _scanTargetPaths];
            }
            SingleInstanceRequest request = SingleInstanceProtocol.Create(pathsToSend);

            int retryCount = 0;
            const int maxRetries = 20;
            const int retryDelayMs = 200;

            while (retryCount < maxRetries)
            {
                try
                {
                    using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
                    await client.ConnectAsync(500);
                    if (GetNamedPipeServerProcessId(client.SafePipeHandle, out uint serverProcessId))
                        _ = AllowSetForegroundWindow(serverProcessId);
                    using var writer = new StreamWriter(client) { AutoFlush = true };
                    await SingleInstanceProtocol.WriteAsync(writer, request);
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
                                    SingleInstanceRequest? request = await SingleInstanceProtocol.ReadAsync(reader, token);
                                    if (request is not null)
                                    {
                                        await DispatchSingleInstanceRequestAsync(request, token);
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

        private static async Task DispatchSingleInstanceRequestAsync(
            SingleInstanceRequest request,
            CancellationToken token)
        {
            MainWindow? window = MainWindow;
            while (window is null)
            {
                await Task.Delay(50, token);
                window = MainWindow;
            }

            bool enqueued = window.DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    window.RestoreAndActivate();
                    if (request.Kind == SingleInstanceRequestKind.Scan && request.Paths.Count != 0)
                        window.TriggerScanForPaths(request.Paths);
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Single-instance request failed: {ex.Message}");
                }
            });
            if (!enqueued)
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", "Failed to dispatch single-instance request to the main window.");
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
                var settings = App.LocalSettings;
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
                App.LocalSettings.Values[RunOOBESettingKey] = value;
            }
        }

        private static void EnsureDefaultStartup()
        {
            try
            {
                StartupService.EnsureCurrentStartupCommand();
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
                //    Path = "This is a file",
                //    IsSucceed = true,
                //});// 测试用的捏（By Shiyi）

                // Initialize sound effects
                var settings = App.LocalSettings;
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

            var settings = App.LocalSettings;
            string lastLang = settings.Values.TryGetValue("AppLanguage", out object? rawLanguage) && rawLanguage is string language
                ? language
                : "en-US";

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
            const float amplitude = 40f;
            Vector3 directionOffset = kind.ToLowerInvariant() switch
            {
                "left" => new Vector3(-amplitude, 0, 0),
                "right" => new Vector3(amplitude, 0, 0),
                "fade" => Vector3.Zero,
                "up" => new Vector3(0, amplitude, 0),
                _ => new Vector3(0, amplitude, 0),
            };

            var transform = uIElement.RenderTransform as Microsoft.UI.Xaml.Media.TranslateTransform;
            if (transform == null)
            {
                transform = new Microsoft.UI.Xaml.Media.TranslateTransform();
                uIElement.RenderTransform = transform;
            }

            double finalY = finalVerticalOffset;
            double startX = directionOffset.X;
            double startY = directionOffset.Y + finalY;
            transform.X = startX;
            transform.Y = startY;
            uIElement.Opacity = 0;

            var easing = new CubicEase { EasingMode = EasingMode.EaseOut };
            var duration = new Duration(TimeSpan.FromMilliseconds(400));
            var beginTime = TimeSpan.FromMilliseconds(delayMs);
            var storyboard = new Storyboard();

            var xAnimation = new DoubleAnimation
            {
                From = startX,
                To = 0,
                Duration = duration,
                BeginTime = beginTime,
                EasingFunction = easing
            };
            Storyboard.SetTarget(xAnimation, transform);
            Storyboard.SetTargetProperty(xAnimation, nameof(Microsoft.UI.Xaml.Media.TranslateTransform.X));

            var yAnimation = new DoubleAnimation
            {
                From = startY,
                To = finalY,
                Duration = duration,
                BeginTime = beginTime,
                EasingFunction = easing
            };
            Storyboard.SetTarget(yAnimation, transform);
            Storyboard.SetTargetProperty(yAnimation, nameof(Microsoft.UI.Xaml.Media.TranslateTransform.Y));

            var opacityAnimation = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = duration,
                BeginTime = beginTime,
                EasingFunction = easing
            };
            Storyboard.SetTarget(opacityAnimation, uIElement);
            Storyboard.SetTargetProperty(opacityAnimation, nameof(UIElement.Opacity));

            storyboard.Children.Add(xAnimation);
            storyboard.Children.Add(yAnimation);
            storyboard.Children.Add(opacityAnimation);
            storyboard.Completed += (_, _) =>
            {
                transform.X = 0;
                transform.Y = finalY;
                uIElement.Opacity = 1.0;
            };
            storyboard.Begin();
        }

        /// <summary>
        /// 重置元素的视觉状态，停止所有正在运行的入场动画。
        /// 仅停止动画并重置 Opacity，不修改 Offset；下次显示时由布局系统重新设置位置。
        /// </summary>
        public static void ResetElementVisualState(UIElement uIElement)
        {
            var visual = ElementCompositionPreview.GetElementVisual(uIElement);
            visual.StopAnimation("Offset");
            visual.StopAnimation("Opacity");
            visual.Opacity = 1.0f;
            uIElement.Opacity = 1.0;

            if (uIElement.RenderTransform is Microsoft.UI.Xaml.Media.TranslateTransform transform)
            {
                transform.X = 0;
                transform.Y = 0;
            }
        }

        public static NavigationTransitionInfo GetNavigationTransitionInfo()
        {
            var settings = App.LocalSettings;
            string transitionType = settings.Values.TryGetValue("PageTransition", out var raw) && raw is string s ? s : "Default";

            return transitionType switch
            {
                "Entrance" => new EntranceNavigationTransitionInfo(),
                "DrillIn" => new DrillInNavigationTransitionInfo(),
                "Suppress" => new SuppressNavigationTransitionInfo(),
                "SlideFromRight" => new SlideNavigationTransitionInfo { Effect = SlideNavigationTransitionEffect.FromRight },
                "SlideFromLeft" => new SlideNavigationTransitionInfo { Effect = SlideNavigationTransitionEffect.FromLeft },
                "Continuum" => new ContinuumNavigationTransitionInfo(),
                _ => new EntranceNavigationTransitionInfo()
            };
        }
    }
}
