using Xdows_Security.Services;
using Protection;
using System.Globalization;
using System.Text.RegularExpressions;

if (typeof(LegacyBootProtection).Assembly.GetReferencedAssemblies()
    .Any(assembly => string.Equals(assembly.Name, "System.Management", StringComparison.Ordinal)))
{
    throw new InvalidOperationException("Protection still references System.Management and can recreate the NativeAOT WbemDefPath failure.");
}

string driverProtectionSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "DriverProtection.cs"));
int registerProtectedProcess = driverProtectionSource.IndexOf(
    "_client.RegisterProtectedProcess();",
    StringComparison.Ordinal);
int setBootProtection = driverProtectionSource.IndexOf(
    "_client.SetBootProtection(bootConfiguration);",
    StringComparison.Ordinal);
if (registerProtectedProcess < 0 ||
    setBootProtection < 0 ||
    registerProtectedProcess >= setBootProtection)
{
    throw new InvalidOperationException(
        "The client must register as the protected process before configuring EFI and BCD protection.");
}

string appSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "App.xaml.cs.source"));
int restoreOpenRequest = appSource.IndexOf(
    "window.RestoreAndActivate();",
    StringComparison.Ordinal);
int dispatchScanRequest = appSource.IndexOf(
    "if (request.Kind == SingleInstanceRequestKind.Scan",
    StringComparison.Ordinal);
if (restoreOpenRequest < 0 ||
    dispatchScanRequest < 0 ||
    restoreOpenRequest >= dispatchScanRequest)
{
    throw new InvalidOperationException(
        "Every single-instance request must restore the existing window before optional scan dispatch.");
}

string mainWindowSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "MainWindow.xaml.cs.source"));
int restoreMethodStart = mainWindowSource.IndexOf(
    "public void RestoreAndActivate()",
    StringComparison.Ordinal);
int restoreMethodEnd = restoreMethodStart < 0
    ? -1
    : mainWindowSource.IndexOf(
        "private async void MainWindow_Activated_FirstTime",
        restoreMethodStart,
        StringComparison.Ordinal);
if (restoreMethodStart < 0 || restoreMethodEnd < 0)
    throw new InvalidOperationException("The main-window restore method could not be found.");

string restoreMethod = mainWindowSource[restoreMethodStart..restoreMethodEnd];
string[] requiredRestoreOperations =
[
    "presenter.Restore();",
    "AppWindow.Show(true);",
    "Activate();",
    "SetForegroundWindow(windowHandle)"
];
if (requiredRestoreOperations.Any(operation =>
    !restoreMethod.Contains(operation, StringComparison.Ordinal)))
{
    throw new InvalidOperationException(
        "Restoring the existing instance must restore, show, activate, and foreground its main window.");
}

string settingsPageSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "SettingsPage.xaml.cs.source"));
string settingsPageXaml = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "SettingsPage.xaml.source"));
string applicationProjectSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "Xdows-Security.csproj.source"));
if (settingsPageSource.Contains("MarkdownTextBlock", StringComparison.Ordinal) ||
    settingsPageSource.Contains("MarkdownView", StringComparison.Ordinal) ||
    settingsPageXaml.Contains("MarkdownView", StringComparison.Ordinal) ||
    applicationProjectSource.Contains("WinUI.Markdown", StringComparison.Ordinal) ||
    applicationProjectSource.Contains(
        "CommunityToolkit.WinUI.UI.Controls.Markdown",
        StringComparison.Ordinal))
{
    throw new InvalidOperationException(
        "The NativeAOT update flow must not activate an external WinUI Markdown control.");
}
if (!settingsPageSource.Contains("UpdateMarkdownHtmlRenderer.RenderDocument", StringComparison.Ordinal) ||
    !settingsPageSource.Contains("WebView2 webView = new()", StringComparison.Ordinal) ||
    !settingsPageSource.Contains("webView.NavigateToString(markdownDocument)", StringComparison.Ordinal) ||
    !applicationProjectSource.Contains(
        "PackageReference Include=\"Markdig\"",
        StringComparison.Ordinal))
{
    throw new InvalidOperationException(
        "The update flow must render release notes with the Markdig NuGet renderer inside the built-in WebView2 control.");
}

string renderedMarkdown = UpdateMarkdownHtmlRenderer.RenderDocument(
    "# Release notes\n\n**Fixed** update checks.\n\n| Area | State |\n| --- | --- |\n| UI | Done |\n\n<script>alert('no')</script>",
    useDarkTheme: true);
if (!renderedMarkdown.Contains(">Release notes</h1>", StringComparison.Ordinal) ||
    !renderedMarkdown.Contains("<strong>Fixed</strong>", StringComparison.Ordinal) ||
    !renderedMarkdown.Contains("<table>", StringComparison.Ordinal) ||
    !renderedMarkdown.Contains("color-scheme: dark", StringComparison.Ordinal) ||
    renderedMarkdown.Contains("<script>", StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        "The Markdig update renderer must produce styled Markdown HTML while disabling embedded raw HTML.");
}

string managedProtocolSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "DriverProtocol.cs.source"));
string bridgeClientSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "DriverBridgeClient.cs.source"));
string nativeProtocolSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "DriverPublic.h.source"));
string driverInfSource = await File.ReadAllTextAsync(
    Path.Combine(AppContext.BaseDirectory, "Xdows-Security-Driver.inf.source"));

Match managedBuildMatch = Regex.Match(
    managedProtocolSource,
    @"DriverBuildId\s*=\s*(\d+)");
Match nativeBuildMatch = Regex.Match(
    nativeProtocolSource,
    @"XDOWS_SECURITY_DRIVER_BUILD_ID\s+(\d+)ULL");
Match previousBuildMatch = Regex.Match(
    managedProtocolSource,
    @"PreviousDriverBuildId\s*=\s*(\d+)");
if (!managedBuildMatch.Success ||
    !nativeBuildMatch.Success ||
    !previousBuildMatch.Success)
{
    throw new InvalidOperationException(
        "The current and previous main-driver build identities must be declared explicitly.");
}

ulong managedBuild = ulong.Parse(managedBuildMatch.Groups[1].Value, CultureInfo.InvariantCulture);
ulong nativeBuild = ulong.Parse(nativeBuildMatch.Groups[1].Value, CultureInfo.InvariantCulture);
ulong previousBuild = ulong.Parse(previousBuildMatch.Groups[1].Value, CultureInfo.InvariantCulture);
if (managedBuild != nativeBuild || previousBuild == managedBuild)
{
    throw new InvalidOperationException(
        "Managed/native driver build IDs must match, and the previous build ID must remain distinct.");
}

if (!Regex.IsMatch(
        bridgeClientSource,
        @"new\s*\(\s*DriverProtocol\.ProtocolVersion\s*,\s*\[\s*DriverProtocol\.PreviousDriverBuildId",
        RegexOptions.Singleline))
{
    throw new InvalidOperationException(
        "The previous same-protocol driver build must be authorized for an in-place upgrade.");
}

if (!Regex.IsMatch(
        bridgeClientSource,
        @"TryAuthorizeUpgradeSourceShutdown[\s\S]*?source\.ProtocolVersion\s*==\s*DriverProtocol\.ProtocolVersion[\s\S]*?DriverProtocol\.RegisterProtectedProcess[\s\S]*?DriverProtocol\.AuthorizedShutdown"))
{
    throw new InvalidOperationException(
        "A same-protocol upgrade must register its client for self-protection before requesting authorized shutdown.");
}

Match driverVerMatch = Regex.Match(
    driverInfSource,
    @"DriverVer\s*=\s*(\d{2}/\d{2}/\d{4}),");
string buildDateText = managedBuild.ToString(CultureInfo.InvariantCulture)[..8];
if (!driverVerMatch.Success ||
    !DateOnly.TryParseExact(
        driverVerMatch.Groups[1].Value,
        "MM/dd/yyyy",
        CultureInfo.InvariantCulture,
        DateTimeStyles.None,
        out DateOnly driverVersionDate) ||
    !DateOnly.TryParseExact(
        buildDateText,
        "yyyyMMdd",
        CultureInfo.InvariantCulture,
        DateTimeStyles.None,
        out DateOnly buildDate) ||
    driverVersionDate < buildDate)
{
    throw new InvalidOperationException(
        "The INF DriverVer date must identify the current driver build so Driver Store replaces stale packages.");
}

SingleInstanceRequest openRequest = SingleInstanceProtocol.Create([]);
if (openRequest.Kind != SingleInstanceRequestKind.Open || openRequest.Paths.Count != 0)
    throw new InvalidOperationException("A parameterless second launch must create an open request.");

string[] scanPaths = [@"C:\Program Files\Xdows Security\sample.exe", @"D:\Samples\folder"];
SingleInstanceRequest scanRequest = SingleInstanceProtocol.Create(scanPaths);
using var writer = new StringWriter();
await SingleInstanceProtocol.WriteAsync(writer, scanRequest);
using var reader = new StringReader(writer.ToString());
SingleInstanceRequest decoded = await SingleInstanceProtocol.ReadAsync(reader)
    ?? throw new InvalidOperationException("The scan request did not round-trip.");
if (decoded.Kind != SingleInstanceRequestKind.Scan || !decoded.Paths.SequenceEqual(scanPaths))
    throw new InvalidOperationException("The scan request changed during IPC serialization.");

using var openWriter = new StringWriter();
await SingleInstanceProtocol.WriteAsync(openWriter, openRequest);
using var openReader = new StringReader(openWriter.ToString());
SingleInstanceRequest decodedOpen = await SingleInstanceProtocol.ReadAsync(openReader)
    ?? throw new InvalidOperationException("The open request did not round-trip.");
if (decodedOpen.Kind != SingleInstanceRequestKind.Open || decodedOpen.Paths.Count != 0)
    throw new InvalidOperationException("The open request changed during IPC serialization.");

Console.WriteLine("PASS: parameterless launches and scan-path launches have distinct IPC requests.");
Console.WriteLine("PASS: every second launch restores and foregrounds the existing window.");
Console.WriteLine("PASS: the NativeAOT update flow uses Markdig and the built-in WebView2 control without an external WinUI Markdown control.");
Console.WriteLine("PASS: Protection no longer depends on System.Management.");
Console.WriteLine("PASS: self-protection registration precedes EFI and BCD configuration.");
Console.WriteLine("PASS: driver build identity forces stale same-protocol packages through the upgrade path.");
