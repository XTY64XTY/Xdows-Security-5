using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Xdows_Local;

const string testParent = @"SOFTWARE\Xdows-Security\Tests";
const string testPath = testParent + @"\RegistryProtection";

Assert(
    RegistryScan.Scan(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Sample") == RegistryScan.DetectionName,
    "native HKLM primary rule");
Assert(
    RegistryScan.Scan(@"\REGISTRY\USER\S-1-5-21-1\SOFTWARE\Classes\ms-settings\Shell\Open\command") == RegistryScan.DetectionName,
    "native HKCU primary rule");
Assert(
    RegistryScan.Scan(
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MMC",
        new RegistryProtectionOptions(false, false)) == string.Empty,
    "secondary disabled");
Assert(
    RegistryScan.Scan(
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MMC",
        RegistryProtectionOptions.Recommended) == RegistryScan.DetectionName,
    "secondary recommended");
Assert(
    RegistryScan.Scan(
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        RegistryProtectionOptions.Recommended) == string.Empty,
    "other disabled by default");
Assert(
    RegistryScan.Scan(
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        RegistryProtectionOptions.All) == RegistryScan.DetectionName,
    "other enabled");
Assert(
    RegistryScan.Scan(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Runaway") == string.Empty,
    "rule path boundary");
Assert(
    RegistryScan.Scan($@"HKEY_CURRENT_USER\{RegistryScan.DiagnosticTestPath}") == RegistryScan.DetectionName,
    "diagnostic test rule");

try
{
    Registry.CurrentUser.DeleteSubKeyTree(testParent, throwOnMissingSubKey: false);
    using RegistryKey testKey = Registry.CurrentUser.CreateSubKey(testPath, writable: true)
        ?? throw new InvalidOperationException("Unable to create the HKCU registry protection test key.");
    testKey.SetValue("Lifecycle", "created", RegistryValueKind.String);
    testKey.SetValue("Lifecycle", "modified", RegistryValueKind.String);
    testKey.SetValue("Duplicate", 1, RegistryValueKind.DWord);
    testKey.SetValue("Duplicate", 1, RegistryValueKind.DWord);
    testKey.DeleteValue("Duplicate", throwOnMissingValue: true);

    using (RegistryKey before = testKey.CreateSubKey("Before", writable: true))
        before.SetValue("Value", "rename", RegistryValueKind.String);
    int renameStatus = RegRenameKey(testKey.Handle.DangerousGetHandle(), "Before", "After");
    Assert(renameStatus == 0, $"RegRenameKey status {renameStatus}");
    Assert(testKey.OpenSubKey("After") is not null, "renamed subkey exists");

    using var child = Process.Start(new ProcessStartInfo
    {
        FileName = "reg.exe",
        Arguments = $"add HKCU\\{testPath} /v ChildProcess /t REG_SZ /d exited /f",
        CreateNoWindow = true,
        UseShellExecute = false
    }) ?? throw new InvalidOperationException("Unable to start the registry test child process.");
    child.WaitForExit();
    Assert(child.ExitCode == 0, $"registry test child exit code {child.ExitCode}");
    Assert((string?)testKey.GetValue("ChildProcess") == "exited", "child process write");
}
finally
{
    Registry.CurrentUser.DeleteSubKeyTree(testParent, throwOnMissingSubKey: false);
}

Console.WriteLine("R3 registry rule and HKCU lifecycle runtime tests passed.");

static void Assert(bool condition, string name)
{
    if (!condition)
        throw new InvalidOperationException($"Registry protection test failed: {name}");
}

[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
static extern int RegRenameKey(nint hKey, string? subKeyName, string newKeyName);
