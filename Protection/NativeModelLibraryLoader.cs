using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Protection;

/// <summary>
/// Resilient loader for Xdows-Model-Native.dll with extensive diagnostics.
///
/// Diagnostic strategy for Win32 1346 (ERROR_BAD_IMPERSONATION_LEVEL):
///  - LOAD_LIBRARY_AS_DATAFILE (0x02): opens the file, creates a SEC_COMMIT
///    data section. Proves file access works.
///  - LOAD_LIBRARY_AS_IMAGE_RESOURCE (0x20): creates a SEC_IMAGE section and
///    maps it, but skips import resolution and DllMain. This is the ONLY
///    probe that isolates "image-section creation" from "DLL initialization".
///  - Normal load: section creation + imports + DllMain.
///  - Control-DLL probes: load other not-yet-loaded DLLs from the same
///    directory to determine whether the failure is specific to the
///    onnxruntime binaries or global to the process state.
///  - fltmc enumeration: lists every minifilter driver on the system so we
///    can see exactly which filters are attached when the failure occurs.
/// </summary>
internal static class NativeModelLibraryLoader
{
    internal const string NativeDllName = "Xdows-Model-Native.dll";

    private const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;
    private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    private const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
    private const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
    private const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;
    private const uint LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400;
    private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
    private const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;
    private const uint GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002;

    private static readonly object Sync = new();
    private static IntPtr _moduleHandle;
    private static string? _loadedFrom;
    private static string? _lastDiagnostics;
    private static bool _searchPathRestricted;
    private static bool _systemDiagnosticsCollected;

    private static readonly string[] NativeAssets =
    [
        "Xdows-Model-Native.dll",
        "onnxruntime.dll",
        "onnxruntime_providers_shared.dll",
        "VCRUNTIME140.dll",
        "VCRUNTIME140_1.dll",
        "MSVCP140.dll",
        "MSVCP140_1.dll",
        "Xdows-Model.onnx",
        "Xdows-Model-Flash.onnx",
        "Xdows-Model-Pro.onnx",
        "Xdows-Model-Pro-Standard.onnx",
        "Xdows-Model-Pro-Flash.onnx",
        "Xdows-Model-Pro-RawStat.onnx",
        "Xdows-Model-Pro-Structural.onnx"
    ];

    private static readonly string[] RequiredAssets =
    [
        "Xdows-Model-Native.dll",
        "onnxruntime.dll",
        "onnxruntime_providers_shared.dll"
    ];

    private static readonly string[] VcRuntimeDlls =
    [
        "VCRUNTIME140.dll",
        "VCRUNTIME140_1.dll",
        "MSVCP140.dll",
        "MSVCP140_1.dll"
    ];

    private static readonly string[] SystemDepDlls =
    [
        "dbghelp.dll",
        "SETUPAPI.dll",
        "dxgi.dll"
    ];

    // DLLs that ship in the application directory but are NOT loaded at
    // startup. Used as control probes: if these also fail with 1346 after the
    // driver connection, the problem is global to the process state; if they
    // load fine, the problem is specific to the onnxruntime binaries.
    private static readonly string[] ControlDlls =
    [
        "DirectML.dll",
        "Dia2Lib.dll",
        "LdaNative.dll",
        "DwmSceneI.dll",
        "MRM.dll",
        "Microsoft.DirectManipulation.dll"
    ];

    public static string? LoadedFrom => _loadedFrom;
    public static string? LastDiagnostics => _lastDiagnostics;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr AddDllDirectory(string lpDirectoryName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetModuleHandleExW(uint dwFlags, string lpModuleName, out IntPtr phModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameW(IntPtr hModule, StringBuilder lpFilename, uint nSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, out int TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Ensures the native model library is loaded and bound for P/Invoke.
    /// Throws DllNotFoundException with full diagnostics on failure.
    /// </summary>
    public static void EnsureLoaded()
    {
        lock (Sync)
        {
            if (_moduleHandle != IntPtr.Zero)
                return;

            if (!_searchPathRestricted)
            {
                try
                {
                    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                    _searchPathRestricted = true;
                }
                catch
                {
                    // Windows 8+; if unavailable, proceed with default search path.
                }
            }

            var attempts = new List<string>();
            var diagnostics = new List<string>();

            // System-level diagnostics collected once: minifilter inventory,
            // token elevation/integrity, impersonation level.
            CollectSystemDiagnostics(diagnostics);

            string baseDirectory = AppContext.BaseDirectory;
            if (TryLoadFromDirectory(baseDirectory, attempts, diagnostics, runProbes: true))
            {
                _lastDiagnostics = string.Join("; ", diagnostics);
                WriteDiagnosticsFile(attempts, diagnostics, succeeded: true);
                return;
            }

            foreach (string stagingDirectory in GetStagingDirectoryCandidates())
            {
                string? stagedDirectory = StageAssets(baseDirectory, stagingDirectory, attempts);
                if (stagedDirectory is null)
                    continue;

                if (TryLoadFromDirectory(stagedDirectory, attempts, diagnostics, runProbes: false))
                {
                    _lastDiagnostics = string.Join("; ", diagnostics);
                    WriteDiagnosticsFile(attempts, diagnostics, succeeded: true);
                    return;
                }
            }

            _lastDiagnostics = string.Join("; ", diagnostics);
            string diagFile = WriteDiagnosticsFile(attempts, diagnostics, succeeded: false);
            // Keep the exception message compact so the log line does not
            // truncate the pointer to the full diagnostic file.
            string lastError = attempts.Count > 0 ? attempts[attempts.Count - 1] : "none";
            throw new DllNotFoundException(
                $"Unable to load DLL '{NativeDllName}' or one of its dependencies. " +
                $"Full diagnostics written to: {diagFile}. Last attempt: {lastError}");
        }
    }

    /// <summary>
    /// Writes the complete attempt/diagnostic history to a dedicated file so
    /// nothing is lost to log-line truncation. Returns the file path.
    /// </summary>
    private static string WriteDiagnosticsFile(List<string> attempts, List<string> diagnostics, bool succeeded)
    {
        string baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Xdows-Security", "Logs");
        try
        {
            Directory.CreateDirectory(baseDir);
        }
        catch
        {
            baseDir = Path.GetTempPath();
        }

        string path = Path.Combine(baseDir, $"NativeLoader-Diag-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("NativeModelLibraryLoader diagnostics");
            sb.AppendLine($"Time: {DateTime.Now:O}");
            sb.AppendLine($"Result: {(succeeded ? "SUCCESS" : "FAILURE")}");
            sb.AppendLine($"LoadedFrom: {_loadedFrom ?? "(none)"}");
            sb.AppendLine();
            sb.AppendLine("=== System ===");
            sb.AppendLine($"OS: {Environment.OSVersion}");
            sb.AppendLine($"BaseDirectory: {AppContext.BaseDirectory}");
            sb.AppendLine($"SearchPathRestricted: {_searchPathRestricted}");
            sb.AppendLine();
            sb.AppendLine("=== Diagnostics ===");
            foreach (string d in diagnostics)
                sb.AppendLine(d);
            sb.AppendLine();
            sb.AppendLine("=== Attempts ===");
            foreach (string a in attempts)
                sb.AppendLine(a);
            File.WriteAllText(path, sb.ToString());
        }
        catch
        {
            // Best-effort — the diagnostics file must never break loading.
        }
        return path;
    }

    /// <summary>
    /// Collects system-level diagnostics once per process: minifilter driver
    /// inventory (fltmc), token elevation type, integrity level, and calling
    /// thread impersonation level.
    /// </summary>
    private static void CollectSystemDiagnostics(List<string> diagnostics)
    {
        if (_systemDiagnosticsCollected)
            return;
        _systemDiagnosticsCollected = true;

        // Thread impersonation level.
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            diagnostics.Add($"Impersonation={identity.ImpersonationLevel}");
        }
        catch (Exception ex)
        {
            diagnostics.Add($"Impersonation=Err:{ex.GetType().Name}");
        }

        // Token elevation type (TokenElevationType=18) and integrity level (25).
        try
        {
            const uint TOKEN_QUERY = 0x0008;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out IntPtr token))
            {
                try
                {
                    if (GetTokenInformation(token, 18, out int elev, sizeof(int), out _))
                        diagnostics.Add($"ElevType={elev}"); // 1=Default 2=Full 3=Limited
                }
                finally
                {
                    CloseHandle(token);
                }
            }
        }
        catch (Exception ex)
        {
            diagnostics.Add($"TokenInfo=Err:{ex.GetType().Name}");
        }

        // Minifilter inventory — this is the rigorous check: it shows exactly
        // which filters sit on the I/O stack when the 1346 occurs.
        string? filters = RunCommand("fltmc.exe", "filters", 6000);
        if (filters != null)
            diagnostics.Add($"FltFilters=[{filters}]");
        string? instances = RunCommand("fltmc.exe", "instances", 6000);
        if (instances != null)
            diagnostics.Add($"FltInstances=[{instances}]");

        // Antivirus kernel-driver detection. "Protection turned off" in an
        // AV's UI usually leaves its minifilter attached, and that filter can
        // still fail SEC_IMAGE section creation for new DLL loads. Detect the
        // most common ones explicitly so the diagnosis is unambiguous.
        string[] avMarkers =
        [
            "sysdiag", "hrfw", "hrwfp", "hrsword", "huorong",
            "wdfilter", "wdboot", "wdnfs",
            "360", "qax", "tsdefense", "qmonitor",
            "ksepkern", "klif", "bdfilesys", "avc", "aswsp",
            "mbam", "srtsp", "eset", "ekbdflt"
        ];
        var foundAvDrivers = new List<string>();
        foreach (string line in RunCommandLines("driverquery.exe", "/fo csv /nh", 8000))
        {
            string lower = line.ToLowerInvariant();
            foreach (string marker in avMarkers)
            {
                if (lower.Contains(marker))
                {
                    int comma = line.IndexOf(',');
                    string name = comma > 0 ? line.Substring(0, comma).Trim('"', ' ') : line.Trim('"', ' ');
                    if (!foundAvDrivers.Contains(name))
                        foundAvDrivers.Add(name);
                    break;
                }
            }
        }
        diagnostics.Add(foundAvDrivers.Count > 0
            ? $"AvDrivers=[{string.Join(",", foundAvDrivers)}]"
            : "AvDrivers=[]");
    }

    /// <summary>Runs a command and returns raw stdout lines.</summary>
    private static IEnumerable<string> RunCommandLines(string fileName, string arguments, int timeoutMs)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var proc = Process.Start(psi);
        if (proc == null)
            yield break;

        // Read stdout asynchronously WHILE waiting — a synchronous
        // WaitForExit before reading deadlocks once the child fills the
        // anonymous pipe buffer (~4 KB).
        Task<string> outputTask = proc.StandardOutput.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(); } catch { }
            yield break;
        }
        string output = outputTask.GetAwaiter().GetResult();
        foreach (string line in output.Split('\n'))
            yield return line.TrimEnd('\r');
    }

    /// <summary>Runs a command and returns compacted stdout (truncated).</summary>
    private static string? RunCommand(string fileName, string arguments, int timeoutMs, int maxChars = 480)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc == null)
                return null;
            // Read stdout asynchronously while waiting to avoid pipe-buffer
            // deadlock on large outputs.
            Task<string> outputTask = proc.StandardOutput.ReadToEndAsync();
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(); } catch { }
                return "timeout";
            }
            string output = outputTask.GetAwaiter().GetResult();
            // Compact: collapse whitespace/newlines, truncate.
            string compact = string.Join(" ", output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            return compact.Length > maxChars ? compact.Substring(0, maxChars) + "…" : compact;
        }
        catch
        {
            return null;
        }
    }

    private static bool TryLoadFromDirectory(
        string directory, List<string> attempts, List<string> diagnostics, bool runProbes)
    {
        string dllPath = Path.Combine(directory, NativeDllName);
        if (!File.Exists(dllPath))
        {
            attempts.Add($"{dllPath}: not found");
            return false;
        }

        try
        {
            // Make dependencies in the same folder resolvable without PATH.
            try { AddDllDirectory(directory); }
            catch { /* best-effort */ }

            IntPtr handle = RunOnCleanThread(() =>
            {
                try { RevertToSelf(); }
                catch { /* ignored — clean thread already has no token */ }
                return LoadWithFullDiagnostics(dllPath, directory, attempts, diagnostics, runProbes);
            });

            if (handle != IntPtr.Zero)
            {
                _moduleHandle = handle;
                _loadedFrom = dllPath;
                RegisterResolver();
                return true;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException or FileLoadException or TimeoutException)
        {
            attempts.Add($"{dllPath}: {ex.GetType().Name}: {ex.Message}");
        }

        return false;
    }

    /// <summary>
    /// Checks whether a module is already loaded WITHOUT incrementing its
    /// reference count. Distinguishes "already in memory" (no new section was
    /// created) from a genuine fresh load.
    /// </summary>
    private static bool IsModuleAlreadyLoaded(string moduleName, out string? loadedPath)
    {
        loadedPath = null;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, moduleName, out IntPtr h) || h == IntPtr.Zero)
            return false;
        var sb = new StringBuilder(512);
        if (GetModuleFileNameW(h, sb, (uint)sb.Capacity) > 0)
            loadedPath = sb.ToString();
        return true;
    }

    /// <summary>
    /// Performs the full loading sequence with diagnostics. Must be called on a
    /// clean thread (RevertToSelf applied, ExecutionContext suppressed).
    /// </summary>
    private static IntPtr LoadWithFullDiagnostics(
        string dllPath, string directory,
        List<string> attempts, List<string> diagnostics, bool runProbes)
    {
        var sw = Stopwatch.StartNew();

        // ── IMAGE_RESOURCE probe for the target DLL ──────────────────────
        // LOAD_LIBRARY_AS_IMAGE_RESOURCE creates the SEC_IMAGE section and
        // maps it, but skips imports and DllMain. This is the decisive probe:
        //   IR=OK  + normal load fails → failure is in imports/DllMain
        //   IR=FAIL 1346               → failure is image-section creation
        if (runProbes)
        {
            sw.Restart();
            IntPtr irProbe = LoadLibraryExW(dllPath, IntPtr.Zero, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (irProbe != IntPtr.Zero)
            {
                diagnostics.Add($"IR({Path.GetFileName(dllPath)})=OK [{sw.ElapsedMilliseconds}ms]");
                FreeLibrary(irProbe);
            }
            else
            {
                diagnostics.Add($"IR({Path.GetFileName(dllPath)})=FAIL W{(uint)Marshal.GetLastWin32Error()} [{sw.ElapsedMilliseconds}ms]");
            }

            // AS_DATAFILE probe (SEC_COMMIT data section — no image mapping).
            sw.Restart();
            IntPtr dfProbe = LoadLibraryExW(dllPath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
            if (dfProbe != IntPtr.Zero)
            {
                diagnostics.Add($"DF({Path.GetFileName(dllPath)})=OK [{sw.ElapsedMilliseconds}ms]");
                FreeLibrary(dfProbe);
            }
            else
            {
                diagnostics.Add($"DF({Path.GetFileName(dllPath)})=FAIL W{(uint)Marshal.GetLastWin32Error()} [{sw.ElapsedMilliseconds}ms]");
            }

            // ── Control DLL probes ───────────────────────────────────────
            // Other DLLs from the same directory that are not yet loaded.
            // If they fail with 1346 too → global process-state issue.
            // If they load fine → specific to the onnxruntime binaries.
            foreach (string ctrl in ControlDlls)
            {
                string ctrlPath = Path.Combine(directory, ctrl);
                if (!File.Exists(ctrlPath))
                    continue;
                if (IsModuleAlreadyLoaded(ctrl, out _))
                {
                    diagnostics.Add($"Ctrl({ctrl})=AlreadyLoaded");
                    continue;
                }

                sw.Restart();
                IntPtr ctrlIr = LoadLibraryExW(ctrlPath, IntPtr.Zero, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
                if (ctrlIr != IntPtr.Zero)
                {
                    FreeLibrary(ctrlIr);
                    IntPtr ctrlNormal = LoadLibraryExW(ctrlPath, IntPtr.Zero, 0);
                    if (ctrlNormal != IntPtr.Zero)
                        diagnostics.Add($"Ctrl({ctrl})=LOAD_OK [{sw.ElapsedMilliseconds}ms]");
                    else
                        diagnostics.Add($"Ctrl({ctrl})=IR_OK+LOAD_FAIL W{(uint)Marshal.GetLastWin32Error()} [{sw.ElapsedMilliseconds}ms]");
                }
                else
                {
                    diagnostics.Add($"Ctrl({ctrl})=IR_FAIL W{(uint)Marshal.GetLastWin32Error()} [{sw.ElapsedMilliseconds}ms]");
                }
            }
        }

        // ── VC++ Runtime preloads (annotated with provenance) ────────────
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (string vc in VcRuntimeDlls)
        {
            if (IsModuleAlreadyLoaded(vc, out string? vcPath))
            {
                diagnostics.Add($"PreLoad({vc})=AlreadyInMem({ShortenPath(vcPath)})");
                continue;
            }
            var vcSw = Stopwatch.StartNew();
            IntPtr vcHandle = LoadLibraryExW(vc, IntPtr.Zero, 0);
            diagnostics.Add(vcHandle != IntPtr.Zero
                ? $"PreLoad({vc})=FreshLoad_OK [{vcSw.ElapsedMilliseconds}ms]"
                : $"PreLoad({vc})=FreshLoad_FAIL W{(uint)Marshal.GetLastWin32Error()} [{vcSw.ElapsedMilliseconds}ms]");
        }

        // ── System dependency preloads (annotated) ───────────────────────
        foreach (string sys in SystemDepDlls)
        {
            if (IsModuleAlreadyLoaded(sys, out _))
            {
                diagnostics.Add($"PreLoad({sys})=AlreadyInMem");
                continue;
            }
            IntPtr sysHandle = LoadLibraryExW(sys, IntPtr.Zero, 0);
            diagnostics.Add(sysHandle != IntPtr.Zero
                ? $"PreLoad({sys})=FreshLoad_OK"
                : $"PreLoad({sys})=FreshLoad_FAIL W{(uint)Marshal.GetLastWin32Error()}");
        }

        // ── Load onnxruntime_providers_shared.dll ────────────────────────
        string providersShared = Path.Combine(directory, "onnxruntime_providers_shared.dll");
        if (File.Exists(providersShared))
        {
            IntPtr psh = TryLoadDllMultipleWays(providersShared, "prov_shared", attempts, diagnostics, runProbes);
            diagnostics.Add(psh != IntPtr.Zero ? "prov_shared=OK" : "prov_shared=FAIL");
        }

        // ── Load onnxruntime.dll ─────────────────────────────────────────
        string ortPath = Path.Combine(directory, "onnxruntime.dll");
        if (File.Exists(ortPath))
        {
            IntPtr ortHandle = TryLoadDllMultipleWays(ortPath, "onnxruntime", attempts, diagnostics, runProbes);
            if (ortHandle == IntPtr.Zero)
                return IntPtr.Zero;
            // Keep loaded — the main DLL binds to it.
        }

        // ── Load the main DLL ────────────────────────────────────────────
        return TryLoadDllMultipleWays(dllPath, "main", attempts, diagnostics, runProbes);
    }

    private static string ShortenPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return "?";
        // Keep only the two trailing path segments to save log space.
        int idx = path.LastIndexOf('\\');
        if (idx > 0)
        {
            int prev = path.LastIndexOf('\\', idx - 1);
            if (prev > 0)
                return "…" + path.Substring(prev);
        }
        return path;
    }

    /// <summary>
    /// Tries to load a DLL using several flag combinations, recording each
    /// attempt. Returns the module handle on success, IntPtr.Zero on failure.
    /// </summary>
    private static IntPtr TryLoadDllMultipleWays(
        string path, string label,
        List<string> attempts, List<string> diagnostics, bool runProbes)
    {
        // Strategy 0 (probe only): IMAGE_RESOURCE — section creation without
        // imports/DllMain. Decisive split between section and init failures.
        if (runProbes)
        {
            var psw = Stopwatch.StartNew();
            IntPtr ir = LoadLibraryExW(path, IntPtr.Zero, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (ir != IntPtr.Zero)
            {
                diagnostics.Add($"{label}:IR=OK [{psw.ElapsedMilliseconds}ms]");
                FreeLibrary(ir);
            }
            else
            {
                diagnostics.Add($"{label}:IR=FAIL W{(uint)Marshal.GetLastWin32Error()} [{psw.ElapsedMilliseconds}ms]");
            }
        }

        // Strategy 1: flags=0 — SetDefaultDllDirectories search (no PATH).
        var sw = Stopwatch.StartNew();
        IntPtr handle = LoadLibraryExW(path, IntPtr.Zero, 0);
        if (handle != IntPtr.Zero)
        {
            diagnostics.Add($"{label}=OK(flags=0) [{sw.ElapsedMilliseconds}ms]");
            return handle;
        }
        uint e1 = (uint)Marshal.GetLastWin32Error();
        attempts.Add($"{label}: flags=0 FAIL W{e1} [{sw.ElapsedMilliseconds}ms]");

        // Strategy 2: DLL_LOAD_DIR | SYSTEM32 only (most restrictive).
        sw.Restart();
        handle = LoadLibraryExW(path, IntPtr.Zero,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (handle != IntPtr.Zero)
        {
            diagnostics.Add($"{label}=OK(DLLDIR|SYS32) [{sw.ElapsedMilliseconds}ms]");
            return handle;
        }
        uint e2 = (uint)Marshal.GetLastWin32Error();
        attempts.Add($"{label}: DLLDIR|SYS32 FAIL W{e2} [{sw.ElapsedMilliseconds}ms]");

        // Strategy 3: DLL_LOAD_DIR | DEFAULT_DIRS (0x1000).
        sw.Restart();
        handle = LoadLibraryExW(path, IntPtr.Zero,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (handle != IntPtr.Zero)
        {
            diagnostics.Add($"{label}=OK(DLLDIR|DEF) [{sw.ElapsedMilliseconds}ms]");
            return handle;
        }
        uint e3 = (uint)Marshal.GetLastWin32Error();
        attempts.Add($"{label}: DLLDIR|DEF FAIL W{e3} [{sw.ElapsedMilliseconds}ms]");

        // Strategy 4: LOAD_WITH_ALTERED_SEARCH_PATH (legacy mechanism).
        sw.Restart();
        handle = LoadLibraryExW(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (handle != IntPtr.Zero)
        {
            diagnostics.Add($"{label}=OK(ALTERED) [{sw.ElapsedMilliseconds}ms]");
            return handle;
        }
        uint e4 = (uint)Marshal.GetLastWin32Error();
        attempts.Add($"{label}: ALTERED FAIL W{e4} [{sw.ElapsedMilliseconds}ms]");

        // Strategy 5: NativeLibrary.Load fallback.
        try
        {
            handle = NativeLibrary.Load(path);
            if (handle != IntPtr.Zero)
            {
                diagnostics.Add($"{label}=OK(NativeLib)");
                return handle;
            }
        }
        catch (Exception nlEx)
        {
            attempts.Add($"{label}: NativeLib FAIL {nlEx.GetType().Name}:{nlEx.Message}");
        }

        return IntPtr.Zero;
    }

    private static void RegisterResolver()
    {
        try
        {
            NativeLibrary.SetDllImportResolver(typeof(NativeModelLibraryLoader).Assembly, ResolveNativeLibrary);
        }
        catch (InvalidOperationException)
        {
            // A resolver is already registered for this assembly.
        }
    }

    private static IntPtr ResolveNativeLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (_moduleHandle != IntPtr.Zero &&
            string.Equals(libraryName, NativeDllName, StringComparison.OrdinalIgnoreCase))
        {
            return _moduleHandle;
        }
        return IntPtr.Zero;
    }

    private static IEnumerable<string> GetStagingDirectoryCandidates()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        yield return Path.Combine(windows, "Xdows-Security", "Native");
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Xdows-Security", "Native");
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Xdows-Security", "Native");
    }

    private static string? StageAssets(string sourceDirectory, string stagingDirectory, List<string> attempts)
    {
        try
        {
            Directory.CreateDirectory(stagingDirectory);

            foreach (string asset in NativeAssets)
            {
                string source = Path.Combine(sourceDirectory, asset);
                string target = Path.Combine(stagingDirectory, asset);
                if (!File.Exists(source))
                    continue;

                if (File.Exists(target) &&
                    new FileInfo(target).Length == new FileInfo(source).Length &&
                    File.GetLastWriteTimeUtc(target) >= File.GetLastWriteTimeUtc(source))
                {
                    continue;
                }

                File.Copy(source, target, overwrite: true);
            }

            foreach (string required in RequiredAssets)
            {
                if (!File.Exists(Path.Combine(stagingDirectory, required)))
                {
                    attempts.Add($"{stagingDirectory}: required asset missing after staging: {required}");
                    return null;
                }
            }

            return stagingDirectory;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            attempts.Add($"{stagingDirectory}: staging failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Executes work on a fresh thread with ExecutionContext flow suppressed,
    /// so that any ambient WindowsIdentity does not propagate. Combined with
    /// RevertToSelf() inside the thread body, this guarantees the loader runs
    /// under the process primary token.
    /// </summary>
    private static T RunOnCleanThread<T>(Func<T> work)
    {
        T? result = default;
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                result = work();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        })
        {
            IsBackground = true,
            Name = "XdowsNativeLoader"
        };

        using (ExecutionContext.SuppressFlow())
        {
            thread.Start();
        }

        if (!thread.Join(TimeSpan.FromSeconds(45)))
            throw new TimeoutException("Timed out while loading the native model library on a clean thread.");

        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();

        return result!;
    }
}
