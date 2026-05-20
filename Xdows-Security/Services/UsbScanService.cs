using Helper;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;
using Xdows_Security.Views;

namespace Xdows_Security.Services;

public class UsbScanThreatInfo
{
    public string FilePath { get; set; } = string.Empty;
    public string VirusName { get; set; } = string.Empty;
    public string EngineName { get; set; } = string.Empty;
}

public class UsbScanProgressEventArgs : EventArgs
{
    public string DriveLetter { get; set; } = string.Empty;
    public string DriveLabel { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public int TotalFiles { get; set; }
    public int ThreatsFound { get; set; }
    public bool IsCompleted { get; set; }
    public bool IsPaused { get; set; }
    public bool IsCancelled { get; set; }
    public List<UsbScanThreatInfo> Threats { get; set; } = [];
}

public class UsbScanService
{
    private static UsbScanService? _instance;
    public static UsbScanService Instance => _instance ??= new UsbScanService();

    private readonly ConcurrentQueue<string> _pendingDrives = new();
    private CancellationTokenSource? _cts;
    private volatile bool _isPaused;
    private bool _isScanning;
    private readonly object _lock = new();

    private static readonly TimeSpan PerFileTimeout = TimeSpan.FromSeconds(30);

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".msi"
    };

    public event EventHandler<UsbScanProgressEventArgs>? ProgressChanged;
    public event EventHandler<UsbScanProgressEventArgs>? ScanCompleted;
    public event EventHandler<string>? ScanStarted;

    public bool IsScanning => _isScanning;
    public bool IsPaused => _isPaused;

    public void EnqueueDrive(string driveLetter)
    {
        var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;
        bool enabled = !(settings.Values["UsbAutoScan"] is bool b && !b);
        if (!enabled) return;

        _pendingDrives.Enqueue(driveLetter);
        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan", $"Device queued: {driveLetter}");

        lock (_lock)
        {
            if (!_isScanning)
            {
                _ = Task.Run(ProcessQueueAsync);
            }
        }
    }

    public void Pause()
    {
        _isPaused = true;
    }

    public void Resume()
    {
        _isPaused = false;
    }

    public void Cancel()
    {
        _cts?.Cancel();
        _isPaused = false;
    }

    public void CancelDrive(string driveLetter)
    {
        lock (_lock)
        {
            var remaining = new List<string>();
            while (_pendingDrives.TryDequeue(out string? dl))
            {
                if (dl != driveLetter)
                    remaining.Add(dl);
            }
            foreach (var dl in remaining)
                _pendingDrives.Enqueue(dl);
        }
    }

    private async Task ProcessQueueAsync()
    {
        lock (_lock) { _isScanning = true; }

        while (_pendingDrives.TryDequeue(out string? driveLetter))
        {
            _cts = new CancellationTokenSource();
            _isPaused = false;
            await ScanDriveAsync(driveLetter, _cts.Token);
            _cts.Dispose();
            _cts = null;
        }

        lock (_lock) { _isScanning = false; }
    }

    private async Task ScanDriveAsync(string driveLetter, CancellationToken token)
    {
        string driveRoot = $"{driveLetter}:\\";
        string driveLabel = GetDriveLabel(driveLetter);

        ScanStarted?.Invoke(this, driveLetter);
        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan", $"Scanning {driveRoot} ({driveLabel})");

        var threats = new List<UsbScanThreatInfo>();
        int filesScanned = 0;
        int totalFiles = 0;

        try
        {
            var fileList = await Task.Run(() =>
            {
                var files = EnumerateExecutableFiles(driveRoot);
                return files.ToList();
            }, token);
            totalFiles = fileList.Count;

            var args = new UsbScanProgressEventArgs
            {
                DriveLetter = driveLetter,
                DriveLabel = driveLabel,
                TotalFiles = totalFiles
            };
            ProgressChanged?.Invoke(this, args);

            var settings = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings;
            bool useModelScan = !(settings.Values["ModelScan"] is bool ms && !ms);
            bool useLocalScan = settings.Values["LocalScan"] is true;
            bool useCloudScan = settings.Values["CloudScan"] is true;
            bool deepScan = settings.Values["DeepScan"] is true;
            bool extraData = settings.Values["ExtraData"] is true;
            bool useVirusFamily = settings.Values["VirusFamily"] is true;

            ScanEngine.ModelEngineScan? modelEngine = null;
            if (useModelScan)
            {
                try { modelEngine = await Task.Run(() => new ScanEngine.ModelEngineScan()); }
                catch { useModelScan = false; }
            }

            foreach (var file in fileList)
            {
                while (_isPaused && !token.IsCancellationRequested)
                    await Task.Delay(100, token);

                if (token.IsCancellationRequested) break;

                try
                {
                    if (TrustManager.IsPathTrusted(file))
                    {
                        filesScanned++;
                        continue;
                    }

                    string? md5Hash = null;
                    if (useCloudScan)
                    {
                        try { md5Hash = await ScanEngine.GetFileMD5Async(file).WaitAsync(token); } catch { }
                    }

                    using var fileCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    fileCts.CancelAfter(PerFileTimeout);

                    var scanRes = await SecurityPage.RunScansOnFileAsync(
                        file, null, md5Hash,
                        deepScan, extraData,
                        useLocalScan, useCloudScan, useModelScan,
                        false, useVirusFamily,
                        modelEngine, fileCts.Token);

                    if (!string.IsNullOrEmpty(scanRes.VirusInfo))
                    {
                        threats.Add(new UsbScanThreatInfo
                        {
                            FilePath = file,
                            VirusName = scanRes.VirusInfo,
                            EngineName = scanRes.EngineName
                        });
                        LogText.AddNewLog(LogText.LogLevel.WARN, "UsbScan", $"Threat found: {file} - {scanRes.VirusInfo} ({scanRes.EngineName})");
                    }
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "UsbScan", $"File scan timed out: {file}");
                    filesScanned++;
                    continue;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "UsbScan", $"Scan file failed: {file} - {ex.Message}");
                }

                filesScanned++;

                ProgressChanged?.Invoke(this, new UsbScanProgressEventArgs
                {
                    DriveLetter = driveLetter,
                    DriveLabel = driveLabel,
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    ThreatsFound = threats.Count,
                    IsPaused = _isPaused
                });
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            LogText.AddNewLog(LogText.LogLevel.ERROR, "UsbScan", $"Scan drive failed: {driveRoot} - {ex.Message}");
        }

        var completedArgs = new UsbScanProgressEventArgs
        {
            DriveLetter = driveLetter,
            DriveLabel = driveLabel,
            FilesScanned = filesScanned,
            TotalFiles = totalFiles,
            ThreatsFound = threats.Count,
            Threats = threats,
            IsCompleted = true,
            IsCancelled = token.IsCancellationRequested
        };
        ScanCompleted?.Invoke(this, completedArgs);

        LogText.AddNewLog(LogText.LogLevel.INFO, "UsbScan",
            token.IsCancellationRequested
                ? $"Scan cancelled: {driveRoot}"
                : $"Scan completed: {driveRoot} - {filesScanned} files, {threats.Count} threats");
    }

    private static IEnumerable<string> EnumerateExecutableFiles(string root)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Where(f => ExecutableExtensions.Contains(Path.GetExtension(f)));
        }
        catch { return Enumerable.Empty<string>(); }
    }

    public static string GetDriveLabel(string driveLetter)
    {
        try
        {
            var drive = new DriveInfo($"{driveLetter}:\\");
            return string.IsNullOrWhiteSpace(drive.VolumeLabel)
                ? $"{driveLetter}:"
                : $"{driveLetter}: ({drive.VolumeLabel})";
        }
        catch { return $"{driveLetter}:"; }
    }
}
