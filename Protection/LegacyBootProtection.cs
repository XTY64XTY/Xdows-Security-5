using Helper;
using Microsoft.Win32.SafeHandles;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using static Protection.CallBack;

namespace Protection;

public enum BootProtectionUserDecision
{
    KeepRepair,
    AllowChange
}

public sealed record BootProtectionPreparation(
    PhysicalDiskInfo Disk,
    Boolean HasTrustedBaseline);

public sealed record BootProtectionDecisionRequest(
    Int32 DiskIndex,
    String DiskModel,
    IReadOnlyList<String> ChangedItems,
    Boolean RepairSucceeded,
    DateTimeOffset DetectedAt);

public sealed class LegacyBootProtection : IProtectionModel
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    private readonly Lock _stateLock = new();
    private readonly BootBaselineStore _store;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private BootProtectionSnapshot? _baseline;

    public LegacyBootProtection(String baselineDirectory)
    {
        if (String.IsNullOrWhiteSpace(baselineDirectory))
            throw new ArgumentException("A baseline directory is required.", nameof(baselineDirectory));

        _store = new BootBaselineStore(baselineDirectory);
    }

    public const String Name = "Boot";
    String IProtectionModel.Name => Name;

    public Func<BootProtectionDecisionRequest, CancellationToken, Task<BootProtectionUserDecision>>? DecisionCallback { get; set; }
    public Action<String>? LogCallback { get; set; }

    public BootProtectionPreparation InspectPreparation()
    {
        PhysicalDiskInfo disk = GetSystemBootDisk();
        Boolean hasBaseline = _store.TryLoad(out BootProtectionSnapshot? snapshot) &&
            snapshot is not null &&
            SnapshotMatchesDisk(snapshot, disk);

        return new BootProtectionPreparation(
            disk,
            hasBaseline);
    }

    public void CreateTrustedBaseline()
    {
        lock (_stateLock)
        {
            if (HasActiveMonitorUnsafe())
                throw new InvalidOperationException("Stop boot protection before replacing its trusted baseline.");
        }

        PhysicalDiskInfo disk = GetSystemBootDisk();
        BootProtectionSnapshot snapshot = BootProtectionSnapshotService.CaptureInitial(disk);
        _store.Save(snapshot);
        Log($"Trusted boot baseline created for PhysicalDrive{disk.Index} with " +
            $"{snapshot.RawRegions.Count} raw regions and {snapshot.Files.Count} boot files.");
    }

    public Boolean Run(InterceptCallBack interceptCallBack)
    {
        _ = interceptCallBack;

        lock (_stateLock)
        {
            if (IsRunUnsafe())
                return true;
            if (HasActiveMonitorUnsafe())
                return false;

            _cts?.Dispose();
            _cts = null;
            _monitorTask = null;
            _baseline = null;

            PhysicalDiskInfo disk = GetSystemBootDisk();
            if (!_store.TryLoad(out BootProtectionSnapshot? baseline) || baseline is null)
            {
                Log("Boot protection cannot start because no trusted baseline exists.");
                return false;
            }

            if (!SnapshotMatchesDisk(baseline, disk))
            {
                Log("Boot protection baseline does not match the current system boot disk.");
                return false;
            }

            _baseline = baseline;
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorAsync(_cts.Token));
            Log($"R3 boot protection started for PhysicalDrive{disk.Index}.");
            return true;
        }
    }

    public Boolean Stop()
    {
        CancellationTokenSource? cts;
        Task? monitorTask;

        lock (_stateLock)
        {
            if (!HasActiveMonitorUnsafe())
            {
                _cts?.Dispose();
                _cts = null;
                _monitorTask = null;
                _baseline = null;
                return true;
            }

            cts = _cts;
            monitorTask = _monitorTask;
        }

        cts?.Cancel();
        if (monitorTask is not null && cts is not null)
            _ = CompleteStopAsync(monitorTask, cts);
        return true;
    }

    public Boolean IsRun()
    {
        lock (_stateLock)
        {
            return IsRunUnsafe();
        }
    }

    private Boolean IsRunUnsafe()
    {
        return _cts is { IsCancellationRequested: false } && _monitorTask is not null;
    }

    private Boolean HasActiveMonitorUnsafe()
    {
        return _monitorTask is { IsCompleted: false };
    }

    private async Task CompleteStopAsync(Task monitorTask, CancellationTokenSource cts)
    {
        try
        {
            await monitorTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Log($"R3 boot protection stopped after a monitor failure: {ex.Message}");
        }
        finally
        {
            Boolean cleared = false;
            lock (_stateLock)
            {
                if (ReferenceEquals(_monitorTask, monitorTask))
                {
                    _cts = null;
                    _monitorTask = null;
                    _baseline = null;
                    cleared = true;
                }
            }
            if (cleared)
            {
                cts.Dispose();
                Log("R3 boot protection stopped.");
            }
        }
    }

    private async Task MonitorAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, token).ConfigureAwait(false);
                BootProtectionSnapshot? baseline;
                lock (_stateLock)
                {
                    baseline = _baseline;
                }

                if (baseline is null)
                    return;

                BootProtectionSnapshot observed = BootProtectionSnapshotService.CaptureCurrent(baseline);
                IReadOnlyList<BootProtectionChange> changes = BootProtectionSnapshotService.Compare(baseline, observed);
                if (changes.Count == 0)
                    continue;

                Log($"Detected {changes.Count} protected boot changes. Repairing before user notification.");
                Boolean repaired = false;
                try
                {
                    BootProtectionSnapshotService.ApplySnapshot(baseline, observed, changes);
                    BootProtectionSnapshot verification = BootProtectionSnapshotService.CaptureCurrent(baseline);
                    repaired = BootProtectionSnapshotService.Compare(baseline, verification).Count == 0;
                }
                catch (Exception ex)
                {
                    Log($"Automatic boot repair failed: {ex.Message}");
                }

                BootProtectionUserDecision decision = await RequestDecisionAsync(
                    baseline,
                    changes,
                    repaired,
                    token).ConfigureAwait(false);

                if (decision != BootProtectionUserDecision.AllowChange || !repaired)
                {
                    Log(repaired
                        ? "The trusted boot baseline remains enforced."
                        : "The detected boot change remains blocked from user release because repair was incomplete.");
                    continue;
                }

                try
                {
                    BootProtectionSnapshotService.ApplySnapshot(observed, baseline, changes);
                    BootProtectionSnapshot released = BootProtectionSnapshotService.CaptureCurrent(observed);
                    if (BootProtectionSnapshotService.Compare(observed, released).Count != 0)
                        throw new IOException("The released boot state did not pass read-back verification.");

                    _store.Save(observed);
                    lock (_stateLock)
                    {
                        _baseline = observed;
                    }
                    Log("The user released the boot change and the trusted baseline was updated.");
                }
                catch (Exception ex)
                {
                    Log($"Failed to release the repaired boot change: {ex.Message}");
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                Log($"Boot protection poll failed and will retry: {ex.Message}");
            }
        }
    }

    private async Task<BootProtectionUserDecision> RequestDecisionAsync(
        BootProtectionSnapshot baseline,
        IReadOnlyList<BootProtectionChange> changes,
        Boolean repairSucceeded,
        CancellationToken token)
    {
        if (DecisionCallback is null)
            return BootProtectionUserDecision.KeepRepair;

        var request = new BootProtectionDecisionRequest(
            baseline.DiskIndex,
            baseline.DiskModel,
            changes.Select(change => change.DisplayName).Take(12).ToArray(),
            repairSucceeded,
            DateTimeOffset.Now);

        try
        {
            return await DecisionCallback(request, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return BootProtectionUserDecision.KeepRepair;
        }
        catch (Exception ex)
        {
            Log($"Boot protection decision callback failed: {ex.Message}");
            return BootProtectionUserDecision.KeepRepair;
        }
    }

    private void Log(String message)
    {
        LogCallback?.Invoke(message);
    }

    internal static PhysicalDiskInfo GetSystemBootDisk()
    {
        PhysicalDiskInfo[] disks = DiskOperator.GetPhysicalDisks()
            .OrderBy(disk => disk.Index)
            .ToArray();

        PhysicalDiskInfo[] bootCandidates = disks
            .Where(disk => BootVolumeLocator.FindProtectedRoots(disk.Index).Count != 0)
            .ToArray();
        if (bootCandidates.Length == 1)
            return WithResolvedDiskSize(bootCandidates[0]);

        PhysicalDiskInfo[] systemDisks = bootCandidates
            .Where(disk => disk.IsSystemDisk)
            .ToArray();

        return systemDisks.Length switch
        {
            1 => WithResolvedDiskSize(systemDisks[0]),
            0 => throw new IOException("The physical disk containing the active Windows boot partition could not be identified."),
            _ => throw new IOException("Multiple physical disks contain possible Windows boot partitions; automatic boot protection requires one unambiguous active boot disk.")
        };
    }

    internal static PhysicalDiskInfo WithResolvedDiskSize(PhysicalDiskInfo disk)
    {
        // GetPhysicalDisks may fail to query the disk length (size 0) depending on
        // the storage stack. Resolve the authoritative size with read access so GPT
        // bounds validation never runs against a bogus zero-length disk.
        return disk.SizeBytes > 0
            ? disk
            : disk with { SizeBytes = DiskOperator.GetDiskLength(disk.Index) };
    }

    private static Boolean SnapshotMatchesDisk(BootProtectionSnapshot snapshot, PhysicalDiskInfo disk)
    {
        if (snapshot.DiskIndex != disk.Index ||
            snapshot.DiskSizeBytes != disk.SizeBytes ||
            snapshot.PartitionStyle != disk.PartitionStyle)
        {
            return false;
        }

        return String.IsNullOrWhiteSpace(snapshot.DiskSerialNumber) ||
            String.IsNullOrWhiteSpace(disk.SerialNumber) ||
            String.Equals(snapshot.DiskSerialNumber, disk.SerialNumber, StringComparison.OrdinalIgnoreCase);
    }
}

internal enum BootProtectionChangeKind
{
    RawRegion,
    FileAdded,
    FileModified,
    FileDeleted
}

internal sealed record BootProtectionChange(
    BootProtectionChangeKind Kind,
    String Key,
    String DisplayName);

internal sealed record BootRawRegion(
    String Name,
    Int64 Offset,
    Byte[] Data);

internal sealed record BootDriverProtectionConfiguration(
    Int32 DiskIndex,
    String DiskModel,
    IReadOnlyList<BootRawRegion> RawRegions,
    IReadOnlyList<String> NtVolumeRoots);

internal sealed record BootFileEntry(
    String VolumeRoot,
    String RelativePath,
    Byte[] Data,
    FileAttributes Attributes,
    DateTime LastWriteTimeUtc)
{
    public String Key => $"{VolumeRoot}|{RelativePath}";
}

internal sealed record BootProtectionSnapshot(
    Int32 DiskIndex,
    String DiskModel,
    String DiskSerialNumber,
    Int64 DiskSizeBytes,
    PhysicalDiskPartitionStyle PartitionStyle,
    Int32 LogicalSectorSize,
    IReadOnlyList<BootRawRegion> RawRegions,
    IReadOnlyList<String> ProtectedRoots,
    IReadOnlyList<BootFileEntry> Files);

internal static class BootProtectionSnapshotService
{
    private const Int32 MaxGptEntryBytes = 16 * 1024 * 1024;
    private const Int64 MaxProtectedFileBytes = 64L * 1024 * 1024;
    private const Int64 MaxProtectedFilesTotalBytes = 256L * 1024 * 1024;
    private static readonly Byte[] GptSignature = "EFI PART"u8.ToArray();

    public static BootDriverProtectionConfiguration CreateDriverConfiguration()
    {
        PhysicalDiskInfo disk = LegacyBootProtection.GetSystemBootDisk();
        Int32 sectorSize = DiskOperator.GetLogicalSectorSize(disk.Index);
        IReadOnlyList<BootRawRegion> rawRegions = CaptureInitialRawRegions(disk, sectorSize);
        IReadOnlyList<String> protectedRoots = BootVolumeLocator.FindProtectedRoots(disk.Index);
        String[] ntVolumeRoots = protectedRoots
            .Select(root => root.Split('|', 2)[0])
            .Select(BootVolumeLocator.GetNtVolumeRoot)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (ntVolumeRoots.Length == 0)
            throw new IOException("No active EFI or BCD boot volume could be mapped to an NT device path.");
        if (ntVolumeRoots.Length > 4)
            throw new IOException("The active boot configuration spans more than four protected volumes.");

        return new BootDriverProtectionConfiguration(
            disk.Index,
            disk.Model,
            rawRegions,
            ntVolumeRoots);
    }

    public static BootProtectionSnapshot CaptureInitial(PhysicalDiskInfo disk)
    {
        Int32 sectorSize = DiskOperator.GetLogicalSectorSize(disk.Index);
        IReadOnlyList<BootRawRegion> rawRegions = CaptureInitialRawRegions(disk, sectorSize);
        IReadOnlyList<String> protectedRoots = BootVolumeLocator.FindProtectedRoots(disk.Index);
        if (protectedRoots.Count == 0)
            throw new IOException("No active EFI or BCD boot path was found on the Windows system disk.");

        IReadOnlyList<BootFileEntry> files = CaptureFiles(protectedRoots);
        if (files.Count == 0)
            throw new IOException("The active boot paths did not contain any supported EFI or BCD files.");

        return new BootProtectionSnapshot(
            disk.Index,
            disk.Model,
            disk.SerialNumber,
            disk.SizeBytes,
            disk.PartitionStyle,
            sectorSize,
            rawRegions,
            protectedRoots,
            files);
    }

    public static BootProtectionSnapshot CaptureCurrent(BootProtectionSnapshot layout)
    {
        PhysicalDiskInfo disk = LegacyBootProtection.WithResolvedDiskSize(
            DiskOperator.GetPhysicalDisks()
                .Single(current => current.Index == layout.DiskIndex));

        if (disk.SizeBytes != layout.DiskSizeBytes ||
            disk.PartitionStyle != layout.PartitionStyle ||
            (!String.IsNullOrWhiteSpace(layout.DiskSerialNumber) &&
             !String.IsNullOrWhiteSpace(disk.SerialNumber) &&
             !String.Equals(layout.DiskSerialNumber, disk.SerialNumber, StringComparison.OrdinalIgnoreCase)))
        {
            throw new IOException("The protected boot disk identity changed; a new trusted baseline is required.");
        }

        var rawRegions = layout.RawRegions
            .Select(region => new BootRawRegion(
                region.Name,
                region.Offset,
                DiskOperator.ReadDiskRegion(layout.DiskIndex, region.Offset, region.Data.Length)))
            .ToArray();

        return new BootProtectionSnapshot(
            layout.DiskIndex,
            disk.Model,
            disk.SerialNumber,
            disk.SizeBytes,
            disk.PartitionStyle,
            layout.LogicalSectorSize,
            rawRegions,
            layout.ProtectedRoots,
            CaptureFiles(layout.ProtectedRoots));
    }

    public static IReadOnlyList<BootProtectionChange> Compare(
        BootProtectionSnapshot baseline,
        BootProtectionSnapshot observed)
    {
        var changes = new List<BootProtectionChange>();
        Dictionary<String, BootRawRegion> observedRaw = observed.RawRegions
            .ToDictionary(region => region.Name, StringComparer.OrdinalIgnoreCase);

        foreach (BootRawRegion expected in baseline.RawRegions)
        {
            if (!observedRaw.TryGetValue(expected.Name, out BootRawRegion? current) ||
                current.Offset != expected.Offset ||
                !current.Data.AsSpan().SequenceEqual(expected.Data))
            {
                changes.Add(new BootProtectionChange(
                    BootProtectionChangeKind.RawRegion,
                    expected.Name,
                    expected.Name));
            }
        }

        Dictionary<String, BootFileEntry> expectedFiles = baseline.Files
            .ToDictionary(file => file.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<String, BootFileEntry> currentFiles = observed.Files
            .ToDictionary(file => file.Key, StringComparer.OrdinalIgnoreCase);

        foreach ((String key, BootFileEntry expected) in expectedFiles)
        {
            if (!currentFiles.TryGetValue(key, out BootFileEntry? current))
            {
                changes.Add(new BootProtectionChange(
                    BootProtectionChangeKind.FileDeleted,
                    key,
                    expected.RelativePath));
            }
            else if (!current.Data.AsSpan().SequenceEqual(expected.Data))
            {
                changes.Add(new BootProtectionChange(
                    BootProtectionChangeKind.FileModified,
                    key,
                    expected.RelativePath));
            }
        }

        foreach ((String key, BootFileEntry current) in currentFiles)
        {
            if (!expectedFiles.ContainsKey(key))
            {
                changes.Add(new BootProtectionChange(
                    BootProtectionChangeKind.FileAdded,
                    key,
                    current.RelativePath));
            }
        }

        return changes;
    }

    public static void ApplySnapshot(
        BootProtectionSnapshot desired,
        BootProtectionSnapshot previous,
        IReadOnlyList<BootProtectionChange> changes)
    {
        Dictionary<String, BootRawRegion> desiredRaw = desired.RawRegions
            .ToDictionary(region => region.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<String, BootFileEntry> desiredFiles = desired.Files
            .ToDictionary(file => file.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<String, BootFileEntry> previousFiles = previous.Files
            .ToDictionary(file => file.Key, StringComparer.OrdinalIgnoreCase);

        foreach (BootProtectionChange change in changes
                     .Where(change => change.Kind == BootProtectionChangeKind.RawRegion)
                     .OrderBy(change => RawWritePriority(change.Key)))
        {
            if (desiredRaw.TryGetValue(change.Key, out BootRawRegion? region))
                DiskOperator.WriteDiskRegion(desired.DiskIndex, region.Offset, region.Data);
        }

        foreach (BootProtectionChange change in changes.Where(change => change.Kind != BootProtectionChangeKind.RawRegion))
        {
            if (desiredFiles.TryGetValue(change.Key, out BootFileEntry? desiredFile))
            {
                WriteProtectedFile(desiredFile);
            }
            else if (previousFiles.TryGetValue(change.Key, out BootFileEntry? previousFile))
            {
                DeleteProtectedFile(previousFile.VolumeRoot, previousFile.RelativePath);
            }
        }
    }

    private static IReadOnlyList<BootRawRegion> CaptureInitialRawRegions(
        PhysicalDiskInfo disk,
        Int32 sectorSize)
    {
        var regions = new List<BootRawRegion>
        {
            new("MBR", 0, DiskOperator.ReadDiskRegion(disk.Index, 0, sectorSize))
        };
        if (regions[0].Data.Length < DiskOperator.BootSectorSize ||
            !DiskOperator.IsValidBootSector(regions[0].Data.AsSpan(0, DiskOperator.BootSectorSize)))
        {
            throw new InvalidDataException("The system disk does not contain a valid 55 AA MBR signature.");
        }

        if (disk.PartitionStyle != PhysicalDiskPartitionStyle.Gpt)
            return regions;

        Byte[] primaryHeader = DiskOperator.ReadDiskRegion(disk.Index, sectorSize, sectorSize);
        GptHeaderInfo primary = ParseAndValidateGptHeader(primaryHeader, sectorSize, disk.SizeBytes, "primary GPT header");
        Byte[] primaryEntries = ReadAndValidateGptEntries(disk.Index, primary, sectorSize, "primary GPT entries");

        Int64 backupHeaderOffset = checked((Int64)primary.BackupLba * sectorSize);
        Byte[] backupHeader = DiskOperator.ReadDiskRegion(disk.Index, backupHeaderOffset, sectorSize);
        GptHeaderInfo backup = ParseAndValidateGptHeader(backupHeader, sectorSize, disk.SizeBytes, "backup GPT header");
        Byte[] backupEntries = ReadAndValidateGptEntries(disk.Index, backup, sectorSize, "backup GPT entries");

        regions.Add(new BootRawRegion(
            "GPT.PrimaryEntries",
            checked((Int64)primary.EntryLba * sectorSize),
            primaryEntries));
        regions.Add(new BootRawRegion("GPT.PrimaryHeader", sectorSize, primaryHeader));
        regions.Add(new BootRawRegion(
            "GPT.BackupEntries",
            checked((Int64)backup.EntryLba * sectorSize),
            backupEntries));
        regions.Add(new BootRawRegion("GPT.BackupHeader", backupHeaderOffset, backupHeader));
        return regions;
    }

    private static GptHeaderInfo ParseAndValidateGptHeader(
        Byte[] data,
        Int32 sectorSize,
        Int64 diskSize,
        String label)
    {
        if (data.Length != sectorSize || !data.AsSpan(0, GptSignature.Length).SequenceEqual(GptSignature))
            throw new InvalidDataException($"The {label} signature is invalid.");

        UInt32 headerSize = BitConverter.ToUInt32(data, 12);
        if (headerSize is < 92 || headerSize > sectorSize)
            throw new InvalidDataException($"The {label} size is invalid: {headerSize}.");

        UInt32 storedHeaderCrc = BitConverter.ToUInt32(data, 16);
        Byte[] headerForCrc = data.AsSpan(0, checked((Int32)headerSize)).ToArray();
        Array.Clear(headerForCrc, 16, sizeof(UInt32));
        if (Crc32.Compute(headerForCrc) != storedHeaderCrc)
            throw new InvalidDataException($"The {label} CRC is invalid.");

        UInt64 currentLba = BitConverter.ToUInt64(data, 24);
        UInt64 backupLba = BitConverter.ToUInt64(data, 32);
        UInt64 entryLba = BitConverter.ToUInt64(data, 72);
        UInt32 entryCount = BitConverter.ToUInt32(data, 80);
        UInt32 entrySize = BitConverter.ToUInt32(data, 84);
        UInt32 entryCrc = BitConverter.ToUInt32(data, 88);

        if (entryCount == 0 || entrySize is < 128 or > 4096 || entrySize % 8 != 0)
            throw new InvalidDataException($"The {label} partition-entry layout is invalid.");

        if (diskSize <= 0)
            throw new InvalidDataException($"The disk size reported for the {label} validation is invalid: {diskSize}.");

        UInt64 sectorCount = checked((UInt64)(diskSize / sectorSize));
        if (currentLba >= sectorCount || backupLba >= sectorCount || entryLba >= sectorCount)
            throw new InvalidDataException(
                $"The {label} references a sector outside the disk " +
                $"(currentLba={currentLba}, backupLba={backupLba}, entryLba={entryLba}, " +
                $"sectorCount={sectorCount}, diskSize={diskSize}, sectorSize={sectorSize}).");

        UInt64 entryBytes = checked((UInt64)entryCount * entrySize);
        if (entryBytes == 0 || entryBytes > MaxGptEntryBytes)
            throw new InvalidDataException($"The {label} partition-entry array is too large.");

        return new GptHeaderInfo(backupLba, entryLba, checked((Int32)entryBytes), entryCrc);
    }

    private static Byte[] ReadAndValidateGptEntries(
        Int32 diskIndex,
        GptHeaderInfo header,
        Int32 sectorSize,
        String label)
    {
        Int32 roundedLength = checked((header.EntryBytes + sectorSize - 1) / sectorSize * sectorSize);
        if (roundedLength > MaxGptEntryBytes)
            throw new InvalidDataException($"The {label} rounded partition-entry array is too large.");
        Byte[] data = DiskOperator.ReadDiskRegion(
            diskIndex,
            checked((Int64)header.EntryLba * sectorSize),
            roundedLength);

        if (Crc32.Compute(data.AsSpan(0, header.EntryBytes)) != header.EntryCrc)
            throw new InvalidDataException($"The {label} CRC is invalid.");

        return data;
    }

    private static IReadOnlyList<BootFileEntry> CaptureFiles(IReadOnlyList<String> protectedRoots)
    {
        var files = new Dictionary<String, BootFileEntry>(StringComparer.OrdinalIgnoreCase);
        Int64 totalBytes = 0;

        foreach (String protectedRoot in protectedRoots)
        {
            (String volumeRoot, String relativeRoot) = SplitProtectedRoot(protectedRoot);
            String directory = CombineProtectedPath(volumeRoot, relativeRoot);
            if (!Directory.Exists(directory))
                continue;

            foreach (String path in EnumerateFilesWithoutReparsePoints(directory))
            {
                FileAttributes currentAttributes = File.GetAttributes(path);
                if ((currentAttributes & FileAttributes.ReparsePoint) != 0)
                    continue;
                if (!IsProtectedBootFile(path))
                    continue;

                FileInfo info = new(path);
                if (info.Length > MaxProtectedFileBytes)
                    throw new IOException($"Protected boot file is too large: {path}.");

                String relativePath = Path.GetRelativePath(volumeRoot, path);
                ValidateRelativePath(relativePath);
                EnsureNoReparsePoints(volumeRoot, relativePath);
                Byte[] data = ReadSharedFile(path);
                if (data.LongLength > MaxProtectedFileBytes)
                    throw new IOException($"Protected boot file grew beyond the safety limit while being read: {path}.");

                totalBytes = checked(totalBytes + data.LongLength);
                if (totalBytes > MaxProtectedFilesTotalBytes)
                    throw new IOException("Protected EFI and BCD files exceed the 256 MiB safety limit.");

                var entry = new BootFileEntry(
                    EnsureTrailingSeparator(volumeRoot),
                    relativePath,
                    data,
                    currentAttributes,
                    info.LastWriteTimeUtc);
                files[entry.Key] = entry;
            }
        }

        return files.Values.OrderBy(file => file.Key, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IEnumerable<String> EnumerateFilesWithoutReparsePoints(String root)
    {
        var pending = new Stack<String>();
        pending.Push(root);

        while (pending.Count != 0)
        {
            String directory = pending.Pop();
            foreach (String file in Directory.EnumerateFiles(directory))
                yield return file;

            foreach (String child in Directory.EnumerateDirectories(directory))
            {
                FileAttributes attributes = File.GetAttributes(child);
                if ((attributes & FileAttributes.ReparsePoint) == 0)
                    pending.Push(child);
            }
        }
    }

    private static Boolean IsProtectedBootFile(String path)
    {
        String name = Path.GetFileName(path);
        if (name.StartsWith("BCD.LOG", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("bootstat.dat", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (name.Equals("BCD", StringComparison.OrdinalIgnoreCase))
            return true;

        String extension = Path.GetExtension(name);
        return !extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".log", StringComparison.OrdinalIgnoreCase);
    }

    private static Byte[] ReadSharedFile(String path)
    {
        using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.SequentialScan);
        using var memory = new MemoryStream(checked((Int32)Math.Min(stream.Length, Int32.MaxValue)));
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static void WriteProtectedFile(BootFileEntry file)
    {
        EnsureNoReparsePoints(file.VolumeRoot, file.RelativePath);
        String path = CombineProtectedPath(file.VolumeRoot, file.RelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? file.VolumeRoot);
        if (File.Exists(path))
        {
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
        }

        using (FileStream stream = new(
                   path,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.Read,
                   64 * 1024,
                   FileOptions.WriteThrough))
        {
            stream.Write(file.Data);
            stream.Flush(true);
        }

        File.SetLastWriteTimeUtc(path, file.LastWriteTimeUtc);
        File.SetAttributes(path, file.Attributes);
    }

    private static void DeleteProtectedFile(String volumeRoot, String relativePath)
    {
        EnsureNoReparsePoints(volumeRoot, relativePath);
        String path = CombineProtectedPath(volumeRoot, relativePath);
        if (!File.Exists(path))
            return;

        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReadOnly) != 0)
            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
        File.Delete(path);
    }

    private static (String VolumeRoot, String RelativeRoot) SplitProtectedRoot(String protectedRoot)
    {
        Int32 separator = protectedRoot.IndexOf('|');
        if (separator <= 0 || separator == protectedRoot.Length - 1)
            throw new InvalidDataException("A protected boot root is malformed.");

        String volumeRoot = EnsureTrailingSeparator(protectedRoot[..separator]);
        String relativeRoot = protectedRoot[(separator + 1)..];
        ValidateRelativePath(relativeRoot);
        return (volumeRoot, relativeRoot);
    }

    private static String CombineProtectedPath(String volumeRoot, String relativePath)
    {
        ValidateRelativePath(relativePath);
        String normalizedRoot = EnsureTrailingSeparator(Path.GetFullPath(volumeRoot));
        String fullPath = Path.GetFullPath(Path.Combine(normalizedRoot, relativePath));
        if (!fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("A protected boot path escaped its volume root.");
        return fullPath;
    }

    private static void ValidateRelativePath(String relativePath)
    {
        if (String.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
            throw new InvalidDataException("A protected boot path must be relative.");

        String[] components = relativePath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        if (components.Any(component => component is "." or ".."))
            throw new InvalidDataException("A protected boot path contains traversal components.");
    }

    private static void EnsureNoReparsePoints(String volumeRoot, String relativePath)
    {
        ValidateRelativePath(relativePath);
        String current = EnsureTrailingSeparator(Path.GetFullPath(volumeRoot));
        String[] components = relativePath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        foreach (String component in components)
        {
            current = Path.Combine(current, component);
            if (!File.Exists(current) && !Directory.Exists(current))
                continue;

            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"A protected boot path contains a reparse point: {relativePath}.");
        }
    }

    private static String EnsureTrailingSeparator(String path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;
    }

    private static Int32 RawWritePriority(String name)
    {
        return name switch
        {
            "GPT.BackupEntries" => 0,
            "GPT.BackupHeader" => 1,
            "GPT.PrimaryEntries" => 2,
            "GPT.PrimaryHeader" => 3,
            "MBR" => 4,
            _ => 5
        };
    }

    private sealed record GptHeaderInfo(
        UInt64 BackupLba,
        UInt64 EntryLba,
        Int32 EntryBytes,
        UInt32 EntryCrc);
}

internal static class BootVolumeLocator
{
    private const UInt32 FileShareRead = 0x00000001;
    private const UInt32 FileShareWrite = 0x00000002;
    private const UInt32 OpenExisting = 3;
    private const UInt32 IoctlVolumeGetVolumeDiskExtents = 0x00560000;
    private const Int32 ErrorNoMoreFiles = 18;
    private const Int32 ErrorInsufficientBuffer = 122;
    private static readonly String[] CandidateRoots =
    [
        @"EFI\Microsoft\Boot",
        @"EFI\Boot",
        @"Boot"
    ];

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindFirstVolumeW(StringBuilder volumeName, UInt32 bufferLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern Boolean FindNextVolumeW(IntPtr findVolume, StringBuilder volumeName, UInt32 bufferLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern Boolean FindVolumeClose(IntPtr findVolume);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        String fileName,
        UInt32 desiredAccess,
        UInt32 shareMode,
        IntPtr securityAttributes,
        UInt32 creationDisposition,
        UInt32 flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern UInt32 QueryDosDeviceW(
        String deviceName,
        Char[] targetPath,
        UInt32 maximumLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern Boolean DeviceIoControl(
        SafeFileHandle device,
        UInt32 controlCode,
        Byte[]? input,
        UInt32 inputSize,
        Byte[]? output,
        UInt32 outputSize,
        out UInt32 bytesReturned,
        IntPtr overlapped);

    public static IReadOnlyList<String> FindProtectedRoots(Int32 diskIndex)
    {
        var protectedRoots = new SortedSet<String>(StringComparer.OrdinalIgnoreCase);

        const UInt32 capacity = 1024;
        var volumeName = new StringBuilder((Int32)capacity);
        IntPtr search = FindFirstVolumeW(volumeName, capacity);
        if (search == new IntPtr(-1))
            throw new IOException($"Failed to enumerate volumes. Win32 error {Marshal.GetLastWin32Error()}.");

        try
        {
            while (true)
            {
                String volumeRoot = volumeName.ToString();
                if (VolumeUsesDisk(volumeRoot, diskIndex))
                    AddCandidateRoots(protectedRoots, volumeRoot);

                volumeName.Clear();
                volumeName.EnsureCapacity((Int32)capacity);
                if (FindNextVolumeW(search, volumeName, capacity))
                    continue;

                Int32 error = Marshal.GetLastWin32Error();
                if (error == ErrorNoMoreFiles)
                    break;
                throw new IOException($"Failed to enumerate volumes. Win32 error {error}.");
            }
        }
        finally
        {
            _ = FindVolumeClose(search);
        }

        return protectedRoots.ToArray();
    }

    public static String GetNtVolumeRoot(String volumeRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeRoot);
        String normalized = volumeRoot.TrimEnd('\\');
        if (normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return normalized;

        String dosDeviceName;
        if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            dosDeviceName = normalized[4..];
        else if (normalized.Length >= 2 && normalized[1] == ':')
            dosDeviceName = normalized[..2];
        else
            throw new IOException($"Unsupported boot volume path: {volumeRoot}.");

        Int32 bufferSize = 512;
        while (bufferSize <= 64 * 1024)
        {
            Char[] buffer = new Char[bufferSize];
            UInt32 length = QueryDosDeviceW(dosDeviceName, buffer, (UInt32)buffer.Length);
            if (length != 0)
            {
                Int32 terminator = Array.IndexOf(buffer, '\0');
                if (terminator < 0)
                    terminator = checked((Int32)length);
                String target = new(buffer, 0, terminator);
                if (!target.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                    throw new IOException($"Boot volume {volumeRoot} resolved to an invalid NT path.");
                return target.TrimEnd('\\');
            }

            Int32 error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer)
                throw new IOException($"Failed to resolve boot volume {volumeRoot}. Win32 error {error}.");
            bufferSize *= 2;
        }

        throw new IOException($"The NT path for boot volume {volumeRoot} exceeded the supported size.");
    }

    private static void AddCandidateRoots(ISet<String> protectedRoots, String volumeRoot)
    {
        String normalizedRoot = EnsureTrailingSeparator(volumeRoot);
        foreach (String relativeRoot in CandidateRoots)
        {
            String path = Path.Combine(normalizedRoot, relativeRoot);
            if (Directory.Exists(path))
                protectedRoots.Add($"{normalizedRoot}|{relativeRoot}");
        }
    }

    private static String EnsureTrailingSeparator(String path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;
    }

    private static Boolean VolumeUsesDisk(String volumeRoot, Int32 diskIndex)
    {
        String devicePath = volumeRoot.TrimEnd('\\');
        using SafeFileHandle handle = CreateFileW(
            devicePath,
            0,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (handle.IsInvalid)
            return false;

        Byte[] output = new Byte[64 * 1024];
        if (!DeviceIoControl(
                handle,
                IoctlVolumeGetVolumeDiskExtents,
                null,
                0,
                output,
                (UInt32)output.Length,
                out UInt32 bytesReturned,
                IntPtr.Zero) ||
            bytesReturned < 32)
        {
            return false;
        }

        UInt32 count = BitConverter.ToUInt32(output, 0);
        const Int32 firstExtentOffset = 8;
        const Int32 extentSize = 24;
        for (UInt32 index = 0; index < count; index++)
        {
            Int32 offset = firstExtentOffset + checked((Int32)index * extentSize);
            if (offset + extentSize > bytesReturned)
                break;

            if (BitConverter.ToUInt32(output, offset) == diskIndex)
                return true;
        }

        return false;
    }
}

internal sealed class BootBaselineStore
{
    private const Int32 FormatVersion = 1;
    private const String ArchiveFileName = "boot-baseline.zip";
    private const String KeyFileName = "boot-baseline.key";
    private const String ManifestEntryName = "manifest.json";
    private readonly String _directory;

    public BootBaselineStore(String directory)
    {
        _directory = Path.GetFullPath(directory);
    }

    public void Save(BootProtectionSnapshot snapshot)
    {
        Directory.CreateDirectory(_directory);
        Byte[] key = LoadOrCreateKey();
        String archivePath = Path.Combine(_directory, ArchiveFileName);
        String temporaryPath = archivePath + ".tmp";

        var manifest = new BootBaselineManifest
        {
            Version = FormatVersion,
            DiskIndex = snapshot.DiskIndex,
            DiskModel = snapshot.DiskModel,
            DiskSerialNumber = snapshot.DiskSerialNumber,
            DiskSizeBytes = snapshot.DiskSizeBytes,
            PartitionStyle = snapshot.PartitionStyle,
            LogicalSectorSize = snapshot.LogicalSectorSize,
            ProtectedRoots = snapshot.ProtectedRoots.ToList()
        };

        try
        {
            using (FileStream stream = new(temporaryPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false))
            {
                for (Int32 index = 0; index < snapshot.RawRegions.Count; index++)
                {
                    BootRawRegion region = snapshot.RawRegions[index];
                    String entryName = $"raw/{index:D4}.bin";
                    WriteEntry(archive, entryName, region.Data);
                    manifest.RawRegions.Add(new BootRawManifest
                    {
                        Name = region.Name,
                        Offset = region.Offset,
                        EntryName = entryName,
                        Length = region.Data.Length,
                        Sha256 = Convert.ToHexString(SHA256.HashData(region.Data))
                    });
                }

                for (Int32 index = 0; index < snapshot.Files.Count; index++)
                {
                    BootFileEntry file = snapshot.Files[index];
                    String entryName = $"files/{index:D6}.bin";
                    WriteEntry(archive, entryName, file.Data);
                    manifest.Files.Add(new BootFileManifest
                    {
                        VolumeRoot = file.VolumeRoot,
                        RelativePath = file.RelativePath,
                        EntryName = entryName,
                        Length = file.Data.Length,
                        Sha256 = Convert.ToHexString(SHA256.HashData(file.Data)),
                        Attributes = file.Attributes,
                        LastWriteTimeUtc = file.LastWriteTimeUtc
                    });
                }

                Byte[] unsignedManifest = JsonSerializer.SerializeToUtf8Bytes(
                    manifest,
                    BootBaselineJsonContext.Default.BootBaselineManifest);
                manifest.Signature = Convert.ToHexString(HMACSHA256.HashData(key, unsignedManifest));
                Byte[] signedManifest = JsonSerializer.SerializeToUtf8Bytes(
                    manifest,
                    BootBaselineJsonContext.Default.BootBaselineManifest);
                WriteEntry(archive, ManifestEntryName, signedManifest);
            }

            File.Move(temporaryPath, archivePath, true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public Boolean TryLoad(out BootProtectionSnapshot? snapshot)
    {
        snapshot = null;
        String archivePath = Path.Combine(_directory, ArchiveFileName);
        String keyPath = Path.Combine(_directory, KeyFileName);
        if (!File.Exists(archivePath) || !File.Exists(keyPath))
            return false;

        Byte[] key = Array.Empty<Byte>();
        try
        {
            key = Dpapi.Unprotect(File.ReadAllBytes(keyPath));
            using FileStream stream = new(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            Byte[] manifestBytes = ReadEntry(archive, ManifestEntryName, 4 * 1024 * 1024);
            BootBaselineManifest? manifest = JsonSerializer.Deserialize(
                manifestBytes,
                BootBaselineJsonContext.Default.BootBaselineManifest);
            if (manifest is null || manifest.Version != FormatVersion || String.IsNullOrWhiteSpace(manifest.Signature))
                return false;

            String signature = manifest.Signature;
            manifest.Signature = null;
            Byte[] unsignedManifest = JsonSerializer.SerializeToUtf8Bytes(
                manifest,
                BootBaselineJsonContext.Default.BootBaselineManifest);
            Byte[] expectedSignature = HMACSHA256.HashData(key, unsignedManifest);
            if (!CryptographicOperations.FixedTimeEquals(
                    expectedSignature,
                    Convert.FromHexString(signature)))
            {
                return false;
            }

            var rawRegions = new List<BootRawRegion>();
            foreach (BootRawManifest item in manifest.RawRegions)
            {
                Byte[] data = ReadVerifiedEntry(archive, item.EntryName, item.Length, item.Sha256);
                rawRegions.Add(new BootRawRegion(item.Name, item.Offset, data));
            }

            var files = new List<BootFileEntry>();
            foreach (BootFileManifest item in manifest.Files)
            {
                Byte[] data = ReadVerifiedEntry(archive, item.EntryName, item.Length, item.Sha256);
                files.Add(new BootFileEntry(
                    item.VolumeRoot,
                    item.RelativePath,
                    data,
                    item.Attributes,
                    item.LastWriteTimeUtc));
            }

            snapshot = new BootProtectionSnapshot(
                manifest.DiskIndex,
                manifest.DiskModel,
                manifest.DiskSerialNumber,
                manifest.DiskSizeBytes,
                manifest.PartitionStyle,
                manifest.LogicalSectorSize,
                rawRegions,
                manifest.ProtectedRoots,
                files);
            return true;
        }
        catch (Exception)
        {
            snapshot = null;
            return false;
        }
        finally
        {
            if (key.Length != 0)
                CryptographicOperations.ZeroMemory(key);
        }
    }

    private Byte[] LoadOrCreateKey()
    {
        String path = Path.Combine(_directory, KeyFileName);
        if (File.Exists(path))
            return Dpapi.Unprotect(File.ReadAllBytes(path));

        Byte[] key = RandomNumberGenerator.GetBytes(32);
        Byte[] protectedKey = Dpapi.Protect(key);
        try
        {
            File.WriteAllBytes(path, protectedKey);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedKey);
        }
    }

    private static void WriteEntry(ZipArchive archive, String name, Byte[] data)
    {
        ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using Stream stream = entry.Open();
        stream.Write(data);
    }

    private static Byte[] ReadVerifiedEntry(
        ZipArchive archive,
        String entryName,
        Int32 length,
        String sha256)
    {
        if (length < 0 || length > 64 * 1024 * 1024)
            throw new InvalidDataException("A boot baseline entry length is invalid.");

        Byte[] data = ReadEntry(archive, entryName, length);
        if (data.Length != length ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(data),
                Convert.FromHexString(sha256)))
        {
            throw new InvalidDataException("A boot baseline entry failed integrity validation.");
        }

        return data;
    }

    private static Byte[] ReadEntry(ZipArchive archive, String name, Int32 maximumLength)
    {
        ZipArchiveEntry entry = archive.GetEntry(name) ??
            throw new InvalidDataException($"Boot baseline entry is missing: {name}.");
        if (entry.Length < 0 || entry.Length > maximumLength)
            throw new InvalidDataException($"Boot baseline entry is too large: {name}.");

        using Stream source = entry.Open();
        using var destination = new MemoryStream(checked((Int32)entry.Length));
        source.CopyTo(destination);
        return destination.ToArray();
    }
}

internal sealed class BootBaselineManifest
{
    public Int32 Version { get; set; }
    public Int32 DiskIndex { get; set; }
    public String DiskModel { get; set; } = String.Empty;
    public String DiskSerialNumber { get; set; } = String.Empty;
    public Int64 DiskSizeBytes { get; set; }
    public PhysicalDiskPartitionStyle PartitionStyle { get; set; }
    public Int32 LogicalSectorSize { get; set; }
    public List<String> ProtectedRoots { get; set; } = [];
    public List<BootRawManifest> RawRegions { get; set; } = [];
    public List<BootFileManifest> Files { get; set; } = [];
    public String? Signature { get; set; }
}

internal sealed class BootRawManifest
{
    public String Name { get; set; } = String.Empty;
    public Int64 Offset { get; set; }
    public String EntryName { get; set; } = String.Empty;
    public Int32 Length { get; set; }
    public String Sha256 { get; set; } = String.Empty;
}

internal sealed class BootFileManifest
{
    public String VolumeRoot { get; set; } = String.Empty;
    public String RelativePath { get; set; } = String.Empty;
    public String EntryName { get; set; } = String.Empty;
    public Int32 Length { get; set; }
    public String Sha256 { get; set; } = String.Empty;
    public FileAttributes Attributes { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(BootBaselineManifest))]
internal sealed partial class BootBaselineJsonContext : JsonSerializerContext;

internal static class Dpapi
{
    private const UInt32 CryptProtectUiForbidden = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public Int32 Length;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern Boolean CryptProtectData(
        ref DataBlob dataIn,
        String? description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        UInt32 flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern Boolean CryptUnprotectData(
        ref DataBlob dataIn,
        IntPtr description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        UInt32 flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static Byte[] Protect(Byte[] data)
    {
        return Transform(data, protect: true);
    }

    public static Byte[] Unprotect(Byte[] data)
    {
        return Transform(data, protect: false);
    }

    private static Byte[] Transform(Byte[] data, Boolean protect)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0)
            throw new CryptographicException("DPAPI input cannot be empty.");

        DataBlob input = new()
        {
            Length = data.Length,
            Data = Marshal.AllocHGlobal(data.Length)
        };
        DataBlob output = default;
        try
        {
            Marshal.Copy(data, 0, input.Data, data.Length);
            Boolean success = protect
                ? CryptProtectData(
                    ref input,
                    "Xdows Security R3 boot baseline",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output)
                : CryptUnprotectData(
                    ref input,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output);
            if (!success)
                throw new CryptographicException(Marshal.GetLastWin32Error());

            Byte[] result = new Byte[output.Length];
            Marshal.Copy(output.Data, result, 0, output.Length);
            return result;
        }
        finally
        {
            if (input.Data != IntPtr.Zero)
            {
                Marshal.Copy(new Byte[data.Length], 0, input.Data, data.Length);
                Marshal.FreeHGlobal(input.Data);
            }
            if (output.Data != IntPtr.Zero)
                _ = LocalFree(output.Data);
        }
    }
}

internal static class Crc32
{
    private const UInt32 Polynomial = 0xEDB88320u;

    public static UInt32 Compute(ReadOnlySpan<Byte> data)
    {
        UInt32 crc = UInt32.MaxValue;
        foreach (Byte value in data)
        {
            crc ^= value;
            for (Int32 bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ ((crc & 1) != 0 ? Polynomial : 0);
        }
        return ~crc;
    }
}
