using System.Buffers;
using System.IO.Compression;

namespace Helper
{
    public static class ZipScanner
    {
        private const Int64 MaxEntrySize = 100 * 1024 * 1024; // 100MB limit per entry
        private const Int32 BufferSize = 262144; // 256KB buffer for streaming (optimized from 80KB)
        public static Boolean IsZipFile(String filePath)
        {
            if (!File.Exists(filePath)) return false;

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                if (fs.Length < 4) return false;

                var buffer = ArrayPool<Byte>.Shared.Rent(4);
                try
                {
                    Int32 bytesRead = fs.Read(buffer, 0, 4);
                    if (bytesRead < 4) return false;

                    return buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04;
                }
                finally
                {
                    ArrayPool<Byte>.Shared.Return(buffer);
                }
            }
            catch
            {
                return false;
            }
        }

        public static async Task<List<(String EntryPath, Byte[] Data)>> ReadZipEntriesAsync(String zipPath, Boolean scanNestedArchives = false)
        {
            var entries = new List<(String EntryPath, Byte[] Data)>();

            await Task.Run(() =>
            {
                try
                {
                    using var archive = ZipFile.OpenRead(zipPath);
                    foreach (var entry in archive.Entries)
                    {
                        if (entry.Length == 0 || entry.Name.EndsWith("/")) continue;

                        // Skip entries larger than MaxEntrySize
                        if (entry.Length > MaxEntrySize) continue;

                        String entryPath = entry.FullName.Replace('/', '\\');

                        if (scanNestedArchives && IsZipEntry(entry))
                        {
                            try
                            {
                                var data = ReadEntryData(entry);
                                if (data != null)
                                {
                                    var nestedEntries = ReadNestedZipEntries(data, entryPath);
                                    lock (entries)
                                    {
                                        entries.AddRange(nestedEntries);
                                    }
                                }
                            }
                            catch
                            {
                                var data = ReadEntryData(entry);
                                if (data != null)
                                {
                                    lock (entries)
                                    {
                                        entries.Add((entryPath, data));
                                    }
                                }
                            }
                        }
                        else
                        {
                            var data = ReadEntryData(entry);
                            if (data != null)
                            {
                                lock (entries)
                                {
                                    entries.Add((entryPath, data));
                                }
                            }
                        }
                    }
                }
                catch { }
            });

            return entries;
        }

        private static Boolean IsZipEntry(ZipArchiveEntry entry)
        {
            try
            {
                using var stream = entry.Open();
                var buffer = ArrayPool<Byte>.Shared.Rent(4);
                try
                {
                    Int32 bytesRead = stream.Read(buffer, 0, 4);
                    if (bytesRead < 4) return false;
                    return buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04;
                }
                finally
                {
                    ArrayPool<Byte>.Shared.Return(buffer);
                }
            }
            catch
            {
                return false;
            }
        }

        private static Byte[]? ReadEntryData(ZipArchiveEntry entry)
        {
            try
            {
                if (entry.Length > MaxEntrySize) return null;

                using var stream = entry.Open();
                var buffer = ArrayPool<Byte>.Shared.Rent(BufferSize);
                try
                {
                    var ms = new MemoryStream();
                    Int32 bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, BufferSize)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                        // Prevent memory explosion
                        if (ms.Length > MaxEntrySize) return null;
                    }
                    return ms.ToArray();
                }
                finally
                {
                    ArrayPool<Byte>.Shared.Return(buffer);
                }
            }
            catch
            {
                return null;
            }
        }

        private static List<(String EntryPath, Byte[] Data)> ReadNestedZipEntries(Byte[] zipData, String parentPath)
        {
            var entries = new List<(String EntryPath, Byte[] Data)>();
            try
            {
                using var ms = new MemoryStream(zipData);
                using var archive = new ZipArchive(ms, ZipArchiveMode.Read);
                foreach (var entry in archive.Entries)
                {
                    if (entry.Length == 0 || entry.Name.EndsWith("/")) continue;
                    if (entry.Length > MaxEntrySize) continue;

                    String fullPath = entry.FullName.Replace('/', '\\');
                    String entryPath = Path.GetFileName(fullPath);
                    
                    var data = ReadEntryData(entry);
                    if (data != null)
                    {
                        entries.Add((entryPath, data));
                    }
                }
            }
            catch { }
            return entries;
        }

        public static async Task<Boolean> DeleteEntryFromZipAsync(String zipPath, String entryPath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    String tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

                    using (var readArchive = ZipFile.OpenRead(zipPath))
                    using (var createArchive = ZipFile.Open(tempPath, ZipArchiveMode.Create))
                    {
                        foreach (var entry in readArchive.Entries)
                        {
                            if (String.Equals(entry.FullName, entryPath, StringComparison.OrdinalIgnoreCase))
                                continue;

                            var newEntry = createArchive.CreateEntry(entry.FullName);
                            using var entryStream = entry.Open();
                            using var newEntryStream = newEntry.Open();
                            entryStream.CopyTo(newEntryStream);
                        }
                    }

                    File.Delete(zipPath);
                    File.Move(tempPath, zipPath);
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }

        public static async Task<Int32> DeleteMultipleEntriesFromZipAsync(String zipPath, List<String> entryPaths)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var entriesToDelete = new HashSet<String>(
                        entryPaths.Select(p => p.Replace('\\', '/')),
                        StringComparer.OrdinalIgnoreCase);
                    String tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    Int32 deletedCount = 0;

                    using (var readArchive = ZipFile.OpenRead(zipPath))
                    using (var createArchive = ZipFile.Open(tempPath, ZipArchiveMode.Create))
                    {
                        foreach (var entry in readArchive.Entries)
                        {
                            if (entriesToDelete.Contains(entry.FullName))
                            {
                                deletedCount++;
                                continue;
                            }

                            var newEntry = createArchive.CreateEntry(entry.FullName);
                            using var entryStream = entry.Open();
                            using var newEntryStream = newEntry.Open();
                            entryStream.CopyTo(newEntryStream);
                        }
                    }

                    File.Delete(zipPath);
                    File.Move(tempPath, zipPath);
                    return deletedCount;
                }
                catch
                {
                    return 0;
                }
            });
        }

        public static async Task<Byte[]?> ExtractEntryAsync(String zipPath, String entryPath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    String normalizedEntryPath = entryPath.Replace('\\', '/');
                    using var archive = ZipFile.OpenRead(zipPath);

                    foreach (var entry in archive.Entries)
                    {
                        if (String.Equals(entry.FullName, normalizedEntryPath, StringComparison.OrdinalIgnoreCase))
                        {
                            return ReadEntryData(entry);
                        }
                    }
                    return null;
                }
                catch
                {
                    return null;
                }
            });
        }

        public static async Task<(Int64 Size, DateTime CreationTime, DateTime LastWriteTime)?> GetEntryInfoAsync(String zipPath, String entryPath)
        {
            return await Task.Run<(Int64 Size, DateTime CreationTime, DateTime LastWriteTime)?>(() =>
            {
                try
                {
                    String normalizedEntryPath = entryPath.Replace('\\', '/');
                    Int32 innerZipIndex = normalizedEntryPath.IndexOf(".zip/", StringComparison.OrdinalIgnoreCase);

                    if (innerZipIndex > 0)
                    {
                        String outerEntryPath = normalizedEntryPath.Substring(0, innerZipIndex + 4);
                        String remainingPath = normalizedEntryPath.Substring(innerZipIndex + 5);

                        using var outerArchive = ZipFile.OpenRead(zipPath);
                        var outerEntry = outerArchive.Entries.FirstOrDefault(e =>
                            String.Equals(e.FullName, outerEntryPath, StringComparison.OrdinalIgnoreCase));

                        if (outerEntry == null)
                        {
                            outerEntryPath = normalizedEntryPath.Substring(0, innerZipIndex + 4).Replace(".zip/", "/");
                            outerEntry = outerArchive.Entries.FirstOrDefault(e =>
                                String.Equals(e.FullName, outerEntryPath, StringComparison.OrdinalIgnoreCase) ||
                                String.Equals(e.FullName, outerEntryPath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
                        }

                        if (outerEntry != null)
                        {
                            try
                            {
                                // Check size before loading into memory
                                if (outerEntry.Length > MaxEntrySize) return null;

                                var buffer = ArrayPool<Byte>.Shared.Rent(BufferSize);
                                try
                                {
                                    using var innerMs = new MemoryStream();
                                    using var outerStream = outerEntry.Open();
                                    Int32 bytesRead;
                                    while ((bytesRead = outerStream.Read(buffer, 0, BufferSize)) > 0)
                                    {
                                        innerMs.Write(buffer, 0, bytesRead);
                                        if (innerMs.Length > MaxEntrySize) return null;
                                    }
                                    innerMs.Position = 0;

                                    using var innerArchive = new ZipArchive(innerMs, ZipArchiveMode.Read);
                                    var innerEntry = innerArchive.Entries.FirstOrDefault(e =>
                                        String.Equals(e.FullName, remainingPath, StringComparison.OrdinalIgnoreCase));

                                    if (innerEntry != null)
                                    {
                                        return (innerEntry.Length, innerEntry.LastWriteTime.DateTime, innerEntry.LastWriteTime.DateTime);
                                    }
                                }
                                finally
                                {
                                    ArrayPool<Byte>.Shared.Return(buffer);
                                }
                            }
                            catch { }
                        }
                        return null;
                    }
                    else
                    {
                        using var archive = ZipFile.OpenRead(zipPath);

                        foreach (var entry in archive.Entries)
                        {
                            if (String.Equals(entry.FullName, normalizedEntryPath, StringComparison.OrdinalIgnoreCase))
                            {
                                return (entry.Length, entry.LastWriteTime.DateTime, entry.LastWriteTime.DateTime);
                            }
                        }
                        return null;
                    }
                }
                catch
                {
                    return null;
                }
            });
        }
    }
}
