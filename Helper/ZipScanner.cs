using System.IO.Compression;

namespace Helper
{
    public static class ZipScanner
    {
        public static Boolean IsZipFile(String filePath)
        {
            if (!File.Exists(filePath)) return false;

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                if (fs.Length < 4) return false;

                Byte[] header = new Byte[4];
                Int32 bytesRead = fs.Read(header, 0, 4);
                if (bytesRead < 4) return false;

                return header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04;
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

                        String entryPath = entry.FullName.Replace('/', '\\');

                        if (scanNestedArchives && IsZipEntry(entry))
                        {
                            try
                            {
                                using var ms = new MemoryStream();
                                using var stream = entry.Open();
                                stream.CopyTo(ms);
                                var nestedEntries = ReadNestedZipEntries(ms.ToArray(), entryPath);
                                entries.AddRange(nestedEntries);
                            }
                            catch
                            {
                                using var ms = new MemoryStream();
                                using var stream = entry.Open();
                                stream.CopyTo(ms);
                                entries.Add((entryPath, ms.ToArray()));
                            }
                        }
                        else
                        {
                            using var ms = new MemoryStream();
                            using var stream = entry.Open();
                            stream.CopyTo(ms);
                            entries.Add((entryPath, ms.ToArray()));
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
                Byte[] header = new Byte[4];
                Int32 bytesRead = stream.Read(header, 0, 4);
                if (bytesRead < 4) return false;
                return header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04;
            }
            catch
            {
                return false;
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
                    String fullPath = entry.FullName.Replace('/', '\\');
                    String entryPath = Path.GetFileName(fullPath);
                    using var entryMs = new MemoryStream();
                    using var stream = entry.Open();
                    stream.CopyTo(entryMs);
                    entries.Add((entryPath, entryMs.ToArray()));
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
                            using var ms = new MemoryStream();
                            using var stream = entry.Open();
                            stream.CopyTo(ms);
                            return ms.ToArray();
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
                                using var innerMs = new MemoryStream();
                                using var outerStream = outerEntry.Open();
                                outerStream.CopyTo(innerMs);
                                innerMs.Position = 0;

                                using var innerArchive = new ZipArchive(innerMs, ZipArchiveMode.Read);
                                var innerEntry = innerArchive.Entries.FirstOrDefault(e =>
                                    String.Equals(e.FullName, remainingPath, StringComparison.OrdinalIgnoreCase));

                                if (innerEntry != null)
                                {
                                    return (innerEntry.Length, innerEntry.LastWriteTime.DateTime, innerEntry.LastWriteTime.DateTime);
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
