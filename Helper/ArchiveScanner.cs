using SharpCompress.Archives;
using SharpCompress.Readers;
using System.Buffers;
using System.IO.Compression;
using System.Text;

namespace Helper
{
    /// <summary>
    /// 通用归档文件扫描支持 —— 在 ZipScanner 基础上扩展 7z / TAR / GZip / BZip2 / XZ 等格式。
    /// 复用 ZipScanner 已有的魔数检测、编码回退、ArrayPool 缓冲等最佳实践。
    /// </summary>
    public static class ArchiveScanner
    {
        private const Int64 MaxEntrySize = 100 * 1024 * 1024; // 100MB limit per entry
        private const Int32 BufferSize = 262144; // 256KB buffer for streaming

        private static readonly byte[] Magic7z = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        private static readonly byte[] MagicGz = [0x1F, 0x8B];
        private static readonly byte[] MagicBz2 = [0x42, 0x5A];
        private static readonly byte[] MagicPk03 = [0x50, 0x4B, 0x03, 0x04];
        private static readonly byte[] MagicPk05 = [0x50, 0x4B, 0x05, 0x06];
        private static readonly byte[] MagicPk07 = [0x50, 0x4B, 0x07, 0x08];
        private static readonly byte[] MagicXz = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

        /// <summary>
        /// 检测文件是否为支持的归档格式。
        /// </summary>
        public static bool IsArchiveFile(string filePath)
        {
            if (!File.Exists(filePath)) return false;

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length < 2) return false;

                var buffer = ArrayPool<byte>.Shared.Rent(8);
                try
                {
                    int bytesRead = fs.Read(buffer, 0, 8);
                    if (bytesRead < 2) return false;

                    if (MatchesBytes(buffer, bytesRead, Magic7z)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicGz)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicBz2)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicPk03)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicPk05)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicPk07)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicXz)) return true;

                    var ext = Path.GetExtension(filePath).ToLowerInvariant();
                    return ext is ".tar" or ".tgz" or ".tbz2" or ".txz";
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool MatchesBytes(byte[] buffer, int length, byte[] magic)
        {
            if (length < magic.Length) return false;
            for (int i = 0; i < magic.Length; i++)
            {
                if (buffer[i] != magic[i]) return false;
            }
            return true;
        }

        /// <summary>
        /// 读取归档文件中所有条目的路径和字节数据。
        /// 支持嵌套归档递归展开。
        /// </summary>
        public static async Task<List<(string EntryPath, byte[] Data)>> ReadArchiveEntriesAsync(
            string archivePath,
            bool scanNestedArchives = false,
            string? password = null,
            CancellationToken ct = default)
        {
            var entries = new List<(string EntryPath, byte[] Data)>();
            bool hasEncryptedEntries = false;

            await Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var options = new ReaderOptions();
                    if (!string.IsNullOrEmpty(password))
                        options.Password = password;

                    using var archive = ArchiveFactory.Open(archivePath, options);

                    foreach (var entry in archive.Entries)
                    {
                        if (entry.IsDirectory) continue;

                        // 检测加密条目（头部未加密但内容加密）
                        if (entry.IsEncrypted && string.IsNullOrEmpty(password))
                        {
                            hasEncryptedEntries = true;
                            continue;
                        }

                        // 大小检查
                        var fileSize = entry.Size;
                        if (fileSize > MaxEntrySize) continue;

                        string entryPath;
                        try
                        {
                            entryPath = DecodeEntryKey(entry.Key);
                        }
                        catch
                        {
                            entryPath = (entry.Key ?? "").Replace('/', '\\');
                        }

                        try
                        {
                            byte[]? data = null;
                            if (scanNestedArchives && IsNestedArchive(entry))
                            {
                                data = ReadEntryToBytes(entry);
                                if (data != null)
                                {
                                    var nestedEntries = ReadNestedArchiveEntries(data, entryPath, password);
                                    lock (entries) entries.AddRange(nestedEntries);
                                }
                            }
                            else
                            {
                                data = ReadEntryToBytes(entry);
                                if (data != null) lock (entries) entries.Add((entryPath, data));
                            }
                        }
                        catch (InvalidOperationException ex) when (ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase))
                        {
                            // 密码异常需要向上传播，以便弹出密码对话框
                            throw;
                        }
                        catch (Exception)
                        {
                            // Skip entries that fail to read
                        }
                    }

                    // 如果有加密条目但未提供密码，抛出异常以便上层弹出密码对话框
                    if (hasEncryptedEntries && entries.Count == 0 && string.IsNullOrEmpty(password))
                    {
                        throw new InvalidOperationException("The archive contains encrypted entries. Please supply a password.");
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception)
                {
                    // Silently skip unreadable archives
                    throw;
                }
            }, ct);

            return entries;
        }

        /// <summary>
        /// 检测文件是否为 7z 格式。
        /// </summary>
        public static bool IsSevenZipFile(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length < 6) return false;
                var buffer = ArrayPool<byte>.Shared.Rent(6);
                try
                {
                    if (fs.Read(buffer, 0, 6) >= 6)
                        return buffer[0] == 0x37 && buffer[1] == 0x7A && buffer[2] == 0xBC
                            && buffer[3] == 0xAF && buffer[4] == 0x27 && buffer[5] == 0x1C;
                    return false;
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            catch { return false; }
        }

        // ==================== 通用工具方法 ====================

        private static string DecodeEntryKey(string? key)
        {
            if (string.IsNullOrEmpty(key)) return key ?? "";

            try
            {
                var keyBytes = Encoding.UTF8.GetBytes(key);
                // 尝试直接 UTF-8
                string utf8Result = Encoding.UTF8.GetString(keyBytes);
                if (!utf8Result.Contains('\uFFFD') && !utf8Result.Contains('?'))
                    return utf8Result.Replace('/', '\\');

                // 回退编码
                foreach (var encName in new[] { "gb2312", "gbk", "big5" })
                {
                    try
                    {
                        var decoded = Encoding.GetEncoding(encName).GetString(keyBytes);
                        if (!decoded.Contains('\uFFFD') && !decoded.Contains('?'))
                            return decoded.Replace('/', '\\');
                    }
                    catch { }
                }
                return utf8Result.Replace('/', '\\');
            }
            catch
            {
                return key.Replace('/', '\\');
            }
        }

        private static bool IsNestedArchive(IArchiveEntry entry)
        {
            try
            {
                using var stream = entry.OpenEntryStream();
                var buffer = ArrayPool<byte>.Shared.Rent(8);
                try
                {
                    int bytesRead = stream.Read(buffer, 0, 8);
                    if (bytesRead < 2) return false;

                    if (MatchesBytes(buffer, bytesRead, Magic7z)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicPk03)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicGz)) return true;
                    if (MatchesBytes(buffer, bytesRead, MagicBz2)) return true;
                    if (bytesRead >= 6 && MatchesBytes(buffer, bytesRead, MagicXz)) return true;
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
                return false;
            }
            catch { return false; }
        }

        private static bool IsPasswordException(Exception ex)
        {
            return ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("crypt", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("加密", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("解密", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("decrypt", StringComparison.OrdinalIgnoreCase) ||
                   (ex.InnerException != null && IsPasswordException(ex.InnerException));
        }

        private static byte[]? ReadEntryToBytes(IArchiveEntry entry)
        {
            try
            {
                using var stream = entry.OpenEntryStream();
                var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
                try
                {
                    using var ms = new MemoryStream();
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, BufferSize)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                        if (ms.Length > MaxEntrySize) return null;
                    }
                    return ms.ToArray();
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            catch (Exception ex) when (IsPasswordException(ex))
            {
                throw new InvalidOperationException("The archive entry is encrypted. Please supply a password.", ex);
            }
            catch { return null; }
        }

        // ==================== 嵌套归档检测 ====================

        private static List<(string EntryPath, byte[] Data)> ReadNestedArchiveEntries(
            byte[] archiveData,
            string parentPath,
            string? password = null)
        {
            var entries = new List<(string EntryPath, byte[] Data)>();
            try
            {
                using var ms = new MemoryStream(archiveData);

                var buffer = ArrayPool<byte>.Shared.Rent(8);
                try
                {
                    int bytesRead = ms.Read(buffer, 0, 8);
                    ms.Position = 0;

                    var options = new ReaderOptions();
                    if (!string.IsNullOrEmpty(password))
                        options.Password = password;

                    // 检测嵌套类型
                    if (bytesRead >= 6 && MatchesBytes(buffer, bytesRead, Magic7z))
                    {
                        using var archive = ArchiveFactory.Open(ms, options);
                        foreach (var entry in archive.Entries)
                        {
                            if (entry.IsDirectory) continue;
                            string fullPath = DecodeEntryKey(entry.Key);
                            string entryPath = parentPath + "\\" + fullPath;
                            try
                            {
                                var data = ReadSharpCompressEntryToBytes(entry);
                                if (data != null) lock (entries) entries.Add((entryPath, data));
                            }
                            catch (InvalidOperationException ex) when (ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase))
                            {
                                throw;
                            }
                            catch { }
                        }
                    }
                    else if (bytesRead >= 4 && MatchesBytes(buffer, bytesRead, MagicPk03))
                    {
                        ms.Position = 0;
                        using var zipArchive = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Read);
                        foreach (var entry in zipArchive.Entries)
                        {
                            if (entry.Length > 0 && !entry.Name.EndsWith('/'))
                            {
                                string fullPath = DecodeZipEntryName(entry);
                                string entryPath = parentPath + "\\" + fullPath;
                                try
                                {
                                    var data = ReadSystemZipEntryToBytes(entry);
                                    if (data != null) lock (entries) entries.Add((entryPath, data));
                                }
                                catch { }
                            }
                        }
                    }
                    else
                    {
                        ms.Position = 0;
                        using var archive = ArchiveFactory.Open(ms, options);
                        foreach (var entry in archive.Entries)
                        {
                            if (entry.IsDirectory) continue;
                            string fullPath = DecodeEntryKey(entry.Key);
                            string entryPath = parentPath + "\\" + fullPath;
                            try
                            {
                                var data = ReadSharpCompressEntryToBytes(entry);
                                if (data != null) lock (entries) entries.Add((entryPath, data));
                            }
                            catch (InvalidOperationException ex) when (ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase))
                            {
                                throw;
                            }
                            catch { }
                        }
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            catch (Exception) { }
            return entries;
        }

        private static byte[]? ReadSharpCompressEntryToBytes(IArchiveEntry entry)
        {
            try
            {
                using var stream = entry.OpenEntryStream();
                var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
                try
                {
                    using var ms = new MemoryStream();
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, BufferSize)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                        if (ms.Length > MaxEntrySize) return null;
                    }
                    return ms.ToArray();
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            catch (Exception ex) when (IsPasswordException(ex))
            {
                throw new InvalidOperationException("The archive entry is encrypted. Please supply a password.", ex);
            }
            catch { return null; }
        }

        private static string DecodeZipEntryName(System.IO.Compression.ZipArchiveEntry entry)
        {
            try
            {
                var nameField = typeof(System.IO.Compression.ZipArchiveEntry).GetField(
                    "_storedEntryNameBytes",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (nameField == null) return entry.Name.Replace('/', '\\');

                if (nameField.GetValue(entry) is not byte[] nameBytes || nameBytes.Length == 0) return entry.Name.Replace('/', '\\');

                string utf8Result = Encoding.UTF8.GetString(nameBytes);
                if (!utf8Result.Contains('\uFFFD') && !utf8Result.Contains('?'))
                    return utf8Result.Replace('/', '\\');

                foreach (var enc in new[] { "gb2312", "gbk", "big5" })
                {
                    try
                    {
                        var decoded = Encoding.GetEncoding(enc).GetString(nameBytes);
                        if (!decoded.Contains('\uFFFD') && !decoded.Contains('?'))
                            return decoded.Replace('/', '\\');
                    }
                    catch { }
                }
                return utf8Result.Replace('/', '\\');
            }
            catch { return entry.Name.Replace('/', '\\'); }
        }

        private static byte[]? ReadSystemZipEntryToBytes(System.IO.Compression.ZipArchiveEntry entry)
        {
            try
            {
                if (entry.Length > MaxEntrySize) return null;

                using var stream = entry.Open();
                var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
                try
                {
                    using var ms = new MemoryStream();
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, BufferSize)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                        if (ms.Length > MaxEntrySize) return null;
                    }
                    return ms.ToArray();
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }
            catch { return null; }
        }

        // ==================== ZIP 专属方法（自 ZipScanner 合并） ====================

        private static readonly Encoding[] _fallbackEncodings;

        static ArchiveScanner()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            _fallbackEncodings =
            [
                Encoding.UTF8,
                Encoding.GetEncoding("gb2312"),
                Encoding.GetEncoding("gbk"),
                Encoding.GetEncoding("big5")
            ];
        }

        private static String DecodeEntryName(ZipArchiveEntry entry)
        {
            try
            {
                var nameField = typeof(ZipArchiveEntry).GetField("_storedEntryNameBytes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (nameField == null) return entry.FullName;

                var nameBytes = nameField.GetValue(entry) as Byte[];
                if (nameBytes == null || nameBytes.Length == 0) return entry.FullName;

                String utf8Result = Encoding.UTF8.GetString(nameBytes);
                if (!utf8Result.Contains('\uFFFD') && !utf8Result.Contains('?'))
                    return utf8Result;

                foreach (var enc in _fallbackEncodings)
                {
                    if (enc.CodePage == Encoding.UTF8.CodePage) continue;
                    try
                    {
                        String decoded = enc.GetString(nameBytes);
                        if (!decoded.Contains('\uFFFD') && !decoded.Contains('?'))
                            return decoded;
                    }
                    catch { }
                }

                return utf8Result;
            }
            catch
            {
                return entry.FullName;
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
                    using var ms = new MemoryStream();
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
            catch (Exception)
            {
                return null;
            }
        }

        public static async Task<Boolean> DeleteEntryFromZipAsync(String zipPath, String entryPath)
        {
            return await Task.Run(() =>
            {
                String tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                try
                {
                    using (var readArchive = ZipFile.OpenRead(zipPath))
                    using (var createArchive = ZipFile.Open(tempPath, ZipArchiveMode.Create))
                    {
                        foreach (var entry in readArchive.Entries)
                        {
                            String decodedName = DecodeEntryName(entry);
                            if (String.Equals(decodedName, entryPath, StringComparison.OrdinalIgnoreCase))
                                continue;

                            var newEntry = createArchive.CreateEntry(decodedName);
                            using var entryStream = entry.Open();
                            using var newEntryStream = newEntry.Open();
                            entryStream.CopyTo(newEntryStream);
                        }
                    }

                    File.Delete(zipPath);
                    File.Move(tempPath, zipPath);
                    return true;
                }
                catch (Exception)
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                    return false;
                }
            });
        }

        public static async Task<Int32> DeleteMultipleEntriesFromZipAsync(String zipPath, List<String> entryPaths)
        {
            return await Task.Run(() =>
            {
                String tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                try
                {
                    var entriesToDelete = new HashSet<String>(
                        entryPaths.Select(p => p.Replace('\\', '/')),
                        StringComparer.OrdinalIgnoreCase);
                    Int32 deletedCount = 0;

                    using (var readArchive = ZipFile.OpenRead(zipPath))
                    using (var createArchive = ZipFile.Open(tempPath, ZipArchiveMode.Create))
                    {
                        foreach (var entry in readArchive.Entries)
                        {
                            String decodedName = DecodeEntryName(entry);
                            if (entriesToDelete.Contains(decodedName))
                            {
                                deletedCount++;
                                continue;
                            }

                            var newEntry = createArchive.CreateEntry(decodedName);
                            using var entryStream = entry.Open();
                            using var newEntryStream = newEntry.Open();
                            entryStream.CopyTo(newEntryStream);
                        }
                    }

                    File.Delete(zipPath);
                    File.Move(tempPath, zipPath);
                    return deletedCount;
                }
                catch (Exception)
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
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
                        if (String.Equals(DecodeEntryName(entry), normalizedEntryPath, StringComparison.OrdinalIgnoreCase))
                        {
                            return ReadEntryData(entry);
                        }
                    }
                    return null;
                }
                catch (Exception)
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
                            String.Equals(DecodeEntryName(e), outerEntryPath, StringComparison.OrdinalIgnoreCase));

                        if (outerEntry == null)
                        {
                            outerEntryPath = normalizedEntryPath.Substring(0, innerZipIndex + 4).Replace(".zip/", "/");
                            outerEntry = outerArchive.Entries.FirstOrDefault(e =>
                                String.Equals(DecodeEntryName(e), outerEntryPath, StringComparison.OrdinalIgnoreCase) ||
                                String.Equals(DecodeEntryName(e), outerEntryPath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
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
                                        String.Equals(DecodeEntryName(e), remainingPath, StringComparison.OrdinalIgnoreCase));

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
                            catch (Exception) { }
                        }
                        return null;
                    }
                    else
                    {
                        using var archive = ZipFile.OpenRead(zipPath);

                        foreach (var entry in archive.Entries)
                        {
                            if (String.Equals(DecodeEntryName(entry), normalizedEntryPath, StringComparison.OrdinalIgnoreCase))
                            {
                                return (entry.Length, entry.LastWriteTime.DateTime, entry.LastWriteTime.DateTime);
                            }
                        }
                        return null;
                    }
                }
                catch (Exception)
                {
                    return null;
                }
            });
        }
    }
}
