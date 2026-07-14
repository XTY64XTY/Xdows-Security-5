using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Xdows_Security.Services
{
    public static class LogService
    {
        private const int BATCH_SIZE = 50;

        private abstract record LogQueueItem;
        private sealed record PendingLog(LogEntry Entry) : LogQueueItem;
        private sealed record FlushRequest(TaskCompletionSource<bool> Completion) : LogQueueItem;

        private static readonly Channel<LogQueueItem> _writeChannel = Channel.CreateUnbounded<LogQueueItem>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });

        public static event EventHandler<LogEntry>? LogAdded;

        static LogService()
        {
            _ = Task.Run(WritePumpAsync);
        }

        public static void AddLog(LogText.LogLevel level, string source, string text)
        {
            var entry = new LogEntry
            {
                Time = DateTime.Now,
                Level = level,
                Source = source,
                Text = text,
                ThreadId = Environment.CurrentManagedThreadId
            };
            _writeChannel.Writer.TryWrite(new PendingLog(entry));
            LogAdded?.Invoke(null, entry);
        }

        public static async Task FlushAsync(CancellationToken token = default)
        {
            var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            await _writeChannel.Writer
                .WriteAsync(new FlushRequest(completion), token)
                .ConfigureAwait(false);
            await completion.Task.WaitAsync(token).ConfigureAwait(false);
        }

        public static List<LogEntry> GetLatestLogs(int count, LogText.LogLevel[]? levels = null, string? keyword = null)
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                return LogStorage.GetLatestLogs(conn, count, levels, keyword);
            }
            catch
            {
                return [];
            }
        }

        public static List<LogEntry> GetOlderLogs(long beforeId, int count, LogText.LogLevel[]? levels = null, string? keyword = null)
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                return LogStorage.GetOlderLogs(conn, beforeId, count, levels, keyword);
            }
            catch
            {
                return [];
            }
        }

        public static void DeleteLogsByDate(string date)
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                LogStorage.DeleteLogsByDate(conn, date);
            }
            catch { }
        }

        public static void DeleteLogsByDateRange(string fromDate, string toDate)
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                LogStorage.DeleteLogsByDateRange(conn, fromDate, toDate);
            }
            catch { }
        }

        public static void ClearAll()
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                LogStorage.DeleteAll(conn);
            }
            catch { }
        }

        public static List<LogDateStats> GetDateStats()
        {
            try
            {
                using var conn = LogStorage.GetConnection();
                conn.Open();
                conn.DefaultTimeout = 5;
                return LogStorage.GetDateStats(conn);
            }
            catch
            {
                return [];
            }
        }

        public static async Task ExportAsync(string filePath, LogText.LogLevel[]? levels = null,
            string? keyword = null, string? fromDate = null, string? toDate = null,
            CancellationToken token = default)
        {
            await FlushAsync(token).ConfigureAwait(false);

            using var conn = LogStorage.GetConnection();
            await conn.OpenAsync(token).ConfigureAwait(false);
            conn.DefaultTimeout = 5;
            await using var writer = new StreamWriter(filePath, append: false);

            var (where, args) = BuildExportWhere(levels, keyword, fromDate, toDate);
            var sql = $"SELECT * FROM logs{where} ORDER BY id ASC";

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            foreach (var (name, value) in args)
                cmd.Parameters.AddWithValue(name, value);

            await using var reader = await cmd.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                var entry = new LogEntry
                {
                    Id = reader.GetInt64(0),
                    Time = DateTime.Parse(reader.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                    Level = (LogText.LogLevel)reader.GetInt32(2),
                    Source = reader.GetString(3),
                    Text = reader.GetString(4),
                    ThreadId = reader.GetInt32(5)
                };
                await writer.WriteLineAsync(entry.Formatted.AsMemory(), token).ConfigureAwait(false);
            }
        }

        private static async Task WritePumpAsync()
        {
            var batch = new List<LogEntry>(BATCH_SIZE);
            Exception? writeError = null;

            while (await _writeChannel.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                while (_writeChannel.Reader.TryRead(out LogQueueItem? item))
                {
                    switch (item)
                    {
                        case PendingLog pending:
                            batch.Add(pending.Entry);
                            if (batch.Count >= BATCH_SIZE)
                                PersistPendingBatch(batch, ref writeError);
                            break;

                        case FlushRequest flush:
                            PersistPendingBatch(batch, ref writeError);
                            if (writeError is null)
                                flush.Completion.TrySetResult(true);
                            else
                                flush.Completion.TrySetException(
                                    new InvalidOperationException("Pending logs could not be persisted before export.", writeError));
                            break;
                    }
                }

                PersistPendingBatch(batch, ref writeError);
            }
        }

        private static void PersistPendingBatch(List<LogEntry> batch, ref Exception? writeError)
        {
            if (batch.Count == 0)
                return;

            Exception? lastError = null;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using var conn = LogStorage.GetConnection();
                    conn.Open();
                    conn.DefaultTimeout = 5;
                    LogStorage.InsertBatch(conn, batch);
                    batch.Clear();
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            batch.Clear();
            writeError = lastError;
        }

        private static (string where, List<(string name, object value)> args) BuildExportWhere(
            LogText.LogLevel[]? levels, string? keyword, string? fromDate, string? toDate)
        {
            var conditions = new List<string>();
            var args = new List<(string, object)>();

            if (levels is { Length: > 0 })
            {
                var paramNames = new List<string>();
                for (int i = 0; i < levels.Length; i++)
                {
                    var pName = $"@lv{i}";
                    paramNames.Add(pName);
                    args.Add((pName, (int)levels[i]));
                }
                conditions.Add($"level IN ({string.Join(",", paramNames)})");
            }

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                conditions.Add("text LIKE @kw");
                args.Add(("@kw", $"%{keyword}%"));
            }

            if (!string.IsNullOrWhiteSpace(fromDate))
            {
                conditions.Add("date(time) >= @fromDate");
                args.Add(("@fromDate", fromDate));
            }

            if (!string.IsNullOrWhiteSpace(toDate))
            {
                conditions.Add("date(time) <= @toDate");
                args.Add(("@toDate", toDate));
            }

            var where = conditions.Count > 0
                ? " WHERE " + string.Join(" AND ", conditions)
                : "";
            return (where, args);
        }
    }
}
