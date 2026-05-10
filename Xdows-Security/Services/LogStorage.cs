using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;

namespace Xdows_Security.Services
{
    public record LogEntry
    {
        public long Id { get; init; }
        public DateTime Time { get; init; }
        public LogText.LogLevel Level { get; init; }
        public string Source { get; init; } = "";
        public string Text { get; init; } = "";
        public int ThreadId { get; init; }
        public string Formatted => $"[{Time:yyyy-MM-dd HH:mm:ss}][{Level}][{Source}][T:{ThreadId}]: {Text}";
    }

    public record LogDateStats
    {
        public string Date { get; init; } = "";
        public int Count { get; init; }
        public long MinId { get; init; }
        public long MaxId { get; init; }
    }

    public static class LogStorage
    {
        public static readonly string DbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Xdows-Security", "logs.db");

        static LogStorage()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DbPath)!);

            using var conn = GetConnection();
            conn.Open();

            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS logs (
                        id        INTEGER PRIMARY KEY AUTOINCREMENT,
                        time      TEXT    NOT NULL,
                        level     INTEGER NOT NULL,
                        source    TEXT    NOT NULL,
                        text      TEXT    NOT NULL,
                        thread_id INTEGER NOT NULL
                    )";
                cmd.ExecuteNonQuery();
            }

            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
                    CREATE INDEX IF NOT EXISTS idx_logs_time   ON logs(time);
                    CREATE INDEX IF NOT EXISTS idx_logs_level  ON logs(level);
                    CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)";
                cmd.ExecuteNonQuery();
            }

            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "PRAGMA journal_mode=WAL";
                cmd.ExecuteNonQuery();
            }
        }

        public static SqliteConnection GetConnection() => new($"Data Source={DbPath}");

        public static void InsertBatch(SqliteConnection conn, List<LogEntry> entries)
        {
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO logs (time, level, source, text, thread_id)
                VALUES (@time, @level, @source, @text, @threadId)";

            var pTime = cmd.Parameters.Add("@time", SqliteType.Text);
            var pLevel = cmd.Parameters.Add("@level", SqliteType.Integer);
            var pSource = cmd.Parameters.Add("@source", SqliteType.Text);
            var pText = cmd.Parameters.Add("@text", SqliteType.Text);
            var pThreadId = cmd.Parameters.Add("@threadId", SqliteType.Integer);

            foreach (var e in entries)
            {
                pTime.Value = e.Time.ToString("o");
                pLevel.Value = (int)e.Level;
                pSource.Value = e.Source;
                pText.Value = e.Text;
                pThreadId.Value = e.ThreadId;
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }

        public static List<LogEntry> GetLatestLogs(SqliteConnection conn, int count,
            LogText.LogLevel[]? levels = null, string? keyword = null)
        {
            var (where, args) = BuildWhere(levels, keyword);
            var sql = $"SELECT * FROM logs{where} ORDER BY id DESC LIMIT @count";

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            AddWhereParams(cmd, args);
            cmd.Parameters.AddWithValue("@count", count);

            var result = ReadEntries(cmd);
            result.Reverse();
            return result;
        }

        public static List<LogEntry> GetOlderLogs(SqliteConnection conn, long beforeId, int count,
            LogText.LogLevel[]? levels = null, string? keyword = null)
        {
            var (where, args) = BuildWhere(levels, keyword);
            var sql = $"SELECT * FROM logs{where} AND id < @beforeId ORDER BY id DESC LIMIT @count";

            if (string.IsNullOrEmpty(where))
                sql = $"SELECT * FROM logs WHERE id < @beforeId ORDER BY id DESC LIMIT @count";

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            AddWhereParams(cmd, args);
            cmd.Parameters.AddWithValue("@beforeId", beforeId);
            cmd.Parameters.AddWithValue("@count", count);

            var result = ReadEntries(cmd);
            result.Reverse();
            return result;
        }

        public static int DeleteLogsByDate(SqliteConnection conn, string date)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM logs WHERE date(time) = @date";
            cmd.Parameters.AddWithValue("@date", date);
            return cmd.ExecuteNonQuery();
        }

        public static int DeleteLogsByDateRange(SqliteConnection conn, string fromDate, string toDate)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM logs WHERE date(time) BETWEEN @fromDate AND @toDate";
            cmd.Parameters.AddWithValue("@fromDate", fromDate);
            cmd.Parameters.AddWithValue("@toDate", toDate);
            return cmd.ExecuteNonQuery();
        }

        public static int DeleteAll(SqliteConnection conn)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM logs";
            return cmd.ExecuteNonQuery();
        }

        public static List<LogDateStats> GetDateStats(SqliteConnection conn)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT date(time) AS d, COUNT(*) AS cnt, MIN(id) AS minId, MAX(id) AS maxId
                FROM logs
                GROUP BY d
                ORDER BY d DESC";

            var result = new List<LogDateStats>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                result.Add(new LogDateStats
                {
                    Date = reader.GetString(0),
                    Count = reader.GetInt32(1),
                    MinId = reader.GetInt64(2),
                    MaxId = reader.GetInt64(3)
                });
            }
            return result;
        }

        public static long GetTotalCount(SqliteConnection conn,
            LogText.LogLevel[]? levels = null, string? keyword = null)
        {
            var (where, args) = BuildWhere(levels, keyword);
            var sql = $"SELECT COUNT(*) FROM logs{where}";

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            AddWhereParams(cmd, args);

            return (long)cmd.ExecuteScalar()!;
        }

        private static (string where, List<(string name, object value)> args) BuildWhere(
            LogText.LogLevel[]? levels, string? keyword)
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

            var where = conditions.Count > 0
                ? " WHERE " + string.Join(" AND ", conditions)
                : "";
            return (where, args);
        }

        private static void AddWhereParams(SqliteCommand cmd, List<(string name, object value)> args)
        {
            foreach (var (name, value) in args)
                cmd.Parameters.AddWithValue(name, value);
        }

        private static List<LogEntry> ReadEntries(SqliteCommand cmd)
        {
            var result = new List<LogEntry>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                result.Add(new LogEntry
                {
                    Id = reader.GetInt64(0),
                    Time = DateTime.Parse(reader.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                    Level = (LogText.LogLevel)reader.GetInt32(2),
                    Source = reader.GetString(3),
                    Text = reader.GetString(4),
                    ThreadId = reader.GetInt32(5)
                });
            }
            return result;
        }
    }
}
