using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Services;

internal enum SingleInstanceRequestKind
{
    Open,
    Scan
}

internal sealed record SingleInstanceRequest(
    SingleInstanceRequestKind Kind,
    IReadOnlyList<string> Paths);

internal static class SingleInstanceProtocol
{
    private const string OpenCommand = "OPEN";
    private const string ScanCommand = "SCAN";
    private const char LegacyPathSeparator = '\t';
    private const int MaximumPathCount = 1024;

    public static SingleInstanceRequest Create(IReadOnlyList<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return paths.Count == 0
            ? new SingleInstanceRequest(SingleInstanceRequestKind.Open, [])
            : new SingleInstanceRequest(SingleInstanceRequestKind.Scan, [.. paths]);
    }

    public static async Task WriteAsync(
        TextWriter writer,
        SingleInstanceRequest request,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(request);

        if (request.Kind == SingleInstanceRequestKind.Open)
        {
            await writer.WriteLineAsync(OpenCommand.AsMemory(), token).ConfigureAwait(false);
            return;
        }

        if (request.Paths.Count is 0 or > MaximumPathCount)
            throw new InvalidDataException("A scan request must contain between 1 and 1024 paths.");

        await writer.WriteLineAsync(ScanCommand.AsMemory(), token).ConfigureAwait(false);
        string count = request.Paths.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        await writer.WriteLineAsync(count.AsMemory(), token).ConfigureAwait(false);
        foreach (string path in request.Paths)
        {
            if (path.Contains('\r') || path.Contains('\n'))
                throw new InvalidDataException("A scan path cannot contain a line break.");
            await writer.WriteLineAsync(path.AsMemory(), token).ConfigureAwait(false);
        }
    }

    public static async Task<SingleInstanceRequest?> ReadAsync(
        TextReader reader,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        string? command = await reader.ReadLineAsync(token).ConfigureAwait(false);
        if (command is null)
            return null;

        if (string.Equals(command, OpenCommand, StringComparison.Ordinal))
            return new SingleInstanceRequest(SingleInstanceRequestKind.Open, []);

        if (string.Equals(command, ScanCommand, StringComparison.Ordinal))
        {
            string? countLine = await reader.ReadLineAsync(token).ConfigureAwait(false);
            if (!int.TryParse(countLine, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int count) ||
                count is <= 0 or > MaximumPathCount)
            {
                throw new InvalidDataException("The scan request path count is invalid.");
            }

            string[] paths = new string[count];
            for (int index = 0; index < paths.Length; index++)
            {
                paths[index] = await reader.ReadLineAsync(token).ConfigureAwait(false)
                    ?? throw new EndOfStreamException("The scan request ended before all paths were received.");
            }
            return new SingleInstanceRequest(SingleInstanceRequestKind.Scan, paths);
        }

        string[] legacyPaths = command.Split(LegacyPathSeparator, StringSplitOptions.RemoveEmptyEntries);
        return legacyPaths.Length == 0
            ? null
            : new SingleInstanceRequest(SingleInstanceRequestKind.Scan, legacyPaths);
    }
}
