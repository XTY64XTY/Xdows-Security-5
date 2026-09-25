using PeNet;
using System.Buffers;

namespace Xdows_Local
{
    public static class Core
    {
        public record PEInfo
        {
            public string[]? ImportsDll;
            public string[]? ImportsName;
            public string[]? ExportsName;
        }

        public static string Scan(string path, bool deep, bool extraData)
        {
            if (!File.Exists(path)) return string.Empty;
            try
            {
                const int BufferSize = 65536;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize);
                using var ms = new MemoryStream();
                var buffer = ArrayPool<Byte>.Shared.Rent(BufferSize);
                try
                {
                    int bytesRead;
                    while ((bytesRead = fs.Read(buffer, 0, BufferSize)) > 0)
                    {
                        ms.Write(buffer, 0, bytesRead);
                    }
                }
                finally
                {
                    ArrayPool<Byte>.Shared.Return(buffer);
                }
                Byte[] fileBytes = ms.ToArray();
                return ScanFromBytes(path, fileBytes, deep, extraData);
            }
            catch (Exception) { return string.Empty; }
        }

        public static string ScanFromBytes(string path, Byte[] fileBytes, bool deep, bool extraData)
        {
            if (fileBytes.Length == 0) return string.Empty;

            if (!PeFile.IsPeFile(fileBytes))
            {
                try
                {
                    (int score, string extra) scriptScanResult = ScriptScan.ScanScriptFile(path, fileBytes);
                    if (scriptScanResult.score >= 100)
                    {
                        return extraData ? $"Xdows.script.code{scriptScanResult.score} {scriptScanResult.extra}" : $"Xdows.script.code{scriptScanResult.score}";
                    }
                    return string.Empty;
                }
                catch (Exception) { return string.Empty; }
            }

            PeFile peFile = new(fileBytes);
            PEInfo fileInfo = new();

            if (peFile.IsDll)
            {
                IReadOnlyList<PeNet.Header.Pe.ExportFunction>? exports = peFile.ExportedFunctions;
                if (exports != null)
                {
                    fileInfo.ExportsName = [.. exports.Select(exported => exported.Name ?? string.Empty)];
                }
                else
                {
                    fileInfo.ExportsName = [];
                }
            }

            IReadOnlyList<PeNet.Header.Pe.ImportFunction>? importedFunctions = peFile.ImportedFunctions;
            if (importedFunctions != null)
            {
                List<PeNet.Header.Pe.ImportFunction> validImports = [.. importedFunctions.Where(import => import.Name != null)];

                fileInfo.ImportsDll = [.. validImports.Select(import => import.DLL)];
                fileInfo.ImportsName = [.. validImports.Select(import => import.Name ?? string.Empty)];
            }
            else
            {
                fileInfo.ImportsDll = [];
                fileInfo.ImportsName = [];
            }

            (int score, string extra) score = Heuristic.Evaluate(path, peFile, fileInfo, deep);
            if (score.score >= 100)
            {
                return extraData ? $"Xdows.local.code{score.score} {score.extra}" : $"Xdows.local.code{score.score}";
            }

            return string.Empty;
        }
    }
}
