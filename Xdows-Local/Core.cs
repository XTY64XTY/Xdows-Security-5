using PeNet;
using System.Buffers;

namespace Xdows_Local
{
    public static class Core
    {
        public record PEInfo
        {
            public String[]? ImportsDll;
            public String[]? ImportsName;
            public String[]? ExportsName;
        }

        public static String ScanAsync(String path, Boolean deep, Boolean extraData)
        {
            if (!File.Exists(path)) return String.Empty;
            try
            {
                const Int32 BufferSize = 65536; // 64KB buffer
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize);
                using var ms = new MemoryStream();
                var buffer = ArrayPool<Byte>.Shared.Rent(BufferSize);
                try
                {
                    Int32 bytesRead;
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
            catch { return String.Empty; }
        }

        public static String ScanFromBytes(String path, Byte[] fileBytes, Boolean deep, Boolean extraData)
        {
            if (fileBytes.Length == 0) return String.Empty;

            if (!PeFile.IsPeFile(fileBytes))
            {
                try
                {
                    (Int32 score, String extra) scriptScanResult = ScriptScan.ScanScriptFile(path, fileBytes);
                    if (scriptScanResult.score >= 100)
                    {
                        return extraData ? $"Xdows.script.code{scriptScanResult.score} {scriptScanResult.extra}" : $"Xdows.script.code{scriptScanResult.score}";
                    }
                    return String.Empty;
                }
                catch
                {
                    return String.Empty;
                }
            }

            PeFile peFile = new(fileBytes);
            PEInfo fileInfo = new();

            if (peFile.IsDll)
            {
                IReadOnlyList<PeNet.Header.Pe.ExportFunction>? exports = peFile.ExportedFunctions;
                if (exports != null)
                {
                    fileInfo.ExportsName = [.. exports.Select(exported => exported.Name ?? String.Empty)];
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
                fileInfo.ImportsName = [.. validImports.Select(import => import.Name ?? String.Empty)];
            }
            else
            {
                fileInfo.ImportsDll = [];
                fileInfo.ImportsName = [];
            }

            (Int32 score, String extra) score = Heuristic.Evaluate(path, peFile, fileInfo, deep);
            if (score.score >= 100)
            {
                return extraData ? $"Xdows.local.code{score.score} {score.extra}" : $"Xdows.local.code{score.score}";
            }

            return String.Empty;
        }
    }
}
