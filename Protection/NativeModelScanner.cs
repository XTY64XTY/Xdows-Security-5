using System.Runtime.InteropServices;

namespace Protection;

public enum NativeModelScannerMode
{
    Standard = 0,
    Flash = 1,
    Pro = 2
}

public sealed record NativeModelScannerResult(
    bool IsThreat,
    double Probability,
    string DetectionName,
    bool UsedNativeEngine,
    string? ErrorMessage);

public sealed class NativeModelScanner : IDisposable
{
    private const string NativeDllName = "Xdows-Model-Native.dll";

    private IntPtr _session;
    private bool _nativeReady;
    private string? _nativeInitializationError;
    private readonly NativeModelScannerMode _mode;

    public bool NativeReady => _nativeReady;
    public string? InitializationError => _nativeInitializationError;
    public NativeModelScannerMode Mode => _mode;

    public NativeModelScanner(NativeModelScannerMode mode = NativeModelScannerMode.Standard, string? modelDirectory = null)
    {
        _mode = mode;

        try
        {
            int status = XdowsModelNativeInitialize(modelDirectory, (int)mode, out _session);
            _nativeReady = status == 0 && _session != IntPtr.Zero;
            if (!_nativeReady)
                _nativeInitializationError = $"native-init-status:{status}";
        }
        catch (DllNotFoundException ex)
        {
            _nativeReady = false;
            _nativeInitializationError = $"native-init-exception:{ex.GetType().Name}:{ex.Message}";
        }
        catch (EntryPointNotFoundException ex)
        {
            _nativeReady = false;
            _nativeInitializationError = $"native-init-exception:{ex.GetType().Name}:{ex.Message}";
        }
        catch (Exception ex)
        {
            _nativeReady = false;
            _nativeInitializationError = $"native-init-exception:{ex.GetType().Name}:{ex.Message}";
        }
    }

    public NativeModelScannerResult ScanFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new NativeModelScannerResult(false, 0, string.Empty, _nativeReady, "file-not-found");

        if (!_nativeReady)
            return new NativeModelScannerResult(
                false,
                0,
                string.Empty,
                false,
                $"native-not-ready:{_nativeInitializationError ?? "unknown"}");

        try
        {
            int status = XdowsModelNativeScanFile(_session, path, out XdowsNativeScanResult nativeResult);
            string detectionName = NormalizeDetectionName(PtrToStringAndFree(nativeResult.DetectionName));
            string? error = PtrToStringAndFree(nativeResult.ErrorMessage);

            if (status == 0 && nativeResult.Status == 0)
            {
                return new NativeModelScannerResult(
                    nativeResult.IsThreat != 0,
                    nativeResult.Probability,
                    detectionName,
                    true,
                    error);
            }

            return new NativeModelScannerResult(false, 0, detectionName, true, error ?? $"native-status:{status}/{nativeResult.Status}");
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException or BadImageFormatException)
        {
            _nativeReady = false;
            _nativeInitializationError = $"native-scan-exception:{ex.GetType().Name}:{ex.Message}";
            return new NativeModelScannerResult(false, 0, string.Empty, true, _nativeInitializationError);
        }
    }

    public void Dispose()
    {
        if (_session != IntPtr.Zero)
        {
            try
            {
                XdowsModelNativeShutdown(_session);
            }
            catch
            {
            }

            _session = IntPtr.Zero;
        }

        _nativeReady = false;
    }

    private static string PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return string.Empty;

        try
        {
            return Marshal.PtrToStringUni(ptr) ?? string.Empty;
        }
        finally
        {
            try
            {
                XdowsModelNativeFreeString(ptr);
            }
            catch
            {
            }
        }
    }

    private static string NormalizeDetectionName(string detectionName)
    {
        return detectionName.Replace("Xdows.Model.Native.", "Xdows.Model.", StringComparison.Ordinal);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct XdowsNativeScanResult
    {
        public int Size;
        public int Status;
        public int IsThreat;
        public float Probability;
        public IntPtr DetectionName;
        public IntPtr ErrorMessage;
    }

    [DllImport(NativeDllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    private static extern int XdowsModelNativeInitialize(
        string? modelDirectory,
        int mode,
        out IntPtr session);

    [DllImport(NativeDllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    private static extern int XdowsModelNativeScanFile(
        IntPtr session,
        string filePath,
        out XdowsNativeScanResult result);

    [DllImport(NativeDllName, CallingConvention = CallingConvention.StdCall)]
    private static extern void XdowsModelNativeShutdown(IntPtr session);

    [DllImport(NativeDllName, CallingConvention = CallingConvention.StdCall)]
    private static extern void XdowsModelNativeFreeString(IntPtr value);
}
