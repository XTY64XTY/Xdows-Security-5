using System.Runtime.InteropServices;

namespace Protection;

public enum NativeModelScannerMode
{
    Standard = 0,
    Flash = 1,
    Pro = 2,
    Adaptive = 3
}

/// <summary>
/// 原生库状态码，与 xdows_model_native.h 的 <c>XDOWS_MODEL_NATIVE_STATUS</c> 一一对应。
/// </summary>
public enum NativeModelStatus
{
    Ok = 0,
    InvalidArgument = 1,
    FileNotFound = 2,
    UnsupportedFile = 3,
    ModelNotFound = 4,
    InternalError = 5,
    ModelManifestInvalid = 6
}

/// <summary>
/// 三档判定，与 xdows_model_native.h 的 <c>XDOWS_MODEL_NATIVE_VERDICT</c> 一一对应。
/// </summary>
public enum NativeModelVerdict
{
    Clean = 0,
    Suspicious = 1,
    Malware = 2
}

public sealed record NativeModelScannerResult(
    bool IsThreat,
    double Probability,
    string DetectionName,
    bool UsedNativeEngine,
    string? ErrorMessage,
    NativeModelStatus Status,
    NativeModelVerdict Verdict);

public sealed class NativeModelScanner : IDisposable
{
    private const string NativeDllName = NativeModelLibraryLoader.NativeDllName;

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
            // Pre-load the native library through the resilient loader first. This
            // works around Win32 1346 (ERROR_BAD_IMPERSONATION_LEVEL) failures that
            // the default P/Invoke resolution hits when the calling thread carries a
            // degraded impersonation token or the binaries live on a network path.
            NativeModelLibraryLoader.EnsureLoaded();
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
            return Benign(NativeModelStatus.FileNotFound, _nativeReady);

        if (!_nativeReady)
            return new NativeModelScannerResult(
                false,
                0,
                string.Empty,
                false,
                $"native-not-ready:{_nativeInitializationError ?? "unknown"}",
                NativeModelStatus.InternalError,
                NativeModelVerdict.Clean);

        try
        {
            // 版本化 Size 协议：必须先把 Size 声明为本结构大小，原生库才会写回
            // Verdict；Size 不足时只写旧字段，避免越界写内存。
            NativeScanResult nativeResult = NativeScanResult.Create();
            int status = XdowsModelNativeScanFile(_session, path, ref nativeResult);
            string detectionName = NormalizeDetectionName(PtrToStringAndFree(nativeResult.DetectionName));
            string? error = PtrToStringAndFree(nativeResult.ErrorMessage);

            NativeModelStatus callStatus = (NativeModelStatus)status;
            NativeModelStatus resultStatus = (NativeModelStatus)nativeResult.Status;
            NativeModelVerdict verdict = (NativeModelVerdict)nativeResult.Verdict;

            if (status == 0 && nativeResult.Status == 0)
            {
                return new NativeModelScannerResult(
                    nativeResult.IsThreat != 0,
                    nativeResult.Probability,
                    detectionName,
                    true,
                    error,
                    NativeModelStatus.Ok,
                    verdict);
            }

            NativeModelStatus failureStatus = callStatus != NativeModelStatus.Ok ? callStatus : resultStatus;

            // 非 PE/空文件（UnsupportedFile）与文件不存在不是模型基础设施故障，
            // 而是「这个文件不参与模型判定」：按无威胁返回且不带错误信息，
            // 让驱动侧正常放行，而不是 fail-open 并误记为基础设施错误。
            if (failureStatus is NativeModelStatus.UnsupportedFile or NativeModelStatus.FileNotFound)
                return Benign(failureStatus, true);

            return new NativeModelScannerResult(
                false,
                0,
                detectionName,
                true,
                error ?? $"native-status:{status}/{nativeResult.Status}",
                failureStatus,
                verdict);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException or BadImageFormatException)
        {
            _nativeReady = false;
            _nativeInitializationError = $"native-scan-exception:{ex.GetType().Name}:{ex.Message}";
            return new NativeModelScannerResult(
                false,
                0,
                string.Empty,
                true,
                _nativeInitializationError,
                NativeModelStatus.InternalError,
                NativeModelVerdict.Clean);
        }
    }

    /// <summary>
    /// 「不是威胁，也不是故障」的结果：文件不存在或不是 PE。ErrorMessage 保持为空，
    /// 避免驱动侧把它归因为模型基础设施错误而触发 fail-open。
    /// </summary>
    private static NativeModelScannerResult Benign(NativeModelStatus status, bool usedNativeEngine)
    {
        return new NativeModelScannerResult(
            false,
            0,
            string.Empty,
            usedNativeEngine,
            null,
            status,
            NativeModelVerdict.Clean);
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
    private struct NativeScanResult
    {
        public int Size;
        public int Status;
        public int IsThreat;
        public float Probability;
        public IntPtr DetectionName;
        public IntPtr ErrorMessage;
        public int Verdict;

        /// <summary>按版本化协议声明自身大小，使原生库写回 Verdict。</summary>
        public static NativeScanResult Create()
        {
            NativeScanResult result = default;
            result.Size = Marshal.SizeOf<NativeScanResult>();
            return result;
        }
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
        ref NativeScanResult result);

    [DllImport(NativeDllName, CallingConvention = CallingConvention.StdCall)]
    private static extern void XdowsModelNativeShutdown(IntPtr session);

    [DllImport(NativeDllName, CallingConvention = CallingConvention.StdCall)]
    private static extern void XdowsModelNativeFreeString(IntPtr value);
}
