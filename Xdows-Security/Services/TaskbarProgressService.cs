using Microsoft.UI.Dispatching;
using System;
using System.Runtime.InteropServices;
using System.Threading;
using WinRT.Interop;

namespace Xdows_Security.Services
{
    internal static class TaskbarProgressService
    {
        private static ITaskbarList3? _taskbar;
        private static bool _initialized;
        private static readonly object _lock = new();

        public static bool TrySetIndeterminate()
        {
            return RunOnMainWindowThread(() => TrySetProgressStateCore(TBPFLAG.TBPF_INDETERMINATE));
        }

        public static bool TrySetNormal(double progress01)
        {
            if (progress01 < 0) progress01 = 0;
            if (progress01 > 1) progress01 = 1;

            return RunOnMainWindowThread(() =>
            {
                if (!TrySetProgressStateCore(TBPFLAG.TBPF_NORMAL)) return false;

                try
                {
                    var hwnd = GetMainWindowHwnd();
                    if (hwnd == IntPtr.Zero) return false;
                    var tb = EnsureTaskbar();
                    if (tb == null) return false;

                    ulong completed = (ulong)Math.Round(progress01 * 1000);
                    ulong total = 1000;
                    tb.SetProgressValue(hwnd, completed, total);
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }

        public static bool TrySetPaused(double? progress01 = null)
        {
            return RunOnMainWindowThread(() =>
            {
                try
                {
                    if (progress01.HasValue)
                    {
                        if (progress01.Value < 0) progress01 = 0;
                        if (progress01.Value > 1) progress01 = 1;

                        var hwnd = GetMainWindowHwnd();
                        if (hwnd == IntPtr.Zero) return false;
                        var tb = EnsureTaskbar();
                        if (tb == null) return false;

                        ulong completed = (ulong)Math.Round(progress01.Value * 1000);
                        tb.SetProgressValue(hwnd, completed, 1000);
                    }

                    return TrySetProgressStateCore(TBPFLAG.TBPF_PAUSED);
                }
                catch
                {
                    return false;
                }
            });
        }

        public static bool TryClear()
        {
            return RunOnMainWindowThread(() => TrySetProgressStateCore(TBPFLAG.TBPF_NOPROGRESS));
        }

        private static bool TrySetProgressStateCore(TBPFLAG state)
        {
            try
            {
                var hwnd = GetMainWindowHwnd();
                if (hwnd == IntPtr.Zero)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", "MainWindow HWND is 0");
                    return false;
                }
                var tb = EnsureTaskbar();
                if (tb == null)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", "ITaskbarList3 init failed");
                    return false;
                }
                tb.SetProgressState(hwnd, state);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool RunOnMainWindowThread(Func<bool> action)
        {
            try
            {
                var window = App.MainWindow;
                DispatcherQueue? dq = window?.DispatcherQueue;

                if (dq == null)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", "MainWindow DispatcherQueue is null");
                    return false;
                }

                if (dq.HasThreadAccess)
                {
                    return action();
                }

                bool result = false;
                using var evt = new ManualResetEventSlim(false);
                bool enqueued = dq.TryEnqueue(() =>
                {
                    try { result = action(); }
                    catch { result = false; }
                    finally { evt.Set(); }
                });

                if (!enqueued)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", "DispatcherQueue.TryEnqueue failed");
                    return false;
                }

                if (!evt.Wait(1000))
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", "Taskbar action timed out");
                    return false;
                }

                return result;
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", ex.Message);
                return false;
            }
        }

        private static IntPtr GetMainWindowHwnd()
        {
            try
            {
                if (App.MainWindow == null) return IntPtr.Zero;
                return WindowNative.GetWindowHandle(App.MainWindow);
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private static ITaskbarList3? EnsureTaskbar()
        {
            lock (_lock)
            {
                if (_initialized) return _taskbar;
                _initialized = true;

                try
                {
                    _taskbar = (ITaskbarList3?)new CTaskbarList();
                    if (_taskbar == null) return null;

                    int hr = _taskbar.HrInit();
                    if (hr < 0)
                    {
                        LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", $"ITaskbarList3 HrInit failed: 0x{hr:X8}");
                        try { Marshal.FinalReleaseComObject(_taskbar); } catch { }
                        _taskbar = null;
                        return null;
                    }

                    return _taskbar;
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(LogText.LogLevel.WARN, "TaskbarProgress", $"ITaskbarList3 init exception: {ex.GetType().Name}: {ex.Message}");
                    _taskbar = null;
                    return null;
                }
            }
        }

        [ComImport]
        [Guid("56FDF344-FD6D-11d0-958A-006097C9A090")]
        private class CTaskbarList
        {
        }

        [ComImport]
        [Guid("EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ITaskbarList3
        {
            [PreserveSig]
            int HrInit();
            void AddTab(IntPtr hwnd);
            void DeleteTab(IntPtr hwnd);
            void ActivateTab(IntPtr hwnd);
            void SetActiveAlt(IntPtr hwnd);

            void MarkFullscreenWindow(IntPtr hwnd, [MarshalAs(UnmanagedType.Bool)] bool fFullscreen);

            void SetProgressValue(IntPtr hwnd, ulong ullCompleted, ulong ullTotal);
            void SetProgressState(IntPtr hwnd, TBPFLAG tbpFlags);

            void RegisterTab(IntPtr hwndTab, IntPtr hwndMDI);
            void UnregisterTab(IntPtr hwndTab);
            void SetTabOrder(IntPtr hwndTab, IntPtr hwndInsertBefore);
            void SetTabActive(IntPtr hwndTab, IntPtr hwndMDI, uint dwReserved);

            void ThumbBarAddButtons(IntPtr hwnd, uint cButtons, IntPtr pButton);
            void ThumbBarUpdateButtons(IntPtr hwnd, uint cButtons, IntPtr pButton);
            void ThumbBarSetImageList(IntPtr hwnd, IntPtr himl);
            void SetOverlayIcon(IntPtr hwnd, IntPtr hIcon, [MarshalAs(UnmanagedType.LPWStr)] string pszDescription);
            void SetThumbnailTooltip(IntPtr hwnd, [MarshalAs(UnmanagedType.LPWStr)] string pszTip);
            void SetThumbnailClip(IntPtr hwnd, IntPtr prcClip);
        }

        private enum TBPFLAG
        {
            TBPF_NOPROGRESS = 0,
            TBPF_INDETERMINATE = 0x1,
            TBPF_NORMAL = 0x2,
            TBPF_ERROR = 0x4,
            TBPF_PAUSED = 0x8
        }
    }
}
