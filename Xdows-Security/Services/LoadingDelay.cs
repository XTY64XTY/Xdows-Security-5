using System;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Services;

/// <summary>
/// 延迟显示加载态：操作在阈值内完成时不闪一下加载动画。
/// </summary>
internal static class LoadingDelay
{
    /// <summary>超过这个时长才让加载界面出现。</summary>
    public const int ThresholdMilliseconds = 50;

    /// <summary>
    /// 到达阈值后执行 <paramref name="show"/>；<paramref name="token"/> 提前取消则不执行，
    /// 调用方完成加载后应立即取消，避免加载界面在结果出来之后才闪出来。
    /// </summary>
    public static async Task ShowAsync(CancellationToken token, Action show)
    {
        try
        {
            await Task.Delay(ThresholdMilliseconds, token);
            if (!token.IsCancellationRequested)
            {
                show();
            }
        }
        catch (OperationCanceledException)
        {
            // 加载在阈值内完成，本就不该出现加载界面。
        }
    }
}
