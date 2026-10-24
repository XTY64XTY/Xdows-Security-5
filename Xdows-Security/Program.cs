using System;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Settings;

namespace Xdows_Security;

/// <summary>
/// 自定义入口点。
///
/// XamlOptionalChanges 的全部方法只能在 XAML 初始化（Application.Start）之前调用，
/// 一旦 XAML 初始化或 Lock 之后调用会抛 InvalidOperationException。SDK 生成的 Main
/// 没有可插入的位置（App 构造函数执行时 XAML 已初始化），因此项目定义
/// DISABLE_XAML_GENERATED_MAIN 并在这里接管入口。
/// </summary>
public static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();
        EnableXamlOptionalChanges();

        Application.Start(p =>
        {
            var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            new App();
        });
    }

    /// <summary>启用 Windows App SDK 引入的可选 XAML 性能优化。</summary>
    private static void EnableXamlOptionalChanges()
    {
        // 以下优化需通过 XamlOptionalChanges API 显式选择启用：
        //  - DefaultStyleOptimizations: 优化 XamlControlsResources 样式，含 ScrollBar 模板
        //  - IconNoGridOptimization: FontIcon/BitmapIcon 不再插入额外 Grid
        //  - OptimizeApplyStyles: 跳过不应用值的样式设置器，并延迟应用样式到元素入树后
        //  - DeferContextFlyoutInit: 延迟 TextBlock/RichTextBlock 默认 ContextFlyout 初始化
        XamlChangeId[] changes =
        [
            XamlChangeId.DefaultStyleOptimizations,
            XamlChangeId.IconNoGridOptimization,
            XamlChangeId.OptimizeApplyStyles,
            XamlChangeId.DeferContextFlyoutInit
        ];

        foreach (XamlChangeId change in changes)
        {
            try
            {
                XamlOptionalChanges.EnableChange(change);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to enable XamlChangeId {change}: {ex.Message}");
            }
        }
    }
}
