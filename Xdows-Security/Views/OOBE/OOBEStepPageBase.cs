using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading.Tasks;

namespace Xdows_Security.Views.OOBE
{
    public abstract class OOBEStepPageBase : Page, IOOBEStepPage
    {
        public virtual bool ShowBackButton => true;
        public virtual bool ShowNextButton => true;
        public virtual string NextButtonUid => "OOBE_Button_Next";

        public event EventHandler? RequestSkipToFinish;
        public event EventHandler? RequestComplete;

        protected void RaiseSkipToFinish() => RequestSkipToFinish?.Invoke(this, EventArgs.Empty);
        protected void RaiseComplete() => RequestComplete?.Invoke(this, EventArgs.Empty);

        protected async Task PlayTitleAndContentEntranceAsync(UIElement title, UIElement content)
        {
            App.PlayEntranceAnimation(title, "up");
            await Task.Delay(150);
            App.PlayEntranceAnimation(content, "up");
        }
    }
}
