using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEFinishPage : OOBEStepPageBase
    {
        public override bool ShowNextButton => false;

        public OOBEFinishPage()
        {
            InitializeComponent();
            Loaded += OOBEFinishPage_Loaded;
        }

        private async void OOBEFinishPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEFinishPage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void FinishButton_Click(object sender, RoutedEventArgs e)
        {
            RaiseComplete();
        }
    }
}
