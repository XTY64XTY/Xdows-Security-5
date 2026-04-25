using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OobeFinishPage : OobeStepPageBase
    {
        public override bool ShowNextButton => false;

        public OobeFinishPage()
        {
            InitializeComponent();
            Loaded += OobeFinishPage_Loaded;
        }

        private async void OobeFinishPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OobeFinishPage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void FinishButton_Click(object sender, RoutedEventArgs e)
        {
            RaiseComplete();
        }
    }
}
