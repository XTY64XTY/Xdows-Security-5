using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OobeAppearancePage : OobeStepPageBase
    {
        public OobeAppearancePage()
        {
            InitializeComponent();
            Loaded += OobeAppearancePage_Loaded;
        }

        private async void OobeAppearancePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OobeAppearancePage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void SkipButton_Click(object sender, RoutedEventArgs e)
        {
            RaiseSkipToFinish();
        }
    }
}
