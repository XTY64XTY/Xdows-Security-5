using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEAppearancePage : OOBEStepPageBase
    {
        public OOBEAppearancePage()
        {
            InitializeComponent();
            Loaded += OOBEAppearancePage_Loaded;
        }

        private async void OOBEAppearancePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEAppearancePage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);
        }

        private void SkipButton_Click(object sender, RoutedEventArgs e)
        {
            RaiseSkipToFinish();
        }
    }
}
