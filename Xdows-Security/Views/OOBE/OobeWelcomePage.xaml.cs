using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OobeWelcomePage : OobeStepPageBase
    {
        public override bool ShowBackButton => false;

        public OobeWelcomePage()
        {
            InitializeComponent();
            Loaded += OobeWelcomePage_Loaded;
        }

        private async void OobeWelcomePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OobeWelcomePage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentText);
        }
    }
}
