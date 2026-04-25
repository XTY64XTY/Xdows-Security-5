using Microsoft.UI.Xaml;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEWelcomePage : OOBEStepPageBase
    {
        public override bool ShowBackButton => false;

        public OOBEWelcomePage()
        {
            InitializeComponent();
            Loaded += OOBEWelcomePage_Loaded;
        }

        private async void OOBEWelcomePage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEWelcomePage_Loaded;
            await PlayTitleAndContentEntranceAsync(TitleText, ContentText);
        }
    }
}
