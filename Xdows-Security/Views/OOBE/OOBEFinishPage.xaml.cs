using Microsoft.UI.Xaml;
using System;
using System.Threading.Tasks;
using WinUI3Localizer;

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

            SetLoadingState(true);

            await PlayTitleAndContentEntranceAsync(TitleText, ContentRoot);

            await Task.Run(() =>
            {
                if (!ProtectionStatus.IsRun(0))
                {
                    ProtectionStatus.Run(0);
                }
            });

            SetLoadingState(false);
        }

        private void SetLoadingState(bool isLoading)
        {
            if (isLoading)
            {
                FinishButton.IsEnabled = false;
                LoadingRing.IsActive = true;
                LoadingRing.Visibility = Visibility.Visible;
                FinishButtonText.Text = Localizer.Get().GetLocalizedString("OOBE_Finish_Button_Loading");
            }
            else
            {
                FinishButton.IsEnabled = true;
                LoadingRing.IsActive = false;
                LoadingRing.Visibility = Visibility.Collapsed;
                FinishButtonText.Text = Localizer.Get().GetLocalizedString("OOBE_Finish_Button");
            }
        }

        private void FinishButton_Click(object sender, RoutedEventArgs e)
        {
            RaiseComplete();
        }
    }
}
