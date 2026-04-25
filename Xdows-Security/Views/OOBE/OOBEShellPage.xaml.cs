using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Threading.Tasks;

namespace Xdows_Security.Views.OOBE
{
    public sealed partial class OOBEShellPage : Page
    {
        private readonly List<Type> _mainFlow =
        [
            typeof(OOBEWelcomePage),
            typeof(OOBELanguagePage),
            typeof(OOBEAppearancePage),
            typeof(OOBEFinishPage)
        ];

        private readonly List<Type> _appearanceDetailFlow =
        [
            typeof(OOBEAppearanceThemePage),
            typeof(OOBEAppearanceBackdropPage),
            typeof(OOBEAppearanceNavPage),
            typeof(OOBEAppearanceSoundPage)
        ];

        private int _mainIndex;
        private int _detailIndex;
        private bool _inDetailFlow;

        public OOBEShellPage()
        {
            InitializeComponent();
            Loaded += OOBEShellPage_Loaded;
        }

        private async void OOBEShellPage_Loaded(object sender, RoutedEventArgs e)
        {
            Loaded -= OOBEShellPage_Loaded;
            await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next, initial: true);
        }

        private Type GetCurrentPageType()
        {
            if (_inDetailFlow)
            {
                return _appearanceDetailFlow[_detailIndex];
            }
            return _mainFlow[_mainIndex];
        }

        private bool CanGoBack()
        {
            if (_inDetailFlow)
            {
                return _detailIndex > 0 || _mainIndex > 0;
            }
            return _mainIndex > 0;
        }

        private bool CanGoNext()
        {
            if (_inDetailFlow)
            {
                return _detailIndex < _appearanceDetailFlow.Count - 1 || _mainIndex < _mainFlow.Count - 1;
            }
            return _mainIndex < _mainFlow.Count - 1;
        }

        private async void BackButton_Click(object sender, RoutedEventArgs e)
        {
            if (!CanGoBack()) return;

            if (_inDetailFlow)
            {
                if (_detailIndex > 0)
                {
                    _detailIndex--;
                    await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Back);
                    return;
                }

                _inDetailFlow = false;
                await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Back);
                return;
            }

            _mainIndex--;
            await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Back);
        }

        private async void NextButton_Click(object sender, RoutedEventArgs e)
        {
            if (!CanGoNext()) return;

            if (_inDetailFlow)
            {
                if (_detailIndex < _appearanceDetailFlow.Count - 1)
                {
                    _detailIndex++;
                    await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next);
                    return;
                }

                _inDetailFlow = false;
                _mainIndex++;
                await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next);
                return;
            }

            if (_mainFlow[_mainIndex] == typeof(OOBEAppearancePage))
            {
                _inDetailFlow = true;
                _detailIndex = 0;
                await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next);
                return;
            }

            _mainIndex++;
            await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next);
        }

        private async Task NavigateToAsync(Type pageType, OOBENavKind kind, bool initial = false)
        {
            ContentFrame.Navigate(pageType);

            if (ContentFrame.Content is IOOBEStepPage step)
            {
                step.RequestSkipToFinish -= Step_RequestSkipToFinish;
                step.RequestComplete -= Step_RequestComplete;

                step.RequestSkipToFinish += Step_RequestSkipToFinish;
                step.RequestComplete += Step_RequestComplete;

                NextButtonUid = step.NextButtonUid;
                await UpdateNavButtonsAsync(step.ShowBackButton, step.ShowNextButton, initial);
            }
            else
            {
                NextButtonUid = "OOBE_Button_Next";
                await UpdateNavButtonsAsync(showBack: true, showNext: true, initial);
            }
        }

        private string NextButtonUid
        {
            set
            {
                NextButton.ClearValue(WinUI3Localizer.Uids.UidProperty);
                WinUI3Localizer.Uids.SetUid(NextButton, value);
            }
        }

        private async void Step_RequestSkipToFinish(object? sender, EventArgs e)
        {
            _inDetailFlow = false;
            _mainIndex = _mainFlow.IndexOf(typeof(OOBEFinishPage));
            await NavigateToAsync(GetCurrentPageType(), OOBENavKind.Next);
        }

        private async void Step_RequestComplete(object? sender, EventArgs e)
        {
            if (App.MainWindow != null)
            {
                await App.MainWindow.CloseOOBEAsync(markCompleted: true);
            }
        }

        private bool _lastShowBack;
        private bool _lastShowNext;

        private async Task UpdateNavButtonsAsync(bool showBack, bool showNext, bool initial)
        {
            if (initial)
            {
                _lastShowBack = showBack;
                _lastShowNext = showNext;

                await FadeButtonAsync(BackButton, showBack, fadeIn: true);
                await FadeButtonAsync(NextButton, showNext, fadeIn: true);
                return;
            }

            bool backChanged = _lastShowBack != showBack;
            bool nextChanged = _lastShowNext != showNext;

            if (showNext && !_lastShowNext)
                await FadeButtonAsync(NextButton, showNext, fadeIn: true);
            else if (!showNext && _lastShowNext)
                FadeButtonAsync(NextButton, showNext, fadeIn: false);

            if (showBack && !_lastShowBack)
                await FadeButtonAsync(BackButton, showBack, fadeIn: true);
            else if (!showBack && _lastShowBack)
                FadeButtonAsync(BackButton, showBack, fadeIn: false);

            _lastShowBack = showBack;
            _lastShowNext = showNext;

            if (backChanged || nextChanged)
                await Task.Delay(300);
        }

        private async Task FadeButtonAsync(UIElement element, bool show, bool fadeIn)
        {
            element.IsHitTestVisible = show;
            element.Opacity = 1;

            var visual = ElementCompositionPreview.GetElementVisual(element);
            var compositor = visual.Compositor;
            visual.StopAnimation("Offset");
            visual.StopAnimation("Opacity");

            if (fadeIn)
            {
                visual.Opacity = 0;
                var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));
                var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
                opacityAnimation.Target = "Opacity";
                opacityAnimation.InsertKeyFrame(1.0f, 1.0f, easing);
                opacityAnimation.Duration = TimeSpan.FromMilliseconds(300);
                visual.StartAnimation("Opacity", opacityAnimation);
                await Task.Delay(300);
            }
            else
            {
                var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));
                var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
                opacityAnimation.Target = "Opacity";
                opacityAnimation.InsertKeyFrame(1.0f, 0.0f, easing);
                opacityAnimation.Duration = TimeSpan.FromMilliseconds(300);
                visual.StartAnimation("Opacity", opacityAnimation);
            }
        }
        private Task PlayPageTransitionAsync(OOBENavKind kind, bool initial)
        {
            if (initial) return Task.CompletedTask;

            if (ContentFrame.Content is not FrameworkElement root) return Task.CompletedTask;

            var visual = ElementCompositionPreview.GetElementVisual(root);
            var compositor = visual.Compositor;

            float x = kind == OOBENavKind.Next ? 40f : -40f;
            visual.Opacity = 0;
            visual.Offset = new Vector3(x, 0, 0);

            var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));

            var offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
            offsetAnimation.Target = "Offset";
            offsetAnimation.InsertKeyFrame(1.0f, new Vector3(0, 0, 0), easing);
            offsetAnimation.Duration = TimeSpan.FromMilliseconds(300);

            var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
            opacityAnimation.Target = "Opacity";
            opacityAnimation.InsertKeyFrame(1.0f, 1.0f, easing);
            opacityAnimation.Duration = TimeSpan.FromMilliseconds(300);

            visual.StartAnimation("Offset", offsetAnimation);
            visual.StartAnimation("Opacity", opacityAnimation);
            return Task.CompletedTask;
        }
    }
}
