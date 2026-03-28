using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace Xdows_Security;

[ContentProperty(Name = "CardContent")]
public sealed partial class InfoCard : UserControl
{
    public InfoCard()
    {
        this.InitializeComponent();
    }

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(InfoCard),
            new PropertyMetadata(string.Empty));

    public string Icon
    {
        get => (string)GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    public static readonly DependencyProperty IconProperty =
        DependencyProperty.Register(
            nameof(Icon),
            typeof(string),
            typeof(InfoCard),
            new PropertyMetadata(string.Empty));

    public object CardContent
    {
        get => GetValue(CardContentProperty);
        set => SetValue(CardContentProperty, value);
    }

    public static readonly DependencyProperty CardContentProperty =
        DependencyProperty.Register(
            nameof(CardContent),
            typeof(object),
            typeof(InfoCard),
            new PropertyMetadata(null));
}