using System;

namespace Xdows_Security.Views.OOBE
{
    internal enum OobeNavKind
    {
        Next,
        Back
    }

    internal interface IOobeStepPage
    {
        bool ShowBackButton { get; }
        bool ShowNextButton { get; }
        string NextButtonUid { get; }

        event EventHandler? RequestSkipToFinish;
        event EventHandler? RequestComplete;
    }
}
