using System;

namespace Xdows_Security.Views.OOBE
{
    internal enum OOBENavKind
    {
        Next,
        Back
    }

    internal interface IOOBEStepPage
    {
        bool ShowBackButton { get; }
        bool ShowNextButton { get; }
        string NextButtonUid { get; }

        event EventHandler? RequestSkipToFinish;
        event EventHandler? RequestComplete;
    }
}
