# BugReport Page Refactor Plan

## Constraints

- Keep the BugReport page implemented as a WinUI `Page` with code-behind.
- Do not introduce ViewModel, VM, MVVM, command binding, or new state layers.
- Preserve the current feedback-channel behavior and existing `FeedbackTCPClient` interface.
- Keep commits small: one commit after each completed plan item.

## Plan

1. Record the refactor boundary and commit plan.
2. Rework `BugReportPage.xaml` into a clearer page structure with accessible controls.
3. Split `BugReportPage.xaml.cs` into focused private methods for connection, message UI, dialogs, timers, and cleanup.
4. Build, review the diff, fix any issues found, then merge and push.

## Verification

- Built with `BuildAndRun.ps1 -SkipRun`: succeeded.
- Remaining warning: existing `App.xaml.cs` WUI1001 analyzer warning, outside BugReport changes.
- Checked no `ViewModel`, `MVVM`, `ICommand`, command binding, sync wait, or `ContinueWith` was introduced in BugReport code-behind.
- Review follow-up: preserved the previous `Environment.UserName` initialization behavior.
- FeedbackTCPClient implementation was adjusted without changing its public interface because BugReport depends on its receive loop and disconnect behavior.
