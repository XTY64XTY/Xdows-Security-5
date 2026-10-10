namespace Protection;

internal static class DriverDecisionService
{
    private static readonly SemaphoreSlim UiDecisionQueue = new(1, 1);

    public static async Task<ProtectionUserDecision> AskUserAsync(
        Func<CancellationToken, Task<ProtectionUserDecision>> callback,
        TimeSpan timeout,
        CancellationToken token)
    {
        if (timeout <= TimeSpan.Zero)
            return ProtectionUserDecision.Timeout;

        try
        {
            if (!await UiDecisionQueue.WaitAsync(0, token).ConfigureAwait(false))
            {
                //
                // The UI decision queue is busy because another event for the
                // same file / behavior is already showing its dialog. This is
                // NOT a user timeout: the caller must defer to the pending
                // decision instead of blocking and quarantining behind the
                // user's back (files were being deleted even after the user
                // chose release because busy duplicates mapped to Timeout).
                //
                return ProtectionUserDecision.Deferred;
            }
        }
        catch (OperationCanceledException)
        {
            return ProtectionUserDecision.Timeout;
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeoutCts.CancelAfter(timeout);

        try
        {
            return await callback(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return ProtectionUserDecision.Timeout;
        }
        catch
        {
            return ProtectionUserDecision.Block;
        }
        finally
        {
            UiDecisionQueue.Release();
        }
    }
}
