namespace Protection;

internal sealed class DriverShutdownToken
{
    private string? _token;

    public bool HasToken => !string.IsNullOrWhiteSpace(_token);

    public void Capture(string? token)
    {
        _token = string.IsNullOrWhiteSpace(token) ? null : token;
    }

    public string? Consume()
    {
        string? token = _token;
        _token = null;
        return token;
    }

    public string? CopyForAuthorization()
    {
        return _token;
    }

    public void Clear()
    {
        _token = null;
    }
}
