namespace UniProtocol;

/// <summary>
/// The endpoint has no way to reach the requested kind of path.
/// </summary>
/// <remarks>
/// In practice this means a peer can only be reached through a relay and no relay is
/// configured. It is a configuration problem with a specific fix, so it is a distinct type
/// rather than a generic failure.
/// </remarks>
public sealed class PathUnavailableException : UniProtocolException
{
    /// <summary>Creates an exception.</summary>
    public PathUnavailableException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public PathUnavailableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public PathUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
