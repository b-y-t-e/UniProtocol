namespace UniProtocol.Protocol.Relay;

/// <summary>A relay connection was malformed, unauthenticated, or refused.</summary>
public sealed class RelayProtocolException : Exception
{
    /// <summary>Creates an exception.</summary>
    public RelayProtocolException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public RelayProtocolException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public RelayProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
