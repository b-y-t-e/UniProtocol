namespace UniProtocol;

/// <summary>Base type for errors raised by UniProtocol.</summary>
public class UniProtocolException : Exception
{
    /// <summary>Creates an exception.</summary>
    public UniProtocolException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public UniProtocolException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public UniProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The peer did not complete a handshake.
/// </summary>
/// <remarks>
/// Covers both "no reply arrived" and "the reply was not acceptable". The two are
/// deliberately not distinguished to a caller that is merely dialling: from the outside,
/// an unreachable peer and a peer that rejected us look the same, and pretending otherwise
/// would invite retry logic that cannot actually tell them apart.
/// </remarks>
public sealed class HandshakeFailedException : UniProtocolException
{
    /// <summary>Creates an exception.</summary>
    public HandshakeFailedException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public HandshakeFailedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public HandshakeFailedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The connection is no longer usable.</summary>
public sealed class ConnectionClosedException : UniProtocolException
{
    /// <summary>Creates an exception.</summary>
    public ConnectionClosedException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public ConnectionClosedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public ConnectionClosedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
