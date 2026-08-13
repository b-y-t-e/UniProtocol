namespace UniProtocol.Discovery;

/// <summary>
/// Local discovery could not start because multicast is unavailable on this machine.
/// </summary>
/// <remarks>
/// Common and not alarming: the mDNS port may be held by another process that will not
/// share it, a container may have no multicast route, or a corporate network may block the
/// group outright. It is a reason to fall back to pasting a ticket, not a reason to fail
/// the application — so it is a distinct exception type callers can catch narrowly.
/// </remarks>
public sealed class MulticastUnavailableException : UniProtocolException
{
    /// <summary>Creates an exception.</summary>
    public MulticastUnavailableException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    public MulticastUnavailableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public MulticastUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
