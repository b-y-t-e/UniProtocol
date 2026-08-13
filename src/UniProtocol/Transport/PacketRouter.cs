using UniProtocol.Abstractions;
using UniProtocol.Protocol;

namespace UniProtocol.Transport;

/// <summary>
/// Sends a packet over whichever transport can reach the requested path.
/// </summary>
/// <remarks>
/// <para>
/// An endpoint holds several transports at once — a UDP socket for direct paths and a relay
/// connection for relayed ones — and this decides which handles a given destination.
/// </para>
/// <para>
/// Everything above this point addresses peers by <see cref="PathEndpoint"/> and never
/// learns which transport carried a packet. That is what allows a live connection to move
/// between a relay and a direct link: the path changes, the transport underneath changes
/// with it, and the session does not notice.
/// </para>
/// </remarks>
internal sealed class PacketRouter
{
    private readonly IPacketTransport[] _transports;

    public PacketRouter(IReadOnlyList<IPacketTransport> transports)
    {
        ArgumentNullException.ThrowIfNull(transports);

        if (transports.Count == 0)
        {
            throw new ArgumentException("An endpoint needs at least one transport.", nameof(transports));
        }

        _transports = [.. transports];
    }

    /// <summary>The transports this router can use, in the order they were supplied.</summary>
    public IReadOnlyList<IPacketTransport> Transports => _transports;

    /// <summary>Indicates whether any transport can reach paths of the given kind.</summary>
    public bool CanReach(PathKind kind) => TryGetTransport(kind, out _);

    /// <summary>
    /// Sends <paramref name="payload"/> to <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="PathUnavailableException">
    /// No transport can reach that kind of path.
    /// </exception>
    public ValueTask SendAsync(
        ReadOnlyMemory<byte> payload,
        PathEndpoint destination,
        CancellationToken cancellationToken)
    {
        if (!TryGetTransport(destination.Kind, out IPacketTransport? transport))
        {
            throw new PathUnavailableException(
                $"This endpoint has no transport that can reach a {destination.Kind} path. " +
                "Configure a relay to reach peers that have no directly reachable address.");
        }

        return transport.SendAsync(payload, destination, cancellationToken);
    }

    private bool TryGetTransport(
        PathKind kind,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out IPacketTransport? transport)
    {
        foreach (IPacketTransport candidate in _transports)
        {
            if (candidate.SupportedPathKind == kind)
            {
                transport = candidate;
                return true;
            }
        }

        transport = null;
        return false;
    }
}
