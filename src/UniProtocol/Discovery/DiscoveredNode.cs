using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Discovery;

/// <summary>A node found by a discovery mechanism.</summary>
/// <param name="Ticket">Everything needed to connect: identity and address hints.</param>
/// <param name="DiscoveredAt">When the advertisement was seen.</param>
/// <remarks>
/// Discovery is a hint, never an authority. Anyone on the network can advertise anything,
/// including somebody else's identity — but they cannot complete the handshake for a key
/// they do not hold, so a forged advertisement wastes a connection attempt and nothing more.
/// </remarks>
public sealed record DiscoveredNode(UniTicket Ticket, DateTimeOffset DiscoveredAt)
{
    /// <summary>The identity advertised.</summary>
    public NodeId NodeId => Ticket.NodeId;
}
