using System.Diagnostics.CodeAnalysis;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol;

/// <summary>Which kind of path a packet travels over.</summary>
public enum PathKind : byte
{
    /// <summary>No path.</summary>
    None = 0,

    /// <summary>Straight to an IP address and port.</summary>
    Direct = 1,

    /// <summary>Forwarded to a node by a relay server.</summary>
    Relay = 2,
}

/// <summary>
/// Where to send a packet: an IP address, or a node reached through a relay.
/// </summary>
/// <remarks>
/// <para>
/// The transport layer addresses peers by this rather than by <see cref="NetworkAddress"/>
/// because a relayed packet has no meaningful IP destination — it is addressed to a
/// <see cref="NodeId"/>, and the relay works out where that node currently is.
/// </para>
/// <para>
/// This is what makes the relay ordinary. A connection over a relay and a connection over
/// a direct link differ only in the value of this struct; the handshake, the session, the
/// replay window and everything above are identical and unaware. Upgrading a live
/// connection from a relay to a direct path is therefore a matter of replacing one of these
/// — not renegotiating anything.
/// </para>
/// </remarks>
public readonly struct PathEndpoint : IEquatable<PathEndpoint>
{
    private readonly NetworkAddress _address;
    private readonly NodeId _nodeId;

    private PathEndpoint(PathKind kind, NetworkAddress address, NodeId nodeId)
    {
        Kind = kind;
        _address = address;
        _nodeId = nodeId;
    }

    /// <summary>What kind of path this is.</summary>
    public PathKind Kind { get; }

    /// <summary>The IP address, valid when <see cref="Kind"/> is <see cref="PathKind.Direct"/>.</summary>
    public NetworkAddress Address => _address;

    /// <summary>The destination node, valid when <see cref="Kind"/> is <see cref="PathKind.Relay"/>.</summary>
    public NodeId NodeId => _nodeId;

    /// <summary>Indicates whether this endpoint names anywhere at all.</summary>
    public bool IsNone => Kind == PathKind.None;

    /// <summary>Creates a direct path to <paramref name="address"/>.</summary>
    public static PathEndpoint ToAddress(NetworkAddress address) => new(PathKind.Direct, address, default);

    /// <summary>Creates a relayed path to <paramref name="nodeId"/>.</summary>
    public static PathEndpoint ToRelayedNode(NodeId nodeId) => new(PathKind.Relay, default, nodeId);

    /// <inheritdoc />
    public bool Equals(PathEndpoint other) => Kind == other.Kind && Kind switch
    {
        PathKind.Direct => _address == other._address,
        PathKind.Relay => _nodeId == other._nodeId,
        _ => true,
    };

    /// <inheritdoc />
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is PathEndpoint other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Kind switch
    {
        PathKind.Direct => HashCode.Combine(Kind, _address),
        PathKind.Relay => HashCode.Combine(Kind, _nodeId),
        _ => 0,
    };

    /// <summary>Compares two endpoints.</summary>
    public static bool operator ==(PathEndpoint left, PathEndpoint right) => left.Equals(right);

    /// <summary>Compares two endpoints.</summary>
    public static bool operator !=(PathEndpoint left, PathEndpoint right) => !left.Equals(right);

    /// <inheritdoc />
    public override string ToString() => Kind switch
    {
        PathKind.Direct => _address.ToString(),
        PathKind.Relay => $"relay:{_nodeId.ToShortString()}",
        _ => "none",
    };
}
