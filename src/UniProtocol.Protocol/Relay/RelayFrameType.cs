namespace UniProtocol.Protocol.Relay;

/// <summary>
/// The kinds of message exchanged with a relay server, after its handshake.
/// </summary>
/// <remarks>
/// The set is small on purpose. A relay is a dumb forwarder: it learns which node is on
/// which connection and moves opaque bodies between them. Everything that gives those
/// bodies meaning — the peer-to-peer handshake, sessions, streams — happens end to end
/// inside them, so the relay sees only NodeIds and ciphertext and cannot read, alter or
/// selectively forge a single byte of what it carries.
/// </remarks>
public enum RelayFrameType : byte
{
    /// <summary>Server tells the client the limits it will enforce. Server to client.</summary>
    ServerInfo = 0x01,

    /// <summary>Deliver a body to a node. Client to server.</summary>
    SendPacket = 0x02,

    /// <summary>A body from a node. Server to client.</summary>
    ReceivePacket = 0x03,

    /// <summary>Keeps the connection and any NAT mapping in front of it alive.</summary>
    KeepAlive = 0x04,

    /// <summary>The named peer is no longer connected to this relay. Server to client.</summary>
    PeerGone = 0x05,

    /// <summary>Latency probe.</summary>
    Ping = 0x06,

    /// <summary>Reply to a <see cref="Ping"/>.</summary>
    Pong = 0x07,
}
