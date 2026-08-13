namespace UniProtocol.Protocol.Packets;

/// <summary>
/// The first byte of every UniProtocol datagram.
/// </summary>
/// <remarks>
/// The values start at <c>0x20</c> so that a UniProtocol packet can never be mistaken for
/// STUN, whose messages begin with <c>0x00</c> or <c>0x01</c>. One UDP socket carries
/// handshakes, session data, path probes and STUN responses, and this byte is what tells
/// them apart — without it, path discovery would need a second port, and a second port is
/// a second NAT mapping to keep alive.
/// </remarks>
public enum PacketType : byte
{
    /// <summary>Noise IK message 1, from initiator to responder.</summary>
    HandshakeInit = 0x20,

    /// <summary>Noise IK message 2, from responder to initiator.</summary>
    HandshakeResponse = 0x21,

    /// <summary>An encrypted session packet.</summary>
    Data = 0x22,

    /// <summary>A cookie challenge, sent instead of a handshake response when under load.</summary>
    CookieReply = 0x23,

    /// <summary>A path-probing message, sealed under the peers' disco keys.</summary>
    Disco = 0x24,
}
