using System.Buffers.Binary;
using UniProtocol.Crypto.Hashing;

namespace UniProtocol.Protocol.Packets;

/// <summary>
/// Framing for the two Noise handshake messages.
/// </summary>
/// <remarks>
/// <para>
/// Layout:
/// </para>
/// <code>
///   offset  size  field
///        0     1  type (0x20 or 0x21)
///        1     1  version
///        2     2  reserved, must be zero
///        4     4  senderIndex
///        8     4  receiverIndex (zero in HandshakeInit)
///       12     n  Noise handshake message
///     12+n    16  mac1
///     28+n    16  mac2
/// </code>
/// <para>
/// <c>senderIndex</c> is the session identifier the sender wants its peer to put in the
/// <c>receiverIndex</c> field of every subsequent data packet.
/// </para>
/// <para>
/// <c>receiverIndex</c> echoes back the index the peer chose. The response needs it because
/// a handshake reply may arrive from an address the initiator has never seen — that is the
/// normal case during hole punching — so the source address cannot be used to work out
/// which pending handshake a reply belongs to.
/// </para>
/// <para>
/// The two MACs are WireGuard's anti-denial-of-service design. <c>mac1</c> is keyed by the
/// recipient's static public key, so anyone who does not know who they are talking to
/// cannot produce it, and a flood of random packets is discarded after one hash instead of
/// three Diffie-Hellman operations. <c>mac2</c> carries a cookie that proves the sender can
/// receive at its claimed address, defeating spoofed-source floods; the cookie exchange
/// itself is only engaged under load and is not yet implemented, so the field is present
/// and zero.
/// </para>
/// </remarks>
public static class HandshakePacket
{
    /// <summary>Current protocol version.</summary>
    public const byte Version = 1;

    /// <summary>Size of the fixed header preceding the Noise message.</summary>
    public const int HeaderSizeInBytes = 12;

    /// <summary>Size of each MAC in bytes.</summary>
    public const int MacSizeInBytes = 16;

    /// <summary>Total overhead added to a Noise handshake message.</summary>
    public const int OverheadInBytes = HeaderSizeInBytes + (2 * MacSizeInBytes);

    private static ReadOnlySpan<byte> Mac1Label => "uniprotocol/v1/mac1"u8;

    /// <summary>
    /// Derives the key used for <c>mac1</c> from the recipient's static public key.
    /// </summary>
    /// <remarks>
    /// Precomputed once per peer: it depends only on who the packet is addressed to.
    /// </remarks>
    public static void DeriveMac1Key(ReadOnlySpan<byte> recipientStaticPublicKey, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, Blake2s.HashSizeInBytes);

        Blake2sHasher hasher = Blake2sHasher.Create(Blake2s.HashSizeInBytes);
        hasher.Update(Mac1Label);
        hasher.Update(recipientStaticPublicKey);
        hasher.Finish(destination);
    }

    /// <summary>
    /// Writes the header and both MACs around a Noise message that has already been placed
    /// at <see cref="HeaderSizeInBytes"/>.
    /// </summary>
    /// <returns>The total packet length.</returns>
    public static int Finish(
        Span<byte> packet,
        PacketType type,
        uint senderIndex,
        uint receiverIndex,
        int noiseMessageLength,
        ReadOnlySpan<byte> mac1Key)
    {
        int total = HeaderSizeInBytes + noiseMessageLength + (2 * MacSizeInBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(packet.Length, total);

        packet[0] = (byte)type;
        packet[1] = Version;
        packet[2] = 0;
        packet[3] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(packet[4..], senderIndex);
        BinaryPrimitives.WriteUInt32LittleEndian(packet[8..], receiverIndex);

        int mac1Offset = HeaderSizeInBytes + noiseMessageLength;
        ComputeMac(mac1Key, packet[..mac1Offset], packet.Slice(mac1Offset, MacSizeInBytes));

        // mac2 stays zero until the cookie mechanism exists. A zero mac2 is what a peer
        // that has not been challenged sends, so this is a valid packet, not a placeholder.
        packet.Slice(mac1Offset + MacSizeInBytes, MacSizeInBytes).Clear();

        return total;
    }

    /// <summary>
    /// Validates the header and <c>mac1</c>, and locates the Noise message.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> for anything that is not a well-formed handshake packet
    /// addressed to us. This is the cheap filter that runs before any public-key operation.
    /// </returns>
    public static bool TryParse(
        ReadOnlySpan<byte> packet,
        PacketType expectedType,
        ReadOnlySpan<byte> mac1Key,
        out uint senderIndex,
        out uint receiverIndex,
        out ReadOnlySpan<byte> noiseMessage)
    {
        senderIndex = 0;
        receiverIndex = 0;
        noiseMessage = default;

        if (packet.Length <= OverheadInBytes
            || packet[0] != (byte)expectedType
            || packet[1] != Version
            || packet[2] != 0
            || packet[3] != 0)
        {
            return false;
        }

        int mac1Offset = packet.Length - (2 * MacSizeInBytes);

        Span<byte> expectedMac1 = stackalloc byte[MacSizeInBytes];
        ComputeMac(mac1Key, packet[..mac1Offset], expectedMac1);

        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                expectedMac1,
                packet.Slice(mac1Offset, MacSizeInBytes)))
        {
            return false;
        }

        senderIndex = BinaryPrimitives.ReadUInt32LittleEndian(packet[4..]);
        receiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(packet[8..]);
        noiseMessage = packet[HeaderSizeInBytes..mac1Offset];

        return true;
    }

    private static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> destination)
        => Blake2s.HashDataKeyed(key, data, destination, MacSizeInBytes);
}
