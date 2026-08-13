using System.Buffers.Binary;

namespace UniProtocol.Protocol.Packets;

/// <summary>
/// The 16-byte header of an encrypted session packet.
/// </summary>
/// <remarks>
/// <para>
/// Layout, little-endian throughout:
/// </para>
/// <code>
///   offset  size  field
///        0     1  type (0x22)
///        1     1  flags (bit 0 = key phase)
///        2     2  reserved, must be zero
///        4     4  receiverIndex
///        8     8  counter
///       16     n  ciphertext
///     16+n    16  authentication tag
/// </code>
/// <para>
/// The whole header is the AEAD associated data, so none of it can be altered in flight.
/// </para>
/// <para>
/// <strong><c>receiverIndex</c> identifies the session, not the path.</strong> It is
/// chosen by the receiver during the handshake and never changes, which is what makes it
/// possible to move a live connection from a relay to a direct path — or between Wi-Fi and
/// cellular — without renegotiating anything. The packet arrives from a new address, is
/// authenticated against the same session, and the streams above never notice.
/// </para>
/// <para>
/// <c>counter</c> is the packet number and doubles as the AEAD nonce. It is a single
/// sequence per session that continues across rekeys, so acknowledgements stay meaningful
/// when the key changes.
/// </para>
/// </remarks>
public readonly record struct DataPacketHeader
{
    /// <summary>Size of the header in bytes.</summary>
    public const int SizeInBytes = 16;

    /// <summary>Bit 0 of <see cref="Flags"/>: which key generation encrypted this packet.</summary>
    public const byte KeyPhaseFlag = 0x01;

    /// <summary>Creates a header.</summary>
    public DataPacketHeader(uint receiverIndex, ulong counter, bool keyPhase = false)
    {
        ReceiverIndex = receiverIndex;
        Counter = counter;
        Flags = keyPhase ? KeyPhaseFlag : (byte)0;
    }

    /// <summary>The receiver's session identifier.</summary>
    public uint ReceiverIndex { get; }

    /// <summary>The packet number, which is also the AEAD nonce.</summary>
    public ulong Counter { get; }

    /// <summary>Packet flags.</summary>
    public byte Flags { get; init; }

    /// <summary>Indicates which key generation was used.</summary>
    public bool KeyPhase => (Flags & KeyPhaseFlag) != 0;

    /// <summary>Writes the header to <paramref name="destination"/>.</summary>
    public void Write(Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SizeInBytes);

        destination[0] = (byte)PacketType.Data;
        destination[1] = Flags;
        destination[2] = 0;
        destination[3] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], ReceiverIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], Counter);
    }

    /// <summary>Reads a header from <paramref name="source"/>.</summary>
    /// <returns><see langword="false"/> when the bytes are not a well-formed data header.</returns>
    /// <remarks>
    /// The reserved bytes are required to be zero. Being strict now keeps them genuinely
    /// available: a future version can give them meaning and know that an old peer would
    /// have rejected, rather than ignored, a packet that used them.
    /// </remarks>
    public static bool TryRead(ReadOnlySpan<byte> source, out DataPacketHeader header)
    {
        header = default;

        if (source.Length < SizeInBytes
            || source[0] != (byte)PacketType.Data
            || (source[1] & ~KeyPhaseFlag) != 0
            || source[2] != 0
            || source[3] != 0)
        {
            return false;
        }

        header = new DataPacketHeader(
            BinaryPrimitives.ReadUInt32LittleEndian(source[4..]),
            BinaryPrimitives.ReadUInt64LittleEndian(source[8..]),
            (source[1] & KeyPhaseFlag) != 0);

        return true;
    }
}
