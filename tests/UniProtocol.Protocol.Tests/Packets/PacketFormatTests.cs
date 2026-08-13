using UniProtocol.Protocol.Packets;

namespace UniProtocol.Protocol.Tests.Packets;

/// <summary>
/// Wire-format tests, including golden byte vectors.
/// </summary>
/// <remarks>
/// The golden vectors are the interoperability guard. A refactor that quietly changes a
/// field's offset or endianness leaves every round-trip test passing and breaks every peer
/// running a different build. Changing one of these expected strings is therefore a
/// protocol change and requires a version bump.
/// </remarks>
public sealed class PacketFormatTests
{
    [Fact]
    public void DataPacketHeader_GoldenVector_HasTheExactExpectedBytes()
    {
        DataPacketHeader header = new(receiverIndex: 0x11223344, counter: 0x8899AABBCCDDEEFF);

        Span<byte> encoded = stackalloc byte[DataPacketHeader.SizeInBytes];
        header.Write(encoded);

        Assert.Equal(
            "22" +      // type = Data
            "00" +      // flags
            "0000" +    // reserved
            "44332211" + // receiverIndex, little-endian
            "ffeeddccbbaa9988", // counter, little-endian
            Convert.ToHexStringLower(encoded));
    }

    [Fact]
    public void DataPacketHeader_WriteThenRead_RoundTrips()
    {
        DataPacketHeader original = new(receiverIndex: 42, counter: 1_000_000, keyPhase: true);

        Span<byte> encoded = stackalloc byte[DataPacketHeader.SizeInBytes];
        original.Write(encoded);

        Assert.True(DataPacketHeader.TryRead(encoded, out DataPacketHeader decoded));
        Assert.Equal(original.ReceiverIndex, decoded.ReceiverIndex);
        Assert.Equal(original.Counter, decoded.Counter);
        Assert.True(decoded.KeyPhase);
    }

    [Fact]
    public void DataPacketHeader_TryRead_RejectsNonZeroReservedBytes()
    {
        // Reserved bytes are rejected rather than ignored so that a future version can give
        // them meaning and rely on older peers having refused, not silently accepted, them.
        Span<byte> encoded = stackalloc byte[DataPacketHeader.SizeInBytes];
        new DataPacketHeader(1, 1).Write(encoded);
        encoded[2] = 0x01;

        Assert.False(DataPacketHeader.TryRead(encoded, out _));
    }

    [Fact]
    public void DataPacketHeader_TryRead_RejectsUndefinedFlagBits()
    {
        Span<byte> encoded = stackalloc byte[DataPacketHeader.SizeInBytes];
        new DataPacketHeader(1, 1).Write(encoded);
        encoded[1] = 0x02;

        Assert.False(DataPacketHeader.TryRead(encoded, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(DataPacketHeader.SizeInBytes - 1)]
    public void DataPacketHeader_TryRead_TruncatedInput_ReturnsFalse(int length)
    {
        Assert.False(DataPacketHeader.TryRead(new byte[length], out _));
    }

    [Fact]
    public void DataPacketHeader_TryRead_WrongPacketType_ReturnsFalse()
    {
        Span<byte> encoded = stackalloc byte[DataPacketHeader.SizeInBytes];
        new DataPacketHeader(1, 1).Write(encoded);
        encoded[0] = (byte)PacketType.HandshakeInit;

        Assert.False(DataPacketHeader.TryRead(encoded, out _));
    }

    [Fact]
    public void PacketType_ValuesAreOutsideTheStunRange()
    {
        // STUN messages begin with 0x00 or 0x01. One socket carries both, so a collision
        // here would make path probing and session traffic indistinguishable.
        foreach (PacketType type in Enum.GetValues<PacketType>())
        {
            Assert.True((byte)type >= 0x20, $"{type} = 0x{(byte)type:x2} collides with the STUN range");
            Assert.True((byte)type <= 0x2F, $"{type} = 0x{(byte)type:x2} is outside the reserved range");
        }
    }

    [Fact]
    public void HandshakePacket_FinishThenTryParse_RoundTrips()
    {
        byte[] recipientKey = new byte[32];
        recipientKey[0] = 7;

        byte[] mac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(recipientKey, mac1Key);

        byte[] noiseMessage = [1, 2, 3, 4, 5];
        byte[] packet = new byte[HandshakePacket.OverheadInBytes + noiseMessage.Length];
        noiseMessage.CopyTo(packet.AsSpan(HandshakePacket.HeaderSizeInBytes));

        int length = HandshakePacket.Finish(
            packet,
            PacketType.HandshakeInit,
            senderIndex: 0xAABBCCDD,
            receiverIndex: 0,
            noiseMessage.Length,
            mac1Key);

        Assert.Equal(packet.Length, length);

        Assert.True(HandshakePacket.TryParse(
            packet,
            PacketType.HandshakeInit,
            mac1Key,
            out uint senderIndex,
            out uint receiverIndex,
            out ReadOnlySpan<byte> parsedNoise));

        Assert.Equal(0xAABBCCDDu, senderIndex);
        Assert.Equal(0u, receiverIndex);
        Assert.Equal(noiseMessage, parsedNoise.ToArray());
    }

    [Fact]
    public void HandshakePacket_TryParse_WrongMac1Key_ReturnsFalse()
    {
        // This is the cheap filter that runs before any Diffie-Hellman. A packet from
        // someone who does not know who they are addressing must not get past it.
        byte[] mac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(new byte[32], mac1Key);

        byte[] packet = new byte[HandshakePacket.OverheadInBytes + 8];
        HandshakePacket.Finish(packet, PacketType.HandshakeInit, 1, 0, 8, mac1Key);

        byte[] otherRecipient = new byte[32];
        otherRecipient[31] = 1;
        byte[] otherKey = new byte[32];
        HandshakePacket.DeriveMac1Key(otherRecipient, otherKey);

        Assert.False(HandshakePacket.TryParse(packet, PacketType.HandshakeInit, otherKey, out _, out _, out _));
    }

    [Fact]
    public void HandshakePacket_TryParse_TamperedBody_ReturnsFalse()
    {
        byte[] mac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(new byte[32], mac1Key);

        byte[] packet = new byte[HandshakePacket.OverheadInBytes + 8];
        HandshakePacket.Finish(packet, PacketType.HandshakeInit, 1, 0, 8, mac1Key);

        packet[HandshakePacket.HeaderSizeInBytes] ^= 0x01;

        Assert.False(HandshakePacket.TryParse(packet, PacketType.HandshakeInit, mac1Key, out _, out _, out _));
    }

    [Fact]
    public void HandshakePacket_TryParse_WrongTypeOrVersion_ReturnsFalse()
    {
        byte[] mac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(new byte[32], mac1Key);

        byte[] packet = new byte[HandshakePacket.OverheadInBytes + 8];
        HandshakePacket.Finish(packet, PacketType.HandshakeInit, 1, 0, 8, mac1Key);

        Assert.False(HandshakePacket.TryParse(packet, PacketType.HandshakeResponse, mac1Key, out _, out _, out _));

        packet[1] = 99;
        Assert.False(HandshakePacket.TryParse(packet, PacketType.HandshakeInit, mac1Key, out _, out _, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(HandshakePacket.OverheadInBytes)]
    public void HandshakePacket_TryParse_NoRoomForANoiseMessage_ReturnsFalse(int length)
    {
        byte[] mac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(new byte[32], mac1Key);

        Assert.False(HandshakePacket.TryParse(new byte[length], PacketType.HandshakeInit, mac1Key, out _, out _, out _));
    }
}
