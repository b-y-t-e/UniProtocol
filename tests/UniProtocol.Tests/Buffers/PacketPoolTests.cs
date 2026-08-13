using UniProtocol.Buffers;

namespace UniProtocol.Tests.Buffers;

public sealed class PacketPoolTests
{
    [Fact]
    public void Rent_ReturnsABufferOfTheDeclaredSize()
    {
        PacketPool pool = new();

        using Packet packet = pool.Rent();

        Assert.Equal(PacketPool.PacketSizeInBytes, packet.Buffer.Length);
        Assert.Equal(0, packet.Length);
        Assert.Equal(0, packet.Offset);
    }

    [Fact]
    public void Rent_AfterReturn_ReusesTheSameInstance()
    {
        // The point of the pool: steady-state allocation must be zero.
        PacketPool pool = new();

        Packet first = pool.Rent();
        first.Dispose();

        Packet second = pool.Rent();

        Assert.Same(first, second);
        second.Dispose();
    }

    [Fact]
    public void Rent_ResetsStateFromThePreviousUse()
    {
        PacketPool pool = new();

        Packet packet = pool.Rent();
        packet.Length = 100;
        packet.Offset = 16;
        packet.Dispose();

        using Packet reused = pool.Rent();

        Assert.Equal(0, reused.Length);
        Assert.Equal(0, reused.Offset);
    }

    [Fact]
    public void Dispose_CalledTwice_Throws()
    {
        // A double return would hand the same buffer to two owners, and the resulting
        // corruption surfaces far from its cause. Failing immediately is the whole point.
        PacketPool pool = new();

        Packet packet = pool.Rent();
        packet.Dispose();

        Assert.Throws<InvalidOperationException>(packet.Dispose);
    }

    [Fact]
    public void Buffer_AfterReturn_Throws()
    {
        PacketPool pool = new();

        Packet packet = pool.Rent();
        packet.Dispose();

        Assert.Throws<ObjectDisposedException>(() => packet.Buffer);
    }

    [Fact]
    public void Span_RespectsOffsetAndLength()
    {
        PacketPool pool = new();

        using Packet packet = pool.Rent();
        packet.Buffer.Span[16] = 0xAB;
        packet.Offset = 16;
        packet.Length = 1;

        Assert.Equal(1, packet.Span.Length);
        Assert.Equal(0xAB, packet.Span[0]);
    }

    [Fact]
    public void Rent_MoreThanOneSlab_KeepsWorking()
    {
        PacketPool pool = new();

        List<Packet> packets = [];

        for (int i = 0; i < 200; i++)
        {
            packets.Add(pool.Rent());
        }

        Assert.Equal(200, packets.Distinct().Count());

        foreach (Packet packet in packets)
        {
            packet.Dispose();
        }
    }

    [Fact]
    public void Return_BeyondTheRetentionCap_DropsTheExtraPackets()
    {
        PacketPool pool = new(maximumRetained: 32);

        List<Packet> packets = [];
        for (int i = 0; i < 200; i++)
        {
            packets.Add(pool.Rent());
        }

        foreach (Packet packet in packets)
        {
            packet.Dispose();
        }

        // A burst must not permanently inflate the pool's memory footprint.
        Assert.True(pool.AvailableCount <= 64, $"the pool retained {pool.AvailableCount} packets");
    }
}
