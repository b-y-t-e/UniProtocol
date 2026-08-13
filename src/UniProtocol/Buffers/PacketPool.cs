using System.Collections.Concurrent;

namespace UniProtocol.Buffers;

/// <summary>
/// A pool of fixed-size datagram buffers carved out of pinned slabs.
/// </summary>
/// <remarks>
/// <para>
/// Buffers are allocated in the pinned object heap and sliced into packet-sized pieces.
/// Socket I/O pins whatever buffer it is given for the duration of the operation, and a
/// steady stream of pinning requests against the normal heap fragments it and interferes
/// with compaction. Allocating pinned up front makes that a non-issue and costs one
/// allocation per slab.
/// </para>
/// <para>
/// This is why the pool exists rather than <c>ArrayPool&lt;byte&gt;</c>: the goal is not
/// avoiding allocation — <c>ArrayPool</c> does that too — but keeping the buffers involved
/// in socket calls out of the compacting heap entirely.
/// </para>
/// <para>
/// Reuse is last-in, first-out. The most recently returned buffer is the one most likely to
/// still be in cache, and on the receive path a packet is typically rented, processed and
/// returned within microseconds.
/// </para>
/// </remarks>
public sealed class PacketPool
{
    /// <summary>
    /// Size of one packet buffer.
    /// </summary>
    /// <remarks>
    /// Comfortably above the largest path MTU we will ever probe for (1500), with room for
    /// a jumbo-frame local link, so a datagram is never truncated by the buffer.
    /// </remarks>
    public const int PacketSizeInBytes = 2048;

    private const int PacketsPerSlab = 32;
    private const int SlabSizeInBytes = PacketSizeInBytes * PacketsPerSlab;

    private readonly ConcurrentStack<Packet> _available = new();
    private readonly int _maximumRetained;

    // Tracked separately because ConcurrentStack.Count walks the whole stack, and the
    // retention check runs on every returned packet.
    private int _availableCount;

    /// <summary>Creates a pool retaining at most <paramref name="maximumRetained"/> packets.</summary>
    /// <remarks>
    /// The cap bounds memory when a burst inflates the pool: packets beyond it are dropped
    /// on return and collected normally, rather than being kept alive forever because one
    /// peer once sent a flood.
    /// </remarks>
    public PacketPool(int maximumRetained = 1024)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumRetained, PacketsPerSlab);

        _maximumRetained = maximumRetained;
    }

    /// <summary>Number of packets currently held for reuse.</summary>
    public int AvailableCount => Volatile.Read(ref _availableCount);

    /// <summary>Rents a packet. Return it with <see cref="Packet.Dispose"/>.</summary>
    public Packet Rent()
    {
        if (!TryTake(out Packet? packet))
        {
            AllocateSlab();

            if (!TryTake(out packet))
            {
                // Another thread drained the slab we just added; a standalone buffer is
                // cheaper than spinning, and it joins the pool the first time it is returned.
                packet = new Packet(this, GC.AllocateUninitializedArray<byte>(PacketSizeInBytes, pinned: true));
            }
        }

        packet.IsRented = true;
        packet.Length = 0;
        packet.Offset = 0;
        packet.RemotePath = default;

        return packet;
    }

    internal void Return(Packet packet)
    {
        ArgumentNullException.ThrowIfNull(packet);

        if (!packet.IsRented)
        {
            throw new InvalidOperationException("This packet has already been returned to the pool.");
        }

        packet.IsRented = false;

        // A soft cap: concurrent returns can briefly overshoot it, which costs one extra
        // retained buffer and is not worth stricter synchronisation to prevent.
        if (Volatile.Read(ref _availableCount) >= _maximumRetained)
        {
            return;
        }

        _available.Push(packet);
        Interlocked.Increment(ref _availableCount);
    }

    private bool TryTake([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Packet? packet)
    {
        if (!_available.TryPop(out packet))
        {
            return false;
        }

        Interlocked.Decrement(ref _availableCount);
        return true;
    }

    private void AllocateSlab()
    {
        byte[] slab = GC.AllocateUninitializedArray<byte>(SlabSizeInBytes, pinned: true);

        for (int offset = 0; offset < SlabSizeInBytes; offset += PacketSizeInBytes)
        {
            _available.Push(new Packet(this, slab.AsMemory(offset, PacketSizeInBytes)));
            Interlocked.Increment(ref _availableCount);
        }
    }
}
