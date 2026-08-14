using UniProtocol.Protocol;

namespace UniProtocol.Buffers;

/// <summary>
/// A fixed-size datagram buffer rented from a <see cref="PacketPool"/>.
/// </summary>
/// <remarks>
/// <para>
/// A pooled class rather than a struct handle. A struct would avoid the object header, but
/// the buffer is passed between the receive loop, the frame parser and per-connection
/// queues, and a struct handle copied along that path makes double-return bugs both easy
/// to write and very hard to find. The object itself is reused, so the steady-state
/// allocation rate is still zero — which is the property that actually matters.
/// </para>
/// <para>
/// Returning a packet twice, or using one after returning it, throws — but only while the
/// packet is still on the free list. <strong>Once it has been rented again the checks go
/// quiet</strong>, because the flag they read belongs to the packet, not to the reference
/// that was supposed to have finished with it: a stale reference sees a rented packet and
/// happily reads and writes the new owner's datagram, and a stale return hands a live packet
/// back to the pool. On the receive path a packet is rented again within microseconds, so
/// this is the common case rather than the rare one.
/// </para>
/// <para>
/// So the checks catch the mistake that is easy to make — returning twice in a row, using a
/// packet just after disposing it — and cannot catch the one that is hard to find. Treating
/// them as a safety net is the error; the discipline that actually holds is that exactly one
/// place owns a packet at a time, which is why <c>TryAcceptDataPacket</c> transfers ownership
/// by return value rather than leaving it ambiguous.
/// </para>
/// </remarks>
public sealed class Packet : IDisposable
{
    private readonly PacketPool _pool;
    private readonly Memory<byte> _buffer;

    internal Packet(PacketPool pool, Memory<byte> buffer)
    {
        _pool = pool;
        _buffer = buffer;
    }

    /// <summary>Whether this packet is currently rented. Used to catch double returns.</summary>
    internal bool IsRented { get; set; }

    /// <summary>Number of meaningful bytes, starting at <see cref="Offset"/>.</summary>
    public int Length { get; set; }

    /// <summary>
    /// Where the meaningful bytes start within <see cref="Buffer"/>.
    /// </summary>
    /// <remarks>
    /// Lets a packet be decrypted in place — plaintext written exactly over the ciphertext
    /// it came from — and then handed on without shifting the payload down to offset zero.
    /// The shift would be a second pass over every byte received, and, because it overlaps
    /// its own source, it is the kind of aliasing that some AEAD implementations refuse.
    /// </remarks>
    public int Offset { get; set; }

    /// <summary>Which path the datagram arrived over, or is going out on.</summary>
    public PathEndpoint RemotePath { get; set; }

    /// <summary>The full buffer, of <see cref="PacketPool.PacketSizeInBytes"/> bytes.</summary>
    public Memory<byte> Buffer
    {
        get
        {
            ThrowIfReturned();
            return _buffer;
        }
    }

    /// <summary>The meaningful bytes, as indicated by <see cref="Length"/>.</summary>
    public Span<byte> Span
    {
        get
        {
            ThrowIfReturned();
            return _buffer.Span.Slice(Offset, Length);
        }
    }

    /// <summary>Returns the packet to its pool.</summary>
    public void Dispose() => _pool.Return(this);

    private void ThrowIfReturned()
    {
        if (!IsRented)
        {
            throw new ObjectDisposedException(nameof(Packet), "This packet has already been returned to the pool.");
        }
    }
}
