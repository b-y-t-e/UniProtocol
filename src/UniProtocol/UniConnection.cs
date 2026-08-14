using System.Threading.Channels;
using UniProtocol.Buffers;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Packets;
using UniProtocol.Sessions;
using UniProtocol.Transport;

namespace UniProtocol;

/// <summary>
/// An authenticated, encrypted connection to one peer.
/// </summary>
/// <remarks>
/// <para>
/// At this milestone a connection carries unreliable datagrams only. Ordered, reliable
/// streams arrive with the transport layer; <see cref="SendDatagramAsync"/> keeps the same
/// meaning once they do, because a datagram is a distinct service and not a stepping stone
/// to one.
/// </para>
/// <para>
/// <see cref="RemotePath"/> is mutable on purpose. The session is keyed by an identifier
/// that is independent of the network path, so a connection can move from a relay to a
/// direct link — or between Wi-Fi and cellular — by changing this one field, with no effect
/// on anything above.
/// </para>
/// </remarks>
public sealed class UniConnection : IAsyncDisposable
{
    /// <summary>
    /// The packet size assumed before path MTU discovery has run.
    /// </summary>
    /// <remarks>
    /// 1200 bytes is the largest datagram IPv6 guarantees will not be dropped for size
    /// alone, and it is what every QUIC implementation starts from for the same reason.
    /// </remarks>
    private const int DefaultPathMaximumTransmissionUnit = 1200;

    private readonly PacketRouter _router;
    private readonly PacketPool _pool;
    private readonly UniSession _session;
    private readonly Channel<Packet> _received;
    private readonly CancellationTokenSource _closed = new();

    /// <summary>
    /// Guards <see cref="RemotePath"/>, which is wider than a machine word.
    /// </summary>
    /// <remarks>
    /// A receive loop adopting a new path writes it while a sender reads it. Without this
    /// the reader can observe a half-updated struct — a relay path carrying a direct
    /// address — and send the packet nowhere.
    /// </remarks>
    private readonly Lock _pathLock = new();

    private int _pathMaximumTransmissionUnit = DefaultPathMaximumTransmissionUnit;

    private PathEndpoint _remotePath;
    private byte[]? _cachedHandshakeResponse;
    private int _cachedHandshakeResponseLength;
    /// <summary>Non-zero once <see cref="DisposeAsync"/> has run; an int so the transition is atomic.</summary>
    private int _disposeState;

    internal UniConnection(
        PacketRouter router,
        PacketPool pool,
        UniSession session,
        NodeId remoteNodeId,
        PathEndpoint remotePath,
        int receiveQueueCapacity)
    {
        _router = router;
        _pool = pool;
        _session = session;

        RemoteNodeId = remoteNodeId;
        _remotePath = remotePath;

        // Datagrams are unreliable by contract, so a slow reader drops the oldest rather
        // than stalling the endpoint's single receive loop, which serves every peer.
        // The drop callback is what keeps discarded packets from leaking out of the pool.
        _received = Channel.CreateBounded<Packet>(
            new BoundedChannelOptions(receiveQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,

                // One receive loop per transport, so a session that spans a relay and a
                // direct path has two writers.
                SingleWriter = false,
            },
            static dropped => dropped.Dispose());
    }

    /// <summary>The identity of the peer, authenticated by the handshake.</summary>
    public NodeId RemoteNodeId { get; }

    /// <summary>The path packets are currently sent over.</summary>
    /// <remarks>
    /// Mutable because it changes: a connection that started over a relay becomes direct
    /// once a working direct path is found, and a device that moves between networks keeps
    /// the same session on a new address.
    /// </remarks>
    public PathEndpoint RemotePath
    {
        get
        {
            lock (_pathLock)
            {
                return _remotePath;
            }
        }

        internal set
        {
            lock (_pathLock)
            {
                _remotePath = value;
            }
        }
    }

    /// <summary>Number of packets sent on this connection.</summary>
    public ulong PacketsSent => _session.PacketsSent;

    /// <summary>Largest datagram payload that fits in one packet.</summary>
    /// <remarks>
    /// Tracks the path MTU, so it changes over the life of a connection: it drops when the
    /// connection is relayed and rises when probing finds a larger path. Read it per send
    /// rather than caching it. Until path MTU discovery exists it stays at the
    /// IPv6-guaranteed minimum, which is the only value that is safe everywhere.
    /// </remarks>
    public int MaxDatagramSize => _pathMaximumTransmissionUnit - UniSession.OverheadInBytes;

    internal uint LocalIndex => _session.LocalIndex;

    internal uint RemoteIndex => _session.RemoteIndex;

    /// <summary>
    /// Invoked once when the connection closes, so the endpoint can stop routing to it.
    /// </summary>
    /// <remarks>
    /// Without this the endpoint's dispatch table only ever grows: a long-running node that
    /// dials a thousand peers holds a thousand dead sessions, their keys, their replay
    /// windows and their queues, for as long as the process lives.
    /// </remarks>
    internal Action<UniConnection>? Closed { get; set; }

    private bool IsDisposed => Volatile.Read(ref _disposeState) != 0;

    /// <summary>Encrypts and sends a datagram.</summary>
    /// <remarks>
    /// Delivery is not guaranteed and datagrams may arrive out of order. Duplicates are
    /// suppressed by the session's replay window.
    /// </remarks>
    public async ValueTask SendDatagramAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        if (payload.Length > MaxDatagramSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                payload.Length,
                $"A datagram may carry at most {MaxDatagramSize} bytes on this connection.");
        }

        using Packet packet = _pool.Rent();
        packet.Length = _session.Encrypt(payload.Span, packet.Buffer.Span);

        await _router.SendAsync(packet.Buffer[..packet.Length], RemotePath, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Waits for the next datagram and copies it into <paramref name="buffer"/>.</summary>
    /// <returns>The number of bytes written.</returns>
    public async ValueTask<int> ReceiveDatagramAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _closed.Token);

        Packet packet;

        try
        {
            packet = await _received.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_closed.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new ConnectionClosedException("The connection was closed.");
        }
        catch (ChannelClosedException)
        {
            throw new ConnectionClosedException("The connection was closed.");
        }

        using (packet)
        {
            if (packet.Length > buffer.Length)
            {
                throw new ArgumentException(
                    $"The buffer is too small for a {packet.Length}-byte datagram.",
                    nameof(buffer));
            }

            packet.Span.CopyTo(buffer.Span);
            return packet.Length;
        }
    }

    /// <summary>
    /// Offers a received data packet to this connection, which decrypts it in place.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> if the packet was not for this session, was forged, or was a
    /// replay. Ownership of <paramref name="packet"/> transfers to the connection only when
    /// this returns <see langword="true"/>.
    /// </returns>
    internal bool TryAcceptDataPacket(Packet packet)
    {
        // A packet for a connection that has just closed is an ordinary network event — the
        // peer cannot know yet — so it is dropped, not raised as an error. Letting the
        // session throw here would put an exception on the receive loop that serves every
        // other peer.
        if (IsDisposed)
        {
            return false;
        }

        // Decrypted in place: the plaintext is written exactly over the ciphertext it came
        // from, so the destination and source start at the same offset. That is the only
        // form of overlap every AEAD implementation guarantees to support, and it means a
        // received datagram is never copied between the socket and the application.
        Span<byte> payloadDestination = packet.Buffer.Span[DataPacketHeader.SizeInBytes..];

        if (!_session.TryDecrypt(packet.Span, payloadDestination, out int payloadLength))
        {
            return false;
        }

        // The packet authenticated against this session, so whatever path it arrived on is a
        // path the peer can actually reach us from — adopt it. This is what makes the two
        // sides converge on the same path when the handshake raced a direct address against
        // a relay, and what keeps a session alive when a peer changes network. A forged or
        // replayed packet cannot get here: the tag check and the replay window run first.
        if (!packet.RemotePath.IsNone)
        {
            lock (_pathLock)
            {
                _remotePath = packet.RemotePath;
            }
        }

        packet.Offset = DataPacketHeader.SizeInBytes;
        packet.Length = payloadLength;

        return _received.Writer.TryWrite(packet);
    }

    /// <summary>
    /// Remembers the handshake response sent to this peer, so a retransmitted handshake can
    /// be answered without building a second session.
    /// </summary>
    internal void CacheHandshakeResponse(ReadOnlySpan<byte> response)
    {
        _cachedHandshakeResponse = response.ToArray();
        _cachedHandshakeResponseLength = response.Length;
    }

    /// <summary>Re-sends the cached handshake response, if there is one.</summary>
    internal ValueTask ResendHandshakeResponseAsync(PathEndpoint destination, CancellationToken cancellationToken)
        => _cachedHandshakeResponse is null
            ? ValueTask.CompletedTask
            : _router.SendAsync(
                _cachedHandshakeResponse.AsMemory(0, _cachedHandshakeResponseLength),
                destination,
                cancellationToken);

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        Close();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Closes the connection. Everything a close does is synchronous, so callers that are not
    /// themselves asynchronous do not have to pretend otherwise.
    /// </summary>
    internal void Close()
    {
        // Exchange, not a read followed by a write: two threads closing at once must not
        // both tear the session down and both raise Closed.
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }

        _closed.Cancel();
        _received.Writer.TryComplete();

        while (_received.Reader.TryRead(out Packet? packet))
        {
            packet.Dispose();
        }

        _session.Dispose();
        _closed.Dispose();

        Closed?.Invoke(this);
    }
}
