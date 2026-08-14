using System.Buffers;
using System.Threading.Channels;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;

namespace UniProtocol.Server;

/// <summary>
/// One connected client: its connection, its outbound queue and its rate limit.
/// </summary>
/// <remarks>
/// Reading and writing run as separate loops. A client that stops reading must not be able
/// to block the server from reading <em>its</em> traffic, and a packet queued for it must
/// not stall the peer that sent it — so the two directions are decoupled by a bounded queue
/// that drops rather than blocks.
/// </remarks>
internal sealed class RelayClient : IAsyncDisposable
{
    private readonly RelayConnection _connection;
    private readonly Channel<QueuedPacket> _outbound;
    private readonly TokenBucket _rateLimit;
    private readonly CancellationTokenSource _closed = new();
    private readonly TimeSpan _idleTimeout;

    /// <summary>
    /// Closes the connection when nothing has been heard for <see cref="_idleTimeout"/>.
    /// </summary>
    /// <remarks>
    /// A timer reset per frame rather than a deadline per read: a client under load sends
    /// hundreds of frames a second, and allocating a cancellation source for each of them to
    /// enforce a ninety-second limit is work out of all proportion to the job.
    /// </remarks>
    private readonly ITimer _idleTimer;

    /// <summary>
    /// Non-zero once disposed; an int because the transition is read from the timer callback
    /// thread and made from whichever thread ends the connection.
    /// </summary>
    private int _disposeState;

    public RelayClient(
        RelayConnection connection,
        NodeId nodeId,
        int sendQueueCapacity,
        int packetsPerSecond,
        TimeSpan idleTimeout,
        TimeProvider timeProvider)
    {
        _connection = connection;
        NodeId = nodeId;
        _rateLimit = new TokenBucket(packetsPerSecond, timeProvider);
        _idleTimeout = idleTimeout;

        // Created stopped; the read loop arms it. A client that never gets that far is
        // already bounded by the handshake timeout.
        _idleTimer = timeProvider.CreateTimer(
            static state => ((RelayClient)state!).OnIdle(),
            this,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);

        _outbound = Channel.CreateBounded<QueuedPacket>(
            new BoundedChannelOptions(sendQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            },
            static dropped => dropped.Return());
    }

    /// <summary>The client's identity.</summary>
    public NodeId NodeId { get; }

    /// <summary>Queues a packet for delivery to this client.</summary>
    /// <remarks>
    /// Copies the body, because the caller's buffer belongs to the sending client's read
    /// loop and is reused as soon as this returns.
    /// </remarks>
    public void Enqueue(NodeId source, ReadOnlyMemory<byte> body)
    {
        byte[] copy = ArrayPool<byte>.Shared.Rent(body.Length);
        body.CopyTo(copy);

        if (!_outbound.Writer.TryWrite(new QueuedPacket(source, copy, body.Length)))
        {
            ArrayPool<byte>.Shared.Return(copy);
        }
    }

    /// <summary>
    /// Tells this client that a node it addressed is not connected here.
    /// </summary>
    /// <remarks>
    /// Sent straight down the connection rather than through the outbound queue, because the
    /// queue exists to absorb bursts of forwarded traffic and this is an answer to something
    /// the client just asked. Sends are serialised inside the connection, so this cannot
    /// interleave with the write loop. It is not an amplification vector either: the reply is
    /// smaller than the frame that provoked it and is already behind the rate limit.
    /// </remarks>
    public ValueTask SendPeerGoneAsync(NodeId missing)
    {
        byte[] payload = new byte[NodeId.SizeInBytes];
        missing.CopyTo(payload);

        return _connection.SendAsync(RelayFrameType.PeerGone, payload, _closed.Token);
    }

    /// <summary>Runs the read and write loops until the connection ends.</summary>
    public async Task RunAsync(
        Func<NodeId, NodeId, ReadOnlyMemory<byte>, ValueTask> forward,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _closed.Token);

        Task write = WriteLoopAsync(linked.Token);
        Task read = ReadLoopAsync(forward, linked.Token);

        // Whichever ends first ends the other: a dead connection is dead in both directions.
        await Task.WhenAny(read, write).ConfigureAwait(false);
        await _closed.CancelAsync().ConfigureAwait(false);

        try
        {
            await Task.WhenAll(read, write).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or RelayProtocolException)
        {
            // Expected as the connection tears down.
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }

        // Disposed first, and awaited: DisposeAsync on a timer does not return until any
        // callback already running has finished. Cancelling the source before that could put
        // OnIdle on a disposed source. The flag alone cannot close that window — the callback
        // may have passed its check already.
        await _idleTimer.DisposeAsync().ConfigureAwait(false);

        await _closed.CancelAsync().ConfigureAwait(false);
        _outbound.Writer.TryComplete();

        while (_outbound.Reader.TryRead(out QueuedPacket queued))
        {
            queued.Return();
        }

        await _connection.DisposeAsync().ConfigureAwait(false);
        _closed.Dispose();
    }

    private async Task ReadLoopAsync(
        Func<NodeId, NodeId, ReadOnlyMemory<byte>, ValueTask> forward,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[RelayProtocol.MaximumFrameSizeInBytes];

        ResetIdleTimer();

        while (!cancellationToken.IsCancellationRequested)
        {
            RelayFrame frame = await _connection.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> payload = buffer.AsMemory(1, frame.PayloadLength);

            // Any frame counts as a sign of life, keep-alives included — that is what they
            // are for.
            ResetIdleTimer();

            switch (frame.Type)
            {
                case RelayFrameType.SendPacket:
                    if (payload.Length <= NodeId.SizeInBytes || !_rateLimit.TryConsume())
                    {
                        break;
                    }

                    await forward(
                            NodeId,
                            NodeId.FromPublicKey(payload.Span[..NodeId.SizeInBytes]),
                            payload[NodeId.SizeInBytes..])
                        .ConfigureAwait(false);
                    break;

                case RelayFrameType.Ping:
                    // Behind the same rate limit as forwarding. A Pong echoes the ping's
                    // payload, which the client chooses and which may be the largest frame
                    // the protocol allows — so an unlimited ping is an unlimited demand on
                    // the server's CPU and uplink, and the one exchange in the protocol where
                    // a client can make the server send as much as it likes.
                    if (!_rateLimit.TryConsume())
                    {
                        break;
                    }

                    await _connection.SendAsync(RelayFrameType.Pong, payload, cancellationToken).ConfigureAwait(false);
                    break;

                case RelayFrameType.KeepAlive:
                case RelayFrameType.Pong:
                    break;

                default:
                    // Unknown and server-only frames are ignored rather than treated as an
                    // attack, so a newer client can send something we do not know about.
                    break;
            }
        }
    }

    private async Task WriteLoopAsync(CancellationToken cancellationToken)
    {
        byte[] sourceHeader = new byte[NodeId.SizeInBytes];

        await foreach (QueuedPacket queued in _outbound.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                queued.Source.CopyTo(sourceHeader);

                await _connection
                    .SendAsync(
                        RelayFrameType.ReceivePacket,
                        sourceHeader,
                        queued.Body.AsMemory(0, queued.Length),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                queued.Return();
            }
        }
    }

    private void ResetIdleTimer()
    {
        try
        {
            _idleTimer.Change(_idleTimeout, Timeout.InfiniteTimeSpan);
        }
        catch (ObjectDisposedException)
        {
            // The client was disposed between the check and the call. Rearming a timer that
            // no longer exists is exactly as harmless as it sounds.
        }
    }

    /// <summary>Ends a connection that has gone silent.</summary>
    /// <remarks>
    /// The socket may look open indefinitely after the peer has gone — a laptop closed, a
    /// mobile network handing over — and nothing else on the server would ever notice.
    /// </remarks>
    private void OnIdle()
    {
        if (Volatile.Read(ref _disposeState) != 0)
        {
            return;
        }

        try
        {
            _closed.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposal won the race. There is nothing left to cancel, which is the outcome
            // this method wanted anyway.
        }
    }

    private readonly record struct QueuedPacket(NodeId Source, byte[] Body, int Length)
    {
        public void Return() => ArrayPool<byte>.Shared.Return(Body);
    }
}
