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

    private bool _isDisposed;

    public RelayClient(
        RelayConnection connection,
        NodeId nodeId,
        int sendQueueCapacity,
        int packetsPerSecond,
        TimeProvider timeProvider)
    {
        _connection = connection;
        NodeId = nodeId;
        _rateLimit = new TokenBucket(packetsPerSecond, timeProvider);

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
        if (_isDisposed)
        {
            return;
        }

        _isDisposed = true;

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

        while (!cancellationToken.IsCancellationRequested)
        {
            RelayFrame frame = await _connection.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> payload = buffer.AsMemory(1, frame.PayloadLength);

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

    private readonly record struct QueuedPacket(NodeId Source, byte[] Body, int Length)
    {
        public void Return() => ArrayPool<byte>.Shared.Return(Body);
    }
}
