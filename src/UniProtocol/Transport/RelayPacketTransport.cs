using System.Buffers;
using System.Runtime.CompilerServices;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using UniProtocol.Abstractions;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;

namespace UniProtocol.Transport;

/// <summary>
/// An <see cref="IPacketTransport"/> that carries packets through a relay server.
/// </summary>
/// <remarks>
/// <para>
/// The point of implementing the ordinary transport interface is that nothing above it
/// changes. The peer-to-peer handshake, the session, the replay window and the application
/// are identical whether a packet crossed the internet directly or was forwarded by a
/// relay — which is exactly what will later allow a live connection to be moved from one to
/// the other without renegotiating anything.
/// </para>
/// <para>
/// The connection to the relay is maintained in the background and re-established with
/// backoff when it drops. Packets sent while it is down are discarded rather than queued:
/// this is a datagram transport, the layers above already recover from loss, and a queue
/// would deliver a burst of stale packets at exactly the wrong moment.
/// </para>
/// </remarks>
#pragma warning disable RS0030 // Adapter boundary: the relay client owns a TCP socket.
public sealed partial class RelayPacketTransport : IPacketTransport
{
    private readonly RelayAddress _relayAddress;
    private readonly UniIdentity _identity;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<RelayPacketTransport> _logger;
    private readonly Channel<ReceivedPacket> _received;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TaskCompletionSource _firstConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private volatile RelayConnection? _connection;
    private Task? _maintainLoop;
    private bool _isDisposed;

    private RelayPacketTransport(
        RelayAddress relayAddress,
        UniIdentity identity,
        TimeProvider timeProvider,
        ILoggerFactory loggerFactory,
        int receiveQueueCapacity)
    {
        _relayAddress = relayAddress;
        _identity = identity;
        _timeProvider = timeProvider;
        _logger = loggerFactory.CreateLogger<RelayPacketTransport>();

        _received = Channel.CreateBounded<ReceivedPacket>(
            new BoundedChannelOptions(receiveQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleWriter = true,
            },
            static dropped => dropped.Return());
    }

    /// <inheritdoc />
    /// <remarks>
    /// A relayed path has no local IP address of its own; peers address this node by its
    /// <see cref="NodeId"/> and the relay resolves that to a connection.
    /// </remarks>
    public NetworkAddress LocalAddress => default;

    /// <inheritdoc />
    public PathKind SupportedPathKind => PathKind.Relay;

    /// <summary>The relay this transport is configured to use.</summary>
    public RelayAddress RelayAddress => _relayAddress;

    /// <summary>Indicates whether the relay connection is currently up.</summary>
    public bool IsConnected => _connection is not null;

    /// <summary>
    /// Creates the transport and begins connecting to <paramref name="relayAddress"/>.
    /// </summary>
    /// <remarks>
    /// Returns immediately; use <see cref="WaitUntilConnectedAsync"/> to wait for the relay
    /// to be usable. Starting without blocking means an endpoint comes up even when the
    /// relay is temporarily unreachable, and starts working the moment it returns.
    /// </remarks>
    public static RelayPacketTransport Create(
        RelayAddress relayAddress,
        UniIdentity identity,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        int receiveQueueCapacity = 512)
    {
        ArgumentNullException.ThrowIfNull(relayAddress);
        ArgumentNullException.ThrowIfNull(identity);

        RelayPacketTransport transport = new(
            relayAddress,
            identity,
            timeProvider ?? TimeProvider.System,
            loggerFactory ?? NullLoggerFactory.Instance,
            receiveQueueCapacity);

        transport._maintainLoop = Task.Run(() => transport.MaintainConnectionAsync(transport._shutdown.Token));

        return transport;
    }

    /// <summary>Waits until the relay connection is established.</summary>
    public async Task WaitUntilConnectedAsync(CancellationToken cancellationToken = default)
    {
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _shutdown.Token);

        await _firstConnection.Task.WaitAsync(linked.Token).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> payload,
        PathEndpoint destination,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (destination.Kind != PathKind.Relay)
        {
            throw new ArgumentException(
                $"A relay transport cannot reach a {destination.Kind} destination.",
                nameof(destination));
        }

        RelayConnection? connection = _connection;

        if (connection is null)
        {
            // Reconnecting. Dropping is the honest behaviour for a datagram transport.
            return;
        }

        byte[] header = ArrayPool<byte>.Shared.Rent(NodeId.SizeInBytes);

        try
        {
            destination.NodeId.CopyTo(header);

            await connection
                .SendAsync(RelayFrameType.SendPacket, header.AsMemory(0, NodeId.SizeInBytes), payload, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException or RelayProtocolException)
        {
            // The connection died mid-send; the maintain loop will notice and reconnect.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    /// <inheritdoc />
    public async ValueTask<PacketReceiveResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _shutdown.Token);

        ReceivedPacket packet = await _received.Reader.ReadAsync(linked.Token).ConfigureAwait(false);

        try
        {
            if (packet.Length > buffer.Length)
            {
                // Cannot fit, so it is dropped — the same outcome as an oversized datagram.
                return new PacketReceiveResult(0, default);
            }

            packet.Body.AsSpan(0, packet.Length).CopyTo(buffer.Span);

            return new PacketReceiveResult(packet.Length, PathEndpoint.ToRelayedNode(packet.Source));
        }
        finally
        {
            packet.Return();
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
        await _shutdown.CancelAsync().ConfigureAwait(false);

        if (_maintainLoop is not null)
        {
            try
            {
                await _maintainLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected: the loop exits by cancellation.
            }
        }

        _received.Writer.TryComplete();

        while (_received.Reader.TryRead(out ReceivedPacket packet))
        {
            packet.Return();
        }

        _shutdown.Dispose();
    }

    private async Task MaintainConnectionAsync(CancellationToken cancellationToken)
    {
        TimeSpan retryDelay = TimeSpan.FromSeconds(1);
        TimeSpan maximumRetryDelay = TimeSpan.FromSeconds(30);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                RelayConnection connection = await ConnectAsync(cancellationToken).ConfigureAwait(false);
                await using ConfiguredAsyncDisposable scope = connection.ConfigureAwait(false);

                _connection = connection;
                _firstConnection.TrySetResult();
                retryDelay = TimeSpan.FromSeconds(1);

                LogRelayConnected(_relayAddress.Host, _relayAddress.Port);

                using CancellationTokenSource connectionScope = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                Task keepAlive = SendKeepAlivesAsync(connection, connectionScope.Token);
                Task receive = ReceiveLoopAsync(connection, connectionScope.Token);

                await Task.WhenAny(keepAlive, receive).ConfigureAwait(false);
                await connectionScope.CancelAsync().ConfigureAwait(false);

                try
                {
                    await Task.WhenAll(keepAlive, receive).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsExpectedDisconnect(exception))
                {
                    // Normal teardown.
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception) when (IsExpectedDisconnect(exception))
            {
                LogRelayUnavailable(_relayAddress.Host, _relayAddress.Port, exception.Message);
            }
            finally
            {
                _connection = null;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                await Task.Delay(retryDelay, _timeProvider, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            // Backing off keeps a node from hammering a relay that is restarting, while
            // still recovering within a second from a brief network blip.
            retryDelay = retryDelay < maximumRetryDelay
                ? TimeSpan.FromTicks(Math.Min(retryDelay.Ticks * 2, maximumRetryDelay.Ticks))
                : maximumRetryDelay;
        }
    }

    private async Task<RelayConnection> ConnectAsync(CancellationToken cancellationToken)
    {
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

        try
        {
            await socket.ConnectAsync(_relayAddress.Host, _relayAddress.Port, cancellationToken).ConfigureAwait(false);

            NetworkStream stream = new(socket, ownsSocket: true);

            return await RelayConnection
                .ConnectAsync(stream, _identity, _relayAddress.NodeId, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private async Task ReceiveLoopAsync(RelayConnection connection, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[RelayProtocol.MaximumFrameSizeInBytes];

        while (!cancellationToken.IsCancellationRequested)
        {
            RelayFrame frame = await connection.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);

            // Logged rather than acted on. A relay saying "that peer is not here" is a
            // useful hint and an untrusted one: acting on it would let a relay end a dial
            // that the direct candidates racing alongside it were about to win. Failing the
            // relay path alone, while the rest keep running, is path management's job.
            if (frame.Type == RelayFrameType.PeerGone && frame.PayloadLength >= NodeId.SizeInBytes)
            {
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    NodeId absent = NodeId.FromPublicKey(buffer.AsSpan(1, NodeId.SizeInBytes));
                    LogPeerGone(absent);
                }

                continue;
            }

            if (frame.Type != RelayFrameType.ReceivePacket || frame.PayloadLength <= NodeId.SizeInBytes)
            {
                continue;
            }

            ReadOnlySpan<byte> payload = buffer.AsSpan(1, frame.PayloadLength);
            NodeId source = NodeId.FromPublicKey(payload[..NodeId.SizeInBytes]);
            ReadOnlySpan<byte> body = payload[NodeId.SizeInBytes..];

            byte[] copy = ArrayPool<byte>.Shared.Rent(body.Length);
            body.CopyTo(copy);

            if (!_received.Writer.TryWrite(new ReceivedPacket(source, copy, body.Length)))
            {
                ArrayPool<byte>.Shared.Return(copy);
            }
        }
    }

    private async Task SendKeepAlivesAsync(RelayConnection connection, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(RelayProtocol.KeepAliveInterval, _timeProvider, cancellationToken).ConfigureAwait(false);
            await connection.SendAsync(RelayFrameType.KeepAlive, default, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsExpectedDisconnect(Exception exception) => exception
        is IOException
        or SocketException
        or EndOfStreamException
        or ObjectDisposedException
        or RelayProtocolException;

    [LoggerMessage(EventId = 4000, Level = LogLevel.Information, Message = "Connected to relay {Host}:{Port}.")]
    private partial void LogRelayConnected(string host, int port);

    [LoggerMessage(EventId = 4001, Level = LogLevel.Warning, Message = "Relay {Host}:{Port} is unavailable: {Reason}.")]
    private partial void LogRelayUnavailable(string host, int port, string reason);

    [LoggerMessage(
        EventId = 4002,
        Level = LogLevel.Debug,
        Message = "The relay reports that {NodeId} is not connected to it.")]
    private partial void LogPeerGone(NodeId nodeId);

    private readonly record struct ReceivedPacket(NodeId Source, byte[] Body, int Length)
    {
        public void Return() => ArrayPool<byte>.Shared.Return(Body);
    }
}
#pragma warning restore RS0030
