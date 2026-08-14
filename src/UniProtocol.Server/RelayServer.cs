using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;

namespace UniProtocol.Server;

/// <summary>
/// Forwards encrypted packets between nodes that cannot reach each other directly.
/// </summary>
/// <remarks>
/// <para>
/// This is what makes "connect from anywhere" true. Two devices behind NAT cannot exchange
/// a single packet until something with a reachable address introduces them — no protocol
/// can work around that — so one publicly reachable server is the irreducible requirement.
/// You run one; it serves all your devices.
/// </para>
/// <para>
/// It is deliberately stupid. It learns which node is on which connection and moves opaque
/// bodies between them. It holds no keys of its peers, terminates no sessions, and sees only
/// NodeIds and ciphertext — so a compromised relay can drop traffic and observe who talks to
/// whom, and can neither read nor forge any of it.
/// </para>
/// <para>
/// Once path discovery exists, connections established here are upgraded to direct links and
/// the relay drops out of the data path for the great majority of them.
/// </para>
/// </remarks>
#pragma warning disable RS0030 // Adapter boundary: a server is inherently socket-level.
public sealed partial class RelayServer : IAsyncDisposable
{
    private readonly RelayServerOptions _options;
    private readonly Socket _listener;
    private readonly ILogger<RelayServer> _logger;
    private readonly ConcurrentDictionary<NodeId, RelayClient> _clients = new();

    /// <summary>How many connections each remote address currently holds.</summary>
    /// <remarks>
    /// Counted by address rather than by identity because an unauthenticated connection has
    /// no identity yet — and that is precisely the connection a flood consists of.
    /// </remarks>
    private readonly ConcurrentDictionary<IPAddress, int> _connectionsPerAddress = new();
    private readonly CancellationTokenSource _shutdown = new();

    private int _pendingHandshakes;
    private Task? _acceptLoop;
    private bool _isDisposed;

    private RelayServer(RelayServerOptions options, Socket listener)
    {
        _options = options;
        _listener = listener;
        _logger = options.LoggerFactory.CreateLogger<RelayServer>();

        NodeId = options.Identity.NodeId;
        Port = ((IPEndPoint)listener.LocalEndPoint!).Port;
    }

    /// <summary>The relay's identity. Clients dial this key, not a host name.</summary>
    public NodeId NodeId { get; }

    /// <summary>The port actually bound.</summary>
    public int Port { get; }

    /// <summary>How many clients are connected right now.</summary>
    public int ConnectedClientCount => _clients.Count;

    /// <summary>
    /// How many accepted connections have not yet completed the relay handshake.
    /// </summary>
    /// <remarks>
    /// The number that matters under a flood: unlike <see cref="ConnectedClientCount"/> it
    /// counts connections nobody has had to authenticate for.
    /// </remarks>
    public int PendingHandshakeCount => Volatile.Read(ref _pendingHandshakes);

    /// <summary>Binds the listening socket and starts accepting.</summary>
    public static RelayServer Start(RelayServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Socket listener = new(options.ListenEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        try
        {
            if (options.ListenEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // Unlike the UDP data path, a relay gains nothing from knowing which family a
                // client arrived on, and one dual-stack socket is one fewer thing to operate.
                listener.DualMode = true;
            }

            listener.Bind(options.ListenEndPoint);
            listener.Listen(backlog: 512);

            RelayServer server = new(options, listener);
            server._acceptLoop = Task.Run(() => server.AcceptLoopAsync(server._shutdown.Token));

            return server;
        }
        catch
        {
            listener.Dispose();
            throw;
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

        _listener.Dispose();

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected: the loop exits by cancellation.
            }
        }

        foreach (RelayClient client in _clients.Values)
        {
            await client.DisposeAsync().ConfigureAwait(false);
        }

        _clients.Clear();
        _shutdown.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;

            try
            {
                socket = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            // Each client is handled independently: a handshake that hangs or a peer that
            // stops reading must not delay the next connection.
            _ = Task.Run(() => HandleClientAsync(socket, cancellationToken), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        socket.NoDelay = true;

        IPAddress remoteAddress = (socket.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.None;

        NetworkStream stream = new(socket, ownsSocket: true);
        RelayConnection? connection = null;

        // Admission is decided before anything is read, and every counter it touches is
        // released in the finally below. A connection that is turned away here has cost the
        // server one accept and one close.
        if (!TryAdmit(remoteAddress, out string? rejection))
        {
            LogClientRejected(rejection);
            await stream.DisposeAsync().ConfigureAwait(false);
            return;
        }

        bool isHandshaking = true;

        try
        {
            using CancellationTokenSource handshakeTimeout = new(TimeSpan.FromSeconds(10), _options.TimeProvider);
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                handshakeTimeout.Token);

            connection = await RelayConnection
                .AcceptAsync(stream, _options.Identity, cancellationToken: linked.Token)
                .ConfigureAwait(false);

            // The handshake budget is for connections still proving who they are. Holding a
            // slot for the whole session would make it a second, much lower, client limit.
            Interlocked.Decrement(ref _pendingHandshakes);
            isHandshaking = false;

            await ServeClientAsync(connection, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception
            is RelayProtocolException
            or OperationCanceledException
            or IOException
            or SocketException
            or EndOfStreamException)
        {
            // Clients disconnect, time out and send nonsense. None of it is the server's
            // problem beyond closing the connection.
            LogClientDisconnected(exception.Message);
        }
        finally
        {
            if (isHandshaking)
            {
                Interlocked.Decrement(ref _pendingHandshakes);
            }

            ReleaseAddress(remoteAddress);

            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Decides whether to take one more connection, reserving its budget if so.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> with a reason when a limit is reached. Rejecting costs less
    /// than accepting, which is the property that makes a limit worth having.
    /// </returns>
    private bool TryAdmit(IPAddress remoteAddress, out string rejection)
    {
        if (_clients.Count >= _options.MaximumClients)
        {
            rejection = "the server is at its client limit";
            return false;
        }

        if (Interlocked.Increment(ref _pendingHandshakes) > _options.MaximumPendingHandshakes)
        {
            Interlocked.Decrement(ref _pendingHandshakes);
            rejection = "too many connections are waiting to complete a handshake";
            return false;
        }

        // AddOrUpdate rather than a read and a write: admission is decided on the accept loop
        // and on every connection's own task at once.
        int held = _connectionsPerAddress.AddOrUpdate(remoteAddress, 1, static (_, count) => count + 1);

        if (held > _options.MaximumConnectionsPerAddress)
        {
            ReleaseAddress(remoteAddress);
            Interlocked.Decrement(ref _pendingHandshakes);
            rejection = "that address already holds its maximum number of connections";
            return false;
        }

        rejection = string.Empty;
        return true;
    }

    private void ReleaseAddress(IPAddress remoteAddress)
    {
        // Removed at zero rather than left behind, or the table becomes a record of every
        // address that has ever connected.
        if (_connectionsPerAddress.AddOrUpdate(remoteAddress, 0, static (_, count) => count - 1) <= 0)
        {
            _connectionsPerAddress.TryRemove(new KeyValuePair<IPAddress, int>(remoteAddress, 0));
        }
    }

    private async Task ServeClientAsync(RelayConnection connection, CancellationToken cancellationToken)
    {
        NodeId clientNodeId = connection.RemoteNodeId;

        RelayClient client = new(
            connection,
            clientNodeId,
            _options.SendQueueCapacity,
            _options.PacketsPerSecondPerClient,
            _options.IdleTimeout,
            _options.TimeProvider);

        // One connection per identity. A node that reconnects — after a network change, or
        // because the old connection is a half-open ghost the server cannot detect — must
        // displace the stale one, or it would be unreachable until the old one times out.
        if (_clients.TryRemove(clientNodeId, out RelayClient? previous))
        {
            await previous.DisposeAsync().ConfigureAwait(false);
        }

        _clients[clientNodeId] = client;
        LogClientConnected(clientNodeId, _clients.Count);

        try
        {
            await client.RunAsync(ForwardAsync, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Only remove the entry if it is still ours; a reconnect may have replaced it.
            if (_clients.TryGetValue(clientNodeId, out RelayClient? current) && ReferenceEquals(current, client))
            {
                _clients.TryRemove(clientNodeId, out _);
            }

            // Removing it from the table is not the same as releasing it. The client owns an
            // idle timer, and a timer registered with a TimeProvider is rooted by the timer
            // queue — so an undisposed client keeps itself, its connection and its 16 KiB
            // send buffer alive for as long as the process runs, and the buffers still in its
            // queue never go back to the array pool. On a server meant to stay up for months
            // that is a leak proportional to the number of disconnections.
            await client.DisposeAsync().ConfigureAwait(false);

            LogClientLeft(clientNodeId, _clients.Count);
        }
    }

    /// <summary>
    /// Moves a packet from one client to another, or reports that the destination is not here.
    /// </summary>
    private ValueTask ForwardAsync(NodeId source, NodeId destination, ReadOnlyMemory<byte> body)
    {
        if (!_clients.TryGetValue(destination, out RelayClient? target))
        {
            // Tells the sender the destination is not here. It is the one thing the relay
            // reveals about who is connected, so it goes only to a client that already named
            // the destination — it answers a question, it does not offer a directory.
            //
            // The client side is deliberately not wired up yet, and this is not an oversight
            // to be tidied away later. Acting on PeerGone would let a relay end a dial by
            // asserting a peer is absent — and the relay is explicitly untrusted, so that is
            // a downgrade it must not be handed: a dial races the relay against direct
            // addresses, and one of the racers cannot be allowed to eliminate the others.
            // Using it safely means failing only the relay path while the direct candidates
            // keep running, which is path management's job in M4. Until then the frame is
            // sent, logged by the client, and acted on by nobody.
            return _clients.TryGetValue(source, out RelayClient? sender)
                ? sender.SendPeerGoneAsync(destination)
                : ValueTask.CompletedTask;
        }

        target.Enqueue(source, body);
        return ValueTask.CompletedTask;
    }

    /// <summary>Indicates whether a node is currently connected to this relay.</summary>
    internal bool IsConnected(NodeId nodeId) => _clients.ContainsKey(nodeId);

    [LoggerMessage(EventId = 3000, Level = LogLevel.Information, Message = "Client {NodeId} connected ({Count} total).")]
    private partial void LogClientConnected(NodeId nodeId, int count);

    [LoggerMessage(EventId = 3001, Level = LogLevel.Information, Message = "Client {NodeId} left ({Count} remaining).")]
    private partial void LogClientLeft(NodeId nodeId, int count);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Debug, Message = "Rejected a connection: {Reason}.")]
    private partial void LogClientRejected(string reason);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Debug, Message = "A client connection ended: {Reason}.")]
    private partial void LogClientDisconnected(string reason);
}
#pragma warning restore RS0030
