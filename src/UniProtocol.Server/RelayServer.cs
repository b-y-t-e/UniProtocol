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
    private readonly CancellationTokenSource _shutdown = new();

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

        NetworkStream stream = new(socket, ownsSocket: true);
        RelayConnection? connection = null;

        try
        {
            if (_clients.Count >= _options.MaximumClients)
            {
                LogClientRejected("the server is at its client limit");
                await stream.DisposeAsync().ConfigureAwait(false);
                return;
            }

            using CancellationTokenSource handshakeTimeout = new(TimeSpan.FromSeconds(10), _options.TimeProvider);
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                handshakeTimeout.Token);

            connection = await RelayConnection
                .AcceptAsync(stream, _options.Identity, cancellationToken: linked.Token)
                .ConfigureAwait(false);

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

    private async Task ServeClientAsync(RelayConnection connection, CancellationToken cancellationToken)
    {
        NodeId clientNodeId = connection.RemoteNodeId;

        RelayClient client = new(
            connection,
            clientNodeId,
            _options.SendQueueCapacity,
            _options.PacketsPerSecondPerClient,
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
            // Telling the sender immediately is what lets a dial fail in a second rather than
            // waiting out a handshake timeout against a node that is simply not here.
            return ValueTask.CompletedTask;
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
