using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using UniProtocol.Protocol;

namespace UniProtocol.Discovery.Mdns;

/// <summary>
/// Finds and advertises UniProtocol nodes on the local network using multicast DNS.
/// </summary>
/// <remarks>
/// <para>
/// This is the zero-configuration path: two machines on one network find each other with
/// nothing typed and no server involved. It is also the only discovery mechanism that keeps
/// working when the internet does not.
/// </para>
/// <para>
/// It speaks standard DNS-SD on the standard port, so a node also shows up in
/// <c>dns-sd -B _uniprotocol._udp</c> or an Avahi browser. That interoperability is why the
/// wire format is real mDNS rather than a private beacon of our own.
/// </para>
/// <para>
/// This type is an adapter at the system boundary and touches sockets directly.
/// </para>
/// </remarks>
#pragma warning disable RS0030 // Adapter boundary: multicast discovery is inherently socket-level.
public sealed partial class MdnsDiscovery : INodeAdvertiser, INodeBrowser
{
    private const int MulticastPort = 5353;
    private const int MessageBufferSize = 4096;

    private static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
    private static readonly IPEndPoint MulticastEndPoint = new(MulticastGroup, MulticastPort);

    private readonly Socket _socket;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<MdnsDiscovery> _logger;
    private readonly Channel<DiscoveredNode> _discovered;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TimeSpan _announceInterval;

    // A separate, mutable endpoint for receives: the socket writes the sender's address
    // into it, so the shared multicast endpoint must not be handed over.
    private readonly IPEndPoint _receivedFrom = new(IPAddress.Any, 0);

    private volatile AdvertisedNode? _advertised;
    private Task? _receiveLoop;
    private Task? _announceLoop;
    private bool _isDisposed;

    private MdnsDiscovery(Socket socket, TimeProvider timeProvider, ILoggerFactory loggerFactory, TimeSpan announceInterval)
    {
        _socket = socket;
        _timeProvider = timeProvider;
        _logger = loggerFactory.CreateLogger<MdnsDiscovery>();
        _announceInterval = announceInterval;

        // Advertisements repeat; a browser that stops reading must not stall the receive
        // loop, and losing the older copy of a repeated announcement costs nothing.
        _discovered = Channel.CreateBounded<DiscoveredNode>(
            new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.DropOldest });
    }

    /// <summary>
    /// Opens the multicast socket and starts listening.
    /// </summary>
    /// <exception cref="MulticastUnavailableException">
    /// The multicast port could not be opened or no interface accepted the group.
    /// </exception>
    public static MdnsDiscovery Create(
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        TimeSpan? announceInterval = null)
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        try
        {
            // Port 5353 is shared with whatever else on the machine speaks mDNS — Bonjour on
            // Windows and macOS, Avahi on Linux — so the address must be reusable or binding
            // fails on any normally configured desktop.
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(IPAddress.Any, MulticastPort));

            // Without loopback, two processes on one machine cannot find each other — which
            // is precisely what someone trying the tool out does first.
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);

            if (JoinAllInterfaces(socket) == 0)
            {
                throw new MulticastUnavailableException(
                    "No network interface accepted the mDNS multicast group, so local discovery is unavailable.");
            }

            MdnsDiscovery discovery = new(
                socket,
                timeProvider ?? TimeProvider.System,
                loggerFactory ?? NullLoggerFactory.Instance,
                announceInterval ?? TimeSpan.FromSeconds(30));

            discovery._receiveLoop = Task.Run(() => discovery.ReceiveLoopAsync(discovery._shutdown.Token));
            discovery._announceLoop = Task.Run(() => discovery.AnnounceLoopAsync(discovery._shutdown.Token));

            return discovery;
        }
        catch (SocketException exception)
        {
            socket.Dispose();

            throw new MulticastUnavailableException(
                $"Could not open the mDNS port {MulticastPort}: {exception.Message}",
                exception);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask AdvertiseAsync(UniTicket ticket, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        ushort port = ticket.Addresses.Count > 0 ? ticket.Addresses[0].Port : (ushort)0;
        _advertised = new AdvertisedNode(ticket.NodeId.ToString(), port, ticket.ToString());

        // mDNS expects a short burst on first announcement rather than one packet, because a
        // single multicast datagram is lost more often than people expect on wireless.
        for (int i = 0; i < 3; i++)
        {
            await SendAnnouncementAsync(cancellationToken).ConfigureAwait(false);

            if (i < 2)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), _timeProvider, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<DiscoveredNode> BrowseAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        await SendQueryAsync(cancellationToken).ConfigureAwait(false);

        await foreach (DiscoveredNode node in _discovered.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return node;
        }
    }

    /// <summary>
    /// Collects the nodes that answer within <paramref name="window"/>.
    /// </summary>
    /// <remarks>
    /// The convenience most callers want: multicast discovery has no completion signal, so
    /// somebody has to decide when to stop waiting.
    /// </remarks>
    public async Task<IReadOnlyList<DiscoveredNode>> DiscoverAsync(
        TimeSpan window,
        CancellationToken cancellationToken = default)
    {
        Dictionary<Protocol.Identity.NodeId, DiscoveredNode> found = [];

        using CancellationTokenSource deadline = new(window, _timeProvider);
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            deadline.Token);

        try
        {
            await foreach (DiscoveredNode node in BrowseAsync(linked.Token).ConfigureAwait(false))
            {
                found[node.NodeId] = node;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The window elapsed, which is the normal way this ends.
        }

        return [.. found.Values];
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

        foreach (Task? loop in new[] { _receiveLoop, _announceLoop })
        {
            if (loop is null)
            {
                continue;
            }

            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected: the loops exit by cancellation.
            }
        }

        _discovered.Writer.TryComplete();
        _socket.Dispose();
        _shutdown.Dispose();
    }

    private static int JoinAllInterfaces(Socket socket)
    {
        int joined = 0;

        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up || !adapter.SupportsMulticast)
            {
                continue;
            }

            IPv4InterfaceProperties? properties;

            try
            {
                properties = adapter.GetIPProperties().GetIPv4Properties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            if (properties is null)
            {
                continue;
            }

            try
            {
                socket.SetSocketOption(
                    SocketOptionLevel.IP,
                    SocketOptionName.AddMembership,
                    new MulticastOption(MulticastGroup, properties.Index));

                joined++;
            }
            catch (SocketException)
            {
                // Interfaces come and go, and some refuse the group. One that declines is
                // not a reason to give up on the rest.
            }
        }

        return joined;
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[MessageBufferSize];
        List<string> tickets = [];

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                SocketReceiveFromResult result = await _socket
                    .ReceiveFromAsync(buffer, SocketFlags.None, _receivedFrom, cancellationToken)
                    .ConfigureAwait(false);

                ReadOnlySpan<byte> message = buffer.AsSpan(0, result.ReceivedBytes);

                if (IsQuery(message))
                {
                    await SendAnnouncementAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                tickets.Clear();
                MdnsMessage.ReadTickets(message, tickets);

                foreach (string text in tickets)
                {
                    PublishIfUseful(text);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                // The network changed under us; the next receive will either work or the
                // loop will exit on cancellation.
            }
#pragma warning disable CA1031 // One malformed advertisement must not stop discovery.
            catch (Exception exception)
            {
                LogAdvertisementFailed(exception);
            }
#pragma warning restore CA1031
        }
    }

    private async Task AnnounceLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(_announceInterval, _timeProvider, cancellationToken).ConfigureAwait(false);
                await SendAnnouncementAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown.
        }
    }

    private void PublishIfUseful(string text)
    {
        if (!UniTicket.TryParse(text, out UniTicket? ticket))
        {
            return;
        }

        AdvertisedNode? mine = _advertised;
        if (mine is not null && string.Equals(mine.InstanceLabel, ticket.NodeId.ToString(), StringComparison.Ordinal))
        {
            // Our own announcement, reflected back by multicast loopback.
            return;
        }

        _discovered.Writer.TryWrite(new DiscoveredNode(ticket, _timeProvider.GetUtcNow()));
    }

    private async ValueTask SendAnnouncementAsync(CancellationToken cancellationToken)
    {
        AdvertisedNode? advertised = _advertised;

        if (advertised is null)
        {
            return;
        }

        byte[] buffer = new byte[MessageBufferSize];
        int length = MdnsMessage.WriteResponse(buffer, advertised.InstanceLabel, advertised.Port, advertised.Ticket);

        await SendAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendQueryAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[512];
        int length = MdnsMessage.WriteQuery(buffer, transactionId: 0);

        await SendAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        try
        {
            await _socket.SendToAsync(message, SocketFlags.None, MulticastEndPoint, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException exception)
        {
            // A missing route or an interface that just went down: discovery is best-effort
            // and the next announcement will try again.
            LogSendFailed(exception);
        }
    }

    private static bool IsQuery(ReadOnlySpan<byte> message)
        => message.Length >= 4 && (message[2] & 0x80) == 0;

    [LoggerMessage(EventId = 2000, Level = LogLevel.Debug, Message = "Discarded a malformed mDNS advertisement.")]
    private partial void LogAdvertisementFailed(Exception exception);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Debug, Message = "Could not send an mDNS message.")]
    private partial void LogSendFailed(Exception exception);

    private sealed record AdvertisedNode(string InstanceLabel, ushort Port, string Ticket);
}
#pragma warning restore RS0030
