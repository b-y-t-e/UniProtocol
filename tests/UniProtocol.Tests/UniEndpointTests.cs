using System.Net;
using System.Net.Sockets;
using UniProtocol.Abstractions;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Packets;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Tests;

/// <summary>
/// End-to-end tests over a real UDP socket on the loopback interface.
/// </summary>
/// <remarks>
/// Loopback is not a substitute for the deterministic simulator that will arrive with the
/// transport layer — it never loses or reorders a packet, so it proves nothing about
/// recovery. What it does prove is that the real socket path, the framing and the handshake
/// fit together, which is exactly the question at this milestone.
/// </remarks>
public sealed class UniEndpointTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task ConnectAsync_TwoEndpoints_ExchangeDatagramsInBothDirections()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(
            server.NodeId,
            LoopbackAddressOf(server),
            cancellation.Token);

        await using UniConnection inbound = await acceptTask;

        Assert.Equal(client.NodeId, inbound.RemoteNodeId);
        Assert.Equal(server.NodeId, outbound.RemoteNodeId);

        byte[] request = "ping"u8.ToArray();
        await outbound.SendDatagramAsync(request, cancellation.Token);

        byte[] buffer = new byte[1500];
        int received = await inbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal(request, buffer[..received]);

        byte[] response = "pong"u8.ToArray();
        await inbound.SendDatagramAsync(response, cancellation.Token);

        received = await outbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal(response, buffer[..received]);
    }

    [Fact]
    public async Task ConnectAsync_ManyDatagrams_AllArriveIntactAndInOrderOnLoopback()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();
        await using UniConnection outbound = await client.ConnectAsync(server.NodeId, LoopbackAddressOf(server), cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        const int Count = 200;

        Task receiver = Task.Run(
            async () =>
            {
                byte[] buffer = new byte[1500];

                for (int i = 0; i < Count; i++)
                {
                    int received = await inbound.ReceiveDatagramAsync(buffer, cancellation.Token);
                    Assert.Equal(4, received);
                    Assert.Equal(i, System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(buffer));
                }
            },
            cancellation.Token);

        byte[] payload = new byte[4];
        for (int i = 0; i < Count; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(payload, i);
            await outbound.SendDatagramAsync(payload, cancellation.Token);
        }

        await receiver;
    }

    [Fact]
    public async Task ConnectAsync_WrongNodeIdForTheListeningEndpoint_Fails()
    {
        // Dialling the right address with the wrong identity must fail: the responder cannot
        // decrypt a handshake addressed to somebody else, so no reply is ever produced.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint(handshakeTimeout: TimeSpan.FromSeconds(2));

        using UniIdentity impostor = UniIdentity.Generate();

        await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectAsync(impostor.NodeId, LoopbackAddressOf(server), cancellation.Token));
    }

    [Fact]
    public async Task ConnectAsync_DifferentApplicationProtocol_Fails()
    {
        // The application protocol is bound into the Noise prologue, so a mismatch fails the
        // handshake outright rather than producing a session whose peers disagree about what
        // the bytes mean.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint(applicationProtocol: "app/one");
        await using UniEndpoint client = CreateEndpoint(
            applicationProtocol: "app/two",
            handshakeTimeout: TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectAsync(server.NodeId, LoopbackAddressOf(server), cancellation.Token));
    }

    [Fact]
    public async Task ConnectAsync_NoListenerAtTheAddress_FailsWithinTheTimeout()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint client = CreateEndpoint(handshakeTimeout: TimeSpan.FromSeconds(2));
        using UniIdentity unreachable = UniIdentity.Generate();

        // Port 1 on loopback: reserved, and nothing will be listening.
        NetworkAddress address = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, 1));

        await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectAsync(unreachable.NodeId, address, cancellation.Token));
    }

    [Fact]
    public async Task SendDatagramAsync_PayloadLargerThanMaxDatagramSize_Throws()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();
        await using UniConnection outbound = await client.ConnectAsync(server.NodeId, LoopbackAddressOf(server), cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        byte[] tooLarge = new byte[outbound.MaxDatagramSize + 1];

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await outbound.SendDatagramAsync(tooLarge, cancellation.Token));
    }

    [Fact]
    public async Task ConnectAsync_TwoClientsToOneServer_AreKeptApart()
    {
        // One socket multiplexes every peer, so the demultiplexing by session identifier is
        // what keeps two conversations from bleeding into each other.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint first = CreateEndpoint();
        await using UniEndpoint second = CreateEndpoint();

        Task<UniConnection> acceptFirst = server.AcceptAsync(cancellation.Token).AsTask();
        await using UniConnection firstOutbound = await first.ConnectAsync(server.NodeId, LoopbackAddressOf(server), cancellation.Token);
        await using UniConnection firstInbound = await acceptFirst;

        Task<UniConnection> acceptSecond = server.AcceptAsync(cancellation.Token).AsTask();
        await using UniConnection secondOutbound = await second.ConnectAsync(server.NodeId, LoopbackAddressOf(server), cancellation.Token);
        await using UniConnection secondInbound = await acceptSecond;

        Assert.Equal(first.NodeId, firstInbound.RemoteNodeId);
        Assert.Equal(second.NodeId, secondInbound.RemoteNodeId);

        await firstOutbound.SendDatagramAsync("from-first"u8.ToArray(), cancellation.Token);
        await secondOutbound.SendDatagramAsync("from-second"u8.ToArray(), cancellation.Token);

        byte[] buffer = new byte[1500];

        int received = await firstInbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal("from-first"u8.ToArray(), buffer[..received]);

        received = await secondInbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal("from-second"u8.ToArray(), buffer[..received]);
    }

    // A test needs a real socket to play the on-path observer. The ban exists to keep
    // sockets out of the protocol core, not out of the tests that prove it works.
#pragma warning disable RS0030
    [Fact]
    public async Task ConnectAsync_ForgedHandshakeReplyFromAnObserver_StillConnectsToTheRealPeer()
    {
        // A handshake reply is authenticated by mac1 alone, and the mac1 key is derived from
        // the recipient's public key — so anyone who sees the outbound handshake, a relay
        // included, can send back a well-formed reply with a bogus Noise message. That must
        // cost the connection attempt nothing: the genuine reply still has to be accepted.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        using Socket observer = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        observer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        int observerPort = ((IPEndPoint)observer.LocalEndPoint!).Port;

        byte[] clientMac1Key = new byte[32];
        byte[] clientNoiseKey = new byte[32];
        Assert.True(client.NodeId.TryGetNoiseStaticKey(clientNoiseKey));
        HandshakePacket.DeriveMac1Key(clientNoiseKey, clientMac1Key);

        Task forgery = Task.Run(
            async () =>
            {
                byte[] buffer = new byte[2048];
                SocketReceiveFromResult received = await observer.ReceiveFromAsync(
                    buffer,
                    new IPEndPoint(IPAddress.Loopback, 0),
                    cancellation.Token);

                // Echo back a reply that is structurally valid and carries the right
                // receiverIndex, but whose Noise message is nonsense.
                uint clientIndex = BitConverter.ToUInt32(buffer, 4);

                byte[] reply = new byte[HandshakePacket.OverheadInBytes + 48];
                reply.AsSpan(HandshakePacket.HeaderSizeInBytes, 48).Fill(0xA5);

                int length = HandshakePacket.Finish(
                    reply,
                    PacketType.HandshakeResponse,
                    senderIndex: 0xDEADBEEF,
                    receiverIndex: clientIndex,
                    noiseMessageLength: 48,
                    clientMac1Key);

                await observer.SendToAsync(reply.AsMemory(0, length), received.RemoteEndPoint, cancellation.Token);
            },
            cancellation.Token);

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        // The observer is offered first, so its forgery is in flight before — or alongside —
        // the genuine reply.
        await using UniConnection outbound = await client.ConnectAsync(
            server.NodeId,
            [
                PathEndpoint.ToAddress(NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, observerPort))),
                PathEndpoint.ToAddress(LoopbackAddressOf(server)),
            ],
            cancellation.Token);

        await using UniConnection inbound = await acceptTask;

        Assert.Equal(server.NodeId, outbound.RemoteNodeId);
        Assert.Equal(client.NodeId, inbound.RemoteNodeId);

        await forgery;
    }
#pragma warning restore RS0030

    [Fact]
    public async Task DisposeAsync_OnAConnection_StopsTheEndpointRoutingToIt()
    {
        // Nothing removed a closed connection from the dispatch table, so a node that dialled
        // a thousand peers over its lifetime kept a thousand dead sessions — each with its
        // keys, its replay window and its queued packets — until the process ended.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        UniConnection outbound = await client.ConnectAsync(
            server.NodeId,
            LoopbackAddressOf(server),
            cancellation.Token);

        UniConnection inbound = await acceptTask;

        Assert.Equal(1, client.ConnectionCount);
        Assert.Equal(1, server.ConnectionCount);

        await outbound.DisposeAsync();
        await inbound.DisposeAsync();

        Assert.Equal(0, client.ConnectionCount);
        Assert.Equal(0, server.ConnectionCount);

        // The identifier goes back too, so a long-lived endpoint does not slowly consume the
        // space it draws them from.
        Assert.Equal(0, client.ReservedSessionIndexCount);
        Assert.Equal(0, server.ReservedSessionIndexCount);
    }

    [Fact]
    public async Task SendDatagramAsync_AfterThePeerClosed_DoesNotFaultTheReceiveLoop()
    {
        // Packets keep arriving for a connection that has just closed — the peer cannot know
        // yet. Dispatching them must be a no-op, not an exception on the loop that serves
        // every other peer.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        UniConnection outbound = await client.ConnectAsync(
            server.NodeId,
            LoopbackAddressOf(server),
            cancellation.Token);

        UniConnection inbound = await acceptTask;

        await inbound.DisposeAsync();

        // Straight at a closed session, several times over.
        for (int i = 0; i < 10; i++)
        {
            await outbound.SendDatagramAsync("orphan"u8.ToArray(), cancellation.Token);
        }

        // The server's loop is still alive: a second connection still works.
        Task<UniConnection> secondAccept = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection second = await client.ConnectAsync(
            server.NodeId,
            LoopbackAddressOf(server),
            cancellation.Token);

        await using UniConnection secondInbound = await secondAccept;

        await second.SendDatagramAsync("alive"u8.ToArray(), cancellation.Token);

        byte[] buffer = new byte[1500];
        int received = await secondInbound.ReceiveDatagramAsync(buffer, cancellation.Token);

        Assert.Equal("alive"u8.ToArray(), buffer[..received]);

        await outbound.DisposeAsync();
    }

    [Fact]
    public async Task CreateTicket_OnAWildcardBoundEndpoint_NeverProducesATicketItCannotEncode()
    {
        // CreateTicket advertises every local address, and a ticket has room for sixteen. A
        // machine with enough adapters — Wi-Fi, Ethernet, a hypervisor bridge, a VPN, IPv6
        // privacy addresses — would build a ticket its own encoder refuses, taking mDNS
        // advertisement and `unip listen` down with it. Being well connected is not an error.
        UniEndpoint endpoint = UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = UniIdentity.Generate(),
            ListenEndPoint = new IPEndPoint(IPAddress.Any, 0),
        });

        UniTicket ticket = endpoint.CreateTicket();

        Assert.True(
            ticket.Addresses.Count <= UniTicket.MaximumAddressCount,
            $"the ticket carries {ticket.Addresses.Count} addresses");

        // Encoding is the operation that would have thrown.
        Assert.StartsWith(UniTicket.UriPrefix, ticket.ToString(), StringComparison.Ordinal);

        await endpoint.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_WithACallerSuppliedRelayTransport_LeavesItOpen()
    {
        // Ownership was one flag for every transport, so an endpoint that bound its own UDP
        // socket also closed the relay the caller had connected and was still holding.
        using CancellationTokenSource cancellation = new(Timeout);

        CountingTransport relay = new();

        await using (UniEndpoint endpoint = UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = UniIdentity.Generate(),
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            RelayTransport = relay,
        }))
        {
            Assert.Equal(0, relay.DisposeCount);
        }

        Assert.Equal(0, relay.DisposeCount);
    }

    /// <summary>A transport that does nothing but count how often it is closed.</summary>
    private sealed class CountingTransport : IPacketTransport
    {
        public int DisposeCount { get; private set; }

        public NetworkAddress LocalAddress => default;

        public PathKind SupportedPathKind => PathKind.Relay;

        public ValueTask SendAsync(ReadOnlyMemory<byte> payload, PathEndpoint destination, CancellationToken cancellationToken)
            => ValueTask.CompletedTask;

        public async ValueTask<PacketReceiveResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, TimeProvider.System, cancellationToken);
            return default;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    private static NetworkAddress LoopbackAddressOf(UniEndpoint endpoint)
        => NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, endpoint.LocalAddress.Port));

    private static UniEndpoint CreateEndpoint(
        string applicationProtocol = "uniprotocol/test",
        TimeSpan? handshakeTimeout = null)
        => UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = UniIdentity.Generate(),
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocol = applicationProtocol,
            HandshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(10),
        });
}
