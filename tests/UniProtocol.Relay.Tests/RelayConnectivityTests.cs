using System.Net;
using UniProtocol.Abstractions;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;
using UniProtocol.Server;
using UniProtocol.Transport;

namespace UniProtocol.Relay.Tests;

/// <summary>
/// End-to-end tests of the case the whole project exists for: two nodes that cannot send
/// each other a single packet directly, connecting anyway.
/// </summary>
/// <remarks>
/// The endpoints here are given <em>no usable direct candidates at all</em>. That is
/// stricter than reality — where a direct path merely usually fails — and it is the only way
/// to be sure a passing test proves the relay carried the traffic rather than the loopback
/// interface quietly saving it.
/// </remarks>
public sealed class RelayConnectivityTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task TwoNodes_WithNoDirectPath_ConnectThroughTheRelay()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);

        RelayAddress relayAddress = LocalAddressOf(relay);

        using UniIdentity serverIdentity = UniIdentity.Generate();
        using UniIdentity clientIdentity = UniIdentity.Generate();

        await using RelayPacketTransport serverRelay = await ConnectRelayAsync(relayAddress, serverIdentity, cancellation.Token);
        await using RelayPacketTransport clientRelay = await ConnectRelayAsync(relayAddress, clientIdentity, cancellation.Token);

        await using UniEndpoint server = CreateEndpoint(serverIdentity, serverRelay);
        await using UniEndpoint client = CreateEndpoint(clientIdentity, clientRelay);

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectViaRelayAsync(server.NodeId, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        Assert.Equal(PathKind.Relay, outbound.RemotePath.Kind);
        Assert.Equal(server.NodeId, outbound.RemoteNodeId);
        Assert.Equal(client.NodeId, inbound.RemoteNodeId);

        byte[] request = "over the relay"u8.ToArray();
        await outbound.SendDatagramAsync(request, cancellation.Token);

        byte[] buffer = new byte[2048];
        int received = await inbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal(request, buffer[..received]);

        byte[] response = "and back"u8.ToArray();
        await inbound.SendDatagramAsync(response, cancellation.Token);

        received = await outbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal(response, buffer[..received]);
    }

    [Fact]
    public async Task TicketFromARelayConnectedEndpoint_IsEnoughToConnect()
    {
        // The pairing story: one string, copied once, works from anywhere.
        using CancellationTokenSource cancellation = new(Timeout);

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);
        RelayAddress relayAddress = LocalAddressOf(relay);

        using UniIdentity serverIdentity = UniIdentity.Generate();
        using UniIdentity clientIdentity = UniIdentity.Generate();

        await using RelayPacketTransport serverRelay = await ConnectRelayAsync(relayAddress, serverIdentity, cancellation.Token);
        await using RelayPacketTransport clientRelay = await ConnectRelayAsync(relayAddress, clientIdentity, cancellation.Token);

        await using UniEndpoint server = CreateEndpoint(serverIdentity, serverRelay);
        await using UniEndpoint client = CreateEndpoint(clientIdentity, clientRelay);

        // Round-trip the ticket through text, exactly as a copy and paste would.
        string text = server.CreateTicket().ToString();
        Assert.True(UniTicket.TryParse(text, out UniTicket? ticket));
        Assert.NotNull(ticket.Relay);
        Assert.Equal(relay.NodeId, ticket.Relay.NodeId);

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(ticket, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        Assert.Equal(server.NodeId, outbound.RemoteNodeId);
    }

    [Fact]
    public async Task ConnectViaRelay_PeerNotConnectedToTheRelay_FailsRatherThanHanging()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);

        using UniIdentity clientIdentity = UniIdentity.Generate();
        await using RelayPacketTransport clientRelay = await ConnectRelayAsync(LocalAddressOf(relay), clientIdentity, cancellation.Token);

        await using UniEndpoint client = CreateEndpoint(clientIdentity, clientRelay, handshakeTimeout: TimeSpan.FromSeconds(3));

        using UniIdentity absent = UniIdentity.Generate();

        await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectViaRelayAsync(absent.NodeId, cancellation.Token));
    }

    [Fact]
    public async Task ConnectAsync_NoRelayAndNoAddresses_FailsWithAnActionableMessage()
    {
        await using UniEndpoint client = CreateEndpoint(UniIdentity.Generate(), relayTransport: null);

        using UniIdentity peer = UniIdentity.Generate();

        HandshakeFailedException exception = await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectAsync(
                new UniTicket { NodeId = peer.NodeId },
                TestContext.Current.CancellationToken));

        Assert.Contains("relay", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RelayTransport_WrongRelayIdentity_NeverConnects()
    {
        // The relay is authenticated by key. Reaching the right host and port is not enough:
        // a server that cannot complete the handshake for the key we dialled is not our relay.
        using CancellationTokenSource cancellation = new(TimeSpan.FromSeconds(10));

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);

        using UniIdentity impostor = UniIdentity.Generate();
        RelayAddress wrongAddress = LocalAddressOf(relay) with { NodeId = impostor.NodeId };

        using UniIdentity clientIdentity = UniIdentity.Generate();
        await using RelayPacketTransport transport = RelayPacketTransport.Create(wrongAddress, clientIdentity);

        using CancellationTokenSource shortWait = new(TimeSpan.FromSeconds(3));

        // ThrowsAny: cancellation surfaces as TaskCanceledException, a subclass.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await transport.WaitUntilConnectedAsync(shortWait.Token));

        Assert.False(transport.IsConnected);
    }

    [Fact]
    public async Task RelayServer_TracksConnectedClients()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);

        Assert.Equal(0, relay.ConnectedClientCount);

        using UniIdentity clientIdentity = UniIdentity.Generate();
        await using RelayPacketTransport transport = await ConnectRelayAsync(LocalAddressOf(relay), clientIdentity, cancellation.Token);

        await WaitForAsync(() => relay.ConnectedClientCount == 1, cancellation.Token);
    }

    [Fact]
    public async Task RelayClient_ReconnectingWithTheSameIdentity_DisplacesTheStaleConnection()
    {
        // A node whose network changed reconnects while the relay still believes the old
        // connection is alive. Without displacement it would stay unreachable until the dead
        // connection timed out.
        using CancellationTokenSource cancellation = new(Timeout);

        using UniIdentity relayIdentity = UniIdentity.Generate();
        await using RelayServer relay = StartRelay(relayIdentity);
        RelayAddress relayAddress = LocalAddressOf(relay);

        using UniIdentity clientIdentity = UniIdentity.Generate();

        RelayPacketTransport first = await ConnectRelayAsync(relayAddress, clientIdentity, cancellation.Token);
        await WaitForAsync(() => relay.ConnectedClientCount == 1, cancellation.Token);

        await using RelayPacketTransport second = await ConnectRelayAsync(relayAddress, clientIdentity, cancellation.Token);

        // Still exactly one client: the same identity, not two.
        await WaitForAsync(() => relay.ConnectedClientCount == 1, cancellation.Token);

        await first.DisposeAsync();
    }

    private static async Task WaitForAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        while (!condition())
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(50), TimeProvider.System, cancellationToken);
        }
    }

    private static RelayServer StartRelay(UniIdentity identity)
        => RelayServer.Start(new RelayServerOptions
        {
            Identity = identity,
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
        });

    private static RelayAddress LocalAddressOf(RelayServer relay)
        => new()
        {
            NodeId = relay.NodeId,
            Host = "127.0.0.1",
            Port = relay.Port,
        };

    private static async Task<RelayPacketTransport> ConnectRelayAsync(
        RelayAddress address,
        UniIdentity identity,
        CancellationToken cancellationToken)
    {
        RelayPacketTransport transport = RelayPacketTransport.Create(address, identity);
        await transport.WaitUntilConnectedAsync(cancellationToken);

        return transport;
    }

    private static UniEndpoint CreateEndpoint(
        UniIdentity identity,
        IPacketTransport? relayTransport,
        TimeSpan? handshakeTimeout = null)
        => UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = identity,

            // Bound to a loopback port that is never advertised, so the only path either side
            // can use is the relay.
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            RelayTransport = relayTransport,
            ApplicationProtocol = "uniprotocol/relay-test",
            HandshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(15),
        });
}
