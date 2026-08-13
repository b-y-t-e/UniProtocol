using System.Net;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Tests;

/// <summary>
/// Connecting by ticket, including the case where several candidate addresses all work.
/// </summary>
public sealed class UniEndpointPairingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task ConnectAsync_ByTicket_Connects()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        UniTicket ticket = server.CreateTicket();
        Assert.Equal(server.NodeId, ticket.NodeId);
        Assert.NotEmpty(ticket.Addresses);

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(ticket, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        Assert.Equal(client.NodeId, inbound.RemoteNodeId);
    }

    [Fact]
    public async Task ConnectAsync_TicketRoundTrippedThroughText_Connects()
    {
        // The path a real pairing takes: the ticket is printed, copied, pasted and parsed.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        string text = server.CreateTicket().ToString();
        Assert.True(UniTicket.TryParse(text, out UniTicket? parsed));

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(parsed, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        Assert.Equal(server.NodeId, outbound.RemoteNodeId);
    }

    [Fact]
    public async Task ConnectAsync_SeveralCandidateAddressesThatAllReachTheServer_ProducesOneConnection()
    {
        // A machine advertises every local address it has, and on a developer box several of
        // them reach the same listening socket. Probing them in parallel must still yield one
        // session — otherwise the server would accept one connection per address, and the
        // client would hold a connection while the server held three.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint(IPAddress.Any);
        await using UniEndpoint client = CreateEndpoint(IPAddress.Any);

        ushort port = server.LocalAddress.Port;

        UniTicket ticket = new()
        {
            NodeId = server.NodeId,

            // The same listening socket, named three different ways.
            Addresses =
            [
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, port)),
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("127.0.0.2"), port)),
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("127.0.0.3"), port)),
            ],
        };

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(ticket, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        // Traffic must flow on the connection the server actually kept.
        await outbound.SendDatagramAsync("one"u8.ToArray(), cancellation.Token);

        byte[] buffer = new byte[64];
        int received = await inbound.ReceiveDatagramAsync(buffer, cancellation.Token);
        Assert.Equal("one"u8.ToArray(), buffer[..received]);

        // No second connection should be waiting to be accepted.
        using CancellationTokenSource shortWait = new(TimeSpan.FromSeconds(2));
        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await server.AcceptAsync(shortWait.Token));
    }

    [Fact]
    public async Task ConnectAsync_UnreachableCandidatesAlongsideAGoodOne_StillConnects()
    {
        // The common real case: a ticket lists a Wi-Fi address, an Ethernet address and a
        // virtual adapter, and only one of them is reachable from where the caller is.
        using CancellationTokenSource cancellation = new(Timeout);

        await using UniEndpoint server = CreateEndpoint();
        await using UniEndpoint client = CreateEndpoint();

        UniTicket ticket = new()
        {
            NodeId = server.NodeId,
            Addresses =
            [
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 39_999)),
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, server.LocalAddress.Port)),
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("198.51.100.7"), 40_000)),
            ],
        };

        Task<UniConnection> acceptTask = server.AcceptAsync(cancellation.Token).AsTask();

        await using UniConnection outbound = await client.ConnectAsync(ticket, cancellation.Token);
        await using UniConnection inbound = await acceptTask;

        Assert.Equal(PathKind.Direct, outbound.RemotePath.Kind);
        Assert.Equal(IPAddress.Loopback.ToString(), outbound.RemotePath.Address.ToIPEndPoint().Address.ToString());
    }

    [Fact]
    public async Task ConnectAsync_TicketWithNoAddresses_FailsWithAClearMessage()
    {
        await using UniEndpoint client = CreateEndpoint();

        using UniIdentity peer = UniIdentity.Generate();
        UniTicket ticket = new() { NodeId = peer.NodeId };

        HandshakeFailedException exception = await Assert.ThrowsAsync<HandshakeFailedException>(
            async () => await client.ConnectAsync(ticket, TestContext.Current.CancellationToken));

        Assert.Contains("no addresses", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateTicket_WithLifetime_SetsAnExpiry()
    {
        await using UniEndpoint endpoint = CreateEndpoint();

        UniTicket ticket = endpoint.CreateTicket(TimeSpan.FromMinutes(5));

        DateTimeOffset now = TimeProvider.System.GetUtcNow();

        Assert.NotNull(ticket.ExpiresAt);
        Assert.False(ticket.IsExpired(now));
        Assert.True(ticket.IsExpired(now.AddMinutes(10)));
    }

    private static UniEndpoint CreateEndpoint(IPAddress? bindTo = null)
        => UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = UniIdentity.Generate(),
            ListenEndPoint = new IPEndPoint(bindTo ?? IPAddress.Loopback, 0),
            ApplicationProtocol = "uniprotocol/test",
            HandshakeTimeout = TimeSpan.FromSeconds(10),
        });
}
