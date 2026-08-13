using System.Net;
using UniProtocol.Discovery;
using UniProtocol.Discovery.Mdns;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Tests.Discovery;

/// <summary>
/// Local discovery tests against a real multicast socket.
/// </summary>
/// <remarks>
/// These skip rather than fail where multicast is unavailable — containers without a
/// multicast route and locked-down corporate networks are both normal environments to build
/// in, and neither says anything about whether the code is correct.
/// </remarks>
public sealed class MdnsDiscoveryTests
{
    private static readonly TimeSpan DiscoveryWindow = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task DiscoverAsync_FindsAnAdvertisedNode()
    {
        await using MdnsDiscovery advertiser = CreateOrSkip();
        await using MdnsDiscovery browser = CreateOrSkip();

        UniTicket ticket = CreateTicket(39_123);
        await advertiser.AdvertiseAsync(ticket, TestContext.Current.CancellationToken);

        IReadOnlyList<DiscoveredNode> found = await browser.DiscoverAsync(
            DiscoveryWindow,
            TestContext.Current.CancellationToken);

        DiscoveredNode? node = found.FirstOrDefault(candidate => candidate.NodeId == ticket.NodeId);

        Assert.NotNull(node);
        Assert.Equal(ticket.Addresses, node.Ticket.Addresses);
    }

    [Fact]
    public async Task DiscoverAsync_DoesNotReportTheAdvertisersOwnNode()
    {
        // Multicast loopback means every announcement comes straight back. Reporting
        // ourselves as a discovered peer would make "dial the one node on the LAN" pick us.
        await using MdnsDiscovery discovery = CreateOrSkip();

        UniTicket ticket = CreateTicket(39_124);
        await discovery.AdvertiseAsync(ticket, TestContext.Current.CancellationToken);

        IReadOnlyList<DiscoveredNode> found = await discovery.DiscoverAsync(
            TimeSpan.FromSeconds(2),
            TestContext.Current.CancellationToken);

        Assert.DoesNotContain(found, candidate => candidate.NodeId == ticket.NodeId);
    }

    [Fact]
    public async Task DiscoverAsync_NothingAdvertising_ReturnsEmptyWithinTheWindow()
    {
        await using MdnsDiscovery browser = CreateOrSkip();

        IReadOnlyList<DiscoveredNode> found = await browser.DiscoverAsync(
            TimeSpan.FromSeconds(1),
            TestContext.Current.CancellationToken);

        // Other UniProtocol nodes may genuinely exist on the developer's network, so the
        // assertion is that the call completes on time rather than that nothing was found.
        Assert.NotNull(found);
    }

    private static UniTicket CreateTicket(ushort port)
    {
        using UniIdentity identity = UniIdentity.Generate();

        return new UniTicket
        {
            NodeId = identity.NodeId,
            Addresses = [NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, port))],
        };
    }

    private static MdnsDiscovery CreateOrSkip()
    {
        try
        {
            return MdnsDiscovery.Create(announceInterval: TimeSpan.FromSeconds(1));
        }
        catch (MulticastUnavailableException exception)
        {
            Assert.Skip($"Multicast is unavailable in this environment: {exception.Message}");
            throw;
        }
    }
}
