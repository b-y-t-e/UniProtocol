using System.Net;

namespace UniProtocol.Protocol.Tests;

public sealed class NetworkAddressTests
{
    [Theory]
    [InlineData("127.0.0.1", 1234)]
    [InlineData("0.0.0.0", 0)]
    [InlineData("255.255.255.255", 65535)]
    [InlineData("::1", 4321)]
    [InlineData("2001:db8::1", 443)]
    [InlineData("::", 1)]
    public void FromIPEndPointThenBack_RoundTrips(string address, int port)
    {
        IPEndPoint original = new(IPAddress.Parse(address), port);

        NetworkAddress converted = NetworkAddress.FromIPEndPoint(original);

        Assert.Equal(original, converted.ToIPEndPoint());
        Assert.Equal(port, converted.Port);
    }

    [Fact]
    public void IsIPv4_DistinguishesTheFamilies()
    {
        Assert.True(NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, 1)).IsIPv4);
        Assert.False(NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.IPv6Loopback, 1)).IsIPv4);
    }

    [Fact]
    public void Equals_SameAddressAndPort_AreEqualAndHashAlike()
    {
        NetworkAddress first = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 500));
        NetworkAddress second = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 500));

        Assert.Equal(first, second);
        Assert.True(first == second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
    }

    [Fact]
    public void Equals_DifferentPort_AreNotEqual()
    {
        NetworkAddress first = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 500));
        NetworkAddress second = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 501));

        Assert.NotEqual(first, second);
        Assert.True(first != second);
    }

    [Fact]
    public void Equals_IPv4AndItsMappedIPv6Form_AreEqual()
    {
        // Both spellings name the same destination, and a path table keyed by address must
        // not hold two entries for one peer.
        NetworkAddress fromIPv4 = NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 80));
        NetworkAddress fromMapped = NetworkAddress.FromIPEndPoint(
            new IPEndPoint(IPAddress.Parse("192.0.2.1").MapToIPv6(), 80));

        Assert.Equal(fromIPv4, fromMapped);
    }

    [Theory]
    [InlineData("127.0.0.1:9000")]
    [InlineData("[::1]:9000")]
    [InlineData("[2001:db8::1]:443")]
    public void TryParse_ValidText_Succeeds(string text)
    {
        Assert.True(NetworkAddress.TryParse(text, out NetworkAddress address));
        Assert.Equal(text, address.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-address")]
    [InlineData("example.com:80")]
    public void TryParse_InvalidText_ReturnsFalse(string text)
    {
        Assert.False(NetworkAddress.TryParse(text, out _));
    }

    [Fact]
    public void Default_IsUnspecified()
    {
        Assert.True(default(NetworkAddress).IsUnspecified);
        Assert.False(NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, 1)).IsUnspecified);
    }
}
