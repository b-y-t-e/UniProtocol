using System.Net;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Tests;

public sealed class UniTicketTests
{
    private const string KnownPublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    [Fact]
    public void ToStringThenParse_WithAddresses_RoundTrips()
    {
        UniTicket original = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Addresses =
            [
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("192.0.2.10"), 39123)),
                NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 39123)),
            ],
        };

        string text = original.ToString();

        Assert.StartsWith(UniTicket.UriPrefix, text, StringComparison.Ordinal);
        Assert.True(UniTicket.TryParse(text, out UniTicket? parsed));
        Assert.Equal(original.NodeId, parsed.NodeId);
        Assert.Equal(original.Addresses, parsed.Addresses);
    }

    [Fact]
    public void ToStringThenParse_WithExpiryAndPairingToken_RoundTrips()
    {
        byte[] token = new byte[UniTicket.PairingTokenSizeInBytes];
        for (int i = 0; i < token.Length; i++)
        {
            token[i] = (byte)(i + 1);
        }

        UniTicket original = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Addresses = [NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, 1))],
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            PairingToken = token,
        };

        Assert.True(UniTicket.TryParse(original.ToString(), out UniTicket? parsed));

        Assert.Equal(original.ExpiresAt, parsed.ExpiresAt);
        Assert.Equal(token, parsed.PairingToken.ToArray());
    }

    [Fact]
    public void TryParse_BareNodeId_ProducesATicketWithNoAddresses()
    {
        // People will paste a NodeId. It is a complete ticket with no address hints, so it
        // must work rather than produce a format error.
        NodeId nodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));

        Assert.True(UniTicket.TryParse(nodeId.ToString(), out UniTicket? parsed));

        Assert.Equal(nodeId, parsed.NodeId);
        Assert.Empty(parsed.Addresses);
    }

    [Fact]
    public void TryParse_WithoutTheUriPrefix_StillWorks()
    {
        UniTicket original = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Addresses = [NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Loopback, 1234))],
        };

        string withoutPrefix = original.ToString()[UniTicket.UriPrefix.Length..];

        Assert.True(UniTicket.TryParse(withoutPrefix, out UniTicket? parsed));
        Assert.Equal(original.Addresses, parsed.Addresses);
    }

    [Fact]
    public void TryParse_SurroundingWhitespace_IsIgnored()
    {
        UniTicket original = new() { NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)) };

        Assert.True(UniTicket.TryParse($"  {original}\r\n", out _));
    }

    [Fact]
    public void TryParse_SingleMistypedCharacter_IsRejectedByTheChecksum()
    {
        // The whole reason the checksum exists: a transcription slip must fail immediately
        // and legibly, not ten seconds later as an unexplained connection timeout.
        UniTicket original = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Addresses = [NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("192.0.2.10"), 39123))],
        };

        char[] text = original.ToString().ToCharArray();
        int corruptedIndex = UniTicket.UriPrefix.Length + 5;
        text[corruptedIndex] = text[corruptedIndex] == 'a' ? 'b' : 'a';

        Assert.False(UniTicket.TryParse(text, out _));
    }

    [Fact]
    public void TryParse_TrailingBytes_AreRejected()
    {
        UniTicket original = new() { NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)) };

        byte[] encoded = original.Encode();
        byte[] withExtra = [.. encoded[..^2], 0xFF, .. encoded[^2..]];

        Assert.False(UniTicket.TryDecode(withExtra, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("unip://n/")]
    [InlineData("hello world")]
    [InlineData("unip://n/aaaa")]
    public void TryParse_MalformedInput_ReturnsFalse(string text)
    {
        Assert.False(UniTicket.TryParse(text, out _));
    }

    [Fact]
    public void TryDecode_UnknownVersion_ReturnsFalse()
    {
        UniTicket original = new() { NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)) };

        byte[] encoded = original.Encode();
        encoded[0] = 99;

        Assert.False(UniTicket.TryDecode(encoded, out _));
    }

    [Fact]
    public void IsExpired_ComparesAgainstTheSuppliedTime()
    {
        UniTicket ticket = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_000),
        };

        Assert.False(ticket.IsExpired(DateTimeOffset.FromUnixTimeSeconds(999)));
        Assert.True(ticket.IsExpired(DateTimeOffset.FromUnixTimeSeconds(1_001)));

        UniTicket permanent = ticket with { ExpiresAt = null };
        Assert.False(permanent.IsExpired(DateTimeOffset.MaxValue));
    }

    [Fact]
    public void ToString_TypicalTicket_IsShortEnoughToPasteAndToFitAQrCode()
    {
        // One identity and one IPv4 address is the common case. Keeping it near a hundred
        // characters is what makes a ticket practical to paste into a chat window or encode
        // in a QR code that scans from a laptop screen.
        UniTicket ticket = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Addresses = [NetworkAddress.FromIPEndPoint(new IPEndPoint(IPAddress.Parse("192.0.2.10"), 39123))],
        };

        Assert.True(ticket.ToString().Length <= 110, $"a typical ticket grew to {ticket.ToString().Length} characters");
    }

    [Fact]
    public void TryParse_TextFarLongerThanAnyTicket_IsRejectedWithoutExhaustingTheStack()
    {
        // Ticket text arrives from a command line, a chat message or a QR code, so its
        // length is chosen by whoever supplies it. Decoding onto the stack without a bound
        // turns a long argument into a stack overflow, which no catch block can rescue.
        string oversized = UniTicket.UriPrefix + new string('a', 4_000_000);

        Assert.False(UniTicket.TryParse(oversized, out UniTicket? ticket));
        Assert.Null(ticket);
    }

    [Fact]
    public void TryParse_TextJustPastTheLargestPossibleTicket_IsRejected()
    {
        // 651 bytes is every optional field at its maximum, which encodes to 1042
        // characters. Anything longer cannot be a ticket whatever its contents.
        Assert.False(UniTicket.TryParse(new string('a', 1_043), out _));
    }

    [Fact]
    public void Encode_RelayHostLongerThanTheLengthPrefixCanHold_Throws()
    {
        // The host length is one byte. Silently truncating would produce a ticket that
        // parses cleanly and names a different server.
        UniTicket ticket = new()
        {
            NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
            Relay = new Relay.RelayAddress
            {
                NodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex)),
                Host = new string('h', 256),
                Port = 443,
            },
        };

        Assert.Throws<InvalidOperationException>(ticket.Encode);
    }
}
