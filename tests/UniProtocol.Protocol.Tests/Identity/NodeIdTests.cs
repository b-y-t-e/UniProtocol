using UniProtocol.Crypto.Curve25519;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Tests.Identity;

public sealed class NodeIdTests
{
    private const string KnownPublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    [Fact]
    public void ToStringThenParse_RoundTrips()
    {
        NodeId original = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));

        string text = original.ToString();

        Assert.Equal(NodeId.TextLength, text.Length);
        Assert.True(NodeId.TryParse(text, out NodeId parsed));
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void TryParse_IsCaseInsensitive()
    {
        NodeId original = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));

        Assert.True(NodeId.TryParse(original.ToString().ToUpperInvariant(), out NodeId parsed));
        Assert.Equal(original, parsed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-node-id")]
    // One character short, one too long, and a character outside the alphabet.
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1a")]
    public void TryParse_MalformedInput_ReturnsFalse(string text)
    {
        Assert.False(NodeId.TryParse(text, out _));
    }

    [Fact]
    public void TryParse_NonCanonicalTrailingBits_ReturnsFalse()
    {
        // 52 base32 characters carry 260 bits but a NodeId is 256, so the last character
        // has four unused bits. Allowing them to be non-zero would give one identity many
        // spellings, and an allow-list keyed by text would be trivially bypassable.
        NodeId original = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));
        char[] text = original.ToString().ToCharArray();

        Assert.True(NodeId.TryParse(text, out _));

        text[^1] = text[^1] == 'a' ? 'b' : 'a';

        Assert.False(NodeId.TryParse(text, out _));
    }

    [Fact]
    public void TryGetNoiseStaticKey_MatchesDirectConversion()
    {
        NodeId nodeId = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));

        byte[] fromNodeId = new byte[X25519.KeySizeInBytes];
        Assert.True(nodeId.TryGetNoiseStaticKey(fromNodeId));

        byte[] direct = new byte[X25519.KeySizeInBytes];
        Assert.True(Ed25519.TryConvertPublicKeyToX25519(Convert.FromHexString(KnownPublicKeyHex), direct));

        Assert.Equal(direct, fromNodeId);
    }

    [Fact]
    public void Equals_DistinguishesDifferentIdentities()
    {
        NodeId first = NodeId.FromPublicKey(Convert.FromHexString(KnownPublicKeyHex));

        byte[] other = Convert.FromHexString(KnownPublicKeyHex);
        other[31] ^= 0x01;
        NodeId second = NodeId.FromPublicKey(other);

        Assert.NotEqual(first, second);
        Assert.True(first != second);
        Assert.False(first == second);
    }

    [Fact]
    public void FromPublicKey_WrongLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NodeId.FromPublicKey(new byte[31]));
    }
}
