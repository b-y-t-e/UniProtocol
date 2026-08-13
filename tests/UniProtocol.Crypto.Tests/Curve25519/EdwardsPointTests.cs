using UniProtocol.Crypto.Curve25519;

namespace UniProtocol.Crypto.Tests.Curve25519;

/// <summary>
/// Group-law tests for edwards25519, independent of Ed25519's hashing and encoding.
/// </summary>
/// <remarks>
/// When an Ed25519 test vector fails there are three candidate causes — the group law,
/// the scalar arithmetic, or the RFC 8032 wrapper. These tests pin down the group law on
/// its own, so a failure is localised immediately instead of requiring a bisection.
/// </remarks>
public sealed class EdwardsPointTests
{
    private const string BasePointHex = "5866666666666666666666666666666666666666666666666666666666666666";

    [Fact]
    public void DecodeThenEncode_BasePoint_RoundTrips()
    {
        Assert.True(EdwardsPoint.TryDecode(Convert.FromHexString(BasePointHex), out EdwardsPoint point));

        Span<byte> encoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        point.Encode(encoded);

        Assert.Equal(BasePointHex, Convert.ToHexStringLower(encoded));
    }

    [Fact]
    public void Encode_Identity_ProducesTheCanonicalEncodingOfOne()
    {
        Span<byte> encoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        EdwardsPoint.Identity.Encode(encoded);

        Assert.Equal("0100000000000000000000000000000000000000000000000000000000000000", Convert.ToHexStringLower(encoded));
    }

    [Fact]
    public void Double_Identity_StaysIdentity()
    {
        Span<byte> encoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        EdwardsPoint.Identity.Double().Encode(encoded);

        Assert.Equal("0100000000000000000000000000000000000000000000000000000000000000", Convert.ToHexStringLower(encoded));
    }

    [Fact]
    public void Add_BasePointToItself_EqualsDouble()
    {
        EdwardsPoint b = EdwardsPoint.BasePoint;

        Span<byte> viaAdd = stackalloc byte[EdwardsPoint.SizeInBytes];
        Span<byte> viaDouble = stackalloc byte[EdwardsPoint.SizeInBytes];
        (b + b).Encode(viaAdd);
        b.Double().Encode(viaDouble);

        Assert.Equal(Convert.ToHexStringLower(viaDouble), Convert.ToHexStringLower(viaAdd));
    }

    [Fact]
    public void Add_BasePointAndItsNegation_YieldsIdentity()
    {
        Span<byte> encoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        (EdwardsPoint.BasePoint - EdwardsPoint.BasePoint).Encode(encoded);

        Assert.Equal("0100000000000000000000000000000000000000000000000000000000000000", Convert.ToHexStringLower(encoded));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(16)]
    [InlineData(255)]
    public void Multiply_SmallScalar_MatchesRepeatedAddition(int factor)
    {
        byte[] scalar = new byte[32];
        scalar[0] = (byte)factor;

        EdwardsPoint expected = EdwardsPoint.Identity;
        for (int i = 0; i < factor; i++)
        {
            expected += EdwardsPoint.BasePoint;
        }

        Span<byte> expectedEncoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        Span<byte> actualEncoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        expected.Encode(expectedEncoded);
        EdwardsPoint.BasePoint.Multiply(scalar).Encode(actualEncoded);

        Assert.Equal(Convert.ToHexStringLower(expectedEncoded), Convert.ToHexStringLower(actualEncoded));
    }

    [Fact]
    public void Multiply_ByTheGroupOrder_YieldsIdentity()
    {
        // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
        byte[] order = Convert.FromHexString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

        Span<byte> encoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        EdwardsPoint.BasePoint.Multiply(order).Encode(encoded);

        Assert.Equal("0100000000000000000000000000000000000000000000000000000000000000", Convert.ToHexStringLower(encoded));
    }
}
