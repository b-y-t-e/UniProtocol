using UniProtocol.Crypto.Curve25519;

namespace UniProtocol.Crypto.Tests.Curve25519;

public sealed class X25519Tests
{
    [Theory]
    // RFC 7748 section 5.2.
    [InlineData(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [InlineData(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public void ScalarMultiply_Rfc7748Vector_MatchesReference(string scalarHex, string uHex, string expectedHex)
    {
        Span<byte> actual = stackalloc byte[X25519.KeySizeInBytes];
        X25519.ScalarMultiply(Convert.FromHexString(scalarHex), Convert.FromHexString(uHex), actual);

        Assert.Equal(expectedHex, Convert.ToHexStringLower(actual));
    }

    [Fact]
    public void ScalarMultiply_Rfc7748IteratedVector_MatchesReferenceAfterOneThousandIterations()
    {
        // RFC 7748 section 5.2 iterated test. One iteration catches gross errors; a
        // thousand exercises the carry chains across a wide range of inputs, which is
        // where a subtly wrong reduction constant shows up.
        byte[] k = Convert.FromHexString("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] u = (byte[])k.Clone();
        byte[] result = new byte[X25519.KeySizeInBytes];

        for (int iteration = 0; iteration < 1000; iteration++)
        {
            // The RFC's loop is (k, u) := (X25519(k, u), k).
            X25519.ScalarMultiply(k, u, result);
            k.CopyTo(u.AsSpan());
            result.CopyTo(k.AsSpan());

            if (iteration == 0)
            {
                Assert.Equal(
                    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                    Convert.ToHexStringLower(k));
            }
        }

        Assert.Equal(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            Convert.ToHexStringLower(k));
    }

    [Fact]
    public void GetPublicKeyAndTryAgree_Rfc7748Section61_ProducesTheSharedSecret()
    {
        byte[] alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        byte[] alicePublic = new byte[X25519.KeySizeInBytes];
        byte[] bobPublic = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(alicePrivate, alicePublic);
        X25519.GetPublicKey(bobPrivate, bobPublic);

        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Convert.ToHexStringLower(alicePublic));
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Convert.ToHexStringLower(bobPublic));

        byte[] aliceShared = new byte[X25519.SharedSecretSizeInBytes];
        byte[] bobShared = new byte[X25519.SharedSecretSizeInBytes];

        Assert.True(X25519.TryAgree(alicePrivate, bobPublic, aliceShared));
        Assert.True(X25519.TryAgree(bobPrivate, alicePublic, bobShared));

        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Convert.ToHexStringLower(aliceShared));
        Assert.Equal(aliceShared, bobShared);
    }

    [Theory]
    // The complete set of order-1, order-2, order-4 and order-8 points, plus the two
    // non-canonical encodings of the small-order points above 2^255-19. A peer that sends
    // any of these forces an all-zero shared secret, so the handshake must reject it.
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    [InlineData("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")]
    [InlineData("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    [InlineData("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    [InlineData("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    public void TryAgree_LowOrderPoint_ReturnsFalse(string peerPublicKeyHex)
    {
        byte[] privateKey = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] sharedSecret = new byte[X25519.SharedSecretSizeInBytes];

        bool isUsable = X25519.TryAgree(privateKey, Convert.FromHexString(peerPublicKeyHex), sharedSecret);

        Assert.False(isUsable);
    }

    [Fact]
    public void ScalarMultiply_IgnoresBit255OfTheUCoordinate()
    {
        // RFC 7748 section 5: the most significant bit of the u-coordinate must be
        // ignored, so two encodings differing only in that bit must agree.
        byte[] scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] u = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] uWithHighBit = (byte[])u.Clone();
        uWithHighBit[31] |= 0x80;

        byte[] first = new byte[X25519.KeySizeInBytes];
        byte[] second = new byte[X25519.KeySizeInBytes];
        X25519.ScalarMultiply(scalar, u, first);
        X25519.ScalarMultiply(scalar, uWithHighBit, second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ClampScalar_ClearsLowThreeBitsAndFixesTopBits()
    {
        byte[] scalar = new byte[X25519.KeySizeInBytes];
        scalar.AsSpan().Fill(0xFF);

        X25519.ClampScalar(scalar);

        Assert.Equal(0xF8, scalar[0]);
        Assert.Equal(0x7F, scalar[31]);
    }
}
