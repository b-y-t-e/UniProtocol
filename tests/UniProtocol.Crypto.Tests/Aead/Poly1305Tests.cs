using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Tests.Aead;

public sealed class Poly1305Tests
{
    [Fact]
    public void Finish_Rfc8439Vector_MatchesReference()
    {
        // RFC 8439 section 2.5.2.
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] message = "Cryptographic Forum Research Group"u8.ToArray();

        Poly1305 mac = Poly1305.Create(key);
        mac.Update(message);

        Span<byte> tag = stackalloc byte[Poly1305.TagSizeInBytes];
        mac.Finish(tag);

        Assert.Equal("a8061dc1305136c6c22b8baf0c0127a9", Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void Finish_ZeroKeyAndZeroMessage_ProducesZeroTag()
    {
        // RFC 8439 appendix A.3 test 1: r and s are both zero, so the tag must be zero.
        Poly1305 mac = Poly1305.Create(new byte[Poly1305.KeySizeInBytes]);
        mac.Update(new byte[64]);

        Span<byte> tag = stackalloc byte[Poly1305.TagSizeInBytes];
        mac.Finish(tag);

        Assert.Equal("00000000000000000000000000000000", Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void Finish_ZeroRNonZeroS_ProducesSAsTag()
    {
        // RFC 8439 appendix A.3 test 2: r is zero, so the tag is exactly s.
        byte[] key = Convert.FromHexString("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
        byte[] message = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"u8.ToArray();

        Poly1305 mac = Poly1305.Create(key);
        mac.Update(message);

        Span<byte> tag = stackalloc byte[Poly1305.TagSizeInBytes];
        mac.Finish(tag);

        Assert.Equal("36e5f6b5c5e06070f0efca96227a863e", Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void Finish_AccumulatorExactlyAtPrime_ReducesCorrectly()
    {
        // RFC 8439 appendix A.3 test 5: the classic "h == p" carry bug detector.
        byte[] key = Convert.FromHexString("02000000000000000000000000000000" + "00000000000000000000000000000000");
        byte[] message = Convert.FromHexString("ffffffffffffffffffffffffffffffff");

        Poly1305 mac = Poly1305.Create(key);
        mac.Update(message);

        Span<byte> tag = stackalloc byte[Poly1305.TagSizeInBytes];
        mac.Finish(tag);

        Assert.Equal("03000000000000000000000000000000", Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void Update_SplitAcrossBlockBoundary_MatchesSingleUpdate()
    {
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] message = new byte[100];
        for (int i = 0; i < message.Length; i++)
        {
            message[i] = (byte)(i * 5 + 3);
        }

        Poly1305 whole = Poly1305.Create(key);
        whole.Update(message);
        byte[] expected = new byte[Poly1305.TagSizeInBytes];
        whole.Finish(expected);

        byte[] actual = new byte[Poly1305.TagSizeInBytes];

        for (int split = 0; split <= message.Length; split++)
        {
            Poly1305 mac = Poly1305.Create(key);
            mac.Update(message.AsSpan(0, split));
            mac.Update(message.AsSpan(split));
            mac.Finish(actual);

            Assert.True(actual.AsSpan().SequenceEqual(expected), $"split at {split} disagreed");
        }
    }
}
