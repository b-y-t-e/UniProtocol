using UniProtocol.Crypto.Hashing;

namespace UniProtocol.Crypto.Tests.Hashing;

public sealed class Blake2sTests
{
    [Theory]
    // RFC 7693 appendix B.
    [InlineData("abc", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")]
    // Official BLAKE2 reference test values.
    [InlineData("", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")]
    [InlineData(
        "The quick brown fox jumps over the lazy dog",
        "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812")]
    public void HashData_KnownVector_MatchesReference(string message, string expectedHex)
    {
        byte[] actual = Blake2s.HashData(System.Text.Encoding.ASCII.GetBytes(message));

        Assert.Equal(expectedHex, Convert.ToHexStringLower(actual));
    }

    [Theory]
    // BLAKE2s keyed KAT (blake2s-kat.txt), key = 00 01 .. 1f.
    [InlineData("", "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")]
    [InlineData("00", "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1")]
    [InlineData("0001", "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803")]
    [InlineData("000102", "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b")]
    public void HashDataKeyed_KeyedKatVector_MatchesReference(string messageHex, string expectedHex)
    {
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }

        Span<byte> actual = stackalloc byte[Blake2s.HashSizeInBytes];
        Blake2s.HashDataKeyed(key, Convert.FromHexString(messageHex), actual);

        Assert.Equal(expectedHex, Convert.ToHexStringLower(actual));
    }

    [Fact]
    public void Update_SplitAcrossBlockBoundary_MatchesOneShot()
    {
        // The buffering rule ("never compress a full buffer until Finish") is the easiest
        // part of BLAKE2 to get wrong, and it only breaks on exact multiples of the block
        // size. Every split of a multi-block message must agree with the one-shot hash.
        byte[] message = new byte[3 * Blake2s.BlockSizeInBytes];
        for (int i = 0; i < message.Length; i++)
        {
            message[i] = (byte)(i * 7 + 13);
        }

        byte[] expected = Blake2s.HashData(message);
        byte[] actual = new byte[Blake2s.HashSizeInBytes];

        for (int split = 0; split <= message.Length; split++)
        {
            Blake2sHasher hasher = Blake2sHasher.Create();
            hasher.Update(message.AsSpan(0, split));
            hasher.Update(message.AsSpan(split));
            hasher.Finish(actual);

            Assert.True(actual.AsSpan().SequenceEqual(expected), $"split at {split} disagreed with the one-shot hash");
        }
    }

    [Fact]
    public void Finish_ShortDigestSize_ProducesRequestedLength()
    {
        byte[] actual = Blake2s.HashData("abc"u8, hashSizeInBytes: 16);

        Assert.Equal(16, actual.Length);
    }

    [Fact]
    public void Create_HashSizeOutOfRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Blake2sHasher.Create(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Blake2sHasher.Create(33));
    }
}
