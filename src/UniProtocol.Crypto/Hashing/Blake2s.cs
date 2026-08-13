namespace UniProtocol.Crypto.Hashing;

/// <summary>
/// One-shot BLAKE2s-256 helpers. For streaming input use <see cref="Blake2sHasher"/>.
/// </summary>
public static class Blake2s
{
    /// <summary>Digest size of BLAKE2s-256 in bytes.</summary>
    public const int HashSizeInBytes = Blake2sHasher.MaxHashSizeInBytes;

    /// <summary>Compression function block size in bytes.</summary>
    public const int BlockSizeInBytes = Blake2sHasher.BlockSizeInBytes;

    /// <summary>Computes BLAKE2s-256 of <paramref name="source"/>.</summary>
    public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes);

        Blake2sHasher hasher = Blake2sHasher.Create(HashSizeInBytes);
        hasher.Update(source);
        hasher.Finish(destination);
    }

    /// <summary>Computes BLAKE2s-256 of the concatenation of two inputs.</summary>
    /// <remarks>
    /// Noise hashes <c>h || data</c> constantly; this overload avoids materialising
    /// the concatenation on every transcript update.
    /// </remarks>
    public static void HashData(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes);

        Blake2sHasher hasher = Blake2sHasher.Create(HashSizeInBytes);
        hasher.Update(first);
        hasher.Update(second);
        hasher.Finish(destination);
    }

    /// <summary>Computes BLAKE2s of <paramref name="source"/> and returns a new array.</summary>
    public static byte[] HashData(ReadOnlySpan<byte> source, int hashSizeInBytes = HashSizeInBytes)
    {
        byte[] destination = new byte[hashSizeInBytes];

        Blake2sHasher hasher = Blake2sHasher.Create(hashSizeInBytes);
        hasher.Update(source);
        hasher.Finish(destination);

        return destination;
    }

    /// <summary>Computes keyed BLAKE2s (the native MAC mode, not HMAC).</summary>
    public static void HashDataKeyed(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        int hashSizeInBytes = HashSizeInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, hashSizeInBytes);

        Blake2sHasher hasher = Blake2sHasher.Create(hashSizeInBytes, key);
        hasher.Update(source);
        hasher.Finish(destination);
    }
}
