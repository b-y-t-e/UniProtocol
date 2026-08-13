using System.Security.Cryptography;

namespace UniProtocol.Crypto.Hashing;

/// <summary>
/// HMAC (RFC 2104) instantiated with BLAKE2s-256.
/// </summary>
/// <remarks>
/// The Noise Protocol Framework specifies HMAC-HASH for its HKDF, i.e. the standard
/// ipad/opad construction over BLAKE2s — deliberately <em>not</em> BLAKE2's own keyed
/// mode. Using keyed BLAKE2s here would produce a different, incompatible key schedule.
/// </remarks>
internal static class HmacBlake2s
{
    /// <summary>Output size in bytes.</summary>
    public const int HashSizeInBytes = Blake2s.HashSizeInBytes;

    private const int BlockSizeInBytes = Blake2s.BlockSizeInBytes;
    private const byte InnerPad = 0x36;
    private const byte OuterPad = 0x5C;

    /// <summary>
    /// Computes HMAC-BLAKE2s over <paramref name="message"/> under <paramref name="key"/>.
    /// </summary>
    public static void ComputeHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> destination)
        => ComputeHash(key, message, default, destination);

    /// <summary>
    /// Computes HMAC-BLAKE2s over <paramref name="message"/> followed by
    /// <paramref name="suffix"/>, avoiding a temporary concatenation.
    /// </summary>
    public static void ComputeHash(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> suffix,
        Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes);

        Span<byte> paddedKey = stackalloc byte[BlockSizeInBytes];
        paddedKey.Clear();

        if (key.Length > BlockSizeInBytes)
        {
            Blake2s.HashData(key, paddedKey);
        }
        else
        {
            key.CopyTo(paddedKey);
        }

        Span<byte> pad = stackalloc byte[BlockSizeInBytes];
        Span<byte> inner = stackalloc byte[HashSizeInBytes];

        for (int i = 0; i < BlockSizeInBytes; i++)
        {
            pad[i] = (byte)(paddedKey[i] ^ InnerPad);
        }

        Blake2sHasher hasher = Blake2sHasher.Create(HashSizeInBytes);
        hasher.Update(pad);
        hasher.Update(message);
        hasher.Update(suffix);
        hasher.Finish(inner);

        for (int i = 0; i < BlockSizeInBytes; i++)
        {
            pad[i] = (byte)(paddedKey[i] ^ OuterPad);
        }

        hasher = Blake2sHasher.Create(HashSizeInBytes);
        hasher.Update(pad);
        hasher.Update(inner);
        hasher.Finish(destination);

        CryptographicOperations.ZeroMemory(paddedKey);
        CryptographicOperations.ZeroMemory(pad);
        CryptographicOperations.ZeroMemory(inner);
    }
}
