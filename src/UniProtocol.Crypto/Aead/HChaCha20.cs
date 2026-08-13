using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// The HChaCha20 key-derivation function used to build XChaCha20 from ChaCha20.
/// </summary>
/// <remarks>
/// HChaCha20 runs the ChaCha20 permutation over a state built from the key and a
/// 16-byte nonce, then returns the first and last four state words <em>without</em> the
/// feed-forward addition. Omitting the feed-forward is what makes it a PRF rather than a
/// block function, which is why the extended nonce is safe to choose at random.
/// </remarks>
internal static class HChaCha20
{
    /// <summary>Nonce size in bytes.</summary>
    public const int NonceSizeInBytes = 16;

    /// <summary>Derived subkey size in bytes.</summary>
    public const int SubkeySizeInBytes = 32;

    /// <summary>Derives a 32-byte subkey from <paramref name="key"/> and <paramref name="nonce"/>.</summary>
    public static void DeriveSubkey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subkey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, ChaCha20.KeySizeInBytes);
        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSizeInBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(subkey.Length, SubkeySizeInBytes);

        // The whole 16-byte nonce occupies the counter word and the three nonce words,
        // so the state is built directly rather than through ChaCha20.InitializeState.
        Span<uint> state = stackalloc uint[16];
        ChaCha20.InitializeState(
            state,
            key,
            nonce[4..],
            counter: BinaryPrimitives.ReadUInt32LittleEndian(nonce));

        Span<uint> permuted = stackalloc uint[16];
        ChaCha20.PermuteWithoutFeedForward(state, permuted);

        for (int i = 0; i < 4; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(subkey[(i * 4)..], permuted[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(subkey[(16 + (i * 4))..], permuted[12 + i]);
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(permuted));
    }
}
