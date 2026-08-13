using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// The ChaCha20 stream cipher and its block function (RFC 8439 section 2).
/// </summary>
/// <remarks>
/// Implemented in managed code because <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>
/// is not available on every target platform, and UniProtocol requires one identical
/// code path on Windows, Linux and Android.
/// <para>
/// This is the straightforward scalar implementation. It is constant-time by
/// construction: the round function is pure add/xor/rotate on whole words with no
/// data-dependent branches, table lookups or shifts. A vectorised variant is a pure
/// throughput optimisation and is deferred to the performance milestone, where it
/// will be introduced behind the same API and validated against these same vectors.
/// </para>
/// </remarks>
internal static class ChaCha20
{
    /// <summary>Key size in bytes.</summary>
    public const int KeySizeInBytes = 32;

    /// <summary>Nonce size in bytes (RFC 8439 uses a 96-bit nonce).</summary>
    public const int NonceSizeInBytes = 12;

    /// <summary>Keystream block size in bytes.</summary>
    public const int BlockSizeInBytes = 64;

    private const int StateWordCount = 16;
    private const int Rounds = 20;

    /// <summary>The "expand 32-byte k" constant, as four little-endian words.</summary>
    private static ReadOnlySpan<uint> Constants => [0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u];

    /// <summary>
    /// XORs the ChaCha20 keystream into <paramref name="destination"/>, starting at
    /// <paramref name="initialCounter"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="source"/> and <paramref name="destination"/> may be the same span:
    /// in-place transformation is what lets the receive path decrypt a datagram without
    /// copying it out of the socket buffer.
    /// </remarks>
    public static void Transform(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        uint initialCounter,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySizeInBytes);
        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSizeInBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length);

        Span<uint> state = stackalloc uint[StateWordCount];
        InitializeState(state, key, nonce, initialCounter);

        Span<uint> block = stackalloc uint[StateWordCount];
        Span<byte> keyStream = MemoryMarshal.AsBytes(block);

        while (!source.IsEmpty)
        {
            Permute(state, block);

            int count = Math.Min(BlockSizeInBytes, source.Length);
            for (int i = 0; i < count; i++)
            {
                destination[i] = (byte)(source[i] ^ keyStream[i]);
            }

            source = source[count..];
            destination = destination[count..];

            // RFC 8439 fixes the counter at 32 bits; wrapping would silently reuse
            // keystream, so a message long enough to wrap is rejected instead.
            state[12]++;
            if (state[12] == 0 && !source.IsEmpty)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
                CryptographicOperations.ZeroMemory(keyStream);
                throw new CryptographicException("ChaCha20 block counter overflowed; message is too long for a single nonce.");
            }
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
        CryptographicOperations.ZeroMemory(keyStream);
    }

    /// <summary>
    /// Produces a single keystream block. Used to derive the Poly1305 one-time key
    /// (block 0) and by HChaCha20.
    /// </summary>
    public static void GenerateKeyStreamBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        uint counter,
        Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSizeInBytes);

        Span<uint> state = stackalloc uint[StateWordCount];
        InitializeState(state, key, nonce, counter);

        Span<uint> block = stackalloc uint[StateWordCount];
        Permute(state, block);

        MemoryMarshal.AsBytes(block)[..BlockSizeInBytes].CopyTo(destination);

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(block));
    }

    /// <summary>
    /// Runs the 20-round core on <paramref name="state"/> <em>without</em> the final
    /// feed-forward addition, leaving the raw permutation output in
    /// <paramref name="destination"/>. This is the form HChaCha20 needs.
    /// </summary>
    public static void PermuteWithoutFeedForward(ReadOnlySpan<uint> state, Span<uint> destination)
    {
        state.CopyTo(destination);
        DoubleRounds(destination);
    }

    /// <summary>Builds the initial ChaCha20 state from key, nonce and counter.</summary>
    public static void InitializeState(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
    {
        Constants.CopyTo(state);

        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        }

        state[12] = counter;

        for (int i = 0; i < 3; i++)
        {
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(i * 4)..]);
        }
    }

    /// <summary>The full block function: 20 rounds plus the feed-forward addition.</summary>
    private static void Permute(ReadOnlySpan<uint> state, Span<uint> destination)
    {
        state.CopyTo(destination);
        DoubleRounds(destination);

        for (int i = 0; i < StateWordCount; i++)
        {
            destination[i] += state[i];
        }
    }

    private static void DoubleRounds(Span<uint> x)
    {
        for (int round = 0; round < Rounds; round += 2)
        {
            // Column round.
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);

            // Diagonal round.
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}
