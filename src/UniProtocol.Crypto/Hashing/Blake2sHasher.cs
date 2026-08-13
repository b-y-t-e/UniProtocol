using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Hashing;

/// <summary>
/// Incremental BLAKE2s state (RFC 7693), optionally keyed.
/// </summary>
/// <remarks>
/// <para>
/// This is a mutable value type so that a hash state can live inline in another
/// struct (the Noise symmetric state keeps one) without allocating. Copying the
/// value copies the state, which is exactly what Noise needs when it forks a
/// transcript hash.
/// </para>
/// <para>
/// BLAKE2s is implemented here rather than taken from the BCL because .NET does
/// not ship BLAKE2 at all, and Noise_IK_25519_ChaChaPoly_BLAKE2s requires it.
/// </para>
/// </remarks>
public struct Blake2sHasher
{
    /// <summary>Compression function block size in bytes.</summary>
    public const int BlockSizeInBytes = 64;

    /// <summary>Largest digest BLAKE2s can produce, in bytes.</summary>
    public const int MaxHashSizeInBytes = 32;

    /// <summary>Largest key BLAKE2s accepts, in bytes.</summary>
    public const int MaxKeySizeInBytes = 32;

    private static ReadOnlySpan<uint> InitializationVector =>
    [
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
    ];

    /// <summary>Message word permutation schedule, 10 rounds of 16 indices.</summary>
    private static ReadOnlySpan<byte> Sigma =>
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ];

    private StateWords _h;
    private BlockBuffer _buffer;
    private ulong _bytesCompressed;
    private int _bufferedCount;
    private int _hashSizeInBytes;
    private bool _isFinalized;

    /// <summary>
    /// Creates an unkeyed hasher producing <paramref name="hashSizeInBytes"/> bytes.
    /// </summary>
    public static Blake2sHasher Create(int hashSizeInBytes = MaxHashSizeInBytes)
        => Create(hashSizeInBytes, key: default);

    /// <summary>
    /// Creates a hasher producing <paramref name="hashSizeInBytes"/> bytes, keyed with
    /// <paramref name="key"/>. An empty key is equivalent to the unkeyed construction.
    /// </summary>
    public static Blake2sHasher Create(int hashSizeInBytes, ReadOnlySpan<byte> key)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(hashSizeInBytes, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(hashSizeInBytes, MaxHashSizeInBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(key.Length, MaxKeySizeInBytes);

        Blake2sHasher hasher = default;
        hasher._hashSizeInBytes = hashSizeInBytes;

        InitializationVector.CopyTo(hasher._h);

        // RFC 7693 section 2.5: the parameter block is XORed into the state. Only the
        // digest length, key length, fanout and depth are used; the rest stay zero.
        hasher._h[0] ^= 0x01010000u ^ ((uint)key.Length << 8) ^ (uint)hashSizeInBytes;

        if (!key.IsEmpty)
        {
            // The key is processed as one zero-padded block before the message.
            Span<byte> keyBlock = stackalloc byte[BlockSizeInBytes];
            keyBlock.Clear();
            key.CopyTo(keyBlock);
            hasher.Update(keyBlock);
            CryptographicOperations.ZeroMemory(keyBlock);
        }

        return hasher;
    }

    /// <summary>Absorbs <paramref name="data"/> into the state.</summary>
    public void Update(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_isFinalized, typeof(Blake2sHasher));

        if (data.IsEmpty)
        {
            return;
        }

        Span<byte> buffer = _buffer;

        // A full buffer is deliberately NOT compressed here: BLAKE2 marks the last
        // block during finalization, so the final block must stay buffered until then.
        if (_bufferedCount + data.Length > BlockSizeInBytes)
        {
            int fill = BlockSizeInBytes - _bufferedCount;
            data[..fill].CopyTo(buffer[_bufferedCount..]);
            data = data[fill..];

            _bytesCompressed += BlockSizeInBytes;
            Compress(buffer, isFinalBlock: false);
            _bufferedCount = 0;

            while (data.Length > BlockSizeInBytes)
            {
                _bytesCompressed += BlockSizeInBytes;
                Compress(data[..BlockSizeInBytes], isFinalBlock: false);
                data = data[BlockSizeInBytes..];
            }
        }

        data.CopyTo(buffer[_bufferedCount..]);
        _bufferedCount += data.Length;
    }

    /// <summary>
    /// Produces the digest into <paramref name="destination"/> and invalidates the state.
    /// </summary>
    public void Finish(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_isFinalized, typeof(Blake2sHasher));
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, _hashSizeInBytes);

        Span<byte> buffer = _buffer;
        _bytesCompressed += (ulong)_bufferedCount;
        buffer[_bufferedCount..].Clear();
        Compress(buffer, isFinalBlock: true);

        Span<byte> digest = stackalloc byte[MaxHashSizeInBytes];
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(digest[(i * 4)..], _h[i]);
        }

        digest[.._hashSizeInBytes].CopyTo(destination);

        CryptographicOperations.ZeroMemory(digest);
        CryptographicOperations.ZeroMemory(buffer);
        _isFinalized = true;
    }

    private void Compress(ReadOnlySpan<byte> block, bool isFinalBlock)
    {
        Span<uint> m = stackalloc uint[16];
        for (int i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block[(i * 4)..]);
        }

        Span<uint> v = stackalloc uint[16];
        for (int i = 0; i < 8; i++)
        {
            v[i] = _h[i];
        }

        InitializationVector.CopyTo(v[8..]);

        v[12] ^= (uint)_bytesCompressed;
        v[13] ^= (uint)(_bytesCompressed >> 32);
        if (isFinalBlock)
        {
            v[14] = ~v[14];
        }

        for (int round = 0; round < 10; round++)
        {
            ReadOnlySpan<byte> s = Sigma.Slice(round * 16, 16);

            Mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            Mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (int i = 0; i < 8; i++)
        {
            _h[i] ^= v[i] ^ v[i + 8];
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(m));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(v));
    }

    /// <summary>The BLAKE2 G mixing function (RFC 7693 section 3.1).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Mix(Span<uint> v, int a, int b, int c, int d, uint x, uint y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 8);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 7);
    }

    [InlineArray(8)]
    private struct StateWords
    {
        private uint _element0;
    }

    [InlineArray(BlockSizeInBytes)]
    private struct BlockBuffer
    {
        private byte _element0;
    }
}
