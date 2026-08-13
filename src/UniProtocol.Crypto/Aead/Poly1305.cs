using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// The Poly1305 one-time authenticator (RFC 8439 section 2.5), as an incremental state.
/// </summary>
/// <remarks>
/// <para>
/// The accumulator is held as three limbs of 44, 44 and 42 bits so that a limb product
/// fits in a 128-bit intermediate. This is the "donna64" layout; on .NET it maps
/// directly onto <see cref="UInt128"/>, so the reduction needs no assembly and no
/// data-dependent branching.
/// </para>
/// <para>
/// A Poly1305 key must never be reused across messages. Callers get that for free by
/// going through <see cref="ChaCha20Poly1305Algorithm"/>, which derives a fresh one-time
/// key from the ChaCha20 keystream for every nonce.
/// </para>
/// </remarks>
internal struct Poly1305
{
    /// <summary>Key size in bytes (16 bytes of <c>r</c> followed by 16 bytes of <c>s</c>).</summary>
    public const int KeySizeInBytes = 32;

    /// <summary>Authentication tag size in bytes.</summary>
    public const int TagSizeInBytes = 16;

    /// <summary>Message block size in bytes.</summary>
    public const int BlockSizeInBytes = 16;

    private const ulong LimbMask = 0xFFFFFFFFFFFUL; // 44 bits
    private const ulong HighLimbMask = 0x3FFFFFFFFFFUL; // 42 bits

    private ulong _r0;
    private ulong _r1;
    private ulong _r2;
    private ulong _s1;
    private ulong _s2;

    private ulong _h0;
    private ulong _h1;
    private ulong _h2;

    private ulong _pad0;
    private ulong _pad1;

    private BlockBuffer _buffer;
    private int _bufferedCount;

    /// <summary>Creates an authenticator state from a 32-byte one-time key.</summary>
    public static Poly1305 Create(ReadOnlySpan<byte> key)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySizeInBytes);

        ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
        ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);

        Poly1305 state = default;

        // Clamp r per RFC 8439 section 2.5.1, expressed directly in the 44/44/42 layout.
        state._r0 = t0 & 0x0FFC0FFFFFFFUL;
        state._r1 = ((t0 >> 44) | (t1 << 20)) & 0x0FFFFFC0FFFFUL;
        state._r2 = (t1 >> 24) & 0x00FFFFFFC0FUL;

        // 2^130 mod p == 5, and the top limb is 42 bits, so folding a carry out of limb 2
        // back into limb 0 multiplies by 5 * 4 == 20.
        state._s1 = state._r1 * 20;
        state._s2 = state._r2 * 20;

        state._pad0 = BinaryPrimitives.ReadUInt64LittleEndian(key[16..]);
        state._pad1 = BinaryPrimitives.ReadUInt64LittleEndian(key[24..]);

        return state;
    }

    /// <summary>Absorbs <paramref name="data"/> into the authenticator.</summary>
    public void Update(ReadOnlySpan<byte> data)
    {
        Span<byte> buffer = _buffer;

        if (_bufferedCount > 0)
        {
            int fill = Math.Min(BlockSizeInBytes - _bufferedCount, data.Length);
            data[..fill].CopyTo(buffer[_bufferedCount..]);
            _bufferedCount += fill;
            data = data[fill..];

            if (_bufferedCount < BlockSizeInBytes)
            {
                return;
            }

            AbsorbBlock(buffer, isFinalPartialBlock: false);
            _bufferedCount = 0;
        }

        while (data.Length >= BlockSizeInBytes)
        {
            AbsorbBlock(data[..BlockSizeInBytes], isFinalPartialBlock: false);
            data = data[BlockSizeInBytes..];
        }

        if (!data.IsEmpty)
        {
            data.CopyTo(buffer);
            _bufferedCount = data.Length;
        }
    }

    /// <summary>
    /// Appends zeros until the absorbed length is a multiple of the block size.
    /// </summary>
    /// <remarks>
    /// The AEAD construction pads the associated data and the ciphertext to 16-byte
    /// boundaries so that a caller cannot shift bytes between the two fields.
    /// </remarks>
    public void PadToBlockBoundary()
    {
        if (_bufferedCount == 0)
        {
            return;
        }

        Span<byte> padding = stackalloc byte[BlockSizeInBytes];
        padding.Clear();
        Update(padding[..(BlockSizeInBytes - _bufferedCount)]);
    }

    /// <summary>Produces the 16-byte tag and invalidates the state.</summary>
    public void Finish(Span<byte> tag)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(tag.Length, TagSizeInBytes);

        if (_bufferedCount > 0)
        {
            Span<byte> buffer = _buffer;
            buffer[_bufferedCount] = 0x01;
            buffer[(_bufferedCount + 1)..].Clear();
            AbsorbBlock(buffer, isFinalPartialBlock: true);
            _bufferedCount = 0;
        }

        // Fully carry the accumulator.
        ulong carry = _h1 >> 44;
        _h1 &= LimbMask;
        _h2 += carry;
        carry = _h2 >> 42;
        _h2 &= HighLimbMask;
        _h0 += carry * 5;
        carry = _h0 >> 44;
        _h0 &= LimbMask;
        _h1 += carry;
        carry = _h1 >> 44;
        _h1 &= LimbMask;
        _h2 += carry;
        carry = _h2 >> 42;
        _h2 &= HighLimbMask;
        _h0 += carry * 5;
        carry = _h0 >> 44;
        _h0 &= LimbMask;
        _h1 += carry;

        // Compute h + -p and select it if and only if h >= p, without branching.
        ulong g0 = _h0 + 5;
        carry = g0 >> 44;
        g0 &= LimbMask;
        ulong g1 = _h1 + carry;
        carry = g1 >> 44;
        g1 &= LimbMask;
        ulong g2 = _h2 + carry - (1UL << 42);

        ulong selectG = (g2 >> 63) - 1; // all ones when h >= p, zero otherwise
        g0 &= selectG;
        g1 &= selectG;
        g2 &= selectG;

        ulong selectH = ~selectG;
        _h0 = (_h0 & selectH) | g0;
        _h1 = (_h1 & selectH) | g1;
        _h2 = (_h2 & selectH) | g2;

        // tag = (h + s) mod 2^128
        ulong t0 = _pad0;
        ulong t1 = _pad1;

        _h0 += t0 & LimbMask;
        carry = _h0 >> 44;
        _h0 &= LimbMask;
        _h1 += (((t0 >> 44) | (t1 << 20)) & LimbMask) + carry;
        carry = _h1 >> 44;
        _h1 &= LimbMask;
        _h2 += ((t1 >> 24) & HighLimbMask) + carry;
        _h2 &= HighLimbMask;

        BinaryPrimitives.WriteUInt64LittleEndian(tag, _h0 | (_h1 << 44));
        BinaryPrimitives.WriteUInt64LittleEndian(tag[8..], (_h1 >> 20) | (_h2 << 24));

        this = default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void AbsorbBlock(ReadOnlySpan<byte> block, bool isFinalPartialBlock)
    {
        ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(block);
        ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(block[8..]);

        // A whole block carries an implicit 1 bit above its 128 bits; a final partial
        // block already had its 0x01 byte written into the padding, so it must not.
        ulong highBit = isFinalPartialBlock ? 0UL : 1UL << 40;

        _h0 += t0 & LimbMask;
        _h1 += ((t0 >> 44) | (t1 << 20)) & LimbMask;
        _h2 += ((t1 >> 24) & HighLimbMask) | highBit;

        UInt128 d0 = ((UInt128)_h0 * _r0) + ((UInt128)_h1 * _s2) + ((UInt128)_h2 * _s1);
        UInt128 d1 = ((UInt128)_h0 * _r1) + ((UInt128)_h1 * _r0) + ((UInt128)_h2 * _s2);
        UInt128 d2 = ((UInt128)_h0 * _r2) + ((UInt128)_h1 * _r1) + ((UInt128)_h2 * _r0);

        ulong carry = (ulong)(d0 >> 44);
        _h0 = (ulong)d0 & LimbMask;

        d1 += carry;
        carry = (ulong)(d1 >> 44);
        _h1 = (ulong)d1 & LimbMask;

        d2 += carry;
        carry = (ulong)(d2 >> 42);
        _h2 = (ulong)d2 & HighLimbMask;

        _h0 += carry * 5;
        carry = _h0 >> 44;
        _h0 &= LimbMask;
        _h1 += carry;
    }

    /// <summary>Overwrites the key material held by this state.</summary>
    public void Clear()
    {
        Span<byte> buffer = _buffer;
        CryptographicOperations.ZeroMemory(buffer);
        this = default;
    }

    [InlineArray(BlockSizeInBytes)]
    private struct BlockBuffer
    {
        private byte _element0;
    }
}
