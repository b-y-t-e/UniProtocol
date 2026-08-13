using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace UniProtocol.Crypto.Curve25519;

/// <summary>
/// An integer modulo the order of the Ed25519 prime-order subgroup,
/// <c>L = 2^252 + 27742317777372353535851937790883648493</c>.
/// </summary>
/// <remarks>
/// <para>
/// Held as four 64-bit limbs. Reduction is a bitwise long division — one shift and one
/// masked conditional subtraction per bit of the input — rather than the packed 21-bit
/// Barrett reduction used by the classic ref10 code.
/// </para>
/// <para>
/// That is a deliberate trade. Signing performs one reduction of a 512-bit hash and one
/// multiply-add; at UniProtocol's rate (a signature per node record, not per packet) the
/// difference is unmeasurable, while the long-division form is short enough to read and
/// check by eye. The ref10 version is several hundred lines of hand-scheduled limb
/// arithmetic in which a single mistyped constant produces signatures that verify against
/// themselves and nothing else.
/// </para>
/// <para>
/// Every operation is constant time: the loop trip count depends only on the input size,
/// and the conditional subtraction is a mask, not a branch.
/// </para>
/// </remarks>
internal readonly struct Scalar
{
    /// <summary>Encoded size of a scalar in bytes.</summary>
    public const int SizeInBytes = 32;

    /// <summary>The group order L, little-endian by limb.</summary>
    private const ulong OrderL0 = 0x5812631A5CF5D3EDUL;
    private const ulong OrderL1 = 0x14DEF9DEA2F79CD6UL;
    private const ulong OrderL2 = 0x0000000000000000UL;
    private const ulong OrderL3 = 0x1000000000000000UL;

    private readonly ulong _l0;
    private readonly ulong _l1;
    private readonly ulong _l2;
    private readonly ulong _l3;

    private Scalar(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        _l0 = l0;
        _l1 = l1;
        _l2 = l2;
        _l3 = l3;
    }

    /// <summary>The additive identity.</summary>
    public static Scalar Zero => new(0, 0, 0, 0);

    /// <summary>
    /// Reduces a little-endian integer of 32 or 64 bytes modulo L.
    /// </summary>
    /// <remarks>
    /// The 64-byte form is what Ed25519 needs: both <c>r</c> and <c>k</c> are SHA-512
    /// outputs interpreted as integers and reduced.
    /// </remarks>
    public static Scalar FromBytesModOrder(ReadOnlySpan<byte> littleEndian)
    {
        if (littleEndian.Length is not (32 or 64))
        {
            throw new ArgumentOutOfRangeException(
                nameof(littleEndian),
                littleEndian.Length,
                "A scalar is reduced from either 32 or 64 little-endian bytes.");
        }

        Span<ulong> value = stackalloc ulong[8];
        value.Clear();

        for (int i = 0; i < littleEndian.Length / 8; i++)
        {
            value[i] = BinaryPrimitives.ReadUInt64LittleEndian(littleEndian[(i * 8)..]);
        }

        return ReduceWideValue(value, bitCount: littleEndian.Length * 8);
    }

    /// <summary>
    /// Reads a scalar that is required to be already reduced, rejecting any encoding
    /// greater than or equal to L.
    /// </summary>
    /// <remarks>
    /// Ed25519 verification must reject non-canonical <c>S</c> values: accepting them
    /// makes signatures malleable, because <c>S</c> and <c>S + L</c> would both verify.
    /// </remarks>
    public static bool TryFromCanonicalBytes(ReadOnlySpan<byte> littleEndian, out Scalar scalar)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(littleEndian.Length, SizeInBytes);

        Scalar candidate = new(
            BinaryPrimitives.ReadUInt64LittleEndian(littleEndian),
            BinaryPrimitives.ReadUInt64LittleEndian(littleEndian[8..]),
            BinaryPrimitives.ReadUInt64LittleEndian(littleEndian[16..]),
            BinaryPrimitives.ReadUInt64LittleEndian(littleEndian[24..]));

        // A borrow out of candidate - L means candidate < L, i.e. the encoding is canonical.
        SubtractOrder(candidate, out ulong borrow);

        scalar = borrow == 1 ? candidate : Zero;
        return borrow == 1;
    }

    /// <summary>Encodes the scalar as 32 little-endian bytes.</summary>
    public void ToBytes(Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SizeInBytes);

        BinaryPrimitives.WriteUInt64LittleEndian(destination, _l0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], _l1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], _l2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], _l3);
    }

    /// <summary>Computes <c>(a * b + c) mod L</c>.</summary>
    /// <remarks>
    /// This is the whole of Ed25519 signing's scalar arithmetic: <c>S = (r + k * a) mod L</c>.
    /// </remarks>
    public static Scalar MultiplyAdd(Scalar a, Scalar b, Scalar c)
    {
        Span<ulong> product = stackalloc ulong[8];
        MultiplyWide(a, b, product);

        // Adding c (which is below 2^253) to the low half cannot overflow the 512-bit
        // product, because the product of two values below L is itself below 2^505.
        AddInPlace(product, c);

        return ReduceWideValue(product, bitCount: 512);
    }

    /// <summary>Returns 1 when the scalar is zero, in constant time.</summary>
    public uint IsZero()
    {
        ulong accumulator = _l0 | _l1 | _l2 | _l3;

        // accumulator == 0 -> 1, otherwise 0.
        return (uint)(((accumulator | (~accumulator + 1)) >> 63) ^ 1);
    }

    private static void MultiplyWide(Scalar a, Scalar b, Span<ulong> destination)
    {
        ReadOnlySpan<ulong> left = [a._l0, a._l1, a._l2, a._l3];
        ReadOnlySpan<ulong> right = [b._l0, b._l1, b._l2, b._l3];

        destination.Clear();

        for (int i = 0; i < 4; i++)
        {
            ulong carry = 0;

            for (int j = 0; j < 4; j++)
            {
                UInt128 term = (UInt128)left[i] * right[j] + destination[i + j] + carry;
                destination[i + j] = (ulong)term;
                carry = (ulong)(term >> 64);
            }

            destination[i + 4] += carry;
        }
    }

    private static void AddInPlace(Span<ulong> value, Scalar addend)
    {
        ReadOnlySpan<ulong> limbs = [addend._l0, addend._l1, addend._l2, addend._l3];

        ulong carry = 0;
        for (int i = 0; i < value.Length; i++)
        {
            UInt128 sum = (UInt128)value[i] + carry + (i < 4 ? limbs[i] : 0UL);
            value[i] = (ulong)sum;
            carry = (ulong)(sum >> 64);
        }
    }

    /// <summary>
    /// Reduces a wide little-endian value modulo L by shifting one bit at a time into a
    /// remainder and conditionally subtracting L.
    /// </summary>
    private static Scalar ReduceWideValue(ReadOnlySpan<ulong> value, int bitCount)
    {
        ulong r0 = 0;
        ulong r1 = 0;
        ulong r2 = 0;
        ulong r3 = 0;

        for (int bit = bitCount - 1; bit >= 0; bit--)
        {
            ulong nextBit = (value[bit >> 6] >> (bit & 63)) & 1;

            // The remainder is always below L < 2^253, so doubling it cannot overflow
            // four limbs and no fifth limb is needed.
            r3 = (r3 << 1) | (r2 >> 63);
            r2 = (r2 << 1) | (r1 >> 63);
            r1 = (r1 << 1) | (r0 >> 63);
            r0 = (r0 << 1) | nextBit;

            Scalar remainder = new(r0, r1, r2, r3);
            Scalar reduced = SubtractOrder(remainder, out ulong borrow);

            // borrow == 0 means remainder >= L, so the subtraction is the value to keep.
            ulong mask = borrow - 1;
            r0 = (r0 & ~mask) | (reduced._l0 & mask);
            r1 = (r1 & ~mask) | (reduced._l1 & mask);
            r2 = (r2 & ~mask) | (reduced._l2 & mask);
            r3 = (r3 & ~mask) | (reduced._l3 & mask);
        }

        return new Scalar(r0, r1, r2, r3);
    }

    /// <summary>
    /// Computes <c>value - L</c>, reporting whether the subtraction borrowed (i.e.
    /// whether <c>value &lt; L</c>).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Scalar SubtractOrder(Scalar value, out ulong borrow)
    {
        UInt128 difference = (UInt128)value._l0 - OrderL0;
        ulong d0 = (ulong)difference;
        ulong currentBorrow = (ulong)(difference >> 64) & 1;

        difference = (UInt128)value._l1 - OrderL1 - currentBorrow;
        ulong d1 = (ulong)difference;
        currentBorrow = (ulong)(difference >> 64) & 1;

        difference = (UInt128)value._l2 - OrderL2 - currentBorrow;
        ulong d2 = (ulong)difference;
        currentBorrow = (ulong)(difference >> 64) & 1;

        difference = (UInt128)value._l3 - OrderL3 - currentBorrow;
        ulong d3 = (ulong)difference;
        borrow = (ulong)(difference >> 64) & 1;

        return new Scalar(d0, d1, d2, d3);
    }
}
