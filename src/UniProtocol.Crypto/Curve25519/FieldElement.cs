using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace UniProtocol.Crypto.Curve25519;

/// <summary>
/// An element of the prime field GF(2^255 - 19), stored as five 51-bit limbs.
/// </summary>
/// <remarks>
/// <para>
/// The radix-2^51 representation keeps every limb product below 2^110, so a full
/// multiplication fits in <see cref="UInt128"/> intermediates with room for the
/// accumulated sum — no assembly, no 32-bit fallback, and the same code path on every
/// platform UniProtocol targets.
/// </para>
/// <para>
/// <strong>Every operation here is constant time.</strong> There are no branches on limb
/// values, no data-dependent memory access and no early exits. Conditional behaviour is
/// expressed through <see cref="ConditionalSwap"/> and <see cref="ConditionalMove"/>,
/// which use arithmetic masks. Introducing an <c>if</c> on secret data in this file is a
/// key-recovery vulnerability, not a style issue.
/// </para>
/// <para>
/// Limbs are only weakly reduced between operations (they may briefly exceed 2^51);
/// full reduction happens in <see cref="ToBytes"/>. This is the standard "fe51" contract
/// and is what makes the carry chains cheap.
/// </para>
/// <para>
/// <strong>Input bound.</strong> Multiplication and squaring require every input limb to
/// be below 2^53. Outputs of <see cref="operator *"/>, <see cref="Square"/>,
/// <see cref="operator -"/> and <see cref="FromBytes"/> are below 2^51 + 2^13, so a single
/// <see cref="operator +"/> applied to them stays comfortably inside the bound — which is
/// exactly the pattern the Montgomery ladder and the Edwards formulas use. Chaining two
/// or more additions without an intervening multiplication would eventually overflow the
/// 64-bit carry fold, so do not do it.
/// </para>
/// </remarks>
internal readonly struct FieldElement
{
    /// <summary>Encoded size of a field element in bytes.</summary>
    public const int SizeInBytes = 32;

    private const ulong LimbMask = (1UL << 51) - 1;

    private readonly ulong _l0;
    private readonly ulong _l1;
    private readonly ulong _l2;
    private readonly ulong _l3;
    private readonly ulong _l4;

    private FieldElement(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
    {
        _l0 = l0;
        _l1 = l1;
        _l2 = l2;
        _l3 = l3;
        _l4 = l4;
    }

    /// <summary>The additive identity.</summary>
    public static FieldElement Zero => new(0, 0, 0, 0, 0);

    /// <summary>The multiplicative identity.</summary>
    public static FieldElement One => new(1, 0, 0, 0, 0);

    /// <summary>The constant 121666, used by the Montgomery ladder.</summary>
    public static FieldElement A24 => new(121666, 0, 0, 0, 0);

    /// <summary>Decodes a little-endian 32-byte value, ignoring bit 255.</summary>
    /// <remarks>
    /// Bit 255 is masked off rather than rejected: RFC 7748 requires implementations to
    /// ignore it on the Montgomery u-coordinate, and callers that care about canonical
    /// encodings check that separately.
    /// </remarks>
    public static FieldElement FromBytes(ReadOnlySpan<byte> source)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, SizeInBytes);

        ulong l0 = BinaryPrimitives.ReadUInt64LittleEndian(source) & LimbMask;
        ulong l1 = (BinaryPrimitives.ReadUInt64LittleEndian(source[6..]) >> 3) & LimbMask;
        ulong l2 = (BinaryPrimitives.ReadUInt64LittleEndian(source[12..]) >> 6) & LimbMask;
        ulong l3 = (BinaryPrimitives.ReadUInt64LittleEndian(source[19..]) >> 1) & LimbMask;
        ulong l4 = (BinaryPrimitives.ReadUInt64LittleEndian(source[24..]) >> 12) & LimbMask;

        return new FieldElement(l0, l1, l2, l3, l4);
    }

    /// <summary>Encodes the fully reduced value as 32 little-endian bytes.</summary>
    public void ToBytes(Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SizeInBytes);

        // Two full carry passes are required, not one: the first pass can push a carry
        // out of the top limb back into limb 0 (times 19) and leave it above 2^51 again.
        // Skipping the second pass leaves a value that encodes correctly most of the time
        // and silently wrong occasionally, which is the worst possible failure mode here.
        FieldElement reduced = new FieldElement(_l0, _l1, _l2, _l3, _l4).FullCarry().FullCarry();

        ulong l0 = reduced._l0;
        ulong l1 = reduced._l1;
        ulong l2 = reduced._l2;
        ulong l3 = reduced._l3;
        ulong l4 = reduced._l4;

        // The value is now in [0, 2^255). It needs one conditional subtraction of p:
        // adding 19 carries out of the top limb exactly when the value is >= p, so q is
        // the 0/1 answer computed without a branch.
        ulong q = (l0 + 19) >> 51;
        q = (l1 + q) >> 51;
        q = (l2 + q) >> 51;
        q = (l3 + q) >> 51;
        q = (l4 + q) >> 51;

        l0 += 19 * q;
        ulong carry = l0 >> 51;
        l0 &= LimbMask;
        l1 += carry;
        carry = l1 >> 51;
        l1 &= LimbMask;
        l2 += carry;
        carry = l2 >> 51;
        l2 &= LimbMask;
        l3 += carry;
        carry = l3 >> 51;
        l3 &= LimbMask;
        l4 += carry;

        // Discarding the carry out of l4 performs the reduction modulo 2^255.
        l4 &= LimbMask;

        BinaryPrimitives.WriteUInt64LittleEndian(destination, l0 | (l1 << 51));
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], (l1 >> 13) | (l2 << 38));
        BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], (l2 >> 26) | (l3 << 25));
        BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], (l3 >> 39) | (l4 << 12));
    }

    /// <summary>Field addition.</summary>
    public static FieldElement operator +(FieldElement left, FieldElement right)
        => new(
            left._l0 + right._l0,
            left._l1 + right._l1,
            left._l2 + right._l2,
            left._l3 + right._l3,
            left._l4 + right._l4);

    /// <summary>Field subtraction.</summary>
    public static FieldElement operator -(FieldElement left, FieldElement right)
    {
        // Add 2p before subtracting so limbs never go negative. 2p in this radix is
        // (2^52 - 38, 2^52 - 2, 2^52 - 2, 2^52 - 2, 2^52 - 2).
        ulong l0 = left._l0 + 0xFFFFFFFFFFFDAUL - right._l0;
        ulong l1 = left._l1 + 0xFFFFFFFFFFFFEUL - right._l1;
        ulong l2 = left._l2 + 0xFFFFFFFFFFFFEUL - right._l2;
        ulong l3 = left._l3 + 0xFFFFFFFFFFFFEUL - right._l3;
        ulong l4 = left._l4 + 0xFFFFFFFFFFFFEUL - right._l4;

        return WeakReduce(l0, l1, l2, l3, l4);
    }

    /// <summary>Field negation.</summary>
    public static FieldElement operator -(FieldElement value) => Zero - value;

    /// <summary>Field multiplication.</summary>
    public static FieldElement operator *(FieldElement left, FieldElement right)
    {
        ulong g1_19 = 19 * right._l1;
        ulong g2_19 = 19 * right._l2;
        ulong g3_19 = 19 * right._l3;
        ulong g4_19 = 19 * right._l4;

        UInt128 t0 = ((UInt128)left._l0 * right._l0)
                   + ((UInt128)left._l1 * g4_19)
                   + ((UInt128)left._l2 * g3_19)
                   + ((UInt128)left._l3 * g2_19)
                   + ((UInt128)left._l4 * g1_19);

        UInt128 t1 = ((UInt128)left._l0 * right._l1)
                   + ((UInt128)left._l1 * right._l0)
                   + ((UInt128)left._l2 * g4_19)
                   + ((UInt128)left._l3 * g3_19)
                   + ((UInt128)left._l4 * g2_19);

        UInt128 t2 = ((UInt128)left._l0 * right._l2)
                   + ((UInt128)left._l1 * right._l1)
                   + ((UInt128)left._l2 * right._l0)
                   + ((UInt128)left._l3 * g4_19)
                   + ((UInt128)left._l4 * g3_19);

        UInt128 t3 = ((UInt128)left._l0 * right._l3)
                   + ((UInt128)left._l1 * right._l2)
                   + ((UInt128)left._l2 * right._l1)
                   + ((UInt128)left._l3 * right._l0)
                   + ((UInt128)left._l4 * g4_19);

        UInt128 t4 = ((UInt128)left._l0 * right._l4)
                   + ((UInt128)left._l1 * right._l3)
                   + ((UInt128)left._l2 * right._l2)
                   + ((UInt128)left._l3 * right._l1)
                   + ((UInt128)left._l4 * right._l0);

        return CarryReduce(t0, t1, t2, t3, t4);
    }

    /// <summary>Field squaring.</summary>
    public FieldElement Square()
    {
        ulong l0_2 = 2 * _l0;
        ulong l1_2 = 2 * _l1;
        ulong l3_19 = 19 * _l3;
        ulong l4_19 = 19 * _l4;

        UInt128 t0 = ((UInt128)_l0 * _l0)
                   + ((UInt128)l1_2 * l4_19)
                   + ((UInt128)(2 * _l2) * l3_19);

        UInt128 t1 = ((UInt128)l0_2 * _l1)
                   + ((UInt128)_l2 * l4_19 * 2)
                   + ((UInt128)_l3 * l3_19);

        UInt128 t2 = ((UInt128)l0_2 * _l2)
                   + ((UInt128)_l1 * _l1)
                   + ((UInt128)(2 * _l3) * l4_19);

        UInt128 t3 = ((UInt128)l0_2 * _l3)
                   + ((UInt128)l1_2 * _l2)
                   + ((UInt128)_l4 * l4_19);

        UInt128 t4 = ((UInt128)l0_2 * _l4)
                   + ((UInt128)l1_2 * _l3)
                   + ((UInt128)_l2 * _l2);

        return CarryReduce(t0, t1, t2, t3, t4);
    }

    /// <summary>Squares the value <paramref name="count"/> times.</summary>
    public FieldElement SquareRepeatedly(int count)
    {
        FieldElement result = this;
        for (int i = 0; i < count; i++)
        {
            result = result.Square();
        }

        return result;
    }

    /// <summary>Multiplies by the ladder constant 121666.</summary>
    public FieldElement MultiplyBy121666()
    {
        UInt128 t0 = (UInt128)_l0 * 121666;
        UInt128 t1 = (UInt128)_l1 * 121666;
        UInt128 t2 = (UInt128)_l2 * 121666;
        UInt128 t3 = (UInt128)_l3 * 121666;
        UInt128 t4 = (UInt128)_l4 * 121666;

        return CarryReduce(t0, t1, t2, t3, t4);
    }

    /// <summary>Computes the multiplicative inverse, i.e. <c>this^(p-2)</c>.</summary>
    /// <remarks>
    /// The addition chain is the standard ref10 one: 254 squarings and 11 multiplications.
    /// Exponentiating by the fixed exponent p-2 keeps inversion constant time, which
    /// matters because the inverse is taken on secret coordinates.
    /// </remarks>
    public FieldElement Invert()
    {
        FieldElement z2 = Square();
        FieldElement z8 = z2.SquareRepeatedly(2);
        FieldElement z9 = this * z8;
        FieldElement z11 = z2 * z9;
        FieldElement z22 = z11.Square();
        FieldElement z5To0 = z9 * z22;

        FieldElement t = z5To0.SquareRepeatedly(5);
        FieldElement z10To0 = t * z5To0;

        t = z10To0.SquareRepeatedly(10);
        FieldElement z20To0 = t * z10To0;

        t = z20To0.SquareRepeatedly(20);
        FieldElement z40To0 = t * z20To0;

        t = z40To0.SquareRepeatedly(10);
        FieldElement z50To0 = t * z10To0;

        t = z50To0.SquareRepeatedly(50);
        FieldElement z100To0 = t * z50To0;

        t = z100To0.SquareRepeatedly(100);
        FieldElement z200To0 = t * z100To0;

        t = z200To0.SquareRepeatedly(50);
        FieldElement z250To0 = t * z50To0;

        return z250To0.SquareRepeatedly(5) * z11;
    }

    /// <summary>Computes <c>this^((p-5)/8)</c>, the exponent used for square roots.</summary>
    public FieldElement PowP58()
    {
        FieldElement z2 = Square();
        FieldElement z8 = z2.SquareRepeatedly(2);
        FieldElement z9 = this * z8;
        FieldElement z11 = z2 * z9;
        FieldElement z22 = z11.Square();
        FieldElement z5To0 = z9 * z22;

        FieldElement t = z5To0.SquareRepeatedly(5);
        FieldElement z10To0 = t * z5To0;

        t = z10To0.SquareRepeatedly(10);
        FieldElement z20To0 = t * z10To0;

        t = z20To0.SquareRepeatedly(20);
        FieldElement z40To0 = t * z20To0;

        t = z40To0.SquareRepeatedly(10);
        FieldElement z50To0 = t * z10To0;

        t = z50To0.SquareRepeatedly(50);
        FieldElement z100To0 = t * z50To0;

        t = z100To0.SquareRepeatedly(100);
        FieldElement z200To0 = t * z100To0;

        t = z200To0.SquareRepeatedly(50);
        FieldElement z250To0 = t * z50To0;

        return z250To0.SquareRepeatedly(2) * this;
    }

    /// <summary>
    /// Swaps <paramref name="a"/> and <paramref name="b"/> when <paramref name="swap"/>
    /// is 1, and leaves them alone when it is 0, in constant time.
    /// </summary>
    /// <remarks>
    /// This is the primitive the Montgomery ladder uses to consume one secret scalar bit
    /// per iteration without branching. <paramref name="swap"/> must be exactly 0 or 1.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ConditionalSwap(ref FieldElement a, ref FieldElement b, uint swap)
    {
        ulong mask = 0UL - swap;

        ulong d0 = mask & (a._l0 ^ b._l0);
        ulong d1 = mask & (a._l1 ^ b._l1);
        ulong d2 = mask & (a._l2 ^ b._l2);
        ulong d3 = mask & (a._l3 ^ b._l3);
        ulong d4 = mask & (a._l4 ^ b._l4);

        FieldElement newA = new(a._l0 ^ d0, a._l1 ^ d1, a._l2 ^ d2, a._l3 ^ d3, a._l4 ^ d4);
        FieldElement newB = new(b._l0 ^ d0, b._l1 ^ d1, b._l2 ^ d2, b._l3 ^ d3, b._l4 ^ d4);

        a = newA;
        b = newB;
    }

    /// <summary>
    /// Returns <paramref name="ifTrue"/> when <paramref name="condition"/> is 1 and
    /// <paramref name="ifFalse"/> when it is 0, in constant time.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FieldElement ConditionalMove(FieldElement ifFalse, FieldElement ifTrue, uint condition)
    {
        ulong mask = 0UL - condition;

        return new FieldElement(
            ifFalse._l0 ^ (mask & (ifFalse._l0 ^ ifTrue._l0)),
            ifFalse._l1 ^ (mask & (ifFalse._l1 ^ ifTrue._l1)),
            ifFalse._l2 ^ (mask & (ifFalse._l2 ^ ifTrue._l2)),
            ifFalse._l3 ^ (mask & (ifFalse._l3 ^ ifTrue._l3)),
            ifFalse._l4 ^ (mask & (ifFalse._l4 ^ ifTrue._l4)));
    }

    /// <summary>Returns 1 when the value is zero and 0 otherwise, in constant time.</summary>
    public uint IsZero()
    {
        Span<byte> encoded = stackalloc byte[SizeInBytes];
        ToBytes(encoded);

        byte accumulator = 0;
        for (int i = 0; i < SizeInBytes; i++)
        {
            accumulator |= encoded[i];
        }

        // accumulator == 0  ->  1, otherwise 0.
        return (uint)((accumulator - 1) >> 31) & 1u;
    }

    /// <summary>Returns the least significant bit of the canonical encoding.</summary>
    /// <remarks>Edwards point compression uses this as the sign of the x-coordinate.</remarks>
    public uint IsNegative()
    {
        Span<byte> encoded = stackalloc byte[SizeInBytes];
        ToBytes(encoded);

        return (uint)(encoded[0] & 1);
    }

    /// <summary>Returns 1 when both values are equal, in constant time.</summary>
    /// <remarks>
    /// Deliberately not named <c>Equals</c>: it returns a mask rather than a
    /// <see cref="bool"/>, precisely so that callers cannot branch on it by accident.
    /// </remarks>
    public uint ConstantTimeEquals(FieldElement other) => (this - other).IsZero();

    /// <summary>
    /// One pass of the carry chain: propagates each limb's overflow into the next and
    /// folds the carry out of the top limb back into limb 0 (times 19, since 2^255 ≡ 19).
    /// </summary>
    private FieldElement FullCarry()
    {
        ulong l0 = _l0;
        ulong l1 = _l1 + (l0 >> 51);
        l0 &= LimbMask;

        ulong l2 = _l2 + (l1 >> 51);
        l1 &= LimbMask;

        ulong l3 = _l3 + (l2 >> 51);
        l2 &= LimbMask;

        ulong l4 = _l4 + (l3 >> 51);
        l3 &= LimbMask;

        l0 += 19 * (l4 >> 51);
        l4 &= LimbMask;

        return new FieldElement(l0, l1, l2, l3, l4);
    }

    private static FieldElement WeakReduce(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
    {
        ulong carry = l0 >> 51;
        l0 &= LimbMask;
        l1 += carry;

        carry = l1 >> 51;
        l1 &= LimbMask;
        l2 += carry;

        carry = l2 >> 51;
        l2 &= LimbMask;
        l3 += carry;

        carry = l3 >> 51;
        l3 &= LimbMask;
        l4 += carry;

        carry = l4 >> 51;
        l4 &= LimbMask;
        l0 += carry * 19;

        carry = l0 >> 51;
        l0 &= LimbMask;
        l1 += carry;

        return new FieldElement(l0, l1, l2, l3, l4);
    }

    private static FieldElement CarryReduce(UInt128 t0, UInt128 t1, UInt128 t2, UInt128 t3, UInt128 t4)
    {
        ulong carry = (ulong)(t0 >> 51);
        ulong l0 = (ulong)t0 & LimbMask;

        t1 += carry;
        carry = (ulong)(t1 >> 51);
        ulong l1 = (ulong)t1 & LimbMask;

        t2 += carry;
        carry = (ulong)(t2 >> 51);
        ulong l2 = (ulong)t2 & LimbMask;

        t3 += carry;
        carry = (ulong)(t3 >> 51);
        ulong l3 = (ulong)t3 & LimbMask;

        t4 += carry;
        carry = (ulong)(t4 >> 51);
        ulong l4 = (ulong)t4 & LimbMask;

        l0 += carry * 19;
        carry = l0 >> 51;
        l0 &= LimbMask;
        l1 += carry;
        carry = l1 >> 51;
        l1 &= LimbMask;
        l2 += carry;

        return new FieldElement(l0, l1, l2, l3, l4);
    }
}
