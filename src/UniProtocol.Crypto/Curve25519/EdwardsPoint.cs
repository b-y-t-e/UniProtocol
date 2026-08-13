namespace UniProtocol.Crypto.Curve25519;

/// <summary>
/// A point on the twisted Edwards curve edwards25519, in extended coordinates.
/// </summary>
/// <remarks>
/// <para>
/// The affine point is <c>(X/Z, Y/Z)</c> and <c>T/Z = (X/Z)·(Y/Z)</c>. Extended
/// coordinates make addition and doubling complete — the same formulas work for every
/// pair of points including doublings and the identity — which removes the special cases
/// that would otherwise need data-dependent branches.
/// </para>
/// <para>
/// Scalar multiplication is plain constant-time double-and-add over 255 bits: one
/// doubling and one masked conditional addition per bit. Windowed methods with
/// precomputed tables are several times faster, but UniProtocol signs node records, not
/// packets — a handful of signatures per minute — so the simpler code that is obviously
/// free of secret-dependent behaviour is the better trade.
/// </para>
/// </remarks>
internal readonly struct EdwardsPoint
{
    /// <summary>Encoded point size in bytes.</summary>
    public const int SizeInBytes = 32;

    private readonly FieldElement _x;
    private readonly FieldElement _y;
    private readonly FieldElement _z;
    private readonly FieldElement _t;

    private EdwardsPoint(FieldElement x, FieldElement y, FieldElement z, FieldElement t)
    {
        _x = x;
        _y = y;
        _z = z;
        _t = t;
    }

    /// <summary>The neutral element (0, 1).</summary>
    public static EdwardsPoint Identity => new(FieldElement.Zero, FieldElement.One, FieldElement.One, FieldElement.Zero);

    /// <summary>The curve constant d = -121665/121666.</summary>
    private static FieldElement CurveD { get; } = FieldElement.FromBytes(
    [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
        0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
        0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
    ]);

    /// <summary>The constant 2d, used by the addition formula.</summary>
    private static FieldElement CurveTwoD { get; } = CurveD + CurveD;

    /// <summary>A square root of -1 modulo p, used when decompressing points.</summary>
    private static FieldElement SqrtMinusOne { get; } = FieldElement.FromBytes(
    [
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
    ]);

    /// <summary>The standard base point B.</summary>
    /// <remarks>
    /// Declared after the curve constants on purpose: static initialisers run in
    /// declaration order, and decoding a point reads <c>CurveD</c> and
    /// <c>SqrtMinusOne</c>. Moving this above them would silently decode the base point
    /// with d = 0 — producing a self-consistent but wrong group.
    /// </remarks>
    public static EdwardsPoint BasePoint { get; } = DecodeOrThrow(
    [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ]);

    /// <summary>Adds two points.</summary>
    public static EdwardsPoint operator +(EdwardsPoint left, EdwardsPoint right)
    {
        // RFC 8032 section 5.1.4, the "add-2008-hwcd-3" formulas.
        FieldElement a = (left._y - left._x) * (right._y - right._x);
        FieldElement b = (left._y + left._x) * (right._y + right._x);
        FieldElement c = left._t * CurveTwoD * right._t;
        FieldElement d = left._z * right._z;
        d += d;

        FieldElement e = b - a;
        FieldElement f = d - c;
        FieldElement g = d + c;
        FieldElement h = b + a;

        return new EdwardsPoint(e * f, g * h, f * g, e * h);
    }

    /// <summary>Doubles a point.</summary>
    public EdwardsPoint Double()
    {
        // RFC 8032 section 5.1.4, the "dbl-2008-hwcd" formulas.
        FieldElement a = _x.Square();
        FieldElement b = _y.Square();
        FieldElement c = _z.Square();
        c += c;

        FieldElement h = a + b;
        FieldElement e = h - (_x + _y).Square();
        FieldElement g = a - b;
        FieldElement f = c + g;

        return new EdwardsPoint(e * f, g * h, f * g, e * h);
    }

    /// <summary>Negates a point.</summary>
    public static EdwardsPoint operator -(EdwardsPoint value)
        => new(-value._x, value._y, value._z, -value._t);

    /// <summary>Subtracts <paramref name="right"/> from <paramref name="left"/>.</summary>
    public static EdwardsPoint operator -(EdwardsPoint left, EdwardsPoint right) => left + -right;

    /// <summary>
    /// Multiplies this point by <paramref name="scalar"/>, whose 32 little-endian bytes
    /// are treated as an integer below 2^255.
    /// </summary>
    public EdwardsPoint Multiply(ReadOnlySpan<byte> scalar)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(scalar.Length, Scalar.SizeInBytes);

        EdwardsPoint result = Identity;

        for (int bit = 254; bit >= 0; bit--)
        {
            result = result.Double();

            uint bitValue = (uint)((scalar[bit >> 3] >> (bit & 7)) & 1);
            EdwardsPoint sum = result + this;

            result = ConditionalSelect(result, sum, bitValue);
        }

        return result;
    }

    /// <summary>
    /// Returns <paramref name="ifTrue"/> when <paramref name="condition"/> is 1 and
    /// <paramref name="ifFalse"/> when it is 0, without branching.
    /// </summary>
    public static EdwardsPoint ConditionalSelect(EdwardsPoint ifFalse, EdwardsPoint ifTrue, uint condition)
        => new(
            FieldElement.ConditionalMove(ifFalse._x, ifTrue._x, condition),
            FieldElement.ConditionalMove(ifFalse._y, ifTrue._y, condition),
            FieldElement.ConditionalMove(ifFalse._z, ifTrue._z, condition),
            FieldElement.ConditionalMove(ifFalse._t, ifTrue._t, condition));

    /// <summary>Encodes the point in the 32-byte compressed form.</summary>
    public void Encode(Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SizeInBytes);

        FieldElement inverseZ = _z.Invert();
        FieldElement x = _x * inverseZ;
        FieldElement y = _y * inverseZ;

        y.ToBytes(destination);

        // The compressed form is the y-coordinate with the low bit of x in bit 255.
        destination[31] = (byte)(destination[31] | (x.IsNegative() << 7));
    }

    /// <summary>Returns the affine y-coordinate.</summary>
    public FieldElement GetAffineY() => _y * _z.Invert();

    /// <summary>
    /// Decodes a 32-byte compressed point.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the encoding does not correspond to a curve point.
    /// </returns>
    public static bool TryDecode(ReadOnlySpan<byte> source, out EdwardsPoint point)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, SizeInBytes);

        point = Identity;

        FieldElement y = FieldElement.FromBytes(source);
        uint expectedXSign = (uint)(source[31] >> 7);

        // Solve x^2 = (y^2 - 1) / (d*y^2 + 1).
        FieldElement ySquared = y.Square();
        FieldElement u = ySquared - FieldElement.One;
        FieldElement v = (CurveD * ySquared) + FieldElement.One;

        // Compute the candidate root as u*v^3 * (u*v^7)^((p-5)/8), avoiding an inversion.
        FieldElement v2 = v.Square();
        FieldElement v3 = v2 * v;
        FieldElement v6 = v3.Square();
        FieldElement v7 = v6 * v;

        FieldElement x = u * v3 * (u * v7).PowP58();

        FieldElement check = v * x.Square();

        uint isCorrectRoot = check.ConstantTimeEquals(u);
        uint isNegatedRoot = check.ConstantTimeEquals(-u);

        // When v*x^2 == -u the true root is x * sqrt(-1).
        x = FieldElement.ConditionalMove(x, x * SqrtMinusOne, isNegatedRoot);

        if ((isCorrectRoot | isNegatedRoot) == 0)
        {
            return false;
        }

        // x == 0 has only one root, so a sign bit of 1 is not a valid encoding of it.
        if (x.IsZero() == 1 && expectedXSign == 1)
        {
            return false;
        }

        x = FieldElement.ConditionalMove(x, -x, x.IsNegative() ^ expectedXSign);

        point = new EdwardsPoint(x, y, FieldElement.One, x * y);
        return true;
    }

    private static EdwardsPoint DecodeOrThrow(ReadOnlySpan<byte> source)
    {
        if (!TryDecode(source, out EdwardsPoint point))
        {
            throw new InvalidOperationException("A compiled-in curve constant failed to decode.");
        }

        return point;
    }
}
