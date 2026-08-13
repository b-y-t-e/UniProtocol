using System.Numerics;
using UniProtocol.Crypto.Curve25519;

namespace UniProtocol.Crypto.Tests.Curve25519;

/// <summary>
/// Differential tests of the 51-bit limb arithmetic against <see cref="BigInteger"/>.
/// </summary>
/// <remarks>
/// The limb representation exists for speed and constant-time behaviour, not clarity, so
/// it is checked against an obviously-correct arbitrary-precision reference rather than
/// against itself. Carry-propagation bugs survive round-trip tests but never survive this.
/// </remarks>
public sealed class FieldElementTests
{
    private static readonly BigInteger Prime = BigInteger.Pow(2, 255) - 19;

    private static readonly string[] SampleValues =
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // 2^255 - 1
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "0900000000000000000000000000000000000000000000000000000000000000",
    ];

    public static TheoryData<string> Samples => [.. SampleValues];

    [Theory]
    [MemberData(nameof(Samples))]
    public void FromBytesThenToBytes_RoundTripsThroughTheCanonicalEncoding(string hex)
    {
        byte[] source = Convert.FromHexString(hex);

        Span<byte> encoded = stackalloc byte[FieldElement.SizeInBytes];
        FieldElement.FromBytes(source).ToBytes(encoded);

        Assert.Equal(Reduce(source), ToBigInteger(encoded));
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Multiply_AgainstBigInteger_MatchesForEverySamplePair(string hex)
    {
        BigInteger left = Reduce(Convert.FromHexString(hex));
        FieldElement leftElement = FieldElement.FromBytes(Convert.FromHexString(hex));

        foreach (string otherHex in SampleValues)
        {
            BigInteger right = Reduce(Convert.FromHexString(otherHex));
            FieldElement rightElement = FieldElement.FromBytes(Convert.FromHexString(otherHex));

            Assert.Equal(left * right % Prime, Evaluate(leftElement * rightElement));
            Assert.Equal((left + right) % Prime, Evaluate(leftElement + rightElement));
            Assert.Equal(Modulo(left - right), Evaluate(leftElement - rightElement));
        }

        Assert.Equal(left * left % Prime, Evaluate(leftElement.Square()));
        Assert.Equal(left * 121666 % Prime, Evaluate(leftElement.MultiplyBy121666()));
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Invert_MultipliedByTheOriginal_YieldsOne(string hex)
    {
        FieldElement value = FieldElement.FromBytes(Convert.FromHexString(hex));

        if (Reduce(Convert.FromHexString(hex)).IsZero)
        {
            // Zero has no inverse; the exponentiation yields zero, which is the documented
            // behaviour of the ref10 chain and is what the ladder relies on.
            Assert.Equal(BigInteger.Zero, Evaluate(value.Invert()));
            return;
        }

        Assert.Equal(BigInteger.One, Evaluate(value * value.Invert()));
    }

    [Fact]
    public void Multiply_ChainedWithoutIntermediateReduction_StaysCorrect()
    {
        // Limbs are only weakly reduced between operations. This reproduces the pattern the
        // Montgomery ladder actually uses — a single addition feeding a multiplication —
        // for long enough that an under-sized carry chain would drift away from the
        // reference. Chaining two additions is outside the documented input bound and is
        // deliberately not tested.
        byte[] seed = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        FieldElement accumulator = FieldElement.FromBytes(seed);
        FieldElement addend = FieldElement.FromBytes(Convert.FromHexString(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"));

        BigInteger expected = Reduce(seed);
        BigInteger expectedAddend = Reduce(Convert.FromHexString(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"));

        for (int i = 0; i < 256; i++)
        {
            accumulator = (accumulator + addend).Square();
            expected = BigInteger.ModPow(expected + expectedAddend, 2, Prime);
        }

        Assert.Equal(expected, Evaluate(accumulator));
    }

    [Fact]
    public void ConditionalSwap_WithOne_SwapsAndWithZeroLeavesAlone()
    {
        FieldElement a = FieldElement.FromBytes(Convert.FromHexString(
            "0900000000000000000000000000000000000000000000000000000000000000"));
        FieldElement b = FieldElement.One;

        FieldElement originalA = a;
        FieldElement originalB = b;

        FieldElement.ConditionalSwap(ref a, ref b, 0);
        Assert.Equal(Evaluate(originalA), Evaluate(a));
        Assert.Equal(Evaluate(originalB), Evaluate(b));

        FieldElement.ConditionalSwap(ref a, ref b, 1);
        Assert.Equal(Evaluate(originalB), Evaluate(a));
        Assert.Equal(Evaluate(originalA), Evaluate(b));
    }

    [Fact]
    public void IsZero_DistinguishesZeroFromTheCanonicalFormOfP()
    {
        Assert.Equal(1u, FieldElement.Zero.IsZero());
        Assert.Equal(0u, FieldElement.One.IsZero());

        // p itself must encode as zero, since it is congruent to zero.
        byte[] p = Convert.FromHexString("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        Assert.Equal(1u, FieldElement.FromBytes(p).IsZero());
    }

    private static BigInteger Evaluate(FieldElement value)
    {
        Span<byte> encoded = stackalloc byte[FieldElement.SizeInBytes];
        value.ToBytes(encoded);
        return ToBigInteger(encoded);
    }

    private static BigInteger Reduce(ReadOnlySpan<byte> littleEndian)
    {
        // FromBytes ignores bit 255, so the reference must too.
        Span<byte> masked = stackalloc byte[FieldElement.SizeInBytes];
        littleEndian[..FieldElement.SizeInBytes].CopyTo(masked);
        masked[31] &= 0x7F;

        return ToBigInteger(masked) % Prime;
    }

    private static BigInteger ToBigInteger(ReadOnlySpan<byte> littleEndian)
        => new(littleEndian, isUnsigned: true, isBigEndian: false);

    private static BigInteger Modulo(BigInteger value)
    {
        BigInteger result = value % Prime;
        return result.Sign < 0 ? result + Prime : result;
    }
}
