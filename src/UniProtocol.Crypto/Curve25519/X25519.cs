using System.Security.Cryptography;

namespace UniProtocol.Crypto.Curve25519;

/// <summary>
/// The X25519 Diffie-Hellman function (RFC 7748).
/// </summary>
/// <remarks>
/// This is the key agreement underpinning every UniProtocol handshake: the Noise_IK
/// pattern performs three X25519 operations, and the disco path-probing keys use a
/// fourth. .NET has no X25519 in the base class library, so it is implemented here.
/// </remarks>
public static class X25519
{
    /// <summary>Private and public key size in bytes.</summary>
    public const int KeySizeInBytes = 32;

    /// <summary>Shared secret size in bytes.</summary>
    public const int SharedSecretSizeInBytes = 32;

    /// <summary>The u-coordinate of the standard base point, i.e. 9.</summary>
    private static ReadOnlySpan<byte> BasePoint =>
    [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// <summary>
    /// Derives the public key for <paramref name="privateKey"/>.
    /// </summary>
    public static void GetPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
        => ScalarMultiply(privateKey, BasePoint, publicKey);

    /// <summary>
    /// Computes the X25519 shared secret between <paramref name="privateKey"/> and
    /// <paramref name="peerPublicKey"/>.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> if the result is the all-zero value, which happens exactly
    /// when the peer supplied a low-order point; otherwise <see langword="true"/>.
    /// </returns>
    /// <remarks>
    /// RFC 7748 section 6.1 requires callers that cannot tolerate a degenerate shared
    /// secret to check for the all-zero output, and Noise requires it — a peer that sends a
    /// low-order point would otherwise force a shared secret it knows in advance,
    /// defeating authentication. The check is reported as a return value so the caller can
    /// abandon the handshake, and the output is still written (as zeros) so timing does not
    /// depend on the result.
    /// </remarks>
    public static bool TryAgree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        ScalarMultiply(privateKey, peerPublicKey, sharedSecret);

        Span<byte> zero = stackalloc byte[SharedSecretSizeInBytes];
        zero.Clear();

        return !CryptographicOperations.FixedTimeEquals(sharedSecret[..SharedSecretSizeInBytes], zero);
    }

    /// <summary>
    /// Clamps a 32-byte value into a valid X25519 scalar, in place.
    /// </summary>
    /// <remarks>
    /// Clearing the three low bits forces the scalar into the prime-order subgroup, which
    /// neutralises small-subgroup attacks; setting bit 254 and clearing bit 255 fixes the
    /// scalar's bit length so the ladder always runs the same number of iterations.
    /// </remarks>
    public static void ClampScalar(Span<byte> scalar)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(scalar.Length, KeySizeInBytes);

        scalar[0] &= 0xF8;
        scalar[31] &= 0x7F;
        scalar[31] |= 0x40;
    }

    /// <summary>
    /// Multiplies the Montgomery u-coordinate <paramref name="uCoordinate"/> by
    /// <paramref name="scalar"/>.
    /// </summary>
    /// <remarks>
    /// The Montgomery ladder processes all 255 scalar bits unconditionally and swaps the
    /// two working points with an arithmetic mask, so its running time and memory access
    /// pattern are independent of the secret scalar.
    /// </remarks>
    public static void ScalarMultiply(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(scalar.Length, KeySizeInBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(uCoordinate.Length, KeySizeInBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, KeySizeInBytes);

        Span<byte> clamped = stackalloc byte[KeySizeInBytes];
        scalar[..KeySizeInBytes].CopyTo(clamped);
        ClampScalar(clamped);

        FieldElement u = FieldElement.FromBytes(uCoordinate);

        FieldElement x1 = u;
        FieldElement x2 = FieldElement.One;
        FieldElement z2 = FieldElement.Zero;
        FieldElement x3 = u;
        FieldElement z3 = FieldElement.One;

        uint previousBit = 0;

        for (int position = 254; position >= 0; position--)
        {
            uint bit = (uint)((clamped[position >> 3] >> (position & 7)) & 1);

            uint swap = bit ^ previousBit;
            previousBit = bit;

            FieldElement.ConditionalSwap(ref x2, ref x3, swap);
            FieldElement.ConditionalSwap(ref z2, ref z3, swap);

            // RFC 7748 section 5, the standard differential addition-and-doubling step.
            FieldElement a = x2 + z2;
            FieldElement aa = a.Square();
            FieldElement b = x2 - z2;
            FieldElement bb = b.Square();
            FieldElement e = aa - bb;
            FieldElement c = x3 + z3;
            FieldElement d = x3 - z3;
            FieldElement da = d * a;
            FieldElement cb = c * b;

            x3 = (da + cb).Square();
            z3 = x1 * (da - cb).Square();
            x2 = aa * bb;

            // RFC 7748 writes this as E * (AA + a24 * E) with a24 = 121665. Since
            // AA = BB + E, that is identical to E * (BB + 121666 * E), and 121666 is the
            // form every reference implementation multiplies by. Mixing the two up —
            // AA with 121666 — still produces a self-consistent ladder that agrees with
            // itself but disagrees with the standard, so it is caught only by test vectors.
            z2 = e * (bb + e.MultiplyBy121666());
        }

        FieldElement.ConditionalSwap(ref x2, ref x3, previousBit);
        FieldElement.ConditionalSwap(ref z2, ref z3, previousBit);

        (x2 * z2.Invert()).ToBytes(destination);

        CryptographicOperations.ZeroMemory(clamped);
    }
}
