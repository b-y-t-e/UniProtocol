using System.Security.Cryptography;

namespace UniProtocol.Crypto.Curve25519;

/// <summary>
/// Ed25519 signatures (RFC 8032, PureEdDSA over edwards25519).
/// </summary>
/// <remarks>
/// A UniProtocol node identity is an Ed25519 public key, so this type defines what a
/// NodeId <em>is</em>. Signed node records are verified with it, and the same 32-byte seed
/// also produces the X25519 static key used by the Noise handshake — see
/// <see cref="TryConvertPublicKeyToX25519"/> and <see cref="ConvertPrivateKeyToX25519"/>.
/// </remarks>
public static class Ed25519
{
    /// <summary>Size of the private key seed in bytes.</summary>
    public const int SeedSizeInBytes = 32;

    /// <summary>Size of a public key in bytes.</summary>
    public const int PublicKeySizeInBytes = 32;

    /// <summary>Size of a signature in bytes.</summary>
    public const int SignatureSizeInBytes = 64;

    /// <summary>Derives the public key for <paramref name="seed"/>.</summary>
    public static void GetPublicKey(ReadOnlySpan<byte> seed, Span<byte> publicKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySizeInBytes);

        Span<byte> scalar = stackalloc byte[SeedSizeInBytes];
        Span<byte> prefix = stackalloc byte[SeedSizeInBytes];
        ExpandSeed(seed, scalar, prefix);

        EdwardsPoint.BasePoint.Multiply(scalar).Encode(publicKey);

        CryptographicOperations.ZeroMemory(scalar);
        CryptographicOperations.ZeroMemory(prefix);
    }

    /// <summary>Signs <paramref name="message"/> with <paramref name="seed"/>.</summary>
    public static void Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, Span<byte> signature)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSizeInBytes);

        Span<byte> scalarBytes = stackalloc byte[SeedSizeInBytes];
        Span<byte> prefix = stackalloc byte[SeedSizeInBytes];
        ExpandSeed(seed, scalarBytes, prefix);

        Span<byte> publicKey = stackalloc byte[PublicKeySizeInBytes];
        EdwardsPoint.BasePoint.Multiply(scalarBytes).Encode(publicKey);

        // r = H(prefix ‖ M). Deriving the nonce from the key and the message rather than
        // from a random source is what makes EdDSA immune to the catastrophic
        // nonce-reuse failures that plague ECDSA.
        Span<byte> wide = stackalloc byte[SHA512.HashSizeInBytes];
        HashConcatenated(prefix, default, message, wide);
        Scalar r = Scalar.FromBytesModOrder(wide);

        Span<byte> rBytes = stackalloc byte[Scalar.SizeInBytes];
        r.ToBytes(rBytes);

        Span<byte> commitment = signature[..32];
        EdwardsPoint.BasePoint.Multiply(rBytes).Encode(commitment);

        // k = H(R ‖ A ‖ M)
        HashConcatenated(commitment, publicKey, message, wide);
        Scalar k = Scalar.FromBytesModOrder(wide);

        // S = (r + k * a) mod L
        Scalar a = Scalar.FromBytesModOrder(scalarBytes);
        Scalar.MultiplyAdd(k, a, r).ToBytes(signature[32..64]);

        CryptographicOperations.ZeroMemory(scalarBytes);
        CryptographicOperations.ZeroMemory(prefix);
        CryptographicOperations.ZeroMemory(rBytes);
        CryptographicOperations.ZeroMemory(wide);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="message"/> under
    /// <paramref name="publicKey"/>.
    /// </summary>
    /// <remarks>
    /// Everything involved is public, so this does not need to be constant time; it
    /// nevertheless reuses the same constant-time scalar multiplication rather than
    /// maintaining a second, faster code path that could disagree with it.
    /// </remarks>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length < PublicKeySizeInBytes || signature.Length < SignatureSizeInBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> commitment = signature[..32];

        // S must be canonical. Accepting S >= L would make signatures malleable: both S
        // and S + L would verify, so a signature would not uniquely identify a message.
        if (!Scalar.TryFromCanonicalBytes(signature[32..64], out Scalar s))
        {
            return false;
        }

        if (!EdwardsPoint.TryDecode(commitment, out EdwardsPoint r)
            || !EdwardsPoint.TryDecode(publicKey, out EdwardsPoint a))
        {
            return false;
        }

        Span<byte> wide = stackalloc byte[SHA512.HashSizeInBytes];
        HashConcatenated(commitment, publicKey, message, wide);
        Scalar k = Scalar.FromBytesModOrder(wide);

        Span<byte> scalarBytes = stackalloc byte[Scalar.SizeInBytes];

        s.ToBytes(scalarBytes);
        EdwardsPoint left = EdwardsPoint.BasePoint.Multiply(scalarBytes);

        k.ToBytes(scalarBytes);
        EdwardsPoint right = r + a.Multiply(scalarBytes);

        Span<byte> leftEncoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        Span<byte> rightEncoded = stackalloc byte[EdwardsPoint.SizeInBytes];
        left.Encode(leftEncoded);
        right.Encode(rightEncoded);

        return CryptographicOperations.FixedTimeEquals(leftEncoded, rightEncoded);
    }

    /// <summary>
    /// Converts an Ed25519 public key to the equivalent X25519 public key.
    /// </summary>
    /// <returns><see langword="false"/> when the input is not a valid Ed25519 point.</returns>
    /// <remarks>
    /// The two curves are birationally equivalent, with <c>u = (1 + y) / (1 - y)</c>. This
    /// is what allows a UniProtocol NodeId — an Ed25519 key — to be dialled directly:
    /// the initiator derives the responder's Noise static key from the NodeId alone, with
    /// no extra key to distribute and no second identity to keep in sync.
    /// </remarks>
    public static bool TryConvertPublicKeyToX25519(ReadOnlySpan<byte> publicKey, Span<byte> x25519PublicKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(x25519PublicKey.Length, X25519.KeySizeInBytes);

        if (!EdwardsPoint.TryDecode(publicKey, out EdwardsPoint point))
        {
            return false;
        }

        FieldElement y = point.GetAffineY();
        FieldElement denominator = FieldElement.One - y;

        // y == 1 is the identity, whose Montgomery image is the point at infinity.
        if (denominator.IsZero() == 1)
        {
            return false;
        }

        ((FieldElement.One + y) * denominator.Invert()).ToBytes(x25519PublicKey);
        return true;
    }

    /// <summary>
    /// Derives the X25519 private key that corresponds to an Ed25519 seed.
    /// </summary>
    public static void ConvertPrivateKeyToX25519(ReadOnlySpan<byte> seed, Span<byte> x25519PrivateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(x25519PrivateKey.Length, X25519.KeySizeInBytes);

        Span<byte> prefix = stackalloc byte[SeedSizeInBytes];
        ExpandSeed(seed, x25519PrivateKey[..SeedSizeInBytes], prefix);

        CryptographicOperations.ZeroMemory(prefix);
    }

    /// <summary>
    /// Expands the seed into the clamped scalar and the nonce prefix (RFC 8032 section 5.1.5).
    /// </summary>
    private static void ExpandSeed(ReadOnlySpan<byte> seed, Span<byte> scalar, Span<byte> prefix)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(seed.Length, SeedSizeInBytes);

        Span<byte> expanded = stackalloc byte[SHA512.HashSizeInBytes];
        SHA512.HashData(seed[..SeedSizeInBytes], expanded);

        expanded[..32].CopyTo(scalar);
        expanded[32..].CopyTo(prefix);

        X25519.ClampScalar(scalar);

        CryptographicOperations.ZeroMemory(expanded);
    }

    private static void HashConcatenated(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        ReadOnlySpan<byte> third,
        Span<byte> destination)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);

        hash.AppendData(first);
        hash.AppendData(second);
        hash.AppendData(third);
        hash.GetHashAndReset(destination);
    }
}
