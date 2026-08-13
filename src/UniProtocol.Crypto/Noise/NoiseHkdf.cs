using UniProtocol.Crypto.Hashing;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// The HKDF construction specified by the Noise Protocol Framework (section 4.3).
/// </summary>
/// <remarks>
/// Noise defines its own two- and three-output HKDF rather than referencing RFC 5869
/// directly. The difference is deliberate and load-bearing: each output is chained into
/// the next HMAC input, so an implementation that substitutes plain RFC 5869 expansion
/// produces a different key schedule and will not interoperate.
/// </remarks>
internal static class NoiseHkdf
{
    /// <summary>Length of each HKDF output in bytes.</summary>
    public const int OutputSizeInBytes = HmacBlake2s.HashSizeInBytes;

    /// <summary>Derives two outputs from a chaining key and input key material.</summary>
    public static void DeriveTwo(
        ReadOnlySpan<byte> chainingKey,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> output1,
        Span<byte> output2)
    {
        Span<byte> temporaryKey = stackalloc byte[OutputSizeInBytes];
        HmacBlake2s.ComputeHash(chainingKey, inputKeyMaterial, temporaryKey);

        HmacBlake2s.ComputeHash(temporaryKey, [0x01], output1);
        HmacBlake2s.ComputeHash(temporaryKey, output1[..OutputSizeInBytes], [0x02], output2);

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(temporaryKey);
    }

    /// <summary>Derives three outputs from a chaining key and input key material.</summary>
    public static void DeriveThree(
        ReadOnlySpan<byte> chainingKey,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> output1,
        Span<byte> output2,
        Span<byte> output3)
    {
        Span<byte> temporaryKey = stackalloc byte[OutputSizeInBytes];
        HmacBlake2s.ComputeHash(chainingKey, inputKeyMaterial, temporaryKey);

        HmacBlake2s.ComputeHash(temporaryKey, [0x01], output1);
        HmacBlake2s.ComputeHash(temporaryKey, output1[..OutputSizeInBytes], [0x02], output2);
        HmacBlake2s.ComputeHash(temporaryKey, output2[..OutputSizeInBytes], [0x03], output3);

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(temporaryKey);
    }
}
