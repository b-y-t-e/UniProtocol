using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Randomness;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// Configuration for a Noise_IK handshake.
/// </summary>
public sealed record NoiseHandshakeOptions
{
    /// <summary>The local X25519 static private key (32 bytes).</summary>
    public required ReadOnlyMemory<byte> StaticPrivateKey { get; init; }

    /// <summary>
    /// Data both peers must agree on, bound into the transcript before any key exchange.
    /// </summary>
    /// <remarks>
    /// UniProtocol puts the protocol version and the application protocol identifier here.
    /// A mismatch makes the handshake fail rather than silently negotiating something
    /// neither side intended.
    /// </remarks>
    public ReadOnlyMemory<byte> Prologue { get; init; }

    /// <summary>The AEAD used for the handshake and named in the protocol string.</summary>
    public IAeadAlgorithm Algorithm { get; init; } = ChaCha20Poly1305Algorithm.Instance;

    /// <summary>Source of the ephemeral key. Substituted in tests to replay known vectors.</summary>
    public IRandomSource RandomSource { get; init; } = SecureRandomSource.Instance;
}
