using System.Security.Cryptography;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Randomness;

namespace UniProtocol.Protocol.Identity;

/// <summary>
/// A node's long-term identity: one 32-byte seed, from which both the Ed25519 signing key
/// and the X25519 Noise static key are derived.
/// </summary>
/// <remarks>
/// One seed rather than two keys is a deliberate simplification with a real payoff: a peer
/// that knows only the <see cref="NodeId"/> can derive the Noise static public key it
/// needs to open an authenticated connection, so there is nothing else to publish,
/// distribute or keep in sync — and no way for the two halves of an identity to drift
/// apart.
/// </remarks>
public sealed class UniIdentity : IDisposable
{
    /// <summary>Size of the identity seed in bytes.</summary>
    public const int SeedSizeInBytes = Ed25519.SeedSizeInBytes;

    private readonly byte[] _seed;
    private readonly byte[] _noiseStaticPrivateKey;
    private bool _isDisposed;

    private UniIdentity(ReadOnlySpan<byte> seed)
    {
        _seed = seed.ToArray();

        Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySizeInBytes];
        Ed25519.GetPublicKey(_seed, publicKey);
        NodeId = NodeId.FromPublicKey(publicKey);

        _noiseStaticPrivateKey = new byte[X25519.KeySizeInBytes];
        Ed25519.ConvertPrivateKeyToX25519(_seed, _noiseStaticPrivateKey);
    }

    /// <summary>This node's identity.</summary>
    public NodeId NodeId { get; }

    /// <summary>Creates a new identity from <paramref name="randomSource"/>.</summary>
    public static UniIdentity Generate(IRandomSource? randomSource = null)
    {
        randomSource ??= SecureRandomSource.Instance;

        Span<byte> seed = stackalloc byte[SeedSizeInBytes];
        randomSource.Fill(seed);

        UniIdentity identity = new(seed);

        CryptographicOperations.ZeroMemory(seed);
        return identity;
    }

    /// <summary>Restores an identity from a previously exported seed.</summary>
    public static UniIdentity FromSeed(ReadOnlySpan<byte> seed)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(seed.Length, SeedSizeInBytes);

        return new UniIdentity(seed);
    }

    /// <summary>
    /// The X25519 private key used as the Noise static key.
    /// </summary>
    public ReadOnlySpan<byte> NoiseStaticPrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _noiseStaticPrivateKey;
        }
    }

    /// <summary>Signs <paramref name="message"/> with this identity.</summary>
    public void Sign(ReadOnlySpan<byte> message, Span<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        Ed25519.Sign(_seed, message, signature);
    }

    /// <summary>
    /// Copies the seed out, for persistence.
    /// </summary>
    /// <remarks>
    /// The seed is the entire secret: anyone holding it is this node. Callers are
    /// responsible for clearing the destination once it has been written to storage.
    /// </remarks>
    public void ExportSeed(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SeedSizeInBytes);

        _seed.CopyTo(destination);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_seed);
        CryptographicOperations.ZeroMemory(_noiseStaticPrivateKey);
        _isDisposed = true;
    }
}
