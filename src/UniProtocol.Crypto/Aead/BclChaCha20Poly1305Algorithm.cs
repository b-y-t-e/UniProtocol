using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// ChaCha20-Poly1305 backed by the platform implementation in
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>.
/// </summary>
/// <remarks>
/// <para>
/// Behaviourally identical to <see cref="ChaCha20Poly1305Algorithm"/> — both implement
/// RFC 8439, so they are interchangeable at every call site and are validated against the
/// same test vectors. This one exists purely as a throughput option where the OS crypto
/// library provides an optimised implementation.
/// </para>
/// <para>
/// It is not the default: <see cref="IsSupported"/> is false on some target platforms,
/// and a transport whose cipher availability varies by platform is a support problem
/// waiting to happen. Selecting it is a deliberate, benchmarked decision.
/// </para>
/// </remarks>
public sealed class BclChaCha20Poly1305Algorithm : IAeadAlgorithm
{
    /// <summary>The shared instance; the algorithm itself holds no state.</summary>
    public static BclChaCha20Poly1305Algorithm Instance { get; } = new();

    private BclChaCha20Poly1305Algorithm()
    {
    }

    /// <summary>
    /// Indicates whether the current platform provides ChaCha20-Poly1305.
    /// </summary>
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    /// <inheritdoc />
    public int KeySizeInBytes => ChaCha20.KeySizeInBytes;

    /// <inheritdoc />
    public int NonceSizeInBytes => ChaCha20.NonceSizeInBytes;

    /// <inheritdoc />
    public int TagSizeInBytes => Poly1305.TagSizeInBytes;

    /// <inheritdoc />
    public string Name => "ChaChaPoly";

    /// <inheritdoc />
    [UnsupportedOSPlatformGuard("browser")]
    public IAeadCipher CreateCipher(ReadOnlySpan<byte> key)
    {
        if (!ChaCha20Poly1305.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "The platform does not provide ChaCha20-Poly1305. Use ChaCha20Poly1305Algorithm.Instance instead.");
        }

        return new BclCipher(this, key);
    }

    private sealed class BclCipher : IAeadCipher
    {
        private readonly ChaCha20Poly1305 _cipher;

        internal BclCipher(IAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
        {
            Algorithm = algorithm;
            _cipher = new ChaCha20Poly1305(key);
        }

        public IAeadAlgorithm Algorithm { get; }

        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            _cipher.Encrypt(nonce, plaintext, ciphertext[..plaintext.Length], tag[..Poly1305.TagSizeInBytes], associatedData);
        }

        public bool TryDecrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext)
        {
            // Checked here rather than left to the platform, which throws an exception type
            // of its own choosing. Same rule as the managed cipher: a wrong-length nonce or
            // tag is a failed decrypt, not something for a receive loop to catch.
            if (nonce.Length != ChaCha20.NonceSizeInBytes || tag.Length != Poly1305.TagSizeInBytes)
            {
                CryptographicOperations.ZeroMemory(plaintext[..ciphertext.Length]);
                return false;
            }

            try
            {
                _cipher.Decrypt(nonce, ciphertext, tag, plaintext[..ciphertext.Length], associatedData);
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Contract of IAeadCipher: a bad tag is a return value, not an exception, and
                // the destination is left zeroed. The platform implementation already clears
                // it before throwing; doing it again here costs one pass over a buffer that
                // has just been rejected and means the guarantee does not depend on an
                // implementation detail of whichever OS crypto library is underneath.
                CryptographicOperations.ZeroMemory(plaintext[..ciphertext.Length]);
                return false;
            }
        }

        public void Dispose() => _cipher.Dispose();
    }
}
