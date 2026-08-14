using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// XChaCha20-Poly1305: ChaCha20-Poly1305 with a 192-bit nonce, derived via HChaCha20.
/// </summary>
/// <remarks>
/// UniProtocol uses this for messages whose nonce cannot be a reliable counter. The disco
/// path-probing packets are the motivating case: they are sealed under a key shared by two
/// disco keys, sent from several sockets, and may be retried, so a random nonce is the only
/// safe choice — and a random 96-bit nonce collides far too soon to be acceptable.
/// Session data packets do have a counter and use plain
/// <see cref="ChaCha20Poly1305Algorithm"/> instead.
/// </remarks>
public sealed class XChaCha20Poly1305Algorithm : IAeadAlgorithm
{
    /// <summary>Nonce size in bytes.</summary>
    public const int ExtendedNonceSizeInBytes = 24;

    /// <summary>The shared instance; the algorithm itself holds no state.</summary>
    public static XChaCha20Poly1305Algorithm Instance { get; } = new();

    private XChaCha20Poly1305Algorithm()
    {
    }

    /// <inheritdoc />
    public int KeySizeInBytes => ChaCha20.KeySizeInBytes;

    /// <inheritdoc />
    public int NonceSizeInBytes => ExtendedNonceSizeInBytes;

    /// <inheritdoc />
    public int TagSizeInBytes => Poly1305.TagSizeInBytes;

    /// <inheritdoc />
    public string Name => "XChaChaPoly";

    /// <inheritdoc />
    public IAeadCipher CreateCipher(ReadOnlySpan<byte> key) => new XChaCha20Poly1305Cipher(this, key);

    private sealed class XChaCha20Poly1305Cipher : IAeadCipher
    {
        private readonly byte[] _key;
        private bool _isDisposed;

        internal XChaCha20Poly1305Cipher(IAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, ChaCha20.KeySizeInBytes);

            Algorithm = algorithm;
            _key = key.ToArray();
        }

        public IAeadAlgorithm Algorithm { get; }

        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            Span<byte> subkey = stackalloc byte[HChaCha20.SubkeySizeInBytes];
            Span<byte> innerNonce = stackalloc byte[ChaCha20.NonceSizeInBytes];
            DeriveInnerParameters(_key, nonce, subkey, innerNonce);

            using IAeadCipher inner = ChaCha20Poly1305Algorithm.Instance.CreateCipher(subkey);
            inner.Encrypt(innerNonce, plaintext, associatedData, ciphertext, tag);

            CryptographicOperations.ZeroMemory(subkey);
        }

        public bool TryDecrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            if (nonce.Length != ExtendedNonceSizeInBytes)
            {
                // Every path that returns false leaves the destination zeroed, including the
                // ones that reject before any cryptography happens. A caller that has to
                // remember which kind of failure it got has no contract at all.
                CryptographicOperations.ZeroMemory(plaintext[..ciphertext.Length]);
                return false;
            }

            Span<byte> subkey = stackalloc byte[HChaCha20.SubkeySizeInBytes];
            Span<byte> innerNonce = stackalloc byte[ChaCha20.NonceSizeInBytes];
            DeriveInnerParameters(_key, nonce, subkey, innerNonce);

            using IAeadCipher inner = ChaCha20Poly1305Algorithm.Instance.CreateCipher(subkey);
            bool isAuthentic = inner.TryDecrypt(innerNonce, ciphertext, tag, associatedData, plaintext);

            CryptographicOperations.ZeroMemory(subkey);

            return isAuthentic;
        }

        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(_key);
            _isDisposed = true;
        }

        /// <summary>
        /// Splits the 24-byte nonce into the HChaCha20 input and the inner ChaCha20 nonce.
        /// </summary>
        private static void DeriveInnerParameters(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            Span<byte> subkey,
            Span<byte> innerNonce)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, ExtendedNonceSizeInBytes);

            HChaCha20.DeriveSubkey(key, nonce[..HChaCha20.NonceSizeInBytes], subkey);

            // The inner 96-bit nonce is four zero bytes followed by the remaining eight
            // bytes of the extended nonce (the libsodium/draft-irtf-cfrg-xchacha layout).
            innerNonce[..4].Clear();
            nonce[HChaCha20.NonceSizeInBytes..].CopyTo(innerNonce[4..]);
        }
    }
}
