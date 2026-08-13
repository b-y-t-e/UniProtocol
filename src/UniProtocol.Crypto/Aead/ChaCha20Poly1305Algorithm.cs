using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace UniProtocol.Crypto.Aead;

/// <summary>
/// ChaCha20-Poly1305 AEAD (RFC 8439), implemented in managed code.
/// </summary>
/// <remarks>
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> is not available on every
/// platform UniProtocol targets — <c>IsSupported</c> depends on the OS crypto library —
/// so the managed implementation is the one that always exists and defines the wire
/// behaviour. <see cref="BclChaCha20Poly1305Algorithm"/> is a drop-in replacement where
/// the platform does offer it.
/// </remarks>
public sealed class ChaCha20Poly1305Algorithm : IAeadAlgorithm
{
    /// <summary>The shared instance; the algorithm itself holds no state.</summary>
    public static ChaCha20Poly1305Algorithm Instance { get; } = new();

    private ChaCha20Poly1305Algorithm()
    {
    }

    /// <inheritdoc />
    public int KeySizeInBytes => ChaCha20.KeySizeInBytes;

    /// <inheritdoc />
    public int NonceSizeInBytes => ChaCha20.NonceSizeInBytes;

    /// <inheritdoc />
    public int TagSizeInBytes => Poly1305.TagSizeInBytes;

    /// <inheritdoc />
    public string Name => "ChaChaPoly";

    /// <inheritdoc />
    public IAeadCipher CreateCipher(ReadOnlySpan<byte> key) => new ChaCha20Poly1305Cipher(this, key);

    private sealed class ChaCha20Poly1305Cipher : IAeadCipher
    {
        private readonly byte[] _key;
        private bool _isDisposed;

        internal ChaCha20Poly1305Cipher(IAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
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
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, ChaCha20.NonceSizeInBytes);
            ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, plaintext.Length);
            ArgumentOutOfRangeException.ThrowIfLessThan(tag.Length, Poly1305.TagSizeInBytes);

            // Block 0 of the keystream is reserved for the Poly1305 one-time key, so the
            // message itself starts at block 1 (RFC 8439 section 2.8).
            Span<byte> oneTimeKey = stackalloc byte[ChaCha20.BlockSizeInBytes];
            ChaCha20.GenerateKeyStreamBlock(_key, nonce, counter: 0, oneTimeKey);

            ChaCha20.Transform(_key, nonce, initialCounter: 1, plaintext, ciphertext);

            ComputeTag(oneTimeKey[..Poly1305.KeySizeInBytes], associatedData, ciphertext[..plaintext.Length], tag);

            CryptographicOperations.ZeroMemory(oneTimeKey);
        }

        public bool TryDecrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, ChaCha20.NonceSizeInBytes);
            ArgumentOutOfRangeException.ThrowIfLessThan(plaintext.Length, ciphertext.Length);

            if (tag.Length != Poly1305.TagSizeInBytes)
            {
                return false;
            }

            Span<byte> oneTimeKey = stackalloc byte[ChaCha20.BlockSizeInBytes];
            ChaCha20.GenerateKeyStreamBlock(_key, nonce, counter: 0, oneTimeKey);

            Span<byte> expectedTag = stackalloc byte[Poly1305.TagSizeInBytes];
            ComputeTag(oneTimeKey[..Poly1305.KeySizeInBytes], associatedData, ciphertext, expectedTag);

            // Verify before decrypting: plaintext may alias ciphertext, and a forged
            // packet must never be allowed to overwrite the caller's buffer.
            bool isAuthentic = CryptographicOperations.FixedTimeEquals(expectedTag, tag);

            if (isAuthentic)
            {
                ChaCha20.Transform(_key, nonce, initialCounter: 1, ciphertext, plaintext);
            }

            CryptographicOperations.ZeroMemory(oneTimeKey);
            CryptographicOperations.ZeroMemory(expectedTag);

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
        /// Computes the Poly1305 tag over
        /// <c>AAD ‖ pad16 ‖ ciphertext ‖ pad16 ‖ len(AAD) ‖ len(ciphertext)</c>.
        /// </summary>
        /// <remarks>
        /// The zero padding and the explicit trailing lengths are what stop an attacker
        /// from moving bytes between the associated data and the ciphertext while keeping
        /// the same tag input.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ComputeTag(
            ReadOnlySpan<byte> oneTimeKey,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> tag)
        {
            Poly1305 mac = Poly1305.Create(oneTimeKey);

            mac.Update(associatedData);
            mac.PadToBlockBoundary();
            mac.Update(ciphertext);
            mac.PadToBlockBoundary();

            Span<byte> lengths = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)associatedData.Length);
            BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
            mac.Update(lengths);

            mac.Finish(tag);
        }
    }
}
