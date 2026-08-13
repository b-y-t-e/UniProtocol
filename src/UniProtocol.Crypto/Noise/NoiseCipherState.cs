using System.Buffers.Binary;
using System.Security.Cryptography;
using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// A Noise <c>CipherState</c>: a key plus the sequential nonce counter that goes with it
/// (Noise Protocol Framework section 5.1).
/// </summary>
/// <remarks>
/// This type exists only to serve the handshake. Once the handshake completes, the
/// transport takes the split keys and drives its own nonces from packet numbers, because
/// a datagram protocol cannot use a strictly sequential counter that assumes in-order,
/// lossless delivery.
/// </remarks>
internal sealed class NoiseCipherState : IDisposable
{
    /// <summary>
    /// The nonce value reserved by Noise; reaching it means the key is exhausted.
    /// </summary>
    private const ulong ReservedNonce = ulong.MaxValue;

    private readonly IAeadAlgorithm _algorithm;
    private IAeadCipher? _cipher;
    private byte[]? _key;
    private ulong _nonce;

    public NoiseCipherState(IAeadAlgorithm algorithm)
    {
        _algorithm = algorithm;
    }

    /// <summary>Indicates whether a key has been installed.</summary>
    public bool HasKey => _cipher is not null;

    /// <summary>Size in bytes that encryption adds to a plaintext.</summary>
    public int TagSizeInBytes => _algorithm.TagSizeInBytes;

    /// <summary>Installs a key and resets the nonce, per Noise <c>InitializeKey</c>.</summary>
    public void InitializeKey(ReadOnlySpan<byte> key)
    {
        _cipher?.Dispose();
        _cipher = _algorithm.CreateCipher(key);

        // Kept so the state can be restored after a message that turns out to be forged.
        // The cipher holds these bytes already; this copy adds no exposure.
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
        }

        _key = key.ToArray();
        _nonce = 0;
    }

    /// <summary>Copies this state so it can be put back with <see cref="Restore"/>.</summary>
    public (byte[]? Key, ulong Nonce) Capture() => (_key?.AsSpan().ToArray(), _nonce);

    /// <summary>Puts back a state previously taken by <see cref="Capture"/>.</summary>
    public void Restore((byte[]? Key, ulong Nonce) state)
    {
        if (state.Key is null)
        {
            _cipher?.Dispose();
            _cipher = null;

            if (_key is not null)
            {
                CryptographicOperations.ZeroMemory(_key);
                _key = null;
            }
        }
        else
        {
            InitializeKey(state.Key);
        }

        _nonce = state.Nonce;
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with <paramref name="associatedData"/>,
    /// returning the number of bytes written.
    /// </summary>
    /// <remarks>
    /// With no key installed this is the identity function, which is what lets the early
    /// messages of a handshake carry plaintext through the same code path.
    /// </remarks>
    public int EncryptWithAssociatedData(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        if (_cipher is null)
        {
            plaintext.CopyTo(destination);
            return plaintext.Length;
        }

        Span<byte> nonce = stackalloc byte[_algorithm.NonceSizeInBytes];
        WriteNonce(nonce);

        _cipher.Encrypt(
            nonce,
            plaintext,
            associatedData,
            destination[..plaintext.Length],
            destination.Slice(plaintext.Length, _algorithm.TagSizeInBytes));

        AdvanceNonce();

        return plaintext.Length + _algorithm.TagSizeInBytes;
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> with <paramref name="associatedData"/>.
    /// </summary>
    /// <returns><see langword="false"/> when authentication fails.</returns>
    public bool TryDecryptWithAssociatedData(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        out int plaintextLength)
    {
        if (_cipher is null)
        {
            ciphertext.CopyTo(destination);
            plaintextLength = ciphertext.Length;
            return true;
        }

        if (ciphertext.Length < _algorithm.TagSizeInBytes)
        {
            plaintextLength = 0;
            return false;
        }

        plaintextLength = ciphertext.Length - _algorithm.TagSizeInBytes;

        Span<byte> nonce = stackalloc byte[_algorithm.NonceSizeInBytes];
        WriteNonce(nonce);

        bool isAuthentic = _cipher.TryDecrypt(
            nonce,
            ciphertext[..plaintextLength],
            ciphertext[plaintextLength..],
            associatedData,
            destination[..plaintextLength]);

        if (!isAuthentic)
        {
            plaintextLength = 0;
            return false;
        }

        AdvanceNonce();
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cipher?.Dispose();
        _cipher = null;

        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }

    /// <summary>
    /// Encodes the counter as Noise specifies for ChaCha20-Poly1305: four zero bytes
    /// followed by the 64-bit counter in little-endian order.
    /// </summary>
    private void WriteNonce(Span<byte> destination)
    {
        destination[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(destination[4..], _nonce);
    }

    private void AdvanceNonce()
    {
        if (_nonce == ReservedNonce - 1)
        {
            throw new CryptographicException("The Noise cipher state has exhausted its nonce space.");
        }

        _nonce++;
    }
}
