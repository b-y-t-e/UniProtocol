using System.Security.Cryptography;
using System.Text;
using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Hashing;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// A Noise <c>SymmetricState</c>: the chaining key, the running transcript hash and the
/// current cipher state (Noise Protocol Framework section 5.2).
/// </summary>
/// <remarks>
/// The transcript hash <c>h</c> is mixed into every AEAD operation as associated data, so
/// each encrypted field is bound to every byte exchanged before it. That is what prevents
/// an attacker from reordering or splicing handshake messages.
/// </remarks>
internal sealed class NoiseSymmetricState : IDisposable
{
    private readonly byte[] _chainingKey = new byte[Blake2s.HashSizeInBytes];
    private readonly byte[] _hash = new byte[Blake2s.HashSizeInBytes];
    private readonly NoiseCipherState _cipherState;

    public NoiseSymmetricState(IAeadAlgorithm algorithm, string protocolName)
    {
        _cipherState = new NoiseCipherState(algorithm);

        // Noise section 5.2: a protocol name at most HASHLEN bytes long is used verbatim
        // and zero-padded; anything longer is hashed.
        int nameLength = Encoding.ASCII.GetByteCount(protocolName);
        if (nameLength <= Blake2s.HashSizeInBytes)
        {
            Encoding.ASCII.GetBytes(protocolName, _hash);
        }
        else
        {
            Span<byte> encoded = stackalloc byte[nameLength];
            Encoding.ASCII.GetBytes(protocolName, encoded);
            Blake2s.HashData(encoded, _hash);
        }

        _hash.CopyTo(_chainingKey.AsSpan());
    }

    /// <summary>The running transcript hash.</summary>
    public ReadOnlySpan<byte> Hash => _hash;

    /// <summary>
    /// Copies the whole symmetric state so a message that fails to authenticate can be
    /// undone.
    /// </summary>
    /// <remarks>
    /// Reading a handshake message mixes the peer's ephemeral key and the Diffie-Hellman
    /// results before it can know whether the message is genuine, and those mixes are
    /// destructive. Without the ability to put the state back, one forged packet from an
    /// on-path observer would permanently break a handshake that was otherwise going to
    /// succeed.
    /// </remarks>
    public Snapshot Capture() => new(_chainingKey, _hash, _cipherState.Capture());

    /// <summary>Puts back a state previously taken by <see cref="Capture"/>.</summary>
    public void Restore(Snapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        snapshot.ChainingKey.CopyTo(_chainingKey.AsSpan());
        snapshot.Hash.CopyTo(_hash.AsSpan());
        _cipherState.Restore(snapshot.CipherState);
    }

    /// <summary>Indicates whether the cipher state holds a key.</summary>
    public bool HasKey => _cipherState.HasKey;

    /// <summary>Size in bytes that encryption adds to a plaintext.</summary>
    public int TagSizeInBytes => _cipherState.HasKey ? _cipherState.TagSizeInBytes : 0;

    /// <summary>Mixes Diffie-Hellman output into the chaining key and rekeys the cipher.</summary>
    public void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
    {
        Span<byte> temporaryKey = stackalloc byte[NoiseHkdf.OutputSizeInBytes];
        NoiseHkdf.DeriveTwo(_chainingKey, inputKeyMaterial, _chainingKey, temporaryKey);

        _cipherState.InitializeKey(temporaryKey);

        CryptographicOperations.ZeroMemory(temporaryKey);
    }

    /// <summary>Absorbs <paramref name="data"/> into the transcript hash.</summary>
    public void MixHash(ReadOnlySpan<byte> data) => Blake2s.HashData(_hash, data, _hash);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> bound to the transcript, then absorbs the
    /// result into the transcript.
    /// </summary>
    public int EncryptAndHash(ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        int written = _cipherState.EncryptWithAssociatedData(_hash, plaintext, destination);
        MixHash(destination[..written]);
        return written;
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> bound to the transcript, then absorbs the
    /// ciphertext into the transcript.
    /// </summary>
    public bool TryDecryptAndHash(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int plaintextLength)
    {
        // The transcript is mixed only on success, preserving the invariant that h
        // reflects exactly the bytes both parties accepted. A failed decryption aborts the
        // handshake, so there is no state left to keep consistent.
        if (!_cipherState.TryDecryptWithAssociatedData(_hash, ciphertext, destination, out plaintextLength))
        {
            return false;
        }

        MixHash(ciphertext);
        return true;
    }

    /// <summary>
    /// Produces the two transport keys, per Noise <c>Split</c>.
    /// </summary>
    public NoiseSplitKeys Split()
    {
        byte[] initiatorToResponder = new byte[NoiseHkdf.OutputSizeInBytes];
        byte[] responderToInitiator = new byte[NoiseHkdf.OutputSizeInBytes];

        NoiseHkdf.DeriveTwo(_chainingKey, [], initiatorToResponder, responderToInitiator);

        return new NoiseSplitKeys(initiatorToResponder, responderToInitiator, _hash);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cipherState.Dispose();
        CryptographicOperations.ZeroMemory(_chainingKey);
    }

    /// <summary>A copy of a symmetric state, taken before a message that may be forged.</summary>
    internal sealed class Snapshot : IDisposable
    {
        internal Snapshot(ReadOnlySpan<byte> chainingKey, ReadOnlySpan<byte> hash, (byte[]? Key, ulong Nonce) cipherState)
        {
            ChainingKey = chainingKey.ToArray();
            Hash = hash.ToArray();
            CipherState = cipherState;
        }

        internal byte[] ChainingKey { get; }

        internal byte[] Hash { get; }

        internal (byte[]? Key, ulong Nonce) CipherState { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(ChainingKey);

            if (CipherState.Key is not null)
            {
                CryptographicOperations.ZeroMemory(CipherState.Key);
            }
        }
    }
}
