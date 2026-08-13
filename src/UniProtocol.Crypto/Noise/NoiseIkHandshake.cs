using System.Globalization;
using System.Security.Cryptography;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Randomness;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// The <c>Noise_IK_25519_ChaChaPoly_BLAKE2s</c> handshake.
/// </summary>
/// <remarks>
/// <para>
/// IK is the right pattern for dialling by public key. The <c>I</c> means the initiator
/// transmits its static key, immediately and encrypted; the <c>K</c> means it already
/// knows the responder's static key — which in UniProtocol is the NodeId being dialled.
/// The consequence is a two-message handshake in which the initiator's identity is hidden
/// from passive observers and the responder is authenticated before any payload is sent.
/// </para>
/// <para>
/// Message flow:
/// </para>
/// <code>
///   &lt;- s                  (pre-message: the responder's static key is the NodeId)
///   ...
///   -&gt; e, es, s, ss       message 1
///   &lt;- e, ee, se          message 2
/// </code>
/// <para>
/// Only IK is implemented. A general pattern interpreter would be more code, more
/// surface, and more ways to configure an insecure handshake, for a flexibility this
/// protocol does not want.
/// </para>
/// </remarks>
public sealed class NoiseIkHandshake : IDisposable
{
    /// <summary>Size of a public key on the wire.</summary>
    public const int PublicKeySizeInBytes = X25519.KeySizeInBytes;

    private readonly NoiseSymmetricState _symmetricState;
    private readonly byte[] _staticPrivateKey;
    private readonly byte[] _staticPublicKey;
    private readonly byte[] _remoteStaticPublicKey = new byte[PublicKeySizeInBytes];
    private readonly byte[] _ephemeralPrivateKey = new byte[X25519.KeySizeInBytes];
    private readonly byte[] _ephemeralPublicKey = new byte[X25519.KeySizeInBytes];
    private readonly byte[] _remoteEphemeralPublicKey = new byte[PublicKeySizeInBytes];
    private readonly IRandomSource _randomSource;
    private readonly int _tagSizeInBytes;

    private HandshakeStep _step;
    private bool _hasRemoteStaticKey;
    private bool _isDisposed;

    private NoiseIkHandshake(NoiseHandshakeOptions options, bool isInitiator, ReadOnlySpan<byte> remoteStaticPublicKey)
    {
        IsInitiator = isInitiator;
        _step = isInitiator ? HandshakeStep.WriteMessage : HandshakeStep.ReadMessage;
        _randomSource = options.RandomSource;
        _tagSizeInBytes = options.Algorithm.TagSizeInBytes;

        _staticPrivateKey = options.StaticPrivateKey.ToArray();
        _staticPublicKey = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(_staticPrivateKey, _staticPublicKey);

        string protocolName = string.Create(
            CultureInfo.InvariantCulture,
            $"Noise_IK_25519_{options.Algorithm.Name}_BLAKE2s");

        _symmetricState = new NoiseSymmetricState(options.Algorithm, protocolName);
        _symmetricState.MixHash(options.Prologue.Span);

        // The pre-message: both sides absorb the responder's static public key, which the
        // initiator already knows because it is the NodeId it dialled.
        if (isInitiator)
        {
            remoteStaticPublicKey.CopyTo(_remoteStaticPublicKey);
            _hasRemoteStaticKey = true;
            _symmetricState.MixHash(_remoteStaticPublicKey);
        }
        else
        {
            _symmetricState.MixHash(_staticPublicKey);
        }
    }

    /// <summary>Indicates whether this side initiated the handshake.</summary>
    public bool IsInitiator { get; }

    /// <summary>Indicates whether both handshake messages have been processed.</summary>
    public bool IsComplete => _step == HandshakeStep.Complete;

    /// <summary>
    /// The peer's static public key, available to the responder only after it has read
    /// message 1.
    /// </summary>
    public ReadOnlySpan<byte> RemoteStaticPublicKey
        => _hasRemoteStaticKey ? _remoteStaticPublicKey : default;

    /// <summary>
    /// Creates the initiator side, dialling <paramref name="remoteStaticPublicKey"/>.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the remote key is unusable — a low-order point, for
    /// which every Diffie-Hellman result is a value the attacker already knows.
    /// </returns>
    /// <remarks>
    /// Reported as a return value rather than an exception because the remote key comes
    /// from outside: it is a NodeId someone typed, pasted, or received over the network.
    /// </remarks>
    public static bool TryCreateInitiator(
        NoiseHandshakeOptions options,
        ReadOnlySpan<byte> remoteStaticPublicKey,
        out NoiseIkHandshake handshake)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNotEqual(remoteStaticPublicKey.Length, PublicKeySizeInBytes);

        Span<byte> probe = stackalloc byte[X25519.SharedSecretSizeInBytes];
        bool isUsable = X25519.TryAgree(options.StaticPrivateKey.Span, remoteStaticPublicKey, probe);
        CryptographicOperations.ZeroMemory(probe);

        if (!isUsable)
        {
            handshake = null!;
            return false;
        }

        handshake = new NoiseIkHandshake(options, isInitiator: true, remoteStaticPublicKey);
        return true;
    }

    /// <summary>Creates the responder side.</summary>
    public static NoiseIkHandshake CreateResponder(NoiseHandshakeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return new NoiseIkHandshake(options, isInitiator: false, default);
    }

    /// <summary>
    /// Returns the exact size of the handshake message this side will write next.
    /// </summary>
    public int GetMessageSize(int payloadSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(payloadSize);

        return IsInitiator
            ? PublicKeySizeInBytes + PublicKeySizeInBytes + _tagSizeInBytes + payloadSize + _tagSizeInBytes
            : PublicKeySizeInBytes + payloadSize + _tagSizeInBytes;
    }

    /// <summary>
    /// Writes this side's handshake message, carrying <paramref name="payload"/>.
    /// </summary>
    /// <returns>The number of bytes written.</returns>
    public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (_step != HandshakeStep.WriteMessage)
        {
            throw new InvalidOperationException(
                "WriteMessage was called out of order; this side is waiting to read the peer's message.");
        }

        int required = GetMessageSize(payload.Length);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, required);

        GenerateEphemeralKey();

        _ephemeralPublicKey.CopyTo(destination);
        _symmetricState.MixHash(_ephemeralPublicKey);

        int offset = PublicKeySizeInBytes;

        if (IsInitiator)
        {
            // -> e, es, s, ss
            MixDiffieHellman(_ephemeralPrivateKey, _remoteStaticPublicKey);
            offset += _symmetricState.EncryptAndHash(_staticPublicKey, destination[offset..]);
            MixDiffieHellman(_staticPrivateKey, _remoteStaticPublicKey);
        }
        else
        {
            // <- e, ee, se
            MixDiffieHellman(_ephemeralPrivateKey, _remoteEphemeralPublicKey);
            MixDiffieHellman(_ephemeralPrivateKey, _remoteStaticPublicKey);
        }

        offset += _symmetricState.EncryptAndHash(payload, destination[offset..]);

        _step = IsInitiator ? HandshakeStep.ReadMessage : HandshakeStep.Complete;

        return offset;
    }

    /// <summary>
    /// Reads the peer's handshake message and recovers its payload.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the message is malformed, fails authentication, or
    /// contains an unusable public key. Everything here arrives from the network, so a
    /// rejection is a normal outcome rather than an error condition.
    /// </returns>
    /// <remarks>
    /// A rejected message leaves this handshake exactly as it was, so the genuine reply is
    /// still accepted afterwards. That matters because the packet carrying a reply is
    /// authenticated only by <c>mac1</c>, which is keyed by a public key — anyone on the
    /// path can produce a well-formed forgery, and a destructive read would let one packet
    /// permanently deny a connection.
    /// </remarks>
    public bool TryReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadDestination, out int payloadLength)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        payloadLength = 0;

        if (_step != HandshakeStep.ReadMessage)
        {
            return false;
        }

        // The reader expects the message the *other* side writes, so the size rule is the
        // mirror of GetMessageSize.
        int overhead = IsInitiator
            ? PublicKeySizeInBytes + _tagSizeInBytes
            : PublicKeySizeInBytes + PublicKeySizeInBytes + _tagSizeInBytes + _tagSizeInBytes;

        if (message.Length < overhead)
        {
            return false;
        }

        using NoiseSymmetricState.Snapshot snapshot = _symmetricState.Capture();
        bool hadRemoteStaticKey = _hasRemoteStaticKey;

        if (TryReadMessageCore(message, payloadDestination, out payloadLength))
        {
            return true;
        }

        _symmetricState.Restore(snapshot);
        _hasRemoteStaticKey = hadRemoteStaticKey;
        payloadLength = 0;

        return false;
    }

    private bool TryReadMessageCore(ReadOnlySpan<byte> message, Span<byte> payloadDestination, out int payloadLength)
    {
        payloadLength = 0;

        message[..PublicKeySizeInBytes].CopyTo(_remoteEphemeralPublicKey);
        _symmetricState.MixHash(_remoteEphemeralPublicKey);

        int offset = PublicKeySizeInBytes;

        if (IsInitiator)
        {
            // <- e, ee, se
            if (!TryMixDiffieHellman(_ephemeralPrivateKey, _remoteEphemeralPublicKey)
                || !TryMixDiffieHellman(_staticPrivateKey, _remoteEphemeralPublicKey))
            {
                return false;
            }
        }
        else
        {
            // -> e, es, s, ss
            if (!TryMixDiffieHellman(_staticPrivateKey, _remoteEphemeralPublicKey))
            {
                return false;
            }

            int encryptedStaticLength = PublicKeySizeInBytes + _tagSizeInBytes;
            if (!_symmetricState.TryDecryptAndHash(
                    message.Slice(offset, encryptedStaticLength),
                    _remoteStaticPublicKey,
                    out int staticLength)
                || staticLength != PublicKeySizeInBytes)
            {
                return false;
            }

            _hasRemoteStaticKey = true;
            offset += encryptedStaticLength;

            if (!TryMixDiffieHellman(_staticPrivateKey, _remoteStaticPublicKey))
            {
                return false;
            }
        }

        if (!_symmetricState.TryDecryptAndHash(message[offset..], payloadDestination, out payloadLength))
        {
            payloadLength = 0;
            return false;
        }

        _step = IsInitiator ? HandshakeStep.Complete : HandshakeStep.WriteMessage;

        return true;
    }

    /// <summary>
    /// Produces the transport keys. Valid only once <see cref="IsComplete"/> is true.
    /// </summary>
    public NoiseSplitKeys Split()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (!IsComplete)
        {
            throw new InvalidOperationException("The handshake has not completed, so there are no transport keys yet.");
        }

        return _symmetricState.Split();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        _symmetricState.Dispose();
        CryptographicOperations.ZeroMemory(_staticPrivateKey);
        CryptographicOperations.ZeroMemory(_ephemeralPrivateKey);
        _isDisposed = true;
    }

    private void GenerateEphemeralKey()
    {
        _randomSource.Fill(_ephemeralPrivateKey);
        X25519.ClampScalar(_ephemeralPrivateKey);
        X25519.GetPublicKey(_ephemeralPrivateKey, _ephemeralPublicKey);
    }

    /// <summary>
    /// Performs a Diffie-Hellman we know cannot degenerate, because the peer key was
    /// validated when it was accepted.
    /// </summary>
    private void MixDiffieHellman(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        if (!TryMixDiffieHellman(privateKey, publicKey))
        {
            throw new CryptographicException("A Diffie-Hellman operation produced an all-zero shared secret.");
        }
    }

    private bool TryMixDiffieHellman(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        Span<byte> sharedSecret = stackalloc byte[X25519.SharedSecretSizeInBytes];

        bool isUsable = X25519.TryAgree(privateKey, publicKey, sharedSecret);
        if (isUsable)
        {
            _symmetricState.MixKey(sharedSecret);
        }

        CryptographicOperations.ZeroMemory(sharedSecret);
        return isUsable;
    }

    /// <summary>
    /// Which half of the two-message exchange this side is waiting to perform. Making the
    /// step explicit means an out-of-order call is rejected rather than silently mixing
    /// keys in the wrong order.
    /// </summary>
    private enum HandshakeStep
    {
        WriteMessage,
        ReadMessage,
        Complete,
    }
}
