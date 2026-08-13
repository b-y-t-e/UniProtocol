using System.Security.Cryptography;

namespace UniProtocol.Crypto.Noise;

/// <summary>
/// The two directional keys produced when a Noise handshake completes, together with the
/// final transcript hash.
/// </summary>
/// <remarks>
/// <para>
/// The handshake hands out raw keys rather than ready-made cipher states because the
/// transport, not Noise, owns nonce policy. Noise's own <c>CipherState</c> assumes a
/// strictly sequential counter over a reliable, ordered stream; UniProtocol runs over UDP,
/// where packets are lost and reordered, so nonces come from packet numbers and a replay
/// window guards against reuse.
/// </para>
/// <para>
/// The transcript hash is a channel binding: it is unique to this handshake and known to
/// both peers, so higher layers can bind their own authentication to this exact session.
/// </para>
/// </remarks>
public sealed class NoiseSplitKeys : IDisposable
{
    private readonly byte[] _initiatorToResponder;
    private readonly byte[] _responderToInitiator;
    private readonly byte[] _handshakeHash;
    private bool _isDisposed;

    internal NoiseSplitKeys(byte[] initiatorToResponder, byte[] responderToInitiator, ReadOnlySpan<byte> handshakeHash)
    {
        _initiatorToResponder = initiatorToResponder;
        _responderToInitiator = responderToInitiator;
        _handshakeHash = handshakeHash.ToArray();
    }

    /// <summary>The key protecting traffic from the initiator to the responder.</summary>
    public ReadOnlySpan<byte> InitiatorToResponder
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _initiatorToResponder;
        }
    }

    /// <summary>The key protecting traffic from the responder to the initiator.</summary>
    public ReadOnlySpan<byte> ResponderToInitiator
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _responderToInitiator;
        }
    }

    /// <summary>The final transcript hash, usable as a channel binding.</summary>
    public ReadOnlySpan<byte> HandshakeHash
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _handshakeHash;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_initiatorToResponder);
        CryptographicOperations.ZeroMemory(_responderToInitiator);
        _isDisposed = true;
    }
}
