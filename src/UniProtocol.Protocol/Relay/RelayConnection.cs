using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Noise;
using UniProtocol.Crypto.Randomness;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Relay;

/// <summary>
/// An authenticated, encrypted frame channel to or from a relay server, over a byte stream.
/// </summary>
/// <remarks>
/// <para>
/// The relay is authenticated by its <see cref="NodeId"/> through a Noise IK handshake, not
/// by a TLS certificate. That removes certificate issuance, renewal and expiry from
/// operating a relay entirely, and it means a compromised certificate authority or a
/// hijacked DNS record cannot impersonate one — the client only ever completes a handshake
/// with the exact key it dialled.
/// </para>
/// <para>
/// Frames are encrypted with the keys the handshake produced. The stream is reliable and
/// ordered, so the nonce is simply a counter and no replay window is needed; anything that
/// fails to decrypt means the stream has been tampered with, and the connection ends.
/// </para>
/// </remarks>
public sealed class RelayConnection : IAsyncDisposable
{
    private const int LengthPrefixSizeInBytes = 2;
    private const int TagSizeInBytes = 16;
    private const int NonceSizeInBytes = 12;
    private const int MaximumHandshakeMessageSize = 512;

    private readonly Stream _stream;
    private readonly IAeadCipher _sendCipher;
    private readonly IAeadCipher _receiveCipher;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly byte[] _sendBuffer;

    private ulong _sendCounter;
    private ulong _receiveCounter;
    private bool _isDisposed;

    private RelayConnection(Stream stream, IAeadCipher sendCipher, IAeadCipher receiveCipher, NodeId remoteNodeId)
    {
        _stream = stream;
        _sendCipher = sendCipher;
        _receiveCipher = receiveCipher;
        RemoteNodeId = remoteNodeId;

        _sendBuffer = new byte[LengthPrefixSizeInBytes + RelayProtocol.MaximumFrameSizeInBytes + TagSizeInBytes];
    }

    /// <summary>
    /// The identity at the other end: the server's, on a client connection; the client's, on
    /// a server connection.
    /// </summary>
    public NodeId RemoteNodeId { get; }

    /// <summary>
    /// Performs the client side of the handshake, authenticating the server as
    /// <paramref name="serverNodeId"/>.
    /// </summary>
    public static async Task<RelayConnection> ConnectAsync(
        Stream stream,
        UniIdentity identity,
        NodeId serverNodeId,
        IRandomSource? randomSource = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(identity);

        byte[] serverNoiseKey = new byte[X25519.KeySizeInBytes];
        if (!serverNodeId.TryGetNoiseStaticKey(serverNoiseKey))
        {
            throw new RelayProtocolException($"'{serverNodeId}' is not a valid relay identity.");
        }

        NoiseHandshakeOptions options = CreateHandshakeOptions(identity, randomSource);

        if (!NoiseIkHandshake.TryCreateInitiator(options, serverNoiseKey, out NoiseIkHandshake handshake))
        {
            throw new RelayProtocolException($"'{serverNodeId}' is not a usable relay identity.");
        }

        using (handshake)
        {
            byte[] payload = new byte[PeerIdentityPayload.HeaderSizeInBytes];
            int payloadLength = PeerIdentityPayload.Write(identity.NodeId, [], payload);

            byte[] message = new byte[handshake.GetMessageSize(payloadLength)];
            int written = handshake.WriteMessage(payload.AsSpan(0, payloadLength), message);

            await WriteHandshakeMessageAsync(stream, message.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);

            byte[] response = new byte[MaximumHandshakeMessageSize];
            int responseLength = await ReadHandshakeMessageAsync(stream, response, cancellationToken)
                .ConfigureAwait(false);

            if (!handshake.TryReadMessage(response.AsSpan(0, responseLength), new byte[responseLength], out _))
            {
                throw new RelayProtocolException("The relay's handshake reply failed authentication.");
            }

            using NoiseSplitKeys keys = handshake.Split();

            return new RelayConnection(
                stream,
                ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.InitiatorToResponder),
                ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.ResponderToInitiator),
                serverNodeId);
        }
    }

    /// <summary>
    /// Performs the server side of the handshake, learning the client's identity from it.
    /// </summary>
    public static async Task<RelayConnection> AcceptAsync(
        Stream stream,
        UniIdentity identity,
        IRandomSource? randomSource = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(identity);

        using NoiseIkHandshake handshake = NoiseIkHandshake.CreateResponder(
            CreateHandshakeOptions(identity, randomSource));

        byte[] message = new byte[MaximumHandshakeMessageSize];
        int messageLength = await ReadHandshakeMessageAsync(stream, message, cancellationToken).ConfigureAwait(false);

        byte[] payload = new byte[messageLength];

        if (!handshake.TryReadMessage(message.AsSpan(0, messageLength), payload, out int payloadLength))
        {
            throw new RelayProtocolException("The client's handshake failed authentication.");
        }

        if (!PeerIdentityPayload.TryParse(
                payload.AsSpan(0, payloadLength),
                handshake.RemoteStaticPublicKey,
                out NodeId clientNodeId,
                out _))
        {
            throw new RelayProtocolException("The client asserted an identity that does not match its key.");
        }

        byte[] response = new byte[handshake.GetMessageSize(0)];
        int written = handshake.WriteMessage([], response);

        await WriteHandshakeMessageAsync(stream, response.AsMemory(0, written), cancellationToken)
            .ConfigureAwait(false);

        using NoiseSplitKeys keys = handshake.Split();

        return new RelayConnection(
            stream,
            ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.ResponderToInitiator),
            ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.InitiatorToResponder),
            clientNodeId);
    }

    /// <summary>Sends a frame carrying <paramref name="body"/>.</summary>
    public ValueTask SendAsync(RelayFrameType type, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        => SendAsync(type, default, body, cancellationToken);

    /// <summary>
    /// Sends a frame whose payload is <paramref name="header"/> followed by
    /// <paramref name="body"/>.
    /// </summary>
    /// <remarks>
    /// The two-part form exists so forwarding a packet does not have to concatenate the
    /// destination NodeId with a body the caller already holds.
    /// </remarks>
    public async ValueTask SendAsync(
        RelayFrameType type,
        ReadOnlyMemory<byte> header,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        int plaintextLength = 1 + header.Length + body.Length;

        if (plaintextLength > RelayProtocol.MaximumFrameSizeInBytes)
        {
            throw new RelayProtocolException(
                $"A relay frame may carry at most {RelayProtocol.MaximumFrameSizeInBytes} bytes.");
        }

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            Memory<byte> frame = _sendBuffer;
            Memory<byte> plaintext = frame.Slice(LengthPrefixSizeInBytes, plaintextLength);

            plaintext.Span[0] = (byte)type;
            header.CopyTo(plaintext[1..]);
            body.CopyTo(plaintext[(1 + header.Length)..]);

            int ciphertextLength = plaintextLength + TagSizeInBytes;
            BinaryPrimitives.WriteUInt16BigEndian(frame.Span, (ushort)ciphertextLength);

            Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
            WriteNonce(_sendCounter++, nonce);

            // The length prefix is authenticated, so an attacker cannot resize a frame to
            // desynchronise the stream without the tag check catching it.
            _sendCipher.Encrypt(
                nonce,
                plaintext.Span,
                frame.Span[..LengthPrefixSizeInBytes],
                plaintext.Span,
                frame.Span.Slice(LengthPrefixSizeInBytes + plaintextLength, TagSizeInBytes));

            await _stream
                .WriteAsync(frame[..(LengthPrefixSizeInBytes + ciphertextLength)], cancellationToken)
                .ConfigureAwait(false);

            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// Reads the next frame into <paramref name="buffer"/>.
    /// </summary>
    /// <exception cref="RelayProtocolException">
    /// The stream is malformed or a frame failed authentication.
    /// </exception>
    public async ValueTask<RelayFrame> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        byte[] lengthPrefix = ArrayPool<byte>.Shared.Rent(LengthPrefixSizeInBytes);

        try
        {
            await _stream.ReadExactlyAsync(lengthPrefix.AsMemory(0, LengthPrefixSizeInBytes), cancellationToken)
                .ConfigureAwait(false);

            int ciphertextLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);

            if (ciphertextLength < 1 + TagSizeInBytes
                || ciphertextLength > RelayProtocol.MaximumFrameSizeInBytes + TagSizeInBytes)
            {
                throw new RelayProtocolException($"The relay sent a frame of an impossible size ({ciphertextLength}).");
            }

            int plaintextLength = ciphertextLength - TagSizeInBytes;

            if (buffer.Length < plaintextLength)
            {
                throw new RelayProtocolException("The receive buffer is too small for the incoming frame.");
            }

            byte[] ciphertext = ArrayPool<byte>.Shared.Rent(ciphertextLength);

            try
            {
                await _stream.ReadExactlyAsync(ciphertext.AsMemory(0, ciphertextLength), cancellationToken)
                    .ConfigureAwait(false);

                Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
                WriteNonce(_receiveCounter++, nonce);

                bool isAuthentic = _receiveCipher.TryDecrypt(
                    nonce,
                    ciphertext.AsSpan(0, plaintextLength),
                    ciphertext.AsSpan(plaintextLength, TagSizeInBytes),
                    lengthPrefix.AsSpan(0, LengthPrefixSizeInBytes),
                    buffer.Span[..plaintextLength]);

                if (!isAuthentic)
                {
                    throw new RelayProtocolException("A relay frame failed authentication; the stream has been tampered with.");
                }

                return new RelayFrame((RelayFrameType)buffer.Span[0], plaintextLength - 1);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(ciphertext);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(lengthPrefix);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
        {
            return;
        }

        _isDisposed = true;

        _sendCipher.Dispose();
        _receiveCipher.Dispose();
        _sendLock.Dispose();

        await _stream.DisposeAsync().ConfigureAwait(false);
    }

    private static NoiseHandshakeOptions CreateHandshakeOptions(UniIdentity identity, IRandomSource? randomSource)
        => new()
        {
            StaticPrivateKey = identity.NoiseStaticPrivateKey.ToArray(),
            Prologue = Encoding.UTF8.GetBytes(RelayProtocol.ApplicationProtocol),
            RandomSource = randomSource ?? SecureRandomSource.Instance,
        };

    private static async Task WriteHandshakeMessageAsync(
        Stream stream,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        byte[] prefix = new byte[LengthPrefixSizeInBytes];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)message.Length);

        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ReadHandshakeMessageAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        byte[] prefix = new byte[LengthPrefixSizeInBytes];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);

        int length = BinaryPrimitives.ReadUInt16BigEndian(prefix);

        if (length == 0 || length > buffer.Length)
        {
            throw new RelayProtocolException($"A handshake message of {length} bytes is not acceptable.");
        }

        await stream.ReadExactlyAsync(buffer[..length], cancellationToken).ConfigureAwait(false);

        return length;
    }

    private static void WriteNonce(ulong counter, Span<byte> destination)
    {
        destination[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(destination[4..], counter);
    }
}

/// <summary>A frame read from a relay connection.</summary>
/// <param name="Type">What the frame is.</param>
/// <param name="PayloadLength">
/// Length of the payload, which begins one byte into the caller's buffer.
/// </param>
public readonly record struct RelayFrame(RelayFrameType Type, int PayloadLength);
