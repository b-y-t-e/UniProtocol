using System.Buffers.Binary;
using System.Security.Cryptography;
using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Noise;
using UniProtocol.Protocol.Packets;

namespace UniProtocol.Sessions;

/// <summary>
/// The encrypted channel between two peers, once the handshake has completed.
/// </summary>
/// <remarks>
/// <para>
/// The session owns the two directional keys, the outbound packet counter and the inbound
/// replay window. It knows nothing about paths, addresses or sockets — a packet is a packet
/// regardless of whether it arrived over a relay or a direct link, which is precisely what
/// allows a live session to migrate between them.
/// </para>
/// <para>
/// Nonces come from the packet counter rather than from Noise's own sequential cipher
/// state, because over UDP packets are lost and reordered and a strictly sequential nonce
/// would desynchronise on the first drop.
/// </para>
/// <para>
/// <strong>Thread-safe, and it has to be.</strong> The send side is reached from every
/// caller of <see cref="UniConnection.SendDatagramAsync"/>, and the receive side from one
/// loop per transport — so a session carried over both a relay and a direct path is
/// decrypted from two threads at once. Two senders reading the same counter would encrypt
/// two different payloads under the same nonce, which for ChaCha20-Poly1305 discloses their
/// XOR and the Poly1305 key; two receivers would corrupt the replay window. The locks are
/// per direction so the two never wait on each other.
/// </para>
/// </remarks>
internal sealed class UniSession : IDisposable
{
    /// <summary>Bytes a session adds to a payload: the header plus the authentication tag.</summary>
    public const int OverheadInBytes = DataPacketHeader.SizeInBytes + TagSizeInBytes;

    private const int TagSizeInBytes = 16;
    private const int NonceSizeInBytes = 12;

    /// <summary>
    /// The counter is reserved once it reaches this value; the session must rekey first.
    /// </summary>
    /// <remarks>
    /// Well below the point where ChaCha20-Poly1305 loses its security margin, and far
    /// below where the counter could wrap and reuse a nonce.
    /// </remarks>
    private const ulong MaximumCounter = 1UL << 60;

    private readonly IAeadCipher _sendCipher;
    private readonly IAeadCipher _receiveCipher;
    private readonly ReplayWindow _replayWindow = new();
    private readonly Lock _sendLock = new();
    private readonly Lock _receiveLock = new();

    private ulong _sendCounter;
    private volatile bool _isDisposed;

    private UniSession(IAeadCipher sendCipher, IAeadCipher receiveCipher, uint localIndex, uint remoteIndex)
    {
        _sendCipher = sendCipher;
        _receiveCipher = receiveCipher;
        LocalIndex = localIndex;
        RemoteIndex = remoteIndex;
    }

    /// <summary>The session identifier this peer expects in inbound packets.</summary>
    public uint LocalIndex { get; }

    /// <summary>The session identifier to put in outbound packets.</summary>
    public uint RemoteIndex { get; }

    /// <summary>Number of packets sent on this session.</summary>
    public ulong PacketsSent => Interlocked.Read(ref _sendCounter);

    /// <summary>
    /// Creates a session from the keys a completed handshake produced.
    /// </summary>
    /// <remarks>
    /// The two peers pick opposite keys for sending, which is what the initiator flag
    /// selects. Getting this backwards yields a session where every packet authenticates
    /// locally and nothing the peer sends can be read.
    /// </remarks>
    public static UniSession Create(
        IAeadAlgorithm algorithm,
        NoiseSplitKeys keys,
        bool isInitiator,
        uint localIndex,
        uint remoteIndex)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(keys);

        IAeadCipher sendCipher = algorithm.CreateCipher(
            isInitiator ? keys.InitiatorToResponder : keys.ResponderToInitiator);

        IAeadCipher receiveCipher = algorithm.CreateCipher(
            isInitiator ? keys.ResponderToInitiator : keys.InitiatorToResponder);

        return new UniSession(sendCipher, receiveCipher, localIndex, remoteIndex);
    }

    /// <summary>Returns the packet size for a payload of <paramref name="payloadSize"/> bytes.</summary>
    public static int GetPacketSize(int payloadSize) => OverheadInBytes + payloadSize;

    /// <summary>
    /// Encrypts <paramref name="payload"/> into a complete data packet.
    /// </summary>
    /// <returns>The packet length.</returns>
    public int Encrypt(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        int packetSize = GetPacketSize(payload.Length);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, packetSize);

        // Reserving the counter and using it must be one indivisible step. Reserving it
        // atomically but encrypting outside the lock would still be wrong for a cipher whose
        // instance is not safe to share, and it is the nonce — not the counter — that must
        // never repeat.
        lock (_sendLock)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            ulong counter = _sendCounter;

            if (counter >= MaximumCounter)
            {
                throw new CryptographicException("The session has exhausted its packet counter and must rekey.");
            }

            _sendCounter = counter + 1;

            new DataPacketHeader(RemoteIndex, counter).Write(destination);

            Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
            WriteNonce(counter, nonce);

            _sendCipher.Encrypt(
                nonce,
                payload,
                destination[..DataPacketHeader.SizeInBytes],
                destination.Slice(DataPacketHeader.SizeInBytes, payload.Length),
                destination.Slice(DataPacketHeader.SizeInBytes + payload.Length, TagSizeInBytes));
        }

        return packetSize;
    }

    /// <summary>
    /// Authenticates and decrypts a data packet.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> if the packet is malformed, is not for this session, fails
    /// authentication, or is a replay. All four are ordinary events on a public UDP socket.
    /// </returns>
    /// <remarks>
    /// <paramref name="destination"/> may alias <paramref name="packet"/>: the payload is
    /// decrypted in place so a received datagram never has to be copied.
    /// </remarks>
    public bool TryDecrypt(ReadOnlySpan<byte> packet, Span<byte> destination, out int payloadLength)
    {
        // No disposal check out here on purpose. A packet arriving for a session that has
        // just closed is an ordinary race — the peer cannot know yet, and the receive loop
        // serving every other peer must not take an exception for it. The one check that
        // matters is inside the lock, where it is actually decisive; a check out here could
        // only ever pass and then go stale a nanosecond later, which is the appearance of
        // safety rather than safety.
        payloadLength = 0;

        if (!DataPacketHeader.TryRead(packet, out DataPacketHeader header)
            || header.ReceiverIndex != LocalIndex
            || packet.Length < OverheadInBytes)
        {
            return false;
        }

        int ciphertextLength = packet.Length - OverheadInBytes;

        Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
        WriteNonce(header.Counter, nonce);

        // The replay window is shared mutable state and the decryption is what gates it, so
        // both happen under one lock: two loops admitting the same counter concurrently would
        // deliver a duplicate, and interleaved bitmap updates would lose the record of a
        // counter that was already seen.
        lock (_receiveLock)
        {
            if (_isDisposed)
            {
                return false;
            }

            bool isAuthentic = _receiveCipher.TryDecrypt(
                nonce,
                packet.Slice(DataPacketHeader.SizeInBytes, ciphertextLength),
                packet.Slice(DataPacketHeader.SizeInBytes + ciphertextLength, TagSizeInBytes),
                packet[..DataPacketHeader.SizeInBytes],
                destination[..ciphertextLength]);

            if (!isAuthentic)
            {
                return false;
            }

            // Only now: the replay window must never be advanced by a counter an attacker
            // chose, or genuine packets would start being rejected as replays.
            if (!_replayWindow.TryAccept(header.Counter))
            {
                return false;
            }
        }

        payloadLength = ciphertextLength;
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Both locks, because disposing a cipher out from under a send or a receive already
        // in flight would zero the key mid-operation.
        lock (_sendLock)
        {
            lock (_receiveLock)
            {
                if (_isDisposed)
                {
                    return;
                }

                _isDisposed = true;
                _sendCipher.Dispose();
                _receiveCipher.Dispose();
            }
        }
    }

    private static void WriteNonce(ulong counter, Span<byte> destination)
    {
        destination[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(destination[4..], counter);
    }
}
