using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using UniProtocol.Abstractions;
using UniProtocol.Buffers;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Noise;
using UniProtocol.Discovery;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Packets;
using UniProtocol.Sessions;
using UniProtocol.Transport;

namespace UniProtocol;

/// <summary>
/// A node's presence on the network: it listens for connections and dials others by
/// <see cref="NodeId"/>.
/// </summary>
/// <remarks>
/// <para>
/// One endpoint owns one transport and one receive loop, and multiplexes every peer over
/// it. That is not an implementation detail — a single UDP socket means a single NAT
/// mapping to discover and keep alive, which is what makes direct connectivity to many
/// peers practical at all.
/// </para>
/// <para>
/// Inbound packets are dispatched by the session identifier in their header, so a peer that
/// changes address mid-connection continues to be recognised.
/// </para>
/// </remarks>
public sealed partial class UniEndpoint : IAsyncDisposable
{
    private readonly UniEndpointOptions _options;
    private readonly PacketRouter _router;
    private readonly bool _ownsTransports;
    private readonly PacketPool _pool = new();
    private readonly ILogger<UniEndpoint> _logger;

    private readonly byte[] _noiseStaticPrivateKey;
    private readonly byte[] _noiseStaticPublicKey;
    private readonly byte[] _inboundMac1Key = new byte[32];
    private readonly byte[] _prologue;

    private readonly ConcurrentDictionary<uint, UniConnection> _connections = new();
    private readonly ConcurrentDictionary<uint, PendingHandshake> _pendingHandshakes = new();
    private readonly ConcurrentDictionary<HandshakeAttemptId, HandshakeAttempt> _handshakeAttempts = new();
    private readonly Channel<UniConnection> _incoming = Channel.CreateUnbounded<UniConnection>();
    private readonly CancellationTokenSource _shutdown = new();

    private Task[]? _receiveLoops;
    private bool _isDisposed;

    private UniEndpoint(UniEndpointOptions options, PacketRouter router, bool ownsTransports)
    {
        _options = options;
        _router = router;
        _ownsTransports = ownsTransports;
        _logger = options.LoggerFactory.CreateLogger<UniEndpoint>();

        NodeId = options.Identity.NodeId;

        _noiseStaticPrivateKey = options.Identity.NoiseStaticPrivateKey.ToArray();
        _noiseStaticPublicKey = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(_noiseStaticPrivateKey, _noiseStaticPublicKey);

        // Inbound handshakes of both kinds are addressed to us, so both carry a mac1 keyed
        // by our own static key. One precomputed key covers both.
        HandshakePacket.DeriveMac1Key(_noiseStaticPublicKey, _inboundMac1Key);

        _prologue = Encoding.UTF8.GetBytes($"uniprotocol/v1\0{options.ApplicationProtocol}");
    }

    /// <summary>This node's identity.</summary>
    public NodeId NodeId { get; }

    /// <summary>The address this endpoint receives on.</summary>
    public NetworkAddress LocalAddress => _router.Transports[0].LocalAddress;

    /// <summary>
    /// Connects to <paramref name="peer"/> through the configured relay.
    /// </summary>
    /// <remarks>
    /// Needs no address at all: the relay knows where the peer is. This is the form that
    /// works from any network, including when both sides are behind NAT.
    /// </remarks>
    public ValueTask<UniConnection> ConnectViaRelayAsync(NodeId peer, CancellationToken cancellationToken = default)
    {
        if (!_router.CanReach(PathKind.Relay))
        {
            throw new PathUnavailableException(
                "This endpoint has no relay configured. Supply one via UniEndpointOptions.RelayTransport.");
        }

        return ConnectAsync(peer, [PathEndpoint.ToRelayedNode(peer)], cancellationToken);
    }

    /// <summary>
    /// Builds a ticket describing how to reach this endpoint right now.
    /// </summary>
    /// <remarks>
    /// The addresses are this machine's current local ones, which is enough for a peer on
    /// the same network and nothing more. Once relays and address discovery exist the ticket
    /// gains publicly reachable candidates, and the identity in it stays the same — so a
    /// ticket handed out today keeps naming the same node.
    /// </remarks>
    public UniTicket CreateTicket(TimeSpan? validFor = null)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        System.Net.Sockets.AddressFamily family = LocalAddress.IsIPv4
            ? System.Net.Sockets.AddressFamily.InterNetwork
            : System.Net.Sockets.AddressFamily.InterNetworkV6;

        // Enumerating every interface is only right for a socket bound to the wildcard. One
        // bound to a specific address is reachable at that address and nowhere else, so
        // advertising the others would send a peer to addresses that silently drop its
        // handshake.
        IReadOnlyList<NetworkAddress> addresses = LocalAddress.IsAnyAddress
            ? LocalAddresses.Enumerate(family, LocalAddress.Port)
            : [LocalAddress];

        return new UniTicket
        {
            NodeId = NodeId,
            Addresses = addresses,
            Relay = (_options.RelayTransport as RelayPacketTransport)?.RelayAddress,
            ExpiresAt = validFor is { } lifetime ? _options.TimeProvider.GetUtcNow() + lifetime : null,
        };
    }

    /// <summary>Creates an endpoint and starts receiving.</summary>
    public static UniEndpoint Create(UniEndpointOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<IPacketTransport> transports = [];
        bool ownsTransports = options.Transport is null;

        transports.Add(options.Transport ?? UdpPacketTransport.Bind(options.ListenEndPoint));

        if (options.RelayTransport is not null)
        {
            transports.Add(options.RelayTransport);
        }

        UniEndpoint endpoint = new(options, new PacketRouter(transports), ownsTransports);

        // One receive loop per transport. They all feed the same dispatch, so a packet that
        // arrives over a relay is handled exactly like one that arrived over UDP.
        endpoint._receiveLoops =
        [
            .. transports.Select(transport =>
                Task.Run(() => endpoint.ReceiveLoopAsync(transport, endpoint._shutdown.Token))),
        ];

        return endpoint;
    }

    /// <summary>
    /// Connects to <paramref name="peer"/> at <paramref name="address"/>.
    /// </summary>
    /// <remarks>
    /// The address is explicit at this milestone. Once discovery exists the caller supplies
    /// only the <see cref="NodeId"/> and the endpoint works out how to reach it — first over
    /// a relay, then directly.
    /// </remarks>
    public ValueTask<UniConnection> ConnectAsync(
        NodeId peer,
        NetworkAddress address,
        CancellationToken cancellationToken = default)
        => ConnectAsync(peer, [PathEndpoint.ToAddress(address)], cancellationToken);

    /// <summary>
    /// Connects using a ticket, which supplies both the identity and the candidate
    /// addresses.
    /// </summary>
    public ValueTask<UniConnection> ConnectAsync(UniTicket ticket, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        List<PathEndpoint> candidates = [.. ticket.Addresses.Select(PathEndpoint.ToAddress)];

        // The relay is tried alongside the direct addresses, not after them. Racing the two
        // means a peer that happens to be directly reachable connects at direct-path latency,
        // while one that is not still connects — without waiting out a timeout first.
        if (_router.CanReach(PathKind.Relay))
        {
            candidates.Add(PathEndpoint.ToRelayedNode(ticket.NodeId));
        }

        if (candidates.Count == 0)
        {
            throw new HandshakeFailedException(
                "The ticket carries no addresses and this endpoint has no relay configured, so there is no way to reach that node. " +
                "Configure a relay to connect to peers that have no publicly reachable address.");
        }

        return ConnectAsync(ticket.NodeId, candidates, cancellationToken);
    }

    /// <summary>
    /// Connects to <paramref name="peer"/>, trying every candidate address at once.
    /// </summary>
    /// <remarks>
    /// The handshake goes to all candidates simultaneously rather than one after another,
    /// and the first address that answers becomes the connection's path. Trying them in
    /// sequence would mean waiting out a timeout per unreachable candidate — and a machine
    /// with a Wi-Fi address, an Ethernet address and a virtual adapter advertises several,
    /// most of which are unreachable from any given peer. This is the same "probe everything,
    /// keep what works" approach that path selection will generalise.
    /// </remarks>
    public async ValueTask<UniConnection> ConnectAsync(
        NodeId peer,
        IReadOnlyList<PathEndpoint> candidates,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(candidates);

        if (candidates.Count == 0)
        {
            throw new ArgumentException("At least one candidate path is required.", nameof(candidates));
        }

        byte[] peerNoiseKey = new byte[X25519.KeySizeInBytes];
        if (!peer.TryGetNoiseStaticKey(peerNoiseKey))
        {
            throw new HandshakeFailedException($"'{peer}' is not a valid node identity.");
        }

        NoiseHandshakeOptions handshakeOptions = new()
        {
            StaticPrivateKey = _noiseStaticPrivateKey,
            Prologue = _prologue,
            Algorithm = _options.Algorithm,
            RandomSource = _options.RandomSource,
        };

        if (!NoiseIkHandshake.TryCreateInitiator(handshakeOptions, peerNoiseKey, out NoiseIkHandshake handshake))
        {
            throw new HandshakeFailedException($"'{peer}' is not a usable node identity.");
        }

        byte[] peerMac1Key = new byte[32];
        HandshakePacket.DeriveMac1Key(peerNoiseKey, peerMac1Key);

        uint localIndex = AllocateSessionIndex();
        PendingHandshake pending = new(handshake, peer);

        try
        {
            _pendingHandshakes[localIndex] = pending;

            byte[] initPacket = BuildHandshakeInit(handshake, localIndex, peerMac1Key);

            return await CompleteHandshakeAsync(pending, initPacket, candidates, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _pendingHandshakes.TryRemove(localIndex, out _);
            pending.Dispose();
        }
    }

    /// <summary>Waits for the next inbound connection.</summary>
    public ValueTask<UniConnection> AcceptAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        return _incoming.Reader.ReadAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
        {
            return;
        }

        _isDisposed = true;
        await _shutdown.CancelAsync().ConfigureAwait(false);

        foreach (Task loop in _receiveLoops ?? [])
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected: the loops exit by cancellation.
            }
        }

        _incoming.Writer.TryComplete();

        foreach (UniConnection connection in _connections.Values)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        _connections.Clear();
        _handshakeAttempts.Clear();

        if (_ownsTransports)
        {
            foreach (IPacketTransport transport in _router.Transports)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }
        }

        _shutdown.Dispose();
    }

    private async Task<UniConnection> CompleteHandshakeAsync(
        PendingHandshake pending,
        byte[] initPacket,
        IReadOnlyList<PathEndpoint> candidates,
        CancellationToken cancellationToken)
    {
        // The deadline is driven by the injected TimeProvider, so a simulated run can
        // exercise handshake expiry without spending ten real seconds on it.
        using CancellationTokenSource deadline = new(_options.HandshakeTimeout, _options.TimeProvider);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _shutdown.Token,
            deadline.Token);

        TimeSpan retryInterval = _options.HandshakeRetryInterval;

        try
        {
            while (true)
            {
                foreach (PathEndpoint candidate in candidates)
                {
                    await _router.SendAsync(initPacket, candidate, timeout.Token).ConfigureAwait(false);
                }

                Task delay = Task.Delay(retryInterval, _options.TimeProvider, timeout.Token);
                Task completed = await Task.WhenAny(pending.Completion.Task, delay).ConfigureAwait(false);

                if (completed == pending.Completion.Task)
                {
                    return await pending.Completion.Task.ConfigureAwait(false);
                }

                // Exponential backoff: a peer that is slow to answer is far more common than
                // one that needs to be asked faster, and a tight retry loop against an
                // unreachable address is indistinguishable from a flood.
                retryInterval *= 2;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HandshakeFailedException(
                $"'{pending.RemoteNodeId}' did not complete a handshake within {_options.HandshakeTimeout}.");
        }
    }

    private byte[] BuildHandshakeInit(NoiseIkHandshake handshake, uint localIndex, ReadOnlySpan<byte> peerMac1Key)
    {
        Span<byte> payload = stackalloc byte[PeerIdentityPayload.HeaderSizeInBytes];
        int payloadLength = PeerIdentityPayload.Write(NodeId, [], payload);

        byte[] packet = new byte[HandshakePacket.OverheadInBytes + handshake.GetMessageSize(payloadLength)];

        int noiseLength = handshake.WriteMessage(
            payload[..payloadLength],
            packet.AsSpan(HandshakePacket.HeaderSizeInBytes));

        int length = HandshakePacket.Finish(
            packet,
            PacketType.HandshakeInit,
            localIndex,
            receiverIndex: 0,
            noiseLength,
            peerMac1Key);

        return length == packet.Length
            ? packet
            : packet[..length];
    }

    private async Task ReceiveLoopAsync(IPacketTransport transport, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Packet packet = _pool.Rent();
            bool handedOff = false;

            try
            {
                PacketReceiveResult result = await transport
                    .ReceiveAsync(packet.Buffer, cancellationToken)
                    .ConfigureAwait(false);

                packet.Length = result.BytesReceived;
                packet.RemotePath = result.Source;

                handedOff = await DispatchAsync(packet, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
#pragma warning disable CA1031 // The receive loop serves every peer; one bad packet must not stop it.
            catch (Exception exception)
            {
                LogPacketProcessingFailed(exception);
            }
#pragma warning restore CA1031
            finally
            {
                if (!handedOff)
                {
                    packet.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// Routes one received packet.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> when ownership of the packet has passed to a connection, in
    /// which case the receive loop must not return it to the pool.
    /// </returns>
    private async ValueTask<bool> DispatchAsync(Packet packet, CancellationToken cancellationToken)
    {
        if (packet.Length == 0)
        {
            return false;
        }

        switch ((PacketType)packet.Span[0])
        {
            case PacketType.Data:
                return TryDispatchData(packet);

            case PacketType.HandshakeInit:
                await HandleHandshakeInitAsync(packet, cancellationToken).ConfigureAwait(false);
                return false;

            case PacketType.HandshakeResponse:
                HandleHandshakeResponse(packet);
                return false;

            default:
                // Unknown types are ignored rather than rejected, so that a future version
                // can introduce one without older peers treating it as an attack.
                return false;
        }
    }

    private bool TryDispatchData(Packet packet)
    {
        if (packet.Length < DataPacketHeader.SizeInBytes
            || !_connections.TryGetValue(ReadReceiverIndex(packet.Span), out UniConnection? connection))
        {
            return false;
        }

        return connection.TryAcceptDataPacket(packet);
    }

    private async ValueTask HandleHandshakeInitAsync(Packet packet, CancellationToken cancellationToken)
    {
        if (!HandshakePacket.TryParse(
                packet.Span,
                PacketType.HandshakeInit,
                _inboundMac1Key,
                out uint peerIndex,
                out _,
                out ReadOnlySpan<byte> noiseMessage))
        {
            return;
        }

        if (noiseMessage.Length < HandshakeAttemptId.SizeInBytes)
        {
            return;
        }

        // The Noise message begins with the initiator's ephemeral public key, which is fresh
        // per handshake attempt. Two packets carrying the same one are the same attempt —
        // either a retransmission, or the same attempt arriving over several of the candidate
        // addresses the initiator probed in parallel. Either way it must produce one session,
        // and the reply is re-sent to whichever address this copy came from.
        //
        // Claimed atomically, not looked up and then created: there is one receive loop per
        // transport, so the copies that arrive over a relay and over a direct address are
        // processed concurrently. A check followed by an insert would let both pass the check
        // and build two sessions for one handshake — the initiator would adopt one and the
        // other would be handed to AcceptAsync as a connection that never receives anything.
        HandshakeAttemptId attemptId = new(noiseMessage);
        HandshakeAttempt attempt = new();

        if (!_handshakeAttempts.TryAdd(attemptId, attempt))
        {
            HandshakeAttempt existing = _handshakeAttempts[attemptId];

            // A duplicate that arrived while the first copy is still being processed has
            // nothing to re-send yet; the initiator retransmits until it gets an answer.
            if (existing.Connection is { } established)
            {
                await established.ResendHandshakeResponseAsync(packet.RemotePath, cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        bool isClaimed = false;

        try
        {
            isClaimed = await TryAcceptHandshakeAsync(packet, peerIndex, attempt, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (!isClaimed)
            {
                // A rejected or failed handshake must not leave its identifier claimed, or a
                // retransmission of the same attempt would be silently dropped for ever.
                _handshakeAttempts.TryRemove(attemptId, out _);
            }
        }
    }

    /// <summary>
    /// Completes the responder half of a handshake whose attempt identifier this endpoint
    /// has already claimed.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> when a connection was established, meaning the claim on the
    /// attempt identifier must be kept so that retransmissions are answered from the cache.
    /// </returns>
    private async ValueTask<bool> TryAcceptHandshakeAsync(
        Packet packet,
        uint peerIndex,
        HandshakeAttempt attempt,
        CancellationToken cancellationToken)
    {
        using NoiseIkHandshake handshake = NoiseIkHandshake.CreateResponder(new NoiseHandshakeOptions
        {
            StaticPrivateKey = _noiseStaticPrivateKey,
            Prologue = _prologue,
            Algorithm = _options.Algorithm,
            RandomSource = _options.RandomSource,
        });

        using Packet scratch = _pool.Rent();

        byte[] peerMac1Key = new byte[32];
        byte[] responsePacket;
        int responseLength;
        uint localIndex;
        NodeId peerNodeId;
        UniSession session;

        // Everything that touches spans is confined here, because a ref struct cannot live
        // across the awaits that follow.
        {
            ReadOnlySpan<byte> noiseMessage = SliceNoiseMessage(packet.Span);
            Span<byte> payload = scratch.Buffer.Span;

            if (!handshake.TryReadMessage(noiseMessage, payload, out int payloadLength))
            {
                LogHandshakeRejected(packet.RemotePath, "the Noise message failed authentication");
                return false;
            }

            if (!PeerIdentityPayload.TryParse(
                    payload[..payloadLength],
                    handshake.RemoteStaticPublicKey,
                    out peerNodeId,
                    out _))
            {
                LogHandshakeRejected(packet.RemotePath, "the asserted identity did not match the authenticated key");
                return false;
            }

            HandshakePacket.DeriveMac1Key(handshake.RemoteStaticPublicKey, peerMac1Key);

            localIndex = AllocateSessionIndex();

            responsePacket = new byte[HandshakePacket.OverheadInBytes + handshake.GetMessageSize(0)];
            int noiseLength = handshake.WriteMessage([], responsePacket.AsSpan(HandshakePacket.HeaderSizeInBytes));
            responseLength = HandshakePacket.Finish(
                responsePacket,
                PacketType.HandshakeResponse,
                localIndex,
                peerIndex,
                noiseLength,
                peerMac1Key);

            using NoiseSplitKeys keys = handshake.Split();
            session = UniSession.Create(_options.Algorithm, keys, isInitiator: false, localIndex, peerIndex);
        }

        UniConnection connection = new(
            _router,
            _pool,
            session,
            peerNodeId,
            packet.RemotePath,
            _options.ReceiveQueueCapacity);

        connection.CacheHandshakeResponse(responsePacket.AsSpan(0, responseLength));
        _connections[localIndex] = connection;

        // Published before the reply goes out, so a duplicate copy of this same attempt that
        // arrives over another transport finds the cached response instead of being dropped.
        attempt.Connection = connection;

        await _router
            .SendAsync(responsePacket.AsMemory(0, responseLength), packet.RemotePath, cancellationToken)
            .ConfigureAwait(false);

        if (!_incoming.Writer.TryWrite(connection))
        {
            _connections.TryRemove(localIndex, out _);
            attempt.Connection = null;
            await connection.DisposeAsync().ConfigureAwait(false);
            return false;
        }

        LogConnectionAccepted(peerNodeId, packet.RemotePath);
        return true;
    }

    /// <summary>Locates the Noise message inside a handshake packet whose MACs already checked out.</summary>
    private static ReadOnlySpan<byte> SliceNoiseMessage(ReadOnlySpan<byte> packet)
        => packet[HandshakePacket.HeaderSizeInBytes..(packet.Length - (2 * HandshakePacket.MacSizeInBytes))];

    private void HandleHandshakeResponse(Packet packet)
    {
        if (!HandshakePacket.TryParse(
                packet.Span,
                PacketType.HandshakeResponse,
                _inboundMac1Key,
                out uint peerIndex,
                out uint localIndex,
                out ReadOnlySpan<byte> noiseMessage))
        {
            return;
        }

        // Looked up, not removed. A handshake reply is authenticated only by mac1, whose key
        // is derived from a public key — so anyone on the path, a relay included, can forge a
        // well-formed one. Removing the pending handshake before the Noise message has been
        // verified would let a single forged packet end a connection attempt that was about
        // to succeed. The pending entry is removed only once a genuine reply has been read.
        if (!_pendingHandshakes.TryRemove(localIndex, out PendingHandshake? pending))
        {
            // Either a duplicate reply to a handshake that already completed, or one for a
            // handshake we abandoned. Both are normal on a lossy path.
            return;
        }

        using Packet scratch = _pool.Rent();

        // One reply per pending handshake gets to mutate it. Without this, two receive loops
        // reading the same reply — the ordinary case when a direct address and a relay were
        // probed in parallel — would both drive the Noise state machine.
        lock (pending.Gate)
        {
            if (!_pendingHandshakes.ContainsKey(localIndex))
            {
                return;
            }

            // A failed read leaves the handshake untouched, so a forgery costs nothing but
            // the work of checking it and the genuine reply is still accepted.
            if (!pending.Handshake.TryReadMessage(noiseMessage, scratch.Buffer.Span, out _))
            {
                pending.Completion.TrySetException(new HandshakeFailedException("forged"));
                return;
            }

            _pendingHandshakes.TryRemove(localIndex, out _);

            using NoiseSplitKeys keys = pending.Handshake.Split();
            UniSession session = UniSession.Create(_options.Algorithm, keys, isInitiator: true, localIndex, peerIndex);

            UniConnection connection = new(
                _router,
                _pool,
                session,
                pending.RemoteNodeId,
                packet.RemotePath,
                _options.ReceiveQueueCapacity);

            _connections[localIndex] = connection;

            if (!pending.Completion.TrySetResult(connection))
            {
                _connections.TryRemove(localIndex, out _);
            }
        }
    }

    private static uint ReadReceiverIndex(ReadOnlySpan<byte> packet)
        => BinaryPrimitives.ReadUInt32LittleEndian(packet[4..]);

    /// <summary>
    /// Picks an unused session identifier.
    /// </summary>
    /// <remarks>
    /// Random rather than sequential: the identifier is visible in every packet, and a
    /// counter would leak how many connections this node has made.
    /// </remarks>
    private uint AllocateSessionIndex()
    {
        Span<byte> bytes = stackalloc byte[4];

        while (true)
        {
            _options.RandomSource.Fill(bytes);
            uint candidate = BinaryPrimitives.ReadUInt32LittleEndian(bytes);

            if (candidate != 0
                && !_connections.ContainsKey(candidate)
                && !_pendingHandshakes.ContainsKey(candidate))
            {
                return candidate;
            }
        }
    }

    private sealed class PendingHandshake(NoiseIkHandshake handshake, NodeId remoteNodeId) : IDisposable
    {
        public NoiseIkHandshake Handshake { get; } = handshake;

        public NodeId RemoteNodeId { get; } = remoteNodeId;

        /// <summary>
        /// Serialises access to <see cref="Handshake"/>, which is a state machine reachable
        /// from one receive loop per transport as well as from the dialling thread's cleanup.
        /// </summary>
        public Lock Gate { get; } = new();

        public TaskCompletionSource<UniConnection> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Dispose()
        {
            // Under the gate, so the handshake is never disposed while a reply is being read
            // through it.
            lock (Gate)
            {
                Handshake.Dispose();
            }
        }
    }

    /// <summary>
    /// Identifies one handshake attempt by the initiator's Noise ephemeral public key.
    /// </summary>
    /// <remarks>
    /// The ephemeral key is fresh per attempt, so every copy of an attempt that reaches this
    /// node — a retransmission, or the same attempt arriving over each candidate path the
    /// initiator probed in parallel — carries the same value. The source address does not,
    /// which is why it cannot be used for this.
    /// </remarks>
    private readonly struct HandshakeAttemptId : IEquatable<HandshakeAttemptId>
    {
        public const int SizeInBytes = 32;

        private readonly KeyBytes _value;

        public HandshakeAttemptId(ReadOnlySpan<byte> noiseMessage)
            => noiseMessage[..SizeInBytes].CopyTo(_value);

        public bool Equals(HandshakeAttemptId other)
            => ((ReadOnlySpan<byte>)_value).SequenceEqual(other._value);

        public override bool Equals(object? obj) => obj is HandshakeAttemptId other && Equals(other);

        public override int GetHashCode()
        {
            HashCode hash = default;
            hash.AddBytes((ReadOnlySpan<byte>)_value);
            return hash.ToHashCode();
        }

        [System.Runtime.CompilerServices.InlineArray(SizeInBytes)]
        private struct KeyBytes
        {
            private byte _element;
        }
    }

    /// <summary>
    /// The slot an accepted handshake attempt occupies, holding the connection it produced.
    /// </summary>
    /// <remarks>
    /// Claiming the slot is what makes "one handshake, one connection" hold when copies of
    /// the same attempt are processed concurrently; the connection it later carries is what
    /// lets a retransmission be answered from the cached reply.
    /// </remarks>
    private sealed class HandshakeAttempt
    {
        private volatile UniConnection? _connection;

        public UniConnection? Connection
        {
            get => _connection;
            set => _connection = value;
        }
    }
}
