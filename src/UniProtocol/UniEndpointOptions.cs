using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using UniProtocol.Abstractions;
using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Randomness;
using UniProtocol.Protocol.Identity;

namespace UniProtocol;

/// <summary>
/// Configuration for a <see cref="UniEndpoint"/>.
/// </summary>
/// <remarks>
/// Every ambient dependency the endpoint could otherwise reach for — the clock, the random
/// source, the network — is a property here. That is what makes the endpoint testable: the
/// simulator constructs one with a virtual clock, a seeded random source and an in-memory
/// transport, and the protocol cannot tell the difference.
/// </remarks>
public sealed record UniEndpointOptions
{
    /// <summary>This node's long-term identity.</summary>
    public required UniIdentity Identity { get; init; }

    /// <summary>
    /// Where to bind. Defaults to an operating-system-assigned port on all IPv4 addresses.
    /// </summary>
    /// <remarks>Ignored when <see cref="Transport"/> is supplied.</remarks>
    public IPEndPoint ListenEndPoint { get; init; } = new(IPAddress.Any, 0);

    /// <summary>
    /// A transport to use instead of opening a UDP socket.
    /// </summary>
    /// <remarks>
    /// The seam that lets the whole protocol run against a simulated network.
    /// </remarks>
    public IPacketTransport? Transport { get; init; }

    /// <summary>
    /// A transport that reaches peers through a relay server.
    /// </summary>
    /// <remarks>
    /// Supply one to reach peers that have no directly reachable address — which is most
    /// peers, most of the time. Without it, an endpoint can only talk to hosts it can send a
    /// UDP packet to.
    /// </remarks>
    public IPacketTransport? RelayTransport { get; init; }

    /// <summary>The AEAD used for the handshake and for session packets.</summary>
    public IAeadAlgorithm Algorithm { get; init; } = ChaCha20Poly1305Algorithm.Instance;

    /// <summary>Source of ephemeral keys and session identifiers.</summary>
    public IRandomSource RandomSource { get; init; } = SecureRandomSource.Instance;

    /// <summary>Clock used for every timeout and retransmission.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Where to write diagnostics.</summary>
    public ILoggerFactory LoggerFactory { get; init; } = NullLoggerFactory.Instance;

    /// <summary>
    /// Identifies the application protocol; peers must agree on it.
    /// </summary>
    /// <remarks>
    /// Mixed into the Noise prologue, so two applications that happen to share a node
    /// identity cannot accidentally interoperate — the handshake fails outright instead of
    /// producing a session where the peers disagree about what the bytes mean.
    /// </remarks>
    public string ApplicationProtocol { get; init; } = "uniprotocol/echo";

    /// <summary>How long to wait for a handshake reply before giving up.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Delay before the first handshake retransmission; doubles on each retry.</summary>
    public TimeSpan HandshakeRetryInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// How many received datagrams a connection buffers before the oldest are discarded.
    /// </summary>
    public int ReceiveQueueCapacity { get; init; } = 256;
}
