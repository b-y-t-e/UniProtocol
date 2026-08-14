using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;

namespace UniProtocol.Server;

/// <summary>Configuration for a <see cref="RelayServer"/>.</summary>
public sealed record RelayServerOptions
{
    /// <summary>The relay's own identity, which clients dial by key.</summary>
    public required UniIdentity Identity { get; init; }

    /// <summary>Where to listen. Dual-stack by default, so one socket serves IPv4 and IPv6.</summary>
    public IPEndPoint ListenEndPoint { get; init; } = new(IPAddress.IPv6Any, RelayProtocol.DefaultPort);

    /// <summary>Where to write diagnostics.</summary>
    public ILoggerFactory LoggerFactory { get; init; } = NullLoggerFactory.Instance;

    /// <summary>Clock used for timeouts and rate limiting.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// How many packets a second one client may have forwarded on its behalf.
    /// </summary>
    /// <remarks>
    /// A relay forwards on behalf of clients it has authenticated but does not trust, and
    /// bandwidth is the operator's to pay for. The limit is generous for interactive use and
    /// well short of what it takes to saturate a link.
    /// </remarks>
    public int PacketsPerSecondPerClient { get; init; } = 1_000;

    /// <summary>
    /// How many packets may be queued for a client that is not reading fast enough.
    /// </summary>
    /// <remarks>
    /// Bounded so one slow client cannot make the server buffer without limit on its behalf.
    /// Beyond it the oldest packets are dropped, which is what would have happened to them on
    /// a congested link anyway.
    /// </remarks>
    public int SendQueueCapacity { get; init; } = 256;

    /// <summary>Maximum number of clients connected at once.</summary>
    public int MaximumClients { get; init; } = 10_000;

    /// <summary>
    /// Maximum number of connections that have been accepted but have not yet completed the
    /// relay handshake.
    /// </summary>
    /// <remarks>
    /// The client limit alone does not bound anything an attacker has to work for: a
    /// connection only counts against it once it has authenticated, so opening sockets and
    /// never finishing the handshake costs a file descriptor and a buffer each and is not
    /// counted at all. This is the limit that a flood actually meets. It is generous relative
    /// to any real burst of arrivals, because handshakes complete in a round trip.
    /// </remarks>
    public int MaximumPendingHandshakes { get; init; } = 512;

    /// <summary>
    /// Maximum number of connections one remote address may hold at once, authenticated or not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keeps a single source from consuming the whole pending-handshake budget. Set high
    /// enough for the legitimate case of many devices behind one NAT.
    /// </para>
    /// <para>
    /// <strong>The remote address is not a reliable stand-in for "one party".</strong> Behind
    /// carrier-grade NAT, a corporate egress or a proxy, thousands of unrelated clients share
    /// one address, and this limit will cut off honest devices long before it inconveniences
    /// anyone. From the other side, an attacker with a /64 of IPv6 — which is what a single
    /// cheap host is handed — gets the full allowance per address and can simply move.
    /// </para>
    /// <para>
    /// It is kept because it raises the cost of the easy case, not because it is a real
    /// defence. The limit that actually holds under a flood is
    /// <see cref="MaximumPendingHandshakes"/>, which is global. A deployment that expects
    /// clients behind shared addresses should raise this or disable it by setting it to
    /// <see cref="int.MaxValue"/>; one facing the open internet should leave it and rely on
    /// the global limit for the rest.
    /// </para>
    /// </remarks>
    public int MaximumConnectionsPerAddress { get; init; } = 64;

    /// <summary>How long a connection may be silent before the server closes it.</summary>
    /// <remarks>
    /// Clients send a keep-alive every <see cref="RelayProtocol.KeepAliveInterval"/>, so
    /// silence past this means the peer is gone and the socket is a ghost the operating
    /// system has not noticed. Without it those accumulate for the life of the process.
    /// </remarks>
    public TimeSpan IdleTimeout { get; init; } = RelayProtocol.IdleTimeout;
}
