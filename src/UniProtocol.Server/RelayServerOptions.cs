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
}
