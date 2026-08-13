namespace UniProtocol.Protocol.Relay;

/// <summary>Constants shared by the relay client and server.</summary>
public static class RelayProtocol
{
    /// <summary>The application protocol identifier mixed into the relay handshake prologue.</summary>
    public const string ApplicationProtocol = "uniprotocol/relay/v1";

    /// <summary>The URI scheme naming a relay server.</summary>
    /// <remarks>
    /// A relay is addressed as <c>unipr://&lt;server-nodeid&gt;@host:port</c>. The identity
    /// is part of the address rather than something a certificate authority vouches for:
    /// the client performs a Noise handshake to exactly that key, so a hijacked DNS name or
    /// a intercepted TCP connection cannot impersonate the relay, and there is no
    /// certificate to obtain, renew or have expire at three in the morning.
    /// </remarks>
    public const string UriScheme = "unipr";

    /// <summary>Default TCP port.</summary>
    /// <remarks>
    /// 443 because it is the port least likely to be blocked. The traffic is not TLS, so
    /// this blends with HTTPS only against port-based filtering — deep inspection will tell
    /// the difference.
    /// </remarks>
    public const int DefaultPort = 443;

    /// <summary>Largest frame body the protocol permits, in bytes.</summary>
    /// <remarks>
    /// Bounded so a peer cannot make the server allocate arbitrarily. Far above the largest
    /// packet a path will ever carry.
    /// </remarks>
    public const int MaximumFrameSizeInBytes = 16 * 1024;

    /// <summary>How often a client sends a keep-alive when otherwise idle.</summary>
    /// <remarks>
    /// Under the timeout of every NAT and stateful firewall worth worrying about. A relay
    /// connection that is allowed to go quiet gets silently dropped, and the node becomes
    /// unreachable without either side noticing.
    /// </remarks>
    public static TimeSpan KeepAliveInterval => TimeSpan.FromSeconds(25);

    /// <summary>How long the server waits for traffic before closing a connection.</summary>
    public static TimeSpan IdleTimeout => TimeSpan.FromSeconds(90);
}
