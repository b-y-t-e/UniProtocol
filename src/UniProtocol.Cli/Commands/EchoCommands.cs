using System.Globalization;
using System.Net;
using System.Text;
using UniProtocol.Discovery;
using UniProtocol.Discovery.Mdns;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;
using UniProtocol.Transport;

namespace UniProtocol.Cli.Commands;

/// <summary>
/// The <c>listen</c>, <c>dial</c> and <c>discover</c> commands: an encrypted echo between
/// two machines, paired either by ticket or by finding each other on the local network.
/// </summary>
/// <remarks>
/// The smallest thing that exercises the whole stack end to end — identity, pairing,
/// framing, handshake, session — over a real socket. It is a diagnostic tool, not a sample
/// of how an application should be structured.
/// </remarks>
internal static class EchoCommands
{
    private const int MaximumDatagramSize = 2048;
    private static readonly TimeSpan DiscoveryWindow = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan RelayConnectTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Runs an echo responder, advertising itself on the local network.</summary>
    public static async Task<int> ListenAsync(CommandLine commandLine, CancellationToken cancellationToken)
    {
        IKeyStore store = new FileKeyStore(commandLine.GetValue("path", FileKeyStore.DefaultPath));
        using UniIdentity identity = store.LoadOrCreate();

        int port = ParsePort(commandLine.GetValue("port", "0"));

        await using RelayPacketTransport? relay = await ConnectRelayAsync(commandLine, identity, cancellationToken)
            .ConfigureAwait(false);

        await using UniEndpoint endpoint = UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = identity,
            ListenEndPoint = new IPEndPoint(IPAddress.Any, port),
            ApplicationProtocol = "uniprotocol/echo",
            RelayTransport = relay,
        });

        UniTicket ticket = endpoint.CreateTicket();

        Console.WriteLine(ticket);
        Console.Error.WriteLine($"NodeId:    {identity.NodeId}");
        Console.Error.WriteLine($"Listening: {endpoint.LocalAddress}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Connect from the other machine with either of:");
        Console.Error.WriteLine($"  unip dial {ticket}");
        Console.Error.WriteLine("  unip dial --discover          (same network, nothing to copy)");

        Console.Error.WriteLine(relay is not null
            ? "  That ticket works from any network, including when both sides are behind NAT."
            : "  No relay configured, so this only works from a network that can reach an address above.");

        Console.Error.WriteLine();

        await using INodeAdvertiser? advertiser = await StartAdvertisingAsync(ticket, cancellationToken)
            .ConfigureAwait(false);

        List<Task> conversations = [];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                UniConnection connection = await endpoint.AcceptAsync(cancellationToken).ConfigureAwait(false);
                Console.Error.WriteLine($"Connected: {connection.RemoteNodeId.ToShortString()} over {connection.RemotePath}");

                conversations.Add(EchoUntilClosedAsync(connection, cancellationToken));
            }
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Stopping.");
        }

        await Task.WhenAll(conversations).ConfigureAwait(false);

        return 0;
    }

    /// <summary>Dials a peer by ticket, by NodeId and address, or by local discovery.</summary>
    public static async Task<int> DialAsync(CommandLine commandLine, CancellationToken cancellationToken)
    {
        UniTicket? ticket = await ResolveTicketAsync(commandLine, cancellationToken).ConfigureAwait(false);

        if (ticket is null)
        {
            return 2;
        }

        IKeyStore store = new FileKeyStore(commandLine.GetValue("path", FileKeyStore.DefaultPath));
        using UniIdentity identity = store.LoadOrCreate();

        // One socket serves one address family, so bind to the family of the peer we intend
        // to reach.
        bool preferIPv4 = ticket.Addresses.Count == 0 || ticket.Addresses[0].IsIPv4;

        // The relay named by the ticket is used unless the caller overrides it: whoever
        // handed out the ticket knows which relay they are actually reachable through.
        await using RelayPacketTransport? relay = await ConnectRelayAsync(
                commandLine,
                identity,
                cancellationToken,
                ticket.Relay)
            .ConfigureAwait(false);

        await using UniEndpoint endpoint = UniEndpoint.Create(new UniEndpointOptions
        {
            Identity = identity,
            ListenEndPoint = new IPEndPoint(preferIPv4 ? IPAddress.Any : IPAddress.IPv6Any, 0),
            ApplicationProtocol = "uniprotocol/echo",
            RelayTransport = relay,
        });

        string relayNote = relay is not null ? " plus the relay" : string.Empty;
        Console.Error.WriteLine(
            $"Dialling {ticket.NodeId.ToShortString()} as {identity.NodeId.ToShortString()} " +
            $"({ticket.Addresses.Count} direct candidate(s){relayNote})");

        try
        {
            await using UniConnection connection = await endpoint.ConnectAsync(ticket, cancellationToken)
                .ConfigureAwait(false);

            Console.Error.WriteLine($"Connected via {connection.RemotePath}.");

            string message = commandLine.GetValue("message", "hello from unip");
            byte[] payload = Encoding.UTF8.GetBytes(message);

            await connection.SendDatagramAsync(payload, cancellationToken).ConfigureAwait(false);

            byte[] buffer = new byte[MaximumDatagramSize];
            int received = await connection.ReceiveDatagramAsync(buffer, cancellationToken).ConfigureAwait(false);

            Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, received));

            return 0;
        }
        catch (HandshakeFailedException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    /// <summary>Lists the UniProtocol nodes advertising themselves on the local network.</summary>
    public static async Task<int> DiscoverAsync(CommandLine commandLine, CancellationToken cancellationToken)
    {
        TimeSpan window = TimeSpan.FromSeconds(
            double.Parse(commandLine.GetValue("seconds", "3"), CultureInfo.InvariantCulture));

        await using MdnsDiscovery? discovery = TryCreateDiscovery();

        if (discovery is null)
        {
            return 1;
        }

        Console.Error.WriteLine($"Looking for nodes on the local network for {window.TotalSeconds:0.#}s…");

        IReadOnlyList<DiscoveredNode> found = await discovery.DiscoverAsync(window, cancellationToken)
            .ConfigureAwait(false);

        if (found.Count == 0)
        {
            Console.Error.WriteLine("No nodes found.");
            return 1;
        }

        foreach (DiscoveredNode node in found)
        {
            Console.WriteLine(node.Ticket);
            Console.Error.WriteLine($"  {node.NodeId.ToShortString()} at {string.Join(", ", node.Ticket.Addresses)}");
        }

        return 0;
    }

    /// <summary>
    /// Works out who to dial, from a ticket, a NodeId plus address, or local discovery.
    /// </summary>
    private static async Task<UniTicket?> ResolveTicketAsync(CommandLine commandLine, CancellationToken cancellationToken)
    {
        if (commandLine.HasFlag("discover"))
        {
            return await DiscoverSinglePeerAsync(commandLine, cancellationToken).ConfigureAwait(false);
        }

        if (commandLine.Positional.Count == 0)
        {
            Console.Error.WriteLine("Usage: unip dial <ticket> | <nodeid> <address> | --discover [prefix]");
            return null;
        }

        // A NodeId with an explicit address: the form that works before any discovery exists.
        if (commandLine.Positional.Count >= 2)
        {
            if (!NodeId.TryParse(commandLine.Positional[0], out NodeId nodeId))
            {
                Console.Error.WriteLine($"'{commandLine.Positional[0]}' is not a valid NodeId.");
                return null;
            }

            if (!NetworkAddress.TryParse(commandLine.Positional[1], out NetworkAddress address))
            {
                Console.Error.WriteLine($"'{commandLine.Positional[1]}' is not a valid address. Use host:port or [v6]:port.");
                return null;
            }

            return new UniTicket { NodeId = nodeId, Addresses = [address] };
        }

        if (!UniTicket.TryParse(commandLine.Positional[0], out UniTicket? ticket))
        {
            Console.Error.WriteLine(
                "That is not a valid ticket. Tickets look like 'unip://n/…' and are printed by 'unip listen'.");
            return null;
        }

        if (ticket.IsExpired(TimeProvider.System.GetUtcNow()))
        {
            Console.Error.WriteLine($"That ticket expired at {ticket.ExpiresAt:u}. Ask for a fresh one.");
            return null;
        }

        if (ticket.Addresses.Count == 0 && ticket.Relay is null && !commandLine.HasFlag("relay"))
        {
            Console.Error.WriteLine(
                "That ticket carries no addresses and names no relay, so there is no way to reach the node. " +
                "Supply an address (unip dial <nodeid> <address>) or a relay (--relay unipr://...).");
            return null;
        }

        return ticket;
    }

    private static async Task<UniTicket?> DiscoverSinglePeerAsync(CommandLine commandLine, CancellationToken cancellationToken)
    {
        await using MdnsDiscovery? discovery = TryCreateDiscovery();

        if (discovery is null)
        {
            return null;
        }

        Console.Error.WriteLine("Looking for a node on the local network…");

        IReadOnlyList<DiscoveredNode> found = await discovery.DiscoverAsync(DiscoveryWindow, cancellationToken)
            .ConfigureAwait(false);

        string? prefix = commandLine.Positional.Count > 0 ? commandLine.Positional[0] : null;

        if (prefix is not null)
        {
            found = [.. found.Where(node => node.NodeId.ToString().StartsWith(prefix, StringComparison.OrdinalIgnoreCase))];
        }

        switch (found.Count)
        {
            case 0:
                Console.Error.WriteLine("No node found on the local network. Is 'unip listen' running on the other machine?");
                return null;

            case 1:
                Console.Error.WriteLine($"Found {found[0].NodeId.ToShortString()}.");
                return found[0].Ticket;

            default:
                // Picking one arbitrarily would connect to the wrong machine roughly half the
                // time, which is worse than asking.
                Console.Error.WriteLine($"Found {found.Count} nodes. Narrow it down with a NodeId prefix:");
                foreach (DiscoveredNode node in found)
                {
                    Console.Error.WriteLine($"  unip dial --discover {node.NodeId.ToShortString()}");
                }

                return null;
        }
    }

    /// <summary>
    /// Opens a relay connection, if one is named on the command line, in the environment,
    /// or by the ticket being dialled.
    /// </summary>
    private static async Task<RelayPacketTransport?> ConnectRelayAsync(
        CommandLine commandLine,
        UniIdentity identity,
        CancellationToken cancellationToken,
        RelayAddress? fallback = null)
    {
        string? text = commandLine.GetValue("relay", string.Empty);

        if (string.IsNullOrEmpty(text))
        {
            text = Environment.GetEnvironmentVariable("UNIP_RELAY");
        }

        RelayAddress? address = fallback;

        if (!string.IsNullOrEmpty(text))
        {
            if (!RelayAddress.TryParse(text, out RelayAddress? parsed))
            {
                Console.Error.WriteLine($"'{text}' is not a valid relay address. Expected unipr://<nodeid>@host:port.");
                return null;
            }

            address = parsed;
        }

        if (address is null)
        {
            return null;
        }

        Console.Error.WriteLine($"Connecting to relay {address.Host}:{address.Port}...");

        RelayPacketTransport relay = RelayPacketTransport.Create(address, identity);

        try
        {
            using CancellationTokenSource timeout = new(RelayConnectTimeout);
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                timeout.Token);

            await relay.WaitUntilConnectedAsync(linked.Token).ConfigureAwait(false);
            Console.Error.WriteLine("Relay connected.");

            return relay;
        }
        catch (OperationCanceledException)
        {
            // Continuing without the relay is better than refusing to start: direct
            // addresses may still work, and the endpoint is useful either way.
            Console.Error.WriteLine("Could not reach the relay in time; continuing without it.");
            await relay.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }

    private static async Task<INodeAdvertiser?> StartAdvertisingAsync(UniTicket ticket, CancellationToken cancellationToken)
    {
        MdnsDiscovery? discovery = TryCreateDiscovery();

        if (discovery is null)
        {
            Console.Error.WriteLine("Local discovery is unavailable; pairing by ticket still works.");
            return null;
        }

        await discovery.AdvertiseAsync(ticket, cancellationToken).ConfigureAwait(false);
        Console.Error.WriteLine("Advertising on the local network.");

        return discovery;
    }

    private static MdnsDiscovery? TryCreateDiscovery()
    {
        try
        {
            return MdnsDiscovery.Create();
        }
        catch (MulticastUnavailableException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return null;
        }
    }

    private static async Task EchoUntilClosedAsync(UniConnection connection, CancellationToken cancellationToken)
    {
        await using (connection.ConfigureAwait(false))
        {
            byte[] buffer = new byte[MaximumDatagramSize];

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int received = await connection.ReceiveDatagramAsync(buffer, cancellationToken).ConfigureAwait(false);

                    Console.Error.WriteLine(
                        $"  {connection.RemoteNodeId.ToShortString()} sent {received} bytes; echoing back");

                    await connection.SendDatagramAsync(buffer.AsMemory(0, received), cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or ConnectionClosedException)
            {
                // The peer went away or we are shutting down; either way this conversation
                // is over and the others must keep running.
            }
        }
    }

    private static int ParsePort(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int port)
            || port is < 0 or > 65535)
        {
            throw new ArgumentException($"'{value}' is not a valid port number.", nameof(value));
        }

        return port;
    }
}
