using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;
using UniProtocol.Server;

using CancellationTokenSource cancellation = new();

Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = !cancellation.IsCancellationRequested;
    cancellation.Cancel();
};

return await RunAsync(args, cancellation.Token).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
{
    Options options;

    try
    {
        options = Options.Parse(args);
    }
    catch (ArgumentException exception)
    {
        Console.Error.WriteLine(exception.Message);
        WriteUsage();
        return 2;
    }

    if (options.ShowHelp)
    {
        WriteUsage();
        return 0;
    }

    IKeyStore store = new FileKeyStore(options.KeyPath);
    using UniIdentity identity = store.LoadOrCreate();

    if (options.PrintAddressOnly)
    {
        Console.WriteLine(new RelayAddress
        {
            NodeId = identity.NodeId,
            Host = options.PublicHost ?? "<your-host>",
            Port = options.AdvertisePort ?? options.Port,
        });

        return 0;
    }

    using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder
        .SetMinimumLevel(options.Verbose ? LogLevel.Debug : LogLevel.Information)
        .AddSimpleConsole(console =>
        {
            console.SingleLine = true;
            console.TimestampFormat = "HH:mm:ss ";
        }));

    await using RelayServer server = RelayServer.Start(new RelayServerOptions
    {
        Identity = identity,
        ListenEndPoint = new IPEndPoint(IPAddress.IPv6Any, options.Port),
        LoggerFactory = loggerFactory,
    });

    ILogger logger = loggerFactory.CreateLogger("unipd");

    // The advertised port is the one clients dial, which is not always the one the server
    // binds: in a container the relay listens unprivileged on 8443 while the host publishes
    // 443. Printing the listening port there would hand out an address that does not work.
    RelayAddress address = new()
    {
        NodeId = server.NodeId,
        Host = options.PublicHost ?? "<your-host>",
        Port = options.AdvertisePort ?? server.Port,
    };

    // The relay address goes to stdout on its own line so it can be captured directly;
    // everything else is logging.
    Console.WriteLine(address);

    Log.RelayStarted(logger, server.Port, options.KeyPath);

    if (options.PublicHost is null)
    {
        Log.MissingHost(logger);
    }

    try
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, TimeProvider.System, cancellationToken).ConfigureAwait(false);
    }
    catch (OperationCanceledException)
    {
        Log.ShuttingDown(logger);
    }

    return 0;
}

static void WriteUsage() => Console.Error.WriteLine("""
    unipd — UniProtocol relay server

    Forwards encrypted packets between nodes that cannot reach each other directly.
    Run one on a machine with a public address; it serves all your devices.

    Usage:
      unipd [--port <n>] [--advertise-port <n>] [--host <public-name-or-ip>]
            [--path <key-file>] [--verbose]
      unipd --print-address [--host <name>] [--port <n>]   Print the relay address and exit

    The relay address (unipr://<nodeid>@host:port) is written to stdout. Give it to clients
    with 'unip listen --relay <address>' and 'unip dial <ticket>'.

    Use --advertise-port when clients reach the relay on a different port from the one it
    binds — behind a container port mapping or a forwarding firewall, for example.

    The server is authenticated by its key, not by a TLS certificate: there is nothing to
    issue, renew or let expire.
    """);

/// <summary>Source-generated log messages, so nothing is formatted when it is not needed.</summary>
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information, Message = "Relay listening on port {Port}. Key file: {KeyPath}")]
    public static partial void RelayStarted(ILogger logger, int port, string keyPath);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Warning,
        Message = "No --host given, so the printed address has a placeholder. Pass --host <public-name-or-ip> to print an address clients can use verbatim.")]
    public static partial void MissingHost(ILogger logger);

    [LoggerMessage(EventId = 3, Level = LogLevel.Information, Message = "Shutting down.")]
    public static partial void ShuttingDown(ILogger logger);
}

internal sealed record Options
{
    public int Port { get; init; } = RelayProtocol.DefaultPort;

    /// <summary>
    /// The port to put in the printed relay address, when it differs from the one bound.
    /// </summary>
    public int? AdvertisePort { get; init; }

    public string? PublicHost { get; init; }

    public string KeyPath { get; init; } = DefaultKeyPath;

    public bool Verbose { get; init; }

    public bool PrintAddressOnly { get; init; }

    public bool ShowHelp { get; init; }

    private static string DefaultKeyPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create),
        "uniprotocol",
        "relay.key");

    public static Options Parse(string[] args)
    {
        Options options = new();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--port":
                    options = options with { Port = ParsePort(RequireValue(args, ref i)) };
                    break;

                case "--advertise-port":
                    options = options with { AdvertisePort = ParsePort(RequireValue(args, ref i)) };
                    break;

                case "--host":
                    options = options with { PublicHost = RequireValue(args, ref i) };
                    break;

                case "--path":
                    options = options with { KeyPath = RequireValue(args, ref i) };
                    break;

                case "--verbose":
                    options = options with { Verbose = true };
                    break;

                case "--print-address":
                    options = options with { PrintAddressOnly = true };
                    break;

                case "--help" or "-h":
                    options = options with { ShowHelp = true };
                    break;

                default:
                    throw new ArgumentException($"Unknown argument '{args[i]}'.", nameof(args));
            }
        }

        return options;
    }

    private static string RequireValue(string[] args, ref int index)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"'{args[index]}' needs a value.", nameof(args));
        }

        return args[++index];
    }

    private static int ParsePort(string value)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int port) && port is > 0 and <= 65535
            ? port
            : throw new ArgumentException($"'{value}' is not a valid port number.", nameof(value));
}
