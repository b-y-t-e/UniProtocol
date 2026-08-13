using UniProtocol;
using UniProtocol.Cli;
using UniProtocol.Cli.Commands;

using CancellationTokenSource cancellation = new();

Console.CancelKeyPress += (_, eventArgs) =>
{
    // Handle the first Ctrl+C ourselves so listeners shut down cleanly; a second one is
    // left to the runtime, so an interrupt is always eventually effective.
    eventArgs.Cancel = !cancellation.IsCancellationRequested;
    cancellation.Cancel();
};

return await RunAsync(args, cancellation.Token).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
{
    CommandLine commandLine = CommandLine.Parse(args);

    try
    {
        return commandLine.Command switch
        {
            "keygen" => KeyCommands.KeyGen(commandLine),
            "show" => KeyCommands.Show(commandLine),
            "listen" => await EchoCommands.ListenAsync(commandLine, cancellationToken).ConfigureAwait(false),
            "dial" => await EchoCommands.DialAsync(commandLine, cancellationToken).ConfigureAwait(false),
            "discover" => await EchoCommands.DiscoverAsync(commandLine, cancellationToken).ConfigureAwait(false),
            null or "help" => WriteUsage(),
            _ => UnknownCommand(commandLine.Command),
        };
    }
    catch (OperationCanceledException)
    {
        return 130;
    }
    catch (Exception exception) when (exception
        is IOException
        or InvalidDataException
        or UnauthorizedAccessException
        or ArgumentException
        or UniProtocolException)
    {
        Console.Error.WriteLine(exception.Message);
        return 1;
    }
}

static int UnknownCommand(string command)
{
    Console.Error.WriteLine($"Unknown command '{command}'.");
    WriteUsage();
    return 2;
}

static int WriteUsage()
{
    // Results go to stdout and diagnostics to stderr, so `unip keygen > id.txt` and
    // `unip dial ... | grep` both behave as expected.
    Console.Error.WriteLine("""
        unip — UniProtocol command line

        Usage:
          unip keygen [--path <file>] [--force]     Create a node identity and print its NodeId
          unip show   [--path <file>]               Print the NodeId of the stored identity
          unip listen [--path <file>] [--port <n>] [--relay <unipr://...>]
                                                    Run an echo responder; advertise it on the LAN
          unip discover [--seconds <n>]             List UniProtocol nodes on the local network

          unip dial <ticket>                        Connect using a ticket from 'unip listen'
          unip dial <nodeid> <address>              Connect to an explicit address
          unip dial --discover [prefix]             Find the peer on the local network
                      [--relay <unipr://...>] [--message <text>]

        A ticket printed by a relay-connected 'unip listen' works from any network, including
        when both machines are behind NAT. Set UNIP_RELAY to avoid passing --relay each time.

        Results are written to stdout; diagnostics go to stderr, so 'unip listen > ticket.txt'
        captures exactly the ticket.
        """);

    return 0;
}
