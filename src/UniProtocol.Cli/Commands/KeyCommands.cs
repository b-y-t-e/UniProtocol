using UniProtocol.Protocol.Identity;

namespace UniProtocol.Cli.Commands;

/// <summary>The <c>keygen</c> and <c>show</c> commands.</summary>
internal static class KeyCommands
{
    /// <summary>Creates an identity and prints its NodeId.</summary>
    public static int KeyGen(CommandLine commandLine)
    {
        string path = commandLine.GetValue("path", FileKeyStore.DefaultPath);

        if (File.Exists(path) && !commandLine.HasFlag("force"))
        {
            Console.Error.WriteLine($"A key already exists at {path}. Pass --force to replace it.");
            Console.Error.WriteLine(
                "Replacing a key changes this node's identity: peers that allow-listed the old NodeId will refuse to connect.");
            return 1;
        }

        FileKeyStore store = new(path);

        using UniIdentity identity = UniIdentity.Generate();
        store.Save(identity);

        Console.WriteLine(identity.NodeId);
        Console.Error.WriteLine($"Written to {path}");

        return 0;
    }

    /// <summary>Prints the NodeId of the stored identity.</summary>
    public static int Show(CommandLine commandLine)
    {
        string path = commandLine.GetValue("path", FileKeyStore.DefaultPath);
        FileKeyStore store = new(path);

        if (!store.TryLoad(out UniIdentity? identity))
        {
            Console.Error.WriteLine($"No key at {path}. Run 'unip keygen' first.");
            return 1;
        }

        using (identity)
        {
            Console.WriteLine(identity.NodeId);
        }

        return 0;
    }
}
