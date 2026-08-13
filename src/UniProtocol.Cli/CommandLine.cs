namespace UniProtocol.Cli;

/// <summary>
/// Minimal parser for <c>--name value</c> options and bare flags.
/// </summary>
/// <remarks>
/// Hand-written rather than taken from a package. The CLI is a diagnostic tool with a
/// handful of options; a parsing library would be a larger dependency than the thing it
/// parses, and this binary is AOT-published where reflection-based parsers are a liability.
/// </remarks>
internal sealed class CommandLine
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.Ordinal);
    private readonly List<string> _positional = [];

    private CommandLine(string? command)
    {
        Command = command;
    }

    /// <summary>The first non-option argument, or <see langword="null"/> if there is none.</summary>
    public string? Command { get; }

    /// <summary>Non-option arguments after the command, in order.</summary>
    public IReadOnlyList<string> Positional => _positional;

    /// <summary>Parses <paramref name="arguments"/>.</summary>
    public static CommandLine Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        string? command = arguments.Length > 0 && !arguments[0].StartsWith("--", StringComparison.Ordinal)
            ? arguments[0]
            : null;

        CommandLine result = new(command);

        for (int i = command is null ? 0 : 1; i < arguments.Length; i++)
        {
            string argument = arguments[i];

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                result._positional.Add(argument);
                continue;
            }

            string name = argument[2..];
            bool hasValue = i + 1 < arguments.Length && !arguments[i + 1].StartsWith("--", StringComparison.Ordinal);

            result._options[name] = hasValue ? arguments[++i] : null;
        }

        return result;
    }

    /// <summary>Returns the value of <paramref name="name"/>, or <paramref name="fallback"/>.</summary>
    public string GetValue(string name, string fallback)
        => _options.TryGetValue(name, out string? value) && value is not null ? value : fallback;

    /// <summary>Indicates whether the flag <paramref name="name"/> was supplied.</summary>
    public bool HasFlag(string name) => _options.ContainsKey(name);
}
